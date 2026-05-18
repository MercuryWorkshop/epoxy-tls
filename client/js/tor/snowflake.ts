// Top-level snowflake client. Composes the snowfort modules
// (encapsulation + KCP + smux v2) over a WebRTC DataChannel to produce a
// duplex byte stream that arti uses as if it were a TCP connection to a tor
// guard.
//
// Modules under ./{encapsulation,kcp,smux,turbotunnel,util} are vendored
// from https://github.com/r58Playz/snowfort (MIT-licensed).

import { openSnowflakePeer } from "./peer";
import { setLogHandler, type LogHandler } from "./logger";
import { Token } from "./turbotunnel/consts";
import { ClientID } from "./turbotunnel/clientid";
import { type PacketConn, UDPSession } from "./kcp/sess";
import {
	Session as SmuxSession,
	DefaultConfig as SmuxDefaultConfig,
} from "./smux/session";
import { EncapsulatedPacketConn } from "./encapsulation/conn";

// Default snowflake bridge fingerprint; matches the one that
// snowflake-broker.torproject.net assigns to clients that don't request a
// specific bridge.
export const DEFAULT_SNOWFLAKE_FINGERPRINT =
	"2B280B23E1107BB62ABFC40DDCC8824814F80A72";

export interface SnowflakeConfig {
	// HTTPS broker URL (must end with `/`). Defaults to the public broker.
	brokerUrl?: string;
	// Snowflake bridge fingerprint, hex. Defaults to the built-in one.
	fingerprint?: string;
	// STUN servers for ICE.
	iceServers?: RTCIceServer[];
	// Optional debug logger. The vendored snowfort modules call this with
	// human-readable status strings (KCP/smux/encapsulation tracing). Leave
	// unset to drop logs entirely.
	log?: LogHandler;
}

export type SnowflakeStream = [
	readable: ReadableStream<Uint8Array<ArrayBuffer>>,
	writable: WritableStream<Uint8Array<ArrayBuffer>>,
];

const DEFAULT_BROKER = "https://snowflake-broker.torproject.net/";
// Mirrors the STUN list shipped in snowflake-client's default torrc — these
// servers implement RFC 5780 so the snowflake broker can do NAT-type
// matching, otherwise it tends to time out finding a compatible proxy.
const DEFAULT_ICE: RTCIceServer[] = [
	{ urls: "stun:stun.antisip.com:3478" },
	{ urls: "stun:stun.epygi.com:3478" },
	{ urls: "stun:stun.uls.co.za:3478" },
	{ urls: "stun:stun.voipgate.com:3478" },
	{ urls: "stun:stun.mixvoip.com:3478" },
	{ urls: "stun:stun.nextcloud.com:3478" },
	{ urls: "stun:stun.bethesda.net:3478" },
	{ urls: "stun:stun.nextcloud.com:443" },
];

const BROKER_RETRY_LIMIT = 5;

// PacketConn over a WebRTC DataChannel: each `dc.send` is one packet, each
// `onmessage` event yields one packet. Adapted from snowfort's
// `WebRTCConn` so we can keep using our own peer.ts.
class DataChannelPacketConn implements PacketConn {
	private readonly dc: RTCDataChannel;
	private readQueue: Uint8Array[] = [];
	private readCallbacks: (() => void)[] = [];
	private closed = false;

	constructor(dc: RTCDataChannel) {
		this.dc = dc;
		dc.binaryType = "arraybuffer";

		dc.addEventListener("message", (ev: MessageEvent) => {
			const data = ev.data;
			if (data instanceof ArrayBuffer) {
				this.enqueue(new Uint8Array(data));
			} else if (typeof data === "string") {
				this.enqueue(new TextEncoder().encode(data));
			}
		});
		dc.addEventListener("close", () => {
			this.closed = true;
			this.wake();
		});
		dc.addEventListener("error", () => {
			this.closed = true;
			this.wake();
		});
	}

	private enqueue(msg: Uint8Array) {
		this.readQueue.push(msg);
		this.wake();
	}

	private wake() {
		const cb = this.readCallbacks.shift();
		if (cb) cb();
	}

	async readFrom(
		buf: Uint8Array
	): Promise<{ n: number; addr: any; err: Error | null }> {
		while (true) {
			if (this.readQueue.length > 0) {
				const msg = this.readQueue.shift()!;
				const n = Math.min(buf.length, msg.length);
				buf.set(msg.subarray(0, n));
				return { n, addr: null, err: null };
			}
			if (this.closed) {
				return { n: 0, addr: null, err: new Error("closed") };
			}
			await new Promise<void>((resolve) => this.readCallbacks.push(resolve));
		}
	}

	async writeTo(
		buf: Uint8Array,
		_addr: any
	): Promise<{ n: number; err: Error | null }> {
		if (this.closed) return { n: 0, err: new Error("closed") };
		try {
			this.dc.send(buf as any);
			return { n: buf.length, err: null };
		} catch (e) {
			return { n: 0, err: e as Error };
		}
	}

	async close(): Promise<void> {
		this.closed = true;
		try {
			this.dc.close();
		} catch {}
		this.wake();
	}

	localAddr(): any {
		return "webrtc";
	}
}

// Open a single snowflake-tunneled byte stream.
export async function openSnowflakeStream(
	cfg: SnowflakeConfig = {}
): Promise<SnowflakeStream> {
	const brokerUrl = cfg.brokerUrl ?? DEFAULT_BROKER;
	const fingerprint = cfg.fingerprint ?? DEFAULT_SNOWFLAKE_FINGERPRINT;
	const iceServers = cfg.iceServers ?? DEFAULT_ICE;

	// Wire the user's log callback (or absence of one) to the shared logger
	// the vendored snowfort modules call into.
	setLogHandler(cfg.log ?? null);

	// Broker matchmaking can time out when no compatible proxy is currently
	// polling; the standard remedy is to retry with a fresh offer.
	let pc: RTCPeerConnection | undefined;
	let dc: RTCDataChannel | undefined;
	let lastErr: unknown;
	for (let attempt = 0; attempt < BROKER_RETRY_LIMIT; attempt += 1) {
		try {
			const peer = await openSnowflakePeer({
				brokerUrl,
				fingerprint,
				iceServers,
			});
			pc = peer.pc;
			dc = peer.dc;
			break;
		} catch (e) {
			lastErr = e;
			console.warn(
				`snowflake: broker rendezvous attempt ${attempt + 1} failed: ${e}`
			);
		}
	}
	if (!pc || !dc) {
		throw new Error(`snowflake: rendezvous failed after retries: ${lastErr}`);
	}

	// Build the snowflake protocol stack: token → clientID → encapsulation →
	// KCP → smux. Mirrors snowfort's `SnowflakeClient.connect`.
	const rawConn = new DataChannelPacketConn(dc);
	await rawConn.writeTo(Token, null);
	const clientId = ClientID.New();
	await rawConn.writeTo(clientId.id, null);

	const encapConn = new EncapsulatedPacketConn(rawConn);

	// Conv id is fixed at 1; matches snowfort's choice and is what the bridge
	// expects for a fresh session.
	const kcpSess = new UDPSession(1, encapConn);
	kcpSess.setNoDelay(0, 0, 0, 1);
	kcpSess.setWindowSize(65535, 65535);
	kcpSess.setACKNoDelay(true);

	const smuxConfig = { ...SmuxDefaultConfig };
	smuxConfig.version = 2;
	smuxConfig.keepAliveTimeout = 10 * 60 * 1000; // 10 min
	smuxConfig.maxStreamBuffer = 1024 * 1024; // 1 MiB

	const smuxSess = new SmuxSession(
		{
			read: (b) => kcpSess.read(b),
			write: (b) => kcpSess.write(b),
			close: () => kcpSess.close(),
		},
		true,
		smuxConfig
	);

	const stream = await smuxSess.openStream();

	const closeAll = () => {
		stream.close().catch(() => {});
		smuxSess.close().catch(() => {});
		try {
			dc!.close();
		} catch {}
		try {
			pc!.close();
		} catch {}
	};

	dc.addEventListener("close", closeAll);
	pc.addEventListener("connectionstatechange", () => {
		if (
			pc!.connectionState === "failed" ||
			pc!.connectionState === "closed"
		) {
			closeAll();
		}
	});

	const readable = new ReadableStream<Uint8Array>({
		async pull(controller) {
			const buf = new Uint8Array(32 * 1024);
			try {
				const n = await stream.read(buf);
				if (n === 0) {
					controller.close();
					return;
				}
				controller.enqueue(buf.subarray(0, n));
			} catch (e) {
				try {
					controller.error(e);
				} catch {}
				closeAll();
			}
		},
		cancel() {
			closeAll();
		},
	});

	const writable = new WritableStream<Uint8Array>({
		async write(chunk) {
			await stream.write(chunk);
		},
		close() {
			closeAll();
		},
		abort() {
			closeAll();
		},
	});

	return [
		readable as ReadableStream<Uint8Array<ArrayBuffer>>,
		writable as WritableStream<Uint8Array<ArrayBuffer>>,
	];
}
