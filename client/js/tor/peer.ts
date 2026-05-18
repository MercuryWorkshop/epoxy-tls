// WebRTC peer setup for snowflake.
//
// Creates an RTCPeerConnection, an ordered+reliable DataChannel, gathers
// all ICE candidates locally (the broker can't relay trickled candidates),
// then exchanges the offer/answer via the broker rendezvous.

import { brokerExchange } from "./broker";

export interface PeerConfig {
	brokerUrl: string;
	fingerprint: string;
	iceServers: RTCIceServer[];
	dataChannelTimeoutMs?: number;
}

export interface SnowflakePeer {
	pc: RTCPeerConnection;
	dc: RTCDataChannel;
}

function waitForIceComplete(pc: RTCPeerConnection): Promise<void> {
	if (pc.iceGatheringState === "complete") return Promise.resolve();
	return new Promise((resolve) => {
		const handle = () => {
			if (pc.iceGatheringState === "complete") {
				pc.removeEventListener("icegatheringstatechange", handle);
				resolve();
			}
		};
		pc.addEventListener("icegatheringstatechange", handle);
	});
}

export async function openSnowflakePeer(
	cfg: PeerConfig
): Promise<SnowflakePeer> {
	const pc = new RTCPeerConnection({
		iceServers: cfg.iceServers,
	});

	const dc = pc.createDataChannel("snowflake", {
		ordered: true,
	});
	dc.binaryType = "arraybuffer";

	const offer = await pc.createOffer();
	await pc.setLocalDescription(offer);

	// Snowflake has trickle ICE disabled — wait for full gather before
	// shipping the offer to the broker.
	await waitForIceComplete(pc);

	const offerSdp = pc.localDescription?.sdp;
	if (!offerSdp) throw new Error("snowflake: no local SDP after gather");

	const answerSdp = await brokerExchange({
		brokerUrl: cfg.brokerUrl,
		offerSdp,
		fingerprint: cfg.fingerprint,
	});

	await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });

	// Wait for the data channel to actually open.
	const timeoutMs = cfg.dataChannelTimeoutMs ?? 30000;
	await new Promise<void>((resolve, reject) => {
		const timer = setTimeout(() => {
			reject(new Error("snowflake: data channel open timeout"));
		}, timeoutMs);
		const cleanup = () => clearTimeout(timer);

		if (dc.readyState === "open") {
			cleanup();
			resolve();
			return;
		}

		dc.addEventListener(
			"open",
			() => {
				cleanup();
				resolve();
			},
			{ once: true }
		);
		dc.addEventListener("error", (ev) => {
			cleanup();
			reject(new Error(`snowflake: data channel error: ${String(ev)}`));
		});
		dc.addEventListener("close", () => {
			cleanup();
			reject(new Error("snowflake: data channel closed before open"));
		});
	});

	return { pc, dc };
}
