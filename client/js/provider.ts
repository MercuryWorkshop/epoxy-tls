import {
	EitherSocketProvider as EpxEitherSocketProvider,
	JsProvider as EpxJsProvider,
	WispProvider as EpxWispProvider,
	JsWispV2Handshake,
	ProtocolExtensionBuilders,
	WasmProvider,
	WasmWispProvider,
} from "epoxy/wbg";
/* EXTENDED.START */
import {
	TorSocketProvider as EpxTorSocketProvider,
	TorBootstrapCallback,
	TorBootstrapProgress,
	TorStateMgrCallbacks,
} from "epoxy/wbg";
/* EXTENDED.END */
import { WebSocketStream } from "./websocketstream";
import { ProtocolExtensionBuilder, WispExtensions } from "./wispExtension";

export type ProviderResult = [
	readable: ReadableStream<Uint8Array<ArrayBuffer>>,
	writable: WritableStream<Uint8Array<ArrayBuffer>>,
];

abstract class Provider<T, P> {
	// @internal
	_provider: T;
	// @internal
	_map: (provider: T) => P;
	// @internal
	used: boolean = false;

	constructor(provider: T, map: (provider: T) => P) {
		this._provider = provider;
		this._map = map;
	}

	// @internal
	clone(): T | undefined {
		return undefined;
	}

	// @internal
	get provider(): P {
		let cloned = this.clone();
		if (!cloned) {
			if (this.used) throw new Error("Provider already used");
			this.used = true;
			cloned = this._provider;
		}

		return this._map(cloned);
	}
}

export class JsProvider extends Provider<EpxJsProvider, WasmWispProvider> {
	constructor(
		func: (host: string) => Promise<ProviderResult> | ProviderResult
	) {
		super(new EpxJsProvider(async (host) => await func(host)), (x) =>
			x.box_wisp()
		);
	}
}

export class WebSocketJsProvider extends JsProvider {
	constructor() {
		super(async (host) => {
			let stream = new WebSocketStream<Uint8Array<ArrayBuffer>>(host);
			let { readable, writable } = await stream.opened;

			return [readable, writable];
		});
	}
}

export class JsSocketProvider extends Provider<EpxJsProvider, WasmProvider> {
	constructor(
		func: (
			host: string,
			port: number
		) => Promise<ProviderResult> | ProviderResult
	) {
		super(
			new EpxJsProvider(async (host, port) => await func(host, port)),
			(x) => x.box()
		);
	}
}

export class WsProxyJsSocketProvider extends JsSocketProvider {
	constructor(wsproxy: string) {
		if (!["ws:", "wss:"].includes(new URL(wsproxy).protocol))
			throw new Error("Invalid wsproxy base url. Needs ws or wss protocol");
		super(async (host, port) => {
			let url = new URL(wsproxy);

			if (!url.pathname.endsWith("/")) url.pathname += "/";

			url.pathname += `${encodeURIComponent(host)}:${port}`;

			let stream = new WebSocketStream<Uint8Array<ArrayBuffer>>(url.toString());
			let { readable, writable } = await stream.opened;

			return [readable, writable];
		});
	}
}

export interface WispV2Handshake {
	builders: ProtocolExtensionBuilder[];
}

export class WispSocketProvider extends Provider<
	EpxWispProvider,
	WasmProvider
> {
	clone() {
		return this._provider.dup();
	}

	constructor(
		provider: JsProvider,
		server: string,
		connectionPrefs?: () => [
			v2: WispV2Handshake | undefined,
			requiredExts: number[],
		]
	) {
		let v2;
		if (connectionPrefs) {
			v2 = () => {
				let [v2, required] = connectionPrefs();

				let handshake: JsWispV2Handshake | undefined;
				if (v2) {
					let builders = new ProtocolExtensionBuilders();
					for (let builder of v2.builders) {
						builder.appendTo(builders);
					}
					handshake = new JsWispV2Handshake(builders, async () => {});
				}

				return [handshake, new Uint8Array(required)];
			};
		}
		super(EpxWispProvider.new(provider.provider, server, v2), (x) => x.box());
	}

	async replaceMux() {
		await this._provider.replace_mux();
	}

	async getExtensions(): Promise<WispExtensions | undefined> {
		let ret = await this._provider.get_extensions();
		if (ret) {
			return new WispExtensions(ret);
		}
	}
}

export class EitherSocketProvider extends Provider<
	EpxEitherSocketProvider,
	WasmProvider
> {
	constructor(
		selector: (host: string, port: number) => "left" | "right",
		left: SocketProvider,
		right: SocketProvider
	) {
		super(
			new EpxEitherSocketProvider(selector, left.provider, right.provider),
			(x) => x.box()
		);
	}
}

/* EXTENDED.START */
import {
	openSnowflakeStream,
	DEFAULT_SNOWFLAKE_FINGERPRINT,
	SnowflakeConfig,
} from "./tor/snowflake";

export type TorStorage = TorStateMgrCallbacks;

/** Backend selector for `TorSocketProvider`. Pass an existing
 *  `SocketProvider` to tunnel tor over your own transport, or pass
 *  `{ snowflake: SnowflakeConfig }` to use the built-in snowflake client.
 *
 *  The bare string `"snowflake"` is shorthand for `{ snowflake: {} }` and
 *  uses the built-in defaults (public broker + bridge). */
export type TorBackend =
	| Exclude<SocketProvider, TorSocketProvider>
	| "snowflake"
	| { snowflake: SnowflakeConfig };

// Address used in the bridge line when the underlying transport ignores
// (host, port) — snowflake routes everything to its single bridge regardless.
// 192.0.2.0/24 is RFC 5737 TEST-NET-1, so it can't conflict with real relays.
const SNOWFLAKE_FAKE_ADDR = "192.0.2.3:80";

function makeSnowflakeUnderlying(cfg: SnowflakeConfig): SocketProvider {
	return new JsSocketProvider(async (_host, _port) => openSnowflakeStream(cfg));
}

export class TorSocketProvider extends Provider<
	EpxTorSocketProvider,
	WasmProvider
> {
	constructor(backend: TorBackend, storage: TorStorage) {
		let underlying: SocketProvider;
		let bridges: string[] | undefined;
		if (backend === "snowflake") {
			underlying = makeSnowflakeUnderlying({});
			bridges = [`${SNOWFLAKE_FAKE_ADDR} ${DEFAULT_SNOWFLAKE_FINGERPRINT}`];
		} else if (
			typeof backend === "object" &&
			backend !== null &&
			"snowflake" in backend
		) {
			underlying = makeSnowflakeUnderlying(backend.snowflake);
			const fpr =
				backend.snowflake.fingerprint ?? DEFAULT_SNOWFLAKE_FINGERPRINT;
			bridges = [`${SNOWFLAKE_FAKE_ADDR} ${fpr}`];
		} else {
			// After the snowflake-shaped checks above, only the
			// `Exclude<SocketProvider, TorSocketProvider>` branch is left, but
			// TS doesn't narrow `{ snowflake: … }` away here.
			underlying = backend as Exclude<SocketProvider, TorSocketProvider>;
		}
		super(
			new EpxTorSocketProvider(underlying.provider, storage, bridges),
			(x) => x.box()
		);
	}

	async bootstrap() {
		await this._provider.bootstrap();
	}

	/** Subscribe to bootstrap progress. The callback fires with the current
	 *  snapshot synchronously, then again on every status change until the
	 *  provider is dropped. Calling this more than once replaces the previous
	 *  callback. */
	onProgress(cb: (progress: TorBootstrapProgress) => void) {
		this._provider.on_progress(cb as TorBootstrapCallback);
	}
}
/* EXTENDED.END */

export type SocketProvider =
	| JsSocketProvider
	| WispSocketProvider
	| EitherSocketProvider
	/* EXTENDED.START */
	| TorSocketProvider
	/* EXTENDED.END */;
