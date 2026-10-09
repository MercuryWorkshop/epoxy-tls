import {
	EitherSocketProvider as EpxEitherSocketProvider,
	JsProvider as EpxJsProvider,
	WispProvider as EpxWispProvider,
	JsWispV2Handshake,
	ProtocolExtensionBuilders,
	WasmProvider,
	WasmWispProvider,
} from "epoxy/wbg";
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
		func: (
			host: string,
			protocol?: string
		) => Promise<ProviderResult> | ProviderResult
	) {
		super(
			new EpxJsProvider(
				async (host, protocol) =>
					await func(host, protocol as string | undefined)
			),
			(x) => x.box_wisp()
		);
	}
}

export class WebSocketJsProvider extends JsProvider {
	constructor() {
		super(async (host, protocol) => {
			let stream = new WebSocketStream<Uint8Array<ArrayBuffer>>(host, {
				protocols: protocol ? [protocol] : [],
			});
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
			new EpxJsProvider(async (host, port) => await func(host, port as number)),
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
	// ids of extensions the server must support, each must also have a builder in `builders`
	requiredExts?: number[];
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
		connectionPrefs?: () => WispV2Handshake | undefined
	) {
		let v2;
		if (connectionPrefs) {
			v2 = () => {
				let v2 = connectionPrefs();

				let handshake: JsWispV2Handshake | undefined;
				if (v2) {
					let required = v2.requiredExts ?? [];
					let ids = new Set(v2.builders.map((x) => x.id));
					let missing = required.filter((x) => !ids.has(x));
					if (missing.length > 0)
						throw new Error(
							`required extensions have no builder: ${missing.join(", ")}`
						);

					let builders = new ProtocolExtensionBuilders();
					for (let builder of v2.builders) {
						builder.appendTo(builders);
					}
					handshake = new JsWispV2Handshake(
						builders,
						new Uint8Array(required),
						async () => {}
					);
				}

				return handshake;
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

export type SocketProvider =
	| JsSocketProvider
	| WispSocketProvider
	| EitherSocketProvider;
