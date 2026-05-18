export interface WebSocketConnection<
	T extends Uint8Array<ArrayBuffer> | string = Uint8Array<ArrayBuffer> | string,
> {
	readable: ReadableStream<T>;
	writable: WritableStream<T>;
	protocol: string;
	extensions: string;
}

export interface WebSocketCloseInfo {
	closeCode?: number;
	reason?: string;
}

export interface WebSocketStreamOptions {
	protocols?: string[];
	signal?: AbortSignal;
}

export class WebSocketStream<
	T extends Uint8Array<ArrayBuffer> | string = Uint8Array<ArrayBuffer> | string,
> {
	readonly url: string;

	readonly opened: Promise<WebSocketConnection<T>>;

	readonly closed: Promise<WebSocketCloseInfo>;

	readonly close: (closeInfo?: WebSocketCloseInfo) => void;

	constructor(url: string, options: WebSocketStreamOptions = {}) {
		if (options.signal?.aborted) {
			throw new DOMException("This operation was aborted", "AbortError");
		}

		this.url = url;

		const ws = new WebSocket(url, options.protocols ?? []);

		ws.binaryType = "arraybuffer";

		const closeWithInfo = ({
			closeCode: code,
			reason,
		}: WebSocketCloseInfo = {}) => ws.close(code, reason);

		this.opened = new Promise((resolve, reject) => {
			ws.onopen = () => {
				resolve({
					readable: new ReadableStream<T>({
						start(controller) {
							ws.onmessage = ({ data }) =>
								controller.enqueue(
									(typeof data === "string"
										? data
										: new Uint8Array(data)) as any
								);
							ws.onerror = (e) => controller.error(e);
						},
						cancel: closeWithInfo,
					}),
					writable: new WritableStream<T>({
						write(chunk) {
							// Calling send() on a CLOSING/CLOSED ws prints a
							// console warning. Reject the write so the upper
							// layer (e.g. wisp mux) sees the close and stops
							// pushing more frames into a dead socket.
							if (ws.readyState !== WebSocket.OPEN) {
								throw new DOMException(
									"WebSocket is closed",
									"InvalidStateError"
								);
							}
							ws.send(chunk);
						},
						abort() {
							ws.close();
						},
						close: closeWithInfo,
					}),
					protocol: ws.protocol,
					extensions: ws.extensions,
				});
				ws.removeEventListener("error", reject);
			};
			ws.addEventListener("error", reject);
		});

		this.closed = new Promise<WebSocketCloseInfo>((resolve, reject) => {
			ws.onclose = ({ code, reason }) => {
				resolve({ closeCode: code, reason });
				ws.removeEventListener("error", reject);
			};
			ws.addEventListener("error", reject);
		});

		if (options.signal) {
			options.signal.onabort = () => ws.close();
		}

		this.close = closeWithInfo;
	}
}
