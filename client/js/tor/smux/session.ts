import { Frame, cmdSYN, cmdFIN, cmdPSH, cmdNOP, cmdUPD, headerSize } from './frame';
import { Stream } from './stream';
// import { log } from '../pt/logger';

export interface Config {
    version: number;
    keepAliveInterval: number;
    keepAliveTimeout: number;
    maxFrameSize: number;
    maxReceiveBuffer: number;
    maxStreamBuffer: number;
}

export const DefaultConfig: Config = {
    version: 1,
    keepAliveInterval: 10000,
    keepAliveTimeout: 30000,
    maxFrameSize: 32768,
    maxReceiveBuffer: 4194304,
    maxStreamBuffer: 65536,
};

export interface Connection {
    read(b: Uint8Array): Promise<number>;
    write(b: Uint8Array): Promise<number>;
    close(): Promise<void>;
}

export class Session {
    conn: Connection;
    config: Config;

    nextStreamID: number;
    streams: Map<number, Stream> = new Map();

    bucket: number;
    bucketNotify: (() => void)[] = [];

    die: boolean = false;
    chAccepts: ((stream: Stream) => void)[] = [];

    constructor(conn: Connection, client: boolean, config: Config = DefaultConfig) {
        this.conn = conn;
        this.config = config;
        this.bucket = config.maxReceiveBuffer;

        this.nextStreamID = client ? 1 : 0;

        this.recvLoop();
        if (config.keepAliveInterval > 0) {
            this.keepAlive();
        }
    }

    async openStream(): Promise<Stream> {
        if (this.die) throw new Error("session closed");

        const id = this.nextStreamID;
        this.nextStreamID += 2;

        const stream = new Stream(id, this.config.maxFrameSize, this);
        this.streams.set(id, stream);

        const frame = new Frame(this.config.version, cmdSYN, id);
        await this.writeFrame(frame);

        return stream;
    }

    async acceptStream(): Promise<Stream> {
        if (this.die) throw new Error("session closed");

        return new Promise<Stream>((resolve, reject) => {
            this.chAccepts.push(resolve);
        });
    }

    async writeFrame(frame: Frame) {
        const buf = new Uint8Array(headerSize + frame.data.length);
        frame.encode(buf);
        await this.conn.write(buf);
    }

    async recvLoop() {
        const headerBuf = new Uint8Array(headerSize);

        try {
            while (!this.die) {
                // Read header
                let n = 0;
                while (n < headerSize) {
                    const read = await this.conn.read(headerBuf.subarray(n));
                    if (read === 0) throw new Error("EOF");
                    n += read;
                }

                const view = new DataView(headerBuf.buffer, headerBuf.byteOffset, headerSize);
                const ver = headerBuf[0];
                const cmd = headerBuf[1];
                const length = view.getUint16(2, true);
                const sid = view.getUint32(4, true);

                if (ver !== this.config.version) {
                    throw new Error("invalid protocol version");
                }

                if (cmd === cmdNOP) {
                    continue;
                }

                if (cmd === cmdSYN) {
                    if (!this.streams.has(sid)) {
                        const stream = new Stream(sid, this.config.maxFrameSize, this);
                        this.streams.set(sid, stream);
                        const resolve = this.chAccepts.shift();
                        if (resolve) resolve(stream);
                    }
                    continue;
                }

                if (cmd === cmdFIN) {
                    const stream = this.streams.get(sid);
                    if (stream) {
                        stream.fin();
                    }
                    continue;
                }

                if (cmd === cmdPSH) {
                    if (length > 0) {
                        const data = new Uint8Array(length);
                        let readLen = 0;
                        while (readLen < length) {
                            const r = await this.conn.read(data.subarray(readLen));
                            if (r === 0) throw new Error("EOF");
                            readLen += r;
                        }

                        const stream = this.streams.get(sid);
                        if (stream) {
                            stream.pushBytes(data);
                            this.bucket -= length;
                        }
                    }
                    continue;
                }

                if (cmd === cmdUPD) {
                    const data = new Uint8Array(8);
                    let readLen = 0;
                    while (readLen < 8) {
                        const r = await this.conn.read(data.subarray(readLen));
                        if (r === 0) throw new Error("EOF");
                        readLen += r;
                    }

                    const updView = new DataView(data.buffer);
                    const consumed = updView.getUint32(0, true);
                    const window = updView.getUint32(4, true);

                    const stream = this.streams.get(sid);
                    if (stream) {
                        stream.update(consumed, window);
                    }
                    continue;
                }
            }
        } catch (e) {
            console.error("recvLoop error:", e);
            this.close();
        }
    }

    async keepAlive() {
        while (!this.die) {
            await new Promise(r => setTimeout(r, this.config.keepAliveInterval));
            try {
                const frame = new Frame(this.config.version, cmdNOP, 0);
                await this.writeFrame(frame);
            } catch (e) {
                console.error("keepAlive error:", e);
                this.close();
                break;
            }
        }
    }

    async close() {
        if (this.die) return;
        this.die = true;

        this.streams.forEach(s => s.close());
        this.streams.clear();

        await this.conn.close();
    }

    streamClosed(sid: number) {
        this.streams.delete(sid);
    }

    returnTokens(n: number) {
        this.bucket += n;
        // Notify if needed (not fully implemented in this simplified version)
    }
}
