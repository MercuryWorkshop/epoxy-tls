import { Session } from './session';
import { Frame, cmdPSH, cmdFIN, cmdUPD } from './frame';

export class Stream {
    id: number;
    sess: Session;
    frameSize: number;

    // Buffers
    buffers: Uint8Array[] = [];

    // Notifications
    chReadEvent: (() => void)[] = [];
    chFinEvent: (() => void)[] = [];
    chUpdate: (() => void)[] = [];

    die: boolean = false;
    finEvent: boolean = false;

    // Flow control
    numRead: number = 0;
    numWritten: number = 0;
    incr: number = 0;

    peerConsumed: number = 0;
    peerWindow: number = 262144; // initialPeerWindow

    constructor(id: number, frameSize: number, sess: Session) {
        this.id = id;
        this.frameSize = frameSize;
        this.sess = sess;
    }

    // pushBytes appends data to buffers
    pushBytes(data: Uint8Array) {
        this.buffers.push(data);
        this.notifyReadEvent();
    }

    notifyReadEvent() {
        while (this.chReadEvent.length > 0) {
            const resolve = this.chReadEvent.shift();
            if (resolve) resolve();
        }
    }

    notifyFinEvent() {
        this.finEvent = true;
        while (this.chFinEvent.length > 0) {
            const resolve = this.chFinEvent.shift();
            if (resolve) resolve();
        }
        // Also wake up readers
        this.notifyReadEvent();
    }

    notifyUpdateEvent() {
        while (this.chUpdate.length > 0) {
            const resolve = this.chUpdate.shift();
            if (resolve) resolve();
        }
    }

    fin() {
        if (!this.finEvent) {
            this.notifyFinEvent();
        }
    }

    update(consumed: number, window: number) {
        this.peerConsumed = consumed;
        this.peerWindow = window;
        this.notifyUpdateEvent();
    }

    async read(b: Uint8Array): Promise<number> {
        while (true) {
            if (this.buffers.length > 0) {
                const buf = this.buffers[0];
                const n = Math.min(b.length, buf.length);
                b.set(buf.subarray(0, n));

                if (n === buf.length) {
                    this.buffers.shift();
                } else {
                    this.buffers[0] = buf.subarray(n);
                }

                // Return tokens to session
                this.sess.returnTokens(n);

                // Window update logic (v2)
                this.numRead += n;
                this.incr += n;

                if (this.incr >= this.sess.config.maxStreamBuffer / 2 || this.numRead === n) {
                    const notifyConsumed = this.numRead;
                    this.incr = 0;
                    await this.sendWindowUpdate(notifyConsumed);
                }

                return n;
            }

            if (this.finEvent) {
                return 0; // EOF
            }

            if (this.die) {
                throw new Error("stream closed");
            }

            await new Promise<void>(resolve => this.chReadEvent.push(resolve));
        }
    }

    async write(b: Uint8Array): Promise<number> {
        if (this.finEvent) throw new Error("closed");
        if (this.die) throw new Error("stream closed");

        let sent = 0;
        let bts = b;

        while (bts.length > 0) {
            // Flow control
            const inflight = this.numWritten - this.peerConsumed;
            const win = this.peerWindow - inflight;

            if (win > 0) {
                const size = Math.min(bts.length, win);
                const chunk = bts.subarray(0, size);
                bts = bts.subarray(size);

                // Split into frames
                let offset = 0;
                while (offset < chunk.length) {
                    const sz = Math.min(chunk.length - offset, this.frameSize);
                    const frameData = chunk.subarray(offset, offset + sz);
                    const frame = new Frame(this.sess.config.version, cmdPSH, this.id, frameData);

                    await this.sess.writeFrame(frame);

                    this.numWritten += sz;
                    sent += sz;
                    offset += sz;
                }
            } else {
                // Wait for window update
                await new Promise<void>(resolve => this.chUpdate.push(resolve));
                if (this.die || this.finEvent) throw new Error("closed");
            }
        }
        return sent;
    }

    async sendWindowUpdate(consumed: number) {
        const frame = new Frame(this.sess.config.version, cmdUPD, this.id);
        const buf = new Uint8Array(8);
        const view = new DataView(buf.buffer);
        view.setUint32(0, consumed, true);
        view.setUint32(4, this.sess.config.maxStreamBuffer, true);
        frame.data = buf;
        await this.sess.writeFrame(frame);
    }

    async close() {
        if (this.die) return;
        this.die = true;

        // Send FIN
        const frame = new Frame(this.sess.config.version, cmdFIN, this.id);
        await this.sess.writeFrame(frame);

        this.sess.streamClosed(this.id);
        this.notifyReadEvent();
        this.notifyUpdateEvent();
    }
}
