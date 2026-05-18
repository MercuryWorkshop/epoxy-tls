import { KCP, IKCP_OVERHEAD } from './kcp';
import { log } from '../logger';

export interface PacketConn {
    readFrom(buf: Uint8Array): Promise<{ n: number; addr: any; err: Error | null }>;
    writeTo(buf: Uint8Array, addr: any): Promise<{ n: number; err: Error | null }>;
    close(): Promise<void>;
    localAddr(): any;
}

export class UDPSession {
    kcp: KCP;
    conn: PacketConn;
    recvbuf: Uint8Array;
    bufptr: Uint8Array | null = null;

    // Settings
    mtuLimit: number = 1500;
    headerSize: number = 0;
    ackNoDelay: boolean = false;
    writeDelay: boolean = false;

    // Notifications
    die: boolean = false;
    chReadEvent: (() => void)[] = [];
    chWriteEvent: (() => void)[] = [];

    // Update loop
    updateTimer: any | null = null;

    constructor(conv: number, conn: PacketConn) {
        this.conn = conn;
        this.recvbuf = new Uint8Array(this.mtuLimit);

        this.kcp = new KCP(conv, (buf: Uint8Array, size: number) => {
            if (size >= IKCP_OVERHEAD) {
                // In Go, xmitBuf is used. Here we just copy.
                // The buffer passed by KCP is internal, so we must copy if we want to be safe,
                // or just send it directly if writeTo handles it immediately.
                // writeTo is async, so we MUST copy.
                const pkt = new Uint8Array(buf.subarray(0, size));
                // log(`[KCP] Sending packet size ${size}`);
                this.conn.writeTo(pkt, null).catch(e => {
                    console.error("writeTo error:", e);
                });
            }
        });
        this.kcp.stream = 1; // Enable stream mode to match server

        // Start update loop
        this.update();

        // Start read loop
        this.readLoop();
    }

    private update() {
        if (this.die) return;

        this.kcp.update();
        const interval = this.kcp.check();
        let next = interval - KCP.currentMs();
        if (next < 10) next = 10;

        this.updateTimer = setTimeout(() => {
            this.update();
        }, next);
    }

    private async readLoop() {
        const buf = new Uint8Array(this.mtuLimit);
        while (!this.die) {
            try {
                const { n, err } = await this.conn.readFrom(buf);
                if (err) {
                    console.error("readLoop error:", err);
                    // If EOF or closed, break
                    break;
                }
                if (n > 0) {
                    this.kcp.input(buf.subarray(0, n), true, this.ackNoDelay);
                    this.notifyReadEvent();
                }
            } catch (e) {
                console.error("readLoop exception:", e);
                break;
            }
        }
    }

    notifyReadEvent() {
        while (this.chReadEvent.length > 0) {
            const resolve = this.chReadEvent.shift();
            if (resolve) resolve();
        }
    }

    notifyWriteEvent() {
        while (this.chWriteEvent.length > 0) {
            const resolve = this.chWriteEvent.shift();
            if (resolve) resolve();
        }
    }

    async read(b: Uint8Array): Promise<number> {
        while (true) {
            if (this.die) throw new Error("closed");

            // If we have remaining data in bufptr
            if (this.bufptr && this.bufptr.length > 0) {
                const n = Math.min(b.length, this.bufptr.length);
                b.set(this.bufptr.subarray(0, n));
                this.bufptr = this.bufptr.subarray(n);
                if (this.bufptr.length === 0) this.bufptr = null;
                return n;
            }

            const size = this.kcp.peekSize();
            if (size > 0) {
                if (b.length >= size) {
                    this.kcp.recv(b);
                    return size;
                }

                // Buffer too small, read into internal buffer
                if (this.recvbuf.length < size) {
                    this.recvbuf = new Uint8Array(size);
                }
                this.kcp.recv(this.recvbuf);
                const n = Math.min(b.length, size);
                b.set(this.recvbuf.subarray(0, n));
                this.bufptr = this.recvbuf.subarray(n, size); // Save remainder
                return n;
            }

            // Wait for data
            await new Promise<void>(resolve => this.chReadEvent.push(resolve));
        }
    }

    async write(b: Uint8Array): Promise<number> {
        // Simple implementation, blocking if window full
        let n = 0;
        while (true) {
            if (this.die) throw new Error("closed");

            const waitsnd = this.kcp.waitSnd();
            if (waitsnd < this.kcp.snd_wnd && waitsnd < this.kcp.rmt_wnd) {
                this.kcp.send(b);
                n = b.length;

                if (this.kcp.waitSnd() >= this.kcp.snd_wnd ||
                    this.kcp.waitSnd() >= this.kcp.rmt_wnd ||
                    !this.writeDelay) {
                    log(`[KCP] Flushing (waitSnd=${this.kcp.waitSnd()}, snd_wnd=${this.kcp.snd_wnd}, rmt_wnd=${this.kcp.rmt_wnd})`);
                    this.kcp.flush(false);
                }
                return n;
            }

            // Wait for write window
            log(`[KCP] Waiting for write window (waitSnd=${this.kcp.waitSnd()})`);
            await new Promise<void>(resolve => this.chWriteEvent.push(resolve));
        }
    }

    async close(): Promise<void> {
        if (this.die) return;
        this.die = true;
        if (this.updateTimer) clearTimeout(this.updateTimer);

        // Flush pending
        this.kcp.flush(false);

        await this.conn.close();

        // Wake up readers/writers
        this.notifyReadEvent();
        this.notifyWriteEvent();
    }

    // Configuration methods
    setWindowSize(sndwnd: number, rcvwnd: number) {
        this.kcp.wndSize(sndwnd, rcvwnd);
    }

    setNoDelay(nodelay: number, interval: number, resend: number, nc: number) {
        this.kcp.setNoDelay(nodelay, interval, resend, nc);
    }

    setMtu(mtu: number) {
        this.kcp.setMtu(mtu);
        this.mtuLimit = mtu;
    }

    setACKNoDelay(nodelay: boolean) {
        this.ackNoDelay = nodelay;
    }

    setWriteDelay(delay: boolean) {
        this.writeDelay = delay;
    }
}
