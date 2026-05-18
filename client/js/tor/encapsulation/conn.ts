import { type PacketConn } from '../kcp/sess';
import { Encapsulation } from './encapsulation';
import { log } from '../logger';

export class EncapsulatedPacketConn implements PacketConn {
    conn: PacketConn;
    readBuf: Uint8Array = new Uint8Array(0);

    constructor(conn: PacketConn) {
        this.conn = conn;
    }

    async readFrom(buf: Uint8Array): Promise<{ n: number; addr: any; err: Error | null }> {
        // We need to return one packet (payload)
        // But readFrom might be called with a small buffer?
        // KCP usually reads MTU size.

        // If we have data in readBuf, try to parse it
        while (true) {
            if (this.readBuf.length > 0) {
                const result = Encapsulation.readData(this.readBuf);
                if (result) {
                    const { data, consumed } = result;
                    this.readBuf = this.readBuf.subarray(consumed);

                    if (data.length > buf.length) {
                        // This is bad, the buffer provided is too small for the packet
                        // But KCP should provide MTU-sized buffer.
                        // We copy what fits? Or error?
                        // Let's copy what fits and warn.
                        log(`[Encapsulation] Warning: Read buffer too small (${buf.length} < ${data.length})`);
                        buf.set(data.subarray(0, buf.length));
                        return { n: buf.length, addr: null, err: null };
                    }

                    buf.set(data);
                    return { n: data.length, addr: null, err: null };
                }
                // Not enough data for a full packet, need to read more
            }

            // Read from underlying conn
            const tmp = new Uint8Array(4096); // Read a chunk
            const { n, err } = await this.conn.readFrom(tmp);
            if (err) return { n: 0, addr: null, err };
            if (n === 0) continue; // Should not happen unless EOF

            // Append to readBuf
            const newBuf = new Uint8Array(this.readBuf.length + n);
            newBuf.set(this.readBuf);
            newBuf.set(tmp.subarray(0, n), this.readBuf.length);
            this.readBuf = newBuf;
        }
    }

    async writeTo(buf: Uint8Array, addr: any): Promise<{ n: number; err: Error | null }> {
        const encapsulated = Encapsulation.writeData(buf);
        // log(`[Encapsulation] Encapsulating ${buf.length} bytes -> ${encapsulated.length} bytes`);
        const { n, err } = await this.conn.writeTo(encapsulated, addr);
        if (err) return { n: 0, err };
        // We return the number of bytes *of the payload* written, to satisfy the interface?
        // Or the bytes written to the wire?
        // Usually the caller expects 'n' to match 'buf.length' if successful.
        return { n: buf.length, err: null };
    }

    async close(): Promise<void> {
        return this.conn.close();
    }

    localAddr(): any {
        return this.conn.localAddr();
    }
}
