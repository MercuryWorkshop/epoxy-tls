export class Encapsulation {
    static writeData(data: Uint8Array): Uint8Array {
        const prefix = this.dataPrefixForLength(data.length);
        const buf = new Uint8Array(prefix.length + data.length);
        buf.set(prefix);
        buf.set(data, prefix.length);
        return buf;
    }

    static dataPrefixForLength(length: number): Uint8Array {
        if (length < 0) throw new Error("negative length");

        // 1 byte: 0x80 | length (if length < 64)
        if (length < 64) {
            return new Uint8Array([0x80 | length]);
        }

        // 2 bytes: 0xC0 | (length >> 7), length & 0x7f (if length < 8192)
        if (length < 8192) {
            return new Uint8Array([
                0xC0 | (length >>> 7),
                length & 0x7f
            ]);
        }

        // 3 bytes: 0xC0 | (length >> 14), 0x80 | ((length >> 7) & 0x7f), length & 0x7f
        if (length < 1048576) {
            return new Uint8Array([
                0xC0 | (length >>> 14),
                0x80 | ((length >>> 7) & 0x7f),
                length & 0x7f
            ]);
        }

        throw new Error("length too large");
    }

    // Reads one chunk of data from the buffer.
    // Returns { data: Uint8Array, consumed: number } or null if not enough data.
    static readData(buf: Uint8Array): { data: Uint8Array; consumed: number } | null {
        if (buf.length === 0) return null;

        let offset = 0;
        // We need to skip padding chunks until we find a data chunk
        while (offset < buf.length) {
            const b0 = buf[offset];
            const isData = (b0 & 0x80) !== 0;
            let moreLength = (b0 & 0x40) !== 0;
            let length = b0 & 0x3f;
            let headerLen = 1;

            // Read continuation bytes for length
            while (moreLength) {
                if (offset + headerLen >= buf.length) return null; // Need more data for header
                const nextByte = buf[offset + headerLen];
                headerLen++;

                if (headerLen > 3) throw new Error("length prefix too long");

                moreLength = (nextByte & 0x80) !== 0; // Note: Go impl uses 0x80 as continuation for subsequent bytes?
                // Wait, let's check Go impl again.
                // Go: "If the continuation bit is set, then the next byte is also part of the length prefix. It lacks the "d" bit, has its own "c" bit, and 7 value-carrying bits ("y")."
                // Go code:
                // moreLength = (b[0] & 0x80) != 0  <-- Wait, inside the loop, b[0] is the NEW byte.
                // n = (n << 7) | int(b[0]&0x7f)

                // So for subsequent bytes:
                // bit 7 (0x80) is the continuation bit (c).
                // bits 0-6 (0x7f) are value bits.

                length = (length << 7) | (nextByte & 0x7f);
                moreLength = (nextByte & 0x80) !== 0;
            }

            const totalLen = headerLen + length;
            if (offset + totalLen > buf.length) return null; // Need more data for body

            if (isData) {
                return {
                    data: buf.subarray(offset + headerLen, offset + totalLen),
                    consumed: offset + totalLen
                };
            } else {
                // Padding, skip it and continue
                offset += totalLen;
            }
        }

        return null; // Only padding found or empty
    }
}
