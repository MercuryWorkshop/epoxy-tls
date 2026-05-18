export const cmdSYN = 0;
export const cmdFIN = 1;
export const cmdPSH = 2;
export const cmdNOP = 3;
export const cmdUPD = 4;

export const sizeOfVer = 1;
export const sizeOfCmd = 1;
export const sizeOfLength = 2;
export const sizeOfSid = 4;
export const headerSize = sizeOfVer + sizeOfCmd + sizeOfSid + sizeOfLength;

export class Frame {
    ver: number;
    cmd: number;
    sid: number;
    data: Uint8Array;

    constructor(ver: number, cmd: number, sid: number, data?: Uint8Array) {
        this.ver = ver;
        this.cmd = cmd;
        this.sid = sid;
        this.data = data || new Uint8Array(0);
    }

    encode(buf: Uint8Array) {
        buf[0] = this.ver;
        buf[1] = this.cmd;
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        view.setUint16(2, this.data.length, true); // Little Endian
        view.setUint32(4, this.sid, true); // Little Endian
        if (this.data.length > 0) {
            buf.set(this.data, headerSize);
        }
    }
}
