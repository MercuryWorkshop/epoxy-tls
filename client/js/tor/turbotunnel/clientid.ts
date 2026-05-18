export class ClientID {
    id: Uint8Array;

    constructor(id?: Uint8Array) {
        if (id) {
            if (id.length !== 8) throw new Error("invalid client id length");
            this.id = id;
        } else {
            this.id = new Uint8Array(8);
            if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
                crypto.getRandomValues(this.id);
            } else if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
                window.crypto.getRandomValues(this.id);
            } else {
                // Fallback for non-secure random if crypto is missing (shouldn't happen in modern browsers)
                for (let i = 0; i < 8; i++) {
                    this.id[i] = Math.floor(Math.random() * 256);
                }
            }
        }
    }

    toString(): string {
        return Array.from(this.id)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    static New(): ClientID {
        return new ClientID();
    }
}
