export class RingBuffer<T> {
    private head: number = 0;
    private tail: number = 0;
    private elements: (T | undefined)[];

    private static readonly MIN_SIZE = 8;
    private static readonly EXP_THRESHOLD = 1024;

    constructor(size: number) {
        if (size <= RingBuffer.MIN_SIZE) {
            size = RingBuffer.MIN_SIZE;
        }
        this.elements = new Array(size);
    }

    public len(): number {
        if (this.head <= this.tail) {
            return this.tail - this.head;
        }
        return (this.elements.length - this.head) + this.tail;
    }

    public push(v: T): void {
        if (this.isFull()) {
            this.grow();
        }
        this.elements[this.tail] = v;
        this.tail = (this.tail + 1) % this.elements.length;
    }

    public pop(): T | undefined {
        if (this.len() === 0) {
            return undefined;
        }
        const value = this.elements[this.head];
        this.elements[this.head] = undefined;
        this.head = (this.head + 1) % this.elements.length;
        return value;
    }

    public peek(): T | undefined {
        if (this.len() === 0) {
            return undefined;
        }
        return this.elements[this.head];
    }

    public discard(n: number): number {
        const length = this.len();
        if (n > length) {
            n = length;
        }
        if (n === length) {
            this.clear();
            return n;
        }
        for (let i = 0; i < n; i++) {
            this.elements[this.head] = undefined;
            this.head = (this.head + 1) % this.elements.length;
        }
        return n;
    }

    public forEach(fn: (item: T) => boolean | void): void {
        if (this.len() === 0) {
            return;
        }
        if (this.head < this.tail) {
            for (let i = this.head; i < this.tail; i++) {
                if (fn(this.elements[i] as T) === false) return;
            }
        } else {
            for (let i = this.head; i < this.elements.length; i++) {
                if (fn(this.elements[i] as T) === false) return;
            }
            for (let i = 0; i < this.tail; i++) {
                if (fn(this.elements[i] as T) === false) return;
            }
        }
    }

    public forEachReverse(fn: (item: T) => boolean | void): void {
        if (this.len() === 0) {
            return;
        }
        if (this.head < this.tail) {
            for (let i = this.tail - 1; i >= this.head; i--) {
                if (fn(this.elements[i] as T) === false) return;
            }
        } else {
            for (let i = this.tail - 1; i >= 0; i--) {
                if (fn(this.elements[i] as T) === false) return;
            }
            for (let i = this.elements.length - 1; i >= this.head; i--) {
                if (fn(this.elements[i] as T) === false) return;
            }
        }
    }

    public clear(): void {
        this.head = 0;
        this.tail = 0;
        this.elements.fill(undefined);
    }

    public isEmpty(): boolean {
        return this.len() === 0;
    }

    public maxLen(): number {
        return this.elements.length - 1;
    }

    public isFull(): boolean {
        return (this.tail + 1) % this.elements.length === this.head;
    }

    private grow(): void {
        const currentLength = this.len();
        const currentSize = this.elements.length;
        let newSize: number;

        if (currentSize < RingBuffer.MIN_SIZE) {
            newSize = RingBuffer.MIN_SIZE;
        } else if (currentSize < RingBuffer.EXP_THRESHOLD) {
            newSize = currentSize * 2;
        } else {
            newSize = currentSize + Math.ceil(currentSize / 10);
        }

        const newElements = new Array(newSize);

        if (this.head < this.tail) {
            for (let i = 0; i < currentLength; i++) {
                newElements[i] = this.elements[this.head + i];
            }
        } else {
            let idx = 0;
            for (let i = this.head; i < currentSize; i++) {
                newElements[idx++] = this.elements[i];
            }
            for (let i = 0; i < this.tail; i++) {
                newElements[idx++] = this.elements[i];
            }
        }

        this.head = 0;
        this.tail = currentLength;
        this.elements = newElements;
    }
}
