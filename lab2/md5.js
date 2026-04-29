function stringToBytes(text) {
    if (typeof TextEncoder !== "undefined") {
        return new TextEncoder().encode(text);
    }

    if (typeof Buffer !== "undefined") {
        return Uint8Array.from(Buffer.from(text, "utf8"));
    }

    const bytes = [];
    for (let i = 0; i < text.length; i++) {
        bytes.push(text.charCodeAt(i) & 0xff);
    }
    return new Uint8Array(bytes);
}

function md5FromString(text) {
    const bytes = stringToBytes(text);
    return md5FromBytes(bytes);
}

function md5FromBytes(inputBytes) {
    const bytes = addPadding(inputBytes);

    let A0 = 0x67452301;
    let B0 = 0xefcdab89;
    let C0 = 0x98badcfe;
    let D0 = 0x10325476;

    const S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];

    const K = [];
    for (let i = 0; i < 64; i++) {
        K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
    }

    for (let offset = 0; offset < bytes.length; offset += 64) {
        const M = [];

        for (let i = 0; i < 16; i++) {
            const index = offset + i * 4;
            M[i] =
                (bytes[index]) |
                (bytes[index + 1] << 8) |
                (bytes[index + 2] << 16) |
                (bytes[index + 3] << 24);

            M[i] = M[i] >>> 0;
        }

        let A = A0;
        let B = B0;
        let C = C0;
        let D = D0;

        for (let i = 0; i < 64; i++) {
            let F;
            let g;

            if (i <= 15) {
                F = (B & C) | ((~B) & D);
                g = i;
            } else if (i <= 31) {
                F = (D & B) | ((~D) & C);
                g = (5 * i + 1) % 16;
            } else if (i <= 47) {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            } else {
                F = C ^ (B | (~D));
                g = (7 * i) % 16;
            }

            F = F >>> 0;

            const tempD = D;
            D = C;
            C = B;

            const sum1 = addUnsigned(A, F);
            const sum2 = addUnsigned(sum1, K[i]);
            const sum3 = addUnsigned(sum2, M[g]);
            const rotated = leftRotate(sum3, S[i]);

            B = addUnsigned(B, rotated);
            A = tempD;
        }

        A0 = addUnsigned(A0, A);
        B0 = addUnsigned(B0, B);
        C0 = addUnsigned(C0, C);
        D0 = addUnsigned(D0, D);
    }

    return (
        wordToHex(A0) +
        wordToHex(B0) +
        wordToHex(C0) +
        wordToHex(D0)
    ).toUpperCase();
}

function addPadding(inputBytes) {
    const originalLength = inputBytes.length;
    const bitLength = BigInt(originalLength) * 8n;

    let paddedLength = originalLength + 1;

    while (paddedLength % 64 !== 56) {
        paddedLength++;
    }

    const result = new Uint8Array(paddedLength + 8);

    for (let i = 0; i < originalLength; i++) {
        result[i] = inputBytes[i];
    }

    result[originalLength] = 0x80;

    for (let i = 0; i < 8; i++) {
        result[paddedLength + i] = Number((bitLength >> BigInt(8 * i)) & 0xFFn);
    }

    return result;
}

function leftRotate(x, c) {
    return ((x << c) | (x >>> (32 - c))) >>> 0;
}

function addUnsigned(x, y) {
    return ((x >>> 0) + (y >>> 0)) >>> 0;
}

function wordToHex(word) {
    let result = "";

    for (let i = 0; i < 4; i++) {
        const byte = (word >>> (8 * i)) & 0xff;
        let hex = byte.toString(16);

        if (hex.length < 2) {
            hex = "0" + hex;
        }

        result += hex;
    }

    return result;
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        stringToBytes,
        md5FromString,
        md5FromBytes,
        addPadding,
        leftRotate,
        addUnsigned,
        wordToHex
    };
}