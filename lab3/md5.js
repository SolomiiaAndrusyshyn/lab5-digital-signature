function md5FromString(text) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text);
    return md5FromBytes(bytes);
}

function md5FromBytes(inputBytes) {
    const bytes = md5ApplyPadding(inputBytes);
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
            const idx = offset + i * 4;
            M[i] =
                (bytes[idx]) |
                (bytes[idx + 1] << 8) |
                (bytes[idx + 2] << 16) |
                (bytes[idx + 3] << 24);
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

            const temp = D;
            D = C;
            C = B;

            const sum = md5Add(md5Add(md5Add(A, F >>> 0), K[i]), M[g] >>> 0);
            B = md5Add(B, ((sum << S[i]) | (sum >>> (32 - S[i]))) >>> 0);
            A = temp;
        }

        A0 = md5Add(A0, A);
        B0 = md5Add(B0, B);
        C0 = md5Add(C0, C);
        D0 = md5Add(D0, D);
    }

    return (md5Hex(A0) + md5Hex(B0) + md5Hex(C0) + md5Hex(D0)).toUpperCase();
}

function md5ApplyPadding(input) {
    const len = input.length;
    const bitLen = BigInt(len) * 8n;
    let padLen = len + 1;

    while (padLen % 64 !== 56) {
        padLen++;
    }

    const res = new Uint8Array(padLen + 8);
    res.set(input);
    res[len] = 0x80;

    for (let i = 0; i < 8; i++) {
        res[padLen + i] = Number((bitLen >> BigInt(8 * i)) & 0xFFn);
    }

    return res;
}

function md5Add(x, y) {
    return ((x >>> 0) + (y >>> 0)) >>> 0;
}

function md5Hex(w) {
    let s = "";

    for (let i = 0; i < 4; i++) {
        let h = ((w >>> (8 * i)) & 0xff).toString(16);
        s += h.length < 2 ? "0" + h : h;
    }

    return s;
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        md5FromString,
        md5FromBytes,
        md5ApplyPadding,
        md5Add,
        md5Hex
    };
}