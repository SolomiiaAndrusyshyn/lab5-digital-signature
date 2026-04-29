const { md5FromString } = require("./md5");

let lastBinaryResult = null;
let lastMode = "";

const w = 16;
const r = 8;
const b = 16;
const MOD = 65536;
const MASK = 65535;
const P = 0xB7E1;
const Q = 0x9E37;

function encryptFile() {
    const password = document.getElementById("passwordInput").value.trim();
    const file = document.getElementById("fileInput").files[0];
    const output = document.getElementById("output");

    if (!password || !file) {
        output.value = "Помилка: введіть пароль та виберіть файл.";
        return;
    }

    const reader = new FileReader();

    reader.onload = function (event) {
        try {
            const fileBytes = new Uint8Array(event.target.result);
            const keyBytes = hexStringToBytes(md5FromString(password));
            const S = generateS(keyBytes);

            const rawIv = new Uint8Array(4);
            window.crypto.getRandomValues(rawIv);

            const [encIvA, encIvB] = encryptBlock(
                rawIv[0] | (rawIv[1] << 8),
                rawIv[2] | (rawIv[3] << 8),
                S
            );

            const encryptedIvBlock = new Uint8Array([
                encIvA & 0xFF, encIvA >> 8,
                encIvB & 0xFF, encIvB >> 8
            ]);

            const paddedBytes = addPadding(fileBytes, 4);
            const encryptedData = encryptCBC(paddedBytes, S, rawIv);

            const finalBytes = new Uint8Array(encryptedIvBlock.length + encryptedData.length);
            finalBytes.set(encryptedIvBlock, 0);
            finalBytes.set(encryptedData, encryptedIvBlock.length);

            output.value = `Успішно зашифровано.\nIV (ECB) додано на початок.\nРозмір: ${finalBytes.length} байт.`;
            lastBinaryResult = finalBytes;
            lastMode = "encrypt";
        } catch (e) {
            output.value = "Помилка: " + e.message;
        }
    };

    reader.readAsArrayBuffer(file);
}

function decryptFile() {
    const password = document.getElementById("passwordInput").value.trim();
    const file = document.getElementById("fileInput").files[0];
    const output = document.getElementById("output");

    if (!password || !file) {
        return;
    }

    const reader = new FileReader();

    reader.onload = function (event) {
        try {
            const fileBytes = new Uint8Array(event.target.result);

            if (fileBytes.length < 8) {
                throw new Error("Файл занадто малий.");
            }

            const S = generateS(hexStringToBytes(md5FromString(password)));

            const [rawIvA, rawIvB] = decryptBlock(
                fileBytes[0] | (fileBytes[1] << 8),
                fileBytes[2] | (fileBytes[3] << 8),
                S
            );

            const rawIv = new Uint8Array([
                rawIvA & 0xFF, rawIvA >> 8,
                rawIvB & 0xFF, rawIvB >> 8
            ]);

            const encryptedData = fileBytes.slice(4);
            const decryptedPadded = decryptCBC(encryptedData, S, rawIv);
            const finalBytes = removePadding(decryptedPadded);

            output.value = `Успішно дешифровано за ТЗ.\nРозмір: ${finalBytes.length} байт.`;
            lastBinaryResult = finalBytes;
            lastMode = "decrypt";
        } catch (e) {
            output.value = "Помилка: " + e.message;
        }
    };

    reader.readAsArrayBuffer(file);
}

function rotl(x, y) {
    return ((x << (y % w)) | (x >>> (w - (y % w)))) & MASK;
}

function rotr(x, y) {
    return ((x >>> (y % w)) | (x << (w - (y % w)))) & MASK;
}

function generateS(K) {
    const L = new Array(b / 2).fill(0);

    for (let i = 0; i < b; i++) {
        L[Math.floor(i / 2)] |= (K[i] << (8 * (i % 2)));
    }

    const t = 2 * (r + 1);
    const S = new Array(t);

    S[0] = P;
    for (let i = 1; i < t; i++) {
        S[i] = (S[i - 1] + Q) & MASK;
    }

    let A = 0;
    let Bv = 0;
    let i = 0;
    let j = 0;
    const n = 3 * Math.max(t, L.length);

    for (let k = 0; k < n; k++) {
        A = S[i] = rotl((S[i] + A + Bv) & MASK, 3);
        Bv = L[j] = rotl((L[j] + A + Bv) & MASK, A + Bv);
        i = (i + 1) % t;
        j = (j + 1) % L.length;
    }

    return S;
}

function encryptBlock(A, Bv, S) {
    A = (A + S[0]) & MASK;
    Bv = (Bv + S[1]) & MASK;

    for (let i = 1; i <= r; i++) {
        A = (rotl(A ^ Bv, Bv) + S[2 * i]) & MASK;
        Bv = (rotl(Bv ^ A, A) + S[2 * i + 1]) & MASK;
    }

    return [A, Bv];
}

function decryptBlock(A, Bv, S) {
    for (let i = r; i >= 1; i--) {
        Bv = (rotr((Bv - S[2 * i + 1] + MOD) & MASK, A) ^ A) & MASK;
        A = (rotr((A - S[2 * i] + MOD) & MASK, Bv) ^ Bv) & MASK;
    }

    return [
        (A - S[0] + MOD) & MASK,
        (Bv - S[1] + MOD) & MASK
    ];
}

function encryptCBC(bytes, S, iv) {
    const res = new Uint8Array(bytes.length);
    let prev = iv;

    for (let i = 0; i < bytes.length; i += 4) {
        const block = bytes.slice(i, i + 4);
        const xored = new Uint8Array(4);

        for (let j = 0; j < 4; j++) {
            xored[j] = block[j] ^ prev[j];
        }

        const [encA, encB] = encryptBlock(
            xored[0] | (xored[1] << 8),
            xored[2] | (xored[3] << 8),
            S
        );

        const encrypted = new Uint8Array([
            encA & 0xFF, encA >> 8,
            encB & 0xFF, encB >> 8
        ]);

        res.set(encrypted, i);
        prev = encrypted;
    }

    return res;
}

function decryptCBC(bytes, S, iv) {
    const res = new Uint8Array(bytes.length);
    let prev = iv;

    for (let i = 0; i < bytes.length; i += 4) {
        const curr = bytes.slice(i, i + 4);

        const [decA, decB] = decryptBlock(
            curr[0] | (curr[1] << 8),
            curr[2] | (curr[3] << 8),
            S
        );

        const decrypted = new Uint8Array([
            decA & 0xFF, decA >> 8,
            decB & 0xFF, decB >> 8
        ]);

        for (let j = 0; j < 4; j++) {
            res[i + j] = decrypted[j] ^ prev[j];
        }

        prev = curr;
    }

    return res;
}

function addPadding(data, size) {
    const pad = size - (data.length % size);
    const res = new Uint8Array(data.length + pad);
    res.set(data);
    res.fill(pad, data.length);
    return res;
}

function removePadding(data) {
    const pad = data[data.length - 1];

    if (pad < 1 || pad > 4) {
        return data;
    }

    return data.slice(0, data.length - pad);
}

function hexStringToBytes(hex) {
    const result = [];

    for (let i = 0; i < hex.length; i += 2) {
        result.push(parseInt(hex.substr(i, 2), 16));
    }

    return result;
}

function saveResult() {
    if (!lastBinaryResult) {
        alert("Немає даних");
        return;
    }

    const blob = new Blob([lastBinaryResult], { type: "application/octet-stream" });
    const a = document.createElement("a");

    a.href = URL.createObjectURL(blob);
    a.download = lastMode === "encrypt" ? "encrypted.bin" : "decrypted.bin";
    a.click();
}

function clearAll() {
    document.getElementById("passwordInput").value = "";
    document.getElementById("fileInput").value = "";
    document.getElementById("output").value = "";
    lastBinaryResult = null;
    lastMode = "";
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        rotl,
        rotr,
        generateS,
        encryptBlock,
        decryptBlock,
        encryptCBC,
        decryptCBC,
        addPadding,
        removePadding,
        hexStringToBytes,
        encryptFile,
        decryptFile,
        saveResult,
        clearAll
    };
}