let rsaKeyPair = null;


async function generateRSA() {
    rsaKeyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function rsaEncryptBlock(data) {
    return await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.publicKey,
        data
    );
}

async function rsaDecryptBlock(data) {
    return await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.privateKey,
        data
    );
}

async function rsaEncryptBytes(fileBytes) {
    const blockSize = 190; 
    const encryptedBlocks = [];

    for (let i = 0; i < fileBytes.length; i += blockSize) {
        const block = fileBytes.slice(i, i + blockSize);
        const encrypted = await rsaEncryptBlock(block);
        encryptedBlocks.push(new Uint8Array(encrypted));
    }

    const result = new Uint8Array(encryptedBlocks.length * 256);
    let offset = 0;

    for (const block of encryptedBlocks) {
        result.set(block, offset);
        offset += 256;
    }

    return result;
}

async function rsaDecryptBytes(encryptedBytes) {
    const blockSize = 256; 
    const decryptedBlocks = [];

    for (let i = 0; i < encryptedBytes.length; i += blockSize) {
        const block = encryptedBytes.slice(i, i + blockSize);
        const decrypted = await rsaDecryptBlock(block);
        decryptedBlocks.push(new Uint8Array(decrypted));
    }

    let totalLength = 0;
    for (const block of decryptedBlocks) {
        totalLength += block.length;
    }

    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const block of decryptedBlocks) {
        result.set(block, offset);
        offset += block.length;
    }

    return result;
}



const w = 16;
const r = 8;
const b = 16;
const MOD = 65536;
const MASK = 65535;
const P = 0xB7E1;
const Q = 0x9E37;

function rotl(x, y) {
    return ((x << (y % w)) | (x >>> (w - (y % w)))) & MASK;
}

function rotr(x, y) {
    return ((x >>> (y % w)) | (x << (w - (y % w)))) & MASK;
}

function passwordTo16Bytes(password) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(password);
    const key = new Uint8Array(16);

    for (let i = 0; i < 16; i++) {
        key[i] = i < bytes.length ? bytes[i] : 0;
    }

    return key;
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
    let B = 0;
    let i = 0;
    let j = 0;
    const n = 3 * Math.max(t, L.length);

    for (let k = 0; k < n; k++) {
        A = S[i] = rotl((S[i] + A + B) & MASK, 3);
        B = L[j] = rotl((L[j] + A + B) & MASK, A + B);
        i = (i + 1) % t;
        j = (j + 1) % L.length;
    }

    return S;
}

function encryptBlock(A, B, S) {
    A = (A + S[0]) & MASK;
    B = (B + S[1]) & MASK;

    for (let i = 1; i <= r; i++) {
        A = (rotl(A ^ B, B) + S[2 * i]) & MASK;
        B = (rotl(B ^ A, A) + S[2 * i + 1]) & MASK;
    }

    return [A, B];
}

function decryptBlock(A, B, S) {
    for (let i = r; i >= 1; i--) {
        B = (rotr((B - S[2 * i + 1] + MOD) & MASK, A) ^ A) & MASK;
        A = (rotr((A - S[2 * i] + MOD) & MASK, B) ^ B) & MASK;
    }

    A = (A - S[0] + MOD) & MASK;
    B = (B - S[1] + MOD) & MASK;

    return [A, B];
}

function addPadding(data, blockSize = 4) {
    let pad = blockSize - (data.length % blockSize);
    if (pad === 0) pad = blockSize;

    const result = new Uint8Array(data.length + pad);
    result.set(data);
    result.fill(pad, data.length);

    return result;
}

function removePadding(data) {
    const pad = data[data.length - 1];
    if (pad < 1 || pad > 4) return data;
    return data.slice(0, data.length - pad);
}

function encryptCBC(bytes, S, iv) {
    const result = new Uint8Array(bytes.length);
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
            encA & 0xFF,
            (encA >> 8) & 0xFF,
            encB & 0xFF,
            (encB >> 8) & 0xFF
        ]);

        result.set(encrypted, i);
        prev = encrypted;
    }

    return result;
}

function decryptCBC(bytes, S, iv) {
    const result = new Uint8Array(bytes.length);
    let prev = iv;

    for (let i = 0; i < bytes.length; i += 4) {
        const curr = bytes.slice(i, i + 4);

        const [decA, decB] = decryptBlock(
            curr[0] | (curr[1] << 8),
            curr[2] | (curr[3] << 8),
            S
        );

        const decrypted = new Uint8Array([
            decA & 0xFF,
            (decA >> 8) & 0xFF,
            decB & 0xFF,
            (decB >> 8) & 0xFF
        ]);

        for (let j = 0; j < 4; j++) {
            result[i + j] = decrypted[j] ^ prev[j];
        }

        prev = curr;
    }

    return result;
}

async function rc5EncryptBytes(fileBytes, password) {
    const keyBytes = passwordTo16Bytes(password);
    const S = generateS(keyBytes);

    const rawIv = new Uint8Array(4);
    crypto.getRandomValues(rawIv);

    const [encIvA, encIvB] = encryptBlock(
        rawIv[0] | (rawIv[1] << 8),
        rawIv[2] | (rawIv[3] << 8),
        S
    );

    const encryptedIvBlock = new Uint8Array([
        encIvA & 0xFF,
        (encIvA >> 8) & 0xFF,
        encIvB & 0xFF,
        (encIvB >> 8) & 0xFF
    ]);

    const paddedBytes = addPadding(fileBytes, 4);
    const encryptedData = encryptCBC(paddedBytes, S, rawIv);

    const finalBytes = new Uint8Array(encryptedIvBlock.length + encryptedData.length);
    finalBytes.set(encryptedIvBlock, 0);
    finalBytes.set(encryptedData, encryptedIvBlock.length);

    return finalBytes;
}

async function rc5DecryptBytes(fileBytes, password) {
    if (fileBytes.length < 8) {
        throw new Error("Файл занадто малий.");
    }

    const keyBytes = passwordTo16Bytes(password);
    const S = generateS(keyBytes);

    const [rawIvA, rawIvB] = decryptBlock(
        fileBytes[0] | (fileBytes[1] << 8),
        fileBytes[2] | (fileBytes[3] << 8),
        S
    );

    const rawIv = new Uint8Array([
        rawIvA & 0xFF,
        (rawIvA >> 8) & 0xFF,
        rawIvB & 0xFF,
        (rawIvB >> 8) & 0xFF
    ]);

    const encryptedData = fileBytes.slice(4);
    const decryptedPadded = decryptCBC(encryptedData, S, rawIv);

    return removePadding(decryptedPadded);
}


async function runRSA() {
    const file = document.getElementById("fileInput").files[0];
    const output = document.getElementById("output");

    if (!file) {
        output.value = "Помилка: вибери файл.";
        return;
    }

    const arrayBuffer = await file.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);

    try {
        await generateRSA();

        const startEnc = performance.now();
        const encrypted = await rsaEncryptBytes(data);
        const endEnc = performance.now();

        const startDec = performance.now();
        const decrypted = await rsaDecryptBytes(encrypted);
        const endDec = performance.now();

        const same =
            decrypted.length === data.length &&
            decrypted.every((value, index) => value === data[index]);

        output.value =
            "RSA Encrypt: " + (endEnc - startEnc).toFixed(3) + " ms\n" +
            "RSA Decrypt: " + (endDec - startDec).toFixed(3) + " ms\n" +
            "Розмір вихідного файлу: " + data.length + " байт\n" +
            "Розмір зашифрованих даних: " + encrypted.length + " байт\n" +
            "Файли співпадають після дешифрування: " + same;
    } catch (e) {
        output.value = "Помилка RSA: " + e.message;
    }
}

async function runRC5() {
    const file = document.getElementById("fileInput").files[0];
    const password = document.getElementById("password").value.trim();
    const output = document.getElementById("output");

    if (!file || !password) {
        output.value = "Помилка: вибери файл і введи пароль.";
        return;
    }

    const arrayBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(arrayBuffer);

    try {
        const startEnc = performance.now();
        const encrypted = await rc5EncryptBytes(fileBytes, password);
        const endEnc = performance.now();

        const startDec = performance.now();
        const decrypted = await rc5DecryptBytes(encrypted, password);
        const endDec = performance.now();

        const same =
            decrypted.length === fileBytes.length &&
            decrypted.every((value, index) => value === fileBytes[index]);

        output.value =
            "RC5 Encrypt: " + (endEnc - startEnc).toFixed(3) + " ms\n" +
            "RC5 Decrypt: " + (endDec - startDec).toFixed(3) + " ms\n" +
            "Розмір вихідного файлу: " + fileBytes.length + " байт\n" +
            "Розмір зашифрованих даних: " + encrypted.length + " байт\n" +
            "Файли співпадають після дешифрування: " + same;
    } catch (e) {
        output.value = "Помилка RC5: " + e.message;
    }
}

async function compare() {
    const file = document.getElementById("fileInput").files[0];
    const password = document.getElementById("password").value.trim();
    const output = document.getElementById("output");

    if (!file || !password) {
        output.value = "Помилка: вибери файл і введи пароль.";
        return;
    }

    const arrayBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(arrayBuffer);

    try {
        await generateRSA();

        const startRsaEnc = performance.now();
        const rsaEncrypted = await rsaEncryptBytes(fileBytes);
        const endRsaEnc = performance.now();

        const startRsaDec = performance.now();
        await rsaDecryptBytes(rsaEncrypted);
        const endRsaDec = performance.now();

        const startRc5Enc = performance.now();
        const rc5Encrypted = await rc5EncryptBytes(fileBytes, password);
        const endRc5Enc = performance.now();

        const startRc5Dec = performance.now();
        await rc5DecryptBytes(rc5Encrypted, password);
        const endRc5Dec = performance.now();

        const rsaEnc = endRsaEnc - startRsaEnc;
        const rsaDec = endRsaDec - startRsaDec;
        const rc5Enc = endRc5Enc - startRc5Enc;
        const rc5Dec = endRc5Dec - startRc5Dec;

        output.value =
            "RSA Encrypt: " + rsaEnc.toFixed(3) + " ms\n" +
            "RSA Decrypt: " + rsaDec.toFixed(3) + " ms\n\n" +
            "RC5 Encrypt: " + rc5Enc.toFixed(3) + " ms\n" +
            "RC5 Decrypt: " + rc5Dec.toFixed(3) + " ms\n\n" +
            (rc5Enc < rsaEnc
                ? "RESULT: RC5 is faster"
                : "RESULT: RSA is faster in this test");
    } catch (e) {
        output.value = "Помилка compare: " + e.message;
    }
}



async function saveKeys() {
    const output = document.getElementById("output");

    if (!rsaKeyPair) {
        output.value = "Спочатку натисни RSA Encrypt/Decrypt!";
        return;
    }

    const privateKey = await crypto.subtle.exportKey("pkcs8", rsaKeyPair.privateKey);
    const publicKey = await crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);

    function download(data, filename) {
        const blob = new Blob([data]);
        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();

        URL.revokeObjectURL(url);
    }

    download(privateKey, "private_key.pem");
    download(publicKey, "public_key.pem");

    output.value = "Ключі збережено!";
}


async function loadPrivateKey() {
    const file = document.getElementById("keyFile").files[0];
    const output = document.getElementById("output");

    if (!file) {
        output.value = "Вибери файл ключа!";
        return;
    }

    try {
        const buffer = await file.arrayBuffer();

        const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            buffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["decrypt"]
        );

        rsaKeyPair = {
            privateKey: privateKey,
            publicKey: null
        };

        output.value = "Приватний ключ завантажено!";
    } catch (e) {
        output.value = "Помилка завантаження ключа: " + e.message;
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
         generateRSA,
        rsaEncryptBytes,
        rsaDecryptBytes,

        rotl,
        rotr,
        passwordTo16Bytes,
        generateS,
        encryptBlock,
        decryptBlock,
        addPadding,
        removePadding,
        encryptCBC,
        decryptCBC,
        rc5EncryptBytes,
        rc5DecryptBytes,

        runRC5,
        runRSA,
        compare,
        saveKeys,
        loadPrivateKey,
    };
}
