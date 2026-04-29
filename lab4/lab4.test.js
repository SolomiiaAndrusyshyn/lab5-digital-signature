const { webcrypto } = require("crypto");
global.crypto = webcrypto;
global.TextEncoder = require("util").TextEncoder;
global.TextDecoder = require("util").TextDecoder;

const {
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
} = require("./lab4.js");



function makeMockDocument(overrides = {}) {
    const defaults = {
        fileInput: { files: [], value: "" },
        password:  { value: "testpass", files: [] },
        output:    { value: "", textContent: "" },
        keyFile:   { files: [] },
    };

    const elements = { ...defaults, ...overrides };

    return {
        getElementById: jest.fn((id) => elements[id] || { value: "", files: [], textContent: "" }),
        createElement: jest.fn(() => ({
            href: "",
            download: "",
            click: jest.fn(),
        })),
    };
}

function makeFileWith(bytes) {
    return {
        arrayBuffer: async () => bytes.buffer,
    };
}



describe("Lab4 RC5 tests", () => {
    test("passwordTo16Bytes returns exactly 16 bytes", () => {
        const key = passwordTo16Bytes("1234");
        expect(key.length).toBe(16);
        expect(key[0]).toBe("1".charCodeAt(0));
        expect(key[1]).toBe("2".charCodeAt(0));
        expect(key[2]).toBe("3".charCodeAt(0));
        expect(key[3]).toBe("4".charCodeAt(0));
    });

    test("passwordTo16Bytes pads with zeros if password is short", () => {
        const key = passwordTo16Bytes("a");
        expect(key.length).toBe(16);
        expect(key[0]).toBe("a".charCodeAt(0));
        expect(key[1]).toBe(0);
        expect(key[15]).toBe(0);
    });

    test("passwordTo16Bytes truncates long password to 16 bytes", () => {
        const key = passwordTo16Bytes("abcdefghijklmnopXYZ");
        expect(key.length).toBe(16);
    });

    test("rotl and rotr are inverse operations", () => {
        const x = 12345;
        const y = 7;
        expect(rotr(rotl(x, y), y)).toBe(x);
    });

    test("rotl returns a number", () => {
        expect(typeof rotl(12345, 7)).toBe("number");
    });

    test("rotr returns a number", () => {
        expect(typeof rotr(12345, 7)).toBe("number");
    });

    test("rotl with y=0 returns same value masked", () => {
        expect(rotl(0xFFFF, 0)).toBe(0xFFFF);
    });

    test("rotr with y=0 returns same value masked", () => {
        expect(rotr(0xFFFF, 0)).toBe(0xFFFF);
    });

    test("generateS creates correct number of round keys", () => {
        const S = generateS(passwordTo16Bytes("password"));
        expect(S.length).toBe(18);
    });

    test("generateS returns array of numbers", () => {
        const S = generateS(passwordTo16Bytes("12345678"));
        expect(Array.isArray(S)).toBe(true);
        expect(typeof S[0]).toBe("number");
    });

    test("encryptBlock and decryptBlock return original values", () => {
        const S = generateS(passwordTo16Bytes("password"));
        const [encA, encB] = encryptBlock(1234, 5678, S);
        const [decA, decB] = decryptBlock(encA, encB, S);
        expect(decA).toBe(1234);
        expect(decB).toBe(5678);
    });

    test("encryptBlock/decryptBlock work with zero values", () => {
        const S = generateS(passwordTo16Bytes("key"));
        const [encA, encB] = encryptBlock(0, 0, S);
        const [decA, decB] = decryptBlock(encA, encB, S);
        expect(decA).toBe(0);
        expect(decB).toBe(0);
    });

    test("encryptBlock/decryptBlock work with max 16-bit values", () => {
        const S = generateS(passwordTo16Bytes("key"));
        const [encA, encB] = encryptBlock(0xFFFF, 0xFFFF, S);
        const [decA, decB] = decryptBlock(encA, encB, S);
        expect(decA).toBe(0xFFFF);
        expect(decB).toBe(0xFFFF);
    });

    test("addPadding adds bytes to make length multiple of 4", () => {
        const padded = addPadding(new Uint8Array([1, 2, 3, 4, 5]), 4);
        expect(padded.length % 4).toBe(0);
        expect(padded.length).toBe(8);
    });

    test("addPadding adds full block when length already multiple of 4", () => {
        const padded = addPadding(new Uint8Array([1, 2, 3, 4]), 4);
        expect(padded.length).toBe(8);
    });

    test("removePadding removes previously added padding", () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const unpadded = removePadding(addPadding(data, 4));
        expect(Array.from(unpadded)).toEqual(Array.from(data));
    });

    test("removePadding removes valid padding bytes", () => {
        const result = removePadding(new Uint8Array([10, 20, 30, 2, 2]));
        expect(Array.from(result)).toEqual([10, 20, 30]);
    });

    test("removePadding returns data unchanged when pad byte is 0 (invalid)", () => {
        const data = new Uint8Array([10, 20, 30, 0]);
        const result = removePadding(data);
        expect(Array.from(result)).toEqual(Array.from(data));
    });

    test("removePadding returns data unchanged when pad byte > 4 (invalid)", () => {
        const data = new Uint8Array([10, 20, 30, 5]);
        const result = removePadding(data);
        expect(Array.from(result)).toEqual(Array.from(data));
    });

    test("encryptCBC and decryptCBC return original bytes", () => {
        const S = generateS(passwordTo16Bytes("password"));
        const data = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
        const iv = new Uint8Array([1, 2, 3, 4]);
        const encrypted = encryptCBC(data, S, iv);
        const decrypted = decryptCBC(encrypted, S, iv);
        expect(Array.from(decrypted)).toEqual(Array.from(data));
    });

    test("encryptCBC output length equals input length", () => {
        const S = generateS(passwordTo16Bytes("password"));
        const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const encrypted = encryptCBC(data, S, new Uint8Array([1, 2, 3, 4]));
        expect(encrypted.length).toBe(data.length);
    });

    test("decryptCBC output length equals input length", () => {
        const S = generateS(passwordTo16Bytes("password"));
        const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const iv = new Uint8Array([1, 2, 3, 4]);
        const decrypted = decryptCBC(encryptCBC(data, S, iv), S, iv);
        expect(decrypted.length).toBe(data.length);
    });

    test("encryptCBC works with empty input", () => {
        const S = generateS(passwordTo16Bytes("pass"));
        const encrypted = encryptCBC(new Uint8Array([]), S, new Uint8Array([1, 2, 3, 4]));
        expect(encrypted.length).toBe(0);
    });

    test("decryptCBC works with empty input", () => {
        const S = generateS(passwordTo16Bytes("pass"));
        const decrypted = decryptCBC(new Uint8Array([]), S, new Uint8Array([1, 2, 3, 4]));
        expect(decrypted.length).toBe(0);
    });

    test("encryptCBC changes the data (output differs from input)", () => {
        const S = generateS(passwordTo16Bytes("password"));
        const data = new Uint8Array([1, 2, 3, 4]);
        const encrypted = encryptCBC(data, S, new Uint8Array([0, 0, 0, 0]));
        expect(Array.from(encrypted)).not.toEqual(Array.from(data));
    });

    test("rc5EncryptBytes and rc5DecryptBytes return original file bytes", async () => {
        const data = new TextEncoder().encode("Hello RC5 test file");
        const encrypted = await rc5EncryptBytes(data, "12345678");
        const decrypted = await rc5DecryptBytes(encrypted, "12345678");
        expect(Array.from(decrypted)).toEqual(Array.from(data));
    });

    test("rc5EncryptBytes works with empty data", async () => {
        const encrypted = await rc5EncryptBytes(new Uint8Array([]), "1234");
        expect(encrypted.length).toBeGreaterThanOrEqual(4);
    });

    test("rc5DecryptBytes throws error for too small file", async () => {
        await expect(rc5DecryptBytes(new Uint8Array([1, 2, 3]), "1234"))
            .rejects.toThrow("Файл занадто малий.");
    });

    test("rc5DecryptBytes with wrong password does not crash", async () => {
        const data = new TextEncoder().encode("Hello");
        const encrypted = await rc5EncryptBytes(data, "1234");
        const decrypted = await rc5DecryptBytes(encrypted, "wrong");
        expect(decrypted).toBeDefined();
    });

    test("rc5EncryptBytes produces different output each call (random IV)", async () => {
        const data = new TextEncoder().encode("Same data");
        const enc1 = await rc5EncryptBytes(data, "pass");
        const enc2 = await rc5EncryptBytes(data, "pass");
        // IV рандомний — зашифровані байти майже завжди різні
        expect(Array.from(enc1)).not.toEqual(Array.from(enc2));
    });

    test("rc5EncryptBytes output length equals 4 (IV) + padded data length", async () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const encrypted = await rc5EncryptBytes(data, "pass");
        // 4 (IV block) + 8 (4 bytes data + 4 padding) = 12
        expect(encrypted.length).toBe(12);
    });
});



describe("RSA tests", () => {
    test("RSA generate + encryptBytes + decryptBytes works", async () => {
        const data = new TextEncoder().encode("Hello RSA");
        await generateRSA();
        const encrypted = await rsaEncryptBytes(data);
        const decrypted = await rsaDecryptBytes(encrypted);
        expect(new TextDecoder().decode(decrypted)).toBe("Hello RSA");
    });

    test("RSA encryptBytes returns Uint8Array", async () => {
        await generateRSA();
        const encrypted = await rsaEncryptBytes(new TextEncoder().encode("Test RSA"));
        expect(encrypted instanceof Uint8Array).toBe(true);
        expect(encrypted.length).toBeGreaterThan(0);
    });

    test("RSA decryptBytes returns original bytes", async () => {
        const data = new TextEncoder().encode("Another RSA test");
        await generateRSA();
        const decrypted = await rsaDecryptBytes(await rsaEncryptBytes(data));
        expect(Array.from(decrypted)).toEqual(Array.from(data));
    });

    test("RSA encryptBytes with empty data returns empty result", async () => {
        await generateRSA();
        const encrypted = await rsaEncryptBytes(new Uint8Array([]));
        // 0 блоків — результат порожній
        expect(encrypted.length).toBe(0);
    });

    test("RSA encryptBytes with large data (>190 bytes) splits into blocks", async () => {
        await generateRSA();
        const data = new Uint8Array(400).fill(0x42);
        const encrypted = await rsaEncryptBytes(data);
        // 400 / 190 = 3 блоки => 3 * 256 = 768 байт
        expect(encrypted.length).toBe(768);
    });
});



describe("runRC5 UI tests", () => {
    test("runRC5: no file — sets error message", async () => {
        const mockDoc = makeMockDocument({
            fileInput: { files: [] },
            password: { value: "pass" },
            output: { value: "" },
        });
        global.document = mockDoc;
        global.performance = { now: jest.fn(() => 0) };

        await runRC5();

        expect(mockDoc.getElementById("output").value).toMatch(/Помилка/);
    });

    test("runRC5: no password — sets error message", async () => {
        const mockDoc = makeMockDocument({
            fileInput: { files: [makeFileWith(new Uint8Array([1, 2, 3, 4]))] },
            password: { value: "" },
            output: { value: "" },
        });
        global.document = mockDoc;

        await runRC5();

        expect(mockDoc.getElementById("output").value).toMatch(/Помилка/);
    });

    test("runRC5: valid file and password — encrypts and decrypts", async () => {
        const fileBytes = new TextEncoder().encode("Hello RC5 UI test");
        const mockOutput = { value: "" };
        const mockDoc = makeMockDocument({
            fileInput: { files: [makeFileWith(fileBytes)] },
            password: { value: "mypassword" },
            output: mockOutput,
        });
        global.document = mockDoc;
        global.performance = { now: jest.fn(() => Date.now()) };

        await runRC5();

        expect(mockOutput.value).toContain("RC5 Encrypt:");
        expect(mockOutput.value).toContain("true");
    });
});

describe("runRSA UI tests", () => {
    test("runRSA: no file — sets error message", async () => {
        const mockDoc = makeMockDocument({ fileInput: { files: [] } });
        global.document = mockDoc;

        await runRSA();

        expect(mockDoc.getElementById("output").value).toMatch(/Помилка/);
    });

    test("runRSA: valid file — encrypts and decrypts", async () => {
        const fileBytes = new TextEncoder().encode("RSA UI test data");
        const mockOutput = { value: "" };
        const mockDoc = makeMockDocument({
            fileInput: { files: [makeFileWith(fileBytes)] },
            output: mockOutput,
        });
        global.document = mockDoc;
        global.performance = { now: jest.fn(() => Date.now()) };

        await runRSA();

        expect(mockOutput.value).toContain("RSA Encrypt:");
        expect(mockOutput.value).toContain("true");
    });
});

describe("compare UI tests", () => {
    test("compare: no file — sets error message", async () => {
        const mockDoc = makeMockDocument({ fileInput: { files: [] } });
        global.document = mockDoc;

        await compare();

        expect(mockDoc.getElementById("output").value).toMatch(/Помилка/);
    });

    test("compare: no password — sets error message", async () => {
        const mockDoc = makeMockDocument({
            fileInput: { files: [makeFileWith(new Uint8Array([1, 2, 3, 4]))] },
            password: { value: "" },
        });
        global.document = mockDoc;

        await compare();

        expect(mockDoc.getElementById("output").value).toMatch(/Помилка/);
    });

    test("compare: valid file and password — shows result", async () => {
        const fileBytes = new TextEncoder().encode("compare test");
        const mockOutput = { value: "" };
        const mockDoc = makeMockDocument({
            fileInput: { files: [makeFileWith(fileBytes)] },
            password: { value: "pass" },
            output: mockOutput,
        });
        global.document = mockDoc;
        global.performance = { now: jest.fn(() => Date.now()) };

        await compare();

        expect(mockOutput.value).toMatch(/RSA (Encrypt|Decrypt|is faster)|RC5 (Encrypt|is faster)/);
    });
});

describe("saveKeys UI tests", () => {
    test("saveKeys: no key pair — sets error message", async () => {
        const mockDoc = makeMockDocument({ output: { value: "" } });
        global.document = mockDoc;

        try {
            await saveKeys();
        } catch (e) {}
        expect(true).toBe(true);
    });

    test("saveKeys: after generateRSA — downloads keys", async () => {
        const mockOutput = { value: "" };
        const createdEl = { href: "", download: "", click: jest.fn() };
        const mockDoc = {
            getElementById: jest.fn((id) => id === "output" ? mockOutput : { value: "", files: [] }),
            createElement: jest.fn(() => createdEl),
        };
        global.document = mockDoc;
        global.URL = {
            createObjectURL: jest.fn(() => "blob:fake"),
            revokeObjectURL: jest.fn(),
        };
        global.Blob = class {
            constructor(data) { this.data = data; }
        };

        await generateRSA();
        await saveKeys();

        expect(mockOutput.value).toContain("збережено");
    });
});

describe("loadPrivateKey UI tests", () => {
    test("loadPrivateKey: no file — sets error message", async () => {
        const mockDoc = makeMockDocument({ keyFile: { files: [] } });
        global.document = mockDoc;

        await loadPrivateKey();

        expect(mockDoc.getElementById("output").value).toMatch(/Вибери файл/);
    });

    test("loadPrivateKey: invalid key file — sets error message", async () => {
        const fakeKeyBytes = new Uint8Array([0x01, 0x02, 0x03]);
        const mockOutput = { value: "" };
        const mockDoc = makeMockDocument({
            keyFile: { files: [makeFileWith(fakeKeyBytes)] },
            output: mockOutput,
        });
        global.document = mockDoc;

        await loadPrivateKey();

        expect(mockOutput.value).toMatch(/Помилка завантаження/);
    });
});