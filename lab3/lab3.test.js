const { webcrypto } = require("crypto");
const { TextEncoder, TextDecoder } = require("util");

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
global.crypto = webcrypto;
global.alert = jest.fn();

jest.mock("./md5", () => ({
    md5FromString: jest.fn(() => "5D41402ABC4B2A76B9719D911017C592")
}));

class MockFileReader {
    constructor() {
        this.onload = null;
    }

    readAsArrayBuffer(file) {
        const bytes = file._bytes || new Uint8Array([1, 2, 3, 4]);

        setTimeout(() => {
            if (this.onload) {
                this.onload({ target: { result: bytes.buffer } });
            }
        }, 0);
    }
}

global.FileReader = MockFileReader;
global.Blob = class {
    constructor(parts, options) {
        this.parts = parts;
        this.options = options;
    }
};

const {
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
} = require("./lab3");

const KEY_HEX = "5D41402ABC4B2A76B9719D911017C592";

function getS() {
    return generateS(hexStringToBytes(KEY_HEX));
}

function makeFile(bytes) {
    return { _bytes: bytes };
}

function setDom() {
    document.body.innerHTML = `
        <input id="passwordInput" value="">
        <input id="fileInput" type="file">
        <textarea id="output"></textarea>
    `;

    Object.defineProperty(window, "crypto", {
        value: webcrypto,
        configurable: true
    });

    const alertMock = jest.fn();
    window.alert = alertMock;
    global.alert = alertMock;

    global.URL.createObjectURL = jest.fn(() => "blob:fake");
    global.URL.revokeObjectURL = jest.fn();
}
describe("hexStringToBytes", () => {
    beforeEach(() => {
        setDom();
    });

    test("converts hex string to bytes", () => {
        expect(hexStringToBytes("0102FF")).toEqual([1, 2, 255]);
    });

    test("returns empty array for empty string", () => {
        expect(hexStringToBytes("")).toEqual([]);
    });
});

describe("helper functions", () => {
    beforeEach(() => {
        setDom();
    });

    test("rotl and rotr are inverse", () => {
        expect(rotr(rotl(0x1234, 5), 5)).toBe(0x1234);
    });

    test("generateS creates 18 subkeys", () => {
        expect(getS().length).toBe(18);
    });

    test("generateS is deterministic", () => {
        expect(generateS(hexStringToBytes(KEY_HEX))).toEqual(generateS(hexStringToBytes(KEY_HEX)));
    });
});

describe("block encryption", () => {
    beforeEach(() => {
        setDom();
    });

    test("encryptBlock + decryptBlock returns original", () => {
        const S = getS();
        const [eA, eB] = encryptBlock(0x1234, 0xABCD, S);
        const [dA, dB] = decryptBlock(eA, eB, S);

        expect(dA).toBe(0x1234);
        expect(dB).toBe(0xABCD);
    });
});

describe("padding", () => {
    beforeEach(() => {
        setDom();
    });

    test("addPadding makes multiple of 4", () => {
        expect(addPadding(new Uint8Array([1, 2, 3, 4, 5]), 4).length % 4).toBe(0);
    });

    test("removePadding restores original", () => {
        const data = new Uint8Array([10, 20, 30, 40, 50]);
        const padded = addPadding(data, 4);

        expect(Array.from(removePadding(padded))).toEqual(Array.from(data));
    });

    test("removePadding returns original if pad invalid", () => {
        const data = new Uint8Array([1, 2, 3, 9]);
        expect(Array.from(removePadding(data))).toEqual(Array.from(data));
    });
});

describe("CBC mode", () => {
    beforeEach(() => {
        setDom();
    });

    test("encryptCBC and decryptCBC restore original padded data", () => {
        const S = getS();
        const iv = new Uint8Array([1, 2, 3, 4]);
        const padded = addPadding(new Uint8Array([11, 22, 33, 44, 55, 66, 77, 88]), 4);

        const encrypted = encryptCBC(padded, S, iv);
        const decrypted = decryptCBC(encrypted, S, iv);

        expect(Array.from(decrypted)).toEqual(Array.from(padded));
    });

    test("different IVs produce different ciphertext", () => {
        const S = getS();
        const data = addPadding(new Uint8Array([1, 2, 3, 4, 5]), 4);

        const a = encryptCBC(data, S, new Uint8Array([1, 2, 3, 4]));
        const b = encryptCBC(data, S, new Uint8Array([5, 6, 7, 8]));

        expect(Array.from(a)).not.toEqual(Array.from(b));
    });
});

describe("UI functions", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        setDom();
        clearAll();
    });

    test("encryptFile: no password", () => {
        const output = document.getElementById("output");
        document.getElementById("passwordInput").value = "";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [makeFile(new Uint8Array([1, 2, 3, 4]))],
            configurable: true
        });

        encryptFile();

        expect(output.value).toMatch(/Помилка/);
    });

    test("encryptFile: no file", () => {
        const output = document.getElementById("output");
        document.getElementById("passwordInput").value = "pass";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [],
            configurable: true
        });

        encryptFile();

        expect(output.value).toMatch(/Помилка/);
    });

    test("encryptFile: success", async () => {
        const output = document.getElementById("output");
        document.getElementById("passwordInput").value = "mypassword";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [makeFile(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))],
            configurable: true
        });

        encryptFile();
        await new Promise((r) => setTimeout(r, 30));

        expect(output.value).toContain("зашифровано");
        expect(output.value).toContain("IV");
    });

    test("decryptFile: returns early when no password and file", () => {
        const output = document.getElementById("output");
        output.value = "unchanged";

        document.getElementById("passwordInput").value = "";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [],
            configurable: true
        });

        expect(() => decryptFile()).not.toThrow();
        expect(output.value).toBe("unchanged");
    });

    test("decryptFile: small file -> error", async () => {
        const output = document.getElementById("output");
        document.getElementById("passwordInput").value = "pass";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [makeFile(new Uint8Array([1, 2, 3]))],
            configurable: true
        });

        decryptFile();
        await new Promise((r) => setTimeout(r, 30));

        expect(output.value).toContain("Помилка");
    });

    test("decryptFile: success", async () => {
        const S = getS();
        const rawIv = new Uint8Array([0x11, 0x22, 0x33, 0x44]);

        const [encIvA, encIvB] = encryptBlock(
            rawIv[0] | (rawIv[1] << 8),
            rawIv[2] | (rawIv[3] << 8),
            S
        );

        const encIvBlock = new Uint8Array([
            encIvA & 0xFF, encIvA >> 8,
            encIvB & 0xFF, encIvB >> 8
        ]);

        const padded = addPadding(new Uint8Array([10, 20, 30, 40]), 4);
        const encData = encryptCBC(padded, S, rawIv);

        const fullFile = new Uint8Array(encIvBlock.length + encData.length);
        fullFile.set(encIvBlock, 0);
        fullFile.set(encData, encIvBlock.length);

        const output = document.getElementById("output");
        document.getElementById("passwordInput").value = "pass";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [makeFile(fullFile)],
            configurable: true
        });

        decryptFile();
        await new Promise((r) => setTimeout(r, 30));

        expect(output.value).toContain("дешифровано");
        expect(output.value).toContain("байт");
    });

   test("saveResult: no data -> alert", () => {
    clearAll();
    saveResult();
    expect(window.alert).toHaveBeenCalledWith("Немає даних");
});

    test("saveResult after encrypt -> click and encrypted filename", async () => {
        const clickMock = jest.fn();
        const aEl = { href: "", download: "", click: clickMock };

        const originalCreateElement = document.createElement.bind(document);
        jest.spyOn(document, "createElement").mockImplementation((tag) => {
            if (tag === "a") {
                return aEl;
            }
            return originalCreateElement(tag);
        });

        document.getElementById("passwordInput").value = "pass";

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [makeFile(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))],
            configurable: true
        });

        encryptFile();
        await new Promise((r) => setTimeout(r, 30));
        saveResult();

        expect(clickMock).toHaveBeenCalled();
        expect(aEl.download).toBe("encrypted.bin");

        document.createElement.mockRestore();
    });
test("clearAll clears fields", () => {
    document.getElementById("passwordInput").value = "secret";
    document.getElementById("output").value = "result";

    clearAll();

    expect(document.getElementById("passwordInput").value).toBe("");
    expect(document.getElementById("fileInput").value).toBe("");
    expect(document.getElementById("output").value).toBe("");
});
});