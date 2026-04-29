const { TextEncoder, TextDecoder } = require("util");

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
const {
    md5Text,
    showOutput,
    clearOutput,
    save,
    readFileBytes,
    hashText,
    hashFile,
    checkIntegrity
} = require("./lab2");

const {
    md5FromString,
    md5FromBytes,
    addPadding,
    leftRotate,
    addUnsigned,
    wordToHex
} = require("./md5");

describe("md5.js", () => {
    test('MD5 of ""', () => {
        expect(md5FromString("")).toBe("D41D8CD98F00B204E9800998ECF8427E");
    });

    test('MD5 of "a"', () => {
        expect(md5FromString("a")).toBe("0CC175B9C0F1B6A831C399E269772661");
    });

    test('MD5 of "abc"', () => {
        expect(md5FromString("abc")).toBe("900150983CD24FB0D6963F7D28E17F72");
    });

    test('MD5 of "message digest"', () => {
        expect(md5FromString("message digest")).toBe("F96B697D7CB7938D525A2F31AAF161D0");
    });

    test('MD5 of alphabet', () => {
        expect(md5FromString("abcdefghijklmnopqrstuvwxyz"))
            .toBe("C3FCD3D76192E4007DFB496CCA67E13B");
    });

    test('MD5 of A-Z a-z 0-9', () => {
        expect(md5FromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
            .toBe("D174AB98D277D9F5A5611C2C9F419D9F");
    });

    test('MD5 of long numeric string', () => {
        expect(md5FromString("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
            .toBe("57EDF4A22BE3C955AC49DA2E2107B67A");
    });

    test("md5FromBytes works for abc bytes", () => {
        const bytes = new TextEncoder().encode("abc");
        expect(md5FromBytes(bytes)).toBe("900150983CD24FB0D6963F7D28E17F72");
    });

    test("addPadding adds correct length", () => {
        const bytes = new Uint8Array([97, 98, 99]);
        const padded = addPadding(bytes);

        expect(padded.length % 64).toBe(0);
        expect(padded[0]).toBe(97);
        expect(padded[1]).toBe(98);
        expect(padded[2]).toBe(99);
        expect(padded[3]).toBe(0x80);
    });

    test("leftRotate works correctly", () => {
        expect(leftRotate(0x12345678, 8)).toBe(0x34567812);
    });

    test("addUnsigned works correctly", () => {
        expect(addUnsigned(0xffffffff, 1)).toBe(0);
    });

    test("wordToHex works correctly", () => {
        expect(wordToHex(0x12345678)).toBe("78563412");
    });
});

describe("lab2.js", () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <textarea id="textInput"></textarea>
            <input id="fileInput" type="file">
            <input id="checkFileInput" type="file">
            <input id="hashFileInput" type="file">
            <div id="output"></div>
        `;

        global.URL.createObjectURL = jest.fn(() => "blob:test-url");
        global.URL.revokeObjectURL = jest.fn();
    });

    test("md5Text uses md5FromString", () => {
        expect(md5Text("abc")).toBe("900150983CD24FB0D6963F7D28E17F72");
    });

    test("showOutput writes text to output", () => {
        showOutput("Hello");
        expect(document.getElementById("output").textContent).toBe("Hello");
    });

    test("clearOutput clears output", () => {
        showOutput("Some text");
        clearOutput();
        expect(document.getElementById("output").textContent).toBe("");
    });

    test("save shows message if nothing to save", () => {
        save();
        expect(document.getElementById("output").textContent).toBe("Nothing to save.");
    });

    test("readFileBytes returns Uint8Array", async () => {
        const file = {
            arrayBuffer: jest.fn().mockResolvedValue(new Uint8Array([65, 66, 67]).buffer)
        };

        const bytes = await readFileBytes(file);
        expect(bytes).toEqual(new Uint8Array([65, 66, 67]));
    });

    test("hashText shows MD5 for entered text", async () => {
        document.getElementById("textInput").value = "abc";

        await hashText();

        const output = document.getElementById("output").textContent;
        expect(output).toContain("MD5 hash for text");
        expect(output).toContain("Input: abc");
        expect(output).toContain("MD5: 900150983CD24FB0D6963F7D28E17F72");
    });

    test("hashFile shows message when no file selected", async () => {
        await hashFile();
        expect(document.getElementById("output").textContent).toBe("Please select a file.");
    });

    test("hashFile hashes selected file", async () => {
        const fakeFile = {
            name: "test.txt",
            arrayBuffer: jest.fn().mockResolvedValue(new TextEncoder().encode("abc").buffer)
        };

        Object.defineProperty(document.getElementById("fileInput"), "files", {
            value: [fakeFile],
            configurable: true
        });

        await hashFile();

        const output = document.getElementById("output").textContent;
        expect(output).toContain("MD5 hash for file");
        expect(output).toContain("File: test.txt");
        expect(output).toContain("MD5: 900150983CD24FB0D6963F7D28E17F72");
    });

    test("checkIntegrity shows message when files are missing", async () => {
        await checkIntegrity();
        expect(document.getElementById("output").textContent).toBe("Please select both files.");
    });

    test("checkIntegrity shows Integrity OK", async () => {
        const realFile = {
            name: "data.txt",
            arrayBuffer: jest.fn().mockResolvedValue(new TextEncoder().encode("abc").buffer)
        };

        const hashFileObj = {
            text: jest.fn().mockResolvedValue("900150983CD24FB0D6963F7D28E17F72")
        };

        Object.defineProperty(document.getElementById("checkFileInput"), "files", {
            value: [realFile],
            configurable: true
        });

        Object.defineProperty(document.getElementById("hashFileInput"), "files", {
            value: [hashFileObj],
            configurable: true
        });

        await checkIntegrity();

        expect(document.getElementById("output").textContent).toContain("Integrity OK");
    });

    test("checkIntegrity shows Integrity FAILED", async () => {
        const realFile = {
            name: "data.txt",
            arrayBuffer: jest.fn().mockResolvedValue(new TextEncoder().encode("abc").buffer)
        };

        const hashFileObj = {
            text: jest.fn().mockResolvedValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        };

        Object.defineProperty(document.getElementById("checkFileInput"), "files", {
            value: [realFile],
            configurable: true
        });

        Object.defineProperty(document.getElementById("hashFileInput"), "files", {
            value: [hashFileObj],
            configurable: true
        });

        await checkIntegrity();

        expect(document.getElementById("output").textContent).toContain("Integrity FAILED");
    });
});