const {
    bytesToHex,
    hexToBytes,
    stringToBytes
} = require("./lab5");

test("bytesToHex converts bytes to hexadecimal string", () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]);

    expect(bytesToHex(bytes)).toBe("48656c6c6f");
});

test("hexToBytes converts hexadecimal string to bytes", () => {
    const result = hexToBytes("48656c6c6f");

    expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
});

test("stringToBytes converts text to bytes", () => {
    const result = stringToBytes("Hi");

    expect(Array.from(result)).toEqual([72, 105]);
});

test("hex conversion works both ways", () => {
    const original = new Uint8Array([1, 2, 3, 255]);

    const hex = bytesToHex(original);
    const back = hexToBytes(hex);

    expect(Array.from(back)).toEqual([1, 2, 3, 255]);
});