const { md5FromString, md5FromBytes } = require("./md5");

let lastOutput = "";
let lastHash = "";

function md5Text(text) {
    return md5FromString(text);
}

function showOutput(text) {
    document.getElementById("output").textContent = text;
    lastOutput = text;
}

function clearOutput() {
    document.getElementById("output").textContent = "";
    lastOutput = "";
    lastHash = "";
}

function save() {
    if (lastHash.trim() === "") {
        showOutput("Nothing to save.");
        return;
    }

    const blob = new Blob([lastHash], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "output.txt";
    a.click();
    URL.revokeObjectURL(a.href);
}

async function readFileBytes(file) {
    const buffer = await file.arrayBuffer();
    return new Uint8Array(buffer);
}

async function hashText() {
    const text = document.getElementById("textInput").value;

    try {
        const hash = md5FromString(text);
        lastHash = hash;

        let result = "";
        result += "Laboratory Work #2\n";
        result += "MD5 hash for text\n";
        result += "-------------------------\n";
        result += "Input: " + text + "\n";
        result += "MD5: " + hash + "\n";

        showOutput(result);
    } catch (error) {
        showOutput("Error: " + error.message);
    }
}

async function hashFile() {
    const file = document.getElementById("fileInput").files[0];

    if (!file) {
        showOutput("Please select a file.");
        return;
    }

    try {
        const bytes = await readFileBytes(file);
        const hash = md5FromBytes(bytes);
        lastHash = hash;

        let result = "";
        result += "Laboratory Work #2\n";
        result += "MD5 hash for file\n";
        result += "-------------------------\n";
        result += "File: " + file.name + "\n";
        result += "MD5: " + hash + "\n";

        showOutput(result);
    } catch (error) {
        showOutput("Error: " + error.message);
    }
}

async function checkIntegrity() {
    const file = document.getElementById("checkFileInput").files[0];
    const hashFileObj = document.getElementById("hashFileInput").files[0];

    if (!file || !hashFileObj) {
        showOutput("Please select both files.");
        return;
    }

    try {
        const bytes = await readFileBytes(file);
        const realHash = md5FromBytes(bytes);

        const hashTextValue = await hashFileObj.text();
        const savedHash = hashTextValue.trim().toUpperCase();

        lastHash = realHash;

        let result = "";
        result += "Laboratory Work #2\n";
        result += "Integrity check\n";
        result += "-------------------------\n";
        result += "File: " + file.name + "\n";
        result += "Expected: " + savedHash + "\n";
        result += "Actual:   " + realHash + "\n";

        if (realHash === savedHash) {
            result += "\n\nIntegrity OK";
        } else {
            result += "\n\nIntegrity FAILED";
        }

        showOutput(result);
    } catch (error) {
        showOutput("Error: " + error.message);
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        md5Text,
        showOutput,
        clearOutput,
        save,
        readFileBytes,
        hashText,
        hashFile,
        checkIntegrity
    };
}