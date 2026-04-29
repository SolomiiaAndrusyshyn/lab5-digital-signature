let privateKey = null;
let publicKey = null;
let currentSignature = null;

function writeOutput(text) {
    document.getElementById("output").value += text + "\n";
}

function clearOutput() {
    document.getElementById("output").value = "";
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

function hexToBytes(hex) {
    const bytes = [];

    for (let i = 0; i < hex.length; i += 2) {
    bytes.push(Number.parseInt(hex.substring(i, i + 2), 16));
}
    return new Uint8Array(bytes);
}

function stringToBytes(text) {
    const encoder = new TextEncoder();
    return encoder.encode(text);
}

async function generateKeys() {
    clearOutput();

    const keyPair = await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
    );

    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
    currentSignature = null;

    writeOutput("Keys generated successfully.");
    writeOutput("Private key is used for signing.");
    writeOutput("Public key is used for verification.");
}

async function signMessage() {
    clearOutput();

    if (privateKey === null) {
        writeOutput("Error: generate or load private key first.");
        return;
    }

    const message = document.getElementById("messageInput").value;

    if (message.length === 0) {
        writeOutput("Error: message is empty.");
        return;
    }

    const data = stringToBytes(message);

    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }
        },
        privateKey,
        data
    );

    currentSignature = new Uint8Array(signature);

    writeOutput("Message signed successfully.");
    writeOutput("Signature in hexadecimal format:");
    writeOutput(bytesToHex(currentSignature));
}

async function verifyMessage() {
    clearOutput();

    if (publicKey === null) {
        writeOutput("Error: generate or load public key first.");
        return;
    }

    if (currentSignature === null) {
        writeOutput("Error: create or load signature first.");
        return;
    }

    const message = document.getElementById("messageInput").value;

    if (message.length === 0) {
        writeOutput("Error: message is empty.");
        return;
    }

    const data = stringToBytes(message);

    const result = await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }
        },
        publicKey,
        currentSignature,
        data
    );

    if (result) {
        writeOutput("Verification result: signature is VALID.");
    } else {
        writeOutput("Verification result: signature is NOT VALID.");
    }
}

async function signFile() {
    clearOutput();

    if (privateKey === null) {
        writeOutput("Error: generate or load private key first.");
        return;
    }

    const fileInput = document.getElementById("fileInput");

    if (fileInput.files.length === 0) {
        writeOutput("Error: choose file first.");
        return;
    }

    const file = fileInput.files[0];
    const data = await file.arrayBuffer();

    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }
        },
        privateKey,
        data
    );

    currentSignature = new Uint8Array(signature);

    writeOutput("File signed successfully.");
    writeOutput("File name: " + file.name);
    writeOutput("Signature in hexadecimal format:");
    writeOutput(bytesToHex(currentSignature));
}

async function verifyFile() {
    clearOutput();

    if (publicKey === null) {
        writeOutput("Error: generate or load public key first.");
        return;
    }

    if (currentSignature === null) {
        writeOutput("Error: create or load signature first.");
        return;
    }

    const fileInput = document.getElementById("fileInput");

    if (fileInput.files.length === 0) {
        writeOutput("Error: choose file first.");
        return;
    }

    const file = fileInput.files[0];
    const data = await file.arrayBuffer();

    const result = await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }
        },
        publicKey,
        currentSignature,
        data
    );

    if (result) {
        writeOutput("Verification result: file signature is VALID.");
    } else {
        writeOutput("Verification result: file signature is NOT VALID.");
    }
}

async function savePrivateKey() {
    clearOutput();

    if (privateKey === null) {
        writeOutput("Error: no private key to save.");
        return;
    }

    const keyData = await crypto.subtle.exportKey("pkcs8", privateKey);
    downloadFile("private_key.key", keyData);

    writeOutput("Private key saved to file.");
}

async function savePublicKey() {
    clearOutput();

    if (publicKey === null) {
        writeOutput("Error: no public key to save.");
        return;
    }

    const keyData = await crypto.subtle.exportKey("spki", publicKey);
    downloadFile("public_key.key", keyData);

    writeOutput("Public key saved to file.");
}

async function loadPrivateKey() {
    clearOutput();

    const fileInput = document.getElementById("privateKeyFile");

    if (fileInput.files.length === 0) {
        writeOutput("Error: choose private key file.");
        return;
    }

    const file = fileInput.files[0];
    const keyData = await file.arrayBuffer();

    privateKey = await crypto.subtle.importKey(
        "pkcs8",
        keyData,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign"]
    );

    writeOutput("Private key loaded successfully.");
}

async function loadPublicKey() {
    clearOutput();

    const fileInput = document.getElementById("publicKeyFile");

    if (fileInput.files.length === 0) {
        writeOutput("Error: choose public key file.");
        return;
    }

    const file = fileInput.files[0];
    const keyData = await file.arrayBuffer();

    publicKey = await crypto.subtle.importKey(
        "spki",
        keyData,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["verify"]
    );

    writeOutput("Public key loaded successfully.");
}

function saveSignature() {
    clearOutput();

    if (currentSignature === null) {
        writeOutput("Error: no signature to save.");
        return;
    }

    const hexSignature = bytesToHex(currentSignature);
    downloadFile("signature.txt", hexSignature);

    writeOutput("Signature saved to file in hexadecimal format.");
}

async function loadSignature() {
    clearOutput();

    const fileInput = document.getElementById("signatureFile");

    if (fileInput.files.length === 0) {
        writeOutput("Error: choose signature file.");
        return;
    }

    const file = fileInput.files[0];
    const text = await file.text();

    currentSignature = hexToBytes(text.trim());

    writeOutput("Signature loaded successfully.");
    writeOutput("Loaded signature:");
    writeOutput(text.trim());
}

function downloadFile(fileName, content) {
    const blob = new Blob([content]);
    const link = document.createElement("a");

    link.href = URL.createObjectURL(blob);
    link.download = fileName;

    document.body.appendChild(link);
    link.click();
    link.remove();
}

if (typeof module !== "undefined") {
    module.exports = {
        bytesToHex,
        hexToBytes,
        stringToBytes
    };
}