const M = 1023;
const A = 32;
const C = 0;
const X0 = 2;

function generateRandomNumbers(countOfNumbers) {
    const result = [];
    let x = X0;

    for (let i = 0; i < countOfNumbers; i++) {
        x = (A * x + C) % M;
        result.push(x);
    }

    return result;
}

function findPeriod() {
    const seen = new Map();
    let x = X0;
    let step = 0;

    while (true) {
        if (seen.has(x)) {
            return step - seen.get(x);
        }

        seen.set(x, step);
        x = (A * x + C) % M;
        step++;
    }
}

function gcd(a, b) {
    if (b === 0) {
        return a;
    }
    return gcd(b, a % b);
}

function algoCesaro(numbers) {
    if (numbers.length < 2) {
        return null;
    }

    let coprimePairs = 0;
    let totalPairs = 0;

    for (let i = 0; i + 1 < numbers.length; i += 2) {
        const a = numbers[i];
        const b = numbers[i + 1];
        totalPairs++;

        if (gcd(a, b) === 1) {
            coprimePairs++;
        }
    }

    if (totalPairs === 0 || coprimePairs === 0) {
        return null;
    }

    const probability = coprimePairs / totalPairs;
    const pi = Math.sqrt(6 / probability);

    return {
        pi,
        probability,
        coprimePairs,
        totalPairs
    };
}

function runLab1(countOfNumbers) {
    const lehmerNumbers = generateRandomNumbers(countOfNumbers);
    const lehmerTest = algoCesaro(lehmerNumbers);

    const randomNumbers = Array.from(
        { length: countOfNumbers },
        () => Math.floor(Math.random() * M) + 1
    );
    const randomTest = algoCesaro(randomNumbers);

    const period = findPeriod();

    return {
        lehmerNumbers,
        lehmerTest,
        randomTest,
        period,
        maxPeriod: M - 1
    };
}

function run() {
    const count = Number(document.getElementById("count").value);
    const output = document.getElementById("output");

    if (!count || count <= 0) {
        output.innerText = "Please enter a positive number.";
        return;
    }

    const result = runLab1(count);

    let text = "";

    text += "Period: " + result.period + "\n";

    if (result.lehmerTest === null) {
        text += "Pi from Lehmer: cannot be estimated\n";
    } else {
        text += "Pi from Lehmer: " + result.lehmerTest.pi + "\n";
    }

    if (result.randomTest === null) {
        text += "Pi from Math.random: cannot be estimated\n\n";
    } else {
        text += "Pi from Math.random: " + result.randomTest.pi + "\n\n";
    }

    text += "Generated numbers:\n";
    text += result.lehmerNumbers.join(", ");

    output.innerText = text;
}

function save() {
    const outputText = document.getElementById("output").innerText;

    if (!outputText) {
        alert("Nothing to save.");
        return;
    }

    const blob = new Blob([outputText], { type: "text/plain" });
    const link = document.createElement("a");

    link.href = URL.createObjectURL(blob);
    link.download = "results.txt";
    link.click();

    URL.revokeObjectURL(link.href);
}

function clearOutput() {
    document.getElementById("output").innerText = "";
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        generateRandomNumbers,
        findPeriod,
        gcd,
        algoCesaro,
        runLab1,
        run,
        save,
        clearOutput
    };
}