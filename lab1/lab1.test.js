const { gcd, generateRandomNumbers, algoCesaro, runLab1, run, save, clearOutput } = require("./lab1");

describe("Лабораторна 1", () => {
    describe("gcd (найбільший спільний дільник)", () => {
        test("обчислює НСД для взаємно простих чисел", () => {
            expect(gcd(17, 13)).toBe(1);
        });

        test("обчислює НСД для чисел зі спільними дільниками", () => {
            expect(gcd(100, 10)).toBe(10);
            expect(gcd(54, 24)).toBe(6);
        });

        test("повертає перше число, якщо друге дорівнює нулю", () => {
            expect(gcd(5, 0)).toBe(5);
        });
    });

    describe("generateRandomNumbers (генератор чисел)", () => {
        test("повертає масив правильної довжини", () => {
            expect(generateRandomNumbers(5).length).toBe(5);
        });

        test("генерує правильне перше число", () => {
            expect(generateRandomNumbers(1)[0]).toBe(64);
        });

        test("генерує правильні перші чотири числа", () => {
            expect(generateRandomNumbers(4)).toEqual([64, 2, 64, 2]);
        });
    });

    describe("algoCesaro (алгоритм Чезаро)", () => {
        test("повертає null, якщо довжина масиву менша за 2", () => {
            expect(algoCesaro([10])).toBeNull();
        });

        test("правильно обчислює ймовірність та число π", () => {
            const result = algoCesaro([3, 4, 3, 6, 5, 10]);

            expect(result.totalPairs).toBe(3);
            expect(result.coprimePairs).toBe(1);
            expect(result.probability).toBeCloseTo(0.3333, 4);
            expect(result.pi).toBeCloseTo(4.2426, 3);
        });

        test("повертає null, якщо немає взаємно простих пар", () => {
            expect(algoCesaro([64, 2, 64, 2])).toBeNull();
        });
    });

    describe("runLab1 (запуск лабораторної)", () => {
        test("повертає правильну структуру об'єкта та реальний період", () => {
            const result = runLab1(10);

            expect(result.lehmerNumbers.length).toBe(10);
            expect(result.period).toBe(2);
            expect(result.maxPeriod).toBe(1022);
            expect(result.lehmerTest).toBeNull();
            expect(result.randomTest).not.toBeNull();
        });
    });
});

describe("DOM-функції", () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <input id="count" />
            <div id="output"></div>
        `;

        global.alert = jest.fn();

        global.URL.createObjectURL = jest.fn(() => "blob:test-url");
        global.URL.revokeObjectURL = jest.fn();
    });

    test("run показує помилку, якщо введено 0", () => {
        document.getElementById("count").value = "0";

        run();

        expect(document.getElementById("output").innerText).toBe("Please enter a positive number.");
    });

    test("run виводить результат, якщо введено правильне число", () => {
        document.getElementById("count").value = "4";

        run();

        const text = document.getElementById("output").innerText;

        expect(text).toContain("Period: 2");
        expect(text).toContain("Generated numbers:");
        expect(text).toContain("64, 2, 64, 2");
    });

    test("save показує alert, якщо output порожній", () => {
        document.getElementById("output").innerText = "";

        save();

        expect(global.alert).toHaveBeenCalledWith("Nothing to save.");
    });

    test("save створює завантаження, якщо output не порожній", () => {
        document.getElementById("output").innerText = "Test results";

        const clickMock = jest.fn();

        const originalCreateElement = document.createElement.bind(document);
        jest.spyOn(document, "createElement").mockImplementation((tagName) => {
            if (tagName === "a") {
                return {
                    href: "",
                    download: "",
                    click: clickMock
                };
            }
            return originalCreateElement(tagName);
        });

        save();

        expect(global.URL.createObjectURL).toHaveBeenCalled();
        expect(clickMock).toHaveBeenCalled();
        expect(global.URL.revokeObjectURL).toHaveBeenCalledWith("blob:test-url");

        document.createElement.mockRestore();
    });

    test("clearOutput очищає output", () => {
        document.getElementById("output").innerText = "Якийсь текст";

        clearOutput();

        expect(document.getElementById("output").innerText).toBe("");
    });
});