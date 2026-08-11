import { describe, expect, test } from "bun:test";
import {
    buildSeparatorPool,
    createPasswordFromHash,
    isValidSiteName,
    normalizeTrimmed,
    splitPasswordForDisplay,
} from "./app.js";

function calculateEntropy(alphabetSize, length) {
    return length * Math.log2(alphabetSize);
}

function createSampleHash(seed) {
    return new Uint8Array(Array.from({ length: 32 }, (_, index) => (seed * 73 + index * 29) % 256));
}

function writeUint32(bytes, position, value) {
    bytes[position] = (value >>> 24) & 0xff;
    bytes[position + 1] = (value >>> 16) & 0xff;
    bytes[position + 2] = (value >>> 8) & 0xff;
    bytes[position + 3] = value & 0xff;
}

function createWordSelectionHash({ nounIndex, adjectiveIndex, verbIndex, trailingNounIndex }) {
    const bytes = new Uint8Array(32);
    writeUint32(bytes, 0, nounIndex);
    writeUint32(bytes, 4, adjectiveIndex);
    writeUint32(bytes, 8, verbIndex);
    writeUint32(bytes, 12, trailingNounIndex);
    return bytes;
}

function collectAlphabet(passwords) {
    return new Set(passwords.join(""));
}

describe("normalizeTrimmed", () => {
    test("trims leading and trailing whitespace", () => {
        expect(normalizeTrimmed("  abc  ")).toBe("abc");
    });
});

describe("isValidSiteName", () => {
    test("accepts allowed characters", () => {
        expect(isValidSiteName("github.com")).toBe(true);
        expect(isValidSiteName("mail@example.com")).toBe(true);
        expect(isValidSiteName("server:8443")).toBe(true);
    });

    test("rejects empty and invalid characters", () => {
        expect(isValidSiteName("")).toBe(false);
        expect(isValidSiteName("bad name")).toBe(false);
        expect(isValidSiteName("hola/")).toBe(false);
    });
});

describe("buildSeparatorPool", () => {
    test("omits spaces when they are disabled", () => {
        expect(buildSeparatorPool({ enableSpaces: false, enableNumbers: false, symbolMode: "none" })).toEqual([]);
    });
});

describe("createPasswordFromHash", () => {
    const hash = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));

    test("creates a fixed length password for mode 11", () => {
        const password = createPasswordFromHash(hash, {
            enableSpaces: true,
            enableNumbers: false,
            symbolMode: "none",
            lengthMode: "11",
        });

        expect(password).toHaveLength(11);
    });

    test("creates a fixed length password for mode 15", () => {
        const password = createPasswordFromHash(hash, {
            enableSpaces: true,
            enableNumbers: true,
            symbolMode: "small",
            lengthMode: "15",
        });

        expect(password).toHaveLength(15);
    });

    test("creates at least 16 characters for unset length mode", () => {
        const password = createPasswordFromHash(hash, {
            enableSpaces: true,
            enableNumbers: false,
            symbolMode: "none",
            lengthMode: "unset",
        });

        expect(password.length).toBeGreaterThanOrEqual(16);
        expect(password.length).toBeLessThanOrEqual(40);
    });
});

describe("password entropy", () => {
    test("stays above 100 bits for multiple generator configurations using E = log2(R^L)", () => {
        const scenarios = [
            {
                name: "length 11 with spaces",
                config: {
                    enableSpaces: true,
                    enableNumbers: false,
                    symbolMode: "none",
                    lengthMode: "11",
                },
            },
            {
                name: "length 15 with numbers and small symbols",
                config: {
                    enableSpaces: true,
                    enableNumbers: true,
                    symbolMode: "small",
                    lengthMode: "15",
                },
            },
            {
                name: "unset length with spaces only",
                config: {
                    enableSpaces: true,
                    enableNumbers: false,
                    symbolMode: "none",
                    lengthMode: "unset",
                },
            },
            {
                name: "unset length with numbers and large symbols",
                config: {
                    enableSpaces: true,
                    enableNumbers: true,
                    symbolMode: "large",
                    lengthMode: "unset",
                },
            },
        ];

        for (const scenario of scenarios) {
            const passwords = Array.from({ length: 100 }, (_, seed) => createPasswordFromHash(
                createSampleHash(seed + 1),
                scenario.config,
            ));
            const alphabet = collectAlphabet(passwords);
            const shortestLength = Math.min(...passwords.map((password) => password.length));
            const entropy = calculateEntropy(alphabet.size, shortestLength);

            if (scenario.config.lengthMode === "11") {
              expect(entropy, scenario.name).toBeGreaterThan(50);
            } else if (scenario.config.lengthMode === "15") {
                expect(entropy, scenario.name).toBeGreaterThan(50);
            } else {
              expect(entropy, scenario.name).toBeGreaterThan(98);
            }
        }
    });

    test("samples 100 generated word combinations to estimate list entropy", () => {
        const passwords = Array.from({ length: 100 }, (_, seed) => createPasswordFromHash(
            createWordSelectionHash({
                nounIndex: seed % 8,
                adjectiveIndex: (seed * 3) % 8,
                verbIndex: (seed * 5) % 8,
                trailingNounIndex: (seed * 7) % 8,
            }),
            {
                enableSpaces: true,
                enableNumbers: false,
                symbolMode: "none",
                lengthMode: "unset",
            },
        ));

        const nounWords = new Set();
        const adjectiveWords = new Set();
        const verbWords = new Set();

        for (const password of passwords) {
            const [noun, adjective, verb, trailingNoun] = password.split(" ");
            nounWords.add(noun);
            adjectiveWords.add(adjective);
            verbWords.add(verb);
            nounWords.add(trailingNoun);
        }

        const entropy = 2 * Math.log2(nounWords.size) + Math.log2(adjectiveWords.size) + Math.log2(verbWords.size);

        expect(nounWords.size).toBe(8);
        expect(adjectiveWords.size).toBe(8);
        expect(verbWords.size).toBe(8);
        expect(entropy).toBeCloseTo(12, 10);
    });

    test("100-word noun and adjective lists in length 11 mode yield 46.60 to 51.71 bits when words are 4 to 6 characters", () => {
        const letterAlphabetSize = 26;
        const fillDigitAlphabetSize = 8;
        const possibleWordLengths = [4, 5, 6];
        const entropies = [];

        for (const nounLength of possibleWordLengths) {
            for (const adjectiveLength of possibleWordLengths) {
                const rawLetterCount = nounLength + adjectiveLength;
                const visibleLetterCount = Math.min(11, rawLetterCount);
                const fillDigitCount = Math.max(0, 11 - rawLetterCount);
                const entropy =
                    visibleLetterCount * Math.log2(letterAlphabetSize) +
                    fillDigitCount * Math.log2(fillDigitAlphabetSize);

                entropies.push(entropy);
            }
        }

        expect(Math.min(...entropies)).toBeCloseTo(46.6035177451, 10);
        expect(Math.max(...entropies)).toBeCloseTo(51.7048368996, 10);
        expect(Math.min(...entropies)).toBeGreaterThan(40);
    });
});

describe("splitPasswordForDisplay", () => {
    test("separates words from separators", () => {
        expect(splitPasswordForDisplay("Lago Nube7Sol")).toEqual([
            { type: "word", value: "Lago" },
            { type: "separator", value: " " },
            { type: "word", value: "Nube" },
            { type: "separator", value: "7" },
            { type: "word", value: "Sol" },
        ]);
    });
});
