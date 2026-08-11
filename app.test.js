import { describe, expect, test } from "bun:test";
import {
    buildSeparatorPool,
    createPasswordFromHash,
    isValidSiteName,
    normalizeTrimmed,
    splitPasswordForDisplay,
} from "./app.js";
import { adjectives, nouns, verbs } from "./words.js";

function calculateChoiceEntropy(...choiceCounts) {
    return choiceCounts.reduce((sum, count) => sum + Math.log2(count), 0);
}

function calculateFixedLengthEntropyRange({
    choiceCounts,
    targetLength,
    minWordLength,
    maxWordLength,
    separatorPoolSize,
    separatorCount,
    fillAlphabetSize = 8,
}) {
    const baseEntropy =
        calculateChoiceEntropy(...choiceCounts) +
        (separatorPoolSize > 0 ? separatorCount * Math.log2(separatorPoolSize) : 0);
    const minRawLength = choiceCounts.length * minWordLength + separatorCount;
    const maxRawLength = choiceCounts.length * maxWordLength + separatorCount;
    const minFillCount = Math.max(0, targetLength - maxRawLength);
    const maxFillCount = Math.max(0, targetLength - minRawLength);

    return {
        minEntropy: baseEntropy + minFillCount * Math.log2(fillAlphabetSize),
        maxEntropy: baseEntropy + maxFillCount * Math.log2(fillAlphabetSize),
    };
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
    // test("uses the updated word list sizes", () => {
    //     expect(nouns).toHaveLength(172);
    //     expect(adjectives).toHaveLength(88);
    //     expect(verbs).toHaveLength(69);
    // });

    test("length 11 mode with no separators yields 13.89 to 22.89 bits with the updated noun and adjective lists", () => {
        const { minEntropy, maxEntropy } = calculateFixedLengthEntropyRange({
            choiceCounts: [nouns.length, adjectives.length],
            targetLength: 11,
            minWordLength: 4,
            maxWordLength: 6,
            separatorPoolSize: 0,
            separatorCount: 0,
        });

        expect(minEntropy).toBeCloseTo(13.8856963733, 10);
        expect(maxEntropy).toBeCloseTo(22.8856963733, 10);
        expect(maxEntropy).toBeGreaterThan(20);
    });

    test("length 15 mode with numbers and small symbols is about 27.81 to 30.81 bits", () => {
        const separatorPoolSize = buildSeparatorPool({
            enableSpaces: true,
            enableNumbers: true,
            symbolMode: "small",
        }).length;
        const { minEntropy, maxEntropy } = calculateFixedLengthEntropyRange({
            choiceCounts: [nouns.length, adjectives.length, verbs.length],
            targetLength: 15,
            minWordLength: 4,
            maxWordLength: 6,
            separatorPoolSize,
            separatorCount: 2,
        });

        expect(separatorPoolSize).toBe(15);
        expect(minEntropy).toBeCloseTo(27.8080020213, 10);
        expect(maxEntropy).toBeCloseTo(30.8080020213, 10);
        expect(minEntropy).toBeGreaterThan(20);
    });

    test("unset mode with spaces only yields about 27.42 bits from the updated word choices", () => {
        const entropy = calculateChoiceEntropy(
            nouns.length,
            adjectives.length,
            verbs.length,
            nouns.length,
        );

        expect(entropy).toBeCloseTo(27.4204855848, 10);
        expect(entropy).toBeGreaterThan(27);
    });

    test("unset mode with numbers and large symbols exceeds 41.52 bits", () => {
        const separatorPoolSize = buildSeparatorPool({
            enableSpaces: true,
            enableNumbers: true,
            symbolMode: "large",
        }).length;
        const entropy = calculateChoiceEntropy(
            nouns.length,
            adjectives.length,
            verbs.length,
            nouns.length,
        ) + 3 * Math.log2(separatorPoolSize);

        expect(separatorPoolSize).toBe(26);
        expect(entropy).toBeCloseTo(41.5218047392, 10);
        expect(entropy).toBeGreaterThan(41.5);
    });

    test("can select all updated nouns, adjectives, and verbs through the hash mapping", () => {
        const nounWords = new Set();
        const adjectiveWords = new Set();
        const verbWords = new Set();

        for (let index = 0; index < nouns.length; index += 1) {
            const password = createPasswordFromHash(
                createWordSelectionHash({ nounIndex: index, adjectiveIndex: 0, verbIndex: 0, trailingNounIndex: 0 }),
                {
                    enableSpaces: true,
                    enableNumbers: false,
                    symbolMode: "none",
                    lengthMode: "unset",
                },
            );
            nounWords.add(password.split(" ")[0]);
        }

        for (let index = 0; index < adjectives.length; index += 1) {
            const password = createPasswordFromHash(
                createWordSelectionHash({ nounIndex: 0, adjectiveIndex: index, verbIndex: 0, trailingNounIndex: 0 }),
                {
                    enableSpaces: true,
                    enableNumbers: false,
                    symbolMode: "none",
                    lengthMode: "unset",
                },
            );
            adjectiveWords.add(password.split(" ")[1]);
        }

        for (let index = 0; index < verbs.length; index += 1) {
            const password = createPasswordFromHash(
                createWordSelectionHash({ nounIndex: 0, adjectiveIndex: 0, verbIndex: index, trailingNounIndex: 0 }),
                {
                    enableSpaces: true,
                    enableNumbers: false,
                    symbolMode: "none",
                    lengthMode: "unset",
                },
            );
            verbWords.add(password.split(" ")[2]);
        }

        expect(nounWords).toHaveLength(172);
        expect(adjectiveWords).toHaveLength(88);
        expect(verbWords).toHaveLength(69);
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
