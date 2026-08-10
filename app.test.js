import { describe, expect, test } from "bun:test";
import {
    buildSeparatorPool,
    createPasswordFromHash,
    isValidSiteName,
    normalizeTrimmed,
    splitPasswordForDisplay,
} from "./app.js";

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
    test("uses digits when spaces are disabled", () => {
        expect(buildSeparatorPool({ disableSpaces: true, enableNumbers: false, symbolMode: "none" })).toEqual([
            "2", "3", "4", "5", "6", "7", "8", "9",
        ]);
    });
});

describe("createPasswordFromHash", () => {
    const hash = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));

    test("creates a fixed length password for mode 11", () => {
        const password = createPasswordFromHash(hash, {
            disableSpaces: false,
            enableNumbers: false,
            symbolMode: "none",
            lengthMode: "11",
        });

        expect(password).toHaveLength(11);
    });

    test("creates a fixed length password for mode 15", () => {
        const password = createPasswordFromHash(hash, {
            disableSpaces: false,
            enableNumbers: true,
            symbolMode: "small",
            lengthMode: "15",
        });

        expect(password).toHaveLength(15);
    });

    test("creates at least 16 characters for unset length mode", () => {
        const password = createPasswordFromHash(hash, {
            disableSpaces: false,
            enableNumbers: false,
            symbolMode: "none",
            lengthMode: "unset",
        });

        expect(password.length).toBeGreaterThanOrEqual(16);
        expect(password.length).toBeLessThanOrEqual(40);
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
