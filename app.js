import { adjectives, nouns, verbs, emojis } from "./words.js";

const STORAGE_KEYS = {
    salt: "mellon.salt",
    siteConfigs: "mellon.site-configs",
};

const DIGITS = "23456789";
const SYMBOL_SETS = {
    none: "",
    small: "-=+*.:",
    large: "/-_=+?%$!@&*:;.<>",
};

const DEFAULT_CONFIG = {
    enableSpaces: true,
    enableNumbers: true,
    symbolMode: "small",
    lengthMode: "unset",
};

const SITE_NAME_PATTERN = /^[a-zA-Z0-9@:.]+$/;
const REVEAL_TIMEOUT_MS = 5_000;
const CLIPBOARD_CLEAR_TIMEOUT_MS = 30_000;
const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000;

const WORD_LISTS = { nouns, adjectives, verbs };

// TODO: Review and lock this emoji list once the product decisions around versioning and immutability are made.
const EMOJI_POOL = emojis;

const LENGTH_PLANS = {
    unset: { targetLength: null, minLength: 16, maxLength: 40, roles: ["nouns", "adjectives", "verbs", "nouns"] },
    11: { targetLength: 11, minLength: null, maxLength: 11, roles: ["nouns", "adjectives"] },
    15: { targetLength: 15, minLength: null, maxLength: 15, roles: ["nouns", "adjectives", "verbs"] },
};

export function normalizeTrimmed(value = "") {
    return String(value).trim();
}

export function isValidSiteName(siteName) {
    const normalized = normalizeTrimmed(siteName);
    return normalized.length > 0 && SITE_NAME_PATTERN.test(normalized);
}

export function capitalizeWord(word) {
    return word.charAt(0).toUpperCase() + word.slice(1);
}

export function getSymbolsForMode(symbolMode) {
    return SYMBOL_SETS[symbolMode] ?? SYMBOL_SETS.none;
}

export function buildSeparatorPool(config = DEFAULT_CONFIG) {
    const pool = [];

    if (config.enableSpaces) {
        pool.push(" ");
    }

    if (config.enableNumbers) {
        pool.push(...DIGITS);
    }

    pool.push(...getSymbolsForMode(config.symbolMode));

    return [...new Set(pool)];
}

export function readUint32Wrapped(bytes, position) {
    if (!bytes.length) {
        return 0;
    }

    let value = 0;

    for (let index = 0; index < 4; index += 1) {
        value = (value << 8) | bytes[(position + index) % bytes.length];
    }

    return value >>> 0;
}

export function buildFillDigits(bytes, startPosition, count) {
    let value = "";

    for (let index = 0; index < count; index += 1) {
        const digitIndex = readUint32Wrapped(bytes, startPosition + index * 4) % DIGITS.length;
        value += DIGITS[digitIndex];
    }

    return value;
}

export function createPasswordFromHash(hashBytes, config = DEFAULT_CONFIG) {
    const mergedConfig = { ...DEFAULT_CONFIG, ...config };
    const plan = LENGTH_PLANS[mergedConfig.lengthMode] ?? LENGTH_PLANS.unset;
    const separatorPool = buildSeparatorPool(mergedConfig);
    let cursor = 0;

    const words = plan.roles.map((role) => {
        const list = WORD_LISTS[role];
        const word = list[readUint32Wrapped(hashBytes, cursor) % list.length];
        cursor += 4;
        return capitalizeWord(word);
    });

    const pieces = [words[0] ?? ""];

    for (let index = 1; index < words.length; index += 1) {
        // TODO: Review the exact separator-selection algorithm once the product decision is made.
        const separator = separatorPool.length
            ? separatorPool[readUint32Wrapped(hashBytes, cursor) % separatorPool.length]
            : "";
        cursor += 4;
        pieces.push(separator, words[index]);
    }

    let password = pieces.join("");

    if (plan.targetLength !== null) {
        if (password.length < plan.targetLength) {
            password += buildFillDigits(hashBytes, cursor, plan.targetLength - password.length);
        }

        return password.slice(0, plan.targetLength);
    }

    // TODO: Review the exact behavior for the unset length mode and whether the output should target a stricter size.
    if (password.length < plan.minLength) {
        password += buildFillDigits(hashBytes, cursor, plan.minLength - password.length);
    }

    return password.slice(0, plan.maxLength);
}

export function splitPasswordForDisplay(password) {
    const tokens = [];
    const letters = /[A-Za-z]/;
    let current = "";
    let currentType = "word";

    for (const character of password) {
        const type = letters.test(character) ? "word" : "separator";

        if (current && type !== currentType) {
            tokens.push({ type: currentType, value: current });
            current = "";
        }

        current += character;
        currentType = type;
    }

    if (current) {
        tokens.push({ type: currentType, value: current });
    }

    return tokens;
}

export async function sha256Bytes(text) {
    const data = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(digest);
}

export async function fingerprintFromText(text) {
    const normalized = normalizeTrimmed(text);

    if (!normalized) {
        return "—";
    }

    const digest = await sha256Bytes(normalized);
    const emojiCount = 4;
    const parts = [];

    for (let index = 0; index < emojiCount; index += 1) {
        const emoji = EMOJI_POOL[readUint32Wrapped(digest, index * 4) % EMOJI_POOL.length];
        parts.push(emoji);
    }

    return parts.join("");
}

export async function derivePasswordHash({ salt, siteName, masterPassword }) {
    const normalizedSalt = normalizeTrimmed(salt);
    const normalizedSiteName = normalizeTrimmed(siteName);
    const normalizedMasterPassword = normalizeTrimmed(masterPassword);

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(normalizedMasterPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"],
    );

    // TODO: Review the exact PBKDF2 and HMAC parameters once the product decision is made.
    const hmacKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new TextEncoder().encode(normalizedSalt),
            iterations: 310000,
            hash: "SHA-256",
        },
        keyMaterial,
        {
            name: "HMAC",
            hash: "SHA-256",
            length: 256,
        },
        false,
        ["sign"],
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        hmacKey,
        new TextEncoder().encode(normalizedSiteName),
    );

    return new Uint8Array(signature);
}

export async function generatePassword({ salt, siteName, masterPassword, config }) {
    const hash = await derivePasswordHash({ salt, siteName, masterPassword });
    return createPasswordFromHash(hash, config);
}

function getStorage() {
    try {
        return window.localStorage;
    } catch {
        return null;
    }
}

function loadJson(storage, key, fallback) {
    if (!storage) {
        return fallback;
    }

    try {
        const raw = storage.getItem(key);
        return raw ? JSON.parse(raw) : fallback;
    } catch {
        return fallback;
    }
}

function saveJson(storage, key, value) {
    if (!storage) {
        return;
    }

    storage.setItem(key, JSON.stringify(value));
}

function createRandomSalt() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function makeDefaultState(storage) {
    return {
        storage,
        storedSalt: storage?.getItem(STORAGE_KEYS.salt) ?? "",
        siteConfigs: loadJson(storage, STORAGE_KEYS.siteConfigs, {}),
        saltEditorOpen: !(storage?.getItem(STORAGE_KEYS.salt) ?? ""),
        generatedPassword: "",
        revealTimer: null,
        clipboardTimer: null,
        inactivityTimer: null,
        saltVisible: false,
        masterPasswordVisible: false,
        passwordVisible: false,
    };
}

function saveSalt(state, salt) {
    state.storedSalt = salt;

    if (state.storage) {
        state.storage.setItem(STORAGE_KEYS.salt, salt);
    }
}

function saveSiteConfigs(state) {
    saveJson(state.storage, STORAGE_KEYS.siteConfigs, state.siteConfigs);
}

function getCurrentConfig(elements) {
    return {
        enableSpaces: elements.enableSpacesInput.checked,
        enableNumbers: elements.enableNumbersInput.checked,
        symbolMode: elements.symbolModeSelect.value,
        lengthMode: elements.lengthModeSelect.value,
    };
}

function setConfigInputs(elements, config = DEFAULT_CONFIG) {
    elements.enableSpacesInput.checked = Boolean(config.enableSpaces);
    elements.enableNumbersInput.checked = Boolean(config.enableNumbers);
    elements.symbolModeSelect.value = config.symbolMode ?? DEFAULT_CONFIG.symbolMode;
    elements.lengthModeSelect.value = config.lengthMode ?? DEFAULT_CONFIG.lengthMode;
}

function getExactSavedSiteName(state, rawSiteName) {
    const normalizedSiteName = normalizeTrimmed(rawSiteName);
    return Object.prototype.hasOwnProperty.call(state.siteConfigs, normalizedSiteName)
        ? normalizedSiteName
        : "";
}

function getEffectiveSalt(state, elements) {
    const editorValue = normalizeTrimmed(elements.saltInput.value);

    if (state.saltEditorOpen && editorValue) {
        return editorValue;
    }

    return state.storedSalt;
}

function getSaltFingerprintSource(state, elements) {
    return state.saltEditorOpen ? elements.saltInput.value : state.storedSalt;
}

function populateSiteNameList(state, elements) {
    const siteNames = Object.keys(state.siteConfigs).sort((left, right) => left.localeCompare(right));
    elements.siteNameList.replaceChildren(...siteNames.map((siteName) => {
        const option = document.createElement("option");
        option.value = siteName;
        return option;
    }));
}

function updateSaltUi(state, elements) {
    const hasStoredSalt = Boolean(state.storedSalt);
    elements.cancelSaltButton.disabled = !hasStoredSalt;
    elements.saltDetails.open = state.saltEditorOpen;
    elements.saltSummary.textContent = hasStoredSalt
        ? "Salt"
        : "No salt stored yet";
}

function renderGeneratedPassword(state, elements) {
    void fingerprintFromText(state.generatedPassword).then((fingerprint) => {
        elements.generatedPasswordFingerprint.textContent = fingerprint;
    });

    if (!state.generatedPassword) {
        elements.generatedPasswordOutput.textContent = "";
        elements.revealPasswordButton.classList.toggle("strike", false);
        elements.revealPasswordButton.disabled = true;
        elements.copyPasswordButton.disabled = true;
        return;
    }

    elements.revealPasswordButton.disabled = false;
    elements.copyPasswordButton.disabled = false;

    if (!state.passwordVisible) {
        elements.generatedPasswordOutput.textContent = "•".repeat(state.generatedPassword.length);
        return;
    }

    elements.generatedPasswordOutput.replaceChildren(...splitPasswordForDisplay(state.generatedPassword).map((token) => {
        const node = document.createElement(token.type === "separator" ? "strong" : "span");
        node.textContent = token.value;
        return node;
    }));
}

function setFormStatus(elements, message) {
    elements.formStatus.innerHTML = `<small>${message}</small>`;
}

async function updateFingerprints(state, elements) {
    const [saltFingerprint, siteFingerprint, masterPasswordFingerprint] = await Promise.all([
        fingerprintFromText(getSaltFingerprintSource(state, elements)),
        fingerprintFromText(elements.siteNameInput.value),
        fingerprintFromText(elements.masterPasswordInput.value),
    ]);

    elements.saltFingerprint.textContent = saltFingerprint;
    elements.siteFingerprint.textContent = siteFingerprint;
    elements.masterPasswordFingerprint.textContent = masterPasswordFingerprint;
}

function clearRevealTimer(state) {
    if (state.revealTimer) {
        clearTimeout(state.revealTimer);
        state.revealTimer = null;
    }
}

function clearClipboardTimer(state) {
    if (state.clipboardTimer) {
        clearTimeout(state.clipboardTimer);
        state.clipboardTimer = null;
    }
}

async function clearClipboardBestEffort() {
    if (!navigator.clipboard?.writeText) {
        return false;
    }

    try {
        await navigator.clipboard.writeText("");
        return true;
    } catch {
        return false;
    }
}

function clearSensitiveInputs(state, elements) {
    elements.siteNameInput.value = "";
    elements.masterPasswordInput.value = "";
    elements.saltInput.value = "";
    state.saltVisible = false;
    elements.saltInput.type = "password";
    elements.toggleSaltButton.classList.toggle("strike", state.saltVisible);
    state.generatedPassword = "";
    state.passwordVisible = false;
    clearRevealTimer(state);
    renderGeneratedPassword(state, elements);
    setFormStatus(elements, "Sensitive fields cleared.");
}

function resetInactivityTimer(state, elements) {
    if (state.inactivityTimer) {
        clearTimeout(state.inactivityTimer);
    }

    // TODO: Review the inactivity timeout duration and exactly which UI state should be cleared.
    state.inactivityTimer = setTimeout(() => {
        clearSensitiveInputs(state, elements);
        updateDerivedState(state, elements).catch(() => {
            setFormStatus(elements, "Unable to refresh after clearing sensitive fields.");
        });
    }, INACTIVITY_TIMEOUT_MS);
}

function persistCurrentSiteConfig(state, elements) {
    const siteName = normalizeTrimmed(elements.siteNameInput.value);

    if (!isValidSiteName(siteName)) {
        return;
    }

    state.siteConfigs[siteName] = getCurrentConfig(elements);
    saveSiteConfigs(state);
    populateSiteNameList(state, elements);
}

function maybeLoadSavedSiteConfig(state, elements) {
    const siteName = getExactSavedSiteName(state, elements.siteNameInput.value);

    // TODO: Review the exact config-loading behavior for typed versus selected site names.
    if (!siteName) {
        return;
    }

    setConfigInputs(elements, state.siteConfigs[siteName]);
}

async function updateDerivedState(state, elements) {
    await updateFingerprints(state, elements);

    const salt = getEffectiveSalt(state, elements);
    const siteName = normalizeTrimmed(elements.siteNameInput.value);
    const masterPassword = normalizeTrimmed(elements.masterPasswordInput.value);
    const savedSiteName = getExactSavedSiteName(state, elements.siteNameInput.value);

    elements.removeSiteButton.disabled = !savedSiteName;

    if (!salt) {
        state.generatedPassword = "";
        renderGeneratedPassword(state, elements);
        setFormStatus(elements, "Set a salt to generate a password.");
        return;
    }

    if (!siteName) {
        state.generatedPassword = "";
        renderGeneratedPassword(state, elements);
        setFormStatus(elements, "Enter a site name.");
        return;
    }

    if (!isValidSiteName(siteName)) {
        state.generatedPassword = "";
        renderGeneratedPassword(state, elements);
        setFormStatus(elements, "Site name contains invalid characters.");
        return;
    }

    if (!masterPassword) {
        state.generatedPassword = "";
        renderGeneratedPassword(state, elements);
        setFormStatus(elements, "Enter the master password.");
        return;
    }

    persistCurrentSiteConfig(state, elements);

    try {
        state.generatedPassword = await generatePassword({
            salt,
            siteName,
            masterPassword,
            config: getCurrentConfig(elements),
        });
        renderGeneratedPassword(state, elements);
        setFormStatus(elements, `Password ready (${state.generatedPassword.length} characters).`);
    } catch (error) {
        console.error(error);
        state.generatedPassword = "";
        renderGeneratedPassword(state, elements);
        setFormStatus(elements, "Password generation failed.");
    }
}

function collectElements(documentRoot) {
    return {
        saltDetails: documentRoot.getElementById("salt-details"),
        saltSummary: documentRoot.getElementById("salt-summary"),
        saltFingerprint: documentRoot.getElementById("salt-fingerprint"),
        saltForm: documentRoot.getElementById("salt-form"),
        saltInput: documentRoot.getElementById("salt-input"),
        toggleSaltButton: documentRoot.getElementById("toggle-salt-button"),
        saveSaltButton: documentRoot.getElementById("save-salt-button"),
        generateSaltButton: documentRoot.getElementById("generate-salt-button"),
        cancelSaltButton: documentRoot.getElementById("cancel-salt-button"),
        siteNameInput: documentRoot.getElementById("site-name-input"),
        siteNameList: documentRoot.getElementById("site-name-list"),
        siteFingerprint: documentRoot.getElementById("site-fingerprint"),
        enableSpacesInput: documentRoot.getElementById("enable-spaces-input"),
        enableNumbersInput: documentRoot.getElementById("enable-numbers-input"),
        symbolModeSelect: documentRoot.getElementById("symbol-mode-select"),
        lengthModeSelect: documentRoot.getElementById("length-mode-select"),
        masterPasswordInput: documentRoot.getElementById("master-password-input"),
        toggleMasterPasswordButton: documentRoot.getElementById("toggle-master-password-button"),
        masterPasswordFingerprint: documentRoot.getElementById("master-password-fingerprint"),
        generatedPasswordOutput: documentRoot.getElementById("generated-password-output"),
        generatedPasswordFingerprint: documentRoot.getElementById("generated-password-fingerprint"),
        formStatus: documentRoot.getElementById("form-status"),
        revealPasswordButton: documentRoot.getElementById("reveal-password-button"),
        copyPasswordButton: documentRoot.getElementById("copy-password-button"),
        resetButton: documentRoot.getElementById("reset-button"),
        removeSiteButton: documentRoot.getElementById("remove-site-button"),
        passwordForm: documentRoot.getElementById("password-form"),
    };
}

async function registerServiceWorker() {
    if (!("serviceWorker" in navigator)) {
        return;
    }

    try {
        await navigator.serviceWorker.register("./sw.js");
    } catch (error) {
        console.error("Service worker registration failed", error);
    }
}

export function startApp(documentRoot = document) {
    const elements = collectElements(documentRoot);
    const state = makeDefaultState(getStorage());

    updateSaltUi(state, elements);
    populateSiteNameList(state, elements);
    setConfigInputs(elements, DEFAULT_CONFIG);
    clearSensitiveInputs(state, elements);

    if (state.storedSalt) {
        elements.saltInput.value = "";
    }

    void updateDerivedState(state, elements);
    resetInactivityTimer(state, elements);
    void registerServiceWorker();

    const onSensitiveInput = async () => {
        resetInactivityTimer(state, elements);
        await updateDerivedState(state, elements);
    };

    elements.saltDetails.addEventListener("toggle", async () => {
        const isOpen = elements.saltDetails.open;

        if (!state.storedSalt && !isOpen) {
            elements.saltDetails.open = true;
            return;
        }

        state.saltEditorOpen = isOpen;

        if (state.saltEditorOpen) {
            elements.saltInput.value = state.storedSalt;
        } else {
            elements.saltInput.value = "";
            state.saltVisible = false;
            elements.saltInput.type = "password";
            elements.toggleSaltButton.classList.toggle("strike", state.saltVisible);
        }

        updateSaltUi(state, elements);
        await updateDerivedState(state, elements);
    });

    elements.cancelSaltButton.addEventListener("click", async () => {
        elements.saltInput.value = state.storedSalt;
        state.saltEditorOpen = false;
        state.saltVisible = false;
        elements.saltInput.type = "password";
        elements.toggleSaltButton.classList.toggle("strike", state.saltVisible);
        updateSaltUi(state, elements);
        await updateDerivedState(state, elements);
    });

    elements.generateSaltButton.addEventListener("click", async () => {
        // TODO: Review the confirmation and regenerate flow for salt changes.
        elements.saltInput.value = createRandomSalt();
        state.saltEditorOpen = true;
        updateSaltUi(state, elements);
        await updateDerivedState(state, elements);
    });

    elements.saltForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const salt = normalizeTrimmed(elements.saltInput.value);

        if (!salt) {
            setFormStatus(elements, "Salt is required.");
            await updateFingerprints(state, elements);
            return;
        }

        elements.saltInput.value = salt;
        saveSalt(state, salt);
        state.saltEditorOpen = false;
        elements.saltInput.value = "";
        updateSaltUi(state, elements);
        await updateDerivedState(state, elements);
    });

    elements.siteNameInput.addEventListener("input", async () => {
        maybeLoadSavedSiteConfig(state, elements);
        await onSensitiveInput();
    });

    elements.siteNameInput.addEventListener("blur", async () => {
        elements.siteNameInput.value = normalizeTrimmed(elements.siteNameInput.value);
        maybeLoadSavedSiteConfig(state, elements);
        await onSensitiveInput();
    });

    elements.masterPasswordInput.addEventListener("input", onSensitiveInput);
    elements.masterPasswordInput.addEventListener("blur", async () => {
        elements.masterPasswordInput.value = normalizeTrimmed(elements.masterPasswordInput.value);
        await onSensitiveInput();
    });

    elements.saltInput.addEventListener("input", onSensitiveInput);
    elements.saltInput.addEventListener("blur", async () => {
        elements.saltInput.value = normalizeTrimmed(elements.saltInput.value);
        await onSensitiveInput();
    });

    [
        elements.enableSpacesInput,
        elements.enableNumbersInput,
        elements.symbolModeSelect,
        elements.lengthModeSelect,
    ].forEach((element) => {
        element.addEventListener("change", async () => {
            persistCurrentSiteConfig(state, elements);
            await onSensitiveInput();
        });
    });

    elements.toggleSaltButton.addEventListener("click", () => {
        state.saltVisible = !state.saltVisible;
        elements.saltInput.type = state.saltVisible ? "text" : "password";
        elements.toggleSaltButton.classList.toggle("strike", state.saltVisible);
        resetInactivityTimer(state, elements);
    });

    elements.toggleMasterPasswordButton.addEventListener("click", () => {
        state.masterPasswordVisible = !state.masterPasswordVisible;
        elements.masterPasswordInput.type = state.masterPasswordVisible ? "text" : "password";
        elements.toggleMasterPasswordButton.classList.toggle("strike", state.masterPasswordVisible);
        resetInactivityTimer(state, elements);
    });

    elements.revealPasswordButton.addEventListener("click", () => {
        if (!state.generatedPassword) {
            return;
        }

        state.passwordVisible = !state.passwordVisible;
        elements.revealPasswordButton.classList.toggle("strike", state.passwordVisible);
        clearRevealTimer(state);

        if (state.passwordVisible) {
            state.revealTimer = setTimeout(() => {
                state.passwordVisible = false;
                elements.revealPasswordButton.classList.toggle("strike", state.passwordVisible);
                renderGeneratedPassword(state, elements);
            }, REVEAL_TIMEOUT_MS);
        }

        renderGeneratedPassword(state, elements);
        resetInactivityTimer(state, elements);
    });

    elements.copyPasswordButton.addEventListener("click", async () => {
        if (!state.generatedPassword) {
            return;
        }

        if (!navigator.clipboard?.writeText) {
            setFormStatus(elements, "Clipboard API is not available in this browser.");
            return;
        }

        try {
            await navigator.clipboard.writeText(state.generatedPassword);
            setFormStatus(elements, "Copied password to the clipboard.");
            clearClipboardTimer(state);
            state.clipboardTimer = setTimeout(async () => {
                const cleared = await clearClipboardBestEffort();
                setFormStatus(elements, cleared
                    ? "Clipboard cleared after 30 seconds."
                    : "Copied password, but clipboard auto-clear was not available.");
            }, CLIPBOARD_CLEAR_TIMEOUT_MS);
        } catch (error) {
            console.error(error);
            setFormStatus(elements, "Unable to copy the password.");
        }

        resetInactivityTimer(state, elements);
    });

    elements.passwordForm.addEventListener("reset", async (event) => {
        event.preventDefault();
        elements.siteNameInput.value = "";
        elements.masterPasswordInput.value = "";
        state.passwordVisible = false;
        elements.revealPasswordButton.classList.toggle("strike", state.passwordVisible);
        clearRevealTimer(state);
        await clearClipboardBestEffort();
        clearClipboardTimer(state);
        await updateDerivedState(state, elements);
        resetInactivityTimer(state, elements);
        setFormStatus(elements, "Site name, master password, and clipboard cleared.");
    });

    elements.removeSiteButton.addEventListener("click", async () => {
        const siteName = getExactSavedSiteName(state, elements.siteNameInput.value);

        if (!siteName) {
            return;
        }

        delete state.siteConfigs[siteName];
        saveSiteConfigs(state);
        populateSiteNameList(state, elements);
        elements.siteNameInput.value = "";
        setConfigInputs(elements, DEFAULT_CONFIG);
        await updateDerivedState(state, elements);
        resetInactivityTimer(state, elements);
    });

    window.addEventListener("pagehide", () => {
        clearSensitiveInputs(state, elements);
    });

    window.addEventListener("beforeunload", () => {
        clearSensitiveInputs(state, elements);
    });

    ["pointerdown", "keydown", "focusin", "input"].forEach((eventName) => {
        window.addEventListener(eventName, () => {
            resetInactivityTimer(state, elements);
        }, { passive: true });
    });
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => startApp());
    } else {
        startApp();
    }
}
