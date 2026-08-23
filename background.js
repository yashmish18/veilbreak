/**
 * background.js — Browser Vigilant Service Worker (MV3)
 *
 * Responsibilities:
 *  1. Cryptographic Identity & ECDSA Request Signing (P-256)
 *  2. Client-side Merkle Threat Ledger with tamper verification
 *  3. Fast 3-Stage Pre-Navigation Scanner (<2ms)
 *  4. Bounded, privacy-preserving scan history (No raw PII/URLs)
 *  5. Download interception & heuristics
 *  6. Temporary Warning Bypass Handling (Proceed Anyway)
 *  7. State provider for popup UI and dashboard bridge
 */

import { identity } from './blockchain/identity.js';
import { MerkleTree } from './blockchain/merkle_tree.js';

// ── Storage keys ─────────────────────────────────────────────────────────────
const KEYS = {
    HISTORY: "bv_scan_history",
    VAULT: "bv_threat_vault",
    STATS: "bv_stats",
    SETTINGS: "bv_settings",
    TAB_STATE: "bv_tab_state",
};

const MAX_HISTORY = 100;
const API_BASE = "http://localhost:3000/api/vault";

const DEFAULT_SETTINGS = {
    protection: true,
    autoBlock: true,
    blockThreshold: 0.50,
    upiDetection: true,
    downloadScanner: true,
    domAnalysis: true,
    notifications: true,
    strictMode: false,
    allowlist: ["localhost", "127.0.0.1"]
};

// ── In-Memory Merkle Vault Cache ─────────────────────────────────────────────
let blockedDomainHashes = new Set();
let merkleRoot = null;
const merkleTree = new MerkleTree();

// ── Temporary Bypass Map for "Proceed Anyway" (domain -> expiration timestamp)
const temporaryBypass = new Map();

function isDomainBypassed(domain) {
    const now = Date.now();
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
    for (const [d, expires] of temporaryBypass.entries()) {
        if (expires < now) {
            temporaryBypass.delete(d);
        } else if (cleanDomain === d || cleanDomain.endsWith('.' + d)) {
            return true;
        }
    }
    return false;
}

// ── SHA-256 via Web Crypto ───────────────────────────────────────────────────
async function sha256(data) {
    const encoded = new TextEncoder().encode(data);
    const buf = await crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── Merkle Vault Cache & Tamper Verification ─────────────────────────────────
async function rebuildVaultCache() {
    const data = await chrome.storage.local.get(KEYS.VAULT);
    const vault = data[KEYS.VAULT] || { blocks: [], merkleRoot: "0".repeat(64) };
    blockedDomainHashes.clear();
    merkleTree.leaves = [];

    const allHashes = [];
    for (const block of vault.blocks) {
        if (block.domainHash) {
            blockedDomainHashes.add(block.domainHash);
            allHashes.push(block.domainHash);
            await merkleTree.addLeaf(block.domainHash);
        }
    }

    const computed = merkleTree.getRoot() || (allHashes.length === 0 ? "0".repeat(64) : await sha256([...allHashes].sort().join("")));
    
    if (vault.blocks.length > 0 && vault.merkleRoot && computed !== vault.merkleRoot) {
        console.warn("[BV] Cryptographic Merkle Root mismatch — ledger may be tampered!");
        await chrome.storage.local.set({ bv_vault_tampered: true });
    } else {
        await chrome.storage.local.set({ bv_vault_tampered: false });
    }
    merkleRoot = computed;
    console.log(`[BV] Cryptographic Threat Ledger loaded: ${blockedDomainHashes.size} verified threat hashes (Merkle root: ${computed.slice(0, 16)}...)`);
}

async function getVault() {
    const data = await chrome.storage.local.get(KEYS.VAULT);
    return data[KEYS.VAULT] || { blocks: [], merkleRoot: "0".repeat(64) };
}

// ── Genesis Block ─────────────────────────────────────────────────────────────
async function buildGenesisBlock() {
    const block = {
        index: 0,
        timestamp: new Date().toISOString(),
        type: "GENESIS",
        urlSummary: null,
        domainHash: null,
        threatType: null,
        signals: [],
        riskScore: null,
        prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: 0,
    };
    block.hash = await hashBlock(block);
    return block;
}

async function hashBlock(block) {
    const data = `${block.index}${block.timestamp}${block.domainHash || ''}${JSON.stringify(block.signals)}${block.prevHash}${block.nonce}`;
    return sha256(data);
}

async function appendChainBlock(threatData) {
    const vault = await getVault();
    const prev = vault.blocks[vault.blocks.length - 1] || await buildGenesisBlock();

    // Privacy-preserving: Extract hostname only, never raw paths or query strings
    let domain = "";
    try {
        domain = new URL(threatData.url).hostname.toLowerCase();
    } catch {
        domain = String(threatData.url).toLowerCase().trim();
    }
    if (domain.startsWith('www.')) domain = domain.slice(4);

    const domainHash = await sha256(domain);

    const block = {
        index: prev.index + 1,
        timestamp: new Date().toISOString(),
        type: "THREAT_BLOCKED",
        urlSummary: domain,     // Hostname only (Privacy-safe)
        domainHash,             // SHA-256(hostname)
        threatType: threatData.threatType || "MALICIOUS_DOMAIN",
        signals: (threatData.signals || []).slice(0, 5),
        riskScore: threatData.riskScore || 90,
        layer: threatData.layer || "heuristic",
        prevHash: prev.hash,
        nonce: crypto.getRandomValues(new Uint32Array(1))[0],
    };

    block.hash = await hashBlock(block);
    vault.blocks.push(block);

    // Update Merkle tree
    await merkleTree.addLeaf(domainHash);
    vault.merkleRoot = merkleTree.getRoot() || await sha256(vault.blocks.map(b => b.domainHash).filter(Boolean).sort().join(""));

    await chrome.storage.local.set({ [KEYS.VAULT]: vault });

    blockedDomainHashes.add(domainHash);
    merkleRoot = vault.merkleRoot;

    // Asymmetrically signed submission to Community Vault
    submitThreatToVault(domainHash, block.threatType, (block.riskScore || 90) / 100);

    return block;
}

// ── Authenticated Community Vault Communication ──────────────────────────────
async function submitThreatToVault(hash, threatType = "MALICIOUS_DOMAIN", confidence = 0.95) {
    try {
        await identity.initialize();
        const payload = {
            hash,
            threatType,
            confidence,
            evidence: {
                source: "extension-ml",
                timestamp: Date.now()
            }
        };

        const signedHeaders = await identity.signRequest("POST", "/api/vault/submit", payload);

        await fetch(`${API_BASE}/submit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...signedHeaders
            },
            body: JSON.stringify(payload)
        });
    } catch (e) {
        // Soft fail if server is unreachable
    }
}

async function syncThreatVault() {
    try {
        await identity.initialize();
        await identity.ensureRegistered(API_BASE);

        const { bv_last_sync } = await chrome.storage.local.get("bv_last_sync");
        const since = bv_last_sync || 0;

        const res = await fetch(`${API_BASE}/sync?since=${since}&clientId=${identity.clientId}`);
        if (!res.ok) return;

        const data = await res.json();
        if (data && data.hashes && Array.isArray(data.hashes) && data.hashes.length > 0) {
            for (const h of data.hashes) {
                blockedDomainHashes.add(h);
                await merkleTree.addLeaf(h);
            }
            await chrome.storage.local.set({ "bv_last_sync": Date.now() });
            console.log(`[BV Vault] Synced ${data.hashes.length} new verified community threats.`);
        }
    } catch {
        // Soft fail if server unreachable
    }
}

// ── Init & Lifecycle ─────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
    try {
        await identity.initialize();
        await identity.ensureRegistered(API_BASE);
    } catch {}

    const existing = await chrome.storage.local.get(KEYS.VAULT);
    if (!existing[KEYS.VAULT]) {
        const genesis = await buildGenesisBlock();
        await chrome.storage.local.set({
            [KEYS.VAULT]: { blocks: [genesis], merkleRoot: genesis.hash },
            [KEYS.HISTORY]: [],
            [KEYS.STATS]: { totalScanned: 0, totalBlocked: 0, threatsToday: 0, lastReset: todayDateStr() },
            [KEYS.TAB_STATE]: {},
        });
    }
    await ensureSettingsDefaults();
    await rebuildVaultCache();
    console.log("[BV] Browser Vigilant Engine initialized with ECDSA identity.");
    await syncThreatVault();
});

chrome.runtime.onStartup.addListener(async () => {
    try {
        await identity.initialize();
    } catch {}
    await resetDailyStatsIfNeeded();
    await rebuildVaultCache();
    await ensureSettingsDefaults();
    await syncThreatVault();
});

// ── Settings ──────────────────────────────────────────────────────────────────
async function ensureSettingsDefaults() {
    const { [KEYS.SETTINGS]: stored } = await chrome.storage.sync.get(KEYS.SETTINGS);
    const merged = { ...DEFAULT_SETTINGS, ...(stored || {}) };
    await chrome.storage.sync.set({ [KEYS.SETTINGS]: merged });
    return merged;
}

async function getSettings() {
    const { [KEYS.SETTINGS]: s } = await chrome.storage.sync.get(KEYS.SETTINGS);
    return s || DEFAULT_SETTINGS;
}

// ── History & Stats (Privacy-Minimized) ───────────────────────────────────────
async function recordScan(entry) {
    const { [KEYS.HISTORY]: history } = await chrome.storage.local.get(KEYS.HISTORY);
    const log = history || [];

    // Privacy safeguard: Strip any query params or paths from URL
    let sanitizedDomain = "unknown";
    try {
        sanitizedDomain = new URL(entry.url).hostname;
    } catch {
        sanitizedDomain = String(entry.url || "").split('/')[0];
    }

    const sanitizedEntry = {
        domain: sanitizedDomain,
        status: entry.status,
        scanMs: entry.scanMs || 0,
        riskScore: entry.riskScore || 0,
        threatType: entry.threatType || "Clean",
        signals: (entry.signals || []).slice(0, 3),
        timestamp: new Date().toISOString()
    };

    log.unshift(sanitizedEntry);
    if (log.length > MAX_HISTORY) log.length = MAX_HISTORY;
    await chrome.storage.local.set({ [KEYS.HISTORY]: log });
}

async function updateStats(blocked) {
    const { [KEYS.STATS]: stats } = await chrome.storage.local.get(KEYS.STATS);
    const s = stats || { totalScanned: 0, totalBlocked: 0, threatsToday: 0, lastReset: todayDateStr() };
    if (s.lastReset !== todayDateStr()) {
        s.threatsToday = 0;
        s.lastReset = todayDateStr();
    }
    s.totalScanned += 1;
    if (blocked) { s.totalBlocked += 1; s.threatsToday += 1; }
    await chrome.storage.local.set({ [KEYS.STATS]: s });
    return s;
}

async function resetDailyStatsIfNeeded() {
    const { [KEYS.STATS]: stats } = await chrome.storage.local.get(KEYS.STATS);
    if (stats && stats.lastReset !== todayDateStr()) {
        await chrome.storage.local.set({
            [KEYS.STATS]: { ...stats, threatsToday: 0, lastReset: todayDateStr() }
        });
    }
}

// ── Tab State & Badges ────────────────────────────────────────────────────────
async function setTabState(tabId, state) {
    if (!tabId) return;
    const { [KEYS.TAB_STATE]: ts } = await chrome.storage.local.get(KEYS.TAB_STATE);
    const tabState = ts || {};
    tabState[tabId] = state;
    await chrome.storage.local.set({ [KEYS.TAB_STATE]: tabState });
}

async function getTabState(tabId) {
    if (!tabId) return null;
    const { [KEYS.TAB_STATE]: ts } = await chrome.storage.local.get(KEYS.TAB_STATE);
    return (ts || {})[tabId] || null;
}

function setBadge(tabId, status) {
    if (!tabId) return;
    if (status === "threat") {
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
        chrome.action.setBadgeText({ text: "✕", tabId });
    } else if (status === "warning") {
        chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId });
        chrome.action.setBadgeText({ text: "!", tabId });
    } else if (status === "safe") {
        chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId });
        chrome.action.setBadgeText({ text: "✓", tabId });
    } else {
        chrome.action.setBadgeText({ text: "", tabId });
    }
}

// ── Message Listener ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse).catch(e => {
        console.error("[BV] Message error:", e);
        sendResponse({ error: e.message });
    });
    return true;
});

async function handleMessage(message, sender) {
    const { type } = message;

    if (type === "SCAN_RESULT") {
        const { result, tabId } = message;
        const settings = await getSettings();
        if (!settings.protection) return { ack: true };

        const targetTabId = tabId || sender.tab?.id;
        if (targetTabId) await setTabState(targetTabId, result);

        await recordScan(result);
        const stats = await updateStats(result.verdict === "threat");

        if (targetTabId) setBadge(targetTabId, result.verdict);

        if (result.verdict === "threat") {
            await appendChainBlock(result);

            if (settings.notifications) {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icons/icon48.png",
                    title: "🛡 Browser Vigilant — Threat Blocked",
                    message: `${result.threatType} detected on ${truncateUrl(result.url, 40)}`,
                    priority: 2,
                });
            }
        }

        return { ack: true, stats };
    }

    if (type === "GET_STATE") {
        const { tabId } = message;
        const [tabState, settings, stats, history, vault, tampered] = await Promise.all([
            getTabState(tabId),
            getSettings(),
            chrome.storage.local.get(KEYS.STATS).then(r => r[KEYS.STATS] || { totalScanned: 0, totalBlocked: 0, threatsToday: 0 }),
            chrome.storage.local.get(KEYS.HISTORY).then(r => r[KEYS.HISTORY] || []),
            getVault(),
            chrome.storage.local.get("bv_vault_tampered").then(r => r.bv_vault_tampered || false),
        ]);
        return {
            tabState, settings, stats, history,
            chain: vault.blocks,
            chainTampered: tampered,
            merkleRoot: vault.merkleRoot,
            vaultSize: blockedDomainHashes.size,
            clientId: identity.clientId
        };
    }

    if (type === "TEMPORARY_BYPASS") {
        const urlToBypass = message.url || "";
        try {
            let domain = new URL(urlToBypass).hostname.toLowerCase().replace(/^www\./, '');
            temporaryBypass.set(domain, Date.now() + 5 * 60 * 1000); // 5-minute temporary bypass
            console.log(`[BV] Temporary bypass granted for: ${domain}`);
            return { success: true };
        } catch {
            return { success: false };
        }
    }

    if (type === "SAVE_SETTINGS") {
        const merged = { ...DEFAULT_SETTINGS, ...message.settings };
        await chrome.storage.sync.set({ [KEYS.SETTINGS]: merged });
        return { ack: true };
    }

    if (type === "CLEAR_HISTORY") {
        await chrome.storage.local.set({ [KEYS.HISTORY]: [] });
        return { ack: true };
    }

    return { error: "Unknown message type" };
}

// ── Download Scanning ─────────────────────────────────────────────────────────
const DANGEROUS_EXTENSIONS = new Set([
    "exe", "scr", "bat", "cmd", "ps1", "vbs", "wsf", "hta", "jar", "msi", "msp",
    "reg", "dll", "pif", "com", "cpl", "inf", "apk", "ipa", "dmg"
]);

chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
    const filename = (downloadItem.filename || "").toLowerCase();
    const ext = filename.split(".").pop();

    if (DANGEROUS_EXTENSIONS.has(ext)) {
        chrome.downloads.pause(downloadItem.id);
        chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon48.png",
            title: "⚠ Dangerous Download Intercepted",
            message: `Executable file '${downloadItem.filename}' blocked for security review.`,
            priority: 2
        });
        chrome.downloads.cancel(downloadItem.id);
    }
    suggest({ filename: downloadItem.filename });
    return true;
});

// ── Pre-Navigation Heuristics (<2ms) ──────────────────────────────────────────
const PRENAV_BRANDS = ["google", "facebook", "amazon", "apple", "microsoft", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "whatsapp", "youtube", "ebay",
    "coinbase", "binance", "metamask", "paytm", "phonepe", "hdfc", "icici", "sbi", "gpay"];

const PRENAV_SUSP_TLDS = new Set(["xyz", "tk", "top", "cf", "ml", "ga", "gq", "pw", "cc",
    "icu", "club", "online", "site", "space", "live", "click", "link", "info", "biz"]);

function prenavScan(url) {
    let score = 0;
    const signals = [];
    const low = url.toLowerCase();

    let host = "", tld = "", domain = "", path = "", scheme = "";
    try {
        const u = new URL(url);
        host = u.hostname;
        path = u.pathname;
        tld = host.split(".").pop() || "";
        domain = host.split(".").slice(-2).join(".");
        scheme = u.protocol.replace(":", "");
    } catch { return { score: 0, signals: [], threatType: "Parse Error", verdict: "safe" }; }

    if (scheme !== "http" && scheme !== "https") {
        return { score: 0, signals: [], threatType: "Clean", verdict: "safe" };
    }

    if (host.includes("xn--")) { score += 0.9; signals.push("Punycode / IDN Homograph"); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 0.85; signals.push("IP Address in URL"); }
    if (PRENAV_SUSP_TLDS.has(tld)) { score += 0.55; signals.push(`Suspicious TLD (.${tld})`); }
    if (host.split(".").length >= 5) { score += 0.45; signals.push("Excessive Subdomain Depth"); }
    if (/upi:\/\/pay|pa=.*@|vpa=/i.test(url)) { score += 0.6; signals.push("UPI Collect Request"); }

    const riskScore = Math.min(Math.round(score * 100), 100);
    let verdict = riskScore >= 50 ? "threat" : riskScore >= 30 ? "warning" : "safe";
    return { score, riskScore, signals, threatType: signals[0] || "Clean", verdict };
}

// ── Pre-Navigation Hook ───────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;

    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    // Check if user clicked "Proceed Anyway"
    if (url.includes("bv_allow=1")) return;

    let domain = "";
    try {
        domain = new URL(url).hostname.toLowerCase();
    } catch { return; }

    if (isDomainBypassed(domain)) {
        console.log(`[BV] Temporary bypass active for ${domain}. Skipping prenav block.`);
        return;
    }

    const settings = await getSettings();
    if (!settings.protection) return;

    // 1. Allowlist Check
    const allowed = settings.allowlist || [];
    if (allowed.some(d => domain === d.trim().toLowerCase() || domain.endsWith("." + d.trim().toLowerCase()))) {
        return;
    }

    // 2. Merkle Threat Vault (O(1) Hash Lookup)
    const cleanDomain = domain.replace(/^www\./, '');
    const dHash = await sha256(cleanDomain);
    if (blockedDomainHashes.has(dHash)) {
        const params = new URLSearchParams({
            url: encodeURIComponent(url),
            risk: 100,
            threat: "Cryptographic Threat Ledger: Confirmed Blocked Domain",
            signals: encodeURIComponent("Merkle Tree Match|SHA-256 Domain Hash Confirmed")
        });
        chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL(`block.html?${params}`) });
        setBadge(details.tabId, "threat");
        return;
    }

    // 3. Fast Heuristics Pre-filter (<2ms)
    const result = prenavScan(url);
    if (result.verdict === "threat" && settings.autoBlock) {
        const params = new URLSearchParams({
            url: encodeURIComponent(url),
            risk: result.riskScore,
            threat: result.threatType,
            signals: encodeURIComponent(result.signals.join("|"))
        });
        chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL(`block.html?${params}`) });
        setBadge(details.tabId, "threat");

        await recordScan({
            url, status: "threat", scanMs: 0,
            riskScore: result.riskScore,
            signals: result.signals,
            threatType: result.threatType
        });
        await updateStats(true);
        await appendChainBlock({
            url, threatType: result.threatType,
            signals: result.signals, riskScore: result.riskScore
        });
    }
});

function todayDateStr() {
    return new Date().toISOString().slice(0, 10);
}

function truncateUrl(url, max) {
    return url.length > max ? url.slice(0, max - 3) + "..." : url;
}
