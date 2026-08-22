/**
 * content.js — Browser Vigilant Detection Engine (Layers 1–4)
 */

// ── Web Dashboard Bridge (PRIORITY) ──────────────────────────────────────────
let cachedSettings = null; // Local copy for instant allowlist checks

window.addEventListener("message", (event) => {
    if (!event.data || event.data.type !== "BV_WEB_REQUEST") return;

    const { action, settings } = event.data;

    // Cache settings locally if sent from dashboard
    if (action === "SAVE_SETTINGS" && settings) {
        cachedSettings = settings;
    }

    if (action === "GET_STATS") {
        try {
            chrome.runtime.sendMessage({ type: "GET_STATE" }, (response) => {
                if (chrome.runtime.lastError) return;
                if (response) {
                    if (response.settings) cachedSettings = response.settings;
                    window.postMessage({
                        type: "BV_WEB_RESPONSE",
                        action: "GET_STATS",
                        data: response
                    }, "*");
                }
            });
        } catch (e) { }
    }

    if (action === "SAVE_SETTINGS") {
        try {
            chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", settings }, (response) => {
                if (chrome.runtime.lastError) return;
                window.postMessage({
                    type: "BV_WEB_RESPONSE",
                    action: "SAVE_SETTINGS",
                    success: response?.ack
                }, "*");
            });
        } catch (e) { }
    }
});

// ── Blockchain Threat Vault Integration ──────────────────────────────────────────
// Initialize blockchain components
let threatVault = null;
let isVaultInitialized = false;
let blockchainModules = null;

// Load blockchain dependencies first
async function loadBlockchainDependencies() {
    if (blockchainModules) return blockchainModules;

    try {
        // Load all blockchain modules
        const basePath = chrome.runtime.getURL('blockchain/');
        const [merkleModule, consensusModule, registryModule, vaultModule] = await Promise.all([
            import(basePath + 'merkle_tree.js'),
            import(basePath + 'federated_consensus.js'),
            import(basePath + 'threat_registry.js'),
            import(basePath + 'blockchain_vault.js')
        ]);

        blockchainModules = {
            MerkleTree: merkleModule.MerkleTree,
            FederatedConsensus: consensusModule.FederatedConsensus,
            ThreatRegistry: registryModule.ThreatRegistry,
            BlockchainThreatVault: vaultModule.BlockchainThreatVault
        };

        console.log('[Blockchain] Dependencies loaded successfully');
        return blockchainModules;
    } catch (error) {
        console.error('[Blockchain] Failed to load dependencies:', error);
        return null;
    }
}

async function initializeThreatVault() {
    if (isVaultInitialized) return;

    try {
        // Load dependencies first
        const modules = await loadBlockchainDependencies();
        if (!modules) {
            throw new Error('Failed to load blockchain dependencies');
        }

        // Create instances with proper dependencies
        const { BlockchainThreatVault, MerkleTree, FederatedConsensus, ThreatRegistry } = modules;

        // Initialize components in correct order
        const merkleTree = new MerkleTree();
        const consensus = new FederatedConsensus('browser-node-' + Date.now());
        const registry = new ThreatRegistry();

        // Create vault with dependencies
        threatVault = new BlockchainThreatVault(merkleTree, consensus, registry);
        await threatVault.initialize();
        isVaultInitialized = true;
        console.log('[Blockchain] Threat vault initialized successfully');
    } catch (error) {
        console.error('[Blockchain] Failed to initialize threat vault:', error);
        threatVault = null;
    }
}

// Enhanced threat checking with blockchain integration
async function checkThreatWithBlockchain(url) {
    if (!isVaultInitialized) {
        await initializeThreatVault();
    }

    if (threatVault) {
        try {
            const result = await threatVault.isThreat(url);
            if (result.isThreat) {
                return {
                    isThreat: true,
                    confidence: 0.99, // High confidence from blockchain
                    source: `blockchain_${result.source}`,
                    threatType: 'BLOCKCHAIN_CONFIRMED'
                };
            }
        } catch (error) {
            console.warn('[Blockchain] Check failed, falling back:', error);
        }
    }

    return null; // Fall back to traditional method
}

// Enhanced threat submission to blockchain
async function submitThreatToBlockchain(domain, confidence, threatType, evidence) {
    if (!isVaultInitialized) {
        await initializeThreatVault();
    }

    if (threatVault) {
        try {
            const result = await threatVault.submitThreat(domain, confidence, threatType, evidence);
            console.log(`[Blockchain] Threat submitted: ${domain}`);
            return result;
        } catch (error) {
            console.error(`[Blockchain] Failed to submit threat ${domain}:`, error);
        }
    }

    return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM — Cybersecurity Intelligence Engine
// Modules: Feature Extraction, Tech Fingerprinting, Security Headers,
//          Legacy Detection, Suspicious Content, Resource Audit, Cookie Audit
// ══════════════════════════════════════════════════════════════════════════════

// ── SHA-256 helper for PHANTOM modules ────────────────────────────────────────
async function sha256Phantom(data) {
    const encoded = new TextEncoder().encode(data);
    const buf = await crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ══════════════════════════════════════════════════════════════════════════════
// JavaScript Feature Extractor — 56 features (mirrors model/features.py)
// Used as fallback when Rust WASM is unavailable
// ══════════════════════════════════════════════════════════════════════════════

function extractFeaturesJS(url) {
    const f = new Array(56).fill(0.0);
    const low = url.toLowerCase();

    // Parse URL
    let scheme = "", host = "", path = "", query = "", fragment = "", port = null;
    let tld = "", domain = "", sub = "", labels = [];
    try {
        const u = new URL(url);
        scheme = u.protocol.replace(":", "");
        host = u.hostname.toLowerCase();
        path = u.pathname;
        query = u.search.slice(1);
        fragment = u.hash;
        port = u.port ? parseInt(u.port) : null;
        labels = host.split(".");
        tld = labels[labels.length - 1] || "";
        domain = labels.slice(-2).join(".");
        sub = labels.slice(0, -2).join(".");
    } catch {
        host = url; labels = [url]; tld = ""; domain = url; sub = "";
    }

    // ── Shannon entropy ──
    function entropy(s) {
        if (!s) return 0;
        const freq = {};
        for (const c of s) freq[c] = (freq[c] || 0) + 1;
        const n = s.length;
        return -Object.values(freq).reduce((sum, f) => sum + (f / n) * Math.log2(f / n), 0);
    }

    // ── N-gram entropy ──
    function ngramEntropy(s, n) {
        if (s.length < n) return 0;
        const ngrams = [];
        for (let i = 0; i <= s.length - n; i++) ngrams.push(s.substring(i, i + n));
        const freq = {};
        for (const g of ngrams) freq[g] = (freq[g] || 0) + 1;
        const total = ngrams.length;
        return -Object.values(freq).reduce((sum, f) => sum + (f / total) * Math.log2(f / total), 0);
    }

    // ── Levenshtein ──
    function lev(a, b) {
        const m = a.length, n = b.length;
        let p = Array.from({ length: n + 1 }, (_, i) => i);
        for (let i = 1; i <= m; i++) {
            const c = [i];
            for (let j = 1; j <= n; j++)
                c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
            p = c;
        }
        return p[n];
    }

    // ── Max consecutive consonants ──
    function maxConsonantRun(s) {
        const vowels = new Set("aeiou");
        let max = 0, cur = 0;
        for (const c of s.toLowerCase()) {
            if (/[a-z]/.test(c) && !vowels.has(c)) { cur++; max = Math.max(max, cur); }
            else cur = 0;
        }
        return max;
    }

    const BRANDS = ["google","facebook","amazon","apple","microsoft","paypal","netflix",
        "instagram","twitter","linkedin","whatsapp","youtube","yahoo","ebay",
        "dropbox","spotify","adobe","chase","wellsfargo","bankofamerica",
        "citi","hsbc","barclays","halifax","natwest","santander","lloyds",
        "steam","roblox","epic","coinbase","binance","metamask","opensea",
        "paytm","phonepe","gpay","bhim","razorpay","hdfc","icici","sbi",
        "axis","kotak","airtel","jio","vodafone","bsnl","flipkart","myntra"];

    const SUSP_TLDS = new Set(["xyz","tk","top","cf","ml","ga","gq","pw","cc","icu","club",
        "online","site","website","space","live","click","link","info","biz","work",
        "tech","store","shop","ru","cn","vip","win","loan","download"]);

    const LEGIT_UPI = new Set(["okaxis","okicici","oksbi","okhdfcbank","ybl","ibl","axl",
        "apl","fbl","upi","paytm","waaxis","waxis","rajgovhdfcbank","barodampay",
        "allbank","andb","aubank","cnrb","csbpay","dbs","dcb","federal","hdfcbank",
        "idbi","idfc","indus","idfcbank","jio","kotak","lvb","mahb","nsdl","pnb",
        "psb","rbl","sib","tjsb","uco","union","united","vijb","yapl","airtel",
        "airtelpaymentsbank","postbank"]);

    const SHORT_URLS = new Set(["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
        "buff.ly","adf.ly","tiny.cc","clck.ru","cutt.ly","rb.gy","short.io","v.gd"]);

    const DANGER_EXT = new Set(["exe","scr","bat","cmd","ps1","vbs","wsf","hta","jar",
        "msi","msp","reg","dll","pif","com","cpl","inf","apk","ipa","dmg","pkg","deb","rpm"]);

    // GROUP A: Lexical Structure (F0-F15)
    f[0] = url.length;
    f[1] = host.length;
    f[2] = path.length;
    f[3] = query.length;
    f[4] = (url.match(/\./g) || []).length;
    f[5] = (url.match(/-/g) || []).length;
    f[6] = (url.match(/_/g) || []).length;
    const noProto = url.includes("//") ? url.split("//").slice(1).join("//") : url;
    f[7] = (noProto.match(/\//g) || []).length;
    f[8] = (url.match(/@/g) || []).length;
    const digits = (url.match(/\d/g) || []).length;
    f[9] = digits;
    f[10] = digits / Math.max(url.length, 1);
    f[11] = scheme === "https" ? 1.0 : 0.0;
    f[12] = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 1.0 : 0.0;
    f[13] = host.includes("xn--") ? 1.0 : 0.0;
    f[14] = Math.max(labels.length - 2, 0);
    f[15] = (port !== null && ![80, 443, 8080, 8443].includes(port)) ? 1.0 : 0.0;

    // GROUP B: Information Theory (F16-F20)
    f[16] = entropy(url);
    f[17] = entropy(host);
    f[18] = entropy(path);
    f[19] = ngramEntropy(host, 2);
    f[20] = ngramEntropy(host, 3);

    // GROUP C: Brand Similarity (F21-F23)
    const core = (domain.split(".")[0] || "").toLowerCase();
    const minDist = Math.min(...BRANDS.map(b => lev(core, b)));
    f[21] = (minDist > 0 && minDist <= 2) ? 1.0 : 0.0;
    f[22] = Math.min(minDist, 10) / 10.0;
    const brandInSub = BRANDS.some(b => sub.includes(b));
    const brandInReg = BRANDS.some(b => core.includes(b));
    f[23] = (brandInSub && !brandInReg) ? 1.0 : 0.0;

    // GROUP D: Keyword Signals (F24-F30)
    const loginKw = ["login","signin","sign-in","account","verify","auth","authenticate","confirm","update"];
    const trustKw = ["secure","safe","trust","bank","protected","official","helpdesk"];
    const payKw = ["pay","payment","wallet","upi","gpay","paytm","bhim","razorpay","phonepay"];
    const freeKw = ["free","bonus","prize","winner","giveaway","reward","claim","gift","lucky","congratulations"];
    const fraudKw = ["kyc","refund","tax","block","suspend","urgent","helpdesk","support","care","alert"];
    f[24] = loginKw.some(k => low.includes(k)) ? 1.0 : 0.0;
    f[25] = trustKw.some(k => host.includes(k)) ? 1.0 : 0.0;
    f[26] = payKw.some(k => low.includes(k)) ? 1.0 : 0.0;
    f[27] = freeKw.some(k => low.includes(k)) ? 1.0 : 0.0;
    f[28] = fraudKw.some(k => low.includes(k)) ? 1.0 : 0.0;
    const allKw = [...loginKw, ...trustKw, ...payKw, ...freeKw, ...fraudKw];
    const kwHits = allKw.filter(k => low.includes(k)).length;
    f[29] = Math.min(kwHits / 6.0, 1.0);
    f[30] = host.includes("-") ? 1.0 : 0.0;

    // GROUP E: Obfuscation & Encoding (F31-F37)
    f[31] = /\.(pdf|doc|jpg|jpeg|png|gif|mp4|zip)\.(exe|js|php|bat|ps1|vbs|cmd|scr)/i.test(path) ? 1.0 : 0.0;
    const pctCount = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
    f[32] = pctCount / Math.max(url.length, 1);
    f[33] = Math.min(pctCount / Math.max(url.length / 3, 1), 1.0);
    f[34] = query ? query.split("&").length : 0;
    f[35] = fragment ? 1.0 : 0.0;
    f[36] = low.startsWith("data:") ? 1.0 : 0.0;
    f[37] = (path.includes("..") || low.includes("%2e%2e")) ? 1.0 : 0.0;

    // GROUP F: Domain Quality (F38-F47)
    f[38] = SUSP_TLDS.has(tld) ? 1.0 : 0.0;
    f[39] = tld.length;
    f[40] = sub ? 1.0 : 0.0;
    f[41] = /^[\d.]+$/.test(host) ? 1.0 : 0.0;
    f[42] = new Set(url).size / Math.max(url.length, 1);
    const vowelCount = (host.match(/[aeiou]/g) || []).length;
    const alphaCount = (host.match(/[a-z]/gi) || []).length;
    f[43] = vowelCount / Math.max(alphaCount, 1);
    f[44] = maxConsonantRun(host);
    f[45] = SHORT_URLS.has(domain) ? 1.0 : 0.0;
    f[46] = /[A-Za-z0-9+/]{20,}={0,2}/.test(query) ? 1.0 : 0.0;
    f[47] = (path.match(/\//g) || []).length;

    // GROUP G: UPI / Payment Specific (F48-F52)
    const upiRe = /[a-zA-Z0-9._-]+@[a-zA-Z]+/g;
    f[48] = upiRe.test(url) ? 1.0 : 0.0;
    let suspUpi = 0.0;
    const fraudPfx = new Set(["refund","tax","prize","block","kyc","urgent","helpdesk","support","care"]);
    for (const m of url.matchAll(/([a-zA-Z0-9._-]+)@([a-zA-Z]+)/g)) {
        const handle = m[2].toLowerCase();
        const prefix = m[1].toLowerCase();
        if (!LEGIT_UPI.has(handle) || [...fraudPfx].some(fp => prefix.includes(fp))) {
            suspUpi = 1.0; break;
        }
    }
    f[49] = suspUpi;
    f[50] = /upi:\/\/pay|pa=.*@|vpa=/i.test(low) ? 1.0 : 0.0;

    // GROUP H: File & Extension Risk (F51-F55)
    const extMatch = path.match(/\.([a-zA-Z0-9]{1,5})(?:[?#]|$)/);
    const ext = extMatch ? extMatch[1].toLowerCase() : "";
    f[51] = DANGER_EXT.has(ext) ? 1.0 : 0.0;
    f[52] = /\/(wp-admin|admin|phpmyadmin|cgi-bin)\//i.test(low) ? 1.0 : 0.0;
    f[53] = /(redirect|returnurl|continue|next|goto|url)=http/i.test(low) ? 1.0 : 0.0;
    const charCounts = {};
    for (const c of host) charCounts[c] = (charCounts[c] || 0) + 1;
    const maxRep = Math.max(...Object.values(charCounts), 0);
    f[54] = maxRep / Math.max(host.length, 1);
    f[55] = /[a-f0-9]{32,}/i.test(low) ? 1.0 : 0.0;

    return f;
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 1: Tech Stack Fingerprinting
// ══════════════════════════════════════════════════════════════════════════════

function phantomFingerprintTechStack() {
    const detected = [];
    const versions = {};

    // ── Frontend Frameworks ──
    // React
    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
        document.querySelector('[data-reactroot]') ||
        document.querySelector('[data-reactid]') ||
        document.getElementById('__next')) {
        detected.push('React');
        if (window.React && window.React.version) versions['React'] = window.React.version;
    }

    // Next.js
    if (window.__NEXT_DATA__ || document.querySelector('script[src*="_next/static"]')) {
        detected.push('Next.js');
        if (window.__NEXT_DATA__?.buildId) versions['Next.js'] = 'build:' + window.__NEXT_DATA__.buildId.slice(0, 8);
    }

    // Vue
    if (window.__VUE__ || window.Vue || document.querySelector('[data-v-]') ||
        document.querySelector('[data-server-rendered]')) {
        detected.push('Vue');
        if (window.Vue && window.Vue.version) versions['Vue'] = window.Vue.version;
    }

    // Nuxt
    if (window.__NUXT__ || window.$nuxt || document.querySelector('[data-n-head]')) {
        detected.push('Nuxt.js');
    }

    // Angular
    const ngVersion = document.querySelector('[ng-version]');
    if (ngVersion || window.getAllAngularRootElements || window.ng) {
        detected.push('Angular');
        if (ngVersion) versions['Angular'] = ngVersion.getAttribute('ng-version');
    }

    // AngularJS (legacy)
    if (window.angular || document.querySelector('[ng-app]') || document.querySelector('[ng-controller]')) {
        detected.push('AngularJS');
        if (window.angular && window.angular.version) versions['AngularJS'] = window.angular.version.full;
    }

    // Svelte
    if (document.querySelector('[class*="svelte-"]') || document.querySelector('.__svelte-')) {
        detected.push('Svelte');
    }

    // jQuery
    if (window.jQuery || window.$?.fn?.jquery) {
        detected.push('jQuery');
        versions['jQuery'] = window.jQuery?.fn?.jquery || window.$?.fn?.jquery || 'unknown';
    }

    // Bootstrap
    if (window.bootstrap || document.querySelector('.navbar') && document.querySelector('[class*="col-"]') ||
        document.querySelector('link[href*="bootstrap"]')) {
        detected.push('Bootstrap');
        if (window.bootstrap?.Tooltip?.VERSION) versions['Bootstrap'] = window.bootstrap.Tooltip.VERSION;
    }

    // Tailwind CSS detection (utility class pattern analysis)
    const allClasses = new Set();
    document.querySelectorAll('[class]').forEach(el => {
        el.classList.forEach(c => allClasses.add(c));
    });
    const twPatterns = ['flex', 'grid', 'p-', 'px-', 'py-', 'mt-', 'mb-', 'text-sm', 'text-lg',
        'bg-', 'rounded', 'shadow', 'border', 'w-', 'h-', 'gap-', 'space-'];
    const twMatches = twPatterns.filter(p => [...allClasses].some(c => c.startsWith(p) || c === p));
    if (twMatches.length >= 5) detected.push('Tailwind CSS');

    // ── CMS Detection ──
    // WordPress
    if (document.querySelector('link[href*="wp-content"]') ||
        document.querySelector('script[src*="wp-includes"]') ||
        document.querySelector('meta[name="generator"][content*="WordPress"]')) {
        detected.push('WordPress');
        const wpMeta = document.querySelector('meta[name="generator"][content*="WordPress"]');
        if (wpMeta) versions['WordPress'] = wpMeta.content.replace('WordPress ', '');
    }

    // Drupal
    if (document.querySelector('meta[name="generator"][content*="Drupal"]') ||
        document.querySelector('[class*="drupal"]') || window.Drupal) {
        detected.push('Drupal');
    }

    // Shopify
    if (window.Shopify || document.querySelector('link[href*="cdn.shopify.com"]')) {
        detected.push('Shopify');
    }

    // Wix
    if (document.querySelector('meta[name="generator"][content*="Wix"]') || window.wixBiSession) {
        detected.push('Wix');
    }

    // ── Server/Backend (from meta/headers) ──
    const metaGenerators = document.querySelectorAll('meta[name="generator"]');
    metaGenerators.forEach(m => {
        const content = m.content || '';
        if (content && !detected.some(d => content.toLowerCase().includes(d.toLowerCase()))) {
            detected.push('Generator: ' + content);
        }
    });

    // Check for PHP indicators
    if (document.querySelector('input[name="PHPSESSID"]') ||
        document.cookie.includes('PHPSESSID') ||
        [...document.querySelectorAll('a[href], form[action]')].some(el =>
            (el.href || el.action || '').includes('.php'))) {
        detected.push('PHP');
    }

    // ASP.NET
    if (document.querySelector('input[name="__VIEWSTATE"]') ||
        document.querySelector('input[name="__EVENTVALIDATION"]')) {
        detected.push('ASP.NET');
    }

    // ── Infrastructure ──
    // CDN detection from scripts/links
    const cdnPatterns = {
        'Cloudflare CDN': /cdnjs\.cloudflare\.com|cloudflare/,
        'AWS CloudFront': /cloudfront\.net/,
        'Google CDN': /googleapis\.com|gstatic\.com/,
        'jsDelivr': /cdn\.jsdelivr\.net/,
        'unpkg': /unpkg\.com/,
        'Fastly': /fastly\.net/,
    };
    document.querySelectorAll('script[src], link[href]').forEach(el => {
        const src = el.src || el.href || '';
        for (const [cdn, re] of Object.entries(cdnPatterns)) {
            if (re.test(src) && !detected.includes(cdn)) detected.push(cdn);
        }
    });

    return { technologies: detected, versions, count: detected.length };
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 2: Security Header Analysis
// ══════════════════════════════════════════════════════════════════════════════

async function phantomAnalyzeSecurityHeaders() {
    const findings = [];
    const headers = {};
    let score = 100;

    // Attempt to read headers via same-origin fetch
    try {
        const resp = await fetch(window.location.href, { method: 'HEAD', cache: 'no-store' });
        const importantHeaders = [
            'content-security-policy', 'strict-transport-security',
            'x-frame-options', 'x-content-type-options',
            'referrer-policy', 'permissions-policy',
            'x-xss-protection', 'x-powered-by', 'server',
            'access-control-allow-origin'
        ];
        for (const h of importantHeaders) {
            const val = resp.headers.get(h);
            if (val) headers[h] = val;
        }
    } catch {
        // Cross-origin or network error — use navigation timing fallback
    }

    // Also check via PerformanceNavigationTiming
    const navEntries = performance.getEntriesByType('navigation');
    if (navEntries.length > 0 && navEntries[0].serverTiming) {
        // Server-Timing headers if available
    }

    // ── Evaluate headers ──
    // CSP
    if (!headers['content-security-policy']) {
        findings.push({ severity: 'HIGH', title: 'Missing Content-Security-Policy',
            detail: 'No CSP header detected. Risk of XSS and injection attacks.',
            recommendation: 'Implement a restrictive CSP header.' });
        score -= 20;
    } else {
        const csp = headers['content-security-policy'];
        if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
            findings.push({ severity: 'MEDIUM', title: 'Weak Content-Security-Policy',
                detail: `CSP allows unsafe-inline or unsafe-eval: ${csp.slice(0, 100)}...`,
                recommendation: 'Remove unsafe-inline and unsafe-eval from CSP.' });
            score -= 10;
        }
    }

    // HSTS
    if (window.location.protocol === 'https:' && !headers['strict-transport-security']) {
        findings.push({ severity: 'HIGH', title: 'Missing Strict-Transport-Security',
            detail: 'HTTPS site without HSTS header. Vulnerable to downgrade attacks.',
            recommendation: 'Add HSTS with max-age >= 31536000.' });
        score -= 15;
    } else if (headers['strict-transport-security']) {
        const maxAge = headers['strict-transport-security'].match(/max-age=(\d+)/);
        if (maxAge && parseInt(maxAge[1]) < 31536000) {
            findings.push({ severity: 'LOW', title: 'Short HSTS max-age',
                detail: `HSTS max-age is ${maxAge[1]}s (recommended: 31536000).`,
                recommendation: 'Increase HSTS max-age to at least 1 year.' });
            score -= 5;
        }
    }

    // X-Frame-Options
    if (!headers['x-frame-options']) {
        findings.push({ severity: 'MEDIUM', title: 'Missing X-Frame-Options',
            detail: 'No X-Frame-Options header. Potentially vulnerable to clickjacking.',
            recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN.' });
        score -= 10;
    }

    // X-Content-Type-Options
    if (!headers['x-content-type-options']) {
        findings.push({ severity: 'MEDIUM', title: 'Missing X-Content-Type-Options',
            detail: 'No nosniff header. Browser may MIME-sniff responses.',
            recommendation: 'Set X-Content-Type-Options: nosniff.' });
        score -= 10;
    }

    // Referrer-Policy
    if (!headers['referrer-policy']) {
        findings.push({ severity: 'LOW', title: 'Missing Referrer-Policy',
            detail: 'No Referrer-Policy header. Full URL may leak to third parties.',
            recommendation: 'Set Referrer-Policy to strict-origin-when-cross-origin.' });
        score -= 5;
    }

    // Permissions-Policy
    if (!headers['permissions-policy']) {
        findings.push({ severity: 'LOW', title: 'Missing Permissions-Policy',
            detail: 'No Permissions-Policy restricting browser features.',
            recommendation: 'Restrict camera, microphone, geolocation via Permissions-Policy.' });
        score -= 5;
    }

    // Server version exposure
    if (headers['server'] && /\/[\d.]+/.test(headers['server'])) {
        findings.push({ severity: 'MEDIUM', title: 'Server Version Exposed',
            detail: `Server header reveals version: ${headers['server']}`,
            recommendation: 'Remove version information from Server header.' });
        score -= 5;
    }

    // X-Powered-By exposure
    if (headers['x-powered-by']) {
        findings.push({ severity: 'MEDIUM', title: 'Technology Exposed via X-Powered-By',
            detail: `X-Powered-By: ${headers['x-powered-by']}`,
            recommendation: 'Remove X-Powered-By header to reduce fingerprinting surface.' });
        score -= 5;
    }

    // HTTPS check
    if (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost' &&
        window.location.hostname !== '127.0.0.1') {
        findings.push({ severity: 'CRITICAL', title: 'Site Served Over HTTP',
            detail: 'All traffic is unencrypted. Credentials and data are exposed.',
            recommendation: 'Enable HTTPS with a valid TLS certificate.' });
        score -= 30;
    }

    return { headers, findings, score: Math.max(0, score), totalChecks: 9 };
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 3: Legacy Technology Detection
// ══════════════════════════════════════════════════════════════════════════════

function phantomDetectLegacyTech(techStack) {
    const legacyFindings = [];
    const versions = techStack.versions || {};

    // jQuery version checks
    if (versions['jQuery']) {
        const jqVer = versions['jQuery'];
        const parts = jqVer.split('.').map(Number);
        if (parts[0] < 2) {
            legacyFindings.push({ technology: 'jQuery', version: jqVer,
                status: 'CRITICAL', riskLevel: 'CRITICAL',
                detail: 'jQuery 1.x is extremely outdated with known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023).',
                recommendation: 'Upgrade to jQuery 3.7+.' });
        } else if (parts[0] === 2 || (parts[0] === 3 && parts[1] < 5)) {
            legacyFindings.push({ technology: 'jQuery', version: jqVer,
                status: 'HIGH', riskLevel: 'HIGH',
                detail: `jQuery ${jqVer} has known security vulnerabilities.`,
                recommendation: 'Upgrade to jQuery 3.7+.' });
        }
    }

    // AngularJS (1.x) — EOL since Dec 2021
    if (versions['AngularJS']) {
        legacyFindings.push({ technology: 'AngularJS', version: versions['AngularJS'],
            status: 'HIGH', riskLevel: 'HIGH',
            detail: 'AngularJS (1.x) reached End-of-Life in December 2021. No security patches.',
            recommendation: 'Migrate to Angular 17+ or another modern framework.' });
    }

    // Angular version checks
    if (versions['Angular']) {
        const parts = versions['Angular'].split('.').map(Number);
        if (parts[0] < 14) {
            legacyFindings.push({ technology: 'Angular', version: versions['Angular'],
                status: 'MEDIUM', riskLevel: 'MEDIUM',
                detail: `Angular ${versions['Angular']} is no longer supported with security patches.`,
                recommendation: 'Upgrade to a currently supported Angular version.' });
        }
    }

    // Bootstrap version checks
    if (versions['Bootstrap']) {
        const parts = versions['Bootstrap'].split('.').map(Number);
        if (parts[0] < 4) {
            legacyFindings.push({ technology: 'Bootstrap', version: versions['Bootstrap'],
                status: 'MEDIUM', riskLevel: 'MEDIUM',
                detail: `Bootstrap ${versions['Bootstrap']} is End-of-Life.`,
                recommendation: 'Upgrade to Bootstrap 5+.' });
        }
    }

    // React version checks
    if (versions['React']) {
        const parts = versions['React'].split('.').map(Number);
        if (parts[0] < 16) {
            legacyFindings.push({ technology: 'React', version: versions['React'],
                status: 'MEDIUM', riskLevel: 'MEDIUM',
                detail: `React ${versions['React']} is very old and lacks modern security features.`,
                recommendation: 'Upgrade to React 18+.' });
        }
    }

    // WordPress version checks
    if (versions['WordPress']) {
        const parts = versions['WordPress'].split('.').map(Number);
        if (parts[0] < 6) {
            legacyFindings.push({ technology: 'WordPress', version: versions['WordPress'],
                status: 'HIGH', riskLevel: 'HIGH',
                detail: `WordPress ${versions['WordPress']} may not receive security patches.`,
                recommendation: 'Upgrade to WordPress 6.x+.' });
        }
    }

    // PHP detection from cookies/forms
    if (techStack.technologies.includes('PHP')) {
        // Try to detect PHP version from headers if available
        legacyFindings.push({ technology: 'PHP', version: 'detected',
            status: 'INFO', riskLevel: 'INFO',
            detail: 'PHP detected on server. Ensure PHP 8.2+ is in use; PHP 7.x is End-of-Life.',
            recommendation: 'Verify PHP version and upgrade if below 8.1.' });
    }

    // ASP.NET WebForms (ViewState = legacy)
    if (techStack.technologies.includes('ASP.NET')) {
        if (document.querySelector('input[name="__VIEWSTATE"]')) {
            legacyFindings.push({ technology: 'ASP.NET WebForms', version: 'detected',
                status: 'MEDIUM', riskLevel: 'MEDIUM',
                detail: 'ASP.NET WebForms with ViewState detected — a legacy pattern.',
                recommendation: 'Consider migrating to ASP.NET Core (Blazor, Razor Pages, or MVC).' });
        }
    }

    const overallRisk = legacyFindings.length === 0 ? 'LOW' :
        legacyFindings.some(f => f.riskLevel === 'CRITICAL') ? 'CRITICAL' :
        legacyFindings.some(f => f.riskLevel === 'HIGH') ? 'HIGH' : 'MEDIUM';

    return { legacyComponents: legacyFindings, overallRisk, count: legacyFindings.length };
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 4: Suspicious Content Scanner
// ══════════════════════════════════════════════════════════════════════════════

function phantomScanSuspiciousContent() {
    const indicators = [];

    // Gather all inline script content
    const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
        .map(s => s.textContent || '').join('\n');

    // 1. Crypto miner detection
    const minerSignatures = ['coinhive', 'cryptonight', 'minero.cc', 'coin-hive',
        'jsecoin', 'cryptoloot', 'webminepool', 'ppoi.org', 'monerominer',
        'coinimp.com', 'minr.pw', 'webmine.pro', 'authedmine'];
    const allScriptSrcs = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
    const allContent = (inlineScripts + ' ' + allScriptSrcs.join(' ')).toLowerCase();

    for (const sig of minerSignatures) {
        if (allContent.includes(sig)) {
            indicators.push({ type: 'CRYPTO_MINER', severity: 'CRITICAL',
                detail: `Crypto mining script signature detected: "${sig}"`,
                recommendation: 'Remove crypto mining scripts immediately.' });
            break;
        }
    }

    // 2. Obfuscation chains: eval(atob(...)) or eval(unescape(...))
    const dangerousPatterns = [
        { re: /eval\s*\(\s*atob\s*\(/gi, label: 'eval(atob()) obfuscation chain' },
        { re: /eval\s*\(\s*unescape\s*\(/gi, label: 'eval(unescape()) obfuscation chain' },
        { re: /eval\s*\(\s*String\.fromCharCode/gi, label: 'eval(String.fromCharCode()) obfuscation' },
        { re: /document\.write\s*\(\s*unescape/gi, label: 'document.write(unescape()) injection' },
        { re: /new\s+Function\s*\(\s*atob/gi, label: 'new Function(atob()) code execution' },
    ];
    for (const { re, label } of dangerousPatterns) {
        if (re.test(inlineScripts)) {
            indicators.push({ type: 'OBFUSCATED_CODE', severity: 'HIGH',
                detail: `Suspicious obfuscation pattern: ${label}`,
                recommendation: 'Investigate obfuscated scripts for malicious payloads.' });
        }
    }

    // 3. Keylogger patterns
    if (/addEventListener\s*\(\s*['"]key(down|press|up)['"]/i.test(inlineScripts) &&
        /(fetch|XMLHttpRequest|navigator\.sendBeacon|\.ajax)\s*\(/i.test(inlineScripts)) {
        indicators.push({ type: 'KEYLOGGER', severity: 'CRITICAL',
            detail: 'Potential keylogger: keyboard event listener + data transmission detected.',
            recommendation: 'Investigate keyboard event handlers sending data externally.' });
    }

    // 4. Formjacking detection (form action to suspicious domain)
    document.querySelectorAll('form').forEach(form => {
        const action = form.getAttribute('action') || '';
        if (action.startsWith('http')) {
            try {
                const actionHost = new URL(action).hostname;
                if (actionHost !== window.location.hostname) {
                    const suspTlds = new Set(['xyz','tk','top','cf','ml','ga','gq','pw','cc','icu']);
                    const actionTld = actionHost.split('.').pop();
                    if (suspTlds.has(actionTld)) {
                        indicators.push({ type: 'FORMJACKING', severity: 'CRITICAL',
                            detail: `Form submits data to suspicious domain: ${actionHost}`,
                            recommendation: 'Verify form action URL is legitimate.' });
                    }
                }
            } catch {}
        }
    });

    // 5. Webshell-like function names in inline scripts
    const webshellFunctions = ['passthru', 'shell_exec', 'system(', 'phpinfo()',
        'base64_decode', 'gzinflate', 'str_rot13', 'assert('];
    for (const fn of webshellFunctions) {
        if (inlineScripts.includes(fn)) {
            indicators.push({ type: 'WEBSHELL_INDICATOR', severity: 'HIGH',
                detail: `Webshell-associated function found in page scripts: "${fn}"`,
                recommendation: 'Investigate the origin of this script.' });
            break;
        }
    }

    // 6. Suspicious meta refresh redirect
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"][content*="url="]');
    if (metaRefresh) {
        const content = metaRefresh.getAttribute('content') || '';
        const urlMatch = content.match(/url=(.+)/i);
        if (urlMatch) {
            try {
                const redirectHost = new URL(urlMatch[1].trim(), window.location.href).hostname;
                if (redirectHost !== window.location.hostname) {
                    indicators.push({ type: 'SUSPICIOUS_REDIRECT', severity: 'MEDIUM',
                        detail: `Meta refresh redirects to different domain: ${redirectHost}`,
                        recommendation: 'Verify the redirect destination is legitimate.' });
                }
            } catch {}
        }
    }

    // 7. Data exfiltration via img pixel
    document.querySelectorAll('img').forEach(img => {
        const src = img.src || '';
        if (src && (img.width <= 1 || img.height <= 1 || img.style.display === 'none')) {
            try {
                const imgHost = new URL(src).hostname;
                if (imgHost !== window.location.hostname && !imgHost.includes('google') &&
                    !imgHost.includes('facebook') && !imgHost.includes('analytics')) {
                    indicators.push({ type: 'TRACKING_PIXEL', severity: 'LOW',
                        detail: `Tracking pixel to: ${imgHost}`,
                        recommendation: 'Review tracking pixels for data collection.' });
                }
            } catch {}
        }
    });

    const threatLevel = indicators.length === 0 ? 'CLEAN' :
        indicators.some(i => i.severity === 'CRITICAL') ? 'CRITICAL' :
        indicators.some(i => i.severity === 'HIGH') ? 'HIGH' : 'MEDIUM';

    return { indicators, threatLevel, count: indicators.length };
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 5: External Resource Audit
// ══════════════════════════════════════════════════════════════════════════════

function phantomAuditExternalResources() {
    const currentHost = window.location.hostname;
    const origins = new Map(); // origin -> { type, count, trusted }

    const TRUSTED_CDN_PATTERNS = [
        /cdnjs\.cloudflare\.com/, /cdn\.jsdelivr\.net/, /unpkg\.com/,
        /ajax\.googleapis\.com/, /fonts\.googleapis\.com/, /fonts\.gstatic\.com/,
        /code\.jquery\.com/, /stackpath\.bootstrapcdn\.com/, /maxcdn\.bootstrapcdn\.com/,
        /cdn\.shopify\.com/, /static\.cloudflareinsights\.com/,
        /\.cloudfront\.net$/, /\.akamaihd\.net$/, /\.fastly\.net$/,
        /\.google\.com$/, /\.gstatic\.com$/, /\.googleapis\.com$/,
        /\.facebook\.com$/, /\.fbcdn\.net$/, /\.twitter\.com$/, /\.twimg\.com$/,
        /\.youtube\.com$/, /\.ytimg\.com$/, /\.linkedin\.com$/, /\.licdn\.com$/,
        /\.github\.com$/, /\.githubusercontent\.com$/,
        /\.cloudflare\.com$/, /\.stripe\.com$/, /\.paypal\.com$/,
    ];

    const SUSPICIOUS_TLDS = new Set(['xyz','tk','top','cf','ml','ga','gq','pw','cc','icu',
        'club','online','site','website','space','live','click','link']);

    function classifyOrigin(hostname) {
        if (hostname === currentHost) return 'self';
        if (TRUSTED_CDN_PATTERNS.some(p => p.test(hostname))) return 'trusted_cdn';
        const tld = hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.has(tld)) return 'suspicious';
        return 'external';
    }

    // Scan scripts
    document.querySelectorAll('script[src]').forEach(el => {
        try {
            const host = new URL(el.src).hostname;
            if (host !== currentHost) {
                const cls = classifyOrigin(host);
                if (!origins.has(host)) origins.set(host, { types: [], classification: cls, urls: [] });
                origins.get(host).types.push('script');
                origins.get(host).urls.push(el.src);
            }
        } catch {}
    });

    // Scan stylesheets
    document.querySelectorAll('link[rel="stylesheet"]').forEach(el => {
        try {
            const host = new URL(el.href).hostname;
            if (host !== currentHost) {
                const cls = classifyOrigin(host);
                if (!origins.has(host)) origins.set(host, { types: [], classification: cls, urls: [] });
                origins.get(host).types.push('stylesheet');
            }
        } catch {}
    });

    // Scan iframes
    document.querySelectorAll('iframe[src]').forEach(el => {
        try {
            const host = new URL(el.src).hostname;
            if (host !== currentHost) {
                const cls = classifyOrigin(host);
                if (!origins.has(host)) origins.set(host, { types: [], classification: cls, urls: [] });
                origins.get(host).types.push('iframe');
            }
        } catch {}
    });

    const flagged = [];
    origins.forEach((info, host) => {
        if (info.classification === 'suspicious') {
            flagged.push({ origin: host, reason: 'Suspicious TLD', types: info.types });
        }
    });

    // Check for HTTP-loaded resources on HTTPS page
    if (window.location.protocol === 'https:') {
        document.querySelectorAll('script[src^="http:"], link[href^="http:"], iframe[src^="http:"]').forEach(el => {
            const src = el.src || el.href;
            try {
                const host = new URL(src).hostname;
                flagged.push({ origin: host, reason: 'Mixed content (HTTP on HTTPS page)',
                    types: [el.tagName.toLowerCase()] });
            } catch {}
        });
    }

    const externalList = [];
    origins.forEach((info, host) => {
        externalList.push({ origin: host, classification: info.classification,
            resourceTypes: [...new Set(info.types)] });
    });

    return {
        externalOrigins: externalList,
        totalExternal: origins.size,
        trustedCount: externalList.filter(e => e.classification === 'trusted_cdn').length,
        untrustedCount: externalList.filter(e => e.classification === 'external' || e.classification === 'suspicious').length,
        flagged,
        flaggedCount: flagged.length
    };
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 6: Cookie Security Audit
// ══════════════════════════════════════════════════════════════════════════════

function phantomAuditCookieSecurity() {
    const findings = [];
    const cookies = document.cookie.split(';').filter(c => c.trim());
    let score = 100;

    const sensitiveNames = ['session', 'token', 'auth', 'jwt', 'sid', 'csrf',
        'login', 'credential', 'access', 'refresh', 'api_key', 'PHPSESSID',
        'connect.sid', 'ASP.NET_SessionId'];

    const cookieDetails = cookies.map(c => {
        const [name, ...valParts] = c.trim().split('=');
        return { name: name.trim(), value: valParts.join('=') };
    });

    // Check each cookie
    for (const cookie of cookieDetails) {
        const nameL = cookie.name.toLowerCase();
        const isSensitive = sensitiveNames.some(s => nameL.includes(s.toLowerCase()));

        // All cookies readable by JS lack HttpOnly (by definition)
        if (isSensitive) {
            findings.push({ severity: 'HIGH', cookie: cookie.name,
                issue: 'Sensitive cookie accessible to JavaScript (lacks HttpOnly)',
                detail: `Cookie "${cookie.name}" contains authentication/session data but is readable via document.cookie.`,
                recommendation: 'Set HttpOnly flag on sensitive cookies.' });
            score -= 15;
        }

        // Check if on HTTP (no Secure flag enforcement possible)
        if (window.location.protocol !== 'https:' && isSensitive) {
            findings.push({ severity: 'HIGH', cookie: cookie.name,
                issue: 'Sensitive cookie on HTTP (no Secure flag)',
                detail: `Cookie "${cookie.name}" transmitted over unencrypted HTTP.`,
                recommendation: 'Serve site over HTTPS and set Secure flag on all sensitive cookies.' });
            score -= 10;
        }
    }

    // General findings
    if (cookies.length === 0) {
        findings.push({ severity: 'INFO', cookie: 'N/A',
            issue: 'No cookies detected', detail: 'Page does not set cookies accessible to JavaScript.',
            recommendation: 'N/A' });
    }

    return {
        totalCookies: cookieDetails.length,
        cookies: cookieDetails.map(c => ({ name: c.name, length: c.value.length })),
        findings,
        score: Math.max(0, score)
    };
}


// ══════════════════════════════════════════════════════════════════════════════
// PHANTOM MODULE 7: Scan Orchestrator
// ══════════════════════════════════════════════════════════════════════════════

async function runPhantomScan() {
    const startTime = performance.now();

    // Run all modules
    const techStack = phantomFingerprintTechStack();
    const secHeaders = await phantomAnalyzeSecurityHeaders();
    const legacyTech = phantomDetectLegacyTech(techStack);
    const suspicious = phantomScanSuspiciousContent();
    const externalAudit = phantomAuditExternalResources();
    const cookieAudit = phantomAuditCookieSecurity();

    const scanMs = +(performance.now() - startTime).toFixed(1);

    // Calculate overall risk score (weighted)
    const weights = {
        secHeaders: 0.30,
        legacyTech: 0.20,
        suspicious: 0.25,
        external: 0.15,
        cookies: 0.10,
    };

    const secScore = secHeaders.score;
    const legacyScore = legacyTech.count === 0 ? 100 :
        legacyTech.overallRisk === 'CRITICAL' ? 10 :
        legacyTech.overallRisk === 'HIGH' ? 30 : 60;
    const suspScore = suspicious.count === 0 ? 100 :
        suspicious.threatLevel === 'CRITICAL' ? 0 :
        suspicious.threatLevel === 'HIGH' ? 20 : 50;
    const extScore = externalAudit.flaggedCount === 0 ? 100 :
        Math.max(0, 100 - externalAudit.flaggedCount * 20);
    const cookieScore = cookieAudit.score;

    const overallScore = Math.round(
        secScore * weights.secHeaders +
        legacyScore * weights.legacyTech +
        suspScore * weights.suspicious +
        extScore * weights.external +
        cookieScore * weights.cookies
    );

    const overallRisk = overallScore >= 80 ? 'LOW' :
        overallScore >= 60 ? 'MEDIUM' :
        overallScore >= 40 ? 'HIGH' : 'CRITICAL';

    // Collect all findings for correlation
    const allFindings = [
        ...secHeaders.findings.map(f => ({ ...f, module: 'security_headers' })),
        ...legacyTech.legacyComponents.map(f => ({ ...f, module: 'legacy_tech', severity: f.riskLevel })),
        ...suspicious.indicators.map(f => ({ ...f, module: 'suspicious_content' })),
        ...externalAudit.flagged.map(f => ({ ...f, module: 'external_resources', severity: 'MEDIUM' })),
        ...cookieAudit.findings.map(f => ({ ...f, module: 'cookie_security' })),
    ];

    // Simple correlation: group related findings
    const riskClusters = [];
    // Legacy + missing headers = compound risk
    if (legacyTech.count > 0 && secHeaders.findings.length > 2) {
        riskClusters.push({
            name: 'Legacy Stack + Weak Security Configuration',
            description: 'Outdated technology combined with missing security headers creates elevated risk.',
            components: [
                ...legacyTech.legacyComponents.map(l => l.technology),
                ...secHeaders.findings.filter(f => f.severity === 'HIGH').map(f => f.title)
            ],
            riskLevel: 'HIGH'
        });
    }
    // Suspicious content + external resources
    if (suspicious.count > 0 && externalAudit.flaggedCount > 0) {
        riskClusters.push({
            name: 'Suspicious Content from Untrusted Sources',
            description: 'Suspicious scripts combined with untrusted external resources.',
            components: [
                ...suspicious.indicators.map(i => i.type),
                ...externalAudit.flagged.map(f => f.origin)
            ],
            riskLevel: 'CRITICAL'
        });
    }

    return {
        target: window.location.hostname,
        url: window.location.origin,
        timestamp: Date.now(),
        scanMs,
        overallScore,
        overallRisk,
        modules: {
            techStack,
            securityHeaders: secHeaders,
            legacyTech,
            suspiciousContent: suspicious,
            externalResources: externalAudit,
            cookieSecurity: cookieAudit,
        },
        totalFindings: allFindings.length,
        findings: allFindings,
        riskClusters,
        criticalCount: allFindings.filter(f => f.severity === 'CRITICAL').length,
        highCount: allFindings.filter(f => f.severity === 'HIGH').length,
        mediumCount: allFindings.filter(f => f.severity === 'MEDIUM').length,
        lowCount: allFindings.filter(f => f.severity === 'LOW').length,
    };
}

// ── PHANTOM message handler (triggered by popup or background) ────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PHANTOM_SCAN') {
        runPhantomScan().then(result => {
            sendResponse({ success: true, result });
        }).catch(err => {
            sendResponse({ success: false, error: err.message });
        });
        return true; // keep channel open for async
    }
});


/**
 * Final verdict = weighted combination of all fired layers.
 * If verdict === "threat", page is replaced with block.html.
 */

(() => {
    "use strict";

    // Don't analyze extension pages, chrome:// pages, or blank pages
    const url = window.location.href;
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    // Avoid double-injection
    if (window.__bvActive) return;
    window.__bvActive = true;

    // Check if the user explicitly allowed this page via the block screen
    if (new URL(window.location.href).searchParams.has("bv_allow")) {
        console.log("[BV] User bypassed protection for this session.");
        return;
    }

    const t0 = performance.now();

    // ── Constants ────────────────────────────────────────────────────────────────

    const BRANDS = [
        "google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix",
        "instagram", "twitter", "linkedin", "whatsapp", "youtube", "yahoo", "ebay",
        "dropbox", "spotify", "adobe", "chase", "wellsfargo", "bankofamerica",
        "citi", "hsbc", "barclays", "halifax", "natwest", "santander", "lloyds",
        "steam", "roblox", "epic", "coinbase", "binance", "metamask", "opensea",
        "paytm", "phonepe", "gpay", "bhim", "razorpay", "hdfc", "icici", "sbi",
        "axis", "kotak", "airtel", "jio", "vodafone", "bsnl", "flipkart", "myntra",
    ];

    // Trusted cross-domain services that legitimately use forms/iframes
    const TRUSTED_SERVICES = new Set([
        // Form services
        "forms.hsforms.com", "form.jotform.com", "form.typeform.com", "form.wufoo.com",
        "form.asana.com", "form.clickup.com", "form.airtable.com", "form.google.com",
        "form.microsoft.com", "form.salesforce.com", "form.hubspot.com",

        // Analytics/Tracking services
        "www.google-analytics.com", "analytics.google.com", "connect.facebook.net",
        "static.ads-twitter.com", "snap.licdn.com", "platform.twitter.com",
        "www.googletagmanager.com", "www.clarity.ms", "js.hs-scripts.com",

        // CDN/Static services
        "cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
        "code.jquery.com", "stackpath.bootstrapcdn.com", "use.fontawesome.com",

        // Payment services
        "checkout.stripe.com", "js.stripe.com", "pay.google.com", "apple-pay-gateway.apple.com",
        "api.paypal.com", "www.paypalobjects.com", "checkout.paypal.com",

        // Crypto services
        "widget.trustwallet.com", "cdn.live.ledger.com", "connect.trezor.io",
        "widget.cloud.coinbase.com", "pay.sendwyre.com", "api.ramp.network",

        // Authentication services
        "accounts.google.com", "login.microsoftonline.com", "auth0.com", "okta.com",
        "login.salesforce.com", "id.atlassian.com", "login.cloudflare.com"
    ]);

    // Trusted domain patterns (regex for subdomains)
    const TRUSTED_PATTERNS = [
        /\.cloudflare\.com$/,      // Cloudflare services
        /\.cloudfront\.net$/,      // AWS CloudFront
        /\.azureedge\.net$/,       // Azure CDN
        /\.fastly\.net$/,          // Fastly CDN
        /\.akamaihd\.net$/,        // Akamai
        /\.doubleclick\.net$/,     // Google advertising
        /\.googlesyndication\.com$/, // Google ads
        /\.googleusercontent\.com$/, // Google services
        /\.gstatic\.com$/,         // Google static
        /\.facebook\.com$/,        // Facebook services
        /\.fbcdn\.net$/,           // Facebook CDN
        /\.twitter\.com$/,         // Twitter services
        /\.twimg\.com$/,           // Twitter images
        /\.linkedin\.com$/,        // LinkedIn services
        /\.licdn\.com$/,           // LinkedIn CDN
        /\.youtube\.com$/,         // YouTube
        /\.ytimg\.com$/,           // YouTube images
        /\.github\.com$/,          // GitHub
        /\.githubusercontent\.com$/, // GitHub assets
        /\.npmjs\.org$/,           // NPM
        /\.jsdelivr\.net$/,        // jsDelivr CDN
        /\.unpkg\.com$/,           // unpkg CDN
    ];

    const SUSPICIOUS_TLDS = new Set([
        "xyz", "tk", "top", "cf", "ml", "ga", "gq", "pw", "cc", "icu", "club", "online",
        "site", "website", "space", "live", "click", "link", "info", "biz", "work",
        "tech", "store", "shop",
    ]);

    const LEGIT_UPI_HANDLES = new Set([
        "okaxis", "okicici", "oksbi", "okhdfcbank", "ybl", "ibl", "axl", "apl", "fbl",
        "upi", "paytm", "waaxis", "waxis", "rajgovhdfcbank", "barodampay", "allbank",
        "andb", "aubank", "cnrb", "csbpay", "dbs", "dcb", "federal", "hdfcbank", "idbi",
        "idfc", "indus", "idfcbank", "jio", "kotak", "lvb", "mahb", "nsdl", "pnb",
        "psb", "rbl", "sib", "tjsb", "uco", "union", "united", "vijb", "yapl", "airtel",
        "airtelpaymentsbank", "postbank",
    ]);

    const FRAUD_UPI_PREFIXES = new Set([
        "refund", "tax", "prize", "block", "kyc", "urgent", "helpdesk", "support",
        "care", "service", "verify", "government", "rbi", "sebi", "npci",
    ]);

    // ── Layer 3: Heuristic rule engine ───────────────────────────────────────────

    function Shannon(s) {
        if (!s) return 0;
        const freq = {};
        for (const c of s) freq[c] = (freq[c] || 0) + 1;
        const n = s.length;
        return -Object.values(freq).reduce((sum, f) => sum + (f / n) * Math.log2(f / n), 0);
    }

    function levenshtein(a, b) {
        const m = a.length, n = b.length;
        let prev = Array.from({ length: n + 1 }, (_, i) => i);
        for (let i = 1; i <= m; i++) {
            const curr = [i];
            for (let j = 1; j <= n; j++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
            }
            prev = curr;
        }
        return prev[n];
    }

    function minBrandDistance(domain) {
        const core = (domain.split(".")[0] || "").toLowerCase();
        return Math.min(...BRANDS.map(b => levenshtein(core, b)));
    }

    function parseUrl(url) {
        try {
            const u = new URL(url);
            return {
                scheme: u.protocol.replace(":", ""),
                host: u.hostname,
                path: u.pathname,
                query: u.search.slice(1),
                hash: u.hash,
                port: u.port ? parseInt(u.port) : null,
                labels: u.hostname.split("."),
                tld: u.hostname.split(".").pop(),
                domain: u.hostname.split(".").slice(-2).join("."),
                sub: u.hostname.split(".").slice(0, -2).join("."),
            };
        } catch {
            return { scheme: "", host: url, path: "", query: "", hash: "", port: null, labels: [url], tld: "", domain: url, sub: "" };
        }
    }

    /**
     * Heuristic rule engine.
     * Returns { score: 0–1, signals: string[], triggered: RuleResult[] }
     */
    function runHeuristics(url) {
        const p = parseUrl(url);
        const low = url.toLowerCase();
        const signals = [];
        let score = 0;

        const rule = (id, label, weight, cond) => {
            if (cond) { score += weight; signals.push(label); }
        };

        // H1 — Punycode IDN homograph
        rule("H1", "Punycode/IDN Homograph", 0.9,
            p.host.includes("xn--"));

        // H2 — IP-in-URL
        rule("H2", "IP Address in URL", 0.85,
            /^\d{1,3}(\.\d{1,3}){3}$/.test(p.host));

        // H3 — Brand Levenshtein spoof (edit dist 1–2) WITH CONTEXT AWARENESS
        const bd = minBrandDistance(p.domain);
        // Additional context checks to reduce false positives
        const isCryptoContext = window.location.hostname.includes("wallet") ||
            window.location.hostname.includes("crypto") ||
            window.location.hostname.includes("blockchain") ||
            document.title.toLowerCase().includes("wallet") ||
            document.title.toLowerCase().includes("crypto");

        // For crypto-related sites, be more lenient with brand matching
        const brandThreshold = isCryptoContext ? 3 : 2; // Allow more distance for crypto sites

        // Check if this might be a legitimate service provider (e.g., metamask.io is legitimate)
        const isKnownLegit = BRANDS.some(b => p.host.includes(b)) ||
            TRUSTED_SERVICES.has(p.host) ||
            TRUSTED_PATTERNS.some(pattern => pattern.test(p.host));

        rule("H3", `Brand Spoof (edit-dist ${bd})`, isKnownLegit ? 0.2 : 0.8,
            bd > 0 && bd <= brandThreshold && !isKnownLegit);

        // H4 — Suspicious TLD
        rule("H4", `Suspicious TLD (.${p.tld})`, 0.6,
            SUSPICIOUS_TLDS.has(p.tld));

        // H5 — Login page without HTTPS
        const loginKw = ["login", "signin", "account", "verify", "auth", "confirm"];
        rule("H5", "Login Page on HTTP", 0.75,
            p.scheme !== "https" && loginKw.some(k => low.includes(k)));

        // H6 — Brand in subdomain, NOT in registered domain
        const brandInSub = BRANDS.some(b => p.sub.includes(b));
        const brandInReg = BRANDS.some(b => (p.domain.split(".")[0] || "").includes(b));
        rule("H6", "Brand Hijacked in Subdomain", 0.85,
            brandInSub && !brandInReg);

        // H7 — Excessive subdomains (depth ≥ 4)
        rule("H7", "Excessive Subdomain Depth", 0.5,
            p.labels.length >= 5);

        // H8 — Obfuscated redirect parameter
        const obfRedirect = /[?&](url|redirect|redir|continue|return|next|target|dest)=/i.test(url);
        rule("H8", "Encoded Redirect Parameter", 0.55,
            obfRedirect);

        // H9 — Multiple @ symbols (credential injection)
        rule("H9", "Multiple @ Symbols", 0.8,
            (url.match(/@/g) || []).length > 1);

        // H10 — Free/prize keywords
        const freeKw = ["free", "prize", "winner", "giveaway", "claim", "bonus", "lucky", "congratulation"];
        rule("H10", "Prize/Scam Keywords", 0.65,
            freeKw.some(k => low.includes(k)));

        // H11 — High URL entropy (characteristic of encoded/obfuscated phishing)
        const entropy = Shannon(url);
        rule("H11", `High URL Entropy (${entropy.toFixed(2)})`, 0.5,
            entropy > 5.2);

        // H12 — UPI VPA fraud detection
        const upiResult = analyzeUPI(url + " " + document.body?.innerText?.slice(0, 2000));
        if (upiResult.suspicious) {
            score += 0.85;
            signals.push(`UPI Fraud: ${upiResult.reason}`);
        }

        // Normalize score 0→1 (it can exceed 1 from multiple rules)
        return { score: Math.min(score, 1.0), signals };
    }

    // ── UPI Fraud Detection ───────────────────────────────────────────────────────

    function analyzeUPI(text) {
        // vpaPattern looks for prefix@handle, but ignores if the "handle" part looks like a full 
        // domain name with a TLD (e.g., @gmail.com) by ensuring no dot follows the handle immediately
        const vpaPattern = /([a-zA-Z0-9._-]+)@([a-zA-Z]+)(?!\.[a-zA-Z]{2,})/g;
        let match;
        while ((match = vpaPattern.exec(text)) !== null) {
            const prefix = match[1].toLowerCase();
            const handle = match[2].toLowerCase();

            // If the handle is too short or just weird, skip it
            if (handle.length < 2) continue;

            // Unknown handle
            if (!LEGIT_UPI_HANDLES.has(handle)) {
                // If it's an unknown handle, it's not immediately suspicious unless it's a known fraud prefix
                // to avoid false positives on random @mentions like @twitter
                let isFraudPfx = false;
                for (const fp of FRAUD_UPI_PREFIXES) {
                    if (prefix.includes(fp)) {
                        isFraudPfx = true; break;
                    }
                }
                if (isFraudPfx) {
                    return { suspicious: true, reason: `Fraudulent UPI prefix "${prefix}" on unknown handle @${handle}` };
                }
                continue; // otherwise just ignore non-whitelisted handles to prevent false positives
            }
            // Levenshtein spoof of a legit handle
            for (const legit of LEGIT_UPI_HANDLES) {
                const d = levenshtein(handle, legit);
                if (d > 0 && d <= 1) {
                    return { suspicious: true, reason: `Spoofed UPI handle @${handle} (near @${legit})` };
                }
            }
            // Fraud-indicating prefix
            for (const fp of FRAUD_UPI_PREFIXES) {
                if (prefix.includes(fp)) {
                    return { suspicious: true, reason: `Fraudulent UPI prefix "${prefix}"` };
                }
            }
        }
        // Scan for UPI pay URIs (upi://pay?pa=...)
        const upiUriPattern = /upi:\/\/pay\?.*?pa=([^&\s]+)/gi;
        while ((match = upiUriPattern.exec(text)) !== null) {
            const vpa = match[1];
            const [pfx, hdl] = vpa.split("@");
            if (!hdl || !LEGIT_UPI_HANDLES.has(hdl.toLowerCase())) {
                return { suspicious: true, reason: `Suspicious UPI URI: ${vpa}` };
            }
            if (pfx && [...FRAUD_UPI_PREFIXES].some(fp => pfx.toLowerCase().includes(fp))) {
                return { suspicious: true, reason: `Fraud UPI collect request: ${vpa}` };
            }
        }
        return { suspicious: false };
    }

    // ── Layer 4: DOM Behavioral Analysis ─────────────────────────────────────────

    function analyzeDom() {
        let score = 0;
        const signals = [];

        const rule = (label, weight, cond) => {
            if (cond) { score += weight; signals.push(label); }
        };

        // D1 — Password input field on HTTP
        const hasPasswordField = document.querySelector('input[type="password"]') !== null;
        rule("Password Form on HTTP", 0.7,
            hasPasswordField && window.location.protocol !== "https:");

        // D2 — Form action pointing to different domain (INTELLIGENT VERSION)
        document.querySelectorAll("form").forEach(form => {
            const action = form.getAttribute("action") || "";
            if (action.startsWith("http") || action.startsWith("//")) {
                try {
                    const actionHost = new URL(action, window.location.href).hostname;
                    if (actionHost && actionHost !== window.location.hostname) {
                        // Check if the target domain is trusted
                        const isTrusted = TRUSTED_SERVICES.has(actionHost) ||
                            TRUSTED_PATTERNS.some(pattern => pattern.test(actionHost));

                        if (!isTrusted) {
                            // Only flag if it's not a known legitimate service
                            // Reduced weight from 0.8 to 0.3 for legitimate cross-domain forms
                            score += 0.3;
                            signals.push(`Cross-Domain Form Action → ${actionHost} (untrusted)`);
                        } else {
                            // Trusted service - very low weight or none
                            signals.push(`Cross-Domain Form Action → ${actionHost} (trusted service)`);
                        }
                    }
                } catch { }
            }
        });

        // D3 — Invisible iframes (INTELLIGENT VERSION - context-aware)
        let hiddenIframeCount = 0;
        let suspiciousIframes = 0;
        document.querySelectorAll("iframe").forEach(iframe => {
            const style = window.getComputedStyle(iframe);
            const w = parseFloat(style.width || "0");
            const h = parseFloat(style.height || "0");
            const src = iframe.src || "";

            // Check if iframe source is from a trusted service
            let isTrustedSource = false;
            try {
                if (src) {
                    const iframeHost = new URL(src, window.location.href).hostname;
                    isTrustedSource = TRUSTED_SERVICES.has(iframeHost) ||
                        TRUSTED_PATTERNS.some(pattern => pattern.test(iframeHost));
                }
            } catch { }

            // Count hidden iframes
            if (style.display === "none" || style.visibility === "hidden" || w < 2 || h < 2) {
                hiddenIframeCount++;
                // Only count as suspicious if it's NOT from a trusted source
                if (!isTrustedSource) {
                    suspiciousIframes++;
                }
            }
        });

        // Weight based on suspicious vs total iframes
        if (suspiciousIframes > 0) {
            // Reduced from 0.15 to 0.1, and scaled by suspicious ratio
            const weight = Math.min(0.1 * (suspiciousIframes / Math.max(1, hiddenIframeCount)), 0.3);
            rule("Suspicious Hidden Iframe Detected", weight, suspiciousIframes > 0);
        }

        // Log trusted iframes for transparency
        if (hiddenIframeCount > suspiciousIframes) {
            signals.push(`${hiddenIframeCount - suspiciousIframes} trusted hidden iframes detected`);
        }

        // D4 — Obfuscated scripts (eval, atob, unescape — characteristic of malware)
        let hasObfScript = false;
        document.querySelectorAll("script:not([src])").forEach(script => {
            const src = script.textContent || "";
            if (/\beval\s*\(|\batob\s*\(|\bunescape\s*\(|\bString\.fromCharCode/i.test(src)) {
                hasObfScript = true;
            }
        });
        rule("Obfuscated Script Detected", 0.2, hasObfScript);

        // D5 — Clipboard hijacking (copy event listener replacing clipboard)
        // Check for event listeners on window for 'copy' (heuristic: check page scripts)
        const allScriptText = Array.from(document.querySelectorAll("script:not([src])"))
            .map(s => s.textContent).join(" ");
        rule("Clipboard/Polyfill Script", 0.15,
            /addEventListener\s*\(\s*['"]copy['"]/i.test(allScriptText) &&
            /clipboardData|getSelection/i.test(allScriptText));

        // D6 — BeforeUnload trap (prevents user from leaving)
        rule("BeforeUnload Exit Trap", 0.4,
            /addEventListener\s*\(\s*['"]beforeunload['"]/i.test(allScriptText));

        // D7 — Fake loading overlay with credential fields
        const overlays = document.querySelectorAll('[style*="position:fixed"],[style*="position: fixed"]');
        let hasCredOverlay = false;
        overlays.forEach(el => {
            if (el.querySelector('input[type="password"]') || el.querySelector('input[type="email"]')) {
                hasCredOverlay = true;
            }
        });
        rule("Fake Credential Overlay", 0.9, hasCredOverlay);

        // D8 — Data URI in iframes or anchor href
        const dataUriElements = document.querySelectorAll('[src^="data:text"],[href^="data:text"]');
        rule("Data URI Injection", 0.2, dataUriElements.length > 0);

        // D9 — Excessive external resource origins (data exfiltration)
        const resourceOrigins = new Set();
        document.querySelectorAll("script[src]").forEach(s => {
            try { resourceOrigins.add(new URL(s.src, window.location.href).hostname); } catch { }
        });
        rule("Excessive External Script Origins", 0.2, resourceOrigins.size > 8);

        // D10 — Fake CAPTCHA (image with captcha-related alt/class on non-standard domain)
        const fakeCapt = document.querySelectorAll('img[alt*="captcha" i],[class*="captcha" i]');
        const legitimateCaptchaDomains = ["recaptcha.net", "hcaptcha.com", "cloudflare.com"];
        if (fakeCapt.length > 0) {
            const isReal = legitimateCaptchaDomains.some(d => window.location.hostname.includes(d));
            rule("Fake CAPTCHA Element", 0.55, !isReal);
        }

        return { score: Math.min(score, 1.0), signals };
    }

    // ── Layer 1+2: WASM + ONNX inference ─────────────────────────────────────────

    async function runWasmAndML(url) {
        let mlProb = null;
        let features = null;

        try {
            // Wait for WASM to be ready via our loader
            const maxWait = 3000; // Reduced wait time
            const startTime = Date.now();

            // Wait for wasm-loader to initialize
            while (!window.wasmFeatureExtractor && (Date.now() - startTime) < maxWait) {
                await new Promise(resolve => setTimeout(resolve, 50));
            }

            // Use fallback if WASM not available
            if (!window.wasmFeatureExtractor || !window.wasmFeatureExtractor.extract_features) {
                console.warn('[BV] WASM not available, using JavaScript feature extraction fallback');
                features = extractFeaturesJS(url);

            } else {
                // Extract features using WASM
                features = window.wasmFeatureExtractor.extract_features(url);
            }

            if (!features && window.wasm_bindgen && typeof window.wasm_bindgen.extract_features === 'function') {
                features = Array.from(window.wasm_bindgen.extract_features(url));
            }

            // Layer 2: ONNX ML inference
            // Disable threading + JSEP — only basic ort-wasm.wasm or ort-wasm-simd.wasm exist
            ort.env.wasm.numThreads = 1;     // stops ORT from loading *-threaded.jsep.mjs
            ort.env.wasm.simd = false;  // disable simd to avoid any SIMD web worker loading issues completely
            ort.env.workers = 0;
            ort.env.wasm.proxy = false; // no web worker proxy
            // Configure ONNX Runtime for extension environment
            ort.env.wasm.numThreads = 1;     // disable threading to avoid loading threaded modules
            ort.env.wasm.simd = false;       // force disable SIMD to avoid loading separate .wasm files that fail in extension context
            ort.env.wasm.wasmPaths = {
                'ort-wasm.wasm': chrome.runtime.getURL('ort-wasm.wasm'),
            };
            // Explicitly prevent search for other wasm files
            ort.env.wasm.proxy = false;
            ort.env.workers = 0;
            // Remove any corejs paths that might cause issues
            ort.env.wasm.wasmCorejsPaths = undefined;
            if (ort.env.wasm.corejs) ort.env.wasm.corejs = undefined;

            const modelUrl = chrome.runtime.getURL("model.onnx");
            const session = await ort.InferenceSession.create(modelUrl, {
                executionProviders: ["wasm"],
                graphOptimizationLevel: "basic",
                enableMemPattern: false,
                enableCpuMemArena: false,
                extraOptions: {
                    session: {
                        intra_op_num_threads: 1,
                        inter_op_num_threads: 1,
                        use_deterministic_compute: 1
                    }
                }
            });
            const tensor = new ort.Tensor("float32", Float32Array.from(features), [1, 56]);
            const results = await session.run({ input: tensor });

            // Extract phishing probability from model outputs
            const probTensor = results.output_probability || results.probabilities || results.output_probabilities;
            if (probTensor) {
                const data = probTensor.data;
                mlProb = data.length >= 2 ? data[1] : data[0];
            } else {
                const label = results.output_label || results.label;
                mlProb = label ? (Number(label.data[0]) === 1 ? 0.9 : 0.1) : 0.1;
            }
        } catch (e) {
            console.warn("[BV] WASM/ML layer failed (heuristics still active):", e.message);
        }

        return { mlProb, features };
    }

    // ── Verdict engine ────────────────────────────────────────────────────────────

    function computeFinalVerdict(mlProb, heuristicResult, domResult, settings, isWhitelisted = false) {
        if (isWhitelisted) {
            return { verdict: "safe", riskScore: 0, composite: 0, hardTriggered: false };
        }

        // Weights: ML is primary, heuristics and DOM supplement
        // REDUCED weights to prevent false positives
        const mlWeight = 0.65;      // Increased from 0.55
        const hWeight = 0.25;       // Reduced from 0.30
        const domWeight = 0.10;     // Reduced from 0.15

        let composite = 0;
        let usedLayers = 0;

        if (mlProb !== null) {
            composite += mlProb * mlWeight;
            usedLayers++;
        }
        composite += heuristicResult.score * hWeight;
        composite += domResult.score * domWeight;

        // Hard rules: certain heuristics override regardless of ML
        const HARD_BLOCK_SIGNALS = [
            "Punycode/IDN Homograph",
            "Brand Hijacked in Subdomain",
            "Multiple @ Symbols",
            "Fake Credential Overlay",
            "Clipboard Hijacking Script",
        ];
        const allSignals = [...heuristicResult.signals, ...domResult.signals];
        const hardTriggered = allSignals.some(s => HARD_BLOCK_SIGNALS.some(hb => s.includes(hb)));

        // INCREASED thresholds to prevent false positives
        const threshold = settings?.blockThreshold ?? 0.65;  // Increased from 0.50
        const strictMode = settings?.strictMode ?? false;
        const effectiveThreshold = strictMode ? 0.50 : threshold; // Increased from 0.35

        let verdict;
        if (hardTriggered || composite >= effectiveThreshold) {
            verdict = "threat";
        } else if (composite >= effectiveThreshold * 0.5) {  // Reduced from 0.6
            verdict = "warning";
        } else {
            verdict = "safe";
        }

        return {
            verdict,
            riskScore: Math.round(composite * 100),
            composite,
            hardTriggered,
        };
    }

    // ── Blocking ──────────────────────────────────────────────────────────────────

    function blockPage(threatType, riskScore, signals) {
        // --- EMERGENCY ALLOWLIST BYPASS ---
        const domain = window.location.hostname.toLowerCase();
        const allowed = cachedSettings?.allowlist || [];
        if (allowed.some(d => domain === d.trim().toLowerCase() || domain.endsWith("." + d.trim().toLowerCase()))) {
            console.log(`[BV] Emergency Bypass: ${domain} is allowlisted. Navigation allowed.`);
            return;
        }

        const blockUrl = chrome.runtime.getURL("block.html");
        const params = new URLSearchParams({
            url: encodeURIComponent(window.location.href),
            risk: riskScore,
            threat: threatType,
            signals: encodeURIComponent(signals.slice(0, 5).join("|")),
        });
        window.location.replace(`${blockUrl}?${params.toString()}`);
    }

    // ── Main execution ────────────────────────────────────────────────────────────

    async function executeVigilant() {
        const t0 = performance.now();
        const url = window.location.href;

        // --- LOAD SETTINGS FIRST ---
        let settings = cachedSettings || { protection: true, domAnalysis: true, autoBlock: true, allowlist: [] };

        // Always try to get most fresh state from background too
        try {
            const state = await chrome.runtime.sendMessage({ type: "GET_STATE" });
            if (state && state.settings) {
                settings = state.settings;
                cachedSettings = settings; // Update cache
            }
        } catch {
            console.warn("[BV] Background sync delayed, using cache.");
        }

        if (settings.protection === false) return;

        // --- LAYER 0: ALLOWLIST (Highest Priority) ---
        const currentDomain = window.location.hostname.toLowerCase();
        const allowed = settings.allowlist || [];
        if (allowed.some(d => currentDomain === d.trim().toLowerCase() || currentDomain.endsWith("." + d.trim().toLowerCase()))) {
            console.log(`[BV] Allowlisted domain: ${currentDomain}. Skipping all checks.`);
            return;
        }

        // --- LAYER 1: Blockchain Threat Vault Check ---
        try {
            const blockchainResult = await checkThreatWithBlockchain(url);
            if (blockchainResult && blockchainResult.isThreat) {
                blockPage(blockchainResult.threatType, 99, [`Blockchain verified threat: ${blockchainResult.source}`]);
                return;
            }
        } catch (error) {
            console.warn('[Blockchain] Check failed, continuing...', error);
        }

        // (Blockchain check completed above, now proceed with heuristics and ML)

        // Layer 3: Heuristics (fast, synchronous)
        const hResult = runHeuristics(url);

        // Layer 4: DOM analysis (runs immediately if DOM is ready)
        let domResult = { score: 0, signals: [] };
        if (settings.domAnalysis !== false) {
            if (document.readyState === "loading") {
                await new Promise(r => document.addEventListener("DOMContentLoaded", r, { once: true }));
            }
            domResult = analyzeDom();
            // Also set up MutationObserver for dynamic DOM threats
            setupMutationObserver(domResult);
        }

        // Early exit for definite hard-rule threats (no need to wait for ML)
        const INSTANT_BLOCK = [
            "Punycode/IDN Homograph", "Brand Hijacked in Subdomain",
            "Multiple @ Symbols", "Fake Credential Overlay",
        ];

        // Critical Whitelist: Never hard-block trusted essential domains based on heuristics alone
        const SAFE_DOMAINS = [
            "google.com", "youtube.com", "github.com", "microsoft.com", "apple.com",
            "metamask.io", "support.metamask.io", "coinbase.com", "binance.com",
            "opensea.io", "trustwallet.com", "ledger.com", "trezor.io"
        ];

        // Extended trusted domains with patterns
        const TRUSTED_DOMAIN_PATTERNS = [
            /\.github\.io$/,           // GitHub Pages
            /\.vercel\.app$/,          // Vercel deployments
            /\.netlify\.app$/,         // Netlify deployments
            /\.surge\.sh$/,            // Surge.sh
            /\.firebaseapp\.com$/,     // Firebase
            /\.web\.app$/,             // Firebase hosting
            /\.onrender\.com$/,        // Render.com
            /\.railway\.app$/,         // Railway
            /\.fly\.dev$/,             // Fly.io
            /\.herokuapp\.com$/,       // Heroku
            /\.pages\.dev$/,           // Cloudflare Pages
            /\.workers\.dev$/,         // Cloudflare Workers
        ];

        const isWhitelisted = SAFE_DOMAINS.some(d =>
            window.location.hostname === d || window.location.hostname.endsWith("." + d)
        ) || TRUSTED_DOMAIN_PATTERNS.some(pattern => pattern.test(window.location.hostname));

        let hasInstantBlock = false;
        if (!isWhitelisted) {
            hasInstantBlock = [...hResult.signals, ...domResult.signals]
                .some(s => INSTANT_BLOCK.some(ib => s.includes(ib)));
        }

        // Layers 1+2: WASM + ONNX (async)
        const { mlProb, features } = await runWasmAndML(url);

        const scanMs = +(performance.now() - t0).toFixed(1);
        const verdictResult = computeFinalVerdict(mlProb, hResult, domResult, settings, isWhitelisted);
        const allSignals = [...hResult.signals, ...domResult.signals];

        // Determine threat type label
        const threatType = determineThreatType(hResult.signals, domResult.signals, mlProb);

        const result = {
            url: url,
            verdict: verdictResult.verdict,
            riskScore: verdictResult.riskScore,
            mlProb: mlProb !== null ? +mlProb.toFixed(3) : null,
            hScore: +hResult.score.toFixed(3),
            domScore: +domResult.score.toFixed(3),
            signals: allSignals,
            threatType: threatType,
            scanMs: scanMs,
            features: features?.slice(0, 10),  // send first 10 features to popup for display
        };

        // Report to background
        try {
            const tabs = await new Promise(r => chrome.tabs.getCurrent(r));
            await chrome.runtime.sendMessage({
                type: "SCAN_RESULT",
                result,
                tabId: tabs?.id,
            });
        } catch { }

        // Block if threat and auto-block is enabled
        if (verdictResult.verdict === "threat" && settings.autoBlock !== false) {
            // Submit high-confidence threats to blockchain for network validation
            if (verdictResult.composite >= 0.8) {
                try {
                    const threatType = determineThreatType(hResult.signals, domResult.signals, mlProb);
                    const evidence = {
                        domainHash: await sha256Phantom(window.location.hostname),
                        featureSnapshot: features ? features.slice(0, 5) : [],
                        heuristicSignals: hResult.signals,
                        domSignals: domResult.signals,
                        mlConfidence: mlProb,
                        compositeScore: verdictResult.composite
                    };

                    await submitThreatToBlockchain(
                        window.location.hostname,
                        verdictResult.composite,
                        threatType,
                        evidence
                    );
                } catch (error) {
                    console.warn('[Blockchain] Failed to submit threat:', error);
                }
            }

            blockPage(threatType, verdictResult.riskScore, allSignals);
        }
    }

    function determineThreatType(hSignals, dSignals, mlProb) {
        const all = [...hSignals, ...dSignals].join(" ").toLowerCase();
        if (all.includes("upi") || all.includes("vpa")) return "UPI Fraud";
        if (all.includes("punycode") || all.includes("homograph")) return "IDN Homograph Attack";
        if (all.includes("brand spoof") || all.includes("brand hijack")) return "Brand Spoofing";
        if (all.includes("credential") || all.includes("password")) return "Credential Harvesting";
        if (all.includes("clipboard")) return "Clipboard Hijacking";
        if (all.includes("ip address")) return "IP-Based Phishing";
        if (all.includes("redirect")) return "Redirect-Based Phishing";
        if (all.includes("suspicious tld")) return "Suspicious Domain";
        if (mlProb !== null && mlProb > 0.7) return "ML-Detected Phishing";
        return "Multi-Signal Threat";
    }

    // ── MutationObserver for dynamic DOM threats ──────────────────────────────────

    function setupMutationObserver(initialDomResult) {
        let debounceTimer = null;
        const observer = new MutationObserver(() => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(async () => {
                const freshDom = analyzeDom();
                if (freshDom.score > initialDomResult.score + 0.3) {
                    // Significant new threat appeared in DOM
                    const settings = {};
                    const tabs = await new Promise(r => chrome.tabs.getCurrent(r)).catch(() => null);
                    if (tabs) {
                        const state = await chrome.runtime.sendMessage({ type: "GET_STATE", tabId: tabs.id }).catch(() => ({}));
                        Object.assign(settings, state?.settings || {});
                    }
                    if (freshDom.score >= 0.6 && settings.autoBlock !== false) {
                        blockPage("DOM Behavioral Threat", Math.round(freshDom.score * 100), freshDom.signals);
                    }
                }
            }, 1500);
        });
        observer.observe(document.body || document.documentElement, {
            childList: true, subtree: true, attributes: false,
        });
    }

    // ── Boot ──────────────────────────────────────────────────────────────────────
    executeVigilant().catch(e => console.warn("[BV] Engine error:", e));
})();
