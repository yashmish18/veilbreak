// wasm-loader.js — Full 56-Feature Extractor & WASM Loader
// Authoritative 56-Feature Contract Matching model/features.py & content.js

function extractFeaturesFullJS(url) {
    const f = new Array(56).fill(0.0);
    const low = (url || '').toLowerCase();

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
        port = u.port ? parseInt(u.port, 10) : null;
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
        return -Object.values(freq).reduce((sum, count) => sum + (count / n) * Math.log2(count / n), 0);
    }

    // ── N-gram entropy ──
    function ngramEntropy(s, n) {
        if (s.length < n) return 0;
        const ngrams = [];
        for (let i = 0; i <= s.length - n; i++) ngrams.push(s.substring(i, i + n));
        const freq = {};
        for (const g of ngrams) freq[g] = (freq[g] || 0) + 1;
        const total = ngrams.length;
        return -Object.values(freq).reduce((sum, count) => sum + (count / total) * Math.log2(count / total), 0);
    }

    // ── Levenshtein distance ──
    function lev(a, b) {
        const m = a.length, n = b.length;
        let p = Array.from({ length: n + 1 }, (_, i) => i);
        for (let i = 1; i <= m; i++) {
            const c = [i];
            for (let j = 1; j <= n; j++) {
                c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
            }
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

// Global exposure
if (typeof window !== 'undefined') {
    window.wasmFeatureExtractor = {
        extract_features: extractFeaturesFullJS,
        analyze_form_action: (form_action, page_host) => {
            if (form_action.startsWith('data:')) return 1.0;
            if (form_action.includes(page_host)) return 0.0;
            return 0.8;
        },
        score_filename: (filename) => {
            const low = filename.toLowerCase();
            const ext = low.split('.').pop() || '';
            const dangerous = ['exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'wsf', 'hta', 'jar', 'msi'];
            return dangerous.includes(ext) ? 0.8 : 0.1;
        }
    };

    window.loadWasmFeatureExtractor = async () => {
        try {
            const wasmGlueUrl = chrome.runtime.getURL('wasm-build/wasm_feature.js');
            const wasmModule = await import(wasmGlueUrl);
            const wasmUrl = chrome.runtime.getURL('wasm-build/wasm_feature_bg.wasm');
            await wasmModule.default({ module_or_path: wasmUrl });

            window.wasmFeatureExtractor = {
                extract_features: (url) => {
                    try {
                        return Array.from(wasmModule.extract_features(url));
                    } catch (e) {
                        return extractFeaturesFullJS(url);
                    }
                },
                analyze_form_action: wasmModule.analyze_form_action,
                score_filename: wasmModule.score_filename
            };
            console.log('[WASM] Real WASM feature extractor loaded');
            return window.wasmFeatureExtractor;
        } catch (e) {
            console.log('[WASM] Using full authoritative 56-feature JS extractor');
            return window.wasmFeatureExtractor;
        }
    };

    window.getWasmFunctions = () => window.wasmFeatureExtractor;
    window.loadWasmFeatureExtractor();
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { extractFeaturesFullJS };
}

export { extractFeaturesFullJS };
