import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const TARGET_BRANDS = [
    'google', 'paypal', 'microsoft', 'apple', 'amazon',
    'netflix', 'facebook', 'instagram', 'twitter', 'github',
    'chase', 'wellsfargo', 'bankofamerica', 'coinbase', 'binance',
    'metamask', 'steampowered', 'discord', 'dropbox', 'linkedin'
];

const SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc',
    'icu', 'click', 'link', 'work', 'date', 'faith', 'review',
    'country', 'kim', 'cricket', 'science', 'party', 'zip', 'mov'
]);

const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'banking',
    'secure', 'security', 'update', 'confirm', 'wallet', 'token',
    'authenticate', 'credential', 'recovery', 'support', 'invoice',
    'payment', 'billing', 'validate', 'password', 'webscr', 'ebayisapi'
];

const SUSPICIOUS_EXTENSIONS = ['.exe', '.zip', '.scr', '.apk', '.bat', '.cmd', '.vbs', '.js', '.jar'];

function calcShannonEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const freqs = {};
    for (let i = 0; i < len; i++) {
        const char = str[i];
        freqs[char] = (freqs[char] || 0) + 1;
    }
    let entropy = 0;
    for (const count of Object.values(freqs)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return +entropy.toFixed(4);
}

function levenshteinDistance(s1, s2) {
    const m = s1.length;
    const n = s2.length;
    const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            );
        }
    }
    return dp[m][n];
}

export async function GET(req) {
    const { searchParams } = new URL(req.url);
    const urlStr = searchParams.get('url') || '';
    return extractFeaturesResponse(urlStr);
}

export async function POST(req) {
    try {
        const body = await req.json().catch(() => ({}));
        const urlStr = body.url || '';
        return extractFeaturesResponse(urlStr);
    } catch (err) {
        return NextResponse.json({ error: err.message || 'Feature extraction failed' }, { status: 500 });
    }
}

function extractFeaturesResponse(rawUrl) {
    let input = rawUrl.trim();
    if (!input) {
        return NextResponse.json({ error: 'Target URL is required' }, { status: 400 });
    }

    if (!input.startsWith('http://') && !input.startsWith('https://')) {
        input = 'https://' + input;
    }

    let parsed;
    try {
        parsed = new URL(input);
    } catch {
        return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
    }

    const fullUrl = parsed.toString();
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname;
    const search = parsed.search;

    const domainParts = hostname.split('.');
    const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
    const mainDomain = domainParts.length > 1 ? domainParts[domainParts.length - 2] : hostname;

    // ── 48 Individual Feature Computation ──
    const f = new Array(48).fill(0);

    f[0] = fullUrl.length;
    f[1] = hostname.length;
    f[2] = pathname.length;
    f[3] = search.length;
    f[4] = Math.max(0, domainParts.length - 2); // Subdomain count
    f[5] = (fullUrl.match(/\./g) || []).length;
    f[6] = (fullUrl.match(/-/g) || []).length;
    f[7] = (fullUrl.match(/@/g) || []).length;
    f[8] = (pathname.match(/\/\//g) || []).length;
    f[9] = (fullUrl.match(/_/g) || []).length;
    f[10] = (fullUrl.match(/~/g) || []).length;
    f[11] = (fullUrl.match(/%/g) || []).length;
    f[12] = (fullUrl.match(/\?/g) || []).length;
    f[13] = (fullUrl.match(/=/g) || []).length;
    f[14] = (fullUrl.match(/&/g) || []).length;
    f[15] = (fullUrl.match(/#/g) || []).length;

    const urlDigits = (fullUrl.match(/\d/g) || []).length;
    f[16] = urlDigits;
    f[17] = +(urlDigits / Math.max(1, fullUrl.length)).toFixed(4);

    const domainDigits = (hostname.match(/\d/g) || []).length;
    f[18] = domainDigits;
    f[19] = +(domainDigits / Math.max(1, hostname.length)).toFixed(4);

    const urlLetters = (fullUrl.match(/[a-zA-Z]/g) || []).length;
    f[20] = urlLetters;
    f[21] = +(urlLetters / Math.max(1, fullUrl.length)).toFixed(4);

    const vowels = (hostname.match(/[aeiou]/gi) || []).length;
    const consonants = (hostname.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
    f[22] = vowels;
    f[23] = consonants;
    f[24] = consonants > 0 ? +(vowels / consonants).toFixed(4) : vowels;

    f[25] = calcShannonEntropy(fullUrl);
    f[26] = calcShannonEntropy(hostname);
    f[27] = calcShannonEntropy(pathname);

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) ? 1 : 0;
    f[28] = isIp;
    f[29] = parsed.protocol === 'https:' ? 1 : 0;
    f[30] = hostname.includes('xn--') ? 1 : 0;
    f[31] = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;

    let keywordCount = 0;
    const lowerUrl = fullUrl.toLowerCase();
    for (const kw of SUSPICIOUS_KEYWORDS) {
        if (lowerUrl.includes(kw)) keywordCount++;
    }
    f[32] = keywordCount;

    let minBrandDist = 999;
    let closestBrand = '';
    for (const brand of TARGET_BRANDS) {
        const dist = levenshteinDistance(mainDomain, brand);
        if (dist < minBrandDist) {
            minBrandDist = dist;
            closestBrand = brand;
        }
    }
    f[33] = minBrandDist;
    const isTyposquat = (minBrandDist === 1 || minBrandDist === 2) && mainDomain !== closestBrand ? 1 : 0;
    f[34] = isTyposquat;

    const tokens = fullUrl.split(/[^a-zA-Z0-9]/).filter(Boolean);
    const tokenLens = tokens.map(t => t.length);
    f[35] = tokenLens.length ? Math.max(...tokenLens) : 0;
    f[36] = tokenLens.length ? +(tokenLens.reduce((a, b) => a + b, 0) / tokenLens.length).toFixed(2) : 0;

    f[37] = hostname.length > 0 ? +((hostname.length - mainDomain.length) / hostname.length).toFixed(4) : 0;
    f[38] = /(.)\1{2,}/.test(hostname) ? 1 : 0;

    const specChars = (fullUrl.match(/[^a-zA-Z0-9]/g) || []).length;
    f[39] = +(specChars / Math.max(1, fullUrl.length)).toFixed(4);

    f[40] = parsed.port ? 1 : 0;
    const pathTokens = pathname.split('/').filter(Boolean);
    f[41] = pathTokens.length;
    f[42] = Array.from(parsed.searchParams.keys()).length;
    f[43] = /%[0-9a-fA-F]{2}/.test(fullUrl) ? 1 : 0;
    f[44] = /[A-Za-z0-9+/=]{20,}/.test(fullUrl) ? 1 : 0;

    const hasExt = /\.[a-zA-Z0-9]{2,4}$/.test(pathname) ? 1 : 0;
    f[45] = hasExt;
    const hasSuspExt = SUSPICIOUS_EXTENSIONS.some(ext => pathname.endsWith(ext)) ? 1 : 0;
    f[46] = hasSuspExt;

    let riskPoints = 0;
    if (isTyposquat) riskPoints += 0.35;
    if (isIp) riskPoints += 0.25;
    if (f[31] === 1) riskPoints += 0.15;
    if (keywordCount >= 2) riskPoints += 0.20;
    else if (keywordCount === 1) riskPoints += 0.10;
    if (f[26] > 3.8) riskPoints += 0.15;
    if (f[29] === 0) riskPoints += 0.10;
    if (f[4] >= 3) riskPoints += 0.10;
    if (f[30] === 1) riskPoints += 0.20;
    if (hasSuspExt) riskPoints += 0.25;

    const compositeScore = Math.min(1.0, Math.max(0.0, +riskPoints.toFixed(4)));
    f[47] = compositeScore;

    const classification = compositeScore >= 0.7 ? 'PHISHING_SUSPECT' :
        compositeScore >= 0.4 ? 'SUSPICIOUS' : 'BENIGN';

    const featureNames = [
        "url_length", "domain_length", "path_length", "query_length", "subdomain_count",
        "dot_count", "hyphen_count", "at_symbol_count", "double_slash_path_count", "underscore_count",
        "tilde_count", "percent_count", "question_count", "equals_count", "ampersand_count",
        "hash_count", "digit_count_url", "digit_ratio_url", "digit_count_domain", "digit_ratio_domain",
        "letter_count_url", "letter_ratio_url", "vowel_count_domain", "consonant_count_domain", "vowel_consonant_ratio",
        "shannon_entropy_url", "shannon_entropy_domain", "shannon_entropy_path", "is_ip_address", "is_https",
        "has_punycode", "suspicious_tld", "suspicious_keyword_count", "brand_levenshtein_min", "is_typosquat",
        "longest_token_length", "avg_token_length", "subdomain_ratio", "consecutive_char_repetition", "special_char_density",
        "port_specified", "path_depth", "query_param_count", "hex_encoded_chars", "base64_indicator",
        "has_file_extension", "suspicious_file_extension", "composite_risk_score"
    ];

    const featureDetails = featureNames.map((name, idx) => ({
        index: idx,
        name,
        value: f[idx],
        description: getFeatureDesc(name)
    }));

    return NextResponse.json({
        success: true,
        target: hostname,
        url: fullUrl,
        classification,
        riskScore: compositeScore,
        confidence: +(compositeScore > 0.5 ? compositeScore : 1 - compositeScore).toFixed(4),
        entropy: {
            url: f[25],
            domain: f[26],
            path: f[27]
        },
        brandAnalysis: {
            closestBrand,
            levenshteinDistance: minBrandDist,
            isTyposquat: isTyposquat === 1
        },
        keyIndicators: {
            isIpAddress: isIp === 1,
            isHttps: f[29] === 1,
            hasPunycode: f[30] === 1,
            suspiciousTld: f[31] === 1,
            suspiciousKeywordsFound: keywordCount,
            subdomainCount: f[4],
            suspiciousFileExtension: hasSuspExt === 1
        },
        vectorLength: 48,
        vector: f,
        features: featureDetails
    });
}

function getFeatureDesc(name) {
    const map = {
        "url_length": "Total character count of the full URI",
        "domain_length": "Character count of the domain name",
        "subdomain_count": "Number of subdomain labels preceding main domain",
        "shannon_entropy_domain": "Information entropy of domain characters (randomness measure)",
        "is_ip_address": "Whether hostname is a raw IPv4/IPv6 address",
        "is_https": "Whether communication uses TLS encryption",
        "has_punycode": "Punycode (xn--) homograph obfuscation flag",
        "suspicious_tld": "High-abuse Top-Level Domain registry flag",
        "suspicious_keyword_count": "Matches against credential/banking harvest terms",
        "brand_levenshtein_min": "Minimum edit distance to top protected brand domains",
        "is_typosquat": "Typosquat lookalike flag (edit distance 1-2 from brand)",
        "composite_risk_score": "Weighted multi-feature heuristic threat score (0.0-1.0)"
    };
    return map[name] || "Normalized numeric lexical/structural feature";
}
