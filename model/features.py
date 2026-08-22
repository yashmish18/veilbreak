"""
features.py — Browser Vigilant ML Feature Extractor
====================================================
Extracts exactly 56 float features from a URL string using pure math.
No network calls. No blacklist lookups. No external data at runtime.
Feature order MUST stay in sync with wasm-feature/src/lib.rs.

Math used:
  - Shannon entropy: H = -Σ p(c) · log₂(p(c))
  - Wagner-Fischer Levenshtein: O(min(m,n)) space
  - Percentage encoding ratio, vowel ratio, consonant runs
  - UPI VPA regex, n-gram character analysis
"""

import math
import re
from urllib.parse import urlparse

# ── Constants (used only for feature COMPUTATION, not runtime lookup) ──────────
# These determine feature values — they are part of the algorithm,
# the same as a word2vec vocabulary is part of an NLP model.

BRANDS = [
    "google","facebook","amazon","apple","microsoft","paypal","netflix",
    "instagram","twitter","linkedin","whatsapp","youtube","yahoo","ebay",
    "dropbox","spotify","adobe","chase","wellsfargo","bankofamerica",
    "citi","hsbc","barclays","halifax","natwest","santander","lloyds",
    "steam","roblox","epic","coinbase","binance","metamask","opensea",
    "paytm","phonepe","gpay","bhim","razorpay","hdfc","icici","sbi",
    "axis","kotak","airtel","jio","vodafone","bsnl","flipkart","myntra",
]

SUSPICIOUS_TLDS = {
    "xyz","tk","top","cf","ml","ga","gq","pw","cc","icu","club","online",
    "site","website","space","live","click","link","info","biz","work",
    "tech","store","shop","ru","cn","vip","win","loan","download",
}

LEGIT_UPI_HANDLES = {
    "okaxis","okicici","oksbi","okhdfcbank","ybl","ibl","axl","apl","fbl",
    "upi","paytm","waaxis","waxis","rajgovhdfcbank","barodampay","allbank",
    "andb","aubank","cnrb","csbpay","dbs","dcb","federal","hdfcbank","idbi",
    "idfc","indus","idfcbank","jio","kotak","lvb","mahb","nsdl","pnb",
    "psb","rbl","sib","tjsb","uco","union","united","vijb","yapl","airtel",
    "airtelpaymentsbank","postbank",
}

SHORT_URL_SERVICES = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
    "adf.ly","tiny.cc","clck.ru","cutt.ly","rb.gy","short.io","v.gd",
    "bitly.com","shorte.st","t2m.io",
}

DANGEROUS_EXTENSIONS = {
    "exe","scr","bat","cmd","ps1","vbs","wsf","hta","jar","msi","msp",
    "reg","dll","pif","com","cpl","inf","apk","ipa","dmg","pkg","deb","rpm",
}

# ── Math helpers ───────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """H = -Σ p(c) · log₂(p(c)) — measures randomness of string."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def levenshtein(a: str, b: str) -> int:
    """Wagner-Fischer algorithm — O(min(m,n)) space."""
    if len(a) < len(b):
        a, b = b, a
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[n]


def min_brand_distance(domain: str) -> int:
    """Minimum Levenshtein distance from domain core to any known brand."""
    core = domain.split(".")[0].lower()
    return min(levenshtein(core, b) for b in BRANDS)


def max_consecutive_consonants(s: str) -> int:
    """Max run of consonants — high runs indicate gibberish domains."""
    vowels = set("aeiou")
    max_run = cur = 0
    for c in s.lower():
        if c.isalpha() and c not in vowels:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


def char_ngram_entropy(s: str, n: int = 2) -> float:
    """Shannon entropy of character n-grams — detects auto-generated strings."""
    if len(s) < n:
        return 0.0
    ngrams = [s[i:i+n] for i in range(len(s) - n + 1)]
    freq: dict = {}
    for g in ngrams:
        freq[g] = freq.get(g, 0) + 1
    total = len(ngrams)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def parse_url_parts(url: str) -> dict:
    try:
        p = urlparse(url)
        netloc    = p.netloc.lower()
        host_port = netloc.split("@")[-1]
        host, _, port_str = host_port.partition(":")
        port = int(port_str) if port_str.isdigit() else None
        labels = host.split(".")
        tld    = labels[-1] if labels else ""
        reg    = ".".join(labels[-2:]) if len(labels) >= 2 else host
        sub    = ".".join(labels[:-2]) if len(labels) > 2 else ""
        return dict(scheme=p.scheme.lower(), host=host, path=p.path,
                    query=p.query, fragment=p.fragment, port=port,
                    tld=tld, registered_domain=reg, subdomain=sub,
                    labels=labels)
    except Exception:
        return dict(scheme="", host=url, path="", query="", fragment="",
                    port=None, tld="", registered_domain=url, subdomain="",
                    labels=[url])


# ── Main extractor — 56 features ──────────────────────────────────────────────

def extract_features(url: str) -> list:
    """
    Returns list[float] of exactly 56 features extracted purely from the URL
    string using mathematical operations. No network calls, no lookups.
    Feature order must match wasm-feature/src/lib.rs.
    """
    p   = parse_url_parts(url)
    host   = p["host"]
    path   = p["path"]
    query  = p["query"]
    tld    = p["tld"]
    domain = p["registered_domain"]
    sub    = p["subdomain"]
    low    = url.lower()
    f = [0.0] * 56

    # ── GROUP A: Lexical Structure (F0–F15) ────────────────────────────────────
    f[0]  = float(len(url))
    f[1]  = float(len(host))
    f[2]  = float(len(path))
    f[3]  = float(len(query))
    f[4]  = float(url.count("."))
    f[5]  = float(url.count("-"))
    f[6]  = float(url.count("_"))
    no_proto = url.split("//", 1)[-1] if "//" in url else url
    f[7]  = float(no_proto.count("/"))
    f[8]  = float(url.count("@"))
    digits = sum(1 for c in url if c.isdigit())
    f[9]  = float(digits)
    f[10] = digits / max(len(url), 1)                                   # digit ratio
    f[11] = 1.0 if p["scheme"] == "https" else 0.0                      # HTTPS flag
    f[12] = 1.0 if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", host) else 0.0  # IP-in-URL
    f[13] = 1.0 if "xn--" in host else 0.0                              # Punycode
    f[14] = float(max(len(p["labels"]) - 2, 0))                         # subdomain depth
    f[15] = 1.0 if (p["port"] is not None and
                    p["port"] not in (80, 443, 8080, 8443)) else 0.0    # port anomaly

    # ── GROUP B: Information Theory (F16–F20) ──────────────────────────────────
    f[16] = shannon_entropy(url)                     # URL Shannon entropy
    f[17] = shannon_entropy(host)                    # domain Shannon entropy
    f[18] = shannon_entropy(path)                    # path Shannon entropy
    f[19] = char_ngram_entropy(host, n=2)            # 2-gram entropy of domain
    f[20] = char_ngram_entropy(host, n=3)            # 3-gram entropy of domain

    # ── GROUP C: Brand Similarity (F21–F23) ────────────────────────────────────
    min_dist = min_brand_distance(domain)
    f[21] = 1.0 if 0 < min_dist <= 2 else 0.0       # brand spoof flag
    f[22] = min(min_dist, 10) / 10.0                 # normalized min distance
    brand_sub = any(b in sub for b in BRANDS)
    brand_reg = any(b in domain.split(".")[0] for b in BRANDS)
    f[23] = 1.0 if (brand_sub and not brand_reg) else 0.0   # brand in subdomain only

    # ── GROUP D: Keyword Signals (F24–F30) ─────────────────────────────────────
    login_kw  = {"login","signin","sign-in","account","verify","auth","authenticate","confirm","update"}
    trust_kw  = {"secure","safe","trust","bank","protected","official","helpdesk"}
    pay_kw    = {"pay","payment","wallet","upi","gpay","paytm","bhim","razorpay","phonepay"}
    free_kw   = {"free","bonus","prize","winner","giveaway","reward","claim","gift","lucky","congratulations"}
    fraud_kw  = {"kyc","refund","tax","block","suspend","urgent","helpdesk","support","care","alert"}
    f[24] = 1.0 if any(k in low for k in login_kw) else 0.0
    f[25] = 1.0 if any(k in host for k in trust_kw) else 0.0
    f[26] = 1.0 if any(k in low for k in pay_kw) else 0.0
    f[27] = 1.0 if any(k in low for k in free_kw) else 0.0
    f[28] = 1.0 if any(k in low for k in fraud_kw) else 0.0
    all_kw = login_kw | trust_kw | pay_kw | free_kw | fraud_kw
    hits = sum(1 for k in all_kw if k in low)
    f[29] = min(hits / 6.0, 1.0)                    # keyword density score
    f[30] = 1.0 if "-" in host else 0.0             # hyphen in domain flag

    # ── GROUP E: Obfuscation & Encoding (F31–F37) ──────────────────────────────
    dbl = re.compile(r"\.(pdf|doc|jpg|jpeg|png|gif|mp4|zip)\.(exe|js|php|bat|ps1|vbs|cmd|scr)", re.I)
    f[31] = 1.0 if dbl.search(path) else 0.0        # double extension
    pct_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    f[32] = pct_count / max(len(url), 1)            # percent-encoding ratio
    f[33] = min(pct_count / max(len(url) / 3, 1), 1.0)  # heavy encoding flag
    f[34] = float(len(query.split("&")) if query else 0)  # query param count
    f[35] = 1.0 if p["fragment"] else 0.0           # fragment presence
    f[36] = 1.0 if low.startswith("data:") else 0.0 # data: URI
    f[37] = 1.0 if (".." in path or "%2e%2e" in low) else 0.0  # path traversal

    # ── GROUP F: Domain Quality (F38–F47) ──────────────────────────────────────
    f[38] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0  # suspicious TLD
    f[39] = float(len(tld))                          # TLD length
    f[40] = 1.0 if sub else 0.0                      # has subdomain
    f[41] = 1.0 if re.fullmatch(r"[\d.]+", host) else 0.0  # numeric domain
    f[42] = len(set(url)) / max(len(url), 1)         # URL compression ratio
    vowels = sum(1 for c in host if c in "aeiou")
    alpha  = sum(1 for c in host if c.isalpha())
    f[43] = vowels / max(alpha, 1)                   # vowel ratio (low = gibberish)
    f[44] = float(max_consecutive_consonants(host))  # max consonant run
    f[45] = 1.0 if domain in SHORT_URL_SERVICES else 0.0   # short URL service
    f[46] = 1.0 if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", query) else 0.0  # base64 in query
    f[47] = float(path.count("/"))                   # path depth

    # ── GROUP G: UPI / Payment Specific (F48–F52) ──────────────────────────────
    upi_re = re.compile(r"[a-zA-Z0-9._-]+@[a-zA-Z]+")
    f[48] = 1.0 if upi_re.search(url) else 0.0      # UPI VPA pattern present
    suspicious_upi = 0.0
    fraud_pfx = {"refund","tax","prize","block","kyc","urgent","helpdesk","support","care"}
    for m in upi_re.finditer(url):
        handle = m.group().split("@")[-1].lower()
        prefix = m.group().split("@")[0].lower()
        if handle not in LEGIT_UPI_HANDLES or any(fp in prefix for fp in fraud_pfx):
            suspicious_upi = 1.0
            break
    f[49] = suspicious_upi                           # suspicious UPI VPA
    f[50] = 1.0 if re.search(r"upi://pay|pa=.*@|vpa=", low) else 0.0  # UPI collect request

    # ── GROUP H: File & Extension Risk (F51–F55) ───────────────────────────────
    ext_m = re.search(r"\.([a-zA-Z0-9]{1,5})(?:[?#]|$)", path)
    ext = ext_m.group(1).lower() if ext_m else ""
    f[51] = 1.0 if ext in DANGEROUS_EXTENSIONS else 0.0   # dangerous extension
    f[52] = 1.0 if re.search(r"/(wp-admin|admin|phpmyadmin|cgi-bin)/", low) else 0.0  # admin path
    f[53] = 1.0 if re.search(r"(redirect|returnurl|continue|next|goto|url)=http", low, re.I) else 0.0  # open redirect
    # Repeated char ratio (e.g. "aaaa" in domain = anomalous)
    max_rep = max((sum(1 for c in host if c == ch) for ch in set(host)), default=0)
    f[54] = max_rep / max(len(host), 1)              # max char repeat ratio
    f[55] = 1.0 if re.search(r"[a-f0-9]{32,}", low) else 0.0  # MD5/hex token in URL

    return f


FEATURE_NAMES = [
    # Group A
    "url_length", "domain_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "at_count", "digit_count", "digit_ratio", "is_https",
    "ip_in_url", "is_punycode", "subdomain_depth", "port_anomaly",
    # Group B
    "url_entropy", "domain_entropy", "path_entropy",
    "domain_bigram_entropy", "domain_trigram_entropy",
    # Group C
    "brand_spoof_flag", "brand_distance_norm", "brand_in_subdomain_only",
    # Group D
    "has_login_kw", "has_trust_kw_in_domain", "has_payment_kw",
    "has_free_kw", "has_fraud_kw", "keyword_density", "hyphen_in_domain",
    # Group E
    "double_extension", "pct_encoding_ratio", "heavy_encoding",
    "query_param_count", "has_fragment", "is_data_uri", "path_traversal",
    # Group F
    "suspicious_tld", "tld_length", "has_subdomain", "numeric_domain",
    "url_compression_ratio", "vowel_ratio", "max_consonant_run",
    "is_short_url", "base64_in_query", "path_depth",
    # Group G
    "upi_vpa_present", "suspicious_upi_vpa", "upi_collect_request",
    # Group H
    "dangerous_extension", "admin_path", "open_redirect",
    "max_char_repeat_ratio", "hex_token_in_url",
]

assert len(FEATURE_NAMES) == 56, f"Feature count mismatch: {len(FEATURE_NAMES)}"
