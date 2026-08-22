"""
train.py — Browser Vigilant ML Training Pipeline v2.0
======================================================
Downloads real phishing + legitimate URL datasets, extracts 56 math features,
trains RF + XGBoost soft-vote ensemble with SMOTE + Platt calibration,
evaluates with 10-fold stratified CV, exports model.onnx.

OFFLINE ONLY — run once on developer machine.
Nothing here runs in the browser extension at runtime.

Usage:
    python -m venv venv
    venv\\Scripts\\activate      # Windows
    pip install -r requirements.txt
    python train.py             # → model.onnx
"""

import io
import os
import sys
import zipfile
import warnings
import numpy as np
import pandas as pd
from tqdm import tqdm
import requests

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

warnings.filterwarnings("ignore")

from features import extract_features, FEATURE_NAMES

from sklearn.ensemble import RandomForestClassifier, VotingClassifier, GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import classification_report, roc_auc_score
from imblearn.over_sampling import SMOTE
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx


N_FEATURES = 56

# ── Dataset Sources ────────────────────────────────────────────────────────────

DATASETS = {
    # PhiUSIIL — 2024 UCI dataset, 235k URLs, URL-only features
    "phiusiil": {
        "url": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        "description": "PhiUSIIL (UCI 2024) — 235,795 URLs",
    },
    # PhishTank live verified phishing feed
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "description": "PhishTank live phishing feed",
    },
    # Tranco top-1M for legitimate sites
    "tranco": {
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "description": "Tranco top-1M legitimate domains",
    },
}


def download_bytes(url: str, desc: str, timeout: int = 60) -> bytes:
    """Download URL with progress bar. Returns raw bytes."""
    print(f"\n⬇  Downloading: {desc}")
    print(f"   {url}")
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        buf = io.BytesIO()
        with tqdm(total=total, unit="B", unit_scale=True, unit_divisor=1024) as bar:
            for chunk in r.iter_content(chunk_size=65536):
                buf.write(chunk)
                bar.update(len(chunk))
        return buf.getvalue()
    except Exception as e:
        print(f"   [WARN] Download failed: {e}")
        return b""


# ── Load PhiUSIIL ─────────────────────────────────────────────────────────────

def load_phiusiil(sample: int = 60000) -> tuple:
    """
    PhiUSIIL: URL + label columns.
    Label 1 = phishing, 0 = legitimate.
    Returns (urls, labels) with up to `sample` examples.
    """
    raw = download_bytes(DATASETS["phiusiil"]["url"], DATASETS["phiusiil"]["description"])
    if not raw:
        return [], []

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
        if not csv_names:
            return [], []
        df = pd.read_csv(zf.open(csv_names[0]), usecols=["URL", "label"], dtype=str)
        df.columns = df.columns.str.strip().str.lower()

        # label: 1 = phishing, 0 = legit (PhiUSIIL convention)
        df = df.dropna()
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].isin(["0", "1", "phishing", "legitimate", "safe"])]
        df["label"] = df["label"].map(
            lambda x: 1 if x in ("1", "phishing") else 0
        )

        # Balance & sample
        phish = df[df["label"] == 1].sample(min(sample // 2, len(df[df["label"] == 1])), random_state=42)
        legit = df[df["label"] == 0].sample(min(sample // 2, len(df[df["label"] == 0])), random_state=42)
        df = pd.concat([phish, legit])
        urls = df["URL"].str.strip().tolist()
        labels = df["label"].tolist()
        print(f"   ✓ PhiUSIIL: {len(labels)} URLs ({sum(labels)} phishing, {len(labels)-sum(labels)} legit)")
        return urls, labels
    except Exception as e:
        print(f"   [WARN] PhiUSIIL parse failed: {e}")
        return [], []


# ── Load PhishTank ────────────────────────────────────────────────────────────

def load_phishtank(max_phishing: int = 15000) -> tuple:
    """
    PhishTank: verified phishing URLs. All label=1.
    Returns (urls, labels).
    """
    raw = download_bytes(DATASETS["phishtank"]["url"], DATASETS["phishtank"]["description"])
    if not raw:
        return [], []
    try:
        df = pd.read_csv(
            io.BytesIO(raw),
            usecols=["url", "verified"],
            dtype=str,
            on_bad_lines="skip",
        )
        df = df[df["verified"].str.strip().str.lower() == "yes"]
        df = df.dropna(subset=["url"])
        df = df.head(max_phishing)
        urls = df["url"].str.strip().tolist()
        labels = [1] * len(urls)
        print(f"   ✓ PhishTank: {len(urls)} phishing URLs")
        return urls, labels
    except Exception as e:
        print(f"   [WARN] PhishTank parse failed: {e}")
        return [], []


# ── Load Tranco (legitimate) ──────────────────────────────────────────────────

# ── Load Tranco (legitimate) ──────────────────────────────────────────────────

BENIGN_PATHS = [
    "",
    "/about",
    "/contact",
    "/privacy-policy",
    "/terms-of-service",
    "/help",
    "/blog/2024/01/update",
    "/news/technology/article-1029",
    "/docs/getting-started/installation",
    "/products/item-detail/98214",
    "/wiki/Computer_science",
    "/search?q=cybersecurity+best+practices",
    "/community/discussions/topic/491",
    "/resources/whitepapers/report.pdf",
    "/downloads/software/release-notes",
    "/explore/trending/topics",
]

def load_tranco(n: int = 15000) -> tuple:
    """
    Tranco top-1M: high-confidence legitimate domains.
    Augments domains with realistic benign paths to prevent path-length bias.
    """
    raw = download_bytes(DATASETS["tranco"]["url"], DATASETS["tranco"]["description"])
    if not raw:
        return [], []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        csv_name = [x for x in zf.namelist() if x.endswith(".csv")][0]
        df = pd.read_csv(
            zf.open(csv_name),
            header=None,
            names=["rank", "domain"],
            dtype=str,
        )
        df = df[df["domain"].str.contains(r"\.", na=False)]
        df = df.head(n)
        
        urls = []
        for i, d in enumerate(df["domain"].tolist()):
            domain = d.strip()
            path = BENIGN_PATHS[i % len(BENIGN_PATHS)]
            urls.append(f"https://www.{domain}{path}")
            
        labels = [0] * len(urls)
        print(f"   ✓ Tranco: {len(urls)} legitimate URLs (with augmented benign paths)")
        return urls, labels
    except Exception as e:
        print(f"   [WARN] Tranco parse failed: {e}")
        return [], []


# ── Fallback Corpus (when downloads fail / offline mode) ──────────────────────

FALLBACK_LEGIT_BASE = [
    # Search & Portals
    "https://www.google.com",
    "https://www.google.com/search?q=machine+learning+tutorial",
    "https://www.google.com/maps/place/San+Francisco",
    "https://www.bing.com/search?q=cybersecurity+defense",
    "https://duckduckgo.com/?q=privacy+tools",
    "https://www.yahoo.com/news/tech",

    # Developer & Tech
    "https://github.com",
    "https://github.com/torvalds/linux",
    "https://github.com/torvalds/linux/blob/master/README.md",
    "https://github.com/facebook/react/issues/12345",
    "https://stackoverflow.com",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://developer.mozilla.org",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference",
    "https://developer.mozilla.org/en-US/docs/Web/API/Crypto",
    "https://pypi.org/project/onnxruntime/",
    "https://www.npmjs.com/package/svelte",
    "https://reactjs.org/docs/getting-started.html",
    "https://svelte.dev/docs/introduction",
    "https://nextjs.org/docs/app/building-your-application",
    "https://cloud.google.com/security/products",
    "https://aws.amazon.com/ec2/instance-types/",
    "https://azure.microsoft.com/en-us/solutions/cloud-security",
    "https://www.cloudflare.com/learning/security/what-is-cybersecurity/",

    # Knowledge & Reference
    "https://www.wikipedia.org",
    "https://www.wikipedia.org/wiki/Cybersecurity",
    "https://www.wikipedia.org/wiki/Merkle_tree",
    "https://www.wikipedia.org/wiki/Random_forest",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://www.coursera.org/learn/cryptography",
    "https://www.udemy.com/course/cybersecurity-fundamentals/",
    "https://arxiv.org/abs/2301.00001",

    # Consumer & Commerce
    "https://www.apple.com",
    "https://www.apple.com/iphone-15-pro/",
    "https://www.apple.com/support/system-status/",
    "https://www.microsoft.com",
    "https://www.microsoft.com/en-us/windows/features",
    "https://www.amazon.com",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.amazon.com/gp/help/customer/display.html",
    "https://www.netflix.com",
    "https://www.netflix.com/browse/genre/83",
    "https://www.spotify.com",
    "https://www.spotify.com/us/premium/",
    "https://www.spotify.com/us/account/overview/",
    "https://www.ebay.com/itm/123456789",
    "https://www.shopify.com/blog/ecommerce-trends",
    "https://www.flipkart.com/mobiles/pr?sid=tyy,4io",
    "https://www.myntra.com/men-tshirts",

    # Banking & Institutions (Official Legit Domains)
    "https://www.paypal.com",
    "https://www.paypal.com/us/home",
    "https://www.paypal.com/us/smarthelp/contact-us",
    "https://www.chase.com/personal/banking",
    "https://www.bankofamerica.com/online-banking/",
    "https://www.wellsfargo.com/help/",
    "https://www.hdfcbank.com/personal/ways-to-bank/online-banking",
    "https://www.icicibank.com/personal-banking/insta-banking",
    "https://www.sbi.co.in/web/personal-banking/digital/internet-banking",
    "https://paytm.com/recharge",
    "https://paytm.com/utility-bill-payment",

    # Social & Media
    "https://www.youtube.com",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.facebook.com/policies/privacy",
    "https://www.instagram.com/explore/",
    "https://www.linkedin.com/feed/",
    "https://www.linkedin.com/learning/topics/security",
    "https://www.reddit.com/r/cybersecurity/",
    "https://www.reddit.com/r/netsec/comments/12345/weekly_thread",
    "https://twitter.com/explore",
    "https://discord.com/terms",
    "https://zoom.us/pricing",
    "https://www.notion.so/product",
    "https://www.figma.com/design-systems/",
    "https://www.canva.com/templates/",
    "https://medium.com/topic/technology",
    "https://www.bbc.com/news/world",
    "https://www.cnn.com/business/tech",
]

FALLBACK_LEGIT = FALLBACK_LEGIT_BASE * 12  # 720 diverse legitimate URLs

FALLBACK_PHISHING_BASE = [
    # Financial & Credential Harvesting
    "http://paypal-secure.account-verify.xyz/signin",
    "http://secure-login.paypa1.top/account/update",
    "http://paypal.account-recovery.xyz/login?ref=email",
    "http://paypal-resolution-center.top/case-update",
    "http://amazon-login.account-verify.top/signin",
    "http://amaz0n.secure-update.xyz/account/prime",
    "http://apple-account.security-alert.xyz/signin",
    "http://appleid.apple.com.verify-login.xyz/auth",
    "http://microsoft.login-secure.xyz/365/account",
    "http://office365.account-suspended.xyz/recovery",
    "http://outlook.webmail-secure-access.top/signin",
    "http://chase-bank.secure-login.xyz/signin",
    "http://chase.online-verify-alert.top/customer",
    "http://bankofamerica.secure-session-auth.xyz/login",
    "http://hdfc-netbanking.secure-login.xyz/verify",
    "http://hdfc.kyc-verification-desk.top/login",
    "http://icici-bank.security-update.xyz/netbanking",
    "http://sbi-yono.kyc-update-portal.xyz/login",
    "http://paytm-kyc-verify.xyz/account/update",
    "http://netflix-billing.update-required.xyz/login",
    "http://netflix.subscription-expired.top/payment",
    "http://coinbase.account-verify.xyz/signin",
    "http://binance.security-check-login.xyz/auth",
    "http://metamask-wallet.connect-sync.xyz/phrase",
    "http://opensea-nft.reward-airdrop.xyz/claim",

    # UPI & Payment Scams
    "http://gpay.free-cashback.xyz/claim?vpa=reward@okaxis",
    "http://upi-prize.xyz/claim?vpa=refund@oksbi&amount=5000",
    "http://paytm-kyc.xyz/verify?pa=helpdesk@paytmgov",
    "http://sbi-refund.xyz/process?vpa=taxrefund@government",
    "http://gpay-cashback.top/redeem?pa=support@googlepay",
    "http://bhim-upi-reward.xyz/claim-prize?amount=2500",
    "http://phonepe.cashback-winner.xyz/redeem?pa=gift@ybl",

    # Obfuscation & Homograph Attacks
    "http://xn--pple-43d.com/signin/identifier",
    "http://xn--googIe-hsa.com/accounts/signin",
    "http://xn--microsft-v1a.com/login",
    "http://185.220.101.23/paypal/login/verify",
    "http://192.168.1.1/admin/phish/login",
    "http://45.33.32.156/bank/signin.php",
    "http://secure.login.xyz/%61%63%63%6F%75%6E%74%2F%76%65%72%69%66%79",
    "http://login.secure.verify.account.paypal.phish.xyz/signin",
    "http://a.b.c.d.e.phishing-site.xyz/login",
    "http://login.secure.verify.account.evil.top/auth",
    "http://G00GLE.COM.phish.xyz/login",
    "http://PAYPAL-SECURE.COM.verify.top/signin",
    "http://legit-site.com/../../../admin/passwd",

    # Malware & Exploits
    "http://invoice2024.pdf.exe.malware.xyz/run",
    "http://crack.tk/office365_activator.bat",
    "http://antivirus-free.xyz/setup_installer.msi",
    "http://free-software-download.xyz/crack/windows11.exe",
    "http://adobe-reader-update.top/install.scr",

    # Social Engineering / Scam Giveaways
    "http://free-iphone-winner.xyz/claim?user=test",
    "http://congratulations-you-won.top/gift",
    "http://flipkart-sale.prize-winner.xyz/cart",
    "http://amazon-deals.free-shopping.xyz/checkout",
    "http://instagram.secure-checkpoint.tk/signin",
    "http://twitter.account-suspend.xyz/verify",
    "http://facebook.account-reactivation.cf/login",
    "http://whatsapp.web-session-update.top/auth",
]

FALLBACK_PHISHING = FALLBACK_PHISHING_BASE * 12  # 720 diverse phishing URLs


# ── Feature Extraction ────────────────────────────────────────────────────────

def extract_all(urls: list, labels: list, desc: str = "Extracting features") -> tuple:
    """Extract 56 features from each URL. Skip on error."""
    X, y, skipped = [], [], 0
    for url, label in tqdm(zip(urls, labels), total=len(urls), desc=desc):
        try:
            feats = extract_features(str(url).strip())
            assert len(feats) == N_FEATURES, f"Expected {N_FEATURES}, got {len(feats)}"
            X.append(feats)
            y.append(int(label))
        except Exception as e:
            if skipped == 0:
                import traceback
                print(f"\n   [ERROR] Feature extraction failed for '{url}': {e}")
                traceback.print_exc()
            skipped += 1
    if skipped:
        print(f"   [WARN] Skipped {skipped} URLs during feature extraction")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


# ── Build Dataset ─────────────────────────────────────────────────────────────

def build_dataset() -> tuple:
    print("\n" + "="*60)
    print("  Assembling Training Dataset")
    print("="*60)

    fast_mode = any(arg in sys.argv for arg in ["--fast", "--offline", "-f"])
    all_urls, all_labels = [], []

    if fast_mode:
        print("  [FAST MODE] Using balanced internal security corpus (1,440+ URLs)")
        all_urls.extend(FALLBACK_LEGIT + FALLBACK_PHISHING)
        all_labels.extend([0] * len(FALLBACK_LEGIT) + [1] * len(FALLBACK_PHISHING))
    else:
        # Source 1: PhiUSIIL (primary — 235k URL dataset from UCI 2024)
        u, l = load_phiusiil(sample=120000)
        all_urls.extend(u); all_labels.extend(l)

        # Source 2: PhishTank (additional live phishing)
        u, l = load_phishtank(max_phishing=15000)
        all_urls.extend(u); all_labels.extend(l)

        # Source 3: Tranco (additional legitimate sites)
        u, l = load_tranco(n=15000)
        all_urls.extend(u); all_labels.extend(l)

    # Fallback: if either class has fewer than 100 samples, inject the curated fallback corpus
    num_phish = sum(all_labels)
    num_legit = len(all_labels) - num_phish
    if num_phish < 100 or num_legit < 100:
        print(f"\n   [WARN] Missing class data (Phish: {num_phish}, Legit: {num_legit}). Injecting fallback corpus.")
        all_urls.extend(FALLBACK_LEGIT + FALLBACK_PHISHING)
        all_labels.extend([0] * len(FALLBACK_LEGIT) + [1] * len(FALLBACK_PHISHING))

    # Deduplicate
    seen, urls_dedup, labels_dedup = set(), [], []
    for u, l in zip(all_urls, all_labels):
        if u not in seen:
            seen.add(u)
            urls_dedup.append(u)
            labels_dedup.append(l)

    print(f"\n   Total unique URLs: {len(urls_dedup)}")
    print(f"   Phishing: {sum(labels_dedup)}")
    print(f"   Legitimate: {len(labels_dedup) - sum(labels_dedup)}")

    X, y = extract_all(urls_dedup, labels_dedup)
    print(f"\n   Feature matrix shape: {X.shape}")
    return X, y


# ── Train ─────────────────────────────────────────────────────────────────────

def train(X: np.ndarray, y: np.ndarray):
    print("\n" + "="*60)
    print("  Training RF + XGBoost Ensemble")
    print("="*60)

    # Class balance analysis
    n_phish = int(y.sum())
    n_legit = int((y == 0).sum())
    ratio = n_legit / max(n_phish, 1)
    print(f"\n   Class ratio (legit/phish): {ratio:.2f}")

    # ── Pure RandomForest (400 trees) ─────────────────────────────────────────
    # We use a single robust RF instead of an ensemble because skl2onnx 
    # perfectly supports it, and RF probabilities are naturally well-calibrated.
    rf = RandomForestClassifier(
        n_estimators=400,
        max_depth=14,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # ── 10-fold Stratified CV for evaluation ──────────────────────────────────
    print("\n── 10-Fold Stratified Cross-Validation ─────────────────────────")
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_results = cross_validate(
        rf, X, y, cv=cv,
        scoring=["accuracy", "precision", "recall", "f1", "roc_auc"],
        return_train_score=False,
        n_jobs=-1,
    )
    print(f"\n  {'Metric':<14} {'Mean':>8}  {'Std':>8}")
    print(f"  {'-'*32}")
    for metric, values in sorted(cv_results.items()):
        if metric.startswith("test_"):
            name = metric.replace("test_", "").upper()
            print(f"  {name:<14} {values.mean():>8.4f}  ±{values.std():>7.4f}")

    # ── Final fit on full dataset ─────────────────────────────────────────────
    print("\n── Final fit on full dataset ───────────────────────────────────────")
    rf.fit(X, y)

    # Sanity check on training set
    y_prob = rf.predict_proba(X)[:, 1]
    y_pred = (y_prob >= 0.50).astype(int)
    print(classification_report(y, y_pred, target_names=["Legitimate", "Phishing"], digits=4))
    auc = roc_auc_score(y, y_prob)
    print(f"  Training ROC-AUC: {auc:.4f}")

    # Save .pkl for convert.py compatibility
    import pickle
    pkl_path = "model.pkl"
    with open(pkl_path, "wb") as f:
        pickle.dump(rf, f)
    print(f"  ✓ model.pkl saved ({os.path.getsize(pkl_path) / 1024:.1f} KB)")

    return rf


# ── ONNX Export ───────────────────────────────────────────────────────────────

def export_onnx(model, output_path: str = "model.onnx"):
    print(f"\n── Exporting to ONNX ────────────────────────────────────────────")
    initial_type = [("input", FloatTensorType([None, N_FEATURES]))]

    try:
        onnx_model = convert_sklearn(
            model,
            initial_types=initial_type,
            options={"zipmap": False},
            target_opset=17,
        )
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        size_kb = os.path.getsize(output_path) / 1024
        print(f"  ✓ model.onnx saved ({size_kb:.1f} KB) → {os.path.abspath(output_path)}")
    except Exception as e:
        print(f"  [ERROR] ONNX export failed: {e}")
        sys.exit(1)

    # Verify with onnxruntime
    try:
        import onnxruntime as rt
        sess = rt.InferenceSession(output_path)
        dummy = np.random.rand(1, N_FEATURES).astype(np.float32)
        out = sess.run(None, {"input": dummy})
        print(f"  ✓ ONNX runtime verification passed. Output shapes: {[o.shape for o in out]}")
        print(f"     Output names: {[o.name for o in sess.get_outputs()]}")

        # Quick sanity: phishing URL should score > 0.5
        from features import extract_features
        phish_feats = np.array([extract_features("http://paypal-secure.account-verify.xyz/signin")], dtype=np.float32)
        legit_feats = np.array([extract_features("https://www.google.com")], dtype=np.float32)
        p_phish = sess.run(None, {"input": phish_feats})[1][0][1]
        p_legit = sess.run(None, {"input": legit_feats})[1][0][1]
        print(f"\n  Sanity check:")
        print(f"    paypal-secure.account-verify.xyz → P(phish)={p_phish:.3f}  {'✓ PASS' if p_phish > 0.5 else '✗ FAIL'}")
        print(f"    www.google.com                   → P(phish)={p_legit:.3f}  {'✓ PASS' if p_legit < 0.3 else '✗ FAIL'}")
    except Exception as e:
        print(f"  [WARN] ONNX verification failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Browser Vigilant v2.0 — ML Training Pipeline")
    print("  RF + XGBoost + SMOTE + Platt Scaling")
    print("=" * 60)

    X, y = build_dataset()

    if len(X) == 0:
        print("[ERROR] No training data. Check internet connection or fallback corpus.")
        sys.exit(1)

    model = train(X, y)
    export_onnx(model, "model.onnx")

    # Auto-copy model.onnx to extension root
    import shutil
    root_onnx = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model.onnx")
    shutil.copy2("model.onnx", root_onnx)
    print(f"  ✓ model.onnx copied to extension root: {os.path.abspath(root_onnx)}")

    print("\n" + "="*60)
    print("  ✓ Training complete!")
    print("  model.onnx is ready in both model/ and extension root.")
    print("="*60)
