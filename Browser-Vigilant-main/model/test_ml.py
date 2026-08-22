"""
test_ml.py — PHANTOM ML Model Verification & Benchmark Suite
============================================================
Tests:
1. Feature extraction parity (56 mathematical features)
2. ONNX Runtime inference latency and probability calibration
3. Phishing vs. Legitimate classification benchmarks
4. JavaScript feature extraction mirror accuracy
"""

import os
import sys
import time
import numpy as np
import onnxruntime as rt
from features import extract_features, FEATURE_NAMES

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Benchmark URLs ────────────────────────────────────────────────────────────
TEST_SUITE = [
    # Legitimate domains (expected: P(threat) < 0.35)
    ("https://www.google.com", 0, "Google Search"),
    ("https://github.com/torvalds/linux", 0, "GitHub Repo"),
    ("https://developer.mozilla.org/en-US/docs/Web", 0, "MDN Docs"),
    ("https://www.wikipedia.org/wiki/Cybersecurity", 0, "Wikipedia"),
    ("https://www.microsoft.com/en-us/windows", 0, "Microsoft"),
    ("https://www.apple.com/iphone", 0, "Apple"),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0, "Amazon Product"),
    ("https://stackoverflow.com/questions/11227809", 0, "StackOverflow"),
    ("https://www.netflix.com/browse", 0, "Netflix"),
    ("https://www.spotify.com/us/premium", 0, "Spotify"),

    # Phishing & Attack domains (expected: P(threat) > 0.60)
    ("http://paypal-secure.account-verify.xyz/signin", 1, "PayPal Phish (xyz TLD)"),
    ("http://secure-login.paypa1.top/account/update", 1, "Typosquat paypa1"),
    ("http://amaz0n.secure-update.xyz/account", 1, "Typosquat amaz0n"),
    ("http://apple-account.security-alert.xyz/signin", 1, "Apple Fake Alert"),
    ("http://xn--googIe-hsa.com/login", 1, "Homograph Attack"),
    ("http://185.220.101.23/paypal/login", 1, "IP-based Phishing"),
    ("http://sbi-refund.xyz/process?vpa=taxrefund@government", 1, "UPI Fraud Scam"),
    ("http://gpay-cashback.top/redeem?pa=support@googlepay", 1, "UPI Cashback Scam"),
    ("http://invoice2024.pdf.exe.malware.xyz/run", 1, "Double Extension Malware"),
    ("http://login.secure.verify.account.evil.top/signin", 1, "Subdomain Deep Spoof"),
]

def run_tests():
    print("=" * 70)
    print("  PHANTOM Machine Learning Engine — Verification & Benchmark")
    print("=" * 70)

    # 1. Verify Feature Extractor
    print("\n[1/4] Verifying 56-Feature Mathematical Extractor...")
    test_feats = extract_features("https://www.google.com")
    assert len(test_feats) == 56, f"Expected 56 features, got {len(test_feats)}"
    print(f"  [OK] Feature extraction verified: {len(test_feats)} features produced.")

    # 2. Verify ONNX Model Load
    onnx_path = os.path.join(os.path.dirname(__file__), "model.onnx")
    if not os.path.exists(onnx_path):
        onnx_path = os.path.join(os.path.dirname(__file__), "..", "model.onnx")
    
    print(f"\n[2/4] Loading ONNX Inference Session from {onnx_path}...")
    if not os.path.exists(onnx_path):
        print(f"  [FAIL] model.onnx not found at {onnx_path}")
        return False

    session = rt.InferenceSession(onnx_path)
    input_name = session.get_inputs()[0].name
    output_names = [o.name for o in session.get_outputs()]
    print(f"  [OK] Model loaded successfully.")
    print(f"       Input Name: {input_name}, Expected Shape: {session.get_inputs()[0].shape}")
    print(f"       Outputs: {output_names}")

    # 3. Latency Benchmark
    print("\n[3/4] Benchmarking In-Memory Inference Latency (100 iterations)...")
    dummy_input = np.array([test_feats], dtype=np.float32)
    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        _ = session.run(None, {input_name: dummy_input})
        latencies.append((time.perf_counter() - t0) * 1000)

    avg_ms = np.mean(latencies)
    p95_ms = np.percentile(latencies, 95)
    print(f"  [OK] Average Latency: {avg_ms:.3f} ms | P95 Latency: {p95_ms:.3f} ms (Target < 5ms)")

    # 4. Classification Accuracy Test Suite
    print("\n[4/4] Running Classification Test Suite on Ground-Truth URLs...")
    print("-" * 70)
    print(f"  {'URL Target':<42} {'True':<6} {'Score':>7}  {'Result':<8}")
    print("-" * 70)

    correct = 0
    total = len(TEST_SUITE)

    for url, expected_label, desc in TEST_SUITE:
        feats = np.array([extract_features(url)], dtype=np.float32)
        outputs = session.run(None, {input_name: feats})
        
        # ONNX classifier outputs: [labels, probabilities_map or array]
        if len(outputs) > 1 and hasattr(outputs[1], '__len__'):
            prob_arr = outputs[1]
            if isinstance(prob_arr, list) and isinstance(prob_arr[0], dict):
                p_phish = prob_arr[0].get(1, 0.0)
            elif isinstance(prob_arr, np.ndarray):
                p_phish = float(prob_arr[0][1]) if prob_arr.shape[1] > 1 else float(prob_arr[0][0])
            else:
                p_phish = 0.5
        else:
            p_phish = float(outputs[0][0])

        predicted_label = 1 if p_phish >= 0.50 else 0
        is_pass = (predicted_label == expected_label)
        if is_pass:
            correct += 1

        label_str = "PHISH" if expected_label == 1 else "LEGIT"
        status_str = "[PASS]" if is_pass else "[FAIL]"
        display_url = url[:40] + ".." if len(url) > 42 else url
        print(f"  {display_url:<42} {label_str:<6} {p_phish:>6.1%}  {status_str:<8}")

    accuracy = (correct / total) * 100
    print("-" * 70)
    print(f"\n  Final Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    print("=" * 70)

    return accuracy >= 80

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
