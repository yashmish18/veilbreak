"""
convert.py — Convert trained sklearn model to ONNX (56 features)
Run this if you have a saved model.pkl from train.py.
For end-to-end training+export, prefer train.py instead.
"""
import os
import sys
import pickle
import numpy as np
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxruntime as rt

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

N_FEATURES = 56
PKL_PATH = "model.pkl"
ONNX_PATH = "model.onnx"

if not os.path.exists(PKL_PATH):
    print(f"[ERROR] {PKL_PATH} not found.")
    print(f"  Run 'python train.py' first — it trains the model AND exports ONNX directly.")
    print(f"  This script is only needed if you want to re-export from a saved .pkl.")
    sys.exit(1)

print(f"Loading model from {PKL_PATH}...")
with open(PKL_PATH, "rb") as f:
    model = pickle.load(f)

print(f"Converting to ONNX with {N_FEATURES} features...")
initial_type = [("input", FloatTensorType([None, N_FEATURES]))]
onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    options={"zipmap": False},
    target_opset=17,
)

with open(ONNX_PATH, "wb") as f:
    f.write(onnx_model.SerializeToString())

size_kb = os.path.getsize(ONNX_PATH) / 1024
print(f"  ✓ {ONNX_PATH} saved ({size_kb:.1f} KB)")

# Verify with onnxruntime
sess = rt.InferenceSession(ONNX_PATH)
dummy = np.random.rand(1, N_FEATURES).astype(np.float32)
out = sess.run(None, {"input": dummy})
print(f"  ✓ ONNX runtime verification passed.")
print(f"    Output names: {[o.name for o in sess.get_outputs()]}")
print(f"    Sample output shapes: {[o.shape for o in out]}")

# Sanity check with known URLs
try:
    from features import extract_features
    phish_feats = np.array([extract_features("http://paypal-secure.account-verify.xyz/signin")], dtype=np.float32)
    legit_feats = np.array([extract_features("https://www.google.com")], dtype=np.float32)
    p_phish = sess.run(None, {"input": phish_feats})[1][0][1]
    p_legit = sess.run(None, {"input": legit_feats})[1][0][1]
    print(f"\n  Sanity check:")
    print(f"    paypal-secure.account-verify.xyz → P(phish)={p_phish:.3f}  {'✓' if p_phish > 0.5 else '✗'}")
    print(f"    www.google.com                   → P(phish)={p_legit:.3f}  {'✓' if p_legit < 0.3 else '✗'}")
except Exception as e:
    print(f"  [WARN] Sanity check skipped: {e}")
