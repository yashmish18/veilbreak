from features import extract_features
import traceback
try:
    feats = extract_features('http://paypal.com')
    print(f"Success: {len(feats)} features")
except Exception as e:
    traceback.print_exc()
