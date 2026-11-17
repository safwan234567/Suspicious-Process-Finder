import joblib
import numpy as np
from spf.explain.shap_explainer import explain
from spf.ml.features import FEATURE_NAMES

model = joblib.load('baseline/models/spf.joblib')
print("Model threshold:", model.threshold)
print("Model feature names:", FEATURE_NAMES)

# Let's test clean_jit feature dict:
clean_jit_features = {
    "vma_count": 18.0,
    "anon_to_file_ratio": 0.67,
    "unbacked_exec_count": 1.0,
    "unbacked_exec_bytes": 1048576.0,
    "fd_count": 3.0,
    "socket_count": 0.0,
    "uid_differs_from_parent": 0.0,
    "runs_from_tmp_or_shm": 0.0,
    "has_ld_preload": 0.0
}

score = model.score([clean_jit_features])[0]
print(f"clean_jit Isolation Forest Anomaly Score: {score:.4f} (Threshold: {model.threshold:.4f})")

contributions, explanation = explain(model, clean_jit_features, top_k=3)
print("\nTreeSHAP Contributions for clean_jit:")
for f in FEATURE_NAMES:
    print(f"  {f:25s}: value={clean_jit_features[f]:<12.2f} shap_contrib={contributions[f]:+.6f}")

print(f"\nGenerated Plain Language Explanation:\n{explanation}")

# Now let's test a scenario where unbacked_exec_* triggers explanation:
# If unbacked_exec_count has non-zero contribution or if baseline deviation fallback is used:
print("\n--- Feature Split Distribution in Current Model Forest ---")
splits_by_feature = {i: 0 for i in range(len(FEATURE_NAMES))}
for tree in model.forest.estimators_:
    for feat_idx in tree.tree_.feature:
        if feat_idx >= 0:
            splits_by_feature[feat_idx] += 1

for idx, count in splits_by_feature.items():
    print(f"  Feature {idx} ({FEATURE_NAMES[idx]:25s}): {count} splits")
