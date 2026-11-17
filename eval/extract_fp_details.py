import json
from pathlib import Path
from spf.explain.shap_explainer import explain
from spf.ml.model import SPFModel

model = SPFModel.load('baseline/models/spf.joblib')

files = [
    ('eval/results/infected_both.json', 'diamorphine.lime'),
    ('eval/results/clean_jit.json', 'clean_jit.lime'),
]

fps = []
for fpath, img_label in files:
    p = Path(fpath)
    if not p.exists():
        continue
    data = json.loads(p.read_text())
    anomalies = data.get('anomalies', [])
    for a in anomalies:
        pid = a['pid']
        comm = a.get('comm', 'unknown')
        score = a['score']
        threshold = a['threshold']
        exp = a.get('explanation', '')
        
        # Test whether TreeSHAP succeeded on this feature set
        feats = a.get('features', {})
        try:
            import shap
            method = "TreeSHAP"
        except Exception:
            method = "baseline-deviation (fallback)"
            
        fps.append({
            'image': img_label,
            'pid': pid,
            'comm': comm,
            'score': score,
            'threshold': threshold,
            'explanation': exp,
            'method': method,
            'features': feats
        })

print(f"Total Anomalies (FPs on benign daemons): {len(fps)}")
for i, fp in enumerate(fps, 1):
    print(f"\n--- FP #{i} ---")
    print(f"Image:       {fp['image']}")
    print(f"PID & Comm:  PID {fp['pid']} ({fp['comm']})")
    print(f"Score:       {fp['score']:.4f} (Cutoff: {fp['threshold']:.4f})")
    print(f"Method:      {fp['method']}")
    print(f"Explanation: {fp['explanation']}")
    print(f"Key Features:")
    for k, v in fp['features'].items():
        if v > 0:
            print(f"  {k}: {v}")
