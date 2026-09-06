"""ML second-layer: feature extraction discriminates, and the classifier trains
and beats a pure-rate baseline. Fast + deterministic — no subprocess episodes."""
import os, sys, tempfile, shutil

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(SRC, "tools"))
import ml_features as F
import train_classifier as T

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp = tempfile.mkdtemp(prefix="hss_ml_")
try:
    # ── Feature extraction discriminates encryption from documents ─────────
    ransom = []
    for i in range(8):
        p = os.path.join(tmp, f"doc_{i}.txt.enc")
        open(p, "wb").write(os.urandom(4096))            # ciphertext-like
        ransom.append(p)
    fr = F.extract_features(ransom, duration_s=0.1)
    check(f"ciphertext -> high median entropy ({fr['median_entropy']:.2f})", fr["median_entropy"] > 7.5)
    check("ciphertext -> frac_high_ent == 1", fr["frac_high_ent"] == 1.0)
    check(f"ransom extension detected ({fr['frac_ransom_ext']:.2f})", fr["frac_ransom_ext"] > 0.5)
    check("fast burst -> high rate", fr["rate"] > 50)

    docs = []
    for i in range(8):
        p = os.path.join(tmp, f"report_{i}.txt")
        open(p, "w").write("The quick brown fox jumps over the lazy dog. " * 80)
        docs.append(p)
    fd = F.extract_features(docs, duration_s=5.0)
    check(f"documents -> low median entropy ({fd['median_entropy']:.2f})", fd["median_entropy"] < 5.0)
    check("documents -> no ransom extension", fd["frac_ransom_ext"] == 0.0)

    check("feature_row length matches FEATURE_NAMES",
          len(F.feature_row(docs, 1.0)) == len(F.FEATURE_NAMES))

    # ── Classifier trains, cross-validates, beats pure rate, round-trips ───
    import numpy as np
    rng = np.random.default_rng(0)
    rows, labels = [], []
    for _ in range(30):   # fast ransomware: high entropy, high rate
        ent = rng.uniform(7.6, 8.0)
        rows.append([rng.uniform(80, 600), rng.integers(20, 60), ent, ent,
                     1.0, 0.0, rng.integers(2, 5), rng.uniform(0.5, 1.0), 1.0])
        labels.append(1)
    for _ in range(10):   # SLOW ransomware: low rate (overlaps benign) but ransom ext
        ent = rng.uniform(7.6, 8.0)                        # -> rate alone cannot catch these
        rows.append([rng.uniform(3, 40), rng.integers(20, 60), ent, ent,
                     1.0, 0.0, rng.integers(2, 5), rng.uniform(0.5, 1.0), 1.0])
        labels.append(1)
    for _ in range(20):   # benign low-entropy (docs/extract), low rate
        ent = rng.uniform(3.2, 4.8)
        rows.append([rng.uniform(2, 40), rng.integers(4, 40), ent, ent,
                     0.0, 1.0, rng.integers(1, 3), 0.0, 1.0])
        labels.append(0)
    for _ in range(20):   # benign HIGH-entropy media, low rate (the hard case)
        ent = rng.uniform(7.6, 8.0)
        rows.append([rng.uniform(2, 40), rng.integers(20, 120), ent, ent,
                     1.0, 0.0, 1, 0.0, 1.0])
        labels.append(0)
    X = np.array(rows, dtype=float); y = np.array(labels)

    model_path = os.path.join(tmp, "m.joblib")
    res = T.train_and_eval(X, y, out_model=model_path, seed=0)
    check(f"RF cross-val accuracy is strong ({res['cv_accuracy']:.3f})", res["cv_accuracy"] >= 0.85)
    check(f"ML beats pure-rate baseline ({res['cv_accuracy']:.3f} > {res['rate_baseline']:.3f})",
          res["cv_accuracy"] > res["rate_baseline"])
    check("model file was saved", os.path.exists(model_path))

    import joblib
    loaded = joblib.load(model_path)
    check("saved model round-trips with feature names",
          loaded["features"] == F.FEATURE_NAMES and hasattr(loaded["model"], "predict"))

    print("\nALL ML CHECKS PASSED")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
