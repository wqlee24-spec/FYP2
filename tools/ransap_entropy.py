"""Validate the detection approach against the REAL RanSAP dataset.

RanSAP (Hirano et al., 2022) records real ransomware and benign storage access
patterns. Per execution there are two CSVs:

    ata_write.csv : time_s, time_ns, LBA, size, Entropy#1, Entropy#2
    ata_read.csv  : time_s, time_ns, LBA, size

`Entropy#1` is the Shannon entropy of each 4096-byte written block — the same
signal our detector's entropy gate uses.

This script does TWO things, both on real data, for Chapter 6:

  1. ENTROPY VALIDATION — extracts per-execution median write-entropy for
     ransomware vs benign and checks how well our threshold separates them.
     -> report_figures/fig_ransap_entropy.png

  2. ML EVALUATION — builds an 11-feature vector per execution (read/write mix,
     entropy stats, write rate, block spread, bytes) and cross-validates a
     Random Forest, comparing it to an entropy-threshold-only baseline.
     -> report_figures/fig_ransap_ml.png   (needs scikit-learn)

Download RanSAP:  https://github.com/manabu-hirano/RanSAP
                  (Kaggle: hiranomanabu/ransap-2022-ransomware-behavioral-features)

Run, pointing the globs at each class's ata_write.csv files, e.g.:

    python tools/ransap_entropy.py \
        --ransomware "RanSAP/original/**/*ransom*/**/ata_write.csv" \
        --benign     "RanSAP/original/**/*benign*/**/ata_write.csv"

(Every ata_write.csv under a ransomware path is one class, benign the other; the
sibling ata_read.csv in the same folder is used automatically when present.)

SCALE: our detector uses bits/byte (0-8, gate 6.5). Some RanSAP builds normalise
Entropy#1 to 0-1; the script auto-detects and rescales the threshold, and prints
which scale it saw. (The ML features are scale-agnostic.)
"""

import argparse
import csv
import glob
import os
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(SRC, "report_figures")

FEATURE_NAMES = [
    "n_writes", "n_reads", "write_read_ratio",
    "ent_mean", "ent_median", "ent_max", "ent_std",
    "write_rate", "mean_write_size", "unique_write_lba", "total_bytes_written",
]


def _rows(path):
    """Yield parsed float rows from a CSV, skipping headers/malformed lines."""
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) < 4:
                    continue
                try:
                    yield [float(x) for x in row]
                except ValueError:
                    continue          # header / non-numeric row
    except OSError:
        return


def _features(write_csv):
    """Build one feature vector for the execution owning *write_csv*.
    Returns (feature_dict, median_entropy) or (None, None) if it has no writes."""
    w_time, w_lba, w_size, w_ent = [], [], [], []
    for r in _rows(write_csv):
        t = r[0] + (r[1] / 1e9 if len(r) > 1 else 0.0)
        w_time.append(t)
        w_lba.append(r[2])
        w_size.append(r[3])
        if len(r) > 4:
            w_ent.append(r[4])
    if not w_ent:
        return None, None

    read_csv = os.path.join(os.path.dirname(write_csv), "ata_read.csv")
    n_reads = sum(1 for _ in _rows(read_csv)) if os.path.exists(read_csv) else 0

    n_writes = len(w_ent)
    dur = (max(w_time) - min(w_time)) if len(w_time) > 1 else 0.0
    total_bytes = sum(w_size)
    med = statistics.median(w_ent)
    feat = {
        "n_writes":            float(n_writes),
        "n_reads":             float(n_reads),
        "write_read_ratio":    n_writes / (n_reads + 1.0),
        "ent_mean":            statistics.mean(w_ent),
        "ent_median":          med,
        "ent_max":             max(w_ent),
        "ent_std":             statistics.pstdev(w_ent) if n_writes > 1 else 0.0,
        "write_rate":          (n_writes / dur) if dur > 0 else float(n_writes),
        "mean_write_size":     total_bytes / n_writes,
        "unique_write_lba":    float(len(set(w_lba))),
        "total_bytes_written": total_bytes,
    }
    return feat, med


def _collect(patterns):
    """Return (list_of_feature_dicts, list_of_median_entropy, n_files_matched)."""
    feats, medians = [], []
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat, recursive=True))
    for f in files:
        feat, med = _features(f)
        if feat is not None:
            feats.append(feat)
            medians.append(med)
    return feats, medians, len(files)


def _entropy_figure(r_med, b_med, thr, scale):
    os.makedirs(OUT, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 4.3))
    ax.hist(b_med, bins=30, alpha=0.65, color="#2c7fb8", label=f"Benign (n={len(b_med)})")
    ax.hist(r_med, bins=30, alpha=0.65, color="#d7301f", label=f"Ransomware (n={len(r_med)})")
    ax.axvline(thr, color="black", ls=":", lw=1.6)
    ax.text(thr, ax.get_ylim()[1] * 0.92, f" threshold {thr:.2f}", fontsize=10, va="top")
    ax.set_xlabel(f"Per-execution median write-entropy [{scale}]")
    ax.set_ylabel("Number of executions")
    ax.set_title("RanSAP: real ransomware vs benign write-entropy")
    ax.legend(); ax.grid(True, alpha=0.3, ls="--")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    p = os.path.join(OUT, "fig_ransap_entropy.png")
    fig.savefig(p, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"  wrote {os.path.relpath(p, SRC)}")


def _ml_eval(r_feats, b_feats):
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_predict, StratifiedKFold
        from sklearn.metrics import accuracy_score
    except ImportError:
        print("\n  (skip ML eval — scikit-learn not installed: pip install scikit-learn)")
        return

    X = np.array([[f[k] for k in FEATURE_NAMES] for f in (r_feats + b_feats)], dtype=float)
    y = np.array([1] * len(r_feats) + [0] * len(b_feats))
    if min(np.bincount(y)) < 2:
        print("\n  (skip ML eval — need >=2 executions per class)")
        return

    rf = RandomForestClassifier(n_estimators=300, random_state=1, class_weight="balanced")
    k = min(5, int(np.bincount(y).min()))
    cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=1)
    ml_acc = accuracy_score(y, cross_val_predict(rf, X, y, cv=cv))

    # entropy-threshold-only baseline (best split on ent_median)
    ent = X[:, FEATURE_NAMES.index("ent_median")]
    best = max(accuracy_score(y, (ent >= t).astype(int)) for t in sorted(set(ent)))

    rf.fit(X, y)
    order = np.argsort(rf.feature_importances_)

    print(f"\n  ML on REAL data ({len(r_feats)} ransomware + {len(b_feats)} benign executions):")
    print(f"    Random Forest (11 features), {k}-fold CV accuracy : {ml_acc*100:.1f}%")
    print(f"    Entropy-threshold-only baseline accuracy          : {best*100:.1f}%")

    os.makedirs(OUT, exist_ok=True)
    # feature importance
    fig, ax = plt.subplots(figsize=(7, 4.3))
    ax.barh([FEATURE_NAMES[i] for i in order],
            [rf.feature_importances_[i] for i in order], color="#1b9e77")
    ax.set_xlabel("Importance")
    ax.set_title("RanSAP Random Forest — feature importance (real data)")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    p1 = os.path.join(OUT, "fig_ransap_ml.png")
    fig.savefig(p1, dpi=150, bbox_inches="tight"); plt.close(fig)

    # accuracy comparison
    fig, ax = plt.subplots(figsize=(5, 4.3))
    bars = ax.bar(["Entropy\nthreshold", "Random Forest\n(11 features)"],
                  [best * 100, ml_acc * 100], color=["#7570b3", "#1b9e77"])
    ax.set_ylabel("Accuracy (%)"); ax.set_ylim(0, 105)
    ax.set_title("RanSAP: classifier vs entropy-only (real data)")
    for r in bars:
        ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 1,
                f"{r.get_height():.1f}%", ha="center", fontsize=11, fontweight="bold")
    p2 = os.path.join(OUT, "fig_ransap_ml_vs_entropy.png")
    fig.savefig(p2, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"    wrote {os.path.relpath(p1, SRC)} and {os.path.relpath(p2, SRC)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ransomware", nargs="+", required=True,
                    help="glob(s) matching ata_write.csv under ransomware runs")
    ap.add_argument("--benign", nargs="+", required=True,
                    help="glob(s) matching ata_write.csv under benign runs")
    ap.add_argument("--threshold", type=float, default=6.5,
                    help="entropy gate threshold in bits/byte (default 6.5)")
    args = ap.parse_args()

    r_feats, r_med, r_files = _collect(args.ransomware)
    b_feats, b_med, b_files = _collect(args.benign)

    if not r_med or not b_med:
        print("No executions read. Check your --ransomware / --benign globs.")
        print(f"  ransomware files matched: {r_files}, benign files matched: {b_files}")
        return 1

    # Detect entropy scale (0-8 vs normalised 0-1) and align the threshold.
    hi = max(max(r_med), max(b_med))
    thr, scale = args.threshold, "bits/byte (0-8)"
    if hi <= 1.0:
        thr, scale = args.threshold / 8.0, "normalised (0-1)"

    print(f"\nRanSAP write-entropy — scale detected: {scale}, threshold={thr:.3f}")
    print(f"  ransomware: {len(r_med)} executions, median-of-medians={statistics.median(r_med):.3f}")
    print(f"  benign    : {len(b_med)} executions, median-of-medians={statistics.median(b_med):.3f}")

    tp = sum(1 for m in r_med if m >= thr); fn = len(r_med) - tp
    tn = sum(1 for m in b_med if m < thr);  fp = len(b_med) - tn
    acc = (tp + tn) / (len(r_med) + len(b_med))
    print(f"  entropy-threshold separation: {acc*100:.1f}%  (TP={tp} FN={fn} TN={tn} FP={fp})")

    _entropy_figure(r_med, b_med, thr, scale)
    _ml_eval(r_feats, b_feats)
    print("\n  Use fig_ransap_entropy.png and fig_ransap_ml*.png as REAL-WORLD"
          " validation in Chapter 6.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
