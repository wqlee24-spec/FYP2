"""Generate publication-quality figures for the FYP2 report (Chapter 6).

Reads the evaluation CSVs produced by the test harnesses and writes clean PNGs
into report_figures/. Run the harnesses first (ideally elevated + full reps):

    python tests/benchmark.py --reps 30        -> tests/benchmark_results.csv
    python tests/validate_behaviour.py --reps 3 -> tests/validation_results.csv
    python tests/sensitivity.py                -> tests/sensitivity_results.csv
    python tools/build_dataset.py              -> tools/ml_dataset.csv
    python tools/make_figures.py               -> report_figures/*.png

Each figure is captioned in FYP2_REPORT_SUPPORT.md with where it belongs.
"""

import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")                      # headless PNG
import matplotlib.pyplot as plt

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(SRC, "report_figures")
os.makedirs(OUT, exist_ok=True)

# ── consistent, print-friendly style ─────────────────────────────────────────
plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white",
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linestyle": "--",
    "axes.spines.top": False, "axes.spines.right": False,
})
C_BENIGN = "#2c7fb8"; C_RANSOM = "#d7301f"; C_ACCENT = "#1b9e77"
C_HEUR = "#7570b3";   C_ETW = "#1b9e77";     C_WARN = "#e6820e"


def _read(path):
    if not os.path.exists(path):
        print(f"  (skip — not found: {os.path.relpath(path, SRC)})")
        return None
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _save(fig, name):
    p = os.path.join(OUT, name)
    fig.savefig(p, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {os.path.relpath(p, SRC)}")


# ── 1. Entropy-threshold sensitivity (the key evaluation figure) ─────────────
def fig_sensitivity():
    rows = _read(os.path.join(SRC, "tests", "sensitivity_results.csv"))
    if not rows:
        return
    t   = [float(r["threshold"]) for r in rows]
    fpr = [float(r["fp_rate"]) * 100 for r in rows]
    fnr = [float(r["fn_rate"]) * 100 for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.3))
    ax.plot(t, fpr, "-o", color=C_WARN, label="False-positive rate (benign flagged)")
    ax.plot(t, fnr, "-s", color=C_RANSOM, label="False-negative rate (attack missed)")
    # shade the FN==0 safe band
    zero = [tt for tt, f in zip(t, fnr) if f == 0]
    if zero:
        ax.axvspan(min(zero), max(zero), color=C_ACCENT, alpha=0.10,
                   label="No attack missed (FN=0)")
    ax.axvline(6.5, color="black", ls=":", lw=1.5)
    ax.text(6.5, 100, "default 6.5", va="top", ha="center", fontsize=10,
            bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="0.6", alpha=0.9))
    ax.set_xlabel("Entropy gate threshold (bits/byte)")
    ax.set_ylabel("Error rate (%)")
    ax.set_title("Detection error vs entropy threshold")
    ax.legend(loc="center right", fontsize=9)
    ax.set_ylim(-3, 103)
    _save(fig, "fig_sensitivity.png")


# ── 2. Behaviour validation — confusion matrix ───────────────────────────────
def fig_validation():
    rows = _read(os.path.join(SRC, "tests", "validation_results.csv"))
    if not rows:
        return
    tp = sum(r["result"] == "TP" for r in rows)
    tn = sum(r["result"] == "TN" for r in rows)
    fp = sum(r["result"] == "FP" for r in rows)
    fn = sum(r["result"] == "FN" for r in rows)
    mat = [[tp, fn], [fp, tn]]                 # rows: actual ransomware/benign
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    ax.imshow(mat, cmap="Blues", vmin=0, vmax=max(1, max(tp, tn, fp, fn)))
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Predicted\nransomware", "Predicted\nbenign"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Actual\nransomware", "Actual\nbenign"])
    labels = [["TP", "FN"], ["FP", "TN"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{labels[i][j]}\n{mat[i][j]}", ha="center", va="center",
                    fontsize=14, fontweight="bold",
                    color="white" if mat[i][j] > max(tp, tn, fp, fn) / 2 else "black")
    ax.set_title(f"Behaviour validation  (TP={tp} TN={tn} FP={fp} FN={fn})")
    ax.grid(False)
    _save(fig, "fig_validation_confusion.png")


# ── 3. Benchmark — detection latency vs load ─────────────────────────────────
def fig_benchmark_latency():
    rows = _read(os.path.join(SRC, "tests", "benchmark_results.csv"))
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7, 4.3))
    for cond, color, marker in (("heur", C_HEUR, "o"), ("etw", C_ETW, "s")):
        d = sorted([r for r in rows if r["condition"] == cond],
                   key=lambda r: float(r["target_rate_ops_s"]))
        if not d:
            continue
        x = [float(r["target_rate_ops_s"]) for r in d]
        p50 = [float(r["lat_p50_ms"]) for r in d]
        p95 = [float(r["lat_p95_ms"]) for r in d]
        ax.plot(x, p50, "-" + marker, color=color, label=f"{cond.upper()} p50")
        ax.plot(x, p95, "--" + marker, color=color, alpha=0.5, label=f"{cond.upper()} p95")
    ax.set_xlabel("File-operation rate (ops/sec)")
    ax.set_ylabel("Detection latency (ms)")
    ax.set_title("Detection latency vs load")
    ax.legend(fontsize=9)
    _save(fig, "fig_benchmark_latency.png")


# ── 4. Benchmark — agent CPU vs load ─────────────────────────────────────────
def fig_benchmark_cpu():
    rows = _read(os.path.join(SRC, "tests", "benchmark_results.csv"))
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(7, 4.3))
    for cond, color in (("heur", C_HEUR), ("etw", C_ETW)):
        d = sorted([r for r in rows if r["condition"] == cond],
                   key=lambda r: float(r["target_rate_ops_s"]))
        if not d:
            continue
        x = [float(r["target_rate_ops_s"]) for r in d]
        cpu = [float(r["agent_cpu_mean_pct"]) for r in d]
        ax.plot(x, cpu, "-o", color=color, label=f"{cond.upper()} agent CPU")
    ax.set_xlabel("File-operation rate (ops/sec)")
    ax.set_ylabel("Agent CPU (% of one core, normalised)")
    ax.set_title("Monitoring-agent CPU overhead vs load")
    ax.legend(fontsize=9)
    _save(fig, "fig_benchmark_cpu.png")


# ── 5. Performance bug fix — before/after (documented one-off measurement) ────
def fig_perf_fix():
    metrics = ["Latency p50\n(ms)", "Agent CPU\n(%)", "Event loss\n(%)"]
    before = [1240, 8.1, 5.0]
    after  = [17, 0.5, 0.0]
    import numpy as np
    x = np.arange(len(metrics)); w = 0.36
    fig, ax = plt.subplots(figsize=(7, 4.3))
    b1 = ax.bar(x - w/2, before, w, color=C_RANSOM, label="Uncached (FYP1)")
    b2 = ax.bar(x + w/2, after,  w, color=C_ACCENT, label="Cached (FYP2)")
    ax.set_yscale("symlog")
    ax.set_xticks(x); ax.set_xticklabels(metrics)
    ax.set_ylabel("value (log scale)")
    ax.set_title("Effect of caching GetLikelyPid (200 ops/s)")
    ax.legend()
    for bars in (b1, b2):
        for r in bars:
            ax.text(r.get_x() + r.get_width()/2, r.get_height(),
                    f"{r.get_height():g}", ha="center", va="bottom", fontsize=9)
    _save(fig, "fig_perf_fix.png")


# ── 6. ML — feature importance + accuracy vs pure-rate ───────────────────────
def fig_ml():
    path = os.path.join(SRC, "tools", "ml_dataset.csv")
    rows = _read(path)
    if not rows:
        return
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_predict, StratifiedKFold
        from sklearn.metrics import accuracy_score
    except ImportError:
        print("  (skip ML figures — scikit-learn not available)")
        return
    sys.path.insert(0, os.path.join(SRC, "tools"))
    import ml_features as F
    X = np.array([[float(r[k]) for k in F.FEATURE_NAMES] for r in rows])
    y = np.array([int(r["label"]) for r in rows])

    # feature importance
    rf = RandomForestClassifier(n_estimators=200, random_state=1, class_weight="balanced")
    rf.fit(X, y)
    order = np.argsort(rf.feature_importances_)
    fig, ax = plt.subplots(figsize=(7, 4.3))
    ax.barh([F.FEATURE_NAMES[i] for i in order],
            [rf.feature_importances_[i] for i in order], color=C_ACCENT)
    ax.set_xlabel("Importance"); ax.set_title("Random Forest feature importance")
    _save(fig, "fig_ml_importance.png")

    # accuracy: ML vs best pure-rate threshold
    cv = StratifiedKFold(n_splits=min(5, int(np.bincount(y).min())), shuffle=True, random_state=1)
    ml_acc = accuracy_score(y, cross_val_predict(rf, X, y, cv=cv))
    ridx = F.FEATURE_NAMES.index("rate")
    best = max(accuracy_score(y, (X[:, ridx] >= t).astype(int)) for t in sorted(set(X[:, ridx])))
    fig, ax = plt.subplots(figsize=(5, 4.3))
    bars = ax.bar(["Pure-rate\nthreshold", "Random Forest\n(9 features)"],
                  [best * 100, ml_acc * 100], color=[C_HEUR, C_ACCENT])
    ax.set_ylabel("Accuracy (%)"); ax.set_ylim(0, 105)
    ax.set_title("Classifier vs rule-only baseline")
    for r in bars:
        ax.text(r.get_x() + r.get_width()/2, r.get_height() + 1,
                f"{r.get_height():.1f}%", ha="center", fontsize=11, fontweight="bold")
    _save(fig, "fig_ml_vs_rate.png")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(f"Writing figures to {os.path.relpath(OUT, SRC)}/ ...")
    for fn in (fig_sensitivity, fig_validation, fig_benchmark_latency,
               fig_benchmark_cpu, fig_perf_fix, fig_ml):
        try:
            fn()
        except Exception as e:
            print(f"  (error in {fn.__name__}: {e})")
    print("Done.")


if __name__ == "__main__":
    raise SystemExit(main())
