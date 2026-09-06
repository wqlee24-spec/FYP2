"""Entropy second-layer detection: the gate must reduce false positives WITHOUT
introducing false negatives."""
import os, sys, tempfile, shutil, math

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SRC)
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp = tempfile.mkdtemp(prefix="hss_ent_")

# ── file_entropy() sanity ──────────────────────────────────────────────────
low = os.path.join(tmp, "low.txt")
open(low, "wb").write(b"AAAAAAAA" * 1024)                    # single byte -> 0 entropy
mid = os.path.join(tmp, "mid.txt")
open(mid, "wb").write(("The quick brown fox. " * 300).encode())   # text
high = os.path.join(tmp, "high.bin")
open(high, "wb").write(os.urandom(8192))                     # random -> ~8

e_low, e_mid, e_high = m.file_entropy(low), m.file_entropy(mid), m.file_entropy(high)
check(f"constant bytes ~0 entropy (got {e_low:.2f})", e_low < 0.1)
check(f"text is mid entropy (got {e_mid:.2f})", 3.0 < e_mid < 5.5)
check(f"random ~8 entropy (got {e_high:.2f})", e_high > 7.5)
check("missing file -> None", m.file_entropy(os.path.join(tmp, "nope")) is None)

# ── Detector gate: build a helper that fires k events for one PID ───────────
def fresh(entropy_thresh):
    db = m.Database(os.path.join(tempfile.mkdtemp(), "e.db"))
    cfg = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=100.0,
                            entropy_thresh=entropy_thresh)   # wide window: rate always crosses
    det = m.RansomwareDetector(db, cfg, m.MonitoringState(True), lambda p, f: "STUB")
    return db, det

def make_files(kind, n, tag):
    paths = []
    for i in range(n):
        p = os.path.join(tmp, f"{tag}_{i}.dat")
        if kind == "high":
            open(p, "wb").write(os.urandom(4096))
        elif kind == "low":
            open(p, "wb").write(b"Z" * 4096)
        paths.append(p)
    return paths

# HIGH-entropy burst (ransomware-like) with gate ON -> must ALERT
db, det = fresh(6.5)
for p in make_files("high", 6, "ransom"):
    det.record(p, 1001, "ETW")
check(f"high-entropy burst fires (alerts={len(db.get_alerts(9))})", len(db.get_alerts(9)) == 1)
check("alert stored the entropy value", db.get_alerts(1)[0][10] is not None and db.get_alerts(1)[0][10] > 7.0)

# LOW-entropy burst (fast extraction) with gate ON -> must be SUPPRESSED
db, det = fresh(6.5)
for p in make_files("low", 6, "extract"):
    det.record(p, 1002, "HEUR")
check(f"low-entropy burst suppressed by gate (alerts={len(db.get_alerts(9))})",
      len(db.get_alerts(9)) == 0)

# Same LOW burst with gate DISABLED (entropy_thresh=0) -> rate-only, must ALERT
db, det = fresh(0.0)
for p in make_files("low", 6, "extract2"):
    det.record(p, 1003, "HEUR")
check(f"gate disabled -> pure rate still alerts (alerts={len(db.get_alerts(9))})",
      len(db.get_alerts(9)) == 1)

# UNKNOWN entropy (files deleted before read) must NOT be suppressed -> ALERT
db, det = fresh(6.5)
ghost = make_files("high", 6, "ghost")
for p in ghost:
    os.remove(p)                     # unreadable at decision time
for p in ghost:
    det.record(p, 1004, "ETW")
check(f"unreadable files -> not suppressed, still alerts (alerts={len(db.get_alerts(9))})",
      len(db.get_alerts(9)) == 1)

# Fewer than MIN_ENT_SAMPLES readable -> must NOT suppress even if those are low
db, det = fresh(6.5)
few = make_files("low", 6, "few")
for p in few[2:]:                    # delete all but 2 -> only 2 readable
    pass
for p in few[:4]:
    os.remove(p)                     # leave only 2 readable low-entropy files
for p in few:
    det.record(p, 1005, "HEUR")
check(f"<MIN_ENT_SAMPLES readable -> conservative, alerts (alerts={len(db.get_alerts(9))})",
      len(db.get_alerts(9)) == 1)

# Suppressed PID can still fire LATER if it turns high-entropy (no _alerted lock-in).
# The later burst must fill the event window (>= event_cap) so the window holds
# only high-entropy files — mirroring the real 0.01s window rolling old events out.
db, det = fresh(6.5)
for p in make_files("low", 6, "mix"):
    det.record(p, 1006, "HEUR")
check("still suppressed after low burst", len(db.get_alerts(9)) == 0)
for p in make_files("high", 12, "mix_high"):   # > event_cap(10): window becomes all-high
    det.record(p, 1006, "HEUR")     # same PID, now high entropy
check(f"same PID fires once entropy rises (alerts={len(db.get_alerts(9))})",
      len(db.get_alerts(9)) == 1)

shutil.rmtree(tmp, ignore_errors=True)
print("\nALL ENTROPY CHECKS PASSED")
