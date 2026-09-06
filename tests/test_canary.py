"""Canary (decoy) file detection: instant trip on tamper, never on our own
creation, and independent of the rate/entropy thresholds."""
import os, sys, tempfile, shutil

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SRC)
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp = tempfile.mkdtemp(prefix="hss_canary_")
try:
    # ── Deploy ─────────────────────────────────────────────────────────────
    can = m.CanaryManager()
    n = can.deploy(tmp)
    check(f"deployed canaries ({n})", n == m.CanaryManager._COUNT)
    canaries = [os.path.join(tmp, f) for f in os.listdir(tmp)
                if f.startswith(m.CanaryManager.PREFIX)]
    check("canary files exist on disk", len(canaries) == n)
    check("is_canary recognises a deployed path", can.is_canary(canaries[0]))
    check("is_canary rejects a normal path", not can.is_canary(os.path.join(tmp, "report.txt")))

    # ── Freshly-created canary is NOT tripped (no false alarm on our writes) ─
    check("untouched canary is not tripped", not can.is_tripped(canaries[0]))

    # ── Tamper cases trip ──────────────────────────────────────────────────
    # (a) content encrypted/overwritten
    with open(canaries[0], "r+b") as fh:      # in-place, like real ransomware (works on hidden)
        fh.seek(0); fh.write(os.urandom(2048)); fh.truncate()
    check("modified canary IS tripped", can.is_tripped(canaries[0]))
    # (b) deleted / renamed away
    os.remove(canaries[1])
    check("deleted canary IS tripped", can.is_tripped(canaries[1]))
    # (c) partial write (creation race) is NOT tripped
    with open(canaries[2], "r+b") as fh:
        fh.seek(0); fh.write(b"HSS"); fh.truncate()   # shorter than the marker
    check("partially-written canary is not tripped (creation race guard)",
          not can.is_tripped(canaries[2]))

    # ── Redeploy to a new folder cleans up the old one ─────────────────────
    tmp2 = tempfile.mkdtemp(prefix="hss_canary2_")
    can.deploy(tmp2)
    old_left = [f for f in os.listdir(tmp) if f.startswith(m.CanaryManager.PREFIX)]
    check("old-folder canaries removed on redeploy", len(old_left) == 0)
    check("new-folder canaries present",
          len([f for f in os.listdir(tmp2) if f.startswith(m.CanaryManager.PREFIX)]) == n)
    shutil.rmtree(tmp2, ignore_errors=True)

    # ── Detector fires INSTANTLY on a single canary touch (rate-independent) ─
    can2 = m.CanaryManager()
    can2.deploy(tmp)
    db = m.Database(os.path.join(tmp, "c.db"))
    # k=5 so a single event would NOT cross the rate threshold — proving the
    # canary path is independent of rate.
    cfg = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=0.01)
    contained = []
    det = m.RansomwareDetector(db, cfg, m.MonitoringState(True),
                               lambda pid, files: contained.append(files) or "C:\\w",
                               canary=can2)
    cpath = [os.path.join(tmp, f) for f in os.listdir(tmp)
             if f.startswith(m.CanaryManager.PREFIX)][0]

    # touching an UNTAMPERED canary must not alert (our own creation events)
    det.record(cpath, 4242, "ETW")
    check("untampered canary event does not alert", len(db.get_alerts(9)) == 0)

    # now encrypt it and touch once -> instant alert on ONE event
    with open(cpath, "r+b") as fh:
        fh.seek(0); fh.write(os.urandom(2048)); fh.truncate()
    det.record(cpath, 4242, "ETW")
    rows = db.get_alerts(9)
    check(f"single tampered-canary event fires instantly (alerts={len(rows)})", len(rows) == 1)
    check("alert marked as a CANARY trip", "[CANARY]" in (rows[0][4] or ""))
    check("containment ran on the canary trip", len(contained) == 1)
    check("alert recorded high entropy (encrypted decoy)",
          rows[0][10] is not None and rows[0][10] > 7.0)

    print("\nALL CANARY CHECKS PASSED")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
