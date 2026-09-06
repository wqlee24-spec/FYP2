import sys, os, time, tempfile, shutil, json

sys.path.insert(0, r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode")
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp_dir = tempfile.mkdtemp(prefix="hss_det_")
db = m.Database(os.path.join(tmp_dir, "det.db"))
config = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=0.5, entropy_thresh=0)  # pure-rate: isolate rate logic
state = m.MonitoringState(active=True)

captured = {}
def fake_lockdown(pid, files):
    captured["pid"] = pid
    captured["files"] = list(files)
    return "C:\\fake\\locked\\dir"

det = m.RansomwareDetector(db, config, state, fake_lockdown)

# ── Below threshold: no alert ──────────────────────────────────────────────
for i in range(4):
    det.record(f"C:\\watched\\f{i}.txt", 4242)
check("no alert below threshold (4 < 5)", len(db.get_alerts(10)) == 0)

# ── Crossing threshold fires exactly one alert ─────────────────────────────
det.record("C:\\watched\\f4.txt", 4242)
rows = db.get_alerts(10)
check("alert fired at threshold", len(rows) == 1)

row = rows[0]
check("alert_type is RANSOMWARE", row[2] == "RANSOMWARE")
check("status is BLOCKED when lockdown succeeded", row[5] == "BLOCKED")
check("locked_dir persisted from on_alert return", row[7] == "C:\\fake\\locked\\dir")
check("lock_active is 1", row[8] == 1)
files = json.loads(row[6])
check(f"full file list persisted ({len(files)} files)", len(files) == 5)
check("containment ran with the full file list", len(captured["files"]) == 5)
check("containment received correct pid", captured["pid"] == 4242)

# ── Same PID does not re-alert ─────────────────────────────────────────────
for i in range(10):
    det.record(f"C:\\watched\\extra{i}.txt", 4242)
check("same PID does not re-alert in same session", len(db.get_alerts(10)) == 1)

# ── Failed lockdown records LOCK FAILED + NULL locked_dir ──────────────────
det2 = m.RansomwareDetector(db, config, state, lambda pid, files: None)
for i in range(5):
    det2.record(f"C:\\watched\\g{i}.txt", 777)
rows = db.get_alerts(10)
newest = rows[0]
check("second alert logged", len(rows) == 2)
check("status is LOCK FAILED when containment returns None", newest[5] == "LOCK FAILED")
check("locked_dir is NULL when containment failed", newest[7] is None)
check("lock_active is 0 when containment failed", newest[8] == 0)

# ── Paused monitoring suppresses detection ─────────────────────────────────
state.set(False)
det3 = m.RansomwareDetector(db, config, state, fake_lockdown)
for i in range(10):
    det3.record(f"C:\\watched\\paused{i}.txt", 555)
check("no new alert while monitoring paused", len(db.get_alerts(10)) == 2)
state.set(True)

# ── recent_rate() feeds the activity graph ─────────────────────────────────
det4 = m.RansomwareDetector(db, config, state, lambda pid, files: None)
counts = det4.recent_rate(window_secs=30.0, buckets=30)
check("recent_rate returns correct bucket count", len(counts) == 30)
check("recent_rate is all zeros with no events", sum(counts) == 0)

for i in range(7):
    det4.record(f"C:\\watched\\r{i}.txt", 31337)
counts = det4.recent_rate(window_secs=30.0, buckets=30)
check(f"recent_rate counts recorded events (sum={sum(counts)})", sum(counts) == 7)
check("events land in the most recent bucket", counts[-1] > 0)

# ── reset_alerted allows a PID to alert again ──────────────────────────────
before = len(db.get_alerts(100))
det.reset_alerted()
for i in range(5):
    det.record(f"C:\\watched\\again{i}.txt", 4242)
after = len(db.get_alerts(100))
check(f"reset_alerted lets the same PID alert again ({before} -> {after})",
      after == before + 1)

shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nALL DETECTOR CHECKS PASSED")
