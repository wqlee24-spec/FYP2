"""ETW attribution: pipe protocol parsing, per-event source tracking, persistence."""
import sys, os, tempfile, shutil, threading, time
import sys; sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode")
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp_dir = tempfile.mkdtemp(prefix="hss_attr_")
db = m.Database(os.path.join(tmp_dir, "attr.db"))
config = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=0.5, entropy_thresh=0)  # pure-rate: isolate attribution
state = m.MonitoringState(active=True)
det = m.RansomwareDetector(db, config, state, lambda pid, files: "C:\\w")

# ── Schema ─────────────────────────────────────────────────────────────────
cols = [r[1] for r in db._conn.execute("PRAGMA table_info(alerts)").fetchall()]
check("alerts has attribution column", "attribution" in cols)

# ── ETW-attributed alert persists attribution=ETW ──────────────────────────
for i in range(5):
    det.record(f"C:\\w\\etw{i}.txt", 4242, "ETW")
rows = db.get_alerts(10)
check("alert fired", len(rows) == 1)
check(f"attribution persisted as ETW (got {rows[0][9]})", rows[0][9] == "ETW")

# ── Heuristic-attributed alert persists attribution=HEUR ───────────────────
for i in range(5):
    det.record(f"C:\\w\\heur{i}.txt", 777, "HEUR")
rows = db.get_alerts(10)
check(f"second alert attribution is HEUR (got {rows[0][9]})", rows[0][9] == "HEUR")

# ── Default arg keeps old callers working ──────────────────────────────────
for i in range(5):
    det.record(f"C:\\w\\default{i}.txt", 555)
rows = db.get_alerts(10)
check("record() without source defaults to HEUR", rows[0][9] == "HEUR")

# ── attribution_stats counts both kinds ────────────────────────────────────
etw_n, heur_n = det.attribution_stats()
check(f"attribution_stats counts ETW events (got {etw_n})", etw_n == 5)
check(f"attribution_stats counts HEUR events (got {heur_n})", heur_n == 10)

# ── PipeReader protocol parsing (3-field, 2-field, malformed) ──────────────
class FakeDetector:
    def __init__(self): self.seen = []
    def record(self, fp, pid, source="HEUR"): self.seen.append((fp, pid, source))

fake = FakeDetector()
reader = m.PipeReader("unused", fake)

class FakePipe:
    """Stands in for the opened named pipe. Signals the reader to stop only once
    the lines are exhausted — run() checks the stop flag before each line, so
    stopping any earlier would break out before parsing anything."""
    def __init__(self, lines, reader): self._lines = lines; self._reader = reader
    def __enter__(self): return iter(self._lines)
    def __exit__(self, *a):
        self._reader.stop()
        return False

lines = [
    "C:\\w\\a.txt|1234|ETW\n",
    "C:\\w\\b.txt|5678|HEUR\n",
    "C:\\w\\c.txt|4321\n",          # legacy 2-field form
    "garbage-no-delimiter\n",        # malformed -> skipped
    "C:\\w\\d.txt|notanint|ETW\n",   # bad pid -> skipped
    "\n",                            # blank -> skipped
]

import builtins
real_open = builtins.open
def fake_open(path, *a, **kw):
    if path == "unused":
        return FakePipe(lines, reader)
    return real_open(path, *a, **kw)

builtins.open = fake_open
try:
    reader.run()
finally:
    builtins.open = real_open

check(f"parsed 3 valid events (got {len(fake.seen)}: {fake.seen})", len(fake.seen) == 3)
check("3-field ETW line parsed", fake.seen[0] == ("C:\\w\\a.txt", 1234, "ETW"))
check("3-field HEUR line parsed", fake.seen[1] == ("C:\\w\\b.txt", 5678, "HEUR"))
check("legacy 2-field line defaults to HEUR", fake.seen[2] == ("C:\\w\\c.txt", 4321, "HEUR"))

# ── Path containing spaces / unicode still round-trips ─────────────────────
fake2 = FakeDetector()
reader2 = m.PipeReader("unused2", fake2)
lines2 = ["C:\\my docs\\报告 final.txt|999|ETW\n"]
def fake_open2(path, *a, **kw):
    if path == "unused2":
        return FakePipe(lines2, reader2)
    return real_open(path, *a, **kw)
builtins.open = fake_open2
try:
    reader2.run()
finally:
    builtins.open = real_open
check(f"unicode/space path parsed (got {fake2.seen})",
      fake2.seen == [("C:\\my docs\\报告 final.txt", 999, "ETW")])

shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nALL ATTRIBUTION CHECKS PASSED")
