"""End-to-end: real C++ agent -> Named Pipe -> Python detector.

Runs the actual monitor_agent_etw.exe, generates a ransomware-like burst in the
watched directory, and verifies the events arrive with an attribution tag.
Containment is stubbed so the test never ACLs a real system folder.
"""
import sys, os, time, subprocess, tempfile, shutil, threading

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode"
sys.path.insert(0, SRC)
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

WATCH = r"C:\Users\Public\Documents"
AGENT = os.path.join(SRC, "monitor_agent.exe")
check("agent binary exists", os.path.exists(AGENT))

tmp_dir = tempfile.mkdtemp(prefix="hss_e2e_")
db = m.Database(os.path.join(tmp_dir, "e2e.db"))
config = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=2.0, entropy_thresh=0)  # pure-rate: isolate pipeline
state = m.MonitoringState(active=True)

locked = []
det = m.RansomwareDetector(db, config, state,
                           lambda pid, files: locked.append(files) or "STUBBED")

# Capture every event the detector sees, with its attribution tag.
seen = []
orig_record = det.record
def spy(fp, pid, source="HEUR"):
    seen.append((fp, pid, source))
    return orig_record(fp, pid, source)
det.record = spy

proc = subprocess.Popen([AGENT], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, encoding="utf-8", errors="replace",
                        creationflags=subprocess.CREATE_NO_WINDOW)
agent_lines = []
threading.Thread(target=lambda: [agent_lines.append(l) for l in proc.stdout],
                 daemon=True).start()
time.sleep(1.5)

reader = m.PipeReader(m.PIPE_NAME, det)
reader.start()
time.sleep(1.5)

made = []
try:
    for i in range(8):
        f = os.path.join(WATCH, f"hss_e2e_test_{i}.txt")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("ransomware simulation payload")
        made.append(f)
    time.sleep(3.0)
finally:
    reader.stop()
    try:
        proc.terminate(); proc.wait(timeout=5)
    except Exception:
        proc.kill()
    for f in made:
        try: os.remove(f)
        except OSError: pass

banner = "".join(agent_lines)
print("\n--- agent output (first 12 lines) ---")
for l in agent_lines[:12]:
    print("   " + l.rstrip())
print("--- end ---\n")

check(f"agent reported its attribution mode", "PID attribution" in banner)
check(f"detector received events over the pipe (got {len(seen)})", len(seen) > 0)

sources = {s for _, _, s in seen}
check(f"every event carries an attribution tag (saw {sources})",
      sources.issubset({"ETW", "HEUR"}) and len(sources) > 0)

pids = {p for _, p, _ in seen}
check(f"events carry PIDs (saw {sorted(pids)[:5]})", all(p > 0 for p in pids))

rows = db.get_alerts(10)
check(f"burst produced a ransomware alert (got {len(rows)})", len(rows) >= 1)
if rows:
    check(f"alert persisted attribution '{rows[0][9]}'", rows[0][9] in ("ETW", "HEUR"))
    check("containment callback fired", len(locked) >= 1)

etw_n = sum(1 for _, _, s in seen if s == "ETW")
heur_n = sum(1 for _, _, s in seen if s == "HEUR")
print(f"\nAttribution split: ETW={etw_n}  HEUR={heur_n}"
      f"   (ETW requires Administrator; 0 here is expected when not elevated)")

shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nEND-TO-END CHECKS PASSED")
