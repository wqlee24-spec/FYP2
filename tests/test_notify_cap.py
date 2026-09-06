"""Regression: the new-alert notification must keep firing after the
get_alerts(200) row cap is reached (row COUNT stops growing; ids keep growing)."""
import sys, os, tempfile, shutil

sys.path.insert(0, r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode")
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp_dir = tempfile.mkdtemp(prefix="hss_cap_")
db = m.Database(os.path.join(tmp_dir, "cap.db"))
config = m.DetectionConfig()
state = m.MonitoringState(active=True)
det = m.RansomwareDetector(db, config, state, lambda pid, files: None)

# Fill past the 200-row query cap.
for i in range(205):
    db.log_alert("RANSOMWARE", f"proc{i}.exe (PID {i})", f"detail {i}",
                 status="BLOCKED", files=[f"C:\\w\\{i}.txt"], locked_dir="C:\\w")

dash = m.Dashboard(db, config, state, det, live_mode=False, agent=None)
dash.withdraw()
dash.update()

check("query is capped at 200 rows", len(dash._log_tree.get_children()) == 200)

fired = []
dash._notify_new_alert = lambda attacker, ts: fired.append(attacker)

dash._refresh()
check("no notification when nothing changed", len(fired) == 0)

# One more alert: row count stays pinned at 200, but the id increases.
db.log_alert("RANSOMWARE", "brand_new.exe (PID 999)", "the newest one",
             status="BLOCKED", files=["C:\\w\\new.txt"], locked_dir="C:\\w")
dash._refresh()
check(f"notification fires past the 200-row cap (fired={fired})", len(fired) == 1)
check("notification names the newest attacker", "brand_new.exe" in fired[0])

check("row count still pinned at the cap",
      len(dash._log_tree.get_children()) == 200)

dash._refresh()
check("no duplicate notification on the next tick", len(fired) == 1)

dash._activity_graph.stop()
dash.destroy()
shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nNOTIFICATION CAP REGRESSION PASSED")
