import sys, os, tempfile, shutil, sqlite3

sys.path.insert(0, r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode")
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

# ── 1. DB migration + new schema round-trip ────────────────────────────────
tmp_dir = tempfile.mkdtemp(prefix="hss_test_")
db_path = os.path.join(tmp_dir, "fresh.db")
db = m.Database(db_path)

cols = [r[1] for r in db._conn.execute("PRAGMA table_info(alerts)").fetchall()]
check("alerts has files_json column", "files_json" in cols)
check("alerts has locked_dir column", "locked_dir" in cols)
check("alerts has lock_active column", "lock_active" in cols)

tables = [r[0] for r in db._conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
check("blocked_ips table absent", "blocked_ips" not in tables)

db.log_alert("RANSOMWARE", "notepad.exe (PID 123)", "5/10 events in 0.01s: a.txt; b.txt",
             status="BLOCKED", files=["C:\\watched\\a.txt", "C:\\watched\\b.txt"],
             locked_dir="C:\\watched")

rows = db.get_alerts(10)
check("one alert row present", len(rows) == 1)
row = rows[0]
aid = row[0]
check("locked_dir stored correctly", row[7] == "C:\\watched")
check("lock_active is 1", row[8] == 1)

fetched = db.get_alert_by_id(aid)
check("get_alert_by_id returns same row", fetched[0] == aid)
import json as _json
check("files_json round-trips", _json.loads(fetched[6]) == ["C:\\watched\\a.txt", "C:\\watched\\b.txt"])

db.mark_unlocked(aid)
fetched2 = db.get_alert_by_id(aid)
check("mark_unlocked flips lock_active to 0", fetched2[8] == 0)
check("locked_dir preserved after unlock (audit trail)", fetched2[7] == "C:\\watched")

# ── 2. Migration against the REAL pre-existing legacy DB (old schema) ──────
real_db_src = r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode\security_suite.db"
real_db_copy = os.path.join(tmp_dir, "legacy_copy.db")
shutil.copy(real_db_src, real_db_copy)

legacy_conn = sqlite3.connect(real_db_copy)
legacy_tables_before = [r[0] for r in legacy_conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
legacy_alert_count_before = legacy_conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
legacy_conn.close()
print(f"[INFO] legacy db tables before migration: {legacy_tables_before}")
print(f"[INFO] legacy alert row count before migration: {legacy_alert_count_before}")

db2 = m.Database(real_db_copy)  # triggers _migrate() on the legacy schema
rows2 = db2.get_alerts(1000)
check("legacy alert rows preserved after migration",
      len(rows2) == legacy_alert_count_before)
cols2 = [r[1] for r in db2._conn.execute("PRAGMA table_info(alerts)").fetchall()]
check("legacy db migrated: new columns present", all(
    c in cols2 for c in ("files_json", "locked_dir", "lock_active")))
tables2 = [r[0] for r in db2._conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
check("legacy blocked_ips table dropped", "blocked_ips" not in tables2)

# ── 3. icacls lockdown + unlock round-trip on a real temp directory ────────
lock_test_dir = os.path.join(tmp_dir, "lockme")
os.makedirs(lock_test_dir, exist_ok=True)
seed_file = os.path.join(lock_test_dir, "seed.txt")
with open(seed_file, "w") as f:
    f.write("seed")

locked = m.directory_lockdown(pid=999, files=[seed_file])
check("directory_lockdown returns the locked dir path", locked == lock_test_dir)

blocked = False
try:
    with open(os.path.join(lock_test_dir, "new_after_lock.txt"), "w") as f:
        f.write("should fail")
except PermissionError:
    blocked = True
check("write blocked after lockdown", blocked)

ok, err = m.directory_unlock(locked)
check(f"directory_unlock succeeded (err={err!r})", ok)

try:
    with open(os.path.join(lock_test_dir, "new_after_unlock.txt"), "w") as f:
        f.write("should succeed")
    restored = True
except PermissionError:
    restored = False
check("write succeeds again after unlock", restored)

shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nALL CHECKS PASSED")
