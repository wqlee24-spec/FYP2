"""Ransomware hitting a non-ANSI (e.g. Chinese) directory must still alert.

Console encoding on this machine is cp1252. directory_lockdown() prints the
target directory; if that print raises UnicodeEncodeError the exception is a
ValueError subclass, so PipeReader's `except ValueError: pass` swallows it and
the alert disappears silently. Highly relevant here: ransomware routinely
encrypts files in user folders with localised names.
"""
import sys, os, io, tempfile, shutil

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode")
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp_dir = tempfile.mkdtemp(prefix="hss_uni_")
db = m.Database(os.path.join(tmp_dir, "uni.db"))
config = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=0.5, entropy_thresh=0)  # pure-rate: isolate path handling
state = m.MonitoringState(active=True)

# Real containment function (its print() is what can explode).
det = m.RansomwareDetector(db, config, state, m.directory_lockdown)

uni_dir = os.path.join(tmp_dir, "报告文件")
os.makedirs(uni_dir, exist_ok=True)
files = []
for i in range(6):
    f = os.path.join(uni_dir, f"文件_{i}.txt")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("x")
    files.append(f)

# Force the cp1252 console condition that the real app runs under.
real_stdout = sys.stdout
sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
crashed = None
try:
    for f in files[:5]:
        det.record(f, 31337, "ETW")
except Exception as e:
    crashed = e
finally:
    sys.stdout = real_stdout

if crashed is not None:
    print(f"  (record() raised {type(crashed).__name__}: {crashed})")

check("record() does not raise on a non-ANSI path", crashed is None)

rows = db.get_alerts(10)
check(f"alert was still logged for the unicode path (got {len(rows)})", len(rows) == 1)
if rows:
    check("alert kept the unicode filenames in detail",
          "文件" in (rows[0][4] or ""))

# Clean up any ACL the real lockdown applied so the temp dir can be removed.
if rows and rows[0][7]:
    m.directory_unlock(rows[0][7])
shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nUNICODE PATH CHECKS PASSED")
