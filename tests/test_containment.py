"""Process containment: reversible suspend/resume + the safety guards that make
acting on a PID acceptable (ETW-only, never self/agent/critical)."""
import os, sys, time, subprocess, tempfile, shutil

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SRC)
import main_latesttt as m

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}", flush=True)
    if not cond:
        raise SystemExit(1)

tmp = tempfile.mkdtemp(prefix="hss_cont_")
p = None
try:
    # ── Suspend / resume round-trip on a real child ────────────────────────
    counter = os.path.join(tmp, "c.txt")
    # Self-limiting (~30 s max) so a failed assertion can never orphan it.
    child = (
        "import time\n"
        f"f=open(r'{counter}','w')\n"
        "for i in range(1, 3000):\n"
        "    f.seek(0); f.write(str(i)); f.flush(); time.sleep(0.01)\n"
    )
    p = subprocess.Popen([sys.executable, "-c", child])
    time.sleep(0.6)
    val = lambda: (int(open(counter).read() or 0) if os.path.exists(counter) else -1)

    a = val(); time.sleep(0.3); b = val()
    check(f"child is running (counter {a}->{b})", b > a)

    ok, err = m.suspend_process(p.pid)
    check(f"suspend_process succeeds (err={err!r})", ok)
    time.sleep(0.1)
    s1 = val(); time.sleep(0.4); s2 = val()
    check(f"process frozen while suspended ({s1}=={s2})", s1 == s2)

    ok, err = m.resume_process(p.pid)
    check(f"resume_process succeeds (err={err!r})", ok)
    time.sleep(0.1)
    r1 = val(); time.sleep(0.3); r2 = val()
    check(f"process advances after resume ({r1}->{r2})", r2 > r1)

    # ── Safety guards (containment_precheck) ───────────────────────────────
    check("refuses a HEUR-attributed PID",
          m.containment_precheck(p.pid, "HEUR")[0] is False)
    check("allows an ETW-attributed, live, non-critical PID",
          m.containment_precheck(p.pid, "ETW")[0] is True)
    check("refuses our own process", m.containment_precheck(os.getpid(), "ETW")[0] is False)
    check("refuses the monitor agent's PID",
          m.containment_precheck(p.pid, "ETW", agent_pid=p.pid)[0] is False)
    check("refuses PID <= 4 (system/idle)", m.containment_precheck(4, "ETW")[0] is False)
    check("refuses a None PID", m.containment_precheck(None, "ETW")[0] is False)

    # Critical-process denylist: force the name lookup to report a protected proc.
    _orig = m._process_name
    m._process_name = lambda pid: "lsass.exe"
    try:
        ok_crit, reason = m.containment_precheck(p.pid, "ETW")
        check(f"refuses a critical system process ({reason!r})", ok_crit is False)
    finally:
        m._process_name = _orig

    # Dead PID -> refused.
    p.terminate()
    try: p.wait(timeout=3)
    except Exception: p.kill()
    time.sleep(0.3)
    check("refuses a no-longer-running PID",
          m.containment_precheck(p.pid, "ETW")[0] is False)

    # ── DB persists the PID for the drill-down to use ──────────────────────
    db = m.Database(os.path.join(tmp, "c.db"))
    db.log_alert("RANSOMWARE", "evil.exe (PID 4242)", "detail",
                 files=["x"], locked_dir="C:\\w", attribution="ETW", entropy=7.9, pid=4242)
    row = db.get_alerts(1)[0]
    check(f"alert row carries pid at index 11 (got {row[11]})", row[11] == 4242)
    fetched = db.get_alert_by_id(row[0])
    check("get_alert_by_id returns the pid too", fetched[11] == 4242)

    print("\nALL CONTAINMENT CHECKS PASSED")
finally:
    if p and p.poll() is None:
        try: p.kill()
        except Exception: pass
    shutil.rmtree(tmp, ignore_errors=True)
