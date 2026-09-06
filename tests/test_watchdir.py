"""Configurable watched directory: persistence, agent wiring, Settings UI, live re-target."""
import os, sys, time, tempfile, shutil, winreg

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SRC)
import main_latesttt as m
import tkinter as tk

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

# Preserve whatever the user actually has configured.
original = None
try:
    with m._hss_reg_open() as k:
        original, _ = winreg.QueryValueEx(k, m.WATCH_DIR_KEY)
except (FileNotFoundError, OSError):
    pass

tmp_a = tempfile.mkdtemp(prefix="hss_wd_a_")
tmp_b = tempfile.mkdtemp(prefix="hss_wd_b_")

try:
    # ── Persistence ────────────────────────────────────────────────────────
    check("set_watch_dir persists", m.set_watch_dir(tmp_a))
    check(f"get_watch_dir reads it back", os.path.normcase(m.get_watch_dir()) ==
          os.path.normcase(tmp_a))

    # A configured-but-deleted folder must not strand the agent.
    ghost = tempfile.mkdtemp(prefix="hss_wd_ghost_")
    m.set_watch_dir(ghost)
    shutil.rmtree(ghost, ignore_errors=True)
    check("nonexistent configured folder falls back to the default",
          m.get_watch_dir() == m.DEFAULT_WATCH_DIR)
    m.set_watch_dir(tmp_a)

    # ── Agent receives --watch-dir ─────────────────────────────────────────
    agent = m.AgentManager(m.AGENT_EXE, tmp_a)
    check("AgentManager exposes its watch dir", agent.watch_dir == tmp_a)
    check("agent binary exists", m.AGENT_EXE.exists())
    check("agent starts", agent.start())
    time.sleep(1.5)
    check("agent process is alive", agent.pid is not None)

    # ── Live re-target ─────────────────────────────────────────────────────
    old_pid = agent.pid
    check("restart() succeeds", agent.restart(tmp_b))
    time.sleep(1.5)
    check("agent watch dir updated", agent.watch_dir == tmp_b)
    check("agent was actually restarted (new PID)", agent.pid != old_pid)
    agent.stop()

    # ── Settings dialog round-trip ─────────────────────────────────────────
    m.set_watch_dir(tmp_a)
    root = tk.Tk(); root.withdraw()
    cfg = m.DetectionConfig()
    db = m.Database(os.path.join(tmp_a, "t.db"))
    det = m.RansomwareDetector(db, cfg, m.MonitoringState(), lambda p, f: None)

    win = m.SettingsWindow(root, cfg, det, agent=None)
    root.update()
    check("Settings shows the current folder",
          os.path.normcase(win._dir_var.get()) == os.path.normcase(tmp_a))

    win._dir_var.set(tmp_b)
    win._vars["file_thresh"].set("7")
    win._apply()
    root.update()
    check("applying persists the new folder",
          os.path.normcase(m.get_watch_dir()) == os.path.normcase(tmp_b))
    check("thresholds still applied alongside", cfg.get()[0] == 7)

    # Invalid folder must be rejected, not silently saved.
    win2 = m.SettingsWindow(root, cfg, det, agent=None)
    root.update()
    win2._dir_var.set(os.path.join(tmp_b, "does_not_exist_xyz"))
    import tkinter.messagebox as mb
    real_err, shown = mb.showerror, []
    mb.showerror = lambda *a, **k: shown.append(a)
    try:
        win2._apply()
    finally:
        mb.showerror = real_err
    check("nonexistent folder is rejected with an error", len(shown) == 1)
    check("rejected folder was not persisted",
          os.path.normcase(m.get_watch_dir()) == os.path.normcase(tmp_b))
    try: win2.destroy()
    except Exception: pass

    # ── Tour text is not hardcoded ─────────────────────────────────────────
    done = [s for s in m.WelcomePage.STEPS if s["id"] == "done"][0]
    check("tour uses a {watch_dir} placeholder, not a fixed path",
          any("{watch_dir}" in t for t, *_ in done["lines"]))
    check("no step hardcodes Public\\Documents",
          not any("Public\\Documents" in t for s in m.WelcomePage.STEPS
                  for t, *_ in s["lines"]))
    root.destroy()

finally:
    if original is not None:
        m.set_watch_dir(original)
    else:
        try:
            with m._hss_reg_open(winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, m.WATCH_DIR_KEY)
        except OSError:
            pass
    shutil.rmtree(tmp_a, ignore_errors=True)
    shutil.rmtree(tmp_b, ignore_errors=True)

print("\nWATCH DIRECTORY CHECKS PASSED")
