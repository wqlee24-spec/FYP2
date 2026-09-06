import sys, os, tempfile, shutil

sys.path.insert(0, r"c:\Users\wqlee\OneDrive\桌面\FYP\FYP2\sourcecode")
import main_latesttt as m
import tkinter as tk

def check(label, cond):
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    if not cond:
        raise SystemExit(1)

tmp_dir = tempfile.mkdtemp(prefix="hss_gui_")
db = m.Database(os.path.join(tmp_dir, "gui.db"))
config = m.DetectionConfig()
state = m.MonitoringState(active=True)
det = m.RansomwareDetector(db, config, state, lambda pid, files: None)

# Seed a few alerts with distinct, searchable content
db.log_alert("RANSOMWARE", "evil.exe (PID 111)", "5/10 events: alpha.txt",
             status="BLOCKED", files=["C:\\w\\alpha.txt", "C:\\w\\beta.txt"],
             locked_dir="C:\\w")
db.log_alert("RANSOMWARE", "crypto.exe (PID 222)", "6/10 events: gamma.txt",
             status="LOCK FAILED", files=["C:\\x\\gamma.txt"], locked_dir=None)
db.log_alert("RANSOMWARE", "locker.exe (PID 333)", "7/10 events: delta.txt",
             status="BLOCKED", files=["C:\\y\\delta.txt"], locked_dir="C:\\y")

dash = m.Dashboard(db, config, state, det, live_mode=False, agent=None)
dash.withdraw()               # keep it off-screen for the test
dash.update()                 # force full widget realisation

rows = lambda: dash._log_tree.get_children()

# ── Baseline population ────────────────────────────────────────────────────
check(f"log tree populated with 3 alerts (got {len(rows())})", len(rows()) == 3)
check("stat: total alerts == 3", dash._stat_total.get() == "3")
check("stat: directories locked == 2", dash._stat_locked.get() == "2")
check("row iids are alert ids (digits)", all(r.isdigit() for r in rows()))

# ── New GUI attributes exist / old intrusion ones are gone ─────────────────
check("activity graph widget exists", isinstance(dash._activity_graph, m.ActivityGraph))
check("search entry exists", isinstance(dash._search_entry, tk.Entry))
check("banner widget exists", isinstance(dash._banner, tk.Frame))
check("no _ip_tree attribute (intrusion UI removed)", not hasattr(dash, "_ip_tree"))
check("no _blocker attribute (intrusion backend removed)", not hasattr(dash, "_blocker"))
check("widget_map has graph target", "graph" in dash._widget_map)
check("widget_map has no blocked target", "blocked" not in dash._widget_map)

# ── Search filtering ───────────────────────────────────────────────────────
dash._search_var.set("crypto")
dash._refresh()
check(f"search 'crypto' narrows to 1 row (got {len(rows())})", len(rows()) == 1)
check("stat cards still show unfiltered totals while searching",
      dash._stat_total.get() == "3" and dash._stat_locked.get() == "2")

dash._search_var.set("LOCK FAILED")
dash._refresh()
check("search matches the status column", len(rows()) == 1)

dash._search_var.set("zzz-no-match")
dash._refresh()
check("no-match search shows the placeholder row", rows() == ("placeholder",))

dash._search_var.set("")
dash._refresh()
check("clearing search restores all 3 rows", len(rows()) == 3)

# ── Sorting ────────────────────────────────────────────────────────────────
dash._sort_by("Attacker")
first_asc = dash._log_tree.item(rows()[0], "values")[2]
dash._sort_by("Attacker")          # same column again -> reverse
first_desc = dash._log_tree.item(rows()[0], "values")[2]
check(f"sort ascending puts crypto.exe first (got {first_asc})",
      first_asc.startswith("crypto"))
check(f"re-clicking reverses sort (got {first_desc})", first_desc.startswith("locker"))
check("sort_reverse flag toggled", dash._sort_reverse is True)

# ── Placeholder row is not drill-down clickable ────────────────────────────
dash._search_var.set("zzz-no-match")
dash._refresh()
dash._log_tree.selection_set("placeholder")
dash._on_log_row_dblclick(None)     # must be a silent no-op, not a crash
check("double-click on placeholder row is a safe no-op", True)
dash._search_var.set("")
dash._refresh()

# ── Alert drill-down window ────────────────────────────────────────────────
locked_id = [r for r in db.get_alerts(10) if r[7]][0][0]      # has locked_dir
unlocked_id = [r for r in db.get_alerts(10) if not r[7]][0][0]  # locked_dir NULL

w = m.AlertDetailWindow(dash, db, locked_id, on_change=dash._refresh)
dash.update()
check("drill-down window opens for a locked alert", w.winfo_exists())
check("drill-down knows its locked dir", w._locked_dir is not None)
w.destroy()

w2 = m.AlertDetailWindow(dash, db, unlocked_id, on_change=dash._refresh)
dash.update()
check("drill-down opens for a LOCK FAILED alert (locked_dir NULL)", w2.winfo_exists())
check("drill-down shows no locked dir for failed containment", w2._locked_dir is None)
w2.destroy()

# ── Notification path (beep + banner) ──────────────────────────────────────
# NOTE: the test window is withdrawn, so winfo_ismapped() is always false for
# children; winfo_manager() reflects pack/pack_forget regardless of visibility.
check("banner starts unpacked", dash._banner.winfo_manager() == "")
dash._notify_new_alert("test.exe (PID 999)", "2026-07-27 12:00:00")
dash.update()
check("banner is packed on new alert", dash._banner.winfo_manager() == "pack")
check("banner text mentions the attacker", "test.exe" in dash._banner_lbl.cget("text"))
check("banner sits above the title bar",
      dash.pack_slaves().index(dash._banner) < dash.pack_slaves().index(dash._hdr))
dash._hide_banner()
dash.update()
check("banner hides again", dash._banner.winfo_manager() == "")

# ── Activity graph draws without error ─────────────────────────────────────
for i in range(6):
    det.record(f"C:\\w\\graph{i}.txt", 8080)
dash._activity_graph._draw()
dash.update()
check("activity graph redraws with live data", True)
dash._activity_graph.stop()

# ── Monitoring toggle + space-key guard ────────────────────────────────────
was_active = state.active
dash._toggle_monitoring()
check("toggle flips monitoring state", state.active != was_active)
dash._toggle_monitoring()

# Focus only takes effect on a viewable window, so briefly show it for this check.
dash.deiconify()
dash.update()
dash.focus_force()
dash._search_entry.focus_set()
dash.update()
check(f"search entry actually holds focus (got {dash.focus_get()})",
      dash.focus_get() is dash._search_entry)

before_state = state.active
dash._on_space_key(None)
check("space key does NOT toggle monitoring while typing in search",
      state.active == before_state)

dash._log_tree.focus_set()
dash.update()
dash._on_space_key(None)
check("space key toggles monitoring when search is not focused",
      state.active != before_state)
dash.withdraw()

dash.destroy()
shutil.rmtree(tmp_dir, ignore_errors=True)
print("\nALL GUI CHECKS PASSED")
