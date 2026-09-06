"""Behavioural validation matrix — does the detector fire on real ransomware
behaviour, and stay quiet during legitimate heavy I/O?

This is the evaluation harness for the FYP2 "applicable to the real world"
requirement. Unlike the FYP1 empty-file script, each ransomware scenario here
performs the true read -> encrypt -> write -> rename/delete sequence (via
tools/ransomware_sim.py), and each benign scenario reproduces a real heavy-I/O
workload that a naive rate threshold could misfire on (tools/benign_workloads.py).

For every scenario it launches the workload as its own process against a folder
the live C++ agent is watching, runs the real detection pipeline, and records:

    expected  whether an alert SHOULD fire (ransomware = yes, benign = no)
    actual    whether one did
    correct   expected == actual        -> TP / TN / FP / FN
    latency   first attack event -> alert row (ms)
    attribution  ETW (elevated) or HEUR

Output: a confusion-matrix-style table + CSV for the report's evaluation chapter.

    python tests/validate_behaviour.py            # default matrix
    python tests/validate_behaviour.py --reps 3   # average over repeats

Containment is STUBBED here (recorded, not applied) so the harness never ACLs a
folder mid-run — detection is what this validates; the icacls lockdown/unlock
round-trip is covered by tests/test_backend.py.
"""

import argparse
import csv
import os
import statistics
import subprocess
import sys
import tempfile
import time
import shutil
from pathlib import Path

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SRC)
import main_latesttt as m

SIM    = os.path.join(SRC, "tools", "ransomware_sim.py")
BENIGN = os.path.join(SRC, "tools", "benign_workloads.py")
PY     = sys.executable

# scenario: (kind, tool, args, expected_alert)
SCENARIOS = [
    ("overwrite",   "ransomware", ["--family", "overwrite",   "--rate", "0", "--no-note"], True),
    ("copy_delete", "ransomware", ["--family", "copy_delete", "--rate", "0", "--no-note"], True),
    ("rename",      "ransomware", ["--family", "rename",      "--rate", "0", "--no-note"], True),
    ("bulk_copy",   "benign",     ["--workload", "bulk_copy", "--rate", "8"],  False),
    ("backup",      "benign",     ["--workload", "backup",    "--rate", "8"],  False),
    ("edit",        "benign",     ["--workload", "edit",  "--count", "5", "--rate", "2"], False),
    ("extract_fast","benign",     ["--workload", "extract", "--files", "300", "--rate", "150"], False),
]


def seed(sandbox, n, size_kb):
    subprocess.run([PY, SIM, "--dir", str(sandbox), "--seed-corpus",
                    "--files", str(n), "--size-kb", str(size_kb)],
                   capture_output=True, text=True)


def run_scenario(name, kind, args, sandbox, agent, det, state, marks, reps_files, size_kb):
    # Clean the sandbox and lay down a fresh corpus with detection PAUSED, so the
    # seeding burst itself cannot be mistaken for an attack.
    state.set(False)
    for p in sandbox.iterdir():
        try:
            p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass
    seed(sandbox, reps_files, size_kb)
    det.reset_alerted()
    time.sleep(1.5)                     # let seed events drain while paused

    marks["alerts"].clear()
    marks["events"].clear()
    state.set(True)                     # arm detection

    tool = SIM if kind == "ransomware" else BENIGN
    t_launch = time.time_ns()
    subprocess.run([PY, tool, "--dir", str(sandbox)] + args, capture_output=True, text=True)
    time.sleep(2.0)                     # drain the pipe

    events = list(marks["events"])
    alerts = list(marks["alerts"])
    first_event = next((t for t in events if t >= t_launch), None)
    fired = len(alerts) > 0
    latency = ((alerts[0] - first_event) / 1e6
               if alerts and first_event and alerts[0] >= first_event else None)
    src = "ETW" if marks["etw"][0] > marks["heur"][0] else "HEUR"
    return {
        "scenario": name,
        "kind": kind,
        "events": len([t for t in events if t >= t_launch]),
        "expected_alert": bool_word(name_expected(name)),
        "actual_alert": bool_word(fired),
        "latency_ms": round(latency, 1) if latency is not None else "",
        "attribution": src,
        "_fired": fired,
    }


def name_expected(name):
    return next(exp for n, _, _, exp in SCENARIOS if n == name)


def bool_word(b):
    return "ALERT" if b else "quiet"


def classify(expected, fired):
    if expected and fired:      return "TP"
    if expected and not fired:  return "FN"
    if not expected and fired:  return "FP"
    return "TN"


def main():
    ap = argparse.ArgumentParser(description="Behavioural validation matrix (FYP2)")
    ap.add_argument("--reps", type=int, default=1, help="repeat each scenario N times")
    ap.add_argument("--files", type=int, default=40, help="corpus size")
    ap.add_argument("--size-kb", type=int, default=8, help="per-file KB")
    ap.add_argument("--out", default=os.path.join(SRC, "tests", "validation_results.csv"))
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if not m.AGENT_EXE.exists():
        print(f"ERROR: agent not built at {m.AGENT_EXE}")
        return 1

    elevated = False
    try:
        import ctypes
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass

    sandbox = Path(tempfile.mkdtemp(prefix="hss_validate_"))
    (sandbox / m.MARKER if hasattr(m, "MARKER") else sandbox / ".hss_sandbox").write_text("x")

    print("=" * 74)
    print("Behavioural validation — real ransomware behaviour vs benign heavy I/O")
    print("=" * 74)
    print(f"  thresholds: k=5  n=10  t=0.01s   (shipped defaults)")
    print(f"  sandbox: {sandbox}")
    print(f"  elevated={elevated}  attribution={'ETW' if elevated else 'HEUR (run as Admin for ETW)'}\n")

    # One live pipeline for the whole matrix.
    db = m.Database(os.path.join(tempfile.mkdtemp(prefix="hss_vdb_"), "v.db"))
    config = m.DetectionConfig(file_thresh=5, event_cap=10, window_secs=0.01)
    state = m.MonitoringState(active=True)
    marks = {"alerts": [], "events": [], "etw": [0], "heur": [0]}
    det = m.RansomwareDetector(db, config, state,
                               lambda pid, files: marks["alerts"].append(time.time_ns()) or "STUB")
    inner = det.record
    def spy(fp, pid, source="HEUR"):
        marks["events"].append(time.time_ns())
        if source == "ETW": marks["etw"][0] += 1
        else:               marks["heur"][0] += 1
        return inner(fp, pid, source)
    det.record = spy

    agent = m.AgentManager(m.AGENT_EXE, str(sandbox))
    agent.start()
    time.sleep(1.5)
    reader = m.PipeReader(m.PIPE_NAME, det)
    reader.start()
    time.sleep(1.0)

    rows = []
    try:
        for name, kind, sargs, _exp in SCENARIOS:
            cells = []
            for r in range(args.reps):
                res = run_scenario(name, kind, sargs, sandbox, agent, det, state,
                                   marks, args.files, args.size_kb)
                cells.append(res)
            fired_any = any(c["_fired"] for c in cells)
            lat_vals = [c["latency_ms"] for c in cells if isinstance(c["latency_ms"], (int, float))]
            row = {
                "scenario": name,
                "kind": kind,
                "expected": bool_word(name_expected(name)),
                "actual": bool_word(fired_any),
                "result": classify(name_expected(name), fired_any),
                "latency_ms": round(statistics.fmean(lat_vals), 1) if lat_vals else "",
                "attribution": cells[-1]["attribution"],
                "events": cells[-1]["events"],
                "reps": args.reps,
            }
            rows.append(row)
            print(f"  {name:<13} {kind:<10} expected={row['expected']:<6} "
                  f"actual={row['actual']:<6} -> {row['result']:<3} "
                  f"lat={row['latency_ms'] or '-':>6}  ev={row['events']}")
    finally:
        reader.stop()
        agent.stop()
        shutil.rmtree(sandbox, ignore_errors=True)

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    tp = sum(1 for r in rows if r["result"] == "TP")
    tn = sum(1 for r in rows if r["result"] == "TN")
    fp = sum(1 for r in rows if r["result"] == "FP")
    fn = sum(1 for r in rows if r["result"] == "FN")

    print("\n" + "=" * 74)
    print(f"CONFUSION MATRIX   TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print("=" * 74)
    ransomware = [r for r in rows if r["kind"] == "ransomware"]
    detected = sum(1 for r in ransomware if r["result"] == "TP")
    print(f"  Ransomware families detected : {detected}/{len(ransomware)}")
    print(f"  Benign workloads misfired    : {fp}/{sum(1 for r in rows if r['kind']=='benign')}")
    if fp:
        offenders = [r['scenario'] for r in rows if r['result'] == 'FP']
        print(f"    false positives: {', '.join(offenders)}")
        print(f"    -> a real finding: tune thresholds or add an entropy feature "
              f"(these workloads write LOW-entropy data; ransomware writes HIGH).")
    print(f"\nCSV → {args.out}")
    if not elevated:
        print("NOTE: not elevated — attribution shows HEUR. Re-run as Administrator "
              "to record the ETW column.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
