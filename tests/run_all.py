"""Run every verification script and print a summary.

    python tests/run_all.py

Run once normally and once from an elevated prompt — the elevated run is the
only way to exercise the ETW attribution path (the kernel provider requires
Administrator; without it the agent degrades to the heuristic and reports so).
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))

SUITES = [
    ("backend",      "DB migration, schema, icacls lockdown/unlock round-trip"),
    ("detector",     "sliding-window heuristic, alert pipeline, activity graph feed"),
    ("attribution",  "ETW/heuristic tagging, pipe protocol parsing"),
    ("unicode_path", "non-ANSI paths must not silently drop alerts"),
    ("notify_cap",   "new-alert notification survives the 200-row query cap"),
    ("entropy",      "entropy gate: high fires, low suppressed, unknown never suppresses"),
    ("containment",  "reversible process suspend/resume + ETW-only safety guards"),
    ("canary",       "decoy-file tripwire: instant on tamper, safe on our own writes"),
    ("ml",           "ML feature extraction + classifier beats pure-rate baseline"),
    ("watchdir",     "configurable watch folder: persistence, agent re-target, Settings"),
    ("gui",          "dashboard search/sort/drill-down/banner"),
    ("e2e",          "real C++ agent -> named pipe -> detector"),
]

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    results = []
    for name, desc in SUITES:
        path = os.path.join(HERE, f"test_{name}.py")
        if not os.path.exists(path):
            results.append((name, "MISSING", desc))
            continue
        print(f"\n{'='*70}\n{name}  —  {desc}\n{'='*70}")
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stdout.write(r.stderr)
        results.append((name, "PASS" if r.returncode == 0 else "FAIL", desc))

    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    for name, status, desc in results:
        print(f"  [{status:<7}] {name:<14} {desc}")

    failed = [n for n, s, _ in results if s != "PASS"]
    print()
    if failed:
        print(f"{len(failed)} suite(s) failed: {', '.join(failed)}")
        return 1
    print("All suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
