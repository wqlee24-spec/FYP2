"""Print ETW-vs-heuristic attribution stats from the alerts database.

Avoids the PowerShell quoting pain of a one-liner. Run from anywhere:

    python tools/etw_stats.py
    python tools/etw_stats.py 2026-08-14      # only alerts on/after this date
"""
import os
import sqlite3
import sys

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(SRC, "security_suite.db")
since = sys.argv[1] if len(sys.argv) > 1 else None

if not os.path.exists(DB):
    print(f"database not found: {DB}")
    raise SystemExit(1)

con = sqlite3.connect(DB)

print("\n=== Attribution split — ALL alerts ===")
total = 0
etw = 0
for attribution, n in con.execute(
        "SELECT attribution, COUNT(*) FROM alerts GROUP BY attribution"):
    print(f"  {attribution:<6} {n}")
    total += n
    if attribution == "ETW":
        etw = n
if total:
    print(f"  -> ETW attributed {etw}/{total} = {etw/total*100:.1f}% of all alerts")

if since:
    print(f"\n=== Attribution split — alerts on/after {since} ===")
    t2 = e2 = 0
    for attribution, n in con.execute(
            "SELECT attribution, COUNT(*) FROM alerts WHERE timestamp >= ? "
            "GROUP BY attribution", (since,)):
        print(f"  {attribution:<6} {n}")
        t2 += n
        if attribution == "ETW":
            e2 = n
    if t2:
        print(f"  -> ETW attributed {e2}/{t2} = {e2/t2*100:.1f}%  (use this for report 6.6)")

print("\n=== 10 most recent alerts ===")
for row in con.execute(
        "SELECT id, timestamp, attribution, attacker FROM alerts "
        "ORDER BY id DESC LIMIT 10"):
    print(" ", row)
print()
