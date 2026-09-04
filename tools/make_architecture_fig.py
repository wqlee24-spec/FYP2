"""Generate the Chapter 3 system-architecture diagram (Figure 3.1) for the report.

    python tools/make_architecture_fig.py    ->  report_figures/fig_architecture.png
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(SRC, "report_figures")
os.makedirs(OUT, exist_ok=True)

C_NATIVE = "#dbe7f3"   # C++ / native
C_PIPE   = "#e8e0f0"   # IPC
C_PY     = "#dff0e4"   # Python engine
C_LAYER  = "#fdf1d6"   # detection layers
C_ACT    = "#fadcd9"   # containment
C_STORE  = "#e9e9e9"   # storage / UI
EDGE     = "#4a4a4a"

fig, ax = plt.subplots(figsize=(7.4, 9.4))
ax.set_xlim(0, 10); ax.set_ylim(0, 13)
ax.axis("off")


def box(x, y, w, h, text, fc, fs=9.5, bold=False, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.10,rounding_size=0.14",
                                linewidth=1.2, edgecolor=EDGE, facecolor=fc,
                                linestyle=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight=("bold" if bold else "normal"),
            family="DejaVu Sans", linespacing=1.45)


def arrow(x1, y1, x2, y2, label="", fs=8.4, dx=0.12):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="-|>", mutation_scale=13,
                                 linewidth=1.2, color=EDGE))
    if label:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2, label, ha="left", va="center",
                fontsize=fs, style="italic", family="DejaVu Sans")


# ── User space boundary note ─────────────────────────────────────────────────
ax.text(5, 12.78, "All components execute in USER SPACE \u2014 no kernel-mode driver",
        ha="center", va="center", fontsize=9.2, fontweight="bold", color="#333333")

# 1. watched directory
box(2.6, 11.85, 4.8, 0.72, "Watched Directory\n(user-configurable, e.g. C:\\Users\\...\\Documents)",
    C_STORE, fs=9)
arrow(5.0, 11.83, 5.0, 11.25, "file events")

# 2. C++ agent
box(1.15, 9.70, 7.7, 1.55,
    "C++ Monitoring Agent  (monitor_agent.exe)\n\n"
    "ReadDirectoryChangesW  \u2192  WHAT changed\n"
    "ETW Kernel-File Attributor  \u2192  WHO changed it (true PID)",
    C_NATIVE, fs=9.2)
arrow(5.0, 9.68, 5.0, 9.10, "FILEPATH | PID | SOURCE")

# 3. named pipe
box(2.6, 8.35, 4.8, 0.72, "Windows Named Pipe\n\\\\.\\pipe\\SecurityPipe", C_PIPE, fs=9)
arrow(5.0, 8.33, 5.0, 7.75)

# 4. python engine
box(1.15, 6.95, 7.7, 0.78, "Python Analysis Engine  \u2014  PipeReader thread", C_PY, fs=9.2)
arrow(5.0, 6.93, 5.0, 6.35)

# 5. three detection layers
box(0.75, 4.20, 8.5, 2.12, "", C_LAYER, ls="--")
ax.text(5.0, 6.10, "RansomwareDetector  \u2014  three-layer detection",
        ha="center", va="center", fontsize=9.4, fontweight="bold")
box(1.10, 4.45, 2.45, 1.32, "Layer 1\nRATE\n\nk files\nwithin t s", "#ffffff", fs=8.6)
box(3.80, 4.45, 2.45, 1.32, "Layer 2\nENTROPY\n\nmedian \u2265 6.5\nbits/byte", "#ffffff", fs=8.6)
box(6.50, 4.45, 2.45, 1.32, "Layer 3\nCANARY\n\ndecoy file\ntouched", "#ffffff", fs=8.6)
arrow(3.57, 5.11, 3.78, 5.11, "")
arrow(6.27, 5.11, 6.48, 5.11, "")
arrow(5.0, 4.18, 5.0, 3.62, "alert")

# 6. containment
box(0.95, 2.30, 8.1, 1.30,
    "Reversible Containment\n\n"
    "icacls directory lockdown (environmental)\n"
    "SuspendThread process suspend (ETW-gated)\n"
    "every action undoable from the dashboard",
    C_ACT, fs=8.5)
arrow(3.1, 2.28, 3.1, 1.72)
arrow(6.9, 2.28, 6.9, 1.72)

# 7. storage + dashboard
box(0.95, 0.85, 3.7, 0.85, "SQLite Database\nalerts table", C_STORE, fs=9)
box(5.35, 0.85, 3.7, 0.85, "Tkinter Dashboard\nlog \u00b7 graph \u00b7 drill-down", C_STORE, fs=9)
arrow(4.63, 1.27, 5.33, 1.27)

fig.tight_layout()
p = os.path.join(OUT, "fig_architecture.png")
fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white")
plt.close(fig)
print("wrote", os.path.relpath(p, SRC))
