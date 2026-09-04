# -*- coding: utf-8 -*-
"""Generate the UML figures required by FYP2 guideline section 3.1:

    3.1.2  Use Case Diagram      -> report_figures/fig_usecase.png
    3.1.3  Activity Diagram      -> report_figures/fig_activity.png

(3.1.1 System Architecture Diagram is produced by make_architecture_fig.py.)

Drawn with matplotlib so the styling matches the other report figures and no
external diagramming tool is needed.

    python tools/make_uml_figs.py
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyBboxPatch, FancyArrowPatch, Rectangle, Circle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "report_figures")
os.makedirs(OUT, exist_ok=True)

INK = "#1a1a1a"
LINE = "#333333"
FILL = "#eef4f8"
EDGE = "#2b5f7a"
ACCENT = "#0d6f8c"
GREY = "#6b7680"
RED = "#b03a2e"
GREEN = "#1e7a3c"

plt.rcParams["font.family"] = "DejaVu Sans"


# ═════════════════════════════════════════════════════════════════════════════
#  Use Case Diagram
# ═════════════════════════════════════════════════════════════════════════════
def actor(ax, x, y, label, scale=1.0):
    """A UML stick-figure actor."""
    s = scale
    ax.add_patch(Circle((x, y + 0.30 * s), 0.085 * s, fill=False, ec=LINE, lw=1.4))
    ax.plot([x, x], [y + 0.21 * s, y - 0.08 * s], color=LINE, lw=1.4)          # body
    ax.plot([x - 0.15 * s, x + 0.15 * s], [y + 0.13 * s, y + 0.13 * s],
            color=LINE, lw=1.4)                                                 # arms
    ax.plot([x, x - 0.13 * s], [y - 0.08 * s, y - 0.32 * s], color=LINE, lw=1.4)
    ax.plot([x, x + 0.13 * s], [y - 0.08 * s, y - 0.32 * s], color=LINE, lw=1.4)
    ax.text(x, y - 0.46 * s, label, ha="center", va="top", fontsize=9.5,
            color=INK, fontweight="bold", linespacing=1.35)


def usecase(ax, x, y, label, w=1.85, h=0.46, fs=8.6):
    ax.add_patch(Ellipse((x, y), w, h, facecolor=FILL, edgecolor=EDGE, lw=1.2))
    ax.text(x, y, label, ha="center", va="center", fontsize=fs, color=INK,
            linespacing=1.25)
    return (x, y, w, h)


def assoc(ax, p1, p2, style="-", color=LINE, label=None, lw=1.0):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-", color=color,
                                 lw=lw, linestyle=style,
                                 shrinkA=2, shrinkB=2))
    if label:
        mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
        ax.text(mx, my + 0.07, label, ha="center", va="bottom",
                fontsize=7.4, color=GREY, style="italic")


def dep(ax, p1, p2, label):
    """A dashed <<include>> / <<extend>> dependency with an open arrow head."""
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", color=GREY,
                                 lw=0.9, linestyle=(0, (5, 3)),
                                 mutation_scale=11, shrinkA=3, shrinkB=3))
    mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
    ax.text(mx, my + 0.05, label, ha="center", va="bottom",
            fontsize=7.2, color=GREY, style="italic")


def make_usecase():
    fig, ax = plt.subplots(figsize=(11.0, 7.4))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 7.4)
    ax.axis("off")

    # System boundary
    ax.add_patch(Rectangle((2.85, 0.45), 5.35, 6.5, fill=False,
                           edgecolor=EDGE, lw=1.6))
    ax.text(5.52, 6.72, "Hybrid Security Suite", ha="center", va="center",
            fontsize=11.5, fontweight="bold", color=EDGE)

    # Actors
    actor(ax, 1.35, 4.55, "User\n(Administrator)")
    actor(ax, 9.72, 2.55, "Ransomware\nProcess")
    ax.text(9.72, 1.72, "«external»", ha="center", va="top", fontsize=7.6,
            color=GREY, style="italic")

    # Use cases — user-initiated (upper block)
    uc_cfg = usecase(ax, 5.5, 6.15, "Configure detection\nthresholds")
    uc_dir = usecase(ax, 5.5, 5.53, "Select watched folder")
    uc_tog = usecase(ax, 5.5, 4.91, "Pause / resume\nmonitoring")
    uc_rev = usecase(ax, 5.5, 4.29, "Review alert details")
    uc_und = usecase(ax, 5.5, 3.67, "Reverse containment\n(unlock / resume)")
    uc_sus = usecase(ax, 5.5, 3.05, "Suspend responsible\nprocess")

    # System-internal use cases (lower block)
    uc_mon = usecase(ax, 5.5, 2.34, "Monitor file activity")
    uc_det = usecase(ax, 5.5, 1.66, "Detect ransomware\nbehaviour")
    uc_att = usecase(ax, 4.10, 0.92, "Attribute responsible\nprocess", w=2.0)
    uc_con = usecase(ax, 6.92, 0.92, "Contain attack", w=1.75)

    # Associations from the user
    ua = (1.72, 4.55)
    for uc in (uc_cfg, uc_dir, uc_tog, uc_rev, uc_und, uc_sus):
        assoc(ax, ua, (uc[0] - uc[2] / 2, uc[1]))

    # The ransomware actor does not "use" the system — it triggers detection
    assoc(ax, (9.35, 2.55), (uc_det[0] + uc_det[2] / 2, uc_det[1]),
          style=(0, (4, 3)), color=RED, label="triggers")

    # Internal flow
    dep(ax, (uc_mon[0], uc_mon[1] - uc_mon[3] / 2),
        (uc_det[0], uc_det[1] + uc_det[3] / 2), "«include»")
    dep(ax, (uc_det[0] - 0.35, uc_det[1] - uc_det[3] / 2),
        (uc_att[0] + 0.30, uc_att[1] + uc_att[3] / 2), "«include»")
    dep(ax, (uc_det[0] + 0.35, uc_det[1] - uc_det[3] / 2),
        (uc_con[0] - 0.30, uc_con[1] + uc_con[3] / 2), "«include»")
    dep(ax, (uc_und[0] + uc_und[2] / 2 - 0.30, uc_und[1] + uc_und[3] / 2),
        (uc_rev[0] + uc_rev[2] / 2 - 0.30, uc_rev[1] - uc_rev[3] / 2), "«extend»")
    # "Suspend" also extends "Review alert details" — it is offered from the
    # drill-down, so route it clear of the other extend line.
    ax.add_patch(FancyArrowPatch((uc_sus[0] + uc_sus[2] / 2, uc_sus[1]),
                                 (7.72, uc_sus[1]), arrowstyle="-",
                                 color=GREY, lw=0.9, linestyle=(0, (5, 3))))
    ax.add_patch(FancyArrowPatch((7.72, uc_sus[1]), (7.72, uc_rev[1]),
                                 arrowstyle="-", color=GREY, lw=0.9,
                                 linestyle=(0, (5, 3))))
    ax.add_patch(FancyArrowPatch((7.72, uc_rev[1]),
                                 (uc_rev[0] + uc_rev[2] / 2, uc_rev[1]),
                                 arrowstyle="-|>", color=GREY, lw=0.9,
                                 linestyle=(0, (5, 3)), mutation_scale=11,
                                 shrinkB=3))
    ax.text(7.80, (uc_sus[1] + uc_rev[1]) / 2, "«extend»", ha="left",
            va="center", fontsize=7.2, color=GREY, style="italic", rotation=90)

    # Note on the privilege constraint
    ax.add_patch(FancyBboxPatch((0.35, 0.55), 2.15, 1.15,
                                boxstyle="round,pad=0.06", facecolor="#fdf6e3",
                                edgecolor="#c9a227", lw=1.0))
    ax.text(1.42, 1.12,
            "Process attribution and\nlive containment require\n"
            "Administrator privilege;\notherwise the system\n"
            "degrades gracefully.",
            ha="center", va="center", fontsize=7.6, color=INK, linespacing=1.4)

    fig.tight_layout()
    p = os.path.join(OUT, "fig_usecase.png")
    fig.savefig(p, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return p


# ═════════════════════════════════════════════════════════════════════════════
#  Activity Diagram
# ═════════════════════════════════════════════════════════════════════════════
def act_box(ax, x, y, text, w=2.5, h=0.52, fc=FILL, ec=EDGE, fs=8.6):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.02,rounding_size=0.12",
                                facecolor=fc, edgecolor=ec, lw=1.2))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=INK,
            linespacing=1.25)
    return (x, y, w, h)


def decision(ax, x, y, text, w=1.55, h=0.78, fs=8.2):
    ax.add_patch(plt.Polygon([[x, y + h / 2], [x + w / 2, y],
                              [x, y - h / 2], [x - w / 2, y]],
                             facecolor="#fdf6e3", edgecolor="#c9a227", lw=1.2))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=INK,
            linespacing=1.2)
    return (x, y, w, h)


def flow(ax, p1, p2, label=None, color=LINE, lab_dx=0.0, lab_dy=0.0,
         ha="center", style="-"):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", color=color, lw=1.2,
                                 linestyle=style, mutation_scale=12,
                                 shrinkA=1, shrinkB=3,
                                 connectionstyle="arc3,rad=0"))
    if label:
        mx, my = (p1[0] + p2[0]) / 2 + lab_dx, (p1[1] + p2[1]) / 2 + lab_dy
        ax.text(mx, my, label, ha=ha, va="center", fontsize=7.8,
                color=GREY, fontweight="bold")


def elbow(ax, p1, p2, label=None, color=LINE, lab_dy=0.08):
    """Right-angle connector: horizontal first, then vertical."""
    mid = (p2[0], p1[1])
    ax.add_patch(FancyArrowPatch(p1, mid, arrowstyle="-", color=color, lw=1.2))
    ax.add_patch(FancyArrowPatch(mid, p2, arrowstyle="-|>", color=color, lw=1.2,
                                 mutation_scale=12, shrinkB=3))
    if label:
        ax.text((p1[0] + mid[0]) / 2, p1[1] + lab_dy, label, ha="center",
                va="bottom", fontsize=7.8, color=GREY, fontweight="bold")


def make_activity():
    fig, ax = plt.subplots(figsize=(9.2, 11.6))
    ax.set_xlim(0, 9.2)
    ax.set_ylim(0, 11.6)
    ax.axis("off")

    cx = 3.55          # main column
    rx = 7.35          # right-hand terminator column

    # Start node
    ax.add_patch(Circle((cx, 11.15), 0.13, facecolor=INK, edgecolor=INK))
    y = 11.15

    b_evt = act_box(ax, cx, 10.42,
                    "Capture file event\n(ReadDirectoryChangesW)", w=3.05)
    flow(ax, (cx, y - 0.13), (cx, b_evt[1] + b_evt[3] / 2))

    b_att = act_box(ax, cx, 9.60, "Attribute PID via ETW", w=3.05)
    flow(ax, (cx, b_evt[1] - b_evt[3] / 2), (cx, b_att[1] + b_att[3] / 2))

    d_etw = decision(ax, cx, 8.72, "ETW record\navailable?")
    flow(ax, (cx, b_att[1] - b_att[3] / 2), (cx, d_etw[1] + d_etw[3] / 2))

    b_heu = act_box(ax, 6.85, 8.72, "Tag as HEUR\n(heuristic fallback)",
                    w=2.35, fc="#f6f1f6", ec=GREY)
    flow(ax, (cx + d_etw[2] / 2, d_etw[1]), (b_heu[0] - b_heu[2] / 2, b_heu[1]),
         label="no", lab_dy=0.15)

    d_can = decision(ax, cx, 7.78, "Is the file\na canary?")
    flow(ax, (cx, d_etw[1] - d_etw[3] / 2), (cx, d_can[1] + d_can[3] / 2),
         label="yes", lab_dx=0.28)
    # heuristic branch rejoins
    ax.add_patch(FancyArrowPatch((b_heu[0], b_heu[1] - b_heu[3] / 2),
                                 (b_heu[0], 7.78), arrowstyle="-", color=GREY, lw=1.2))
    ax.add_patch(FancyArrowPatch((b_heu[0], 7.78), (cx + d_can[2] / 2, 7.78),
                                 arrowstyle="-|>", color=GREY, lw=1.2,
                                 mutation_scale=12, shrinkB=3))

    b_win = act_box(ax, cx, 6.86, "Append event to the\nper-PID sliding window",
                    w=3.05)
    flow(ax, (cx, d_can[1] - d_can[3] / 2), (cx, b_win[1] + b_win[3] / 2),
         label="no", lab_dx=0.24)

    d_rate = decision(ax, cx, 5.92,
                      "events within t\n≥ k ?", w=1.9, h=0.86)
    flow(ax, (cx, b_win[1] - b_win[3] / 2), (cx, d_rate[1] + d_rate[3] / 2))

    b_end1 = act_box(ax, rx, 5.92, "Wait for the\nnext event", w=1.85,
                     fc="#f2f2f2", ec=GREY)
    flow(ax, (cx + d_rate[2] / 2, d_rate[1]), (b_end1[0] - b_end1[2] / 2, b_end1[1]),
         label="no", lab_dy=0.15)

    b_ent = act_box(ax, cx, 4.98, "Sample write-entropy of\nrecent distinct files",
                    w=3.35)
    flow(ax, (cx, d_rate[1] - d_rate[3] / 2), (cx, b_ent[1] + b_ent[3] / 2),
         label="yes", lab_dx=0.26)

    d_ent = decision(ax, cx, 4.02, "median entropy\n≥ threshold ?",
                     w=2.2, h=0.86, fs=7.9)
    flow(ax, (cx, b_ent[1] - b_ent[3] / 2), (cx, d_ent[1] + d_ent[3] / 2))

    b_sup = act_box(ax, rx, 4.02, "Suppress —\nbenign burst", w=1.85,
                    fc="#eaf5ec", ec=GREEN)
    flow(ax, (cx + d_ent[2] / 2, d_ent[1]), (b_sup[0] - b_sup[2] / 2, b_sup[1]),
         label="no", lab_dy=0.15)

    # Alert path
    b_alert = act_box(ax, cx, 3.06, "Raise ransomware alert", w=3.05,
                      fc="#fdeceb", ec=RED)
    flow(ax, (cx, d_ent[1] - d_ent[3] / 2), (cx, b_alert[1] + b_alert[3] / 2),
         label="yes", lab_dx=0.26)
    # canary shortcut into the alert
    ax.add_patch(FancyArrowPatch((cx - d_can[2] / 2, d_can[1]), (1.15, d_can[1]),
                                 arrowstyle="-", color=RED, lw=1.2))
    ax.add_patch(FancyArrowPatch((1.15, d_can[1]), (1.15, b_alert[1]),
                                 arrowstyle="-", color=RED, lw=1.2))
    ax.add_patch(FancyArrowPatch((1.15, b_alert[1]), (cx - b_alert[2] / 2, b_alert[1]),
                                 arrowstyle="-|>", color=RED, lw=1.2,
                                 mutation_scale=12, shrinkB=3))
    ax.text(1.05, (d_can[1] + b_alert[1]) / 2,
            "yes — canary tripped\n(first file, no thresholds)",
            ha="center", va="center", fontsize=7.6, color=RED,
            fontweight="bold", rotation=90, linespacing=1.3)

    b_lock = act_box(ax, cx, 2.20,
                     "Contain: icacls directory lockdown", w=3.6,
                     fc="#fdeceb", ec=RED)
    flow(ax, (cx, b_alert[1] - b_alert[3] / 2), (cx, b_lock[1] + b_lock[3] / 2))

    b_log = act_box(ax, cx, 1.38,
                    "Persist alert row\n(status, files, attribution, entropy)",
                    w=3.6)
    flow(ax, (cx, b_lock[1] - b_lock[3] / 2), (cx, b_log[1] + b_log[3] / 2))

    b_ui = act_box(ax, cx, 0.62, "Notify dashboard\n(banner, sound, graph)", w=3.05)
    flow(ax, (cx, b_log[1] - b_log[3] / 2), (cx, b_ui[1] + b_ui[3] / 2))

    # End node
    ax.add_patch(Circle((rx, 0.62), 0.155, fill=False, edgecolor=INK, lw=1.3))
    ax.add_patch(Circle((rx, 0.62), 0.095, facecolor=INK, edgecolor=INK))
    flow(ax, (cx + b_ui[2] / 2, b_ui[1]), (rx - 0.20, b_ui[1]))

    # The two early-exit branches leave to the right and drop down a clear
    # column, so neither dashed line crosses a box on its way to the end node.
    col = 8.72
    for b in (b_end1, b_sup):
        ax.add_patch(FancyArrowPatch((b[0] + b[2] / 2, b[1]), (col, b[1]),
                                     arrowstyle="-", color=GREY, lw=1.0,
                                     linestyle=(0, (4, 3))))
        ax.add_patch(FancyArrowPatch((col, b[1]), (col, 0.62),
                                     arrowstyle="-", color=GREY, lw=1.0,
                                     linestyle=(0, (4, 3))))
    ax.add_patch(FancyArrowPatch((col, 0.62), (rx + 0.20, 0.62),
                                 arrowstyle="-|>", color=GREY, lw=1.0,
                                 linestyle=(0, (4, 3)), mutation_scale=11,
                                 shrinkB=3))

    fig.tight_layout()
    p = os.path.join(OUT, "fig_activity.png")
    fig.savefig(p, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return p


if __name__ == "__main__":
    for p in (make_usecase(), make_activity()):
        print("wrote", os.path.basename(p))
