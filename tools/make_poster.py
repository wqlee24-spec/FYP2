# -*- coding: utf-8 -*-
"""Generate the FYP2 poster (A4, JPEG) to UTAR guideline section 3.2:

    1  Size          A4 paper
    2  Font          contrasting fonts for the title, text and figure legends,
                     large enough to read
    3  Elements      photos / figures / tables, a logical sequence, organised into
                     Introduction, Methods, Results, Discussion and Conclusions,
                     and arranged into columns
    4  File type     JPEG / TIFF / BMP / EPS

Contrasting font families are used deliberately: a heavy sans for the title and
section headings, a regular sans for body text, and a serif italic for every
figure legend.

    python tools/make_poster.py
"""
import os
import textwrap

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.patches import Rectangle, FancyBboxPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "report_figures")
OUT_JPG = os.path.join(ROOT, "FYP2_Poster.jpg")
OUT_TIF = os.path.join(ROOT, "FYP2_Poster.tif")

# ── Palette ──────────────────────────────────────────────────────────────────
NAVY = "#0d1b2a"
CYAN = "#00a6ce"
DEEP = "#0d6f8c"
INK = "#141414"
GREY = "#5a636b"
RED = "#b03a2e"
GREEN = "#1e7a3c"
BAND = "#eef4f8"
PAPER = "#ffffff"

# Contrasting families (guideline item 2)
F_TITLE = "DejaVu Sans"      # heavy sans - title and headings
F_BODY = "DejaVu Sans"       # regular sans - body text
F_LEG = "DejaVu Serif"       # serif italic - figure legends

A4_W, A4_H = 8.27, 11.69

fig = plt.figure(figsize=(A4_W, A4_H), dpi=300)
fig.patch.set_facecolor(PAPER)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis("off")


# ── Helpers ──────────────────────────────────────────────────────────────────
def rect(x, y, w, h, fc, ec="none", lw=0, z=1, round_=False):
    if round_:
        p = FancyBboxPatch((x, y), w, h,
                           boxstyle="round,pad=0,rounding_size=0.008",
                           facecolor=fc, edgecolor=ec, lw=lw, zorder=z)
    else:
        p = Rectangle((x, y), w, h, facecolor=fc, edgecolor=ec, lw=lw, zorder=z)
    ax.add_patch(p)
    return p


def section(x, y, w, label):
    """A section header bar."""
    rect(x, y, w, 0.019, NAVY, z=3)
    ax.text(x + 0.010, y + 0.0095, label, ha="left", va="center",
            fontsize=11.5, fontweight="bold", color="white",
            family=F_TITLE, zorder=4)
    return y


def body(x, y, w, text, size=7.6, color=INK, wrap=None, lh=1.42,
         weight="normal", style="normal", family=None):
    """Wrapped body text; returns the y of the bottom of the block."""
    chars = wrap or int(w * 128)
    lines = []
    for para in text.split("\n"):
        lines.extend(textwrap.wrap(para, chars) or [""])
    t = "\n".join(lines)
    ax.text(x, y, t, ha="left", va="top", fontsize=size, color=color,
            family=family or F_BODY, linespacing=lh, weight=weight,
            style=style, zorder=4)
    return y - len(lines) * size * lh / 720.0


def bullets(x, y, w, items, size=7.6, gap=0.0045, marker="▪"):
    for text, color, bold in items:
        chars = int(w * 122)
        lines = textwrap.wrap(text, chars)
        ax.text(x, y, marker, ha="left", va="top", fontsize=size - 0.6,
                color=CYAN if not bold else color, family=F_BODY, zorder=4)
        ax.text(x + 0.014, y, "\n".join(lines), ha="left", va="top",
                fontsize=size, color=color, family=F_BODY, linespacing=1.42,
                weight="bold" if bold else "normal", zorder=4)
        y -= len(lines) * size * 1.42 / 720.0 + gap
    return y


def legend(x, y, w, text, size=6.6):
    """Figure legend - serif italic, deliberately contrasting with the body."""
    lines = textwrap.wrap(text, int(w * 150))
    ax.text(x + w / 2, y, "\n".join(lines), ha="center", va="top",
            fontsize=size, color=GREY, family=F_LEG, style="italic",
            linespacing=1.35, zorder=4)
    return y - len(lines) * size * 1.35 / 720.0


def image(path, x, y, w, h, border=True):
    """Place an image inside the box (x, y, w, h), preserving aspect ratio."""
    full = os.path.join(FIG, path)
    if not os.path.exists(full):
        rect(x, y, w, h, BAND, ec=GREY, lw=0.6, z=2)
        ax.text(x + w / 2, y + h / 2, f"[{path}]", ha="center", va="center",
                fontsize=7, color=GREY, family=F_LEG, style="italic", zorder=4)
        return y
    img = mpimg.imread(full)
    ih, iw = img.shape[0], img.shape[1]
    box_ar = (w * A4_W) / (h * A4_H)
    img_ar = iw / ih
    if img_ar > box_ar:                      # width-limited
        dw = w
        dh = (w * A4_W / img_ar) / A4_H
    else:                                    # height-limited
        dh = h
        dw = (h * A4_H * img_ar) / A4_W
    dx = x + (w - dw) / 2
    dy = y + (h - dh)
    a = fig.add_axes([dx, dy, dw, dh], zorder=5)
    a.imshow(img)
    a.axis("off")
    if border:
        rect(dx, dy, dw, dh, "none", ec="#c8d4dc", lw=0.7, z=6)
    return dy


def kpi(x, y, w, h, value, label, color):
    rect(x, y, w, h, BAND, ec="#d6e2ea", lw=0.6, z=2, round_=True)
    ax.text(x + w / 2, y + h * 0.60, value, ha="center", va="center",
            fontsize=11.5, fontweight="bold", color=color, family=F_TITLE, zorder=4)
    ax.text(x + w / 2, y + h * 0.22, label, ha="center", va="center",
            fontsize=6.0, color=GREY, family=F_BODY, zorder=4)


def table(x, y, w, rows, col_w, size=6.9, rh=0.0165):
    """Simple table: rows[0] is the header."""
    for i, row in enumerate(rows):
        yy = y - i * rh
        rect(x, yy - rh, w, rh, NAVY if i == 0 else (PAPER if i % 2 else BAND),
             ec="#d6e2ea", lw=0.4, z=2)
        cx = x
        for j, cell in enumerate(row):
            ax.text(cx + 0.006, yy - rh / 2, str(cell), ha="left", va="center",
                    fontsize=size, family=F_BODY,
                    color="white" if i == 0 else INK,
                    fontweight="bold" if i == 0 else "normal", zorder=4)
            cx += col_w[j]
    return y - len(rows) * rh


# ═════════════════════════════════════════════════════════════════════════════
#  HEADER
# ═════════════════════════════════════════════════════════════════════════════
rect(0, 0.918, 1, 0.082, NAVY, z=1)
rect(0, 0.9145, 1, 0.0035, CYAN, z=2)

ax.text(0.5, 0.982, "Design and Development of a Rule-Based Threat Monitoring",
        ha="center", va="center", fontsize=13.4, fontweight="bold",
        color="white", family=F_TITLE, zorder=4)
ax.text(0.5, 0.9645, "and Ransomware Containment System for Windows Platforms",
        ha="center", va="center", fontsize=13.4, fontweight="bold",
        color="white", family=F_TITLE, zorder=4)
ax.text(0.5, 0.9455, "Lee Wen Qi     |     Supervisor:  Ms. Oh Zi Xin     |     "
                     "Hybrid Security Suite",
        ha="center", va="center", fontsize=8.6, color="#9fd8e8",
        family=F_BODY, zorder=4)
ax.text(0.5, 0.9305, "Faculty of Information and Communication Technology "
                     "(Kampar Campus),  Universiti Tunku Abdul Rahman",
        ha="center", va="center", fontsize=7.4, color="#c5d3db",
        family=F_BODY, zorder=4)

# Column geometry
LX, RX, CW = 0.035, 0.513, 0.452

# ═════════════════════════════════════════════════════════════════════════════
#  LEFT COLUMN
# ═════════════════════════════════════════════════════════════════════════════
y = 0.888
section(LX, y, CW, "1.  INTRODUCTION")
y -= 0.028
y = body(LX, y, CW,
         "Ransomware encrypts a victim's files within seconds. Effective behavioural "
         "defences rely on kernel-mode drivers that are costly to deploy, while free "
         "consumer tools are opaque and cannot be undone.")
y -= 0.008
y = bullets(LX, y, CW, [
    ("User-space monitoring cannot identify WHICH process changed a file",
     INK, False),
    ("Rate-only detection false-alarms on fast benign activity such as extraction",
     INK, False),
    ("Existing containment is irreversible — a false positive locks the user out",
     INK, False),
], gap=0.0035)

y -= 0.010
section(LX, y, CW, "2.  OBJECTIVES")
y -= 0.027
y = bullets(LX, y, CW, [
    ("Detect ransomware in real time from user space, with no kernel driver",
     INK, False),
    ("Reduce false alarms using write-entropy and canary decoy files", INK, False),
    ("Attribute the responsible process accurately using ETW", INK, False),
    ("Contain reversibly — every action undoable from the dashboard", INK, False),
], gap=0.0035)

y -= 0.010
section(LX, y, CW, "3.  METHODS")
y -= 0.026
y = body(LX, y, CW,
         "A C++ agent answers WHAT changed using ReadDirectoryChangesW and WHO changed "
         "it using ETW, streaming events over a named pipe to a Python analysis engine.")
y -= 0.006
y = image("fig_architecture.png", LX, y - 0.295, CW, 0.295)
y = legend(LX, y - 0.007, CW,
           "Figure 1.  System architecture — every component runs in user space; "
           "no kernel-mode driver is required.")

y -= 0.014
y = body(LX, y, CW,
         "Each layer covers the previous one's blind spot. The entropy gate only ever "
         "suppresses on positive low-entropy evidence, so it cannot cause a false "
         "negative.", size=7.4)
print("  left column ends at y = %.3f" % y)

# ═════════════════════════════════════════════════════════════════════════════
#  RIGHT COLUMN
# ═════════════════════════════════════════════════════════════════════════════
y = 0.888
section(RX, y, CW, "4.  RESULTS")
y -= 0.028

kw = (CW - 0.016) / 3
for i, (v, l, c) in enumerate([
        ("1240 → 17 ms", "Detection latency (p50)", GREEN),
        ("8.1 → <1 %", "Agent CPU overhead", GREEN),
        ("5 → 0 %", "Event loss", GREEN)]):
    kpi(RX + i * (kw + 0.008), y - 0.040, kw, 0.040, v, l, c)
y -= 0.050

y = table(RX, y, CW,
          [["Evaluation", "Outcome"],
           ["Attack scenarios detected", "no false negatives"],
           ["Archive extraction (rate only)", "false positive"],
           ["Archive extraction (+ entropy)", "true negative"],
           ["ETW attribution, elevated", "kernel-reported PID"]],
          col_w=[0.268, 0.184], size=6.9)

y -= 0.014
y = image("fig_ransap_ml_vs_entropy.png", RX, y - 0.105, CW, 0.105)
y = legend(RX, y - 0.007, CW,
           "Figure 2.  RanSAP real-world dataset: multi-feature classifier "
           "versus an entropy threshold alone.")

y -= 0.012
y = image("fig_drilldown.png", RX, y - 0.142, CW, 0.142)
y = legend(RX, y - 0.007, CW,
           "Figure 3.  Every alert is explained, with reversible containment "
           "controls.")

y -= 0.014
section(RX, y, CW, "5.  DISCUSSION")
y -= 0.027
y = body(RX, y, CW,
         "On the RanSAP dataset the highest write-entropy comes not from ransomware "
         "but from legitimate encryption and compression tools such as AESCrypt and "
         "Zip. An entropy threshold alone therefore reaches only about 64 % accuracy, "
         "while a multi-feature classifier separates the classes almost perfectly.",
         size=7.4)
y -= 0.006
y = body(RX, y, CW,
         "Entropy is necessary but not sufficient — the empirical justification for "
         "layering rate, entropy and canary evidence rather than trusting any single "
         "measure.", size=7.4, weight="bold", color=RED)

y -= 0.014
section(RX, y, CW, "6.  CONCLUSIONS")
y -= 0.027
y = bullets(RX, y, CW, [
    ("Effective, fully reversible ransomware containment is achievable entirely in "
     "user space", INK, True),
    ("No false negatives, detection in tens of milliseconds, under 1 % CPU", INK, False),
    ("ETW gives accurate user-mode attribution, making a process-targeted "
     "response safe to offer", INK, False),
    ("Every containment action is explained to the user and can be undone", INK, False),
], size=7.4, gap=0.004)
print("  right column ends at y = %.3f  (footer top = 0.030)" % y)

# ═════════════════════════════════════════════════════════════════════════════
#  FOOTER
# ═════════════════════════════════════════════════════════════════════════════
rect(0, 0.0, 1, 0.030, NAVY, z=3)
ax.text(0.5, 0.015,
        "Future work:   live ML gate   ·   automatic containment   ·   "
        "multi-folder monitoring   ·   self-healing backup   ·   "
        "commercial code-signing certificate",
        ha="center", va="center", fontsize=7.0, color="#9fd8e8",
        family=F_BODY, zorder=5)

fig.savefig(OUT_JPG, dpi=300, format="jpg", facecolor=PAPER,
            pil_kwargs={"quality": 94})
fig.savefig(OUT_TIF, dpi=300, format="tiff", facecolor=PAPER)
plt.close(fig)
print("wrote FYP2_Poster.jpg and FYP2_Poster.tif  (A4, 300 dpi)")
