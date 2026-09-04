# -*- coding: utf-8 -*-
"""Generate the FYP2 viva presentation deck (FYP2_Presentation.pptx).

Built to UTAR FYP2 guideline section 5 (Viva: Oral Presentation and Project
Demonstration): the presentation must describe the aim of the project, an
outline of the presentation, the results obtained, and the extent to which the
goals of the project are met. Time allocated is 15-20 minutes plus 10 minutes
of Q&A, so the deck is paced at roughly one slide per minute.

Figures are pulled from report_figures/ so the slides and the report always
show the same evidence. Missing figures degrade to a labelled placeholder
rather than breaking the build.

    python tools/make_slides.py
"""
import os

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "report_figures")
OUT = os.path.join(ROOT, "FYP2_Presentation.pptx")

# ── Palette ──────────────────────────────────────────────────────────────────
# Light background: projectors and printed handouts both stay legible, unlike
# the dark UI theme.
NAVY = RGBColor(0x0D, 0x1B, 0x2A)
CYAN = RGBColor(0x00, 0x7A, 0x99)
ACCENT = RGBColor(0x00, 0xA6, 0xCE)
INK = RGBColor(0x1A, 0x1A, 0x1A)
GREY = RGBColor(0x5A, 0x63, 0x6B)
RED = RGBColor(0xC0, 0x39, 0x2B)
GREEN = RGBColor(0x1E, 0x8E, 0x3E)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
BAND = RGBColor(0xF2, 0xF6, 0xF8)

FONT = "Calibri"
W, H = Inches(13.333), Inches(7.5)          # 16:9

prs = Presentation()
prs.slide_width, prs.slide_height = W, H
BLANK = prs.slide_layouts[6]


# ── Helpers ──────────────────────────────────────────────────────────────────
def _tf(box, text, size, color=INK, bold=False, align=PP_ALIGN.LEFT,
        italic=False, space_after=6):
    tf = box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = color
    r.font.name = FONT
    p.space_after = Pt(space_after)
    return tf


def _para(tf, text, size, color=INK, bold=False, level=0, italic=False,
          space_before=0, space_after=6):
    p = tf.add_paragraph()
    p.level = level
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = color
    r.font.name = FONT
    p.space_before = Pt(space_before)
    p.space_after = Pt(space_after)
    return p


def _rect(slide, x, y, w, h, fill):
    from pptx.enum.shapes import MSO_SHAPE
    s = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    s.fill.solid()
    s.fill.fore_color.rgb = fill
    s.line.fill.background()
    s.shadow.inherit = False
    return s


def slide(title, kicker=None):
    """A content slide with the standard header."""
    s = prs.slides.add_slide(BLANK)
    _rect(s, 0, 0, W, Inches(1.15), NAVY)
    _rect(s, 0, Inches(1.15), W, Inches(0.06), ACCENT)
    box = s.shapes.add_textbox(Inches(0.6), Inches(0.18), W - Inches(1.2), Inches(0.9))
    tf = _tf(box, title, 30, WHITE, bold=True)
    if kicker:
        _para(tf, kicker, 13, RGBColor(0x9F, 0xD8, 0xE8))
    return s


def body(s, top=Inches(1.55), left=Inches(0.85), width=None, height=None):
    width = width or (W - Inches(1.7))
    height = height or (H - top - Inches(0.7))
    return s.shapes.add_textbox(left, top, width, height)


def bullets(s, items, size=19, top=Inches(1.7), left=Inches(0.9), width=None):
    """items: list of (text, level, bold, colour)."""
    box = body(s, top=top, left=left, width=width)
    tf = box.text_frame
    tf.word_wrap = True
    first = True
    for text, level, bold, color in items:
        prefix = "" if level == 0 else ("–  " if level == 1 else "·  ")
        if first:
            p = tf.paragraphs[0]
            first = False
        else:
            p = tf.add_paragraph()
        p.level = level
        r = p.add_run()
        r.text = ("•  " if level == 0 else prefix) + text
        r.font.size = Pt(size if level == 0 else size - 3)
        r.font.bold = bold
        r.font.color.rgb = color
        r.font.name = FONT
        p.space_after = Pt(10 if level == 0 else 5)
    return box


def picture(s, filename, top=Inches(1.6), height=Inches(4.9), caption=None):
    path = os.path.join(FIG, filename)
    if os.path.exists(path):
        pic = s.shapes.add_picture(path, Inches(0), top, height=height)
        if pic.width > W - Inches(1.6):                 # too wide: fit to width
            s.shapes._spTree.remove(pic._element)
            pic = s.shapes.add_picture(path, Inches(0.8), top, width=W - Inches(1.6))
        pic.left = int((W - pic.width) / 2)
    else:
        ph = _rect(s, Inches(3.2), top, Inches(6.9), Inches(3.6), BAND)
        _tf(ph.text_frame and ph or ph, "", 1)          # keep shape simple
        tb = s.shapes.add_textbox(Inches(3.2), top + Inches(1.5), Inches(6.9), Inches(0.8))
        _tf(tb, f"[ insert {filename} ]", 16, GREY, align=PP_ALIGN.CENTER, italic=True)
    if caption:
        cb = s.shapes.add_textbox(Inches(0.8), H - Inches(0.95), W - Inches(1.6), Inches(0.5))
        _tf(cb, caption, 13, GREY, align=PP_ALIGN.CENTER, italic=True)


def notes(s, text):
    s.notes_slide.notes_text_frame.text = text


def kpi_row(s, items, top=Inches(4.9)):
    """items: list of (value, label, colour)."""
    n = len(items)
    gap = Inches(0.25)
    cw = int((W - Inches(1.6) - gap * (n - 1)) / n)
    x = Inches(0.8)
    for value, label, color in items:
        _rect(s, x, top, cw, Inches(1.35), BAND)
        vb = s.shapes.add_textbox(x, top + Inches(0.12), cw, Inches(0.65))
        _tf(vb, value, 26, color, bold=True, align=PP_ALIGN.CENTER)
        lb = s.shapes.add_textbox(x, top + Inches(0.78), cw, Inches(0.45))
        _tf(lb, label, 12, GREY, align=PP_ALIGN.CENTER)
        x += cw + gap


def table(s, rows, top=Inches(1.75), col_w=None, size=14):
    nrow, ncol = len(rows), len(rows[0])
    col_w = col_w or [int((W - Inches(1.7)) / ncol)] * ncol
    height = Inches(0.45) * nrow
    shp = s.shapes.add_table(nrow, ncol, Inches(0.85), top,
                             sum(col_w), height).table
    for j, cw in enumerate(col_w):
        shp.columns[j].width = cw
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            cell = shp.cell(i, j)
            cell.text = ""
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.margin_left = Inches(0.12)
            p = cell.text_frame.paragraphs[0]
            r = p.add_run()
            r.text = str(val)
            r.font.size = Pt(size)
            r.font.name = FONT
            r.font.bold = (i == 0)
            r.font.color.rgb = WHITE if i == 0 else INK
            cell.fill.solid()
            cell.fill.fore_color.rgb = NAVY if i == 0 else (WHITE if i % 2 else BAND)
    return shp


# ═════════════════════════════════════════════════════════════════════════════
# 1 — Title
# ═════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(BLANK)
_rect(s, 0, 0, W, H, NAVY)
_rect(s, 0, Inches(3.42), W, Inches(0.05), ACCENT)

tb = s.shapes.add_textbox(Inches(1.0), Inches(1.5), W - Inches(2.0), Inches(1.9))
tf = _tf(tb, "Design and Development of a Rule-Based Threat Monitoring",
         34, WHITE, bold=True, align=PP_ALIGN.CENTER)
_para(tf, "and Ransomware Containment System for Windows Platforms",
      34, WHITE, bold=True)
for p in tf.paragraphs:
    p.alignment = PP_ALIGN.CENTER

tb = s.shapes.add_textbox(Inches(1.0), Inches(3.75), W - Inches(2.0), Inches(2.2))
tf = _tf(tb, "Lee Wen Qi", 24, RGBColor(0x9F, 0xD8, 0xE8), bold=True,
         align=PP_ALIGN.CENTER)
_para(tf, "Supervisor:  Ms. Oh Zi Xin", 18, WHITE, space_before=10)
_para(tf, "Bachelor of Information Technology (Honours) Communications and Networking",
      15, RGBColor(0xC5, 0xD3, 0xDB), space_before=14)
_para(tf, "Faculty of Information and Communication Technology (Kampar Campus)",
      15, RGBColor(0xC5, 0xD3, 0xDB))
_para(tf, "Universiti Tunku Abdul Rahman", 15, RGBColor(0xC5, 0xD3, 0xDB))
for p in tf.paragraphs:
    p.alignment = PP_ALIGN.CENTER
notes(s, "Good morning. My name is Lee Wen Qi and this is my Final Year Project "
         "Two, supervised by Ms. Oh Zi Xin. The project builds a ransomware "
         "detection and containment system for Windows that runs entirely in "
         "user space.")

# ═════════════════════════════════════════════════════════════════════════════
# 2 — Outline (required by the guideline)
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Outline", "What this presentation covers")
bullets(s, [
    ("Problem and motivation", 0, True, INK),
    ("Aim, objectives and scope", 0, True, INK),
    ("Research gap in existing defences", 0, True, INK),
    ("System design — three-layer detection and reversible containment", 0, True, INK),
    ("Implementation", 0, True, INK),
    ("Evaluation and results", 0, True, INK),
    ("Extent to which the objectives are met", 0, True, INK),
    ("Limitations, future work and conclusion", 0, True, INK),
], size=20, top=Inches(1.9))
notes(s, "I will begin with the problem, then state the aim and objectives, "
         "explain the design, show the evaluation results, and finish by "
         "assessing how far each objective has been met.")

# ═════════════════════════════════════════════════════════════════════════════
# 3 — Background and problem
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Background and Motivation", "Why ransomware, and why this gap matters")
bullets(s, [
    ("Ransomware encrypts a victim's files within seconds and demands payment", 0, False, INK),
    ("Damage is done long before a signature is available — detection must be behavioural", 1, False, GREY),
    ("Enterprise defences rely on kernel-mode drivers", 0, False, INK),
    ("Costly, require signed drivers and WDK, and are hard for small organisations to deploy", 1, False, GREY),
    ("Free consumer tools are opaque", 0, False, INK),
    ("The user cannot see why an alert fired, and containment cannot be undone", 1, False, GREY),
    ("Individuals and small organisations are therefore left effectively unprotected", 0, True, RED),
], size=19)
notes(s, "Ransomware is fast, so a behavioural approach is necessary. The tools "
         "that do this well need kernel drivers, which small organisations "
         "cannot realistically deploy. That is the gap this project targets.")

# ═════════════════════════════════════════════════════════════════════════════
# 4 — Problem statement
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Problem Statement", "Three specific technical problems")
table(s, [
    ["Problem", "Consequence"],
    ["User-space monitoring cannot identify WHICH\nprocess changed a file",
     "Containment cannot safely target a process — the\nwrong one, even the monitor itself, may be killed"],
    ["Rate-only detection cannot separate ransomware\nfrom fast benign activity",
     "Extracting an archive looks identical to an attack,\nproducing false alarms"],
    ["Containment in existing tools is irreversible",
     "A false positive locks the user out of their own\nfiles with no way back"],
], top=Inches(1.9), col_w=[Inches(5.4), Inches(6.2)], size=15)
notes(s, "These three problems drive the three main contributions: ETW "
         "attribution, the entropy and canary layers, and reversible containment.")

# ═════════════════════════════════════════════════════════════════════════════
# 5 — Aim and objectives (required)
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Aim and Objectives", "The goals against which the project is assessed")
box = body(s, top=Inches(1.65))
tf = box.text_frame
tf.word_wrap = True
p = tf.paragraphs[0]
r = p.add_run()
r.text = ("Aim:  to design and develop a transparent, deployable ransomware "
          "detection and containment system for Windows that operates entirely "
          "in user space.")
r.font.size = Pt(19)
r.font.bold = True
r.font.color.rgb = CYAN
r.font.name = FONT
p.space_after = Pt(16)
for i, (t, d) in enumerate([
    ("Detect ransomware in real time from user space",
     "behavioural detection, no kernel-mode driver"),
    ("Reduce false alarms on fast benign file activity",
     "add write-entropy and decoy-file evidence to the rate heuristic"),
    ("Attribute the responsible process accurately",
     "replace the PID heuristic with Event Tracing for Windows"),
    ("Contain an attack reversibly",
     "every containment action must be undoable from the dashboard"),
    ("Evaluate the system against realistic ransomware behaviour",
     "simulator, benign stressors and a real-world dataset"),
]):
    _para(tf, f"Objective {i + 1}   {t}", 18, INK, bold=True, space_before=6, space_after=2)
    _para(tf, d, 15, GREY, level=1, space_after=8)
notes(s, "The aim is transparency and deployability. Five objectives follow "
         "from it, and I will return to each one near the end of the "
         "presentation to show how far it has been met.")

# ═════════════════════════════════════════════════════════════════════════════
# 6 — Scope
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Project Scope", "What is in scope, and what deliberately is not")
bullets(s, [
    ("In scope", 0, True, GREEN),
    ("Ransomware detection and containment on Windows 10 / 11 (x64)", 1, False, INK),
    ("User-space only — no kernel driver, no Windows Driver Kit, no driver signing", 1, False, INK),
    ("A single watched folder, user-configurable and persisted", 1, False, INK),
    ("An interactive dashboard with full drill-down into every alert", 1, False, INK),
    ("Out of scope", 0, True, RED),
    ("Network intrusion detection — removed on the moderator's instruction so that "
     "the project focuses solely on ransomware", 1, False, INK),
    ("Recovery of files already encrypted before detection", 1, False, INK),
    ("Live machine-learning inference — the classifier is evaluated offline", 1, False, INK),
], size=18)
notes(s, "The scope was narrowed in FYP2 on the moderator's instruction to "
         "ransomware only. The user-space constraint is the defining design "
         "decision of the whole project.")

# ═════════════════════════════════════════════════════════════════════════════
# 7 — Research gap
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Research Gap", "How the proposed system differs from existing defences")
table(s, [
    ["System", "Kernel driver", "Explains alerts", "Reversible containment"],
    ["Windows Defender Controlled Folder Access", "Yes", "No", "Partial"],
    ["ShieldFS", "Yes (driver)", "Limited", "Yes (copy-on-write)"],
    ["CryptoDrop", "Yes", "Limited", "No"],
    ["UNVEIL", "Yes (sandbox)", "No", "Not applicable"],
    ["Proposed system", "No — user space", "Yes", "Yes"],
], top=Inches(1.85),
    col_w=[Inches(4.6), Inches(2.2), Inches(2.3), Inches(2.7)], size=14)
tb = s.shapes.add_textbox(Inches(0.85), Inches(5.3), W - Inches(1.7), Inches(1.0))
_tf(tb, "No existing system combines user-space deployability, an explained "
        "alert, and containment the user can undo.", 17, CYAN, bold=True)
notes(s, "The literature shows strong behavioural detection, but almost all of "
         "it depends on a kernel driver. Nothing combines deployability, "
         "transparency and reversibility, which is the gap this project fills.")

# ═════════════════════════════════════════════════════════════════════════════
# 8 — Architecture
# ═════════════════════════════════════════════════════════════════════════════
s = slide("System Architecture", "Two processes, connected by a named pipe")
picture(s, "fig_architecture.png", top=Inches(1.5), height=Inches(4.6),
        caption="C++ agent answers WHAT changed and WHO changed it; the Python "
                "engine decides whether it is an attack")
notes(s, "A C++ agent watches the folder with ReadDirectoryChangesW and asks "
         "ETW who touched each file. It streams events over a named pipe to a "
         "Python engine that runs the three detection layers. The split means "
         "either side can be replaced independently.")

# ═════════════════════════════════════════════════════════════════════════════
# 9 — Three layers overview
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Three-Layer Detection", "Each layer covers the previous layer's blind spot")
table(s, [
    ["Layer", "Signal", "Catches", "Blind spot it covers"],
    ["1  Rate", "k files changed within t seconds",
     "Bulk encryption bursts", "—"],
    ["2  Entropy", "Median write-entropy ≥ 6.5 bits/byte",
     "Distinguishes ciphertext from documents", "Fast benign bursts (archive extraction)"],
    ["3  Canary", "A hidden decoy file is modified",
     "Near-certain ransomware on the FIRST file", "Slow, low-and-slow attacks under the rate window"],
], top=Inches(1.85),
    col_w=[Inches(1.7), Inches(3.2), Inches(3.4), Inches(3.5)], size=13)
tb = s.shapes.add_textbox(Inches(0.85), Inches(4.6), W - Inches(1.7), Inches(1.0))
_tf(tb, "The entropy gate only ever SUPPRESSES on positive low-entropy evidence, "
        "so it can never cause a false negative.", 16, CYAN, bold=True)
notes(s, "Rate alone false-alarms on archive extraction. Entropy fixes that "
         "because ciphertext is near-maximum entropy while documents are not. "
         "Canaries fix the opposite weakness, an attack too slow to trip the "
         "rate window. Importantly the entropy gate can only suppress, so it "
         "cannot introduce a missed detection.")

# ═════════════════════════════════════════════════════════════════════════════
# 10 — ETW attribution
# ═════════════════════════════════════════════════════════════════════════════
s = slide("User-Space Process Attribution", "The main technical contribution of FYP2")
bullets(s, [
    ("ReadDirectoryChangesW reports WHAT changed but never WHO changed it", 0, False, INK),
    ("The FYP1 heuristic guessed from process snapshots — it frequently blamed the "
     "monitoring agent itself", 1, False, GREY),
    ("Solution: consume the Microsoft-Windows-Kernel-File ETW provider", 0, False, INK),
    ("True PID comes from the kernel event header — accurate, and still entirely user mode", 1, False, GREY),
    ("NT device paths are mapped back to drive letters so they match the file events", 1, False, GREY),
    ("Engineering problem solved: a timing race", 0, True, RED),
    ("ETW events arrive after the file notification, so every lookup initially missed and "
     "fell back to the heuristic", 1, False, GREY),
    ("Fixed with smaller trace buffers, a one-second flush timer and a bounded retry", 1, False, GREY),
    ("Result: 100 % of alerts correctly attributed when running elevated", 0, True, GREEN),
], size=17)
notes(s, "This is the part I would highlight. ETW gives the true PID from user "
         "mode. The hard part was a timing race: file notifications arrive "
         "before the matching ETW record, so attribution always fell back to "
         "the heuristic. Reducing the buffer size and adding a bounded retry "
         "fixed it, and attribution is now accurate on every elevated alert.")

# ═════════════════════════════════════════════════════════════════════════════
# 11 — Containment
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Reversible Containment", "Every action can be undone from the dashboard")
bullets(s, [
    ("Environmental containment — directory lockdown", 0, True, INK),
    ("icacls /deny strips write permission from the affected folder", 1, False, GREY),
    ("Stops the encryption regardless of which process is responsible", 1, False, GREY),
    ("Undone with icacls /remove:d, the exact inverse, from the alert drill-down", 1, False, GREY),
    ("Process containment — suspend, not terminate", 0, True, INK),
    ("Offered only when attribution is ETW, never on a heuristic guess", 1, False, GREY),
    ("Suspends every thread; Resume restores the process", 1, False, GREY),
    ("User-confirmed, never automatic, and critical system processes are denied", 1, False, GREY),
    ("Design rule: no containment action exists that the user cannot reverse", 0, True, CYAN),
], size=17)
notes(s, "Containment is environmental first, because it does not need a "
         "correct PID. Now that attribution is accurate, a process-targeted "
         "suspend is also offered, but only on ETW attribution and only with "
         "user confirmation. Both are reversible from the interface.")

# ═════════════════════════════════════════════════════════════════════════════
# 12 — Implementation / dashboard
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Implementation", "The dashboard is where transparency is delivered")
picture(s, "fig_dashboard_live.png", top=Inches(1.5), height=Inches(4.5),
        caption="Protection status, summary cards, searchable detection log and "
                "live file-activity graph")
notes(s, "Every alert is explained: which files, which process, how it was "
         "attributed, the measured entropy, and what containment was applied. "
         "Double-clicking a row opens the drill-down with the reversal "
         "controls. This is what 'transparent' means in the aim.")

# ═════════════════════════════════════════════════════════════════════════════
# 13 — Evaluation methodology
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Evaluation Methodology", "Four independent lines of evidence")
bullets(s, [
    ("Behavioural validation", 0, True, INK),
    ("A simulator reproduces the real ransomware I/O sequence — read, encrypt, write, "
     "rename or delete — across three family archetypes", 1, False, GREY),
    ("Benign stressors — bulk copy, archive extraction, backup and editing — test for false alarms", 1, False, GREY),
    ("Threshold sensitivity", 0, True, INK),
    ("The entropy threshold is swept to produce a false-positive / false-negative curve", 1, False, GREY),
    ("Performance benchmarking", 0, True, INK),
    ("Detection latency, agent CPU and event loss measured across a load matrix", 1, False, GREY),
    ("Real-world dataset", 0, True, INK),
    ("RanSAP — 70 real ransomware and 50 benign executions, recorded at the storage layer", 1, False, GREY),
], size=17)
notes(s, "No real malware was executed. The simulator reproduces the file I/O "
         "behaviour and produces genuinely high-entropy output, and the "
         "real-world claim is supported separately by the RanSAP dataset, "
         "which was recorded from actual ransomware.")

# ═════════════════════════════════════════════════════════════════════════════
# 14 — Detection correctness
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Results — Detection Correctness", "Objective 1 and Objective 2")
picture(s, "fig_validation_confusion.png", top=Inches(1.5), height=Inches(3.4))
kpi_row(s, [
    ("0", "False negatives", GREEN),
    ("1 → 0", "False positives once the\nentropy layer is enabled", GREEN),
    ("~1–40 ms", "Detection latency", CYAN),
], top=Inches(5.15))
notes(s, "With rate alone, archive extraction is a false positive. Turning on "
         "the entropy layer turns it into a true negative while every attack "
         "scenario is still detected. Setting the threshold to zero reproduces "
         "the FYP1 behaviour, which is the controlled A/B for this claim.")

# ═════════════════════════════════════════════════════════════════════════════
# 15 — Sensitivity
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Results — Entropy-Threshold Sensitivity", "Why 6.5 bits per byte")
picture(s, "fig_sensitivity.png", top=Inches(1.5), height=Inches(4.4),
        caption="Detection error against the entropy threshold; the shipped "
                "default sits in the stable region")
notes(s, "The threshold is not arbitrary. Documents sit around three to five "
         "bits per byte and ciphertext close to eight, so there is a wide "
         "stable band between them. The default was chosen from this curve, "
         "and it remains adjustable at run time.")

# ═════════════════════════════════════════════════════════════════════════════
# 16 — Performance
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Results — Performance Overhead", "Objective 1: viable for continuous use")
picture(s, "fig_perf_fix.png", top=Inches(1.45), height=Inches(3.4))
kpi_row(s, [
    ("1240 ms → 17 ms", "Detection latency (p50)", GREEN),
    ("8.1 % → < 1 %", "Agent CPU", GREEN),
    ("5 % → 0 %", "Event loss", GREEN),
], top=Inches(5.15))
notes(s, "The attribution heuristic was originally called once per file event "
         "and each call enumerated every process, which dominated the pipeline. "
         "Caching it for one hundred milliseconds removed that cost, and the "
         "system now detects in tens of milliseconds at well under one percent "
         "CPU.")

# ═════════════════════════════════════════════════════════════════════════════
# 17 — RanSAP
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Results — Real-World Dataset (RanSAP)", "The most important finding of the evaluation")
picture(s, "fig_ransap_ml_vs_entropy.png", top=Inches(1.45), height=Inches(3.5))
tb = s.shapes.add_textbox(Inches(0.85), Inches(5.15), W - Inches(1.7), Inches(1.6))
tf = _tf(tb, "The highest write-entropy in the dataset comes not from ransomware "
             "but from legitimate encryption and compression tools.", 18, RED, bold=True)
_para(tf, "Entropy is therefore necessary but not sufficient — which is exactly why "
          "the system layers rate, entropy and canary evidence instead of relying on "
          "any single measure.", 16, INK, space_before=6)
notes(s, "This is the finding I would emphasise. On real ransomware, an "
         "entropy threshold on its own reaches only about sixty-four percent "
         "accuracy, because AESCrypt and Zip produce even higher entropy than "
         "the ransomware does. A multi-feature classifier separates them almost "
         "perfectly. It is empirical justification for the layered design.")

# ═════════════════════════════════════════════════════════════════════════════
# 18 — Attribution accuracy
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Results — Attribution Accuracy", "Objective 3")
table(s, [
    ["Condition", "Attribution source", "Correctly attributed"],
    ["FYP1 heuristic", "Process snapshot guess", "Frequently wrong — often the agent itself"],
    ["ETW, before the timing fix", "Fell back to heuristic", "Attribution unavailable in practice"],
    ["ETW, after the timing fix (elevated)", "Kernel event header", "100 % of alerts"],
], top=Inches(1.95),
    col_w=[Inches(3.6), Inches(3.4), Inches(4.6)], size=15)
tb = s.shapes.add_textbox(Inches(0.85), Inches(4.2), W - Inches(1.7), Inches(1.6))
tf = _tf(tb, "Accurate attribution is what makes process-targeted containment "
             "safe to offer at all.", 18, CYAN, bold=True)
_para(tf, "The attribution source is stored on every alert row, so accuracy can be "
          "measured directly from the database rather than claimed.", 16, INK,
      space_before=6)
notes(s, "Because the source is persisted per alert, this is measured from the "
         "database, not asserted. Without elevation ETW is denied and the "
         "system degrades gracefully to the heuristic, which it reports "
         "honestly in the interface.")

# ═════════════════════════════════════════════════════════════════════════════
# 19 — Objectives evaluation (required by the guideline)
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Extent to Which the Objectives Are Met", "Assessment against Slide 5")
table(s, [
    ["Objective", "Outcome", "Evidence"],
    ["1  Real-time user-space detection", "Met",
     "0 false negatives; 17 ms p50 latency; < 1 % CPU"],
    ["2  Reduce false alarms", "Met",
     "Extraction: false positive → true negative with the entropy layer"],
    ["3  Accurate process attribution", "Met",
     "100 % of elevated alerts attributed via ETW"],
    ["4  Reversible containment", "Met",
     "Lockdown and suspend both reversible from the drill-down"],
    ["5  Realistic evaluation", "Met",
     "Simulator, benign stressors, sensitivity sweep and RanSAP"],
], top=Inches(1.9),
    col_w=[Inches(4.0), Inches(1.5), Inches(6.1)], size=14)
tb = s.shapes.add_textbox(Inches(0.85), Inches(5.35), W - Inches(1.7), Inches(1.0))
_tf(tb, "All five objectives met. The machine-learning layer is evaluated offline "
        "and is not yet wired into the live detector — stated as future work rather "
        "than claimed as delivered.", 15, GREY, italic=True)
notes(s, "All five objectives are met. I want to be explicit that the machine "
         "learning classifier is an offline evaluation, not a live third gate. "
         "It is reported as future work rather than claimed as a delivered "
         "feature.")

# ═════════════════════════════════════════════════════════════════════════════
# 20 — Limitations
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Limitations and Future Work", "Stated honestly")
bullets(s, [
    ("Limitations", 0, True, RED),
    ("ETW attribution requires Administrator; without it the system degrades to the "
     "heuristic and says so", 1, False, GREY),
    ("A thread created after enumeration is not caught by the suspend action", 1, False, GREY),
    ("The in-place overwrite family is borderline at the shipped rate window — this is "
     "what the canary layer covers", 1, False, GREY),
    ("The synthetic benign corpus is narrower than real-world user activity", 1, False, GREY),
    ("Future work", 0, True, GREEN),
    ("Load the trained classifier into the live detector as a fourth gate", 1, False, GREY),
    ("Optional automatic suspend-on-alert mode, currently manual by design", 1, False, GREY),
    ("Multi-folder monitoring and a self-healing backup of canary-adjacent files", 1, False, GREY),
    ("A purchased code-signing certificate to replace the self-signed pipeline", 1, False, GREY),
], size=16)
notes(s, "I would rather state these plainly than be asked about them. The most "
         "significant one is that ETW needs elevation; the system handles that "
         "gracefully and reports the degraded state instead of hiding it.")

# ═════════════════════════════════════════════════════════════════════════════
# 21 — Conclusion
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Conclusion", "What the project demonstrates")
bullets(s, [
    ("Effective, fully reversible ransomware containment is achievable entirely in user space",
     0, True, INK),
    ("Realistic ransomware behaviour is detected with zero false negatives, in tens of "
     "milliseconds, at under one percent CPU", 0, False, INK),
    ("Event Tracing for Windows provides accurate process attribution from user mode, "
     "which makes process-targeted containment safe to offer", 0, False, INK),
    ("Layering rate, entropy and canary evidence is not redundancy — the real-world "
     "dataset shows each layer covers a blind spot of the others", 0, False, INK),
    ("Every containment action is explained and can be undone by the user", 0, False, INK),
], size=19, top=Inches(1.9))
tb = s.shapes.add_textbox(Inches(0.85), Inches(5.5), W - Inches(1.7), Inches(1.1))
_tf(tb, "The project trades a little attribution certainty for far greater "
        "deployability and transparency — the correct trade for the users it targets.",
    18, CYAN, bold=True, align=PP_ALIGN.CENTER)
notes(s, "To conclude: the central claim is that you do not need a kernel driver "
         "to stop ransomware effectively, provided you are honest about the "
         "limits of user-space attribution and make every action reversible.")

# ═════════════════════════════════════════════════════════════════════════════
# 22 — Demonstration
# ═════════════════════════════════════════════════════════════════════════════
s = slide("Live Demonstration", "Product demonstration session")
bullets(s, [
    ("Start the system elevated — status band turns green, ETW attribution active", 0, False, INK),
    ("Trigger a simulated attack against the watched folder", 0, False, INK),
    ("Alert fires — banner, activity-graph spike and a new row in the detection log", 0, False, INK),
    ("Open the drill-down — affected files, ETW attribution, measured entropy", 0, False, INK),
    ("Unlock the directory and resume the process, showing containment is reversible", 0, False, INK),
    ("Trip a canary to show first-file detection independent of the rate threshold", 0, False, INK),
], size=19, top=Inches(1.9))
notes(s, "Demonstration order. Keep the elevated terminal ready before the "
         "session starts, and clear any leftover deny ACE on the demo folder "
         "beforehand so the canaries deploy correctly.")

# ═════════════════════════════════════════════════════════════════════════════
# 23 — Thank you / Q&A
# ═════════════════════════════════════════════════════════════════════════════
s = prs.slides.add_slide(BLANK)
_rect(s, 0, 0, W, H, NAVY)
_rect(s, Inches(5.4), Inches(3.55), Inches(2.5), Inches(0.05), ACCENT)
tb = s.shapes.add_textbox(Inches(1.0), Inches(2.55), W - Inches(2.0), Inches(1.0))
_tf(tb, "Thank you", 46, WHITE, bold=True, align=PP_ALIGN.CENTER)
tb = s.shapes.add_textbox(Inches(1.0), Inches(3.85), W - Inches(2.0), Inches(1.2))
tf = _tf(tb, "Questions and Answers", 24, RGBColor(0x9F, 0xD8, 0xE8),
         align=PP_ALIGN.CENTER)
_para(tf, "Lee Wen Qi   |   Supervisor: Ms. Oh Zi Xin   |   UTAR FICT (Kampar)",
      15, RGBColor(0xC5, 0xD3, 0xDB), space_before=14)
for p in tf.paragraphs:
    p.alignment = PP_ALIGN.CENTER
notes(s, "Thank you. I am happy to take questions.")

prs.save(OUT)
print("wrote", os.path.basename(OUT), "-", len(prs.slides._sldIdLst), "slides")
missing = [f for f in ("fig_architecture.png", "fig_dashboard_live.png",
                       "fig_validation_confusion.png", "fig_sensitivity.png",
                       "fig_perf_fix.png", "fig_ransap_ml_vs_entropy.png")
           if not os.path.exists(os.path.join(FIG, f))]
print("missing figures (placeholders inserted):", missing or "none")
