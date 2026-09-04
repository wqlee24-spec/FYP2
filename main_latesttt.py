# =============================================================================
#  main.py  –  Hybrid Security Suite  v2.0
#  Interactive dashboard + animated onboarding wizard
# =============================================================================

from __future__ import annotations

import argparse
import collections
import ctypes
import json
import math
import os
import random
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import winreg
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog


# ── High-DPI support ─────────────────────────────────────────────────────────
# Must run BEFORE the first Tk window is created.
#
# Left alone, the process is DPI-*unaware*: on a 1920x1080 display at 150 %
# Windows scaling, Windows hands Tk a virtualised 1280x720 desktop and then
# bitmap-stretches the finished window back up to 1920x1080. That blurs every
# glyph and leaves the layout only two-thirds of the real screen to work with,
# so the UI looks both soft and cramped — and, worse, whether it happens at all
# depends on who launched the process, because DPI awareness is inherited.
#
# Declaring awareness makes Tk see the true 1920x1080 at 144 dpi and render
# natively. Tk then converts point sizes with `tk scaling` (dpi/72), so fonts
# keep their physical size; only hard-coded *pixel* geometry has to be scaled
# by hand — that is what S() below is for.
def _enable_dpi_awareness():
    for call in (lambda: ctypes.windll.shcore.SetProcessDpiAwareness(2),   # per-monitor v2
                 lambda: ctypes.windll.shcore.SetProcessDpiAwareness(1),   # system aware
                 lambda: ctypes.windll.user32.SetProcessDPIAware()):       # pre-8.1 fallback
        try:
            call()
            return
        except Exception:
            continue


_enable_dpi_awareness()


def _dpi_scale():
    """Screen scale factor (1.0 at 96 dpi, 1.5 at 150 %, 2.0 at 200 %)."""
    try:
        return max(1.0, ctypes.windll.user32.GetDpiForSystem() / 96.0)
    except Exception:
        return 1.0


UI_SCALE = _dpi_scale()


def S(px):
    """Scale a hard-coded pixel measurement to the current display."""
    return int(round(px * UI_SCALE))

# Modern themed widgets over tkinter (lightweight: ~190 KB, pure-Python skin —
# keeps the "lightweight, minimal-dependency" project positioning, unlike Qt).
try:
    import ttkbootstrap as ttkb
    _TTKB_OK = True
except ImportError:
    ttkb = None            # type: ignore
    _TTKB_OK = False

UI_THEME = "darkly"        # clean professional dark-grey; one-line to swap

# Optional: psutil for CPU monitoring (pip install psutil)
try:
    import psutil as _psutil
    _PSUTIL_OK = True
except ImportError:
    _psutil    = None       # type: ignore
    _PSUTIL_OK = False

# Optional: winsound for audible alerts (stdlib on Windows)
try:
    import winsound
    _WINSOUND_OK = True
except ImportError:
    winsound    = None      # type: ignore
    _WINSOUND_OK = False

# ─── Safe console logging ────────────────────────────────────────────────────
def _log(msg):
    """Write a diagnostic line that can never disrupt detection.

    Guards two real hazards:
      * A non-ANSI path (e.g. ...\\报告\\file.txt) raises UnicodeEncodeError on a
        cp1252 console. UnicodeEncodeError subclasses ValueError, so it used to
        be swallowed by PipeReader's handler — silently losing the alert.
      * PyInstaller packages this app windowed (console=False), where
        sys.stdout can be None.
    """
    try:
        stream = sys.stdout
        if stream is None:
            return
        try:
            stream.write(str(msg) + "\n")
        except UnicodeEncodeError:
            enc = getattr(stream, "encoding", None) or "utf-8"
            stream.write(str(msg).encode(enc, "replace").decode(enc, "replace") + "\n")
        stream.flush()
    except Exception:
        pass   # diagnostics must never take the app down


# ─── Shannon entropy of written data ─────────────────────────────────────────
_ENT_SAMPLE_BYTES = 4096      # a 4 KB sample estimates file entropy cheaply
_ENT_LOG2 = math.log2

def file_entropy(path, sample_bytes=_ENT_SAMPLE_BYTES):
    """Shannon entropy (bits/byte, 0-8) of up to `sample_bytes` read from `path`.

    Returns None if the file cannot be read (e.g. it was renamed/deleted between
    the RDCW event and this read — common for copy_delete's REMOVED events). A
    None result must never *cause* an alert to be suppressed; see the detector.

    Encryption/compression output approaches 8.0; documents and source sit far
    lower (~3-5), which is what lets entropy separate a fast-but-benign burst
    (e.g. extracting text) from ransomware.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_bytes)
    except OSError:
        return None
    if not data:
        return None
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * _ENT_LOG2(c / n) for c in counts.values())


# ─── Config ──────────────────────────────────────────────────────────────────
PIPE_NAME = r"\\.\pipe\SecurityPipe"

# Determine paths based on whether we are running as a PyInstaller .exe or a .py script
if getattr(sys, 'frozen', False):
    # RUNNING AS COMPILED .EXE
    # sys.executable gets the path of the actual .exe in your dist folder
    APP_DIR = Path(sys.executable).parent
    # sys._MEIPASS is the hidden temporary folder where PyInstaller extracts files
    TEMP_MEI_DIR = Path(sys._MEIPASS)

    # The agent is extracted to the temp folder, but DB saves next to the .exe
    AGENT_EXE = TEMP_MEI_DIR / "monitor_agent.exe"
    DB_PATH = APP_DIR / "security_suite.db"
else:
    # RUNNING IN PYCHARM
    APP_DIR = Path(__file__).parent

    AGENT_EXE = APP_DIR / "monitor_agent.exe"
    DB_PATH = APP_DIR / "security_suite.db"

WELCOME_SEEN_KEY = "HybridSecuritySuite_WelcomeSeen"  # registry flag
WATCH_DIR_KEY = "WatchDirectory"                      # registry value
HSS_REG_PATH = r"Software\HybridSecuritySuite"  # dedicated settings hive
DEFAULT_WATCH_DIR = r"C:\Users\Public\Documents"
DASHBOARD_REFRESH = 2000

# ─── Palette ─────────────────────────────────────────────────────────────────
BG          = "#080c10"
PANEL       = "#0d1117"
CARD        = "#111820"
CARD2       = "#151d27"   # slightly lifted card (hover / inner panels)
ACCENT      = "#00d4ff"
ACCENT_DIM  = "#007a99"
RED         = "#ff3d5a"
GREEN       = "#00e676"
ORANGE      = "#ffab40"
YELLOW      = "#ffd740"
TEXT        = "#e8edf2"
DIM         = "#5a6470"
BORDER      = "#1e2830"
GLOW        = "#003848"

# Status-band tints (dark, saturated background per protection state)
HERO_GREEN  = "#0c2417"
HERO_RED    = "#2a0d13"
HERO_AMBER  = "#2a220d"
HERO_ORANGE = "#2a1a0d"

F_MONO   = ("Consolas", 12)
F_MONO_S = ("Consolas", 11)
F_MONO_L = ("Consolas", 14, "bold")
F_MONO_XL= ("Consolas", 18, "bold")
F_TITLE  = ("Consolas", 16, "bold")
F_HERO   = ("Segoe UI", 21, "bold")
F_HERO_ICON = ("Segoe UI Emoji", 34)
F_STAT   = ("Consolas", 25, "bold")
# Modern UI fonts (Segoe UI reads cleaner than Consolas for labels/data)
F_LOG    = ("Consolas", 12)            # detection-log rows
F_LOG_B  = ("Consolas", 12, "bold")    # ...and the row tag / column headings
F_UI     = ("Segoe UI", 12)
F_UI_S   = ("Segoe UI", 11)
F_UI_B   = ("Segoe UI Semibold", 13)


def _hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _mix(a, b, t):
    """Blend hex colour a→b by fraction t (0..1)."""
    try:
        ra, ga, ba = _hex_to_rgb(a); rb, gb, bb = _hex_to_rgb(b)
        return f"#{int(ra+(rb-ra)*t):02x}{int(ga+(gb-ga)*t):02x}{int(ba+(bb-ba)*t):02x}"
    except Exception:
        return a


def _apply_theme_palette(colors):
    """Remap the module palette to the active ttkbootstrap theme so the custom-
    drawn parts (hero band, activity graph, treeview tags, stat cards) stay
    consistent with the themed ttk widgets."""
    global BG, PANEL, CARD, CARD2, ACCENT, ACCENT_DIM, RED, GREEN, ORANGE, YELLOW
    global TEXT, DIM, BORDER, GLOW, HERO_GREEN, HERO_RED, HERO_AMBER, HERO_ORANGE
    BG         = colors.bg
    PANEL      = _mix(colors.bg, colors.light, 0.05)
    CARD       = _mix(colors.bg, colors.light, 0.09)
    CARD2      = _mix(colors.bg, colors.light, 0.14)
    ACCENT     = colors.info
    ACCENT_DIM = colors.primary
    RED        = colors.danger
    GREEN      = colors.success
    ORANGE     = colors.warning
    YELLOW     = colors.warning
    TEXT       = colors.fg
    DIM        = colors.light
    BORDER     = _mix(colors.bg, colors.light, 0.22)
    GLOW       = _mix(colors.bg, colors.info, 0.30)
    HERO_GREEN  = _mix(colors.bg, colors.success, 0.20)
    HERO_RED    = _mix(colors.bg, colors.danger,  0.22)
    HERO_AMBER  = _mix(colors.bg, colors.warning, 0.20)
    HERO_ORANGE = _mix(colors.bg, colors.warning, 0.15)


def _tbutton(parent, text, command, bootstyle="secondary"):
    """A modern themed button (ttkbootstrap) with a plain-tk fallback."""
    if _TTKB_OK:
        return ttkb.Button(parent, text=text, command=command,
                           bootstyle=bootstyle, takefocus=False)
    return tk.Button(parent, text=text, command=command, font=F_MONO,
                     fg=TEXT, bg=CARD, relief="flat", cursor="hand2",
                     padx=12, pady=6, activebackground=GLOW, activeforeground=ACCENT)


def _lerp_hex(c1, c2, t):
    """Blend two #rrggbb colors; t in 0..1. Used for smooth pulse animations."""
    try:
        a = (int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16))
        b = (int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16))
        return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))
    except Exception:
        return c1


def _round_rect_pts(x1, y1, x2, y2, r):
    """Point list for a smooth rounded rectangle (use with create_polygon +
    smooth=True). r is the corner radius."""
    return [
        x1 + r, y1,  x2 - r, y1,  x2, y1,  x2, y1 + r,
        x2, y2 - r,  x2, y2,  x2 - r, y2,  x1 + r, y2,
        x1, y2,  x1, y2 - r,  x1, y1 + r,  x1, y1,
    ]


class RoundedFrame(tk.Frame):
    """A container with smooth rounded corners. Pack/grid your content into its
    `.body` frame. The rounded shape is drawn on a Canvas whose corners show the
    parent background, so the box reads as a soft rounded card rather than a hard
    90-degree rectangle."""

    def __init__(self, parent, radius=16, fill=None, border=None,
                 height=None, pad=None):
        outer = parent.cget("bg")
        super().__init__(parent, bg=outer)
        self._radius = radius
        self._fill   = fill or CARD
        self._border = border
        self._pad    = pad if pad is not None else max(6, int(radius * 0.55))
        self._canvas = tk.Canvas(self, bg=outer, highlightthickness=0, bd=0,
                                 height=height or 1)
        self._canvas.pack(fill="both", expand=True)
        self.body = tk.Frame(self._canvas, bg=self._fill)
        self._win = self._canvas.create_window(0, 0, window=self.body, anchor="nw")
        self._canvas.bind("<Configure>", self._redraw)

    def set_fill(self, fill):
        self._fill = fill
        self.body.configure(bg=fill)
        self.redraw()

    def redraw(self):
        self._canvas.update_idletasks()
        w = self._canvas.winfo_width()
        h = self._canvas.winfo_height()
        self._paint(w, h)

    def _redraw(self, e):
        self._paint(e.width, e.height)

    def _paint(self, w, h):
        if w <= 2 or h <= 2:
            return
        c = self._canvas
        c.delete("rr")
        r = max(2, min(self._radius, w // 2, h // 2))
        pts = _round_rect_pts(1, 1, w - 1, h - 1, r)
        c.create_polygon(pts, smooth=True, fill=self._fill,
                         outline=self._border or self._fill,
                         width=1.5 if self._border else 1, tags="rr")
        c.tag_lower("rr")
        p = self._pad
        c.coords(self._win, p, p)
        c.itemconfig(self._win, width=max(1, w - 2 * p), height=max(1, h - 2 * p))


class ToastNotification(tk.Toplevel):
    """A desktop toast that slides up from the bottom-right corner of the screen
    on a new ransomware alert, so the user is warned even when the dashboard is
    minimised or unfocused. Auto-dismisses; click it to raise the dashboard."""

    _active = []   # currently-visible toasts, so they stack instead of overlap
    _TRANS  = "#010203"

    def __init__(self, root, message, on_click=None):
        super().__init__(root)
        self._on_click = on_click
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        rounded = False
        try:
            self.attributes("-transparentcolor", self._TRANS)
            self.configure(bg=self._TRANS)
            rounded = True
        except tk.TclError:
            self.configure(bg=BG)

        W, H, R = 370, 104, 20
        self._W, self._H = W, H
        cv = tk.Canvas(self, width=W, height=H,
                       bg=(self._TRANS if rounded else BG),
                       highlightthickness=0, bd=0)
        cv.pack(fill="both", expand=True)
        cv.create_polygon(_round_rect_pts(2, 2, W - 2, H - 2, R), smooth=True,
                          fill=CARD2, outline=RED, width=2)

        body = tk.Frame(cv, bg=CARD2)
        cv.create_window(22, H // 2, window=body, anchor="w", width=W - 44)
        tk.Label(body, text="\U0001f6a8  RANSOMWARE DETECTED", bg=CARD2, fg=RED,
                 font=("Consolas", 11, "bold"), anchor="w").pack(anchor="w")
        tk.Label(body, text=message, bg=CARD2, fg=TEXT, font=("Consolas", 9),
                 anchor="w", justify="left").pack(anchor="w", pady=(2, 0))
        tk.Label(body, text="Click to open dashboard  ·  auto-hides",
                 bg=CARD2, fg=DIM, font=("Consolas", 8)).pack(anchor="w", pady=(3, 0))

        for w in (cv, body, *body.winfo_children()):
            w.bind("<Button-1>", self._click)

        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        gap = 8
        stack = sum(t._H + gap for t in ToastNotification._active)
        self._x = sw - W - 24
        self._y_target = sh - H - 70 - stack
        ToastNotification._active.append(self)
        self._y = sh
        self.geometry(f"{W}x{H}+{self._x}+{self._y}")
        self._slide_in()
        self._dismiss_after = self.after(7000, self.dismiss)

    def _slide_in(self):
        if self._y > self._y_target:
            self._y = max(self._y_target, self._y - 20)
            self.geometry(f"{self._W}x{self._H}+{self._x}+{self._y}")
            self.after(10, self._slide_in)

    def _click(self, _e=None):
        if self._on_click:
            try: self._on_click()
            except Exception: pass
        self.dismiss()

    def dismiss(self):
        try:
            if self._dismiss_after:
                self.after_cancel(self._dismiss_after)
        except Exception:
            pass
        try: ToastNotification._active.remove(self)
        except ValueError: pass
        try: self.destroy()
        except Exception: pass


# =============================================================================
# Backend classes (unchanged logic, just renamed vars to match new palette)
# =============================================================================
class DetectionConfig:
    # entropy_thresh is the minimum mean entropy (bits/byte, 0-8) at which a
    # rate-triggered burst is treated as ransomware. Set it to 0 to disable the
    # entropy gate entirely and fall back to pure rate detection (FYP1 behaviour),
    # which is exactly the A/B needed to evidence the entropy contribution.
    def __init__(self, file_thresh=5, event_cap=10, window_secs=0.01,
                 entropy_thresh=6.5):
        self._lock = threading.Lock()
        self.file_thresh    = file_thresh
        self.event_cap      = event_cap
        self.window_secs    = window_secs
        self.entropy_thresh = entropy_thresh

    def get(self):
        with self._lock:
            return self.file_thresh, self.event_cap, self.window_secs

    def get_entropy_thresh(self):
        with self._lock:
            return self.entropy_thresh

    def update(self, ft, ec, ws, entropy_thresh=None):
        with self._lock:
            self.file_thresh   = max(1, int(ft))
            self.event_cap     = max(1, int(ec))
            self.window_secs   = max(0.001, float(ws))
            if entropy_thresh is not None:
                self.entropy_thresh = min(8.0, max(0.0, float(entropy_thresh)))


class MonitoringState:
    def __init__(self, active=True):
        self._lock   = threading.Lock()
        self._active = active

    @property
    def active(self):
        with self._lock:
            return self._active

    def toggle(self):
        with self._lock:
            self._active = not self._active
            return self._active

    def set(self, v):
        with self._lock:
            self._active = v


class Database:
    DDL = """
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, alert_type TEXT NOT NULL,
        attacker TEXT NOT NULL, detail TEXT,
        status TEXT NOT NULL DEFAULT 'BLOCKED');
    """
    def __init__(self, path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        with self._conn: self._conn.executescript(self.DDL)
        self._migrate()

    def _migrate(self):
        with self._lock:
            with self._conn:
                for ddl in (
                    "ALTER TABLE alerts ADD COLUMN files_json TEXT",
                    "ALTER TABLE alerts ADD COLUMN locked_dir TEXT",
                    "ALTER TABLE alerts ADD COLUMN lock_active INTEGER NOT NULL DEFAULT 0",
                    "ALTER TABLE alerts ADD COLUMN attribution TEXT NOT NULL DEFAULT 'HEUR'",
                    "ALTER TABLE alerts ADD COLUMN entropy REAL",
                    "ALTER TABLE alerts ADD COLUMN pid INTEGER",
                ):
                    try:
                        self._conn.execute(ddl)
                    except sqlite3.OperationalError:
                        pass  # column already exists
                self._conn.execute("DROP TABLE IF EXISTS blocked_ips")

    def log_alert(self, atype, attacker, detail="", status="BLOCKED", files=None,
                  locked_dir=None, attribution="HEUR", entropy=None, pid=None):
        # Millisecond resolution: detection latency is sub-second, so a
        # second-granularity timestamp cannot evidence it.
        ts = datetime.now().isoformat(sep=" ", timespec="milliseconds")
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO alerts(timestamp,alert_type,attacker,detail,status,"
                    "files_json,locked_dir,lock_active,attribution,entropy,pid) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (ts, atype, attacker, detail, status, json.dumps(files or []),
                     locked_dir, 1 if locked_dir else 0, attribution, entropy, pid))

    _COLS = ("id,timestamp,alert_type,attacker,detail,status,"
             "files_json,locked_dir,lock_active,attribution,entropy,pid")

    def get_alerts(self, limit=200):
        with self._lock:
            return self._conn.execute(
                f"SELECT {self._COLS} FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()

    def get_alert_by_id(self, alert_id):
        with self._lock:
            return self._conn.execute(
                f"SELECT {self._COLS} FROM alerts WHERE id=?",
                (alert_id,)).fetchone()

    def mark_unlocked(self, alert_id):
        with self._lock:
            with self._conn:
                self._conn.execute("UPDATE alerts SET lock_active=0 WHERE id=?", (alert_id,))


class CanaryManager:
    """Decoy ("canary") files — a third detection layer, independent of rate and
    entropy. Hidden files placed in the watched folder that no legitimate program
    ever touches. Ransomware encrypts *everything*, so the moment a canary is
    modified, renamed or deleted it is near-certain ransomware — caught on the
    FIRST file, which also covers slow "low-and-slow" attacks that stay under the
    rate threshold. A well-established anti-ransomware / honeypot technique."""

    PREFIX  = "~$hss_guard_"                       # ~$ mimics Office lock files
    _MARKER = b"HSS_CANARY_v1 :: decoy file, do not modify :: ransomware tripwire\n"
    _COUNT  = 4
    _EXTS   = (".docx", ".xlsx", ".pdf", ".jpg")

    def __init__(self):
        self._dir = None
        self._paths = set()                        # normcase'd canary paths

    def deploy(self, watch_dir):
        """(Re)place canaries in watch_dir; clean up any from a previous folder."""
        watch_dir = str(watch_dir)
        self._cleanup(self._dir)
        self._dir = watch_dir
        self._paths = set()
        body = self._MARKER + b"0" * (2048 - len(self._MARKER))
        for i in range(self._COUNT):
            p = os.path.join(watch_dir, f"{self.PREFIX}{i}{self._EXTS[i % len(self._EXTS)]}")
            try:
                # A canary left behind by a previous run is HIDDEN, and Windows
                # refuses to truncate a hidden file through a plain open(…, "wb")
                # — it fails with PermissionError, so every redeploy into the
                # same folder used to place 0 canaries. Clear the attribute first.
                if os.path.exists(p):
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)  # NORMAL
                    except Exception:
                        pass
                with open(p, "wb") as fh:
                    fh.write(body)
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x2)   # FILE_ATTRIBUTE_HIDDEN
                except Exception:
                    pass
                self._paths.add(os.path.normcase(p))
            except OSError as e:
                _log(f"[Canary] could not place {p}: {e}")
        return len(self._paths)

    def _cleanup(self, d):
        if not d:
            return
        try:
            for f in os.listdir(d):
                if f.startswith(self.PREFIX):
                    try: os.remove(os.path.join(d, f))
                    except OSError: pass
        except OSError:
            pass

    def is_canary(self, path):
        return os.path.normcase(path) in self._paths

    def is_tripped(self, path):
        """True if the canary was tampered with (content changed) or is gone."""
        try:
            with open(path, "rb") as fh:
                data = fh.read(len(self._MARKER))
        except OSError:
            return True                            # missing / renamed / locked away
        if len(data) < len(self._MARKER):
            return False                           # still being written (creation race)
        return data != self._MARKER                # content changed -> encrypted


class RansomwareDetector:
    def __init__(self, db, config, state, on_alert, canary=None):
        self._db = db; self._config = config
        self._state = state; self._on_alert = on_alert
        self._canary = canary
        self._events = {}; self._alerted = set()
        self._all_events = collections.deque(maxlen=4000)
        # Recent DISTINCT file paths per PID, for entropy sampling. RDCW emits
        # several events per file, so a raw event window spans very few distinct
        # files — entropy must be judged over distinct files, not events.
        # Per-PID (not global) so that high-entropy files from a past attack
        # cannot bleed into a later benign burst by a different process, and the
        # `defer` branch in record() handles the case where the heuristic
        # attribution fallback fragments one burst across several guessed PIDs.
        self._recent_files = {}
        # How each event's PID was attributed: "ETW" (accurate) or "HEUR" (guess)
        self._attr_counts = {}
        self._pid_source  = {}
        self._lock = threading.Lock()

    _RECENT_FILES_MAX = 24

    def reset_alerted(self):
        with self._lock: self._alerted.clear()

    def recent_rate(self, window_secs=30.0, buckets=30):
        """Bucketed event counts over the last `window_secs`, for the live activity graph."""
        now = time.monotonic()
        with self._lock:
            snapshot = list(self._all_events)
        cutoff, bucket_w = now - window_secs, window_secs / buckets
        counts = [0] * buckets
        for t in snapshot:
            if t < cutoff:
                continue
            idx = int((t - cutoff) / bucket_w)
            # Events timestamped at exactly `now` (common when the clock has
            # coarse resolution) land one past the last bucket — clamp them in,
            # otherwise the newest bar would always read zero.
            if idx >= buckets:
                idx = buckets - 1
            if idx >= 0:
                counts[idx] += 1
        return counts

    def attribution_stats(self):
        """(etw_events, heuristic_events) since start — backs the accuracy evaluation."""
        with self._lock:
            return self._attr_counts.get("ETW", 0), self._attr_counts.get("HEUR", 0)

    # Minimum readable entropy samples before we trust an entropy-based
    # suppression. Below this we have no confidence the burst is benign, so we
    # must NOT suppress — the entropy gate may lower false positives but must
    # never introduce a false negative.
    _MIN_ENT_SAMPLES = 3

    def _window_entropy(self, files):
        """MEDIAN sampled entropy over the distinct, readable, non-directory
        files. Returns (median_or_None, n_samples). Directories (parent-folder
        change notifications, not writes) and unreadable paths (renamed/deleted)
        are skipped — never counted as low — so they can't wrongly suppress.

        Median, not mean: a PID transitioning from benign to malicious writes a
        mix of low- and high-entropy files. The mean dilutes the high-entropy
        signal (risking a false negative); the median flips to 'high' as soon as
        encrypted writes dominate the window, so ransomware still fires while a
        uniformly low-entropy benign burst is still suppressed."""
        vals = []
        for f in dict.fromkeys(files):        # dedupe, preserve order
            try:
                if os.path.isdir(f):
                    continue
            except OSError:
                pass
            e = file_entropy(f)
            if e is not None:
                vals.append(e)
        if not vals:
            return None, 0
        return statistics.median(vals), len(vals)

    def _emit_alert(self, pid, files, detail, source, entropy):
        """Write an alert row (+ run containment). Shared by the rate/entropy
        path and the canary tripwire so both produce identical alert records."""
        if _PSUTIL_OK:
            try:
                proc_name = _psutil.Process(pid).name()
            except _psutil.NoSuchProcess:
                proc_name = "Unknown"
            attacker_label = f"{proc_name} (PID {pid})"
        else:
            attacker_label = f"PID {pid}"
        locked_dir = self._on_alert(pid, files)
        status = "BLOCKED" if locked_dir else "LOCK FAILED"
        self._db.log_alert("RANSOMWARE", attacker_label, detail, status=status,
                           files=files, locked_dir=locked_dir, attribution=source,
                           entropy=entropy, pid=pid)

    def record(self, filepath, pid, source="HEUR"):
        if not self._state.active: return

        # ── Canary tripwire (third layer, instant, rate/entropy-independent) ──
        # A decoy file was touched. If its contents changed (or it vanished) it
        # is near-certain ransomware — fire immediately. Canary events never feed
        # the rate/entropy window.
        if self._canary is not None and self._canary.is_canary(filepath):
            if self._canary.is_tripped(filepath) and pid not in self._alerted:
                self._alerted.add(pid)
                ent = file_entropy(filepath)
                detail = (f"[CANARY] decoy '{Path(filepath).name}' was modified — "
                          f"near-certain ransomware")
                self._emit_alert(pid, [filepath], detail, source, ent)
            return

        ft, ec, ws = self._config.get()
        now = time.monotonic()
        with self._lock:
            q = self._events.setdefault(pid, collections.deque())
            q.append((now, filepath))
            while len(q) > ec: q.popleft()
            recent = [(t, f) for t, f in q if t >= now - ws]
            count  = len(recent)
            # Track recent DISTINCT files for this PID (move-to-end on repeat).
            df = self._recent_files.setdefault(pid, collections.OrderedDict())
            df.pop(filepath, None)
            df[filepath] = now
            while len(df) > self._RECENT_FILES_MAX:
                df.popitem(last=False)
            distinct_files = list(df.keys())
            self._all_events.append(now)
            self._attr_counts[source] = self._attr_counts.get(source, 0) + 1
            self._pid_source[pid] = source

        # record() is only ever called from the single PipeReader thread, so the
        # alerted-set check below needs no lock.
        if count < ft or pid in self._alerted:
            return

        full_files = [f for _, f in recent]

        # ── Entropy gate ──────────────────────────────────────────────────
        # The rate threshold is crossed. Judge the entropy of the recently
        # written files (globally, over distinct files) and decide:
        #   * enough readable samples + median LOW  -> benign burst, suppress
        #   * enough readable samples + median HIGH -> encryption-like, fire
        #   * too few samples, few files seen so far -> DEFER (wait for more),
        #     because RDCW emits several events per file so the first rate
        #     crossing can precede any real file evidence. Ransomware accrues
        #     distinct files within milliseconds, so this barely delays a true
        #     positive while removing the premature false alarm.
        #   * too few *readable* samples but many files seen -> can't assess
        #     (e.g. a delete/rename wiper) -> fire rather than risk a miss.
        # Neither suppress nor defer marks the PID alerted, so a workload that
        # turns high-entropy can still fire later.
        ent_thresh = self._config.get_entropy_thresh()
        mean_ent, n_samples = self._window_entropy(distinct_files)
        if ent_thresh > 0:
            if n_samples >= self._MIN_ENT_SAMPLES:
                if mean_ent < ent_thresh:
                    return                         # confidently low -> suppress
            elif len(distinct_files) < 2 * self._MIN_ENT_SAMPLES:
                return                             # not enough evidence -> defer

        self._alerted.add(pid)
        names  = "; ".join(Path(f).name for _, f in recent[:5])
        ent_txt = f"{mean_ent:.2f} bits/byte" if mean_ent is not None else "n/a"
        detail = f"{count}/{ec} events in {ws}s (entropy {ent_txt}): {names}"
        self._emit_alert(pid, full_files, detail, source, mean_ent)


class PipeReader(threading.Thread):
    def __init__(self, pipe_name, detector):
        super().__init__(daemon=True, name="PipeReader")
        self._pipe = pipe_name; self._det = detector
        self._stop = threading.Event()

    def stop(self): self._stop.set()

    def run(self):
        while not self._stop.is_set():
            try:
                with open(self._pipe, "r", encoding="utf-8", errors="replace") as p:
                    for line in p:
                        if self._stop.is_set(): break
                        line = line.strip()
                        if not line:
                            continue

                        # Agent sends FILEPATH|PID|SOURCE. Older builds sent
                        # FILEPATH|PID — still accepted.
                        try:
                            parts = line.rsplit("|", 2)
                            if len(parts) == 3:
                                fp, pid_s, source = parts
                            elif len(parts) == 2:
                                fp, pid_s = parts
                                source = "HEUR"
                            else:
                                continue
                            pid = int(pid_s)
                        except ValueError:
                            continue   # malformed line — expected, skip quietly

                        # Kept separate from the parse guard above: a failure in
                        # here is a bug, not bad input, and must never be
                        # silently discarded (that would drop a real alert).
                        try:
                            self._det.record(fp, pid, source.strip().upper())
                        except Exception as e:
                            _log(f"[PipeReader] detector error on {fp!r}: {e!r}")
            except OSError:
                if not self._stop.is_set(): time.sleep(2)


# ─── Admin privilege detection ────────────────────────────────────────────────

def _is_admin() -> bool:
    """Return True if the process is running with Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ─── Welcome-tour seen flag (persisted in HKCU registry) ─────────────────────

def _hss_reg_open(access=winreg.KEY_READ):
    """Open (creating if necessary) the dedicated HSS settings key."""
    return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, HSS_REG_PATH, 0, access)


def _has_seen_welcome() -> bool:
    """Return True if the user has already completed the welcome tour."""
    try:
        with _hss_reg_open() as k:
            val, _ = winreg.QueryValueEx(k, WELCOME_SEEN_KEY)
            return str(val) == "1"
    except (FileNotFoundError, OSError):
        return False


def _mark_welcome_seen():
    """Persist the 'tour completed' flag so it is not shown again."""
    try:
        with _hss_reg_open(winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, WELCOME_SEEN_KEY, 0, winreg.REG_SZ, "1")
    except OSError as e:
        _log(f"[Welcome] Could not persist seen flag: {e}")


# ─── Watched directory (persisted in HKCU registry) ──────────────────────────

def get_watch_dir() -> str:
    """Directory the agent monitors. Persisted so it survives restarts."""
    try:
        with _hss_reg_open() as k:
            val, _ = winreg.QueryValueEx(k, WATCH_DIR_KEY)
            if val and Path(val).is_dir():
                return str(val)
    except (FileNotFoundError, OSError):
        pass
    return DEFAULT_WATCH_DIR


def set_watch_dir(path) -> bool:
    try:
        with _hss_reg_open(winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, WATCH_DIR_KEY, 0, winreg.REG_SZ, str(path))
        return True
    except OSError as e:
        _log(f"[Config] Could not persist watch directory: {e}")
        return False


# ─── Detection thresholds (persisted in HKCU registry) ───────────────────────
# So k / n / t / entropy survive a restart instead of resetting to defaults.
_CFG_REG = (("file_thresh", "FileThresh"), ("event_cap", "EventCap"),
            ("window_secs", "WindowSecs"), ("entropy_thresh", "EntropyThresh"))


def get_saved_detection():
    """Return {file_thresh, event_cap, window_secs, entropy_thresh} from the
    registry, falling back to the shipped defaults for any missing/invalid value."""
    defaults = {"file_thresh": 5, "event_cap": 10, "window_secs": 0.01, "entropy_thresh": 6.5}
    casts = {"file_thresh": int, "event_cap": int, "window_secs": float, "entropy_thresh": float}
    out = dict(defaults)
    try:
        with _hss_reg_open() as k:
            for attr, name in _CFG_REG:
                try:
                    out[attr] = casts[attr](winreg.QueryValueEx(k, name)[0])
                except (OSError, ValueError):
                    pass
    except OSError:
        pass
    return out


def save_detection(file_thresh, event_cap, window_secs, entropy_thresh):
    vals = {"file_thresh": file_thresh, "event_cap": event_cap,
            "window_secs": window_secs, "entropy_thresh": entropy_thresh}
    try:
        with _hss_reg_open(winreg.KEY_SET_VALUE) as k:
            for attr, name in _CFG_REG:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(vals[attr]))
        return True
    except OSError as e:
        _log(f"[Config] Could not persist detection settings: {e}")
        return False


class AgentManager:
    def __init__(self, exe, watch_dir=None):
        self._exe = exe; self._proc = None
        self._watch_dir = str(watch_dir) if watch_dir else get_watch_dir()

    @property
    def pid(self) -> int | None:
        """PID of the running agent subprocess, or None if not started."""
        return self._proc.pid if self._proc and self._proc.poll() is None else None

    @property
    def watch_dir(self) -> str:
        return self._watch_dir

    def start(self):
        if not self._exe.exists(): return False
        self._proc = subprocess.Popen(
            [str(self._exe), "--watch-dir", self._watch_dir],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW)
        threading.Thread(target=self._fwd, daemon=True).start()
        return True

    def restart(self, watch_dir):
        """Point the agent at a new directory. ReadDirectoryChangesW binds the
        handle at open time, so the subprocess must be restarted to re-target."""
        self._watch_dir = str(watch_dir)
        self.stop()
        time.sleep(0.4)          # let the pipe server tear down before rebinding
        return self.start()

    def _fwd(self):
        for line in self._proc.stdout: _log(f"[Agent] {line.rstrip()}")

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try: self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired: self._proc.kill()


# =============================================================================
# Settings Window  (improved visual)
# =============================================================================
class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, config, detector, agent=None, canary=None):
        super().__init__(parent)
        self._config   = config
        self._detector = detector
        self._agent    = agent
        self._canary   = canary
        self.title("⚙  Detection Settings")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self._build()
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width()  // 2 - self.winfo_width()  // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - self.winfo_height() // 2
        self.geometry(f"+{px}+{py}")

    def _build(self):
        # ── Header strip ──────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=GLOW, pady=14, padx=20)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚙  DETECTION SETTINGS", font=F_MONO_L,
                 bg=GLOW, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text="Changes apply instantly", font=F_MONO_S,
                 bg=GLOW, fg=DIM).pack(side="right")

        body = tk.Frame(self, bg=BG, padx=24, pady=20)
        body.pack(fill="both")

        ft, ec, ws = self._config.get()
        et = self._config.get_entropy_thresh()
        self._vars = {}

        rows = [
            ("file_thresh", "Modified Files", ft, "Alert fires when a program modifies this many files"),
            ("event_cap", "Tracking Limit", ec, "Max number of recent changes to remember per program"),
            ("window_secs", "Time Limit (sec)", ws, "Timeframe to count modifications (e.g. 0.01 for fast threats)"),
            ("entropy_thresh", "Entropy Gate", et, "Min data randomness 0-8 to treat as encryption (0 = rate only)"),
        ]
        for i, (key, label, default, hint) in enumerate(rows):
            # Row container
            row_f = tk.Frame(body, bg=CARD, pady=10, padx=14,
                             highlightthickness=1, highlightbackground=BORDER)
            row_f.pack(fill="x", pady=5)
            row_f.columnconfigure(1, weight=1)

            tk.Label(row_f, text=label, font=F_MONO_L, bg=CARD,
                     fg=TEXT, width=18, anchor="w").grid(row=0, column=0, sticky="w")

            var = tk.StringVar(value=str(default))
            self._vars[key] = var

            if _TTKB_OK:
                ent = ttkb.Entry(row_f, textvariable=var, width=12, font=F_MONO_L)
            else:
                ent = tk.Entry(row_f, textvariable=var, width=10, bg=GLOW,
                               fg=ACCENT, insertbackground=ACCENT,
                               relief="flat", font=F_MONO_L,
                               highlightthickness=2,
                               highlightbackground=BORDER,
                               highlightcolor=ACCENT)
                ent.bind("<FocusIn>",  lambda e, w=ent: w.config(highlightbackground=ACCENT))
                ent.bind("<FocusOut>", lambda e, w=ent: w.config(highlightbackground=BORDER))
            ent.grid(row=0, column=1, padx=(16, 0), sticky="w")

            tk.Label(row_f, text=hint, font=F_MONO_S, bg=CARD,
                     fg=DIM, anchor="w").grid(row=1, column=0, columnspan=3,
                                              sticky="w", pady=(4, 0))

        # ── Watched directory ─────────────────────────────────────────────
        dir_f = tk.Frame(body, bg=CARD, pady=10, padx=14,
                         highlightthickness=1, highlightbackground=BORDER)
        dir_f.pack(fill="x", pady=5)
        dir_f.columnconfigure(0, weight=1)

        tk.Label(dir_f, text="Watched Folder", font=F_MONO_L, bg=CARD,
                 fg=TEXT, anchor="w").grid(row=0, column=0, sticky="w")

        self._dir_var = tk.StringVar(value=get_watch_dir())
        if _TTKB_OK:
            dir_entry = ttkb.Entry(dir_f, textvariable=self._dir_var, font=F_MONO_S)
        else:
            dir_entry = tk.Entry(dir_f, textvariable=self._dir_var, bg=GLOW,
                                 fg=ACCENT, insertbackground=ACCENT, relief="flat",
                                 font=F_MONO_S, highlightthickness=2,
                                 highlightbackground=BORDER, highlightcolor=ACCENT)
        dir_entry.grid(row=1, column=0, sticky="ew", pady=(6, 0))

        if _TTKB_OK:
            ttkb.Button(dir_f, text="Browse…", command=self._browse_dir,
                        bootstyle="secondary", takefocus=False
                        ).grid(row=1, column=1, padx=(8, 0), pady=(6, 0))
        else:
            tk.Button(dir_f, text="Browse…", font=F_MONO_S, bg=CARD, fg=ACCENT,
                      relief="flat", cursor="hand2", padx=10,
                      activebackground=GLOW, activeforeground=ACCENT,
                      command=self._browse_dir).grid(row=1, column=1, padx=(8, 0), pady=(6, 0))

        tk.Label(dir_f, text="Folder the agent monitors. Changing it restarts the agent.",
                 font=F_MONO_S, bg=CARD, fg=DIM, anchor="w"
                 ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # ── Logic hint ────────────────────────────────────────────────────
        hint_f = tk.Frame(body, bg=GLOW, padx=14, pady=10,
                          highlightthickness=1, highlightbackground=BORDER)
        hint_f.pack(fill="x", pady=(12, 0))
        tk.Label(hint_f,
                 text="An alert triggers if a single program modifies the 'Modified Files' amount\n"
                      "within the 'Time Limit', out of the 'Tracking Limit' total events —\n"
                      "AND the written data is at least 'Entropy Gate' random (encryption-like).\n"
                      "Default  →  5 files  /  10 events  /  0.01 s  /  6.5 bits",
                 font=F_MONO_S, bg=GLOW, fg=DIM, justify="left").pack(anchor="w")

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = tk.Frame(self, bg=BG, padx=24, pady=14)
        btn_row.pack(fill="x")

        self._make_btn(btn_row, "RESET", DIM, BG, self._reset).pack(side="left")
        self._make_btn(btn_row, "CANCEL", DIM, BG, self.destroy).pack(side="right", padx=(8,0))
        self._make_btn(btn_row, "✓  APPLY", ACCENT, BG, self._apply,
                       hover_bg=ACCENT, hover_fg=BG).pack(side="right")

    def _make_btn(self, parent, text, fg, bg, cmd, hover_bg=None, hover_fg=None):
        if _TTKB_OK:
            # The primary action (APPLY) passes hover_bg -> make it stand out.
            style = "success" if hover_bg else "secondary"
            return ttkb.Button(parent, text=text, command=cmd,
                               bootstyle=style, takefocus=False)
        b = tk.Button(parent, text=text, font=F_MONO, fg=fg, bg=CARD,
                      relief="flat", cursor="hand2", padx=14, pady=6,
                      activebackground=hover_bg or "#2a3040",
                      activeforeground=hover_fg or TEXT,
                      command=cmd)
        if hover_bg:
            b.bind("<Enter>", lambda e: b.config(bg=GLOW, fg=ACCENT))
            b.bind("<Leave>", lambda e: b.config(bg=CARD, fg=fg))
        return b

    def _browse_dir(self):
        chosen = filedialog.askdirectory(
            parent=self, title="Select folder to monitor",
            initialdir=self._dir_var.get() or DEFAULT_WATCH_DIR)
        if chosen:
            self._dir_var.set(os.path.normpath(chosen))

    def _apply(self):
        try:
            ft = int(self._vars["file_thresh"].get())
            ec = int(self._vars["event_cap"].get())
            ws = float(self._vars["window_secs"].get())
            et = float(self._vars["entropy_thresh"].get())
        except ValueError:
            messagebox.showerror("Invalid Input",
                "File Threshold and Event Cap must be integers.\n"
                "Time Window and Entropy Gate must be decimals (e.g. 0.01, 6.5).", parent=self)
            return
        if ft < 1 or ec < 1 or ws <= 0:
            messagebox.showerror("Invalid Input",
                "File Threshold, Event Cap and Time Window must be greater than zero.", parent=self)
            return
        if not (0.0 <= et <= 8.0):
            messagebox.showerror("Invalid Input",
                "Entropy Gate must be between 0 and 8 (0 disables it).", parent=self)
            return

        new_dir = self._dir_var.get().strip()
        if not new_dir:
            messagebox.showerror("Invalid Folder",
                                 "Watched folder cannot be empty.", parent=self)
            return
        if not Path(new_dir).is_dir():
            messagebox.showerror("Invalid Folder",
                f"This folder does not exist:\n{new_dir}", parent=self)
            return

        self._config.update(ft, ec, ws, entropy_thresh=et)
        save_detection(ft, ec, ws, et)          # survive restart
        self._detector.reset_alerted()

        if os.path.normcase(new_dir) != os.path.normcase(get_watch_dir()):
            set_watch_dir(new_dir)
            if self._canary is not None:
                self._canary.deploy(new_dir)        # move decoys to the new folder
            if self._agent is not None:
                if self._agent.restart(new_dir):
                    messagebox.showinfo(
                        "Watched Folder Changed",
                        f"Now monitoring:\n{new_dir}\n\nThe agent was restarted.",
                        parent=self)
                else:
                    messagebox.showwarning(
                        "Agent Not Restarted",
                        f"Saved '{new_dir}', but the monitor agent could not be "
                        "restarted.\nRestart the application to apply it.",
                        parent=self)
        self.destroy()

    def _reset(self):
        self._vars["file_thresh"].set("5")
        self._vars["event_cap"].set("10")
        self._vars["window_secs"].set("0.01")
        self._vars["entropy_thresh"].set("6.5")
        self._dir_var.set(DEFAULT_WATCH_DIR)


# =============================================================================
# WelcomePage  –  compact floating panel (does NOT cover the dashboard)
#
# Design:
#   • A small card sits pinned to the bottom-right corner of the dashboard,
#     so the user can always see the full UI behind it.
#   • A *separate* transparent Toplevel (ArrowOverlay) draws only the
#     animated arrow that points to the highlighted widget.  Because it is
#     fully transparent with -transparentcolor, it never dims the dashboard.
#   • The panel relocates itself automatically when the root window moves.
# =============================================================================

class _ArrowOverlay:
    """Highlights the current tour target with a pulsing ring and a pointer
    arrow, drawn as lightweight frames placed directly ON the dashboard. Unlike
    a fullscreen transparent overlay it can never cover or dim the UI it is
    describing - it only outlines the widget in focus, so buttons stay visible."""

    def __init__(self, root):
        self._root    = root
        self._parts   = []      # ring bars + arrow label currently shown
        self._anim_id = None
        self._phase   = 0.0     # animation phase for the smooth pulse

    # Kept for API compatibility with the previous overlay implementation.
    def _sync(self):
        pass

    def draw(self, widget, direction):
        """Outline *widget* with a ring and point an arrow at it."""
        self.clear()
        try:
            self._root.update_idletasks()
            rx = self._root.winfo_rootx()
            ry = self._root.winfo_rooty()
            wx = widget.winfo_rootx() - rx
            wy = widget.winfo_rooty() - ry
            ww = widget.winfo_width()
            wh = widget.winfo_height()
        except Exception:
            return
        if ww <= 1 or wh <= 1:
            return

        T   = 4                       # ring thickness
        pad = 4                       # gap between widget and ring
        x1, y1 = wx - pad, wy - pad
        x2, y2 = wx + ww + pad, wy + wh + pad

        def bar(x, y, w, h):
            f = tk.Frame(self._root, bg=ACCENT, highlightthickness=0)
            f.place(x=int(x), y=int(y), width=int(max(1, w)), height=int(max(1, h)))
            f.tkraise()
            self._parts.append(f)

        bar(x1, y1, x2 - x1, T)       # top
        bar(x1, y2 - T, x2 - x1, T)   # bottom
        bar(x1, y1, T, y2 - y1)       # left
        bar(x2 - T, y1, T, y2 - y1)   # right

        arrow = {"left": "\u25c0", "right": "\u25b6",
                 "up": "\u25b2", "down": "\u25bc"}.get(direction)
        if arrow:
            lbl = tk.Label(self._root, text=arrow, font=("Segoe UI", 22, "bold"),
                           bg=BG, fg=ACCENT)
            if direction == "left":      ax, ay = x2 + 4,  wy + wh // 2 - 16
            elif direction == "right":   ax, ay = x1 - 34, wy + wh // 2 - 16
            elif direction == "down":    ax, ay = wx + ww // 2 - 12, y1 - 34
            else:                        ax, ay = wx + ww // 2 - 12, y2 + 4
            lbl.place(x=int(max(2, ax)), y=int(max(2, ay)))
            lbl.lift()
            self._parts.append(lbl)

        self._animate()

    _PULSE_BRIGHT = "#8be9ff"   # light cyan — ring never dims below ACCENT

    def _animate(self):
        # Smooth "breathing" fade between ACCENT and a lighter cyan, updated in
        # small steps, rather than a hard on/off blink.
        self._phase += 0.16
        t = 0.5 - 0.5 * math.cos(self._phase)      # eased 0 -> 1 -> 0
        col = _lerp_hex(ACCENT, self._PULSE_BRIGHT, t)
        for p in self._parts:
            try:
                p.configure(bg=col) if isinstance(p, tk.Frame) else p.configure(fg=col)
            except Exception:
                pass
        self._anim_id = self._root.after(45, self._animate)

    def clear(self):
        if self._anim_id:
            try: self._root.after_cancel(self._anim_id)
            except Exception: pass
            self._anim_id = None
        for p in self._parts:
            try: p.destroy()
            except Exception: pass
        self._parts = []

    def destroy(self):
        self.clear()


class WelcomePage(tk.Toplevel):
    """
    Compact floating tour card pinned to the bottom-right of the dashboard.
    The dashboard remains fully visible and interactive behind the card.
    A separate _ArrowOverlay draws the jumping pointer arrow.
    """

    # Panel dimensions
    _PW = S(370)
    _PH = S(430)
    _FONT_BUMP = 1   # added to every STEPS line size — keeps the tour legible
    _MARGIN = S(14)   # gap from dashboard edge

    STEPS = [
        {
            "id":    "intro",
            "title": "Welcome to Hybrid Security Suite",
            "lines": [
                ("⬡", ACCENT, 22, "bold"),
                ("", None, 2, ""),
                ("Shields your Windows PC from ransomware:", TEXT, 9, ""),
                ("", None, 4, ""),
                ("  🔴  Ransomware", RED, 10, "bold"),
                ("      Malware encrypting files in seconds.", DIM, 9, ""),
                ("", None, 6, ""),
                ("Click  Next  for the interactive tour ▶", ACCENT, 9, "italic"),
            ],
            "target": None,
            "arrow_dir": None,
        },
        {
            "id":    "toggle",
            "title": "① Monitoring Toggle",
            "lines": [
                ("● MONITORING  /  ◉ PAUSED", GREEN, 10, "bold"),
                ("", None, 5, ""),
                ("Pause all detection instantly.", TEXT, 9, ""),
                ("", None, 4, ""),
                ("Use BEFORE large file operations:", DIM, 9, ""),
                ("  • Backup / bulk copy", DIM, 9, ""),
                ("  • Software installation", DIM, 9, ""),
                ("  • Antivirus full scan", DIM, 9, ""),
                ("", None, 4, ""),
                ("→ OFF before  ·  ON after", ACCENT, 9, "italic"),
            ],
            "target": "toggle",
            "arrow_dir": "right",
        },
        {
            "id":    "logs",
            "title": "② Your Detection Log",
            "lines": [
                ("This is your history of every alarm.", TEXT, 9, ""),
                ("", None, 5, ""),
                ("🔴  A red row means a program was", RED, 9, "bold"),
                ("     caught changing files too fast —", DIM, 9, ""),
                ("     the sign of ransomware.", DIM, 9, ""),
                ("", None, 5, ""),
                ("👆  Double-click any row to see", ACCENT, 9, "bold"),
                ("     which files were hit, how it was", DIM, 9, ""),
                ("     caught, and to undo the block or", DIM, 9, ""),
                ("     freeze the program.", DIM, 9, ""),
                ("", None, 5, ""),
                ("🔍  Search past alerts, or click a", DIM, 9, ""),
                ("     column title to sort them.", DIM, 9, ""),
            ],
            "target": "logs",
            "arrow_dir": "down",
        },
        {
            "id":    "graph",
            "title": "③ Live Activity",
            "lines": [
                ("Your files, watched in real time.", TEXT, 9, ""),
                ("", None, 5, ""),
                ("Each bar shows how busy your files", DIM, 9, ""),
                ("are right now.", DIM, 9, ""),
                ("", None, 5, ""),
                ("🟠  The dotted line is the alarm level.", ORANGE, 9, ""),
                ("", None, 3, ""),
                ("🔴  Bars turn red when activity spikes", RED, 9, ""),
                ("     past it — that's what an attack", DIM, 9, ""),
                ("     looks like.", DIM, 9, ""),
                ("", None, 5, ""),
                ("Low and calm  =  you're safe. ✓", GREEN, 9, "italic"),
            ],
            "target": "graph",
            "arrow_dir": "down",
        },
        {
            "id":    "settings",
            "title": "④ Detection Settings",
            "lines": [
                ("Click ⚙ SETTINGS to tune the sensor.", TEXT, 9, ""),
                ("", None, 5, ""),
                ("File Threshold", ACCENT, 9, "bold"),
                ("  Modifications needed to fire alert", DIM, 9, ""),
                ("", None, 2, ""),
                ("Event Cap", ACCENT, 9, "bold"),
                ("  Rolling window size per PID", DIM, 9, ""),
                ("", None, 2, ""),
                ("Time Window", ACCENT, 9, "bold"),
                ("  Seconds evaluated (0.01 = 10 ms)", DIM, 9, ""),
                ("", None, 4, ""),
                ("Default: 5 files / 10 events / 0.01 s", YELLOW, 9, "bold"),
            ],
            "target": "settings",
            "arrow_dir": "right",
        },
        {
            "id":    "done",
            "title": "You're all set! 🛡",
            "lines": [
                ("The suite is now active.", TEXT, 9, ""),
                ("", None, 5, ""),
                ("C++ agent watches:", DIM, 9, ""),
                # {watch_dir} is substituted at render time — the folder is
                # user-configurable via Settings, so it must not be hardcoded.
                ("  {watch_dir}", ACCENT, 9, ""),
                ("", None, 4, ""),
                ("🔔  Sound + banner alert on every", DIM, 9, ""),
                ("    ransomware detection.", DIM, 9, ""),
                ("", None, 5, ""),
                ("Press  Esc  or  ✓ Let's go!  to close.", DIM, 9, "italic"),
            ],
            "target": None,
            "arrow_dir": None,
        },
    ]

    def __init__(self, root, widget_map):
        super().__init__(root)
        self._root   = root
        self._wmap   = widget_map
        self._step   = 0

        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg=ACCENT)        # 1-px accent border via bg

        # Separate transparent arrow overlay
        self._arrow_overlay = _ArrowOverlay(root)
        self._cur_target = None          # widget the current step points at
        self._repos_pending = False      # debounce guard for _reposition
        self._last_place = None          # last placement actually drawn

        self._build()

        # Reposition when the DASHBOARD ITSELF moves or resizes. Filtered to the
        # root window and debounced: drawing the highlight ring creates child
        # widgets whose own <Configure> events must never re-trigger this, or a
        # draw -> configure -> reposition -> draw loop freezes the app and makes
        # the ring flicker frantically.
        root.bind("<Configure>", self._on_root_configure, add="+")
        self.bind("<Escape>", lambda e: self._finish())
        self._render_step()

    def _on_root_configure(self, e):
        if e.widget is not self._root or self._repos_pending:
            return
        self._repos_pending = True
        self.after(80, self._reposition)

    # ── Positioning ───────────────────────────────────────────────────────

    _ARROW_SPAN = S(62)   # how far the drawn arrow reaches from the target edge

    def _compute_placement(self, target):
        """Return (card_x, card_y, arrow_dir) in screen coords. The card is
        placed BESIDE the target (never over it) on whichever side has more
        room, and the arrow is drawn in the gap between them so it is always
        on-screen. arrow_dir is None for steps with no target (card centred)."""
        self._root.update_idletasks()
        rx, ry = self._root.winfo_rootx(), self._root.winfo_rooty()
        rw, rh = self._root.winfo_width(), self._root.winfo_height()

        if target is None:
            return (rx + (rw - self._PW) // 2,
                    ry + (rh - self._PH) // 2, None)

        tx, ty = target.winfo_rootx(), target.winfo_rooty()
        tw, th = target.winfo_width(), target.winfo_height()

        # Put the card on the side of the target with more free space.
        room_left  = tx - rx
        room_right = (rx + rw) - (tx + tw)
        if room_right >= room_left:
            arrow_dir = "left"                       # arrow right of target, points left
            cx = tx + tw + self._ARROW_SPAN
        else:
            arrow_dir = "right"                      # arrow left of target, points right
            cx = tx - self._ARROW_SPAN - self._PW

        cx = max(rx + self._MARGIN, min(cx, rx + rw - self._PW - self._MARGIN))
        cy = ty + th // 2 - self._PH // 2
        cy = max(ry + self._MARGIN, min(cy, ry + rh - self._PH - self._MARGIN))
        return int(cx), int(cy), arrow_dir

    def _reposition(self):
        """Place the card beside the current step's target and (re)draw the ring —
        but ONLY when the placement actually changed. A stable tour step must never
        keep redrawing, or the redraw re-triggers a <Configure> and loops."""
        self._repos_pending = False
        try:
            cx, cy, arrow_dir = self._compute_placement(self._cur_target)
            place = (self._cur_target, cx, cy, arrow_dir)
            if place == self._last_place:
                return                       # nothing moved — do not redraw
            self._last_place = place
            self.geometry(f"{self._PW}x{self._PH}+{cx}+{cy}")
            if self._cur_target is not None and arrow_dir is not None:
                self._arrow_overlay.draw(self._cur_target, arrow_dir)
            else:
                self._arrow_overlay.clear()
        except Exception:
            pass

    # ── Build panel skeleton ──────────────────────────────────────────────

    def _build(self):
        inner = tk.Frame(self, bg=CARD)
        inner.place(x=1, y=1,
                    width=self._PW - 2, height=self._PH - 2)

        # Header
        hdr = tk.Frame(inner, bg=GLOW, pady=8, padx=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬡  TOUR",
                 font=("Consolas", 13, "bold"), bg=GLOW, fg=ACCENT).pack(side="left")
        tk.Button(hdr, text="✕", font=F_MONO_S, bg=GLOW, fg=DIM,
                  relief="flat", cursor="hand2",
                  activebackground=RED, activeforeground=TEXT,
                  command=self._finish).pack(side="right")

        # Step dots
        dot_row = tk.Frame(inner, bg=CARD)
        dot_row.pack(pady=(6, 0))
        self._dots = []
        for i in range(len(self.STEPS)):
            d = tk.Label(dot_row, text="●", font=("Consolas", 7),
                         bg=CARD, fg=BORDER)
            d.pack(side="left", padx=2)
            self._dots.append(d)

        # Footer — packed to the bottom BEFORE the content frame, so a tall step
        # can never push the navigation buttons out of the fixed-size panel.
        nav = tk.Frame(inner, bg=GLOW, pady=8, padx=12)
        nav.pack(fill="x", side="bottom")
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", side="bottom")

        # Content
        self._content = tk.Frame(inner, bg=CARD)
        self._content.pack(fill="both", expand=True, padx=14, pady=(6, 0))

        self._back_btn = tk.Button(nav, text="← Back", font=F_MONO_S,
                                   bg=GLOW, fg=DIM, relief="flat",
                                   cursor="hand2", padx=6,
                                   activebackground=CARD,
                                   command=self._back)
        self._back_btn.pack(side="left")

        tk.Button(nav, text="Skip", font=F_MONO_S, bg=GLOW, fg=DIM,
                  relief="flat", cursor="hand2", padx=6,
                  activebackground=CARD,
                  command=self._finish).pack(side="left", padx=(6, 0))

        self._step_lbl = tk.Label(nav, text="", font=F_MONO_S,
                                  bg=GLOW, fg=DIM)
        self._step_lbl.pack(side="right", padx=8)

        self._next_btn = tk.Button(nav, text="Next →",
                                   font=("Consolas", 11, "bold"),
                                   bg=ACCENT, fg=BG, relief="flat",
                                   cursor="hand2", padx=12, pady=3,
                                   activebackground=ACCENT_DIM,
                                   command=self._next)
        self._next_btn.pack(side="right")

    # ── Step rendering ────────────────────────────────────────────────────

    def _render_step(self):
        self._arrow_overlay.clear()

        s = self.STEPS[self._step]

        # Dots
        for i, d in enumerate(self._dots):
            d.configure(fg=(ACCENT if i == self._step else BORDER))

        # Step counter
        self._step_lbl.configure(text=f"{self._step + 1}/{len(self.STEPS)}")

        # Back button state
        is_first = (self._step == 0)
        self._back_btn.configure(
            state="disabled" if is_first else "normal",
            fg=(BORDER if is_first else DIM))

        # Next button label
        is_last = (self._step == len(self.STEPS) - 1)
        self._next_btn.configure(
            text="✓ Let's go!" if is_last else "Next →",
            bg=(GREEN if is_last else ACCENT),
            activebackground=("#00a050" if is_last else ACCENT_DIM))

        # Clear and repopulate content frame
        for w in self._content.winfo_children():
            w.destroy()

        tk.Label(self._content, text=s["title"],
                 font=("Consolas", 12, "bold"), bg=CARD,
                 fg=TEXT, wraplength=self._PW - 32,
                 justify="left", anchor="w").pack(fill="x", pady=(2, 6))

        tk.Frame(self._content, bg=BORDER, height=1).pack(fill="x", pady=(0, 6))

        for (text, color, size, style) in s["lines"]:
            if not text:
                tk.Frame(self._content, bg=CARD, height=size).pack()
                continue
            if "{watch_dir}" in text:
                text = text.replace("{watch_dir}", get_watch_dir())
            weight = "bold"   if "bold"   in style else "normal"
            slant  = "italic" if "italic" in style else "roman"
            tk.Label(self._content, text=text,
                     font=("Consolas", size + self._FONT_BUMP, weight, slant),
                     bg=CARD, fg=(color or CARD),
                     anchor="w", justify="left",
                     wraplength=self._PW - 32).pack(fill="x")

        # Place the card beside this step's target and point the arrow at it.
        # The card is sized by its content, so wait for layout before measuring.
        self._cur_target = self._wmap.get(s["target"]) if s["target"] else None
        self._last_place = None          # force a redraw for the new step
        self.after(60, self._reposition)

    # ── Navigation ────────────────────────────────────────────────────────

    def _next(self):
        if self._step < len(self.STEPS) - 1:
            self._step += 1
            self._render_step()
        else:
            self._finish()

    def _back(self):
        if self._step > 0:
            self._step -= 1
            self._render_step()

    def _finish(self):
        self._arrow_overlay.clear()
        try: self._arrow_overlay.destroy()
        except Exception: pass
        self.destroy()


# =============================================================================
# ActivityGraph  –  live bar-chart of file-modification rate (hand-drawn canvas)
# =============================================================================
class ActivityGraph(tk.Frame):
    """Rolling bar chart of file-system events across all watched processes,
    redrawn on its own timer independent of DASHBOARD_REFRESH. This visualises
    overall monitored activity — not a literal redraw of RansomwareDetector's
    per-PID 0.01s detection window, which is far too fast to animate usefully."""

    _WINDOW_SECS = 30.0
    _BUCKETS     = 30
    _TICK_MS     = 500

    def __init__(self, parent, detector, config):
        super().__init__(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self._detector = detector
        self._config   = config
        self._after_id = None

        # Title and rate sit on separate rows — side-by-side they collide once the
        # panel is narrower than the two labels combined.
        hdr = tk.Frame(self, bg=CARD, padx=10, pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text="◈  FILE ACTIVITY", font=F_MONO,
                 bg=CARD, fg=ACCENT, anchor="w").pack(fill="x")
        self._rate_lbl = tk.Label(hdr, text="", font=("Consolas", 10),
                                  bg=CARD, fg=DIM, anchor="w")
        self._rate_lbl.pack(fill="x")

        self._canvas = tk.Canvas(self, bg=CARD, highlightthickness=0, height=S(180))
        self._canvas.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        tk.Label(self, text="Aggregate activity across all watched processes — "
                             "not the exact per-process detection window.",
                 font=("Consolas", 9), bg=CARD, fg=DIM, wraplength=S(340),
                 justify="left", anchor="w").pack(fill="x", padx=10, pady=(0, 8))

        self._tick()

    def stop(self):
        if self._after_id:
            try: self.after_cancel(self._after_id)
            except Exception: pass
            self._after_id = None

    def _tick(self):
        self._draw()
        self._after_id = self.after(self._TICK_MS, self._tick)

    def _draw(self):
        counts = self._detector.recent_rate(self._WINDOW_SECS, self._BUCKETS)
        ft, _, _ = self._config.get()

        c = self._canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w <= 1 or h <= 1:
            return

        pad_b = 4
        usable_h = h - pad_b
        peak = max(max(counts, default=0), ft, 1)
        bar_w = w / self._BUCKETS

        for i, cnt in enumerate(counts):
            bar_h = (cnt / peak) * usable_h
            x0, x1 = i * bar_w + 1, (i + 1) * bar_w - 1
            y1 = h - pad_b
            y0 = y1 - bar_h
            color = RED if cnt >= ft else ACCENT
            c.create_rectangle(x0, y0, x1, y1, fill=color, outline="")

        # Threshold reference line at the current file_thresh (k)
        thresh_y = h - pad_b - (ft / peak) * usable_h
        c.create_line(0, thresh_y, w, thresh_y, fill=ORANGE, dash=(4, 2), width=1)

        self._rate_lbl.configure(text=f"{sum(counts)} evt / {int(self._WINDOW_SECS)}s")


# =============================================================================
# AlertDetailWindow  –  drill-down into a single alert + reverse containment
# =============================================================================
class AlertDetailWindow(tk.Toplevel):
    def __init__(self, parent, db, alert_id, on_change=None, agent_pid=None,
                 suspended=None):
        super().__init__(parent)
        self._db        = db
        self._alert_id  = alert_id
        self._on_change = on_change
        self._agent_pid = agent_pid
        # Shared set of PIDs this session has suspended, so reopening the window
        # shows Resume rather than Suspend.
        self._suspended = suspended if suspended is not None else set()
        self._locked_dir = None
        self._pid = None

        self.title("Alert Details")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()

        self._build()
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width()  // 2 - self.winfo_width()  // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - self.winfo_height() // 2
        self.geometry(f"+{px}+{py}")

    def _build(self):
        row = self._db.get_alert_by_id(self._alert_id)
        if row is None:
            self.destroy()
            return
        (aid, ts, atype, attacker, detail, status, files_json,
         locked_dir, lock_active, attribution, entropy, pid) = row
        self._locked_dir = locked_dir
        self._pid = pid
        self._attribution = attribution

        hdr = tk.Frame(self, bg=GLOW, pady=14, padx=20)
        hdr.pack(fill="x")
        tk.Label(hdr, text="◈  ALERT DETAILS", font=F_MONO_L,
                 bg=GLOW, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text=f"#{aid}", font=F_MONO_S,
                 bg=GLOW, fg=DIM).pack(side="right")

        body = tk.Frame(self, bg=BG, padx=24, pady=16)
        body.pack(fill="both")

        if attribution == "ETW":
            attr_text, attr_color = "ETW (accurate — kernel-reported PID)", GREEN
        else:
            attr_text, attr_color = "HEURISTIC (best-effort guess)", ORANGE

        if entropy is None:
            ent_text, ent_color = "n/a (written data unreadable)", DIM
        else:
            # ~8 bits/byte = encrypted/compressed; low = plain document/text.
            ent_text = f"{entropy:.2f} bits/byte"
            ent_color = RED if entropy >= 7.0 else (ORANGE if entropy >= 5.0 else GREEN)
            ent_text += "  (high — encryption-like)" if entropy >= 7.0 else ""

        for label, value, color in (
            ("Timestamp",   ts,        TEXT),
            ("Type",        atype,     RED),
            ("Attacker",    attacker,  TEXT),
            ("Attribution", attr_text, attr_color),
            ("Write entropy", ent_text, ent_color),
            ("Status",      status,    TEXT),
        ):
            row_f = tk.Frame(body, bg=BG)
            row_f.pack(fill="x", pady=2)
            tk.Label(row_f, text=f"{label}:", font=F_MONO_S, bg=BG,
                     fg=DIM, width=12, anchor="w").pack(side="left")
            tk.Label(row_f, text=value, font=F_MONO, bg=BG,
                     fg=color, anchor="w").pack(side="left")

        tk.Label(body, text="Affected files:", font=F_MONO_S,
                 bg=BG, fg=DIM, anchor="w").pack(fill="x", pady=(12, 4))

        list_frame = tk.Frame(body, bg=CARD, highlightthickness=1,
                              highlightbackground=BORDER)
        list_frame.pack(fill="both", expand=True)
        vsb = ttk.Scrollbar(list_frame, orient="vertical")
        lb = tk.Listbox(list_frame, bg=CARD, fg=TEXT, relief="flat",
                        font=F_MONO_S, height=8, width=54,
                        highlightthickness=0, selectbackground=GLOW,
                        yscrollcommand=vsb.set)
        vsb.configure(command=lb.yview)
        vsb.pack(side="right", fill="y")
        lb.pack(side="left", fill="both", expand=True)
        try:
            files = json.loads(files_json) if files_json else []
        except (json.JSONDecodeError, TypeError):
            files = []
        for f in files:
            lb.insert("end", f)
        if not files:
            lb.insert("end", "(no file list recorded)")

        self._lock_frame = tk.Frame(body, bg=BG)
        self._lock_frame.pack(fill="x", pady=(14, 0))
        self._render_lock_section(locked_dir, lock_active)

        self._proc_frame = tk.Frame(body, bg=BG)
        self._proc_frame.pack(fill="x", pady=(10, 0))
        self._render_proc_section()

        btn_row = tk.Frame(self, bg=BG, padx=24, pady=14)
        btn_row.pack(fill="x")
        _tbutton(btn_row, "CLOSE", self.destroy, "secondary").pack(side="right")

    def _render_lock_section(self, locked_dir, lock_active):
        for w in self._lock_frame.winfo_children():
            w.destroy()

        if locked_dir and lock_active:
            box = tk.Frame(self._lock_frame, bg=GLOW, padx=14, pady=10,
                           highlightthickness=1, highlightbackground=BORDER)
            box.pack(fill="x")
            tk.Label(box, text=f"🔒  Directory Locked: {locked_dir}",
                     font=F_MONO_S, bg=GLOW, fg=RED, anchor="w",
                     wraplength=S(380), justify="left").pack(fill="x")
            _tbutton(box, "🔓  Unlock Directory", self._unlock, "success").pack(anchor="w", pady=(8, 0))
        elif locked_dir and not lock_active:
            tk.Label(self._lock_frame,
                     text=f"🔓  Directory was locked, now unlocked:\n{locked_dir}",
                     font=F_MONO_S, bg=BG, fg=DIM, anchor="w",
                     wraplength=S(380), justify="left").pack(fill="x")
        else:
            tk.Label(self._lock_frame,
                     text="⚠  Containment was not applied (insufficient privileges or icacls error).",
                     font=F_MONO_S, bg=BG, fg=ORANGE, anchor="w",
                     wraplength=S(380), justify="left").pack(fill="x")

    def _render_proc_section(self):
        for w in self._proc_frame.winfo_children():
            w.destroy()

        # Already suspended this session -> offer the reverse action.
        if self._pid in self._suspended:
            box = tk.Frame(self._proc_frame, bg=GLOW, padx=14, pady=10,
                           highlightthickness=1, highlightbackground=BORDER)
            box.pack(fill="x")
            tk.Label(box, text=f"⏸  Process suspended: PID {self._pid}",
                     font=F_MONO_S, bg=GLOW, fg=YELLOW, anchor="w").pack(fill="x")
            _tbutton(box, "▶  Resume Process", self._resume, "success").pack(anchor="w", pady=(8, 0))
            return

        ok, reason = containment_precheck(self._pid, self._attribution, self._agent_pid)
        if ok:
            box = tk.Frame(self._proc_frame, bg=CARD, padx=14, pady=10,
                           highlightthickness=1, highlightbackground=BORDER)
            box.pack(fill="x")
            tk.Label(box, text=f"Process containment available (PID {self._pid}, ETW-verified)",
                     font=F_MONO_S, bg=CARD, fg=TEXT, anchor="w",
                     wraplength=S(380), justify="left").pack(fill="x")
            _tbutton(box, "⏸  Suspend Process", self._suspend, "warning").pack(anchor="w", pady=(8, 0))
        else:
            # Explain WHY it's unavailable — usually "heuristic PID, not safe".
            tk.Label(self._proc_frame, text=f"⚠  Process suspend unavailable: {reason}",
                     font=F_MONO_S, bg=BG, fg=DIM, anchor="w",
                     wraplength=S(380), justify="left").pack(fill="x")

    def _suspend(self):
        ok, reason = containment_precheck(self._pid, self._attribution, self._agent_pid)
        if not ok:
            messagebox.showerror("Cannot Suspend", reason, parent=self)
            return
        pname = _process_name(self._pid) or "the process"
        if not messagebox.askyesno(
                "Confirm Suspend",
                f"Suspend all threads of {pname} (PID {self._pid})?\n\n"
                "This freezes the process immediately. It is reversible — a "
                "Resume Process button will appear so you can undo it.",
                parent=self):
            return
        ok, err = suspend_process(self._pid)
        if ok:
            self._suspended.add(self._pid)
            messagebox.showinfo("Process Suspended",
                                f"PID {self._pid} is now frozen.", parent=self)
            self._render_proc_section()
            if self._on_change:
                self._on_change()
        else:
            messagebox.showerror("Suspend Failed", err, parent=self)

    def _resume(self):
        ok, err = resume_process(self._pid)
        if ok:
            self._suspended.discard(self._pid)
            messagebox.showinfo("Process Resumed",
                                f"PID {self._pid} has been resumed.", parent=self)
            self._render_proc_section()
            if self._on_change:
                self._on_change()
        else:
            messagebox.showerror("Resume Failed", err, parent=self)

    def _unlock(self):
        if not messagebox.askyesno(
                "Confirm Unlock",
                f"Restore write access to:\n{self._locked_dir}\n\n"
                "This reverses the ransomware containment lockdown.",
                parent=self):
            return
        ok, err = directory_unlock(self._locked_dir)
        if ok:
            self._db.mark_unlocked(self._alert_id)
            messagebox.showinfo("Unlocked",
                                f"Write access restored to:\n{self._locked_dir}", parent=self)
            self._render_lock_section(self._locked_dir, 0)
            if self._on_change:
                self._on_change()
        else:
            messagebox.showerror("Unlock Failed", err, parent=self)


# =============================================================================
# Dashboard  –  redesigned with scanline bg, glow stats, animated bars
# =============================================================================
class Dashboard(ttkb.Window if _TTKB_OK else tk.Tk):
    def __init__(self, db, config, state, detector,
                 live_mode: bool = True, agent: "AgentManager | None" = None,
                 canary=None):
        if _TTKB_OK:
            super().__init__(themename=UI_THEME)
            # Remap the module palette to the theme so the custom-drawn parts
            # (hero band, activity graph, treeview tags, stat cards) match the
            # themed ttk widgets.
            _apply_theme_palette(self.style.colors)
        else:
            super().__init__()
        self._db        = db
        self._config    = config
        self._state     = state
        self._detector  = detector
        self._live_mode = live_mode
        self._agent     = agent
        self._canary    = canary
        # Track the newest alert id (not the row count) so notifications keep
        # firing after the 200-row query cap is reached.
        self._prev_max_id = 0
        self._banner_after = None
        # Wall-clock of the last new alert, so the hero band shows THREAT briefly.
        self._last_alert_ts = 0.0
        # PIDs suspended via a drill-down this session (shared with each window).
        self._suspended_pids = set()

        self._search_var   = tk.StringVar()
        self._sort_col     = None
        self._sort_reverse = False

        # psutil handles for CPU sampling (initialised lazily in _refresh)
        self._py_proc:  "_psutil.Process | None" = None
        self._cpp_proc: "_psutil.Process | None" = None

        self.title("Hybrid Security Suite")
        self.configure(bg=BG)
        self.geometry(f"{S(1260)}x{S(840)}")
        self.minsize(S(1000), S(680))

        self._build_ui()
        self._schedule_refresh()
        self.protocol("WM_DELETE_WINDOW", self._on_window_close)

    # ── UI build ──────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top bar ────────────────────────────────────────────────────────
        self._hdr = tk.Frame(self, bg=PANEL)
        self._hdr.pack(fill="x", side="top")

        left_hdr = tk.Frame(self._hdr, bg=PANEL)
        tk.Label(left_hdr, text="⬡", font=("Segoe UI Emoji", 20),
                 bg=PANEL, fg=ACCENT).pack(side="left")
        tk.Label(left_hdr, text="  HYBRID SECURITY SUITE",
                 font=F_TITLE, bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(left_hdr, text="  v2.0", font=F_MONO_S,
                 bg=PANEL, fg=DIM).pack(side="left", pady=(4, 0))

        right_hdr = tk.Frame(self._hdr, bg=PANEL)
        # Pack the right cluster FIRST so the Settings/Tour/Monitoring controls
        # always claim the right edge and never clip off-screen on a narrow
        # window; the title on the left yields space instead.
        right_hdr.pack(side="right", padx=16, pady=9)
        left_hdr.pack(side="left", padx=(18, 0), pady=12)

        # Live mode pill
        if self._live_mode:
            self._mode_lbl = tk.Label(right_hdr, text="  ● LIVE  ",
                                      font=("Consolas", 8, "bold"),
                                      bg=HERO_GREEN, fg=GREEN)
        else:
            self._mode_lbl = tk.Label(right_hdr, text="  ⚠ SIMULATED  ",
                                      font=("Consolas", 8, "bold"),
                                      bg=HERO_ORANGE, fg=ORANGE)
        self._mode_lbl.pack(side="left", padx=(0, 8))

        self._thresh_lbl = tk.Label(right_hdr, text="",
                                    font=F_MONO_S, bg=PANEL, fg=DIM)
        self._thresh_lbl.pack(side="left", padx=(0, 10))

        self._settings_btn = self._hdr_btn(right_hdr, "⚙  Settings",
                                           DIM, self._open_settings)
        self._settings_btn.pack(side="left", padx=4)
        self._make_hdr_btn(right_hdr, "?  Tour", DIM,
                           self._show_tour).pack(side="left", padx=4)

        # Monitoring control — a rounded toggle SWITCH, deliberately styled
        # unlike the flat Settings/Tour buttons so its on/off function is obvious.
        self._monitor_var = tk.BooleanVar(value=self._state.active)
        if _TTKB_OK:
            self._toggle_btn = ttkb.Checkbutton(
                right_hdr, text="  Monitoring",
                variable=self._monitor_var,
                bootstyle="success-round-toggle",
                takefocus=False, command=self._on_monitor_toggle)
        else:
            self._toggle_btn = tk.Button(
                right_hdr, text="🛡  MONITORING: ON",
                font=("Consolas", 9, "bold"), bg="#0d2e1a", fg=GREEN,
                relief="flat", cursor="hand2", padx=14, pady=5,
                activebackground="#1a4a2a", command=self._toggle_monitoring)
            self._apply_btn_glow(self._toggle_btn, GREEN)
        self._toggle_btn.pack(side="left", padx=(14, 0))

        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x")

        # ── New-alert banner (hidden until the first alert fires) ──────────
        self._banner = tk.Frame(self, bg=RED, pady=7)
        self._banner_lbl = tk.Label(self._banner, text="",
                                    font=("Consolas", 12, "bold"), bg=RED, fg=TEXT)
        self._banner_lbl.pack()

        # ── HERO protection-status band ────────────────────────────────────
        self._hero = tk.Frame(self, bg=HERO_GREEN)
        self._hero.pack(fill="x")
        self._hero_accent = tk.Frame(self._hero, bg=GREEN, width=S(5))
        self._hero_accent.pack(side="left", fill="y")
        self._hero_in = tk.Frame(self._hero, bg=HERO_GREEN, padx=22, pady=16)
        self._hero_in.pack(side="left", fill="both", expand=True)
        self._hero_icon = tk.Label(self._hero_in, text="🛡", font=F_HERO_ICON,
                                   bg=HERO_GREEN, fg=GREEN)
        self._hero_icon.pack(side="left", padx=(0, 18))
        self._hero_txt = tk.Frame(self._hero_in, bg=HERO_GREEN)
        self._hero_txt.pack(side="left", fill="y")
        self._hero_title = tk.Label(self._hero_txt, text="PROTECTED", font=F_HERO,
                                    bg=HERO_GREEN, fg=GREEN, anchor="w")
        self._hero_title.pack(anchor="w")
        self._hero_sub = tk.Label(self._hero_txt, text="", font=F_MONO_S,
                                  bg=HERO_GREEN, fg=TEXT, anchor="w", justify="left")
        self._hero_sub.pack(anchor="w")

        # ── Stat cards row ─────────────────────────────────────────────────
        stats_row = tk.Frame(self, bg=BG)
        stats_row.pack(fill="x", padx=14, pady=(12, 4))
        self._stat_total     = self._stat_card(stats_row, "🔔", "TOTAL ALERTS",       "0", ACCENT)
        self._stat_locked    = self._stat_card(stats_row, "🔒", "DIRECTORIES LOCKED", "0", RED)
        self._stat_suspended = self._stat_card(stats_row, "⏸", "PROCESSES HELD",     "0", YELLOW)
        self._stat_cpu       = self._stat_card(stats_row, "📊", "AGENT CPU",          "–", GREEN)

        # ── Main body ──────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=14, pady=(4, 8))

        # Left: detection log
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        log_hdr = tk.Frame(left, bg=BG)
        log_hdr.pack(fill="x", pady=(0, 6))
        self._section_label(log_hdr, "DETECTION LOG", ACCENT).pack(side="left")

        self._log_count_lbl = tk.Label(log_hdr, text="",
                                       font=F_MONO_S, bg=BG, fg=DIM)
        self._log_count_lbl.pack(side="right")
        tk.Label(log_hdr, text="🔍", font=F_MONO_S, bg=BG, fg=DIM).pack(side="right", padx=(10, 4))
        if _TTKB_OK:
            self._search_entry = ttkb.Entry(log_hdr, width=26,
                                            textvariable=self._search_var)
        else:
            self._search_entry = tk.Entry(
                log_hdr, width=24, textvariable=self._search_var,
                bg=GLOW, fg=ACCENT, insertbackground=ACCENT, relief="flat",
                font=F_MONO_S, highlightthickness=2,
                highlightbackground=BORDER, highlightcolor=ACCENT)
        self._search_entry.pack(side="right")
        self._search_entry.bind("<KeyRelease>", lambda e: self._refresh())

        # Prominent call-to-action ABOVE the log so the drill-down is discoverable.
        # Styled like a button (accent border + hand cursor) because the log rows
        # themselves give no visual hint that they can be opened.
        hint = tk.Frame(left, bg=GLOW, highlightthickness=1,
                        highlightbackground=ACCENT, cursor="hand2")
        hint.pack(fill="x", pady=(0, 6))
        hint_lbl = tk.Label(
            hint, bg=GLOW, fg=ACCENT, font=("Consolas", 13, "bold"), pady=8,
            text="👆  DOUBLE-CLICK ANY ROW  —  see affected files, attribution, "
                 "entropy and containment options")
        hint_lbl.pack()
        for w in (hint, hint_lbl):
            w.bind("<Enter>", lambda e: (hint.configure(bg=CARD2), hint_lbl.configure(bg=CARD2)))
            w.bind("<Leave>", lambda e: (hint.configure(bg=GLOW), hint_lbl.configure(bg=GLOW)))
            w.bind("<Button-1>", lambda e: self._open_selected_or_first_alert())

        self._log_frame = tk.Frame(left, bg=CARD,
                                   highlightthickness=1, highlightbackground=BORDER)
        self._log_frame.pack(fill="both", expand=True)
        self._log_tree = self._make_treeview(
            self._log_frame,
            columns=("Timestamp", "Type", "Attacker", "Detail", "Status"),
            widths=(S(225), S(110), S(190), 0, S(105)),
            stretch_col="Detail",
        )
        for col in ("Timestamp", "Type", "Attacker", "Detail", "Status"):
            self._log_tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
        self._log_tree.bind("<Double-1>", self._on_log_row_dblclick)

        # Right: live activity
        right = tk.Frame(body, bg=BG, width=S(370))
        right.pack(side="right", fill="both")
        right.pack_propagate(False)
        self._section_label(right, "LIVE ACTIVITY", ACCENT).pack(anchor="w", pady=(0, 6))
        self._activity_graph = ActivityGraph(right, self._detector, self._config)
        self._activity_graph.pack(fill="both", expand=True)

        # ── Footer ─────────────────────────────────────────────────────────
        footer = tk.Frame(self, bg=PANEL, padx=14, pady=5)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, text="F1 Tour   ·   F2 Settings   ·   Space Toggle",
                 font=("Consolas", 10), bg=PANEL, fg=DIM).pack(side="left")
        tk.Label(footer, text="v2.0-PoC", font=F_MONO_S,
                 bg=PANEL, fg=DIM).pack(side="right")

        # ── Keyboard shortcuts ─────────────────────────────────────────────
        self.bind("<F1>", lambda e: self._show_tour())
        self.bind("<F2>", lambda e: self._open_settings())
        self.bind("<space>", self._on_space_key)

        # Widget map exposed to the tour
        self._widget_map = {
            "toggle":   self._toggle_btn,
            "settings": self._settings_btn,
            "logs":     self._log_frame,
            "graph":    self._activity_graph,
        }

    def _section_label(self, parent, text, color):
        """A section header: a small accent bar + bold caption."""
        f = tk.Frame(parent, bg=BG)
        tk.Frame(f, bg=color, width=S(4), height=S(16)).pack(side="left", padx=(0, 8))
        tk.Label(f, text=text, font=("Consolas", 12, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        return f

    def _set_hero(self, state, watch_dir, thresh_txt):
        """Drive the protection-status band. state in {threat, paused, protected, simulated}."""
        spec = {
            "threat":    ("⚠", "THREAT DETECTED",   HERO_RED,    RED,
                          "Ransomware activity contained — review the latest alert below"),
            "paused":    ("⏸", "MONITORING PAUSED", HERO_AMBER,  YELLOW,
                          "Detection is off. Press the toggle or Space to resume"),
            "protected": ("🛡", "PROTECTED",         HERO_GREEN,  GREEN,
                          f"Monitoring {watch_dir}   ·   {thresh_txt}"),
            "simulated": ("🛡", "MONITORING (SIMULATED)", HERO_ORANGE, ORANGE,
                          "Run as Administrator for live containment + ETW attribution"),
        }[state]
        icon, title, bg, fg, sub = spec
        for w in (self._hero, self._hero_in, self._hero_txt,
                  self._hero_icon, self._hero_title, self._hero_sub):
            w.configure(bg=bg)
        self._hero_accent.configure(bg=fg)
        self._hero_icon.configure(text=icon, fg=fg)
        self._hero_title.configure(text=title, fg=fg)
        self._hero_sub.configure(text=sub)

    # ── Widget factories ──────────────────────────────────────────────────

    def _hdr_btn(self, parent, text, fg, cmd):
        if _TTKB_OK:
            return ttkb.Button(parent, text=text, command=cmd,
                               bootstyle="secondary", takefocus=False)
        b = tk.Button(parent, text=text, font=F_MONO_S,
                      bg=PANEL, fg=fg, relief="flat",
                      cursor="hand2", padx=10, pady=4,
                      activebackground=GLOW,
                      activeforeground=ACCENT,
                      command=cmd)
        b.bind("<Enter>", lambda e: b.config(bg=GLOW, fg=ACCENT))
        b.bind("<Leave>", lambda e: b.config(bg=PANEL, fg=fg))
        return b

    def _make_hdr_btn(self, parent, text, fg, cmd):
        return self._hdr_btn(parent, text, fg, cmd)

    def _apply_btn_glow(self, btn, color):
        btn.bind("<Enter>", lambda e: btn.config(
            bg=self._lighten(btn.cget("bg"), 0.15)))
        btn.bind("<Leave>", lambda e: None)

    def _lighten(self, hex_color, amt):
        try:
            r = int(hex_color[1:3], 16)
            g = int(hex_color[3:5], 16)
            b = int(hex_color[5:7], 16)
            r = min(255, int(r + (255 - r) * amt))
            g = min(255, int(g + (255 - g) * amt))
            b = min(255, int(b + (255 - b) * amt))
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception:
            return hex_color

    def _stat_card(self, parent, icon, label, value, color):
        """A rounded stat tile: colored accent underline, big number, icon +
        caption. Cards share the row width equally so the row reads as one strip."""
        card = RoundedFrame(parent, radius=18, fill=CARD, border=BORDER, height=S(108))
        col = len(parent.winfo_children()) - 1
        parent.columnconfigure(col, weight=1, uniform="statcards")
        card.grid(row=0, column=col, sticky="nsew", padx=6)
        b = card.body

        tk.Frame(b, bg=color, height=3).pack(fill="x", side="top", pady=(0, 6))

        var = tk.StringVar(value=value)
        tk.Label(b, textvariable=var, font=F_STAT,
                 bg=CARD, fg=color).pack(anchor="w", padx=6)
        cap = tk.Frame(b, bg=CARD)
        cap.pack(anchor="w", fill="x", padx=6)
        tk.Label(cap, text=icon, font=("Segoe UI Emoji", 13),
                 bg=CARD, fg=DIM).pack(side="left", padx=(0, 5))
        tk.Label(cap, text=label, font=("Consolas", 12, "bold"),
                 bg=CARD, fg=DIM).pack(side="left")
        return var

    def _make_treeview(self, parent, columns, widths, stretch_col=None):
        style = ttk.Style()
        style.theme_use("clam")

        uid = "Sec2.Treeview"

        def _apply_style(*_):
            """(Re)assert the log styling.

            ttkbootstrap republishes its own Treeview settings whenever the theme
            is (re)applied, which silently resets rowheight and font back to the
            theme defaults. Re-applying on <<ThemeChanged>> — and once more after
            the widget is realised — makes our sizing stick."""
            # rowheight is read from the BASE "Treeview" style — ttk ignores it
            # on a derived style name, which is why the rows stayed short while
            # every other setting here took effect.
            style.configure("Treeview", rowheight=S(24), font=F_LOG)
            style.configure(uid,
                            background=CARD,
                            foreground=TEXT,
                            fieldbackground=CARD,
                            rowheight=S(24),
                            font=F_LOG,
                            borderwidth=0,
                            relief="flat")
            style.configure(uid + ".Heading",
                            background=BG,
                            foreground=ACCENT,
                            font=F_LOG_B,
                            relief="flat",
                            borderwidth=0)
            style.map(uid,
                      background=[("selected", GLOW)],
                      foreground=[("selected", ACCENT)])

        _apply_style()

        tree = ttk.Treeview(parent, columns=columns,
                            show="headings", style=uid)
        tree.bind("<<ThemeChanged>>", _apply_style, add="+")
        tree.after(0, _apply_style)

        for col, w in zip(columns, widths):
            tree.heading(col, text=col)
            stretch = (col == stretch_col)
            tree.column(col, width=w, anchor="w", stretch=stretch,
                        minwidth=S(40))

        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)

        tree.tag_configure("odd",        background="#0f1620")
        tree.tag_configure("even",       background=CARD)
        # A tag font overrides the style font, so this must track F_LOG — it is
        # what actually renders every alert row.
        tree.tag_configure("ransomware", foreground=RED, font=F_LOG_B)
        tree.tag_configure("new",        background=GLOW)

        return tree

    # ── Refresh ───────────────────────────────────────────────────────────

    def _schedule_refresh(self):
        self._refresh()
        self.after(DASHBOARD_REFRESH, self._schedule_refresh)

    def _refresh(self):
        ft, ec, ws = self._config.get()
        self._thresh_lbl.configure(
            text=f"  k={ft}  n={ec}  t={ws}s  ")

        # Columns: 0 id, 1 timestamp, 2 alert_type, 3 attacker, 4 detail, 5 status,
        #          6 files_json, 7 locked_dir, 8 lock_active, 9 attribution
        all_rows = self._db.get_alerts(200)
        lock_count = sum(1 for r in all_rows if r[8])

        query = self._search_var.get().strip().lower()
        if query:
            display_rows = [r for r in all_rows
                            if query in f"{r[1]} {r[3]} {r[4]} {r[5]}".lower()]
        else:
            display_rows = list(all_rows)

        if self._sort_col:
            col_idx = {"Timestamp": 1, "Type": 2, "Attacker": 3, "Detail": 4, "Status": 5}[self._sort_col]
            display_rows.sort(key=lambda r: (r[col_idx] or ""), reverse=self._sort_reverse)

        # Rows come back ordered by id DESC, so the first row holds the highest id.
        newest_id = all_rows[0][0] if all_rows else 0
        has_new_alert = newest_id > self._prev_max_id

        selected = self._log_tree.selection()
        self._log_tree.delete(*self._log_tree.get_children())

        if not display_rows:
            placeholder = ("---No threats detected — monitoring is active---"
                           if not all_rows else "---No alerts match your search---")
            self._log_tree.insert("", "end", iid="placeholder",
                values=("", "", "", placeholder, ""))
        else:
            for i, row in enumerate(display_rows):
                aid, ts, atype, attacker, detail, status = row[0], row[1], row[2], row[3], row[4], row[5]
                tags = ["even" if i % 2 == 0 else "odd", "ransomware"]
                if aid == newest_id and has_new_alert:
                    tags.append("new")
                iid = str(aid)
                self._log_tree.insert("", "end", iid=iid,
                    values=(ts, atype, attacker, (detail or "")[:90], status),
                    tags=tuple(tags))
                if iid in selected:
                    self._log_tree.selection_add(iid)

        # Flash + sound + banner on new alert (skipped on the very first load)
        if has_new_alert and self._prev_max_id > 0:
            self._flash_border(self._log_frame)
            newest = all_rows[0]
            self._notify_new_alert(attacker=newest[3], ts=newest[1])
            self._last_alert_ts = time.monotonic()
        self._prev_max_id = newest_id

        self._stat_total.set(str(len(all_rows)))
        self._stat_locked.set(str(lock_count))
        self._stat_suspended.set(str(len(self._suspended_pids)))

        self._log_count_lbl.configure(text=f"{len(display_rows)}/{len(all_rows)} events")

        # ── CPU usage of the C++ monitor agent ────────────────────────────
        cpu_text = "N/A"
        if _PSUTIL_OK and self._agent is not None:
            agent_pid = self._agent.pid
            if agent_pid:
                try:
                    if (self._cpp_proc is None or
                            self._cpp_proc.pid != agent_pid):
                        self._cpp_proc = _psutil.Process(agent_pid)
                        self._cpp_proc.cpu_percent(interval=None)  # seed
                    pct = self._cpp_proc.cpu_percent(interval=None)
                    cpu_text = f"{pct:.1f}%"
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    self._cpp_proc = None
                    cpu_text = "–"
            else:
                cpu_text = "–"
        self._stat_cpu.set(cpu_text)

        # ── Hero protection-status band ───────────────────────────────────
        thresh_txt = f"k={ft} / n={ec} / t={ws}s / entropy {self._config.get_entropy_thresh()}"
        recent_threat = (time.monotonic() - self._last_alert_ts) < 8.0
        if not self._state.active:
            state = "paused"
        elif recent_threat:
            state = "threat"
        elif self._live_mode:
            state = "protected"
        else:
            state = "simulated"
        self._set_hero(state, get_watch_dir(), thresh_txt)

    def _flash_border(self, widget, count=6):
        """Briefly flash the border of a frame red to signal new alert."""
        if count <= 0:
            widget.configure(highlightbackground=BORDER)
            return
        color = RED if count % 2 == 0 else BORDER
        widget.configure(highlightbackground=color)
        self.after(180, lambda: self._flash_border(widget, count - 1))

    # ── Controls ──────────────────────────────────────────────────────────

    def _on_monitor_toggle(self):
        """Fired by the toggle switch (its variable already reflects the new state)."""
        want = bool(self._monitor_var.get())
        self._state.set(want)
        self._sync_monitor_ui(want)

    def _toggle_monitoring(self):
        """Keyboard / programmatic toggle (Space key): flip the switch, then apply."""
        self._monitor_var.set(not self._monitor_var.get())
        self._on_monitor_toggle()

    def _sync_monitor_ui(self, active):
        if _TTKB_OK:
            # Keep the bootstyle constant — reconfiguring a ttkbootstrap toggle's
            # bootstyle at runtime desyncs the switch's checked visual from its
            # variable, which left it stuck after a pause. The round-toggle
            # already shows on (green, knob right) vs off (grey, knob left) from
            # the variable itself; only the label needs updating.
            self._toggle_btn.configure(text=("  Monitoring" if active else "  Paused"))
        elif active:
            self._toggle_btn.configure(text="🛡  MONITORING: ON", bg="#0d2e1a",
                                       fg=GREEN, activebackground="#1a4a2a")
        else:
            self._toggle_btn.configure(text="⏸  MONITORING: OFF", bg="#2e0d1a",
                                       fg=RED, activebackground="#4a1a2a")

    def _open_settings(self):
        SettingsWindow(self, self._config, self._detector, agent=self._agent,
                       canary=self._canary)

    def _on_window_close(self):
        from tkinter import messagebox

        # 1. If the user already paused the monitoring, close normally
        if not self._state.active:
            self._activity_graph.stop()
            self.destroy()
            return

        # 2. If monitoring is still active, warn them and offer to hide
        response = messagebox.askyesnocancel("Keep Monitoring?",
                                             "Monitoring is currently ACTIVE.\n\n"
                                             "Do you want to hide the dashboard and keep monitoring in the background?\n\n"
                                             "• Yes: Hide dashboard (Use Task Manager to stop later)\n"
                                             "• No: Exit application entirely\n"
                                             "• Cancel: Return to dashboard")

        if response is True:
            # Hides the window completely (runs invisibly)
            self.withdraw()

            # NOTE: If you would rather it just minimize to the taskbar instead
            # of becoming completely invisible, change the line above to:
            # self.iconify()

        elif response is False:
            # Closes the app and stops all Python background threads
            self._activity_graph.stop()
            self.destroy()

    def _show_tour(self):
        WelcomePage(self, self._widget_map)

    def _on_space_key(self, event):
        # Don't hijack space presses meant for the search box.
        if isinstance(self.focus_get(), (tk.Entry, ttk.Entry)):   # ttkb.Entry is a ttk.Entry
            return
        self._toggle_monitoring()

    def _sort_by(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self._refresh()

    def _on_log_row_dblclick(self, event):
        sel = self._log_tree.selection()
        if not sel or not sel[0].isdigit():
            return
        agent_pid = self._agent.pid if self._agent else None
        AlertDetailWindow(self, self._db, int(sel[0]), on_change=self._refresh,
                          agent_pid=agent_pid, suspended=self._suspended_pids)

    def _open_selected_or_first_alert(self):
        """Clicking the hint banner opens the selected alert, or the newest one."""
        sel = self._log_tree.selection()
        iid = sel[0] if sel and sel[0].isdigit() else None
        if iid is None:
            for child in self._log_tree.get_children():
                if child.isdigit():
                    iid = child
                    self._log_tree.selection_set(child)
                    break
        if iid is None:
            return
        agent_pid = self._agent.pid if self._agent else None
        AlertDetailWindow(self, self._db, int(iid), on_change=self._refresh,
                          agent_pid=agent_pid, suspended=self._suspended_pids)

    def _notify_new_alert(self, attacker, ts):
        if _WINSOUND_OK:
            try:
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except Exception:
                pass
        self._banner_lbl.configure(text=f"🚨  NEW RANSOMWARE ALERT — {attacker} — {ts}")
        self._banner.pack(fill="x", side="top", before=self._hdr)
        if self._banner_after:
            try: self.after_cancel(self._banner_after)
            except Exception: pass
        self._banner_after = self.after(4000, self._hide_banner)

        # Desktop toast (bottom-right) so the user is warned even when the
        # dashboard is minimised or unfocused — no need to be inside the app.
        try:
            ToastNotification(self, f"{attacker}\n{ts}",
                              on_click=self._raise_dashboard)
        except Exception:
            pass

    def _raise_dashboard(self):
        """Bring the dashboard to the front (from a toast click)."""
        try:
            self.deiconify()
            self.lift()
            self.attributes("-topmost", True)
            self.after(300, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except Exception:
            pass

    def _hide_banner(self):
        self._banner.pack_forget()
        self._banner_after = None


# =============================================================================
# Splash / Boot screen  (shown while backend services start)
# =============================================================================
class SplashScreen(tk.Tk):
    """Animated boot screen shown for ~2 s while services initialise."""

    def __init__(self):
        super().__init__()
        self.overrideredirect(True)
        self.configure(bg=BG)
        w, h = S(480), S(300)
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self._build()
        self._frame = 0
        self._animate()

    def _build(self):
        # Large hex icon
        tk.Label(self, text="⬡", font=("Consolas", 64, "bold"),
                 bg=BG, fg=ACCENT).pack(pady=(32, 0))
        tk.Label(self, text="HYBRID SECURITY SUITE",
                 font=("Consolas", 14, "bold"), bg=BG, fg=TEXT).pack()
        tk.Label(self, text="Initialising threat monitoring…",
                 font=F_MONO_S, bg=BG, fg=DIM).pack(pady=(8, 0))

        # Animated progress bar
        self._bar_canvas = tk.Canvas(self, bg=BG, height=S(6),
                                     highlightthickness=0, width=S(320))
        self._bar_canvas.pack(pady=(24, 0))
        self._bar_canvas.create_rectangle(0, 0, 320, 6, fill=BORDER, outline="", tags="bg")
        self._bar_canvas.create_rectangle(0, 0, 0, 6, fill=ACCENT, outline="", tags="bar")

        tk.Label(self, text="v2.0-PoC", font=F_MONO_S,
                 bg=BG, fg=DIM).pack(side="bottom", pady=12)

    def _animate(self):
        self._frame += 1
        progress = min(self._frame / 50 * 320, 320)
        self._bar_canvas.coords("bar", 0, 0, progress, 6)
        if self._frame < 50:
            self.after(30, self._animate)
        else:
            self.after(200, self.destroy)


# =============================================================================
# Entry Point
# =============================================================================
def _parse_args():
    p = argparse.ArgumentParser(description="Hybrid Security Suite v2")
    p.add_argument("--no-agent",          action="store_true")
    p.add_argument("--skip-welcome",      action="store_true")
    p.add_argument("--no-splash",         action="store_true")
    return p.parse_args()


import subprocess
from pathlib import Path


def directory_lockdown(pid, files):
    """Contain a ransomware alert by revoking write/delete access to the affected
    directory. Returns the locked directory path on success, or None if lockdown
    wasn't attempted (no files) or failed (e.g. not running as Administrator)."""
    if not files:
        return None

    _log(f"\n[!!!] RANSOMWARE THRESHOLD CROSSED (PID={pid})")

    # Get the directory where the attack is happening based on the first modified file
    target_dir = Path(files[0]).parent

    _log(f"[*] INITIATING CONTAINMENT: Locking down directory -> {target_dir}")

    # Use Windows icacls to DENY Write (W) and Delete (D) permissions to Everyone
    # (OI)(CI) ensures the rule applies to all subfolders and files inside it
    lockdown_cmd = [
        "icacls", str(target_dir),
        "/deny", "Everyone:(OI)(CI)(W,D)"
    ]

    try:
        # Run the command hidden from the user
        subprocess.run(lockdown_cmd, check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        _log(f"[+] CONTAINMENT SUCCESSFUL! Write access revoked for {target_dir}")
        _log(f"[+] The ransomware has been blocked from modifying further files.")
        return str(target_dir)
    except subprocess.CalledProcessError as e:
        _log(f"[-] CONTAINMENT FAILED: {e.stderr.decode(errors='replace')}")
        return None


def directory_unlock(target_dir):
    """Reverse directory_lockdown() by removing the DENY ACE it added for Everyone.
    Returns (success, error_message)."""
    try:
        r = subprocess.run(
            ["icacls", str(target_dir), "/remove:d", "Everyone"],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            return True, ""
        return False, r.stderr.decode(errors="replace") or "icacls returned a non-zero exit code."
    except FileNotFoundError as e:
        return False, str(e)


# ─── Process containment (suspend / resume) ──────────────────────────────────
#
#  A SECOND, process-targeted containment layer, additional to the icacls
#  directory lockdown. It is deliberately constrained:
#
#   * ETW-ONLY. We suspend a process only when its PID came from ETW (kernel-
#     reported, accurate). A heuristic PID can be the wrong process — even the
#     agent itself — so suspending it is never allowed. This is the safety
#     guarantee that lets us finally act on a PID at all.
#   * REVERSIBLE. Suspension uses SuspendThread on every thread; resume_process()
#     undoes it with ResumeThread, matching the project principle that every
#     containment action is undoable from the GUI.
#   * USER-CONFIRMED. It is never automatic — the dashboard requires an explicit
#     confirmation dialog before suspending.
#   * GUARDED. Refuses the agent, this process, PIDs <= 4, and a denylist of
#     critical Windows processes whose suspension could destabilise the OS.

_CRITICAL_PROCS = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe", "dwm.exe",
}
_TH32CS_SNAPTHREAD      = 0x00000004
_THREAD_SUSPEND_RESUME  = 0x0002
_INVALID_HANDLE         = 0xFFFFFFFFFFFFFFFF
_DWORD_MINUS_1          = 0xFFFFFFFF

class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
        ("th32ThreadID", ctypes.c_ulong), ("th32OwnerProcessID", ctypes.c_ulong),
        ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
    ]

# HANDLEs are 64-bit pointers on x64; the default c_int restype truncates them
# into invalid handles, so the prototypes must be declared explicitly.
def _init_kernel32():
    k = ctypes.windll.kernel32
    k.CreateToolhelp32Snapshot.restype  = ctypes.c_void_p
    k.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    k.OpenThread.restype   = ctypes.c_void_p
    k.OpenThread.argtypes  = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    k.SuspendThread.restype = ctypes.c_ulong
    k.SuspendThread.argtypes = [ctypes.c_void_p]
    k.ResumeThread.restype  = ctypes.c_ulong
    k.ResumeThread.argtypes = [ctypes.c_void_p]
    k.Thread32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k.Thread32Next.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
    k.CloseHandle.argtypes   = [ctypes.c_void_p]
    return k

_KERNEL32 = _init_kernel32()


def _process_name(pid):
    if _PSUTIL_OK:
        try:
            return _psutil.Process(pid).name().lower()
        except Exception:
            return None
    return None


def containment_precheck(pid, attribution, agent_pid=None):
    """Return (ok, reason). Gate every suspend behind this."""
    if attribution != "ETW":
        return False, ("Process containment needs an accurate (ETW) PID. This alert was "
                       "attributed heuristically, so suspending its PID could hit the wrong "
                       "process. Run as Administrator to enable ETW attribution.")
    if pid is None or pid <= 4:
        return False, "No valid process id recorded for this alert."
    if pid == os.getpid():
        return False, "Refusing to suspend the security suite itself."
    if agent_pid and pid == agent_pid:
        return False, "Refusing to suspend the monitor agent."
    name = _process_name(pid)
    if name is None:
        return False, f"Process {pid} is no longer running."
    if name in _CRITICAL_PROCS:
        return False, f"Refusing to suspend a critical system process ({name})."
    return True, ""


def _iter_thread_ids(pid):
    snap = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if not snap or snap == _INVALID_HANDLE:
        return
    try:
        te = _THREADENTRY32()
        te.dwSize = ctypes.sizeof(_THREADENTRY32)
        ok = _KERNEL32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                yield te.th32ThreadID
            ok = _KERNEL32.Thread32Next(snap, ctypes.byref(te))
    finally:
        _KERNEL32.CloseHandle(snap)


def _apply_to_threads(pid, func):
    """Run kernel32 `func` (SuspendThread/ResumeThread) on every thread of pid.
    Returns the number of threads affected."""
    count = 0
    for tid in _iter_thread_ids(pid):
        h = _KERNEL32.OpenThread(_THREAD_SUSPEND_RESUME, False, tid)
        if h:
            if func(h) != _DWORD_MINUS_1:   # (DWORD)-1 == failure
                count += 1
            _KERNEL32.CloseHandle(h)
    return count


def suspend_process(pid):
    """Suspend every thread of `pid`. Returns (success, error_message).
    NOTE: a thread created after enumeration is not caught — acceptable for a
    PoC; NtSuspendProcess would avoid it but is undocumented."""
    try:
        n = _apply_to_threads(pid, _KERNEL32.SuspendThread)
        if n > 0:
            return True, ""
        return False, "No threads could be suspended (process gone or access denied)."
    except OSError as e:
        return False, str(e)


def resume_process(pid):
    """Reverse suspend_process(): resume every thread of `pid`."""
    try:
        n = _apply_to_threads(pid, _KERNEL32.ResumeThread)
        if n > 0:
            return True, ""
        return False, "No threads could be resumed (process gone or access denied)."
    except OSError as e:
        return False, str(e)


def main():
    args = _parse_args()

    # ── Check for Administrator privileges ────────────────────────────────
    live_mode = _is_admin()
    if live_mode:
        _log("[Security] Running as Administrator – LIVE BLOCKING mode active.")
    else:
        _log("[Security] WARNING: Not running as Administrator.")
        _log("[Security] Directory lockdown (icacls) will be SIMULATED only.")
        _log("[Security] Re-launch as Administrator to enable live containment.")

    # ── Show splash while services boot ───────────────────────────────────
    if not args.no_splash:
        splash = SplashScreen()
        splash.mainloop()

    # ── Initialise shared state ───────────────────────────────────────────
    db       = Database(DB_PATH)
    _cfg = get_saved_detection()
    config   = DetectionConfig(file_thresh=_cfg["file_thresh"], event_cap=_cfg["event_cap"],
                               window_secs=_cfg["window_secs"], entropy_thresh=_cfg["entropy_thresh"])
    state    = MonitoringState(active=True)

    # ── Deploy canary (decoy) files into the watched folder ───────────────
    watch_dir = get_watch_dir()
    _log(f"[Security] Watching: {watch_dir}")
    canary = CanaryManager()
    n_can = canary.deploy(watch_dir)
    _log(f"[Security] Deployed {n_can} canary decoy file(s).")

    detector = RansomwareDetector(db, config, state, directory_lockdown, canary=canary)

    # ── Start background services ─────────────────────────────────────────
    agent = AgentManager(AGENT_EXE, watch_dir)
    if not args.no_agent:
        agent.start()
        time.sleep(0.8)

    pipe_reader = PipeReader(PIPE_NAME, detector)
    pipe_reader.start()

    # ── Build dashboard ───────────────────────────────────────────────────
    dash = Dashboard(db, config, state, detector,
                     live_mode=live_mode, agent=agent, canary=canary)

    # ── Show welcome tour only on first launch ────────────────────────────
    if not args.skip_welcome and not _has_seen_welcome():
        _mark_welcome_seen()           # persist before showing (crash-safe)
        dash.update_idletasks()
        dash.after(400, lambda: WelcomePage(dash, dash._widget_map))

    try:
        dash.mainloop()
    finally:
        pipe_reader.stop()
        agent.stop()
        _log("Shutdown complete.")


if __name__ == "__main__":
    main()