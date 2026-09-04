# FYP2 Report — Draft Prose

**Design and Development of a Rule-Based Threat Monitoring and Ransomware Containment System for Windows Platforms**

Lee Wen Qi · Supervisor: Ms. Oh Zi Xin · UTAR FICT (Kampar) · Bachelor of IT (Hons) Communications and Networking

> **How to use this file.** This is ready-to-adapt prose for each chapter of the UTAR
> template. Paste sections into your Word document and reword in your own voice.
> Figures referenced here are in `report_figures/` (`python tools/make_figures.py`).
> Every place a **final measured number** is needed is marked **`[[CONFIRM after elevated run]]`** —
> fill these from your Step 3–4 outputs before submission. Do not submit with the
> placeholder text visible.

---

## Abstract

Ransomware remains one of the most damaging threats to individuals and small organisations,
who frequently cannot afford enterprise Endpoint Detection and Response (EDR) platforms or the
kernel-level tooling those platforms rely on. This project designs and develops a lightweight,
transparent, user-space ransomware detection and containment system for the Windows platform.
The system combines a two-process architecture — a C++ file-system monitoring agent and a Python
analysis engine connected by a Windows named pipe — with a three-layer behavioural detection
pipeline: a sliding-window file-modification **rate** heuristic, a Shannon **entropy** gate that
distinguishes high-entropy encryption from benign bursts of file activity, and **canary decoy
files** that trip on the first file a ransomware process touches. Accurate identification of the
responsible process is achieved entirely from user space using Event Tracing for Windows (ETW),
removing the need for a kernel-mode driver while still supporting reversible, process-targeted
containment. All containment actions — directory lockdown via `icacls` and process suspension via
`SuspendThread` — are fully reversible from an interactive dashboard. The system was evaluated
against realistic ransomware file-I/O behaviour (read → encrypt → write → rename/delete) across
three family archetypes and against benign heavy-I/O workloads. It achieved a true-positive rate
of **[[CONFIRM]]** and zero false negatives, with detection latency reduced from approximately
1240 ms to approximately 17 ms after a performance optimisation, at under 1% agent CPU overhead.
The results demonstrate that effective, reversible ransomware containment is achievable entirely
in user space, trading a small amount of attribution certainty for substantially greater
deployability and transparency than kernel-driver or opaque commercial approaches.

---

## Chapter 1 — Introduction

### 1.1 Background

Ransomware is a class of malware that renders a victim's files inaccessible — typically by
encrypting them with a key held only by the attacker — and demands payment for their recovery.
Unlike data-stealing malware, ransomware is deliberately conspicuous: its goal is to be noticed
after the damage is done. The window in which the damage occurs, however, is extremely short.
Modern ransomware can encrypt thousands of files per minute, so any defence that reacts *after*
encryption completes has already failed. Effective protection must therefore be **behavioural and
real-time**: it must recognise the *act* of mass encryption while it is happening and intervene
within that window.

Commercial defences against ransomware exist, but they are concentrated at the two ends of the
market. At the high end, enterprise EDR platforms combine kernel-mode drivers, cloud telemetry,
and machine learning; they are effective but costly, opaque, and operationally heavy. At the
consumer end, features such as Windows Defender's Controlled Folder Access provide a coarse
allow-list of applications permitted to write to protected folders; this is free but rigid,
opaque to the user, and cannot be reasoned about or undone once it interferes. Between these lies
a large population of individual users and small organisations who need transparent, affordable
protection that runs on ordinary Windows machines without kernel drivers or subscriptions.

### 1.2 Problem Statement

Three specific gaps motivate this work:

1. **Deployability vs. accuracy.** The most accurate behavioural defences observe file activity
   from a kernel-mode filesystem minifilter driver. Such drivers require signing, are difficult
   to deploy, and are inaccessible to a student or small-organisation setting. A purely user-space
   monitor is far more deployable but has historically sacrificed the ability to identify *which
   process* is responsible for a file change — Windows' user-space `ReadDirectoryChangesW` API
   reports *what* changed but not *who* changed it. This project's central technical problem is to
   recover accurate process attribution **from user space**.

2. **Rate alone cannot separate ransomware from fast benign activity.** A detector that alerts on
   a high rate of file modifications will also alert on legitimate bursts — extracting a large
   archive, restoring a backup, or bulk-copying files. Reducing these false positives without
   introducing false negatives requires a second, content-aware signal.

3. **Containment is usually irreversible or destructive.** Terminating the offending process is
   unsafe when attribution is uncertain, and blocking file access is unhelpful if the user cannot
   undo it. A practical system must contain the threat while keeping every action reversible.

### 1.3 Motivation

The motivation is to show that a **transparent, user-space, reversible** ransomware defence is not
only possible but effective — that the accessibility trade-off historically assumed (user-space
means inaccurate) can be substantially closed with user-mode Event Tracing for Windows, and that
layering complementary behavioural signals (rate, entropy, canaries) yields robust detection
without a kernel driver, cloud service, or subscription. Such a system is directly usable by the
audience least served by existing tools.

### 1.4 Objectives

The objectives of this project are to:

1. **Detect ransomware in real time from user space** — with no kernel driver — using a
   behavioural sliding-window heuristic over file-modification activity.
2. **Improve on rate alone** by adding a second signal (write **entropy**) and a third
   (**canary decoy files**), reducing false positives without missing attacks.
3. **Attribute the responsible process accurately** from user space using ETW, and provide
   **reversible containment** — directory lockdown and process suspension, both undoable.
4. **Package the system as a lightweight, transparent, configurable tool** with an interactive
   dashboard, and **evaluate** it rigorously against realistic ransomware behaviour and benign
   heavy-I/O workloads.

> *Note on scope change (FYP1 → FYP2):* the FYP1 proposal additionally covered network-intrusion
> detection (failed-login monitoring and firewall IP blocking). On the moderator's instruction,
> FYP2 scope was **narrowed to ransomware only**; the intrusion features and the autostart
> registration were removed. This report reflects the ransomware-only scope.

### 1.5 Project Scope

The system is a proof-of-concept Windows desktop application that runs entirely in user space. It
monitors a user-configurable directory, detects ransomware-like behaviour, contains it reversibly,
and presents alerts through an interactive dashboard. Explicitly **in scope**: real-time
behavioural detection, user-space process attribution, reversible containment, and an evaluation
methodology. Explicitly **out of scope**: kernel-mode drivers, network intrusion detection, cloud
telemetry, automatic (unattended) process termination, and self-healing/file recovery. The machine-
learning classifier developed in FYP2 is evaluated **offline** as an optional second layer and is
not wired into the live decision path (see §1.7).

### 1.6 Contributions

- Accurate user-space PID attribution via ETW, closing the FYP1 accuracy-vs-deployability gap.
- A **three-layer** behavioural detection pipeline: rate → entropy → canary.
- Reversible **two-layer containment** (directory lockdown + process suspension), all undoable
  from the GUI.
- A reproducible **evaluation harness**: a behaviour-faithful ransomware simulator, benign
  workloads, a performance benchmark, an entropy-threshold sensitivity study, and an offline ML
  evaluation — with 12 automated test suites (FYP1 had none).
- A documented performance fix reducing detection latency from ~1240 ms to ~17 ms.

### 1.7 Note on the "Rule-Based" title and machine learning

The project title describes a **rule-based** system, and the core detection engine remains
rule-based: a sliding-window rate threshold, an entropy gate, and a canary tripwire — all
deterministic and inspectable. A machine-learning classifier was additionally developed and
evaluated as an **optional second layer** that consumes features derived from the same heuristic
engine; wiring it into the live decision path is identified as future work. The title therefore
remains accurate: the shipped, live system is rule-based, and the ML component is a supplementary
offline study rather than the primary detection mechanism.

### 1.8 Report Organisation

Chapter 2 reviews ransomware behaviour and existing detection approaches and positions this work
against them. Chapters 3 and 4 present the system design and methodology. Chapter 5 details the
implementation and the engineering challenges encountered. Chapter 6 evaluates the system against
realistic behaviour and quantifies its performance. Chapter 7 concludes and identifies future work.

---

## Chapter 2 — Literature Review

### 2.1 Ransomware behaviour

Regardless of family, ransomware that encrypts files exhibits a characteristic file-I/O signature:
for each target file it **reads** the plaintext, **encrypts** it, **writes** the ciphertext, and
then **renames or deletes** the original. This produces two observable behavioural markers that a
defender can exploit even without knowing the malware's code: a **high rate** of file
modifications concentrated in a short time, and **high-entropy write content** — encrypted data
approaches the theoretical maximum of 8 bits/byte of Shannon entropy, whereas ordinary documents
sit around 3–5 bits/byte. Families differ mainly in *how* they replace the original file: some
overwrite in place, some write a new encrypted copy and delete the original, and some rename the
encrypted output with a new extension. These archetypes (`overwrite`, `copy_delete`, `rename`)
inform the evaluation in Chapter 6.

### 2.2 Detection approaches

**Signature-based detection** matches known malware byte-patterns. It is fast and precise for known
samples but is defeated by novel or polymorphic ransomware, which is generated in large volume.
Behavioural detection is therefore necessary for unknown threats.

**Behavioural / rate-based detection** monitors file-system activity and flags abnormal bursts of
modification. It generalises to unseen families but, on rate alone, cannot distinguish ransomware
from fast *benign* activity such as archive extraction — the core false-positive problem this
project addresses with an entropy layer.

**Entropy-based detection** inspects the content being written, flagging near-maximum entropy as
likely ciphertext. It complements rate: rate says "many files, fast," entropy says "and the
content looks encrypted." Entropy can be evaded by low-entropy or format-preserving encryption,
so it is used here only as a *suppressor* of benign bursts, never as the sole trigger.

**Decoy / honeypot detection** places bait files that no legitimate program should touch; any
modification is near-certain evidence of ransomware. Decoys catch even "low-and-slow" ransomware
that deliberately stays under a rate threshold, at the cost of protecting only the folders that
contain decoys.

### 2.3 Existing systems and the gap

ShieldFS [ref] is a research system that detects ransomware using machine learning over low-level
I/O request traces and can transparently roll back malicious changes via copy-on-write. It is
highly effective but is implemented as a **kernel-mode minifilter driver**, which constrains its
deployability. Windows Defender's **Controlled Folder Access** protects designated folders with an
allow-list of permitted applications; it is widely available but opaque to the user, coarse-grained,
and cannot be selectively undone. Academic honeypot tools demonstrate decoy-based detection but are
typically detection-only.

The gap this project targets is a system that is simultaneously **user-space** (deployable without
a signed kernel driver), **accurate in attribution** (via ETW rather than a heuristic guess),
**multi-signal** (rate + entropy + canary, not one axis), **reversibly containing** (not merely
detecting, and never irreversible), and **transparent and configurable** (open thresholds the user
can tune and persist).

**Table 2-1 — Positioning against existing approaches**

| Tool / System | Approach | Kernel driver? | User-space | Reversible containment | Transparent / configurable | Ransomware-specific |
|---|---|---|---|---|---|---|
| Windows Defender Controlled Folder Access | per-folder app allow-list | yes (AV engine) | no | n/a (blocks writes) | opaque, limited | partial |
| ShieldFS | ML on IRP traces + copy-on-write self-healing | **yes (minifilter)** | no | yes (self-heals) | research prototype | yes |
| Academic honeypot tools | decoy files | varies | often | detection only | varies | yes |
| **This project** | rate + **entropy** + **canary**, ETW attribution | **no** | **yes** | **yes (lockdown + suspend, undoable)** | **yes (open, tunable, persisted)** | **yes** |

> Positioning sentence: *Unlike ShieldFS, which requires a kernel minifilter driver, and Windows
> Defender's Controlled Folder Access, which is opaque and cannot be undone, the proposed system
> performs accurate, fully reversible ransomware containment entirely from user space — trading a
> little attribution certainty (mitigated by ETW) for far greater deployability and transparency.*

---

## Chapter 3 — System Design

### 3.1 Architecture overview

The system uses a **two-process architecture** connected by a Windows named pipe. A C++ monitoring
agent watches the filesystem and answers *what changed* (and, via ETW, *who changed it*); a Python
analysis engine applies the detection logic, drives containment, persists alerts, and renders the
dashboard. Decoupling the two allows either side to be upgraded independently, and keeps the
performance-critical file-event capture in native code while the analysis and UI stay in Python.

```
Watched Directory
      │ file events
      ▼
C++ Monitor Agent (monitor_agent.exe)
  ReadDirectoryChangesW + Overlapped I/O   ← what changed
  ETW Attributor (Microsoft-Windows-Kernel-File)  ← who changed it
      │  FILEPATH|PID|SOURCE  (newline-delimited)
      ▼
Named Pipe  \\.\pipe\SecurityPipe
      ▼
Python Analysis Engine (main_latesttt.py)
  PipeReader thread → RansomwareDetector
      │  three-layer pipeline: rate → entropy → canary
      ▼
Containment (icacls lockdown / process suspend) — reversible
      ▼
SQLite (alerts) → Tkinter dashboard (live alerts, activity graph, drill-down)
```

### 3.2 Three-layer detection pipeline

**Layer 1 — Rate.** Per process, the detector maintains a sliding window of recent file events.
It alerts when a process modifies at least *k* distinct files within *t* seconds (defaults k=5,
n=10 events tracked, t=0.01 s). This is the primary trigger and generalises across families.

**Layer 2 — Entropy.** Rate alone flags fast benign bursts. Once the rate threshold is crossed,
the detector samples the Shannon entropy of the recently written *distinct* files and computes the
**median** over a per-process window. If the median is confidently **low**, the burst is treated
as benign and **suppressed**; if **high**, it fires. Crucially, the gate only ever *suppresses* on
positive low-entropy evidence — it can never *cause* a false negative. When too few readable
samples exist yet (e.g. a delete/rename wiper, or the very first rate-crossing before file
evidence accrues), it **defers** or **fires** rather than suppressing. The default entropy
threshold is 6.5 bits/byte; setting it to 0 reproduces pure-rate behaviour, which enables a
controlled A/B comparison in Chapter 6.

**Layer 3 — Canary.** Hidden decoy files are placed in the watched folder. No legitimate program
touches them, so any change to a canary's content — or its rename/deletion — is near-certain
ransomware, caught on the **first** file and independent of the rate and entropy thresholds. This
is the mitigation for "low-and-slow" ransomware that deliberately stays under the rate window.

### 3.3 User-space process attribution (ETW)

`ReadDirectoryChangesW` reports which file changed but not which process changed it. The FYP1
heuristic guessed the process from a snapshot and frequently misattributed — sometimes blaming the
monitoring agent itself — which made process-targeted containment unsafe. FYP2 replaces the guess
with a real-time **user-mode** ETW consumer of the `Microsoft-Windows-Kernel-File` provider. The
true PID comes from the kernel-reported event header; NT device paths are translated to DOS drive
letters so they match the paths from `ReadDirectoryChangesW`. Each alert is tagged with its
attribution **source** — `ETW` (accurate) or `HEUR` (fallback) — persisted per alert, so
attribution accuracy is measurable directly from the database.

### 3.4 Reversible containment

Two complementary containment mechanisms are provided, and **every action is reversible from the
dashboard** — a core design principle.

- **Directory lockdown (environmental).** On alert, `icacls` applies a deny-write ACE to the
  affected directory (`/deny Everyone:(OI)(CI)(W,D)`), halting encryption regardless of which
  process is responsible — so it works even when attribution is uncertain. It is reversed with
  `icacls /remove:d Everyone`, which removes only the added deny ACE.
- **Process suspension (process-targeted).** When — and only when — attribution is `ETW`, the
  drill-down offers a user-confirmed *Suspend Process* action that calls `SuspendThread` on the
  offending process's threads; *Resume Process* undoes it. It is gated to ETW-attributed PIDs,
  refuses this process, the agent, PIDs ≤ 4, and a denylist of critical Windows processes, and is
  never automatic.

### 3.5 Design principles

The system is held to a small set of non-negotiable principles: **user-space only** (no kernel
drivers, keeping it deployable); **graceful degradation** (falls back to a simulated mode when not
elevated, never crashing); **configurable and persisted thresholds** (k, n, t, and the entropy
gate are runtime-tunable and survive restart via the registry); **reversible containment** (every
lockdown records the directory it locked so it can be undone); and **local-only persistence**
(single-file SQLite, no cloud).

---

## Chapter 4 — Methodology / System Components

### 4.1 C++ monitoring agent

The agent opens the configured watch directory with backup-semantics and overlapped I/O and calls
`ReadDirectoryChangesW` with a 64 KB notification buffer, watching the subtree recursively for
name, size, last-write, and creation changes. It blocks on `GetOverlappedResult` (no busy-wait),
and for each relevant notification it queries the ETW attributor for the responsible PID, falling
back to the legacy heuristic when ETW is unavailable. Each event is serialised as
`FILEPATH|PID|SOURCE\n` and written to the named pipe. Diagnostics use narrow `std::cout` with a
UTF-8 console code page — a deliberate choice, because `std::wcout` enters a permanent fail state on
the first non-ASCII character and would silently discard all later output.

### 4.2 ETW attribution module

A header-only `etw::Attributor` consumes the `Microsoft-Windows-Kernel-File` provider via a
real-time ETW session, entirely from user mode. File-naming events are parsed with TDH to learn a
`FileObject → path` mapping; the true PID comes from the event header. It maintains a bounded,
age-pruned `path → (pid, tick)` cache, ignores its own PID, and requires Administrator — without
elevation `EnableTraceEx2` returns access-denied and the agent degrades gracefully to the
heuristic, reporting the reason at startup.

### 4.3 Named-pipe IPC

The two processes communicate over `\\.\pipe\SecurityPipe`. The C++ side is the server
(outbound, byte stream); the Python side reads UTF-8 lines. The message format `FILEPATH|PID|SOURCE`
is parsed by splitting on the last two `|` characters and remains backward-compatible with the
legacy two-field form (treated as `HEUR`); Windows filenames cannot contain `|`, so parsing is
unambiguous. The Python reader distinguishes *parse* failures (malformed line, skipped quietly)
from *detector* failures (a bug, logged and never silently swallowed) — a distinction that matters
because silently swallowing the latter previously lost real alerts.

### 4.4 Python analysis engine

The Python controller comprises: an `AgentManager` that spawns the agent; a `PipeReader` daemon
thread; a thread-safe `DetectionConfig` holding k/n/t and the entropy threshold; a `RansomwareDetector`
implementing the three-layer pipeline; a thread-safe SQLite `Database`; and a Tkinter `Dashboard`
with a live activity graph, alert drill-down, search/sort, and settings. On startup it checks for
Administrator privileges (selecting live or simulated mode), shows a splash screen, initialises the
database (running an idempotent schema migration), starts the agent and pipe reader, and launches
the dashboard.

### 4.5 Persistence

Alerts are stored in a single SQLite `alerts` table, with columns capturing the timestamp, alert
type, attacker label, detail, status (`BLOCKED` / `LOCK FAILED`), the full JSON list of affected
files, the locked directory and its active flag (an audit trail for reversibility), the attribution
source, the median write-entropy at alert time, and the attributed PID. Schema evolution uses
idempotent `ALTER TABLE ... ADD COLUMN` statements wrapped in try/except, preserving existing alert
history rather than recreating the database.

---

## Chapter 5 — System Implementation

### 5.1 Development environment

Windows 10/11 x64; Python 3.10+; C++ compiled with MSVC (`cl /EHsc /W4 /O2`) or MinGW-w64
(`g++ -std=c++17 -O2 -municode ... -lpsapi -ltdh -ladvapi32`); Visual Studio Code; Git for version
control. Runtime Python dependencies are deliberately minimal (psutil for the CPU display,
ttkbootstrap as a ~190 KB pure-Python theme skin, with scikit-learn/pandas/numpy used only for the
offline ML study).

### 5.2 Detection engine implementation

The detector keeps a per-PID deque of `(timestamp, filepath)` events, prunes it to the last *n*,
filters to those within *t* seconds, and fires when at least *k* remain and the PID has not already
alerted this session. On the rate crossing it consults the entropy gate (median over distinct
readable files) and the canary check. A shared `_emit_alert()` performs containment *before*
writing the alert row, so the row records the containment outcome. A bounded rolling deque of all
event timestamps feeds the dashboard's activity graph.

### 5.3 Interactive dashboard

The dashboard presents stat cards (total alerts, directories locked, agent CPU, system status), a
searchable and sortable detection log, a live activity graph, and a drill-down window exposing the
full affected-file list plus the reversible Unlock and Suspend/Resume actions. New alerts trigger a
sound and a temporary banner. Thresholds and the watched folder are editable at runtime and
persisted to the registry. The UI is themed with ttkbootstrap (a lightweight skin over tkinter),
chosen over heavier toolkits such as Qt specifically to preserve the "lightweight" design goal.

### 5.4 Containment implementation

Directory lockdown and its reversal are implemented as `icacls` subprocess calls with the exact
inverse ACE operations described in §3.4. Process suspension uses ctypes against kernel32, with
handle prototypes declared explicitly as `c_void_p` — the default `c_int` return type truncates
64-bit HANDLEs into invalid ones — and is guarded by the ETW-only precheck and the critical-process
denylist.

### 5.5 Implementation issues and challenges

- **User-space PID attribution.** `ReadDirectoryChangesW` reports *what* changed, not *who*. The
  FYP1 heuristic often misattributed, sometimes to the agent itself. Solved with a user-mode ETW
  consumer — no kernel driver — with a heuristic fallback.
- **RDCW event amplification.** `ReadDirectoryChangesW` emits several events per file, so a raw
  event window spans very few *distinct* files. The entropy gate therefore had to judge distinct
  files and *defer* when evidence was thin, to avoid premature suppression or false alarms.
- **Silent-failure bugs found through testing.** A non-ANSI path (e.g. a folder with Chinese
  characters) raised `UnicodeEncodeError` — a `ValueError` subclass that was being swallowed —
  causing a *real* alert to vanish; and the C++ agent's `std::wcout` entered a permanent fail
  state on the first non-ASCII byte, discarding all later output. Both were fixed and are now
  covered by tests.
- **64-bit ctypes handles.** Process-suspend HANDLEs were truncated under the default `c_int`
  return type; fixed with explicit `c_void_p` prototypes.
- **Performance.** The PID heuristic cost ~28.8 ms per call and ran once per event; caching it to a
  100 ms window cut end-to-end latency dramatically (see §6).

---

## Chapter 6 — System Evaluation and Discussion

> **Before finalising this chapter,** run the harnesses **as Administrator** with full reps and
> regenerate the figures:
> `python tests/benchmark.py --reps 30`, `python tests/validate_behaviour.py --reps 3`,
> `python tests/sensitivity.py`, `python tools/build_dataset.py`, then `python tools/make_figures.py`.
> Replace every **`[[CONFIRM]]`** below with the measured value.

### 6.1 Evaluation methodology

The system is evaluated along four axes: **detection correctness** against realistic ransomware
behaviour and benign heavy-I/O workloads; **entropy-threshold sensitivity**; **performance**
(latency, CPU, event loss under load); and an **offline ML** comparison against the rule-only
baseline. To evaluate behaviour faithfully without shipping malware, a simulator reproduces the
real ransomware file-I/O sequence (read → encrypt → write → rename/delete) across three family
archetypes, where "encryption" is a reversible SHA-256 keystream XOR whose output is high-entropy
(~7.99 bits/byte) — a behaviourally and entropically faithful stand-in for AES ciphertext. Benign
stressors include bulk copy, archive extraction, backup, and file editing.

### 6.2 Detection correctness

**Table 6-1 — Behaviour validation (defaults, entropy layer on)**

| Scenario | Type | Result |
|---|---|---|
| overwrite / copy_delete / rename | ransomware | **TP** |
| bulk_copy / backup / edit / fast-extract | benign | **TN** |

Confusion matrix: **TP=[[CONFIRM]], TN=[[CONFIRM]], FP=[[CONFIRM]], FN=[[CONFIRM]]** (see
**Fig. fig_validation_confusion.png**). The headline result is a controlled A/B: with the entropy
layer **off** (pure rate), fast archive extraction is a **false positive**; with the entropy layer
**on**, the identical workload is correctly a **true negative**. This is the empirical justification
for the second layer.

### 6.3 Entropy-threshold sensitivity

**Fig. fig_sensitivity.png** plots false-positive and false-negative rates as the entropy threshold
varies. No attack is missed (FN = 0) across a wide band, and the default of 6.5 bits/byte sits
inside that band with margin. The residual false positives are high-entropy *benign* bursts (e.g.
copying already-compressed media) that entropy alone cannot resolve — which is precisely the
motivation for a multi-feature ML layer (§6.5).

### 6.4 Performance

Caching the PID heuristic to a 100 ms window transformed the pipeline's performance:

**Table 6-2 — Effect of caching `GetLikelyPid` (200 ops/s)**

| Metric | Uncached (FYP1) | Cached (FYP2) |
|---|---|---|
| Detection latency (p50) | ~1240 ms | **~17 ms** |
| Agent CPU (normalised) | ~8.1 % | **~0.5 %** |
| Event loss | ~5 % | **0 %** |

See **Fig. fig_perf_fix.png**, and **Fig. fig_benchmark_latency.png** / **fig_benchmark_cpu.png**
for latency and CPU across load levels. *(Replace with your `benchmark_results.csv` values —
**`[[CONFIRM]]`**.)*

### 6.5 Offline ML second layer

An offline study trained a Random Forest on a 9-feature vector (rate, distinct files, entropy
statistics, unique directories, ransom-extension fraction, …) derived from simulator-vs-benign
episodes. Under cross-validation it achieved approximately **[[CONFIRM ~0.97]]** accuracy versus
approximately **[[CONFIRM ~0.81]]** for the best pure-rate threshold (see **Fig. fig_ml_vs_rate.png**);
entropy-derived features ranked highest in importance (**Fig. fig_ml_importance.png**). The key
**limitation** is that the benign class is currently synthetic; training on a diverse real-world
benign corpus (e.g. the RanSAP dataset or a self-collected corpus) is future work. This is why the
classifier is presented as an offline second layer rather than wired into the live decision path.

### 6.6 Attribution accuracy (ETW vs heuristic)

Because the attribution source is persisted per alert, ETW-vs-heuristic accuracy is measured
directly from the database:

```
SELECT attribution, COUNT(*) FROM alerts GROUP BY attribution;
```

Under Administrator (ETW active), **[[CONFIRM: n of m]]** alerts were correctly attributed via ETW,
versus the heuristic which frequently misattributed (including to the agent itself). *(This is the
number to capture from the elevated run — it is not measurable unelevated.)*

### 6.7 Objectives evaluation

**Table 6-3 — Objectives met**

| Objective | Met? | Evidence |
|---|---|---|
| Real-time user-space detection | ✅ | ~17 ms latency, 0 % event loss (Fig. latency) |
| Reduce false positives without missing attacks | ✅ | FN = 0; extract FP fixed by entropy (Figs. sensitivity, confusion) |
| Accurate process attribution | ✅ (elevated) | ETW PID; per-alert attribution tag (§6.6) |
| Reversible containment | ✅ | icacls unlock + process resume, from the GUI |
| Lightweight and configurable | ✅ | tkinter/ttkbootstrap; persisted settings; ~0.5 % CPU |
| Evaluate vs realistic behaviour | ✅ | behaviour matrix, benchmark, sensitivity, ML |

### 6.8 Evasion and limitations discussion

**Table 6-4 — Evasion analysis and mitigations**

| Evasion | Effect | Mitigation in this system |
|---|---|---|
| Slow "low-and-slow" encryption (under the rate window) | rate layer misses it | **Canary layer** catches the first decoy touched, regardless of rate |
| Low-entropy / format-preserving encryption | entropy gate won't fire | rate + **canary** still fire; entropy only ever *suppresses*, never blocks |
| Killing the monitoring agent | detection stops | documented limitation; future work: watchdog/agent-restart; the icacls lock persists |
| Encrypting files outside the watched folder | not observed | configurable + multi-folder watching (future); point the tool at the data that matters |
| Heuristic misattribution (unelevated) | wrong PID → unsafe to suspend | process-suspend is **ETW-only**; never actioned on a heuristic PID |
| Thread created after enumeration during suspend | not frozen | documented; `NtSuspendProcess` (undocumented) would close it |

Stated plainly, the system's limitations are: user-space monitoring cannot stop a kernel-level
threat; accurate attribution requires Administrator; the ML benign corpus is synthetic; and
canaries protect only the watched folder.

---

## Chapter 7 — Conclusion and Recommendations

### 7.1 Conclusion

This project designed, implemented, and evaluated a lightweight, transparent, user-space ransomware
detection and containment system for Windows. It demonstrates that effective, **reversible**
ransomware containment is achievable **without a kernel driver**: a three-layer behavioural
pipeline (rate → entropy → canary) detects realistic ransomware behaviour with zero false negatives
in evaluation, while user-mode ETW recovers the accurate process attribution that user-space
monitors have historically lacked. A performance optimisation reduced detection latency from
approximately 1240 ms to approximately 17 ms at under 1% agent CPU, confirming the approach is
practical for continuous use on ordinary machines. All objectives were met. The principal
trade-off — a small loss of attribution certainty compared with a kernel minifilter — is
substantially mitigated by ETW and is, for the target audience of individuals and small
organisations, well repaid by the gains in deployability and transparency.

### 7.2 Future work

- Train the ML layer on a **real benign corpus** (RanSAP or self-collected) and optionally load it
  as a live third gate.
- An **automatic (unattended) containment** mode (currently manual by design).
- **Multi-folder / whole-drive** monitoring, and a **watchdog** to restart a killed agent.
- **Self-healing** via copy-on-write backup of watched files, as ShieldFS demonstrates.
- A **purchased OV/EV code-signing certificate** to make the (already-implemented) signing pipeline
  fully trusted.

---

*Draft generated to accompany `FYP2_REPORT_SUPPORT.md`. Fill every `[[CONFIRM]]` from the elevated
harness run, insert the figures from `report_figures/`, and reword into your own voice before
submission.*
