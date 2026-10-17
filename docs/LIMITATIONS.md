# TermiCipher-Z: Limitations and Honest Claims

TermiCipher-Z is a **measured prototype built in 24 hours**. This page states what it does, what it does not do, and which claims we do not make.

## What it is

A controlled, user-space simulation that:

- parses inert command text and labels each command with a role,
- applies single-command (baseline) rules,
- detects risky multi-step sequences within a session (stateful mode),
- records decisions in a SHA-256 hash-chained local audit log,
- is evaluated on a small synthetic dataset.

## 1. Simulation only

- Input is **inert text**. The prototype never executes commands and never passes input to a shell.
- It uses no paid services.

## 2. Not system-wide enforcement

- It only evaluates text sent through its own gateway.
- Anything run outside the gateway is not seen and can bypass it completely.
- It is not a firewall, an endpoint protection tool, or a replacement for one.

## 3. Parser limitations

- Tokenization uses `shlex`, which is **not a full shell parser**.
- Pipes, chaining (`;`, `&&`), redirection, command substitution and other ambiguous syntax are marked `UNSUPPORTED` and returned as **REVIEW**. We do not try to understand them.
- Role labels (`SENSITIVE_READ`, `STAGE_DATA`, `OUTBOUND_TRANSFER`, `OTHER`) cover only the agreed synthetic examples. Real commands that behave similarly but look different will be labelled `OTHER`.
- Obfuscation, aliases, scripts and encoded commands are not handled.

## 4. Sequence detector limitations

- It implements one explainable rule: `SENSITIVE_READ` → `STAGE_DATA` → `OUTBOUND_TRANSFER`. A full match returns `BLOCK` (`SEQUENCE_EXFIL_PATTERN`); a partial match returns `ALLOW` (`SEQUENCE_PARTIAL`).
- It keeps a bounded history of 8 events per session. Older events scroll out and are forgotten, so slow attacks spread over long gaps may be missed.
- Up to 2 `OTHER` events are tolerated between steps. A third consecutive `OTHER` event resets the match.
- Repeating the step just completed does not restart the match. For example, repeating `STAGE_DATA` keeps the sequence at the staging stage.
- After a full match returns `BLOCK`, the session history is cleared. Subsequent events start a fresh sequence attempt.
- Steps spread across different sessions are not linked.
- Events with a non-OK parse status are skipped (`ALLOW`, `SEQUENCE_SKIPPED`). The gateway is responsible for sending these events to `REVIEW`.
- State is held in memory only: it is not persistent or thread-safe, and the number of sessions is not bounded.
- **It does not claim to catch all real-world exfiltration.**
- The rule was designed around synthetic traces, so results may not generalize to real activity.

## 5. Audit log limitations

- The hash chain can reveal edits when checked against a trusted starting point.
- An attacker who can rewrite the **whole** log can recompute every hash.
- We therefore do **not** call it immutable or tamper-proof. We only claim that it detects the modified-copy case in our tamper test.

## 6. Evaluation limitations


- The dataset is **synthetic and small**. It was written by the team, so it reflects our own assumptions.
- Metrics are computed from actual runs and reported with raw counts (true positives, false positives, false negatives, true negatives).
- The original six-trace fixture and the expanded 20-trace fixture are development/behavior-testing data. The expanded fixture was designed around the detector's existing rule behavior; it is not an independent held-out benchmark.
- No independent held-out evaluation has been established by the runs documented here. Results are **preliminary and synthetic-corpus-only**.
- The sequence engine's perfect results on the expanded fixture must not be interpreted as evidence of generalization.
- Latency was measured locally on LinuxONE for these runs. It is **not** a production-grade performance benchmark.


## 7. Novelty

Session-aware command controls and sequence detection already exist in adjacent tools. We present this as a measured prototype, **not** the first system of its kind.


## 8. IBM Z / LinuxONE

- **Status: tested on LinuxONE.** The project was run on an IBM LinuxONE Community Cloud instance using Ubuntu 24.04 and Python 3.12.
- The full test suite passed: **58 tests, 0 failures, 0 errors, 0 skipped** in the recorded run.
- The labelled-corpus evaluation was also executed on LinuxONE using `fixtures/role_sequences.jsonl` and `fixtures/role_sequences_extended.jsonl`.
- These runs demonstrate execution and functional testing on the platform. They do not establish a platform-specific performance advantage.
- Evidence screenshots should be stored in `results/platform_evidence/`.


## 9. Known gaps

- No real-time interception of live terminals.
- No user authentication or multi-user separation.
- No protection of the log file itself (permissions, remote storage, signing).
- Rules are static. There is no learning and no automatic tuning.

## 10. Parser and baseline details (Member 2)

- `shlex` is used only for basic tokenization. It is not a full shell parser.
- Pipes, chaining (`&&`, `;`), redirection (`<`, `>`), command substitution (`$`, backticks), newlines and malformed input are not interpreted. They return REVIEW instead.
- Roles (SENSITIVE_READ, STAGE_DATA, OUTBOUND_TRANSFER, OTHER) are labels for synthetic, inert examples. They do not prove that a real shell command was understood.
- The role table is small and hand-written. Unlisted tools and aliases map to OTHER.
- Matching is case-sensitive, as on Linux. `CAT` is not treated as `cat`.
- The single-command baseline sees one command at a time, with no history. It cannot detect multi-step sequences.
- Input text is never executed. No subprocess, os.system, eval or real shell is used.

*Last reviewed by the team: ____ (date)*