# TermiCipher-Z: Interface Contract

**Status:** FROZEN after the Hour 6-8 contract check. Any change must be agreed by all four members and recorded in the Change Log at the bottom.

**Scope reminder:** All input is inert text. Nothing is ever executed or passed to a shell.

## 1. Owners and files

| Member | Name | File | Owns |
|---|---|---|---|
| 1 | Pavithra | `src/gateway.py` | CLI, session orchestration, decision precedence |
| 2 | Avani | `src/parser_policy.py` | Parsing, role labels, single-command baseline |
| 3 | Diya | `src/sequence_engine.py` | Stateful multi-step detection |
| 4 | Shivani | `src/audit_eval.py` | Hash-chained audit log, verifier, evaluation |

One file owner per module. Do not edit another member's file.

## 2. Parsed command object

Returned by `parse_command(raw)`.

```json
{
  "raw": "cat /tmp/demo.txt",
  "tokens": ["cat", "/tmp/demo.txt"],
  "binary": "cat",
  "args": ["/tmp/demo.txt"],
  "role": "SENSITIVE_READ",
  "parse_status": "OK"
}
```

| Key | Type | Meaning |
|---|---|---|
| `raw` | string | The original inert text, unchanged |
| `tokens` | list of strings | Result of tokenization (empty list if it could not be tokenized) |
| `binary` | string | First token, or `""` if none |
| `args` | list of strings | All tokens after the first |
| `role` | string | One of the role values below |
| `parse_status` | string | `"OK"` or `"UNSUPPORTED"` |

### Role values

Exactly these four strings:

- `OTHER`
- `SENSITIVE_READ`
- `STAGE_DATA`
- `OUTBOUND_TRANSFER`

Roles are labels for synthetic examples. They are **not** proof that a full shell command has been understood.

### parse_status values

Exactly these two strings:

- `"OK"`: the command was tokenized and is a simple single command.
- `"UNSUPPORTED"`: empty input, malformed quoting, pipes, chaining (`;`, `&&`), redirection (`>`, `<`), command substitution (`` ` ``, `$(`), or any other ambiguous syntax.

When `parse_status` is `"UNSUPPORTED"`, the gateway returns REVIEW. Unsupported commands are never sent to the sequence engine.

## 3. Decision object

Returned by `evaluate_baseline(...)` and `evaluate_sequence(...)`, and by the gateway as the final result.

```json
{
  "decision": "ALLOW",
  "reason_code": "NO_RULE_MATCH",
  "reason": "No configured policy matched",
  "matched_policy": null,
  "role": "OTHER",
  "session_id": "demo-01"
}
```

| Key | Type | Meaning |
|---|---|---|
| `decision` | string | Exactly `ALLOW`, `BLOCK` or `REVIEW` |
| `reason_code` | string | Short stable code, UPPER_SNAKE_CASE |
| `reason` | string | Human-readable explanation |
| `matched_policy` | string or null | Name of the rule that fired, or `null` |
| `role` | string | Role of the command being judged |
| `session_id` | string | The session this decision belongs to |

### Agreed reason codes

| Code | Used by | Meaning |
|---|---|---|
| `NO_RULE_MATCH` | any | No policy matched |
| `UNSUPPORTED_SYNTAX` | gateway | Parser returned `"UNSUPPORTED"` |
| `BASELINE_*` | Member 2 | Single-command rule fired (for example `BASELINE_DESTRUCTIVE`) |
| `SEQ_*` | Member 3 | Sequence rule fired (for example `SEQ_EXFIL_CHAIN`) |

Members 2 and 3 may add their own codes with those prefixes. List them in the Change Log.

## 4. Function signatures

```python
# Member 2: src/parser_policy.py
parse_command(raw: str) -> dict               # parsed command object
evaluate_baseline(parsed: dict, session_id: str) -> dict   # decision object

# Member 3: src/sequence_engine.py
evaluate_sequence(parsed: dict, session_id: str) -> dict   # decision object
reset_session(session_id: str) -> None

# Member 4: src/audit_eval.py
append_event(event: dict) -> dict             # returns the stored record
verify_log(path: str) -> dict
evaluate_corpus(corpus_path: str) -> dict

# Member 1: src/gateway.py
Gateway.process(raw: str, session_id: str) -> dict   # final decision object
load_real() -> Gateway                        # wires in the real modules
```

### Rules for each function

- `parse_command` never raises on bad input. It returns `parse_status: "UNSUPPORTED"` instead.
- `evaluate_baseline` uses **no** session history. Same input always gives the same output.
- `evaluate_sequence` keeps session state internally (bounded recent-role history per session). The gateway passes one parsed command at a time.
- `reset_session` clears all state for that session. Tests call it between cases.
- Every decision function returns **all six keys** of the decision object.

### Audit event (input to `append_event`)

The gateway sends:

```json
{
  "session_id": "demo-01",
  "decision": "BLOCK",
  "role": "OUTBOUND_TRANSFER",
  "reason_code": "SEQ_EXFIL_CHAIN"
}
```

Member 4 adds the remaining fields to the stored JSONL record: sequence number, previous hash and current hash.

### Proposed return shapes for Member 4 (to confirm at contract check)

```json
// verify_log(path)
{"valid": true, "records_checked": 12, "error": null}

// evaluate_corpus(corpus_path): raw counts always included
{
  "baseline": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
  "stateful": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
  "latency_ms_per_command": {"mean": 0.0, "max": 0.0}
}
```

Member 4 confirms or adjusts these at the Hour 6-8 contract check.

## 5. Gateway decision precedence

The gateway applies these rules in order and stops at the first match:

1. `parse_status` is not `"OK"` -> **REVIEW** (`UNSUPPORTED_SYNTAX`)
2. Baseline decision is BLOCK -> **BLOCK**
3. Sequence decision is BLOCK -> **BLOCK**
4. Any decision is REVIEW -> **REVIEW**
5. Otherwise -> **ALLOW**

Processing order per command: parse -> baseline -> sequence (only if parse is OK) -> log -> print.

## 6. Fixtures

Fixtures are plain static data so tests never depend on another member's imports.

- `fixtures/parsed_examples.json`: parsed command objects (Member 2)
- `fixtures/labelled_traces.jsonl`: role-labelled traces (Members 3 and 4)
- `fixtures/expected_decisions.jsonl`: expected decision objects

## 7. Change Log

| Date | Change | Agreed by |
|---|---|---|
| | Initial contract | |

## predict_anomaly

`predict_anomaly(sequence: list[str]) -> dict`

Input: the last few role labels for a session, e.g. `["SENSITIVE_READ", "OTHER"]`.
Returns: `{"score": float, "anomaly": bool, "model_version": str}`.
The gateway only uses an anomaly to upgrade ALLOW to REVIEW. It never blocks and never overrides a rule.
