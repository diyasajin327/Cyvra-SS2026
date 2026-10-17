"""Safe parser + single-command baseline.
NEVER executes input: no subprocess, os.system, eval or real shell.
"""
import posixpath
import shlex

ROLES = ("OTHER", "SENSITIVE_READ", "STAGE_DATA", "OUTBOUND_TRANSFER")

# Anything here means we can't parse safely -> REVIEW
SHELL_META = ["|", "&", ";", "<", ">", "`", "$", "\n", "\r", "(", ")", "{", "}"]

# Commands that run another command; the real command is hidden -> REVIEW
WRAPPER_BINARIES = {"sudo", "env", "nohup", "time", "nice", "xargs", "watch",
                    "bash", "sh", "zsh", "dash"}

READ_BINARIES = {"cat", "less", "more", "head", "tail"}
SENSITIVE_HINTS = ("passwd", "shadow", "secret", "credential", "id_rsa", ".pem", "password", ".ssh")
STAGE_BINARIES = {"tar", "zip", "gzip", "7z", "cp"}
OUTBOUND_BINARIES = {"scp", "curl", "nc", "ncat", "rsync", "sftp", "ftp", "wget"}


def _empty_event(raw, status):
    return {"raw": raw, "tokens": [], "binary": None, "args": [],
            "role": "OTHER", "parse_status": status, "session_id": None}


def _classify_role(binary, args):
    if binary in READ_BINARIES:
        joined = " ".join(args).lower()
        if any(hint in joined for hint in SENSITIVE_HINTS):
            return "SENSITIVE_READ"
        return "OTHER"
    if binary in STAGE_BINARIES:
        return "STAGE_DATA"
    if binary in OUTBOUND_BINARIES:
        return "OUTBOUND_TRANSFER"
    return "OTHER"


def parse_command(raw):
    """Return a parsed-event dict. Unsupported/ambiguous input gets a non-OK status."""
    if not isinstance(raw, str) or not raw.strip():
        return _empty_event(raw if isinstance(raw, str) else "", "EMPTY")

    if any(ch in raw for ch in SHELL_META):
        return _empty_event(raw, "AMBIGUOUS")  # pipes, chaining, redirects, substitution, grouping

    try:
        tokens = shlex.split(raw)
    except ValueError:  # e.g. unbalanced quotes
        return _empty_event(raw, "MALFORMED")

    if not tokens:
        return _empty_event(raw, "EMPTY")

    first = tokens[0]
    if "=" in first and not first.startswith("-"):
        return _empty_event(raw, "AMBIGUOUS")  # VAR=value command prefix

    binary = posixpath.basename(first)  # /bin/cat -> cat (string handling only)
    if not binary:
        return _empty_event(raw, "AMBIGUOUS")
    if binary in WRAPPER_BINARIES:
        return _empty_event(raw, "AMBIGUOUS")  # real command is hidden

    args = tokens[1:]
    return {"raw": raw, "tokens": tokens, "binary": binary, "args": args,
            "role": _classify_role(binary, args), "parse_status": "OK",
            "session_id": None}


def _is_destructive(binary, args):
    if binary == "rm":
        short_flags = "".join(a[1:] for a in args
                              if a.startswith("-") and not a.startswith("--"))
        recursive = "r" in short_flags or "R" in short_flags or "--recursive" in args
        targets = [a for a in args if not a.startswith("-")]
        if recursive and any(t in ("/", "/*", "~", "~/") for t in targets):
            return True
    if binary.startswith("mkfs"):
        return True
    if binary == "dd" and any(a.startswith("of=/dev/") for a in args):
        return True
    return False


def evaluate_baseline(parsed, session_id):
    """Single-command policy. It looks at ONE command only, with no history."""
    role = parsed.get("role", "OTHER")

    def decision(d, code, reason, policy=None):
        return {"decision": d, "reason_code": code, "reason": reason,
                "matched_policy": policy, "role": role, "session_id": session_id}

    if parsed.get("parse_status") != "OK":
        return decision("REVIEW", "UNSUPPORTED_SYNTAX",
                        "Unsupported or ambiguous syntax: " + str(parsed.get("parse_status")))
    if _is_destructive(parsed.get("binary") or "", parsed.get("args") or []):
        return decision("BLOCK", "BASELINE_DESTRUCTIVE", "Destructive single command",
                        "baseline-destructive")
    return decision("ALLOW", "NO_RULE_MATCH", "No configured policy matched")
