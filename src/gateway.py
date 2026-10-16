"""Member 1 (Pavithra) - Gateway. Input is inert text; NEVER executed or passed to a shell."""

# ---------------- MOCKS (replace one at a time at integration) ----------------
_mock_history = {}


def _decision(decision, reason_code, reason, role, session_id, matched_policy=None):
    return {"decision": decision, "reason_code": reason_code, "reason": reason,
            "matched_policy": matched_policy, "role": role, "session_id": session_id}


def mock_parse(raw):
    text = raw.strip()
    tokens = text.split()
    status = "OK"
    if not tokens or any(c in text for c in ["|", ";", "&", ">", "<", "`", "$("]):
        status = "UNSUPPORTED"
    binary = tokens[0] if tokens else ""
    role = "OTHER"
    if binary in ("cat", "less") and any(s in text for s in ("/etc/passwd", "/etc/shadow", ".ssh")):
        role = "SENSITIVE_READ"
    elif binary in ("tar", "zip", "cp"):
        role = "STAGE_DATA"
    elif binary in ("curl", "scp", "nc", "wget"):
        role = "OUTBOUND_TRANSFER"
    return {"raw": raw, "tokens": tokens, "binary": binary, "args": tokens[1:],
            "role": role, "parse_status": status}


def mock_baseline(parsed, session_id):
    if "rm -rf /" in parsed["raw"]:
        return _decision("BLOCK", "BASELINE_DESTRUCTIVE", "Destructive command",
                         parsed["role"], session_id, "baseline-destructive")
    return _decision("ALLOW", "NO_RULE_MATCH", "No configured policy matched",
                     parsed["role"], session_id)


def mock_sequence(parsed, session_id):
    hist = _mock_history.setdefault(session_id, [])
    hist.append(parsed["role"])
    hist[:] = hist[-6:]
    need = ["SENSITIVE_READ", "STAGE_DATA", "OUTBOUND_TRANSFER"]
    i = 0
    for r in hist:
        if i < 3 and r == need[i]:
            i += 1
    if i == 3:
        return _decision("BLOCK", "SEQ_EXFIL_CHAIN", "Read -> stage -> outbound sequence",
                         parsed["role"], session_id, "seq-exfil-chain")
    return _decision("ALLOW", "NO_RULE_MATCH", "No configured policy matched",
                     parsed["role"], session_id)


def mock_reset(session_id):
    _mock_history.pop(session_id, None)


MOCK_LOG = []


def mock_log(event):
    MOCK_LOG.append(event)
    return event


def mock_predict_anomaly(sequence):
    """Stand-in for Member 5's predict_anomaly(sequence) -> dict. Never flags anything."""
    return {"score": 0.0, "anomaly": False, "model_version": "mock-0"}


# ---------------- DECISION PRECEDENCE ----------------

def combine(parsed, baseline, sequence, session_id):
    """Apply decision precedence and return a consistent decision structure."""
    role = parsed.get("role", "OTHER")

    if parsed.get("parse_status") != "OK":
        return _decision(
            "REVIEW",
            "UNSUPPORTED_SYNTAX",
            "Unsupported or ambiguous syntax - needs review",
            role,
            session_id,
        )

    results = [baseline] + ([sequence] if sequence else [])

    for result in results:
        if result.get("decision") == "BLOCK":
            return {
                **result,
                "role": role,
                "session_id": session_id,
            }

    for result in results:
        if result.get("decision") == "REVIEW":
            return {
                **result,
                "role": role,
                "session_id": session_id,
            }

    return _decision(
        "ALLOW",
        "NO_RULE_MATCH",
        "No configured policy matched",
        role,
        session_id,
    )



# ---------------- GATEWAY ----------------
class Gateway:
    HISTORY_LEN = 6

    def __init__(self, parse=mock_parse, baseline=mock_baseline, sequence=mock_sequence,
                 log=mock_log, reset=mock_reset, predict=mock_predict_anomaly):
        self.parse, self.baseline, self.sequence = parse, baseline, sequence
        self.log, self.predict = log, predict
        self._reset_sequence = reset
        self._roles = {}   # session_id -> last roles, fed to the ML model

    def reset(self, session_id):
        """Clear the sequence engine state and the ML history for one session."""
        self._reset_sequence(session_id)
        self._roles.pop(session_id, None)

    def _ml_score(self, parsed, session_id):
        roles = self._roles.setdefault(session_id, [])
        roles.append(parsed.get("role", "OTHER"))
        del roles[:-self.HISTORY_LEN]
        try:
            return self.predict(list(roles))
        except Exception:   # a broken model must never break the gateway
            return {"score": None, "anomaly": False, "model_version": "unavailable"}

    def process(self, raw, session_id="demo-01"):
        parsed = self.parse(raw)
        base = self.baseline(parsed, session_id)
        seq = None
        ml = None
        if parsed.get("parse_status") == "OK":   # don't feed junk to the engines
            seq = self.sequence(parsed, session_id)
            ml = self._ml_score(parsed, session_id)
        final = combine(parsed, base, seq, session_id)
        # The model may only upgrade ALLOW to REVIEW. It never overrides a rule and never blocks.
        if ml and final["decision"] == "ALLOW" and ml.get("anomaly"):
            final = _decision("REVIEW", "SEQUENCE_ANOMALY", "Unusual role sequence (ML)",
                              final["role"], session_id, "ml-anomaly")
            final["score"] = ml.get("score")
        event = {"session_id": session_id, "decision": final["decision"],
                 "role": final["role"], "reason_code": final["reason_code"]}
        if final.get("score") is not None:
            event["score"] = final["score"]
        self.log(event)
        return final



def load_real():
    """Load the real parser, sequence engine, ML detector, and audit logger."""
    from src import parser_policy, sequence_engine, audit_eval, ml_detector

    return Gateway(
        parse=parser_policy.parse_command,
        baseline=parser_policy.evaluate_baseline,
        sequence=sequence_engine.evaluate_sequence,
        log=audit_eval.append_event,
        reset=sequence_engine.reset_session,
        predict=ml_detector.predict_anomaly,
    )


def run_cli(gw=None, session_id="demo-01"):
    gw = gw or Gateway()
    print("TermiCipher-Z demo. Text is only analysed, never executed.")
    print("Type a command. ':reset' clears the session, ':quit' exits.")
    while True:
        try:
            raw = input(f"[{session_id}]> ")
        except (EOFError, KeyboardInterrupt):
            break
        if raw.strip() == ":quit":
            break
        if raw.strip() == ":reset":
            gw.reset(session_id)
            print("session reset")
            continue
        d = gw.process(raw, session_id)
        score = d.get("score")
        extra = f"  score={score:.2f}" if isinstance(score, (int, float)) else ""
        print(f"{d['decision']}  [{d['reason_code']}]  {d['reason']}{extra}")


if __name__ == "__main__":
    run_cli()