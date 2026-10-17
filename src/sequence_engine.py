"""Stateful sequence engine (Member 3).

Tracks a bounded history of role labels per session and flags the pattern
SENSITIVE_READ -> STAGE_DATA -> OUTBOUND_TRANSFER, tolerating a limited
number of benign OTHER events between steps.
Never executes anything: it only reads role labels.
"""

from collections import deque

PATTERN = ["SENSITIVE_READ", "STAGE_DATA", "OUTBOUND_TRANSFER"]
VALID_ROLES = {"OTHER", "SENSITIVE_READ", "STAGE_DATA", "OUTBOUND_TRANSFER"}
HISTORY_LEN = 8
MAX_NOISE = 2


def match_progress(history):
    """Return how many pattern steps (0..3) are matched, in order."""
    stage = 0
    noise = 0

    for role in history:
        if stage < len(PATTERN) and role == PATTERN[stage]:
            stage += 1
            noise = 0

        elif role == "OTHER":
            if stage > 0:
                noise += 1
                if noise > MAX_NOISE:
                    stage, noise = 0, 0

        elif stage > 0 and role == PATTERN[stage - 1]:
            # Repeating the previous step does not restart the match.
            noise = 0

        else:
            # An out-of-order risky role restarts the match.
            stage = 1 if role == PATTERN[0] else 0
            noise = 0

        if stage == len(PATTERN):
            return stage

    return stage


class SequenceEngine:
    def __init__(self, history_len=HISTORY_LEN):
        self.history_len = history_len
        self._sessions = {}

    def reset_session(self, session_id=None):
        """Clear one session, or all sessions if session_id is None."""
        if session_id is None:
            self._sessions.clear()
        else:
            self._sessions.pop(session_id, None)

    def get_history(self, session_id):
        """Return a copy of the session's event history."""
        return list(self._sessions.get(session_id, []))

    def evaluate(self, parsed, session_id):
        """Evaluate a parsed event and return a sequence decision."""

        # Skip events the parser could not understand.
        if parsed.get("parse_status", "OK") != "OK":
            return self._decision(
                "ALLOW",
                "SEQUENCE_SKIPPED",
                "Event skipped because parsing was unsuccessful",
                session_id,
                0,
            )

        role = parsed.get("role")

        # Ignore invalid or unsupported role labels.
        if role not in VALID_ROLES:
            return self._decision(
                "ALLOW",
                "SEQUENCE_SKIPPED",
                "Event skipped because the role is invalid",
                session_id,
                0,
            )

        hist = self._sessions.setdefault(
            session_id, deque(maxlen=self.history_len)
        )
        hist.append(role)

        progress = match_progress(list(hist))

        if progress == len(PATTERN):
            # Block once for this completed match, then start fresh.
            hist.clear()
            return self._decision(
                "BLOCK",
                "SEQUENCE_EXFIL_PATTERN",
                "Sensitive read, then staging, then outbound transfer",
                session_id,
                progress,
            )

        if progress > 0:
            return self._decision(
                "ALLOW",
                "SEQUENCE_PARTIAL",
                f"Partial pattern ({progress}/{len(PATTERN)})",
                session_id,
                progress,
            )

        return self._decision(
            "ALLOW",
            "SEQUENCE_CLEAR",
            "No risky sequence",
            session_id,
            0,
        )

    @staticmethod
    def _decision(decision, code, reason, session_id, progress):
        return {
            "decision": decision,
            "reason_code": code,
            "reason": reason,
            "session_id": session_id,
            "progress": progress,
        }


# Module-level default engine.
_engine = SequenceEngine()


def evaluate_sequence(parsed: dict, session_id: str) -> dict:
    """Evaluate an event using the module-level engine."""
    return _engine.evaluate(parsed, session_id)


def reset_session(session_id=None):
    """Reset one session or all sessions in the module-level engine."""
    _engine.reset_session(session_id)
