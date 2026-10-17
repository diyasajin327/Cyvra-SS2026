
"""Lightweight, deterministic role-sequence anomaly detector.

This is a transparent heuristic baseline, not a trained ML model.
It accepts role labels only and never executes commands.
"""

from collections import Counter

ROLE_VOCABULARY = {
    "OTHER",
    "SENSITIVE_READ",
    "STAGE_DATA",
    "OUTBOUND_TRANSFER",
}

MODEL_VERSION = "role-heuristic-1.0"
MAX_SEQUENCE_LENGTH = 6


def _is_risky_order(sequence):
    """Return True for SENSITIVE_READ -> STAGE_DATA -> OUTBOUND_TRANSFER."""
    expected = (
        "SENSITIVE_READ",
        "STAGE_DATA",
        "OUTBOUND_TRANSFER",
    )
    next_index = 0

    for role in sequence:
        if role == expected[next_index]:
            next_index += 1
            if next_index == len(expected):
                return True

    return False


def predict_anomaly(sequence):
    """Return {'score', 'anomaly', 'model_version'} for a role sequence.

    The score is a heuristic risk indicator in [0.0, 1.0], not a
    calibrated probability. Unknown role labels produce a safe fallback.
    """
    if not isinstance(sequence, list):
        return {
            "score": None,
            "anomaly": False,
            "model_version": "unavailable",
        }

    if any(not isinstance(role, str) or role not in ROLE_VOCABULARY
           for role in sequence):
        return {
            "score": None,
            "anomaly": False,
            "model_version": MODEL_VERSION,
        }

    roles = sequence[-MAX_SEQUENCE_LENGTH:]

    if not roles:
        return {
            "score": 0.0,
            "anomaly": False,
            "model_version": MODEL_VERSION,
        }

    counts = Counter(roles)
    risky_order = _is_risky_order(roles)

    # Transparent indicators: the complete ordered pattern is strongest.
    score = 0.0
    if "SENSITIVE_READ" in counts and "OUTBOUND_TRANSFER" in counts:
        score += 0.25
    if "STAGE_DATA" in counts and "OUTBOUND_TRANSFER" in counts:
        score += 0.15
    if risky_order:
        score = 0.95

    score = min(1.0, score)

    return {
        "score": round(score, 4),
        "anomaly": risky_order,
        "model_version": MODEL_VERSION,
    }