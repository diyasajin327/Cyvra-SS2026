
"""Append-only JSONL audit chain and labelled-corpus evaluation.

The hash chain is an integrity check, not a tamper-proof logging system.
The anomaly detector comparison uses a deterministic heuristic, not a
trained machine-learning model.
"""

import hashlib
import json
import os
import time
from pathlib import Path

from src.ml_detector import predict_anomaly
from src.sequence_engine import SequenceEngine


DEFAULT_LOG_PATH = Path("results") / "audit.jsonl"
GENESIS_HASH = "0" * 64


def _canonical_json(record):
    """Return a stable UTF-8 JSON representation."""
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _record_hash(record):
    """Hash every field except current_hash."""
    payload = {
        key: value
        for key, value in record.items()
        if key != "current_hash"
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def append_event(event):
    """Append an event to the JSONL hash chain and return its record."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    path = Path(
        os.environ.get("TERMICIPHER_AUDIT_LOG", str(DEFAULT_LOG_PATH))
    )
    path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = GENESIS_HASH
    sequence = 1

    if path.exists() and path.stat().st_size:
        with path.open("r", encoding="utf-8-sig") as stream:
            for line in stream:
                if not line.strip():
                    continue

                previous = json.loads(line)
                previous_hash = previous.get("current_hash", "")
                sequence = int(previous.get("sequence_number", 0)) + 1

    record = {
        "sequence_number": sequence,
        "session_id": event.get("session_id"),
        "decision": event.get("decision"),
        "role": event.get("role", "OTHER"),
        "reason_code": event.get("reason_code"),
        "previous_hash": previous_hash,
    }

    if "score" in event:
        record["score"] = event["score"]

    record["current_hash"] = _record_hash(record)

    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(_canonical_json(record).decode("utf-8") + "\n")

    return record


def verify_log(path):
    """Check record hashes, chain links, ordering, and sequence numbers."""
    result = {
        "valid": True,
        "records_checked": 0,
        "errors": [],
    }

    previous_hash = GENESIS_HASH
    expected_sequence = 1

    try:
        with open(path, "r", encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    result["errors"].append(
                        f"Line {line_number}: invalid JSON"
                    )
                    continue

                result["records_checked"] += 1

                if not isinstance(record, dict):
                    result["errors"].append(
                        f"Line {line_number}: record must be a JSON object"
                    )
                    expected_sequence += 1
                    previous_hash = ""
                    continue

                if record.get("sequence_number") != expected_sequence:
                    result["errors"].append(
                        f"Line {line_number}: sequence number mismatch"
                    )

                if record.get("previous_hash") != previous_hash:
                    result["errors"].append(
                        f"Line {line_number}: previous hash mismatch"
                    )

                stored_hash = record.get("current_hash")
                calculated_hash = _record_hash(record)

                if (
                    not isinstance(stored_hash, str)
                    or stored_hash != calculated_hash
                ):
                    result["errors"].append(
                        f"Line {line_number}: record hash mismatch"
                    )

                previous_hash = (
                    stored_hash if isinstance(stored_hash, str) else ""
                )
                expected_sequence += 1

    except OSError as exc:
        result["errors"].append(f"Could not read log: {exc}")

    result["valid"] = not result["errors"]
    return result


def _metrics(tp, fp, tn, fn, latencies):
    """Calculate confusion-matrix metrics and mean latency."""
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "count": tp + fp + tn + fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "latency_ms_mean": (
            sum(latencies) / len(latencies) if latencies else 0.0
        ),
    }


def _predict_risky(roles):
    """Detect SENSITIVE_READ -> STAGE_DATA -> OUTBOUND_TRANSFER in order."""
    expected = (
        "SENSITIVE_READ",
        "STAGE_DATA",
        "OUTBOUND_TRANSFER",
    )
    next_index = 0

    for role in roles:
        if role == expected[next_index]:
            next_index += 1
            if next_index == len(expected):
                return True

    return False


def _load_corpus(corpus_path):
    """Load and validate labelled JSONL role-sequence traces."""
    records = []

    with open(corpus_path, "r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from exc

            if not isinstance(item, dict):
                raise ValueError(
                    f"Line {line_number} must contain a JSON object"
                )

            label = item.get("label")
            roles = item.get("roles")

            if label not in ("BENIGN", "RISKY"):
                raise ValueError(
                    f"Line {line_number}: label must be BENIGN or RISKY"
                )

            if not isinstance(roles, list):
                raise ValueError(
                    f"Line {line_number}: roles must be a list"
                )

            if any(not isinstance(role, str) for role in roles):
                raise ValueError(
                    f"Line {line_number}: every role must be a string"
                )

            records.append((label, roles))

    if not records:
        raise ValueError("Corpus contains no labelled traces")

    return records


def evaluate_corpus(corpus_path):
    """Evaluate the role-pattern baseline on labelled JSONL data.

    This preserves the original evaluate_corpus API.
    Results apply only to the supplied corpus.
    """
    records = _load_corpus(corpus_path)

    tp = fp = tn = fn = 0
    latencies = []

    for label, roles in records:
        started = time.perf_counter()
        predicted_risky = _predict_risky(roles)
        latencies.append((time.perf_counter() - started) * 1000)

        if predicted_risky and label == "RISKY":
            tp += 1
        elif predicted_risky and label == "BENIGN":
            fp += 1
        elif not predicted_risky and label == "BENIGN":
            tn += 1
        else:
            fn += 1

    return {
        "method": "role_sequence_pattern_baseline",
        "corpus_path": str(corpus_path),
        "metrics": _metrics(tp, fp, tn, fn, latencies),
        "note": (
            "Measured on the supplied corpus only; this is not a "
            "held-out comparison or a trained-ML result."
        ),
    }


def evaluate_methods(corpus_path):
    """Compare role-pattern, sequence, heuristic, and combined methods.

    Each complete trace is evaluated independently. Sequence rules use a
    fresh SequenceEngine for every trace. The combined method flags a trace
    when either the sequence engine or heuristic flags it.

    This is an initial in-sample comparison, not a held-out benchmark.
    """
    records = _load_corpus(corpus_path)

    methods = {
        "role_pattern_baseline": [],
        "sequence_rules": [],
        "heuristic_anomaly_detector": [],
        "combined_sequence_and_heuristic": [],
    }

    for trace_index, (label, roles) in enumerate(records):
        # 1. Transparent role-pattern baseline.
        started = time.perf_counter()
        pattern_flag = _predict_risky(roles)
        pattern_latency = (time.perf_counter() - started) * 1000

        methods["role_pattern_baseline"].append(
            (label, pattern_flag, pattern_latency)
        )

        
        # 2. Real sequence engine, isolated per trace.
        engine = SequenceEngine()
        sequence_flag = False
        started = time.perf_counter()

        # All events in one trace must share the same session ID.
        session_id = f"evaluation-{trace_index}"

        for event_index, role in enumerate(roles):
            parsed = {
                "role": role,
                "parse_status": "OK",
            }

            decision = engine.evaluate(parsed, session_id)

            if decision.get("decision") == "BLOCK":
                sequence_flag = True

        sequence_latency = (time.perf_counter() - started) * 1000

        methods["sequence_rules"].append(
            (label, sequence_flag, sequence_latency)
        )


        # 3. Existing deterministic heuristic detector.
        started = time.perf_counter()
        prediction = predict_anomaly(roles)
        heuristic_flag = bool(prediction.get("anomaly", False))
        heuristic_latency = (time.perf_counter() - started) * 1000

        methods["heuristic_anomaly_detector"].append(
            (label, heuristic_flag, heuristic_latency)
        )

        # 4. Trace is risky if either method flags it.
        methods["combined_sequence_and_heuristic"].append(
            (
                label,
                sequence_flag or heuristic_flag,
                sequence_latency + heuristic_latency,
            )
        )

    results = {}

    for method_name, outcomes in methods.items():
        tp = fp = tn = fn = 0
        latencies = []

        for label, predicted_risky, latency in outcomes:
            latencies.append(latency)

            if predicted_risky and label == "RISKY":
                tp += 1
            elif predicted_risky and label == "BENIGN":
                fp += 1
            elif not predicted_risky and label == "BENIGN":
                tn += 1
            else:
                fn += 1

        results[method_name] = _metrics(tp, fp, tn, fn, latencies)

    return {
        "corpus_path": str(corpus_path),
        "trace_count": len(records),
        "evaluation_type": "initial_in_sample_comparison",
        "results": results,
        "note": (
            "Results describe only the supplied labelled traces. The "
            "anomaly detector is a deterministic heuristic, not a trained "
            "ML model. Latency is measured locally and is not a platform "
            "benchmark. The pattern baseline and heuristic are related "
            "methods, so their results are not independent evidence."
        ),
    }