
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import audit_eval


class TestAuditEval(unittest.TestCase):
    def test_append_and_verify_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"

            with patch.object(audit_eval, "DEFAULT_LOG_PATH", log_path):
                first = audit_eval.append_event({
                    "session_id": "s-01",
                    "decision": "ALLOW",
                    "role": "OTHER",
                    "reason_code": "SAFE",
                })
                second = audit_eval.append_event({
                    "session_id": "s-01",
                    "decision": "REVIEW",
                    "role": "SENSITIVE_READ",
                    "reason_code": "CHECK",
                })

            self.assertEqual(first["sequence_number"], 1)
            self.assertEqual(second["sequence_number"], 2)
            self.assertEqual(second["previous_hash"], first["current_hash"])
            self.assertTrue(audit_eval.verify_log(log_path)["valid"])

    def test_detect_modified_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"

            with patch.object(audit_eval, "DEFAULT_LOG_PATH", log_path):
                audit_eval.append_event({
                    "session_id": "s-01",
                    "decision": "ALLOW",
                    "role": "OTHER",
                    "reason_code": "SAFE",
                })

            record = json.loads(log_path.read_text(encoding="utf-8"))
            record["decision"] = "BLOCK"
            log_path.write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )

            result = audit_eval.verify_log(log_path)
            self.assertFalse(result["valid"])
            self.assertTrue(any("hash mismatch" in e for e in result["errors"]))

    def test_detect_missing_record_or_sequence_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"

            with patch.object(audit_eval, "DEFAULT_LOG_PATH", log_path):
                for i in range(3):
                    audit_eval.append_event({
                        "session_id": "s-01",
                        "decision": "ALLOW",
                        "role": "OTHER",
                        "reason_code": f"SAFE_{i}",
                    })

            records = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
            ]
            # Remove the middle record to simulate a missing entry.
            log_path.write_text(
                json.dumps(records[0]) + "\n" +
                json.dumps(records[2]) + "\n",
                encoding="utf-8",
            )

            result = audit_eval.verify_log(log_path)
            self.assertFalse(result["valid"])
            self.assertTrue(result["errors"])

    def test_evaluate_existing_role_fixture(self):
        result = audit_eval.evaluate_corpus("fixtures/role_sequences.jsonl")
        metrics = result["metrics"]

        self.assertEqual(metrics["count"], 6)
        self.assertEqual(metrics["TP"], 2)
        self.assertEqual(metrics["FP"], 0)
        self.assertEqual(metrics["TN"], 4)
        self.assertEqual(metrics["FN"], 0)
        self.assertEqual(result["method"], "role_sequence_pattern_baseline")


if __name__ == "__main__":
    unittest.main()