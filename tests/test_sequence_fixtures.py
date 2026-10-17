"""Fixture-driven test: runs every hand-labelled trace in
fixtures/role_sequences.jsonl through a fresh SequenceEngine.

RISKY  traces must end in BLOCK.
BENIGN traces must never produce BLOCK.
"""
import json
import os
import unittest

from src.sequence_engine import SequenceEngine

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures",
                       "role_sequences.jsonl")


def load_traces():
    traces = []
    # utf-8-sig tolerates the BOM that Windows PowerShell can add to files.
    with open(FIXTURE, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                traces.append(json.loads(line))
    return traces


def run_trace(roles, session_id):
    engine = SequenceEngine()  # fresh engine so traces never affect each other
    decisions = []
    for role in roles:
        parsed = {"role": role, "parse_status": "OK"}
        decisions.append(engine.evaluate(parsed, session_id)["decision"])
    return decisions


class TestRoleSequenceFixtures(unittest.TestCase):
    def test_fixture_is_not_empty(self):
        self.assertGreater(len(load_traces()), 0)

    def test_labels_are_valid(self):
        for t in load_traces():
            self.assertIn(t["label"], ("RISKY", "BENIGN"), t["session_id"])

    def test_risky_traces_end_in_block(self):
        for t in load_traces():
            if t["label"] != "RISKY":
                continue
            with self.subTest(session=t["session_id"]):
                decisions = run_trace(t["roles"], t["session_id"])
                self.assertEqual(decisions[-1], "BLOCK")

    def test_benign_traces_never_block(self):
        for t in load_traces():
            if t["label"] != "BENIGN":
                continue
            with self.subTest(session=t["session_id"]):
                decisions = run_trace(t["roles"], t["session_id"])
                self.assertNotIn("BLOCK", decisions)

    def test_summary_counts(self):
        """Prints raw counts, which Shivani can reuse for the metrics."""
        tp = fp = tn = fn = 0
        for t in load_traces():
            blocked = "BLOCK" in run_trace(t["roles"], t["session_id"])
            risky = t["label"] == "RISKY"
            if risky and blocked:
                tp += 1
            elif risky:
                fn += 1
            elif blocked:
                fp += 1
            else:
                tn += 1
        print(f"\n[sequence rules on fixture] TP={tp} FP={fp} TN={tn} FN={fn}")
        self.assertEqual((fp, fn), (0, 0))


if __name__ == "__main__":
    unittest.main()