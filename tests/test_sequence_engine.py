import unittest

import src.sequence_engine as se
from src.sequence_engine import SequenceEngine, HISTORY_LEN, MAX_NOISE


def ev(role, status="OK"):
    """Build a minimal parsed event with a role label."""
    return {"role": role, "parse_status": status}


def run(roles, session_id="s-x"):
    """Feed roles to a fresh engine; return the list of decision dicts."""
    engine = SequenceEngine()
    return [engine.evaluate(ev(r), session_id) for r in roles]


SR, ST, OT, OTHER = "SENSITIVE_READ", "STAGE_DATA", "OUTBOUND_TRANSFER", "OTHER"


class TestSequenceEngine(unittest.TestCase):
    def setUp(self):
        se.reset_session()  # clear the module-level engine between tests

    def test_positive_trace_blocks(self):
        d = run([SR, ST, OT])
        self.assertEqual(d[0]["decision"], "ALLOW")
        self.assertEqual(d[1]["decision"], "ALLOW")
        self.assertEqual(d[1]["reason_code"], "SEQUENCE_PARTIAL")
        self.assertEqual(d[2]["decision"], "BLOCK")
        self.assertEqual(d[2]["reason_code"], "SEQUENCE_EXFIL_PATTERN")

    def test_benign_trace_allows(self):
        d = run([OTHER, OTHER, OTHER])
        for item in d:
            self.assertEqual(item["decision"], "ALLOW")
            self.assertEqual(item["reason_code"], "SEQUENCE_CLEAR")

    def test_noise_tolerated(self):
        d = run([SR, OTHER, ST, OTHER, OT])
        self.assertEqual(d[-1]["decision"], "BLOCK")

    def test_too_much_noise_resets(self):
        d = run([SR] + [OTHER] * (MAX_NOISE + 1) + [ST, OT])
        self.assertEqual(d[-1]["decision"], "ALLOW")

    def test_reordered_not_blocked(self):
        d = run([OT, ST, SR])
        for item in d:
            self.assertNotEqual(item["decision"], "BLOCK")

    def test_missing_middle_step_not_blocked(self):
        d = run([SR, OT])
        self.assertEqual(d[-1]["decision"], "ALLOW")
        d = run([SR, OTHER, OT])
        self.assertEqual(d[-1]["decision"], "ALLOW")

    def test_repeated_events(self):
        # Repeating the first step does not stop the pattern from completing.
        d = run([SR, SR, SR, ST, OT])
        self.assertEqual(d[-1]["decision"], "BLOCK")

    def test_session_isolation(self):
        engine = SequenceEngine()
        engine.evaluate(ev(SR), "a")
        engine.evaluate(ev(ST), "a")
        d = engine.evaluate(ev(OT), "b")  # different session: no history
        self.assertEqual(d["decision"], "ALLOW")
        d = engine.evaluate(ev(OT), "a")  # original session completes
        self.assertEqual(d["decision"], "BLOCK")

    def test_reset_clears_state(self):
        engine = SequenceEngine()
        engine.evaluate(ev(SR), "s")
        engine.evaluate(ev(ST), "s")
        engine.reset_session("s")
        self.assertEqual(engine.get_history("s"), [])
        d = engine.evaluate(ev(OT), "s")
        self.assertEqual(d["decision"], "ALLOW")

    def test_history_is_bounded(self):
        engine = SequenceEngine()
        for _ in range(HISTORY_LEN * 3):
            engine.evaluate(ev(OTHER), "s")
        self.assertEqual(len(engine.get_history("s")), HISTORY_LEN)

    def test_bad_parse_status_skipped(self):
        engine = SequenceEngine()
        d = engine.evaluate(ev(SR, status="AMBIGUOUS"), "s")
        self.assertEqual(d["decision"], "ALLOW")
        self.assertEqual(d["reason_code"], "SEQUENCE_SKIPPED")
        self.assertEqual(engine.get_history("s"), [])  # not added to state

    def test_module_level_interface(self):
        d = se.evaluate_sequence(ev(OTHER), "x")
        for key in ("decision", "reason_code", "reason", "session_id"):
            self.assertIn(key, d)
        self.assertEqual(d["decision"], "ALLOW")
        self.assertEqual(d["session_id"], "x")
        se.evaluate_sequence(ev(SR), "x")
        se.evaluate_sequence(ev(ST), "x")
        d = se.evaluate_sequence(ev(OT), "x")
        self.assertEqual(d["decision"], "BLOCK")
        se.reset_session("x")
        d = se.evaluate_sequence(ev(OT), "x")
        self.assertEqual(d["decision"], "ALLOW")


class TestSequenceBehaviors(unittest.TestCase):
    """Documents known behavior, including limitations. See docs/LIMITATIONS.md."""

   
    def test_repeated_staging(self):
    # Repeating the staging step no longer restarts the match.
     d = run([SR, ST, ST, OT])
     self.assertEqual(d[-1]["decision"], "BLOCK")


    
    def test_block_repeats_after_match(self):
    # After a match, history is cleared, so the next event is allowed.
     d = run([SR, ST, OT, OTHER])
     self.assertEqual(d[2]["decision"], "BLOCK")
     self.assertEqual(d[3]["decision"], "ALLOW")


    def test_third_other_resets_progress(self):
        # MAX_NOISE is 2: two OTHERs are tolerated, the third resets.
        two = run([SR, OTHER, OTHER, ST, OT])
        three = run([SR, OTHER, OTHER, OTHER, ST, OT])
        self.assertEqual(two[-1]["decision"], "BLOCK")
        self.assertEqual(three[-1]["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()