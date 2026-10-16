"""Contract check: each real module must expose the agreed function names.

A module that does not exist yet is skipped. A module that exists but is
missing a function (or names it differently) fails, so mismatches show up
the moment a teammate's branch is merged.
"""
import importlib
import unittest


def check(testcase, module_name, names):
    try:
        mod = importlib.import_module(module_name)
    except ModuleNotFoundError as e:
        if e.name == module_name:
            testcase.skipTest(f"{module_name} not merged yet")
        raise
    for n in names:
        testcase.assertTrue(callable(getattr(mod, n, None)),
                            f"{module_name} is missing {n}()")


class TestContract(unittest.TestCase):
    def test_parser_policy(self):
        check(self, "src.parser_policy", ["parse_command", "evaluate_baseline"])

    def test_sequence_engine(self):
        check(self, "src.sequence_engine", ["evaluate_sequence", "reset_session"])

    def test_ml_detector(self):
        check(self, "src.ml_detector", ["predict_anomaly"])

    def test_audit_eval(self):
        check(self, "src.audit_eval", ["append_event", "verify_log", "evaluate_corpus"])


if __name__ == "__main__":
    unittest.main()
