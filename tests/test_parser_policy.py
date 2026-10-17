import ast
import pathlib
import unittest

from src.parser_policy import parse_command, evaluate_baseline

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src"
BANNED_MODULES = {"subprocess"}
BANNED_CALLS = {"eval", "exec"}


class TestParser(unittest.TestCase):
    def test_roles(self):
        cases = [
            ("cat /home/demo/passwords.txt", "SENSITIVE_READ"),
            ("cat notes.txt", "OTHER"),
            ("tar -czf out.tgz demo.dat", "STAGE_DATA"),
            ("scp out.tgz user@host:/tmp", "OUTBOUND_TRANSFER"),
            ("ls -l", "OTHER"),
            ("cp demo.dat /tmp/copy.dat", "STAGE_DATA"),
            ("wget http://example.com/x", "OUTBOUND_TRANSFER"),
            ("cat /home/demo/.ssh/config", "SENSITIVE_READ"),
            # new: path-qualified binary is reduced to its basename
            ("/bin/cat /etc/passwd", "SENSITIVE_READ"),
        ]
        for raw, role in cases:
            with self.subTest(raw=raw):
                p = parse_command(raw)
                self.assertEqual(p["parse_status"], "OK")
                self.assertEqual(p["role"], role)

    def test_fields(self):
        p = parse_command("tar -czf out.tgz demo.dat")
        self.assertEqual(p["binary"], "tar")
        self.assertEqual(p["args"], ["-czf", "out.tgz", "demo.dat"])

    def test_unsupported_syntax(self):
        for raw in ["ls | grep x", "a && b", "echo $(whoami)", "cat x > y",
                    "echo 'unclosed", "", "   ",
                    # new: grouping, env prefix and wrappers hide the real command
                    "(cat /etc/passwd)",
                    "FOO=1 cat /etc/passwd",
                    "sudo cat /etc/passwd",
                    "bash -c 'cat /etc/passwd'"]:
            with self.subTest(raw=raw):
                self.assertNotEqual(parse_command(raw)["parse_status"], "OK")

    def test_edge_cases(self):
        p = parse_command("  ls   -l  ")
        self.assertEqual(p["parse_status"], "OK")
        self.assertEqual(p["args"], ["-l"])

        p = parse_command('cat "my passwords.txt"')
        self.assertEqual(p["role"], "SENSITIVE_READ")

        p = parse_command("ls\t-l")
        self.assertEqual(p["parse_status"], "OK")

        # uppercase binary is not matched (case-sensitive, like Linux)
        p = parse_command("CAT /etc/passwd")
        self.assertEqual(p["role"], "OTHER")


class TestBaseline(unittest.TestCase):
    def test_decisions(self):
        cases = [
            ("ls -l", "ALLOW"),
            ("rm -rf /", "BLOCK"),
            ("ls | wc", "REVIEW"),
            ("", "REVIEW"),
            # new: separate and reordered flags are still destructive
            ("rm -r -f /", "BLOCK"),
            ("rm -fr /", "BLOCK"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                d = evaluate_baseline(parse_command(raw), "s-01")
                self.assertEqual(d["decision"], expected)
                self.assertEqual(d["session_id"], "s-01")

    def test_decision_has_gateway_keys(self):
        d = evaluate_baseline(parse_command("rm -rf /"), "s-01")
        for key in ("decision", "reason_code", "reason", "matched_policy", "role", "session_id"):
            self.assertIn(key, d)
        self.assertEqual(d["reason_code"], "BASELINE_DESTRUCTIVE")


class TestInertSource(unittest.TestCase):
    """No file in src/ may import subprocess or call eval, exec or .system()."""

    def test_src_files_found(self):
        self.assertTrue(SRC_DIR.is_dir(), f"missing {SRC_DIR}")
        self.assertTrue(list(SRC_DIR.glob("*.py")), "no source files found")

    def test_no_dangerous_imports_or_calls(self):
        for path in SRC_DIR.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(
                            alias.name.split(".")[0], BANNED_MODULES,
                            f"{path.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(
                        node.module.split(".")[0], BANNED_MODULES,
                        f"{path.name} imports from {node.module}")
                elif isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        self.assertNotIn(
                            func.id, BANNED_CALLS,
                            f"{path.name} calls {func.id}()")
                    elif isinstance(func, ast.Attribute):
                        self.assertNotEqual(
                            func.attr, "system",
                            f"{path.name} calls .system()")


if __name__ == "__main__":
    unittest.main()