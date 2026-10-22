import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab


class Completed:
    def __init__(self, argv, code, out="", err=""):
        self.args = argv
        self.returncode = code
        self.stdout = out
        self.stderr = err


class ParseTests(unittest.TestCase):
    def test_github_urls(self):
        cases = [
            "https://github.com/exampleowner/sample-repo.git",
            "https://github.com/exampleowner/sample-repo/",
            "https://github.com/exampleowner/sample-repo/tree/main/src",
            "git@github.com:exampleowner/sample-repo.git",
            "ssh://git@github.com/exampleowner/sample-repo.git",
            "https://www.github.com/exampleowner/sample-repo/issues/3",
        ]
        for url in cases:
            self.assertEqual(sab.parse_github(url), ("exampleowner", "sample-repo"), url)
        self.assertIsNone(sab.parse_github("https://github.com/exampleowner"))
        other = sab.parse_target("https://gitlab.com/exampleowner/sample-repo")
        self.assertEqual(other["kind"], "git")
        local = sab.parse_target("/tmp/sample-repo")
        self.assertEqual(local["kind"], "path")

    def test_gh_api_arguments(self):
        argv = sab.gh_api_argv("/usr/bin/gh", "exampleowner", "sample-repo")
        self.assertEqual(argv[1:], ["api", "repos/exampleowner/sample-repo", "--jq", ".permissions"])


class DecisionTests(unittest.TestCase):
    URL = "https://github.com/exampleowner/sample-repo"

    def test_affirmation_required(self):
        decision = sab.decide_authorization(self.URL, affirm=None, gh_logged_in=False)
        self.assertEqual(decision["status"], "needs_affirmation")
        allowed = sab.decide_authorization(self.URL, affirm="this is my code", gh_logged_in=False)
        self.assertEqual(allowed["status"], "authorized")
        also = sab.decide_authorization(self.URL, affirm="I have permission to review it", gh_logged_in=False)
        self.assertEqual(also["status"], "authorized")
        bad = sab.decide_authorization(self.URL, affirm="sure, go ahead", gh_logged_in=False)
        self.assertEqual(bad["status"], "refused")

    def test_logged_in_permissions(self):
        push = {"admin": False, "maintain": False, "push": True, "triage": True, "pull": True}
        none = {"admin": False, "maintain": False, "push": False, "triage": False, "pull": False}
        waiting = sab.decide_authorization(self.URL, affirm=None, gh_logged_in=True, permissions=push)
        self.assertEqual(waiting["status"], "needs_affirmation")
        ok = sab.decide_authorization(self.URL, affirm="this is my code", gh_logged_in=True, permissions=push)
        self.assertEqual(ok["status"], "authorized")
        self.assertTrue(ok["github_permissions"]["push"])
        denied = sab.decide_authorization(self.URL, affirm="this is my code", gh_logged_in=True, permissions=none)
        self.assertEqual(denied["status"], "refused")
        failed = sab.decide_authorization(
            self.URL,
            affirm="this is my code",
            gh_logged_in=True,
            permissions_error="github permissions check failed",
        )
        self.assertEqual(failed["status"], "refused")

    def test_home_directory_is_refused(self):
        decision = sab.decide_authorization(str(Path.home()), affirm="this is my code", path_exists=True)
        self.assertEqual(decision["status"], "refused")

    def test_missing_path_is_refused(self):
        decision = sab.decide_authorization("/no/such/sample-repo", affirm="this is my code", path_exists=False)
        self.assertEqual(decision["status"], "refused")
        decision = sab.decide_authorization("/no/such/sample-repo", affirm="this is my code", path_exists=True)
        self.assertEqual(decision["status"], "authorized")


class CommandTests(unittest.TestCase):
    def test_command_records_metadata_and_calls_gh(self):
        calls = []

        def which_fn(name):
            return "/usr/bin/gh" if name == "gh" else None

        def runner(argv, timeout, cwd=None, env=None):
            calls.append(list(argv))
            if argv[1] == "auth":
                return Completed(argv, 0)
            if argv[1] == "api":
                payload = {"admin": False, "maintain": False, "push": True, "triage": True, "pull": True}
                return Completed(argv, 0, json.dumps(payload))
            return Completed(argv, 1, "", "unexpected")

        with tempfile.TemporaryDirectory() as tmp:
            meta = Path(tmp) / "run-metadata.json"
            meta.write_text(json.dumps({"run_status": "in_progress", "profile": "standard"}), encoding="utf-8")
            code = sab.cmd_check_authorization(
                [
                    "https://github.com/exampleowner/sample-repo.git",
                    "--affirm",
                    "this is my code",
                    "--metadata",
                    str(meta),
                ],
                which_fn=which_fn,
                runner=runner,
            )
            self.assertEqual(code, 0)
            self.assertEqual(calls[1][1:], ["api", "repos/exampleowner/sample-repo", "--jq", ".permissions"])
            saved = json.loads(meta.read_text(encoding="utf-8"))
            self.assertEqual(saved["run_status"], "in_progress")
            self.assertEqual(saved["profile"], "standard")
            self.assertTrue(saved["authorized"])
            self.assertEqual(saved["statement"], "this is my code")
            self.assertEqual(saved["owner"], "exampleowner")
            self.assertEqual(saved["repo"], "sample-repo")
            self.assertTrue(saved["github_permissions"]["push"])

    def test_command_does_not_write_metadata_when_refused_or_waiting(self):
        def which_fn(name):
            return None

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            waiting = Path(tmp) / "waiting.json"
            folder = Path(tmp) / "sample-repo"
            folder.mkdir()
            refused = sab.cmd_check_authorization(
                ["/no/such/sample-repo", "--affirm", "this is my code", "--metadata", str(missing)],
                which_fn=which_fn,
            )
            self.assertEqual(refused, 1)
            self.assertFalse(missing.exists())
            needs = sab.cmd_check_authorization(
                [str(folder), "--metadata", str(waiting)],
                which_fn=which_fn,
            )
            self.assertEqual(needs, 2)
            self.assertFalse(waiting.exists())

    def test_logged_out_affirmation_skips_api(self):
        calls = []

        def which_fn(name):
            return "/usr/bin/gh" if name == "gh" else None

        def runner(argv, timeout, cwd=None, env=None):
            calls.append(list(argv))
            return Completed(argv, 1, "", "not logged in")

        with tempfile.TemporaryDirectory() as tmp:
            meta = Path(tmp) / "run-metadata.json"
            code = sab.cmd_check_authorization(
                [
                    "git@github.com:exampleowner/sample-repo.git",
                    "--affirm",
                    "I have permission",
                    "--metadata",
                    str(meta),
                ],
                which_fn=which_fn,
                runner=runner,
            )
            self.assertEqual(code, 0)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1], "auth")
            saved = json.loads(meta.read_text(encoding="utf-8"))
            self.assertIsNone(saved["github_permissions"])
            self.assertEqual(saved["statement"], "I have permission")


if __name__ == "__main__":
    unittest.main()
