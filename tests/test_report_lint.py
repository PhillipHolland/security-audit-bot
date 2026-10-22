import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab

FAKE_KEY = "AKIAFAKEFAKEFAKEFAKE"
ENTROPY = "k8s9QmZ3pL2vN7xR4tY6wA1cE5bH0d"


class ReportLintTests(unittest.TestCase):
    def write_report(self, root, body, detail=None, leads=None):
        (root / "REPORT.md").write_text(body, encoding="utf-8")
        if detail is not None:
            (root / "FINDINGS-DETAIL.md").write_text(detail, encoding="utf-8")
        if leads is not None:
            (root / "scanner-leads.json").write_text(json.dumps({"leads": leads}), encoding="utf-8")

    def test_clean_report_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fingerprint = "sha256:" + ("ab" * 32)
            body = "\n".join(
                [
                    "# Report",
                    "",
                    "No confirmed findings.",
                    "",
                    f"Source ref {('0123456789abcdef' * 2) + '01234567'}",
                    f"Lead fingerprint {fingerprint}",
                    "The smallest fix is to check the owner of the record.",
                    "",
                ]
            )
            self.write_report(root, body, "# Detail\n\nNone.\n")
            self.assertEqual(sab.lint_reports(root), [])
            self.assertEqual(sab.cmd_report_lint([str(root)]), 0)

    def test_secret_pattern_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_report(root, f"# Report\n\nKey {FAKE_KEY} was copied.\n")
            problems = sab.lint_reports(root)
            self.assertTrue(problems)
            self.assertIn("secret pattern", problems[0])

    def test_high_entropy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_report(root, f"# Report\n\nvalue {ENTROPY}\n", "# Detail\n\nClean.\n")
            problems = sab.lint_reports(root)
            self.assertTrue(any("high-entropy" in item for item in problems))

    def test_raw_secret_from_leads_fails_only_when_repeated(self):
        lead = {
            "tool": "gitleaks",
            "rule": "aws-access-key",
            "severity": "high",
            "file": "config.py",
            "line": 4,
            "message": f"found {FAKE_KEY}",
            "fingerprint": "sha256:" + ("cd" * 32),
        }
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "clean"
            dirty = Path(tmp) / "dirty"
            clean.mkdir()
            dirty.mkdir()
            self.write_report(clean, "# Report\n\nNo secrets here.\n", leads=[lead])
            self.assertEqual(sab.lint_reports(clean), [])
            self.write_report(
                dirty,
                "# Report\n\nConfirmed.\n",
                f"# Detail\n\nThe note repeats {FAKE_KEY}.\n",
                leads=[lead],
            )
            problems = sab.lint_reports(dirty)
            self.assertTrue(any("raw secret from leads" in item for item in problems))
            self.assertEqual(sab.cmd_report_lint([str(dirty)]), 1)
            nested = Path(tmp) / "nested"
            (nested / "preflight").mkdir(parents=True)
            (nested / "REPORT.md").write_text(f"# Report\n\n{FAKE_KEY}\n", encoding="utf-8")
            (nested / "preflight" / "scanner-leads.json").write_text(
                json.dumps({"leads": [lead]}),
                encoding="utf-8",
            )
            nested_problems = sab.lint_reports(nested)
            self.assertTrue(any("raw secret from leads" in item for item in nested_problems))

    def test_private_key_block_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_report(root, "# Report\n\n-----BEGIN RSA PRIVATE KEY-----\nFAKE\n")
            self.assertTrue(sab.lint_reports(root))

    def test_missing_reports_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(sab.lint_reports(tmp))


if __name__ == "__main__":
    unittest.main()
