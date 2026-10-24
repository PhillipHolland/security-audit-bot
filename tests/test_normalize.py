import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab

FIX = Path(__file__).resolve().parent / "fixtures"
FAKE_KEY = "AKIAFAKEFAKEFAKEFAKE"


class NormalizeDedupeTests(unittest.TestCase):
    def load(self, name):
        return json.loads((FIX / name).read_text(encoding="utf-8"))

    def test_semgrep_dedupes_and_keeps_higher_severity(self):
        leads = sab.dedupe_leads(sab.normalize_semgrep(self.load("semgrep.json"), Path("/repo")))
        self.assertEqual(len(leads), 2)
        exec_lead = next(lead for lead in leads if lead["rule"].endswith("exec-detected"))
        self.assertEqual(exec_lead["severity"], "high")
        self.assertEqual(exec_lead["file"], "app.py")
        self.assertEqual(exec_lead["line"], 12)
        shell = next(lead for lead in leads if "shell" in lead["rule"])
        self.assertEqual(shell["file"], "app.py")
        self.assertEqual(shell["severity"], "medium")
        for lead in leads:
            self.assertEqual(set(sab.public_lead(lead)), set(sab.LEAD_KEYS))

    def test_gitleaks_redacts_and_dedupes(self):
        leads = sab.dedupe_leads(sab.normalize_gitleaks(self.load("gitleaks.json"), Path("/repo")))
        self.assertEqual(len(leads), 1)
        lead = leads[0]
        blob = json.dumps(lead)
        self.assertNotIn(FAKE_KEY, blob)
        self.assertNotIn("aws_key", blob)
        self.assertEqual(lead["tool"], "gitleaks")
        self.assertEqual(lead["rule"], "aws-access-key")
        self.assertEqual(lead["file"], "config.py")
        self.assertEqual(lead["line"], 4)
        self.assertIn("[redacted]", lead["message"])
        self.assertTrue(lead["fingerprint"].startswith("sha256:"))
        again = sab.normalize_gitleaks(self.load("gitleaks.json"), Path("/repo"))[0]
        self.assertEqual(lead["fingerprint"], again["fingerprint"])

    def test_osv_relativizes_and_dedupes(self):
        raw = sab.normalize_osv(self.load("osv.json"), Path("/repo"))
        self.assertEqual(len(raw), 3)
        leads = sab.dedupe_leads(raw)
        self.assertEqual(len(leads), 2)
        primary = next(lead for lead in leads if lead["rule"] == "GHSA-fake-0001")
        self.assertEqual(primary["severity"], "high")
        self.assertEqual(primary["file"], "requirements.txt")
        self.assertEqual(primary["line"], 1)
        self.assertIn("left-pad-demo@1.0.0", primary["message"])
        other = next(lead for lead in leads if lead["rule"] == "GHSA-fake-0002")
        self.assertEqual(other["severity"], "low")
        self.assertNotIn("/repo", json.dumps(leads))

    def test_cap_keeps_highest_severity(self):
        leads = []
        for index in range(5):
            leads.append(sab.make_lead("semgrep", f"c{index}", "critical", "a.py", index + 1, "critical demo", sab.fingerprint_for("c", index)))
        for index in range(120):
            leads.append(sab.make_lead("semgrep", f"h{index}", "high", "b.py", index + 1, "high demo", sab.fingerprint_for("h", index)))
        kept, truncated = sab.cap_leads(leads, cap=100)
        self.assertEqual(len(kept), 100)
        self.assertEqual(truncated["semgrep"], 25)
        self.assertEqual(sum(1 for lead in kept if lead["severity"] == "critical"), 5)

    def test_other_scanners(self):
        trivy = sab.normalize_trivy(
            {
                "Results": [
                    {
                        "Target": "config.py",
                        "Secrets": [
                            {
                                "RuleID": "aws-access-key",
                                "StartLine": 3,
                                "Title": f"AWS key {FAKE_KEY}",
                                "Match": FAKE_KEY,
                            }
                        ],
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-0000-0000",
                                "PkgName": "demo-lib",
                                "InstalledVersion": "0.0.1",
                                "Severity": "HIGH",
                                "Title": "demo vuln",
                            }
                        ],
                    }
                ]
            },
            Path("/repo"),
        )
        self.assertEqual(len(trivy), 2)
        self.assertNotIn(FAKE_KEY, json.dumps(trivy))
        secret = next(lead for lead in trivy if lead["rule"] == "aws-access-key")
        self.assertEqual(secret["line"], 3)
        self.assertIn("[redacted]", secret["message"])

        zizmor = sab.normalize_zizmor(
            [
                {
                    "ident": "template-injection",
                    "desc": "code injection via template expansion",
                    "determinations": {"severity": "High"},
                    "locations": [
                        {
                            "symbolic": {"key": {"Local": {"verbatim_path": "./.github/workflows/ci.yml"}}},
                            "concrete": {"location": {"start_point": {"row": 6, "column": 1}}},
                        }
                    ],
                }
            ],
            Path("/repo"),
        )
        self.assertEqual(zizmor[0]["file"], ".github/workflows/ci.yml")
        self.assertEqual(zizmor[0]["line"], 7)
        self.assertEqual(zizmor[0]["severity"], "high")

        bandit = sab.normalize_bandit(
            {
                "results": [
                    {
                        "filename": "app.py",
                        "line_number": 8,
                        "issue_severity": "HIGH",
                        "issue_text": "use of exec",
                        "test_id": "B102",
                        "test_name": "exec_used",
                    }
                ]
            },
            Path("/repo"),
        )
        self.assertEqual(bandit[0]["rule"], "B102")
        self.assertEqual(bandit[0]["line"], 8)

        npm = sab.normalize_npm_audit(
            {
                "vulnerabilities": {
                    "left-pad-demo": {
                        "severity": "moderate",
                        "via": [{"title": "demo advisory", "source": 1000}],
                    }
                }
            },
            Path("/repo"),
            Path("/repo/package-lock.json"),
        )
        self.assertEqual(npm[0]["file"], "package-lock.json")
        self.assertEqual(npm[0]["severity"], "medium")
        self.assertIn("demo advisory", npm[0]["message"])

        pip = sab.normalize_pip_audit(
            {"dependencies": [{"name": "demo-lib", "version": "0.0.1", "vulns": [{"id": "PYSEC-0000", "description": "demo"}]}]},
            Path("/repo"),
            Path("/repo/requirements.txt"),
        )
        self.assertEqual(pip[0]["rule"], "PYSEC-0000")
        self.assertEqual(pip[0]["file"], "requirements.txt")

        checkov = sab.normalize_checkov(
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_FAKE_1",
                            "check_name": "demo bucket is public",
                            "file_path": "/repo/main.tf",
                            "file_line_range": [10, 14],
                            "severity": "HIGH",
                            "resource": "aws_s3_bucket.demo",
                        }
                    ]
                }
            },
            Path("/repo"),
        )
        self.assertEqual(checkov[0]["file"], "main.tf")
        self.assertEqual(checkov[0]["line"], 10)
        self.assertEqual(checkov[0]["severity"], "high")


class PreflightMockTests(unittest.TestCase):
    def test_preflight_uses_runner_and_writes_redacted_leads(self):
        semgrep = (FIX / "semgrep.json").read_text(encoding="utf-8")
        gitleaks = (FIX / "gitleaks.json").read_text(encoding="utf-8")
        osv = (FIX / "osv.json").read_text(encoding="utf-8")
        calls = []

        def which_fn(name):
            if name in {"semgrep", "gitleaks", "osv-scanner"}:
                return f"/fake/{name}"
            return None

        def runner(argv, timeout, cwd=None, env=None):
            calls.append(list(argv))
            self.assertIsNotNone(env)
            self.assertNotEqual(Path(env["HOME"]).resolve(), Path.home().resolve())
            self.assertTrue(str(env["HOME"]).startswith(tmp))
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertFalse(any(str(arg).startswith("http://") or str(arg).startswith("https://") for arg in argv))
            tool = Path(argv[0]).name
            if tool == "gitleaks":
                report = Path(argv[argv.index("--report-path") + 1])
                report.write_text(gitleaks, encoding="utf-8")
                return sab.subprocess.CompletedProcess(argv, 1, "", "")
            if tool == "semgrep":
                return sab.subprocess.CompletedProcess(argv, 1, semgrep, "")
            if tool == "osv-scanner":
                return sab.subprocess.CompletedProcess(argv, 0, osv, "")
            return sab.subprocess.CompletedProcess(argv, 127, "", "not used")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sample-repo"
            root.mkdir()
            (root / "requirements.txt").write_text("left-pad-demo==1.0.0\n", encoding="utf-8")
            (root / "app.py").write_text("print('demo')\n", encoding="utf-8")
            out = Path(tmp) / "out"
            document = sab.run_preflight(root, out, which_fn=which_fn, runner=runner)
            blob = (out / "scanner-leads.json").read_text(encoding="utf-8")
            blob += (out / "preflight-summary.md").read_text(encoding="utf-8")
            self.assertNotIn(FAKE_KEY, blob)
            self.assertNotIn(str(root), blob)
            self.assertTrue(any(call for call in calls if call[0].endswith("semgrep")))
            self.assertIn("python-deps", document["ecosystems"])
            tools = {row["tool"]: row for row in document["tools"]}
            self.assertEqual(tools["trivy"]["status"], "skipped")
            self.assertIn("not installed", tools["trivy"]["note"])
            self.assertEqual(tools["semgrep"]["status"], "ok")
            self.assertGreaterEqual(document["leads"] and len(document["leads"]), 1)
            gitleak = next(lead for lead in document["leads"] if lead["tool"] == "gitleaks")
            self.assertNotIn(FAKE_KEY, json.dumps(gitleak))

    def test_gitleaks_with_no_report_is_clean(self):
        def which_fn(name):
            return "/fake/gitleaks" if name == "gitleaks" else None

        def runner(argv, timeout, cwd=None, env=None):
            return sab.subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sample-repo"
            root.mkdir()
            leads, note = sab.execute_scanner("gitleaks", root, runner, which_fn, env={"PATH": "/usr/bin", "HOME": tmp})
            self.assertEqual(leads, [])
            self.assertEqual(note, "")


if __name__ == "__main__":
    unittest.main()
