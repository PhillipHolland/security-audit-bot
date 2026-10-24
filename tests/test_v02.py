import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab

FAKE_KEY = "AKIAFAKEFAKEFAKEFAKE"


def done(argv, code=0, out="", err=""):
    return subprocess.CompletedProcess(argv, code, out, err)


OSV_DOC = {
    "results": [{
        "source": {"path": "/repo/package-lock.json"},
        "packages": [{
            "package": {"name": "demo-lib", "version": "1.0.0"},
            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2099-0001"], "summary": "demo flaw",
                                 "database_specific": {"severity": "MODERATE"}}],
            "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"]}],
        }],
    }]
}
TRIVY_DOC = {
    "Results": [{
        "Target": "package-lock.json",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "demo-lib", "InstalledVersion": "1.0.0",
                             "Severity": "HIGH", "Title": "demo flaw"}],
        "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": 4, "Title": "AWS key",
                     "Match": f"key = {FAKE_KEY}"}],
    }, {"Target": "config.py", "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": 4,
                                             "Title": "AWS key", "Match": f"key = {FAKE_KEY}"}]}]
}
GITLEAKS_DOC = [{"RuleID": "aws-access-key", "File": "/repo/config.py", "StartLine": 4, "Secret": FAKE_KEY,
                 "Match": f"key = {FAKE_KEY}", "Description": "AWS key"}]
SEMGREP_DOC = {"results": [{"check_id": "python.lang.security.audit.eval", "path": "/repo/app.py",
                            "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "eval of input"}}]}


def fake_tools(semgrep=SEMGREP_DOC, trivy=TRIVY_DOC):
    def which_fn(name):
        return f"/fake/{name}" if name in {"semgrep", "gitleaks", "osv-scanner", "trivy"} else None

    def runner(argv, timeout, cwd=None, env=None):
        tool = Path(argv[0]).name
        if tool == "gitleaks":
            Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(GITLEAKS_DOC), encoding="utf-8")
            return done(argv, 0)
        if tool == "semgrep":
            return done(argv, 0, json.dumps(semgrep))
        if tool == "osv-scanner":
            return done(argv, 0, json.dumps(OSV_DOC))
        if tool == "trivy":
            return done(argv, 0, json.dumps(trivy))
        return done(argv, 127, "", "no")
    return which_fn, runner


class PreflightV02Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "sample-repo"
        self.root.mkdir()
        (self.root / "package-lock.json").write_text("{}\n", encoding="utf-8")
        (self.root / "app.py").write_text("x = 1\n" * 10, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def run_pf(self, out, **kw):
        which_fn, runner = fake_tools(**{k: kw.pop(k) for k in ("semgrep", "trivy") if k in kw})
        return sab.run_preflight(self.root, self.base / out, which_fn=which_fn, runner=runner,
                                 cache_dir=self.base / "cache", **kw)

    def test_cross_scanner_merge_and_redaction(self):
        doc = self.run_pf("out")
        deps = [lead for lead in doc["leads"] if lead["kind"] == "dep"]
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["tool"], "osv-scanner")
        self.assertEqual(deps[0]["also_reported_by"], ["trivy"])
        self.assertEqual(deps[0]["severity"], "high")  # highest of the two
        secrets = [lead for lead in doc["leads"] if lead["kind"] == "secret" and lead["file"] == "config.py"]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]["tool"], "gitleaks")
        self.assertEqual(secrets[0]["also_reported_by"], ["trivy"])
        self.assertEqual(secrets[0]["severity"], "critical")
        blob = (self.base / "out" / "scanner-leads.json").read_text() + (self.base / "out" / "preflight-summary.md").read_text()
        self.assertNotIn(FAKE_KEY, blob)
        self.assertNotIn("_meta", blob)
        self.assertNotIn(str(self.base), blob)
        self.assertFalse((self.base / "out" / ".tool-home").exists())
        self.assertIn("size", doc)
        self.assertEqual(doc["size"]["class"], "small")
        self.assertTrue(all("seconds" in row for row in doc["tools"]))

    def test_baseline_accept_hides_lead_and_reports_stale(self):
        first = self.run_pf("run1")
        lead = next(lead for lead in first["leads"] if lead["tool"] == "semgrep")
        baseline = self.base / "baseline.json"
        entry = sab.accept_lead(self.base / "run1" / "scanner-leads.json", lead["fingerprint"][7:19],
                                "test helper, not shipped", baseline)
        self.assertEqual(entry["rule"], lead["rule"])
        with self.assertRaises(ValueError):
            sab.accept_lead(self.base / "run1" / "scanner-leads.json", lead["fingerprint"], "", baseline)
        # Line moved: still accepted, because code leads match per rule and file.
        moved = json.loads(json.dumps(SEMGREP_DOC))
        moved["results"][0]["start"]["line"] = 9
        second = self.run_pf("run2", baseline_path=baseline, semgrep=moved)
        self.assertFalse(any(item["tool"] == "semgrep" for item in second["leads"]))
        self.assertEqual(len(second["suppressed"]), 1)
        self.assertEqual(second["suppressed"][0]["accepted_reason"], "test helper, not shipped")
        third = self.run_pf("run3", baseline_path=baseline, semgrep={"results": []})
        self.assertEqual(len(third["baseline_stale"]), 1)

    def test_secret_baseline_does_not_hide_a_new_secret_line(self):
        first = self.run_pf("run1")
        lead = next(lead for lead in first["leads"] if lead["kind"] == "secret" and lead["file"] == "config.py")
        baseline = self.base / "baseline.json"
        sab.accept_lead(self.base / "run1" / "scanner-leads.json", lead["fingerprint"], "fake key in fixture", baseline)
        moved = json.loads(json.dumps(GITLEAKS_DOC))
        moved[0]["StartLine"] = 20
        with mock.patch.object(sys.modules[__name__], "GITLEAKS_DOC", moved):
            second = self.run_pf("run2", baseline_path=baseline, trivy={"Results": []})
        self.assertTrue(any(item["kind"] == "secret" and item["line"] == 20 for item in second["leads"]))

    def test_previous_run_marks_new_and_gone(self):
        self.run_pf("run1")
        changed = {"results": [{"check_id": "python.lang.security.audit.exec", "path": "/repo/app.py",
                                "start": {"line": 5}, "extra": {"severity": "ERROR", "message": "exec of input"}}]}
        second = self.run_pf("run2", previous_path=self.base / "run1" / "scanner-leads.json", semgrep=changed)
        by_rule = {lead["rule"]: lead for lead in second["leads"]}
        self.assertEqual(by_rule["python.lang.security.audit.exec"]["change"], "new")
        self.assertEqual(by_rule["GHSA-aaaa-bbbb-cccc"]["change"], "unchanged")
        self.assertEqual([lead["rule"] for lead in second["resolved"]], ["python.lang.security.audit.eval"])
        summary = (self.base / "run2" / "preflight-summary.md").read_text()
        self.assertIn("1 new", summary)
        self.assertIn("not proof of a fix", summary)

    def test_gone_lead_from_a_skipped_tool_is_not_resolved(self):
        self.run_pf("run1")
        which_fn, runner = fake_tools()
        only = lambda name: which_fn(name) if name != "semgrep" else None  # semgrep missing now
        doc = sab.run_preflight(self.root, self.base / "run2", which_fn=only, runner=runner,
                                cache_dir=self.base / "cache", previous_path=self.base / "run1" / "scanner-leads.json")
        self.assertEqual(doc["resolved"], [])
        self.assertEqual([lead["tool"] for lead in doc["not_rechecked"]], ["semgrep"])
        summary = (self.base / "run2" / "preflight-summary.md").read_text()
        self.assertIn("Not covered this run", summary)


class NotesAndSetupTests(unittest.TestCase):
    def test_osv_no_sources_is_a_skip_without_paths(self):
        def runner(argv, timeout, cwd=None, env=None):
            return done(argv, 128, "", f"Scanning dir {cwd}\nNo package sources found, --help for usage information.")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "r"
            root.mkdir()
            leads, note = sab.execute_scanner("osv-scanner", root, runner, lambda n: "/fake/osv-scanner", {"PATH": "/usr/bin"})
        self.assertEqual(leads, [])
        self.assertTrue(note.startswith("no "))
        self.assertNotIn(tmp, note)

    def test_scrub_paths(self):
        text = sab.scrub_paths(f"failed at {Path.home()}/x and /home/someone/y and /tmp/abc/z", root=None)
        self.assertNotIn(str(Path.home()), text)
        self.assertNotIn("/home/someone", text)
        self.assertNotIn("/tmp/abc", text)

    def test_trivy_uses_shared_cache(self):
        seen = []

        def runner(argv, timeout, cwd=None, env=None):
            seen.append(argv)
            return done(argv, 0, json.dumps({"Results": []}))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "r"
            root.mkdir()
            env = sab.scanner_env(Path(tmp) / "home", cache=Path(tmp) / "shared")
            sab.execute_scanner("trivy", root, runner, lambda n: "/fake/trivy", env)
        self.assertIn("--cache-dir", seen[0])
        self.assertEqual(seen[0][seen[0].index("--cache-dir") + 1], str(Path(tmp) / "shared" / "trivy"))

    def test_pep668_falls_back_to_private_venv(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            installed = {"ok": False}

            def runner(argv, timeout, cwd=None, env=None):
                calls.append(argv)
                if "--user" in argv:
                    return done(argv, 1, "", "error: externally-managed-environment")
                if argv[1:3] == ["-m", "venv"]:
                    Path(argv[3], "bin").mkdir(parents=True)
                    Path(argv[3], "bin", "python").write_text("")
                    return done(argv, 0)
                Path(argv[0]).parent.joinpath("zizmor").write_text("")
                installed["ok"] = True
                return done(argv, 0)

            with mock.patch.object(sab, "data_dir", return_value=Path(tmp) / "data"), \
                    mock.patch.object(sab, "bindir", return_value=Path(tmp) / "bin"):
                which_fn = lambda name: str(Path(tmp, "bin", name)) if installed["ok"] else None
                status, note = sab.install_python_tool("zizmor", "zizmor", runner, which_fn)
                self.assertEqual(status, "ok")
                self.assertIn("venv", note)
                self.assertTrue(Path(tmp, "bin", "zizmor").is_symlink())

    def test_damaged_skill_clone_is_moved_aside(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            skill = data / "skill"
            (skill / ".git").mkdir(parents=True)
            (skill / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {sab.SKILL_REPO}\n')
            (skill / "README.md").write_text("copy")

            def runner(argv, timeout, cwd=None, env=None):
                if "rev-parse" in argv and "--absolute-git-dir" in argv:
                    return done(argv, 128, "", "fatal: not a git repository")
                return done(argv, 1, "", "fatal: offline in test")

            with mock.patch.object(sab, "data_dir", return_value=data):
                status, note = sab.install_skill(runner)
            self.assertEqual(status, "skipped")  # fetch fails offline, but the copy was preserved
            self.assertEqual(len(list(data.glob("skill.damaged-*"))), 1)


class ReportLintV02Tests(unittest.TestCase):
    def test_lints_needs_validation_and_local_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "REPORT.md").write_text("# Report\nNo findings.\n")
            (root / "NEEDS-VALIDATION.md").write_text(f"key {FAKE_KEY}\nsee /home/alice/project/app.py\n")
            problems = sab.lint_reports(root)
            self.assertTrue(any("NEEDS-VALIDATION.md:1" in item for item in problems))
            self.assertTrue(any("local filesystem path" in item for item in problems))
            (root / "NEEDS-VALIDATION.md").write_text("see app.py:3\n")
            self.assertEqual(sab.lint_reports(root), [])


if __name__ == "__main__":
    unittest.main()
