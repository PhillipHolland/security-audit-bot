import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab


class EcosystemTests(unittest.TestCase):
    def test_detects_markers_and_selects_scanners(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('demo')\n", encoding="utf-8")
            (root / "requirements.txt").write_text("demo-lib==0.0.1\n", encoding="utf-8")
            (root / "package.json").write_text('{"name":"demo","version":"0.0.0"}\n', encoding="utf-8")
            (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
            (root / "go.mod").write_text("module example.test/demo\n\ngo 1.22\n", encoding="utf-8")
            (root / "main.tf").write_text('resource "aws_s3_bucket" "demo" {}\n', encoding="utf-8")
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
            (root / "deploy.yaml").write_text("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n", encoding="utf-8")
            found = sab.detect_ecosystems(root)
            self.assertEqual(
                found,
                [
                    "docker",
                    "github-actions",
                    "go",
                    "kubernetes",
                    "node",
                    "node-lock",
                    "python",
                    "python-deps",
                    "terraform",
                ],
            )
            tools = sab.applicable_scanners(found)
            self.assertEqual(
                tools,
                [
                    "semgrep",
                    "gitleaks",
                    "osv-scanner",
                    "trivy",
                    "zizmor",
                    "bandit",
                    "npm-audit",
                    "pip-audit",
                    "checkov",
                ],
            )

    def test_plain_tree_only_runs_always_on_scanners(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("demo\n", encoding="utf-8")
            self.assertEqual(sab.detect_ecosystems(root), [])
            self.assertEqual(sab.applicable_scanners([]), ["semgrep", "gitleaks", "trivy"])

    def test_refuses_home_and_root(self):
        with self.assertRaises(ValueError):
            sab.assert_safe_repo(Path("/"))
        with self.assertRaises(ValueError):
            sab.assert_safe_repo(Path.home())


if __name__ == "__main__":
    unittest.main()
