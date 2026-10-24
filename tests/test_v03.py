"""0.3.0: built-in checks, PHP depth, platform check (Railway), first-steps lint, share line.

Fake secrets are built at run time so this repository never holds a secret-shaped string.
"""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FAKE_OPENAI = "sk-proj-" + "Q7v" * 12
FAKE_STRIPE = "sk_" + "live_" + "N4p" * 8
DB_PASSWORD = "Zx81kq" + "7TT2pLm"


def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def fake_jwt(role):
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + b64({"iss": "supabase", "role": role, "ref": "fixture00"}) + ".c2lnbmF0dXJlZml4dHVyZQ"


def done(argv, code=0, out="", err=""):
    return subprocess.CompletedProcess(argv, code, out, err)


def write(root, rel, text):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rules(leads):
    return {(lead["rule"], lead["file"]) for lead in leads}


def no_tools(name):
    return None


class BuiltinCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_secret_in_client_bundle_is_flagged_and_redacted(self):
        write(self.root, "package.json", '{"dependencies":{"next":"15.0.0"}}')
        write(self.root, "components/Chat.tsx", f'"use client";\nconst key = "{FAKE_OPENAI}";\nconst pay = "{FAKE_STRIPE}";\n')
        write(self.root, ".env.local", f"NEXT_PUBLIC_OPENAI_API_KEY={FAKE_OPENAI}\nNEXT_PUBLIC_SUPABASE_ANON_KEY={fake_jwt('anon')}\n")
        write(self.root, "src/server/ai.ts", f'const key = "{FAKE_OPENAI}";\n')
        leads = sab.run_builtin_checks(self.root)
        found = rules(leads)
        self.assertIn(("sab.client-openai-key", "components/Chat.tsx"), found)
        self.assertIn(("sab.client-stripe-secret-key", "components/Chat.tsx"), found)
        self.assertIn(("sab.secret-in-public-env", ".env.local"), found)
        self.assertIn(("sab.committed-env-file", ".env.local"), found)
        # Server code is gitleaks' job, not the client check.
        self.assertNotIn(("sab.client-openai-key", "src/server/ai.ts"), found)
        # The anon key is public by design.
        self.assertFalse(any("ANON" in lead["message"] for lead in leads))
        blob = json.dumps(leads)
        self.assertNotIn(FAKE_OPENAI, blob)
        self.assertNotIn(FAKE_STRIPE, blob)
        self.assertTrue(all(lead["kind"] == "secret" for lead in leads if lead["rule"].startswith("sab.client-")))

    def test_public_env_names(self):
        write(self.root, "src/lib/config.ts", "export const a = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n"
              "export const b = import.meta.env.VITE_ANTHROPIC_API_KEY;\n"
              "export const c = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY;\n"
              "export const d = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n")
        names = [lead["message"].split()[0] for lead in sab.run_builtin_checks(self.root) if lead["rule"] == "sab.secret-in-public-env"]
        self.assertEqual(sorted(names), ["NEXT_PUBLIC_STRIPE_SECRET_KEY", "VITE_ANTHROPIC_API_KEY"])

    def test_supabase_service_role(self):
        service = fake_jwt("service_role")
        write(self.root, "package.json", '{"dependencies":{"@supabase/supabase-js":"2.0.0"}}')
        write(self.root, "components/Admin.jsx", f'const k = "{service}";\nconst r = process.env.SUPABASE_SERVICE_ROLE_KEY;\n')
        write(self.root, "scripts/seed.js", f'const k = "{service}";\n')
        write(self.root, "components/Public.jsx", f'const k = "{fake_jwt("anon")}";\n')
        leads = sab.run_builtin_checks(self.root)
        found = rules(leads)
        self.assertIn(("sab.client-supabase-service-role", "components/Admin.jsx"), found)
        self.assertIn(("sab.client-service-role-ref", "components/Admin.jsx"), found)
        self.assertIn(("sab.supabase-service-role-committed", "scripts/seed.js"), found)
        self.assertFalse(any(lead["file"] == "components/Public.jsx" for lead in leads))
        self.assertNotIn(service, json.dumps(leads))

    def test_supabase_rls(self):
        write(self.root, "supabase/config.toml", "project_id = 'demo'\n")
        write(self.root, "supabase/migrations/001.sql", "\n".join([
            "create table public.profiles (id uuid primary key);",
            'create table if not exists "notes" (id uuid);',
            "alter table public.notes enable row level security;",
            "create table private.audit (id int);",
            "-- create table commented_out (id int);",
            "create table todos (id int);",
            "alter table todos enable row level security;",
            "alter table todos disable row level security;",
            'create policy "anyone" on notes for insert with check (true);',
            'create policy "read" on notes for select using (true);',
        ]))
        leads = [lead for lead in sab.run_builtin_checks(self.root) if lead["rule"].startswith("sab.supabase")]
        messages = sorted((lead["rule"], lead["message"].split(" ")[1]) for lead in leads)
        self.assertIn(("sab.supabase-table-without-rls", "profiles"), messages)
        self.assertIn(("sab.supabase-table-without-rls", "todos"), messages)
        self.assertIn(("sab.supabase-rls-disabled", "level"), messages)
        self.assertEqual(sum(1 for lead in leads if lead["rule"] == "sab.supabase-policy-allows-all"), 1)
        self.assertFalse(any("audit" in lead["message"] or "commented_out" in lead["message"] for lead in leads))
        self.assertFalse(any(" notes " in lead["message"] and "without" in lead["rule"] for lead in leads))

    def test_firebase_rules(self):
        write(self.root, "firestore.rules", "service cloud.firestore {\n  match /databases/{db}/documents {\n"
              "    match /users/{uid} { allow read, write: if request.auth.uid == uid; }\n"
              "    match /{document=**} { allow read, write: if true; }\n  }\n}\n")
        write(self.root, "storage.rules", "service firebase.storage {\n  match /b/{bucket}/o {\n"
              "    match /{all=**} { allow read, write: if request.time < timestamp.date(2030, 1, 1); }\n  }\n}\n")
        write(self.root, "database.rules.json", '{"rules": {".read": "auth != null", ".write": true}}')
        leads = sab.run_builtin_checks(self.root)
        by_file = {(lead["file"], lead["line"]) for lead in leads}
        self.assertIn(("firestore.rules", 4), by_file)
        self.assertNotIn(("firestore.rules", 3), by_file)
        self.assertIn(("storage.rules", 3), by_file)
        self.assertEqual([lead["rule"] for lead in leads if lead["file"] == "database.rules.json"], ["sab.firebase-rtdb-open"])

    def test_routes_and_llm_endpoints(self):
        write(self.root, "app/api/chat/route.ts", 'import OpenAI from "openai";\nconst c = new OpenAI();\n'
              "export async function POST(req: Request) { return Response.json(await c.responses.create(await req.json())); }\n")
        write(self.root, "app/api/chat-auth/route.ts", 'import Anthropic from "@anthropic-ai/sdk";\nimport { auth } from "@/auth";\n'
              'export async function POST() { const s = await auth(); if (!s) return new Response("no", { status: 401 }); }\n')
        write(self.root, "app/api/chat-safe/route.ts", 'import { generateText } from "ai";\nimport { auth } from "@/auth";\n'
              'import { Ratelimit } from "@upstash/ratelimit";\nexport async function POST() { const s = await auth(); }\n')
        write(self.root, "app/api/users/route.ts", "export async function DELETE() { await db.user.deleteMany(); }\n")
        write(self.root, "app/api/health/route.ts", "export async function GET() { return Response.json({ ok: true }); }\n")
        write(self.root, "server/index.js", "const express = require('express');\nconst OpenAI = require('openai');\n"
              "app.post('/ask', async (req, res) => { res.json(await ai.chat(req.body)); });\n")
        write(self.root, "app/actions.ts", '"use server";\nexport async function removePost(id) { await db.post.delete({ where: { id } }); }\n')
        write(self.root, "main.py", "from fastapi import FastAPI\nfrom openai import OpenAI\napp = FastAPI()\n"
              "@app.post('/chat')\ndef chat(body: dict):\n    return OpenAI().responses.create(**body)\n")
        found = rules(sab.run_builtin_checks(self.root))
        self.assertIn(("sab.llm-route-no-auth", "app/api/chat/route.ts"), found)
        self.assertIn(("sab.llm-route-no-rate-limit", "app/api/chat-auth/route.ts"), found)
        self.assertFalse(any(file == "app/api/chat-safe/route.ts" for _, file in found))
        self.assertIn(("sab.api-route-no-auth", "app/api/users/route.ts"), found)
        self.assertFalse(any(file == "app/api/health/route.ts" for _, file in found))
        self.assertIn(("sab.llm-route-no-auth", "server/index.js"), found)
        self.assertIn(("sab.server-action-no-auth", "app/actions.ts"), found)
        self.assertIn(("sab.llm-route-no-auth", "main.py"), found)

    def test_auth_middleware_lowers_route_severity(self):
        write(self.root, "middleware.ts", "import { clerkMiddleware } from '@clerk/nextjs/server';\nexport default clerkMiddleware();\n")
        write(self.root, "app/api/users/route.ts", "export async function DELETE() { await db.user.deleteMany(); }\n")
        leads = sab.run_builtin_checks(self.root)
        self.assertEqual([(lead["rule"], lead["severity"]) for lead in leads], [("sab.api-route-no-auth", "low")])
        self.assertIn("matcher", leads[0]["message"])

    def test_php_config_checks(self):
        write(self.root, ".env", "APP_NAME=demo\nAPP_DEBUG=true\nAPP_KEY=\n")
        write(self.root, ".env.example", "APP_DEBUG=true\nDB_PASSWORD=\n")
        write(self.root, "public/info.php", "<?php\n// phpinfo(); is commented here\nphpinfo();\n")
        write(self.root, "config/app.php", "<?php\nreturn ['debug' => true, 'name' => 'x'];\n")
        write(self.root, "config/ok.php", "<?php\nreturn ['debug' => env('APP_DEBUG', false)];\n")
        leads = sab.run_builtin_checks(self.root)
        found = {(lead["rule"], lead["file"], lead["line"]) for lead in leads}
        self.assertIn(("sab.committed-env-file", ".env", 1), found)
        self.assertIn(("sab.app-debug-true", ".env", 2), found)
        self.assertIn(("sab.phpinfo-exposed", "public/info.php", 3), found)
        self.assertIn(("sab.app-debug-true", "config/app.php", 2), found)
        self.assertFalse(any(lead["file"] in {".env.example", "config/ok.php"} for lead in leads))
        env_lead = next(lead for lead in leads if lead["rule"] == "sab.committed-env-file")
        self.assertEqual(env_lead["severity"], "low")


class PhpTests(unittest.TestCase):
    def test_framework_detection_and_semgrep_packs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "composer.json", '{"require": {"laravel/framework": "^11.0"}}')
            write(root, "composer.lock", "{}")
            write(root, "wp-content/plugins/demo/demo.php", "<?php\n/*\n * Plugin Name: Demo\n */\n")
            found = sab.detect_ecosystems(root)
            for eco in ("php", "php-lock", "laravel", "wordpress"):
                self.assertIn(eco, found)
            self.assertNotIn("symfony", found)
            tools = sab.applicable_scanners(found)
            self.assertIn("composer-audit", tools)
            self.assertIn("osv-scanner", tools)
            configs = sab.semgrep_configs(found)
            self.assertIn("p/php", configs)
            self.assertIn("r/php.laravel", configs)
            self.assertIn("p/wordpress", configs)
            self.assertNotIn("r/php.symfony", configs)
            self.assertTrue(any(config.endswith("php.yml") for config in configs))
            self.assertTrue(any(config.endswith("ai-app.yml") for config in configs))

    def test_plain_php_without_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "index.php", "<?php echo 'hi';\n")
            found = sab.detect_ecosystems(root)
            self.assertEqual(found, ["php"])
            self.assertNotIn("composer-audit", sab.applicable_scanners(found))
            self.assertNotIn("osv-scanner", sab.applicable_scanners(found))

    def test_composer_audit_normalize_and_merge_with_osv(self):
        payload = {"advisories": {"demo/lib": [{
            "advisoryId": "PKSA-aaaa-bbbb-cccc", "packageName": "demo/lib", "affectedVersions": "<1.2",
            "title": "Demo flaw", "cve": "CVE-2099-0002", "link": "https://example.test", "severity": "high",
            "sources": [{"name": "GitHub", "remoteId": "GHSA-dddd-eeee-ffff"}],
        }]}, "abandoned": {}}
        leads = sab.normalize_composer_audit(payload, Path("/repo"), Path("/repo/composer.lock"))
        self.assertEqual(len(leads), 1)
        lead = leads[0]
        self.assertEqual((lead["tool"], lead["file"], lead["severity"], lead["kind"]), ("composer-audit", "composer.lock", "high", "dep"))
        self.assertIn("GHSA-dddd-eeee-ffff", lead["_meta"]["ids"])
        osv = sab.normalize_osv({"results": [{"source": {"path": "/repo/composer.lock"}, "packages": [{
            "package": {"name": "demo/lib", "version": "1.0"},
            "vulnerabilities": [{"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2099-0002"], "summary": "Demo flaw"}],
        }]}]}, Path("/repo"))
        merged = sab.merge_cross_tool(osv + leads)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["also_reported_by"], ["composer-audit"])

    def test_composer_missing_is_skipped_with_fallback_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "composer.lock", "{}")
            leads, note = sab.run_composer_audit(root, lambda *a, **k: done([], 0), no_tools, {})
            self.assertEqual(leads, [])
            self.assertIn("not installed", note)
            self.assertIn("osv-scanner", note)

    def test_composer_audit_runs_without_plugins_or_scripts(self):
        calls = []

        def runner(argv, timeout, cwd=None, env=None):
            calls.append(argv)
            return done(argv, 1, json.dumps({"advisories": {"demo/lib": [{"advisoryId": "PKSA-1", "packageName": "demo/lib", "title": "x"}]}}))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "composer.lock", "{}")
            leads, note = sab.run_composer_audit(root, runner, lambda name: "/fake/composer", {})
        self.assertEqual(note, "")
        self.assertEqual(len(leads), 1)
        self.assertIn("--no-plugins", calls[0])
        self.assertIn("--no-scripts", calls[0])
        self.assertIn("--locked", calls[0])

    def test_local_rule_ids_drop_host_path(self):
        self.assertEqual(sab.local_rule_id("home.someone.bot.rules.sab.php.eval-user-input"), "sab.php.eval-user-input")
        self.assertEqual(sab.local_rule_id("rules.sab.js.cors-reflect-origin"), "sab.js.cors-reflect-origin")
        self.assertEqual(sab.local_rule_id("php.lang.security.eval-use"), "php.lang.security.eval-use")


@unittest.skipUnless(sab.which("semgrep"), "semgrep not installed")
class LocalRuleTests(unittest.TestCase):
    """Runs this repo's semgrep rules on the fixtures (local rules only, no network)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        # Semgrep skips tests/ by default, so scan a copy.
        target = Path(cls.tmp.name) / "target"
        shutil.copytree(FIXTURES, target)
        home = Path(cls.tmp.name) / "home"
        (home / "config").mkdir(parents=True)
        argv = [sab.which("semgrep"), "scan", "--metrics=off", "--disable-version-check", "--quiet", "--json"]
        for config in sorted(sab.RULES_DIR.glob("*.yml")):
            argv += ["--config", str(config)]
        result = subprocess.run(argv + [str(target)], capture_output=True, text=True, timeout=300,
                                env=sab.scanner_env(home), check=False)
        payload = json.loads(result.stdout)
        cls.errors = payload.get("errors") or []
        cls.hits = {(lead["rule"], lead["file"], lead["line"]) for lead in sab.normalize_semgrep(payload, target)}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_rules_parse(self):
        self.assertEqual([error.get("message") for error in self.errors], [])

    def test_php_rules(self):
        expected = {
            ("sab.php.unserialize-user-input", "php-app/vuln.php", 3),
            ("sab.php.eval-user-input", "php-app/vuln.php", 5),
            ("sab.php.include-user-path", "php-app/vuln.php", 6),
            ("sab.php.sql-string-concat", "php-app/vuln.php", 8),
            ("sab.php.sql-string-concat", "php-app/vuln.php", 10),
            ("sab.php.sql-request-data", "php-app/plugin.php", 24),
            ("sab.php.laravel-csrf-except-all", "php-app/VerifyCsrfToken.php", 6),
            ("sab.php.wp-nopriv-ajax", "php-app/plugin.php", 6),
            ("sab.php.wp-ajax-no-capability", "php-app/plugin.php", 8),
            ("sab.php.wp-nonce-result-ignored", "php-app/plugin.php", 9),
            ("sab.php.wp-is-admin-as-auth", "php-app/plugin.php", 27),
            ("sab.php.wp-rest-open-permission", "php-app/plugin.php", 31),
        }
        self.assertEqual(expected - self.hits, set())
        # Safe variants stay quiet.
        for line in (4, 9):
            self.assertFalse(any(hit[1] == "php-app/vuln.php" and hit[2] == line for hit in self.hits))
        self.assertFalse(any(hit[1] == "php-app/plugin.php" and 14 <= hit[2] <= 20 for hit in self.hits))

    def test_ai_app_rules(self):
        expected = {
            ("sab.js.llm-client-in-browser", "ai-app/chat.ts", 8),
            ("sab.js.cors-any-origin-with-credentials", "ai-app/chat.ts", 10),
            ("sab.js.supabase-service-role-public-env", "ai-app/chat.ts", 12),
            ("sab.js.cors-reflect-origin", "ai-app/chat.ts", 16),
            ("sab.js.jwt-decode-as-auth", "ai-app/chat.ts", 17),
            ("sab.py.cors-any-origin-with-credentials", "ai-app/api.py", 6),
        }
        self.assertEqual(expected - self.hits, set())
        for line in (11, 13):
            self.assertFalse(any(hit[1] == "ai-app/chat.ts" and hit[2] == line for hit in self.hits))


class PlatformCheckTests(unittest.TestCase):
    def make_repo(self, root):
        write(root, "railway.toml", "[deploy]\nstartCommand = 'npm start'\n")
        write(root, "src/db.ts", "const a = process.env.DATABASE_PUBLIC_URL;\n"
              f'const b = "postgresql://postgres:{DB_PASSWORD}@roundhouse.proxy.rlwy.net:12345/railway";\n'
              'const c = "postgresql://dev:devpass@localhost:5432/dev";\n'
              "const { OPENAI_API_KEY, STRIPE_SECRET_KEY } = process.env;\n"
              "const d = process.env['ANTHROPIC_API_KEY'];\nconst e = process.env.PORT;\nconst f = process.env.RAILWAY_PUBLIC_DOMAIN;\n")
        write(root, "app.py", "import os\nkey = os.environ.get('XAI_API_KEY')\nbucket = os.getenv('AWS_SECRET_ACCESS_KEY')\n")
        write(root, "index.php", "<?php\n$k = getenv('GITHUB_TOKEN');\n$s = env('JWT_SECRET');\n")
        write(root, ".env.example", "RESEND_API_KEY=\nNEXT_PUBLIC_OPENAI_API_KEY=\n")
        write(root, ".github/workflows/deploy.yml", "jobs:\n  d:\n    steps:\n      - run: railway up\n"
              "        env:\n          RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}\n")

    def test_classify(self):
        cases = {
            "OPENAI_API_KEY": "ai", "ANTHROPIC_API_KEY": "ai", "XAI_API_KEY": "ai", "DATABASE_URL": "database",
            "REDIS_URL": "database", "PGPORT": "config", "DB_HOST": "config", "AWS_SECRET_ACCESS_KEY": "cloud",
            "S3_BUCKET_SECRET": "cloud", "STRIPE_SECRET_KEY": "payment", "JWT_SECRET": "auth",
            "NEXTAUTH_SECRET": "auth", "GITHUB_TOKEN": "github", "GHCR_TOKEN": "github", "RAILWAY_TOKEN": "platform",
            "RAILWAY_PUBLIC_DOMAIN": "provided", "RESEND_API_KEY": "messaging", "WEBHOOK_SIGNING_SALT": "auth",
            "MY_CUSTOM_TOKEN": "other", "PORT": "config", "NEXT_PUBLIC_SITE_NAME": "public",
            "NEXT_PUBLIC_OPENAI_API_KEY": "public-secret", "SUPABASE_SERVICE_ROLE_KEY": "database",
        }
        for name, group in cases.items():
            self.assertEqual(sab.classify_env_var(name), group, name)
        self.assertEqual(sab.rotate_link("OPENAI_API_KEY")[0], "OpenAI")
        self.assertEqual(sab.rotate_link("MY_CUSTOM_TOKEN"), ("", ""))

    def test_report_lists_rotation_checklist_and_owner_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            self.make_repo(root)
            out = Path(tmp) / "out"
            code = sab.cmd_platform_check([str(root), "--platform", "railway", "--out", str(out)], which_fn=no_tools)
            self.assertEqual(code, 0)
            doc = json.loads((out / "platform-railway.json").read_text())
            text = (out / "PLATFORM-RAILWAY.md").read_text()
            self.assertTrue(doc["detected"])
            groups = {group: [item["name"] for item in items] for group, items in doc["env_groups"].items()}
            self.assertEqual(sorted(groups["ai"]), ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"])
            self.assertIn("STRIPE_SECRET_KEY", groups["payment"])
            self.assertIn("AWS_SECRET_ACCESS_KEY", groups["cloud"])
            self.assertIn("GITHUB_TOKEN", groups["github"])
            self.assertIn("JWT_SECRET", groups["auth"])
            self.assertIn("RESEND_API_KEY", groups["messaging"])
            self.assertIn("NEXT_PUBLIC_OPENAI_API_KEY", groups["public-secret"])
            self.assertIn("RAILWAY_PUBLIC_DOMAIN", groups["provided"])
            self.assertEqual(doc["ci_secrets"], ["RAILWAY_TOKEN"])
            kinds = [item["kind"] for item in doc["db_exposure"]]
            self.assertIn("public-proxy-url-with-password", kinds)
            self.assertIn("public-db-variable", kinds)
            self.assertEqual(sum(1 for kind in kinds if kind.startswith("db-url")), 0)  # localhost dev URL ignored
            self.assertIn("https://platform.openai.com/api-keys", text)
            self.assertIn("Remove public network access to databases", text)
            self.assertIn("still work on GitHub until you revoke them", text)
            self.assertIn("Vercel, Render, or Fly later", text)
            self.assertIn("gitleaks did not run cleanly", text)
            self.assertNotIn(DB_PASSWORD, text + json.dumps(doc))
            self.assertEqual(sab.lint_reports(out), [])

    def test_gitleaks_results_are_listed_without_values(self):
        def which_fn(name):
            return "/fake/gitleaks" if name == "gitleaks" else None

        def runner(argv, timeout, cwd=None, env=None):
            report = Path(argv[argv.index("--report-path") + 1])
            report.write_text(json.dumps([{"RuleID": "openai-api-key", "File": "src/ai.ts", "StartLine": 3,
                                           "Secret": FAKE_OPENAI, "Match": FAKE_OPENAI}]))
            return done(argv, 0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            self.make_repo(root)
            doc = sab.build_platform_report(root, which_fn=which_fn, runner=runner, cache_dir=Path(tmp) / "cache")
            text = sab.render_platform_report(doc)
            self.assertEqual(doc["hardcoded_secrets"][0]["rule"], "openai-api-key")
            self.assertIn("src/ai.ts:3 openai-api-key", text)
            self.assertNotIn(FAKE_OPENAI, text + json.dumps(doc))

    def test_no_railway_and_unknown_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            write(root, "index.js", "console.log(process.env.OPENAI_API_KEY)\n")
            doc = sab.build_platform_report(root, which_fn=no_tools)
            self.assertFalse(doc["detected"])
            self.assertIn("No Railway signals found", sab.render_platform_report(doc))
            self.assertEqual(sab.cmd_platform_check([str(root), "--platform", "vercel", "--out", tmp]), 2)
            self.assertEqual(sab.cmd_platform_check([str(root), "--platform", "heroku", "--out", tmp]), 2)

    def test_preflight_summary_points_at_platform_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "app"
            write(root, "railway.json", "{}")
            doc = sab.run_preflight(root, Path(tmp) / "out", which_fn=no_tools, cache_dir=Path(tmp) / "cache")
            self.assertIn("railway", doc["ecosystems"])
            self.assertIn("platform-check", (Path(tmp) / "out" / "preflight-summary.md").read_text())
            self.assertEqual(doc["tools"][0]["tool"], "sab-checks")
            self.assertEqual(doc["tools"][0]["status"], "ok")


class FirstStepsLintTests(unittest.TestCase):
    def lint(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "REPORT.md").write_text(body, encoding="utf-8")
            return sab.lint_reports(tmp)

    def test_valid_list_passes(self):
        body = ("# Security report\n\n## What to do first\n\n"
                "1. Rotate the OpenAI key and move it to a server variable. About 10 minutes.\n"
                "2. Turn on row level security for the profiles table. About 15 minutes.\n"
                "3. Upgrade the image library. 5-10 min.\n\n## Run profile\n\nDetails.\n")
        self.assertEqual(self.lint(body), [])

    def test_too_many_items_fails(self):
        items = "".join(f"- Fix {n}. About 5 minutes.\n" for n in range(6))
        problems = self.lint(f"# Report\n\n## What to do first\n\n{items}\n## Details\n")
        self.assertTrue(any("6 items" in item for item in problems))

    def test_missing_time_cost_fails(self):
        problems = self.lint("# Report\n\n## What to do first\n\n- Rotate the key.\n- Add auth. About 1 hour.\n")
        self.assertEqual(problems, ["REPORT.md: 'What to do first' item 1 has no time cost (for example 'about 10 minutes')"])

    def test_must_be_first_section(self):
        problems = self.lint("# Report\n\n## Run profile\n\nx\n\n## What to do first\n\n- Fix. About 5 minutes.\n")
        self.assertTrue(any("first section" in item for item in problems))


class ShareLineTests(unittest.TestCase):
    def findings(self, *items):
        return [{"verdict": verdict, "fingerprint": fp, **({"severity": {"overall_severity": sev}} if sev else {})}
                for verdict, fp, sev in items]

    def test_build_from_findings_and_previous(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, new = Path(tmp) / "run-1", Path(tmp) / "run-2"
            old.mkdir()
            new.mkdir()
            (old / "findings.json").write_text(json.dumps(self.findings(
                ("confirmed", "a", "high"), ("confirmed", "b", "high"), ("confirmed", "c", "medium"))))
            (new / "findings.json").write_text(json.dumps(self.findings(
                ("confirmed", "c", "medium"), ("needs_validation", "d", None), ("rejected", "e", None))))
            self.assertEqual(sab.cmd_share_line([str(new), "--previous", str(old), "--write"]), 0)
            line = (new / "SHARE-LINE.md").read_text().strip()
            self.assertEqual(line, "Scanned with Security Audit Bot: 0 critical, 0 high, 1 medium, 2 high fixed.")
            self.assertEqual(sab.lint_reports(new), [])

    def test_clean_and_counts_flag(self):
        self.assertEqual(sab.build_share_line({}), "Scanned with Security Audit Bot: no confirmed findings.")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(sab.cmd_share_line([tmp, "--counts", "critical=0,high=1", "--write"]), 0)
            self.assertEqual((Path(tmp) / "SHARE-LINE.md").read_text().strip(),
                             "Scanned with Security Audit Bot: 0 critical, 1 high.")
            self.assertEqual(sab.cmd_share_line([tmp, "--counts", "bogus=1"]), 1)

    def test_lint_rejects_details(self):
        bad = [
            "Scanned with Security Audit Bot: 1 high in src/auth.ts.",
            "Scanned with Security Audit Bot: 0 critical, 1 high (SQL injection).",
            "Scanned with Security Audit Bot: 0 critical.\nSecond line.",
            "My app is secure!",
        ]
        for text in bad:
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "SHARE-LINE.md").write_text(text, encoding="utf-8")
                self.assertTrue(sab.lint_reports(tmp), text)


if __name__ == "__main__":
    unittest.main()
