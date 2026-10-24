# Security Audit Bot

Version 0.3.0.

Point this bot at code you own, as a GitHub link or a folder. You get back a short list of what to fix first, how long each fix takes, and a full report behind it. Every issue in the report has been checked against your code, not just flagged by a scanner. The report stays private to you.

## What you get

- **What to do first.** At most five items, in plain words, each with a time cost ("Rotate the OpenAI key and move it to a server variable. About 10 minutes.").
- **A verified report.** Each confirmed issue has its file and line, why it matters, and the smallest fix. Things that could not be proven are listed separately, without alarm.
- **Checks for apps built with AI tools.** API keys shipped to the browser (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`), OpenAI, Anthropic, xAI, or Stripe secret keys in frontend code, a Supabase service_role key in the client, tables with no row level security, open Firebase rules, API routes with no login check, CORS that lets any site send logged-in requests, and AI endpoints that let anyone spend your credits.
- **PHP depth.** Laravel, WordPress, and Symfony are detected and get matching rules. Classic bugs are covered: `unserialize` of user input, `eval`, file includes from user paths, SQL built by joining strings, missing CSRF, `APP_DEBUG=true`, a committed `.env`, exposed `phpinfo`, and weak WordPress nonce and permission checks.
- **A share line, if you want one.** Ask, and you get one line you can post yourself, such as `Scanned with Security Audit Bot: 0 critical, 0 high, 2 high fixed.` No file names or details. The bot never posts it.

It reads a copy of your code. It does not attack live sites, ask for production passwords or keys, publish anything, or push to your repo unless you ask.

## Railway users

Railway reported a security incident between Oct 20 and Oct 22, 2026. An attacker looking for AI provider API keys may have decrypted some customers' environment variables, and Railway recommends rotating every sensitive credential stored there before Oct 21 ([preliminary report](https://blog.railway.com/p/preliminary-report-october-security-incident), [changelog](https://railway.com/changelog/2026-10-23-october-21-security-incident.md)).

Ask for the Railway check. In a few minutes, from your repository alone, you get:

- every environment variable your code reads, grouped (AI keys, database, cloud and buckets, payment, auth, GitHub and registry tokens), as a checklist with each provider's rotate page where there is a well-known one;
- hardcoded secrets in the code or git history (location only, never the value);
- database connection strings that use Railway's public proxy, or code that reads `DATABASE_PUBLIC_URL`;
- Railway's recommended dashboard steps as a checklist: rotate, remove public database access, review GitHub logs and app access, revoke old GitHub registry tokens (they keep working on GitHub until you revoke them), check registry logs, and redeploy services that read reset bucket keys.

You do the dashboard steps. The bot never logs in to Railway or any provider. Only Railway is built; Vercel, Render, and Fly could follow.

## Works on

- JavaScript and TypeScript: Next.js, React, Vite, Expo, Express, SvelteKit, Node
- Python: FastAPI, Flask, Django
- PHP: Laravel, WordPress, Symfony, plain PHP
- Go, Rust, Ruby, Java and Kotlin (scanner coverage)
- Supabase migrations and Firebase rules
- Dockerfiles, GitHub Actions, Terraform, Kubernetes

## How it checks

Scanner hits are leads. A lead is not a finding until [Cloudflare's security-audit skill](https://github.com/cloudflare/security-audit-skill) validates it. That skill is MIT-licensed and pinned at `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`. This repo does not copy it. `scripts/sab.py setup` clones that commit into `~/.local/share/security-audit-bot/skill` and checks the hash.

Lead sources: open-source scanners (semgrep, gitleaks, osv-scanner, trivy, zizmor, bandit, pip-audit, npm audit, checkov, and `composer audit` when Composer is installed), this repo's semgrep rules in `rules/`, and `sab-checks`, a set of small checks built into `sab.py`.

## How a run works

1. You state that the code is yours or that you have permission. `sab.py check-authorization` records that in `run-metadata.json`. For a GitHub URL, a logged-in `gh` also checks `repos/<owner>/<repo>` permissions.
2. The bot clones the repo shallow and read-only (`core.hooksPath=/dev/null`, no submodule recursion) or uses the folder you uploaded. It does not run the project's code, builds, tests, or install scripts.
3. `sab.py preflight` runs `sab-checks` and the scanners that fit the tree and writes `scanner-leads.json` plus `preflight-summary.md`. Secrets are reduced to a rule, file, line, and fingerprint. The same advisory or secret found by several scanners is listed once. The summary gives the tree's size class, per-tool timing, and what a skipped scanner leaves uncovered.
4. Before a full audit the bot quotes the size class and lead count and asks for a yes. Quick triage validates the top leads. A full audit runs the skill's six phases: reconnaissance, coverage-led hunting, candidate validation, `findings.json` checked by `validate-findings.cjs` and `validate-coverage-ledger.cjs`, independent verification, and `REPORT.md`. A full audit uses a lot of usage; the bot asks first.
5. `REPORT.md` opens with "What to do first": five items at most, each with a time cost.
6. `sab.py report-lint` checks every report file, including `NEEDS-VALIDATION.md`, `PLATFORM-RAILWAY.md`, and `SHARE-LINE.md`. It rejects a secret pattern, a high-entropy token, a raw secret still present in the leads, or a local filesystem path. It also checks the What to do first list, and that a share line holds nothing but severity counts.

Later runs are cheaper. `--previous` marks each lead `new` or `unchanged` and lists leads that are gone, so a re-audit validates only what changed and re-checks earlier findings in source. Leads you accept, with a reason, go in a per-repo baseline and stop coming back.

The bot does not test live systems, ask for production credentials, publish findings, or push commits unless you ask.

## Install

On the Linux host, as the bot user (Python 3, git, curl, and Node; no sudo):

```bash
git clone <this-repo> ~/security-audit-bot
cd ~/security-audit-bot
python3 scripts/sab.py setup
```

Setup installs the pinned skill and any missing scanners under `~/.local`: `pipx` for Semgrep when present, then `pip install --user`, then a private venv per tool under `~/.local/share/security-audit-bot/venvs` when the host blocks user installs (PEP 668), and checksum-checked GitHub release binaries. A tool that cannot be installed is skipped, and setup prints what its absence leaves uncovered. If the skill clone is damaged (for example copied without `.git/objects`), setup moves it aside and fetches the pin again.

Scanner databases (Trivy's is over 1 GB) are cached in `~/.local/share/security-audit-bot/scanner-cache` and reused across runs. Scanners still get a throwaway `HOME`, so they cannot read your credentials. Add `~/.local/bin` to `PATH` if you want to run the tools yourself. `sab.py` looks there either way.

Use this repository as the specialist's working directory. The skills are `skills/security-audit-bot` and `skills/security-audit-getting-started`.

## Commands

```bash
python3 scripts/sab.py setup
python3 scripts/sab.py check-authorization <git-url-or-path> --affirm "this is my code" --metadata run-metadata.json
python3 scripts/sab.py preflight <repo-path> --out <dir> [--baseline baseline.json] [--previous old/scanner-leads.json]
python3 scripts/sab.py accept <dir>/scanner-leads.json <fingerprint-prefix> --reason "why" --baseline baseline.json
python3 scripts/sab.py report-lint <dir>
python3 scripts/sab.py platform-check <repo-path> --platform railway --out <dir>
python3 scripts/sab.py share-line <dir> [--previous <earlier-dir>] [--counts critical=0,high=1] [--write]
```

`platform-check` reads the repository only and writes `PLATFORM-RAILWAY.md` and `platform-railway.json`. `share-line` builds the owner's optional one-line result from `findings.json` (or `--counts`); with `--previous`, findings confirmed before and gone now count as fixed.

`scanner-leads.json` leads use `{tool, rule, severity, file, line, message, fingerprint, kind, also_reported_by}`, plus `change` when `--previous` is given. The document also has `size`, `tools` (with `seconds`), `suppressed`, `baseline_stale`, and with `--previous`, `resolved` and `not_rechecked`. A previous lead counts as resolved only if its scanner ran cleanly this time.

Baseline matching: code and dependency leads match by tool, rule, file, and message, so a moved line stays accepted. Secret leads match by file and line, so a new secret in the same file is still reported.

## Pin update

1. Pick a new commit of `cloudflare/security-audit-skill` that still contains `skills/security-audit`.
2. Change `SKILL_COMMIT` in `scripts/sab.py`.
3. Update the same hash in this README and in `NOTICE`.
4. On the bot host, run `python3 scripts/sab.py setup`. It fetches that commit and will not report success if `HEAD` differs.
5. Refresh `SHA256SUMS` (`shasum -a 256 scripts/sab.py rules/*.yml skills/*/SKILL.md > SHA256SUMS`).
6. Commit. Do not copy the skill files into this repo.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests use fictional fixtures and do not use the network. Fake secrets are built at run time, so the repo holds no secret-shaped strings. The semgrep rule tests run only when semgrep is installed.

Check an installed copy against this release:

```bash
shasum -a 256 -c SHA256SUMS
```

## Credits

Cloudflare, Inc. wrote the security-audit skill (MIT). See `NOTICE` for that license and for the license of each scanner.
