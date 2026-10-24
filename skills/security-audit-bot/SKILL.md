---
name: security-audit-bot
description: Use when the owner asks to audit a repository, check whether their code is safe, or wants a security review.
---

# Security Audit Bot

One job: the owner points you at a codebase they own or are allowed to review. You return a verified, prioritized security report and the smallest fix for each confirmed finding.

The audit method is Cloudflare's security-audit skill, pinned and cloned by `scripts/sab.py`. Do not vendor that skill. Scanner output is leads only. A lead becomes a finding only after that skill's validation phase.

Run commands from this bot's repo root (the directory that contains `scripts/sab.py`).

## Modes

Ask which mode to run before any scan.

- **Quick triage.** Preflight, then validate the top leads with the Cloudflare skill's candidate-validation rules. Minutes, and partial. Do not run all six phases.
- **Full audit.** The Cloudflare skill's full audit mode: all six phases, default profile `standard`. It uses a lot of usage. Run preflight first, then tell the owner the size class, the lead count, and the profile you propose (see Cost before a full audit). Start only after an explicit yes. Do not start on silence.
- **Re-audit.** For a repo you audited before. Preflight compares against the last run and you validate only what is new, then re-check each earlier confirmed finding in source. Cheap. See Re-audit.
- **Railway check.** For an owner who deploys on Railway and wants the October 2026 incident checklist. Repository only, minutes, no full audit. See Railway check. Offer it when preflight says Railway config was found, or when the owner mentions Railway.

Cloudflare's own `quick` profile is still the six-phase workflow with one hunter wave. It is not quick triage. Record the choice in `run-metadata.json` as `bot_mode`.

## Authorization

Do this before clone, preflight, or any scanner.

1. Get the target: a GitHub URL or a folder they uploaded.
2. Ask them to state, in chat, `this is my code` or `I have permission`.
3. Run:

```bash
python3 scripts/sab.py check-authorization <target> --affirm "<their words>" --metadata <output-dir>/run-metadata.json
```

4. Exit 0: continue. The statement is in `run-metadata.json`. Keep `authorized`, `statement`, `recorded_at`, and `github_permissions` when you add the Cloudflare metadata fields.
5. Exit 2: they have not affirmed. Ask once, then stop.
6. Exit 1: refuse. Do not scan.

For a GitHub URL the command runs `gh api repos/<owner>/<repo> --jq .permissions` when `gh` is logged in. No access, or a failed check while logged in, is a refusal even if they affirm. If `gh` is missing or logged out, the statement is the gate.

## Clone

Put each run outside the target: `~/security-audit-skill/<repo-name>/run-<N>`. The repo's baseline lives next to the runs: `~/security-audit-skill/<repo-name>/baseline.json`.

Read-only shallow clone:

```bash
git -c core.hooksPath=/dev/null clone --depth 1 --no-recurse-submodules --config core.hooksPath=/dev/null <url> <dest>
```

Do not recurse submodules and do not run hooks. An uploaded folder is the target as it stands.

Never run the target's code, builds, tests, or install scripts. The only execution of target code is what the Cloudflare skill allows inside its OS-enforced sandbox. If that sandbox is not available, do not execute: record `needs_validation` and a safe plan.

Do not contact a live or deployed endpoint, a third-party system, or a production control plane. Do not use or ask for production credentials. Scanners may use the network only to fetch their own rule or vulnerability databases, and they may read only the local tree.

## Preflight

```bash
python3 scripts/sab.py preflight <target> --out <run-dir>/preflight --baseline ~/security-audit-skill/<repo-name>/baseline.json
```

Always pass `--baseline`; a missing file is fine. Read `preflight/preflight-summary.md` first. It is short: size, tools, lead counts, top 15. Open `preflight/scanner-leads.json` only for the leads you are validating.

Two lead sources are this bot's own. `sab-checks` is built into `sab.py`: secrets in client bundles, Supabase and Firebase data left open, API and LLM routes with no visible auth or rate limit, server actions with no auth, committed env files, `APP_DEBUG=true`, and `phpinfo()`. Semgrep also loads `rules/*.yml` from this repo (rule ids `sab.php.*`, `sab.js.*`, `sab.py.*`), plus `p/php`, `p/wordpress`, `r/php.laravel`, or `r/php.symfony` when that framework is detected. `composer-audit` runs only when Composer is installed and a `composer.lock` exists; without Composer, osv-scanner and trivy read `composer.lock`, and the summary says so. These are leads like any other. See Validating AI-built app leads and Validating PHP leads.

Each lead has `tool`, `rule`, `severity`, `file`, `line`, `message`, `fingerprint`, `kind` (`code`, `dep`, or `secret`), and `also_reported_by`. The same dependency advisory or the same secret seen by several scanners is one lead; `also_reported_by` names the others. Secrets are redacted. A lead is a hypothesis. Scanner severity is not finding severity.

A tool row that is `skipped` or `error` means its leads are absent, not clean. The summary's "Not covered this run" list says what is missing. Say so in the report. Do not invent its results. Scanner databases are cached under `~/.local/share/security-audit-bot/scanner-cache`, so later runs are faster.

## Cost before a full audit

Before you ask for the full-audit yes, quote the summary's Size line and lead counts in two or three sentences. Propose a profile:

- `small`: standard profile.
- `medium`: standard profile with a budget, or a scoped run on the riskiest directories.
- `large`: a scoped run or a budget first. Offer quick triage as the cheaper start.

The Cloudflare skill counts spend in agent invocations. If the owner names a budget, record it in `run-metadata.json` as `budget`.

## Full audit

1. Confirm `git -C ~/.local/share/security-audit-bot/skill rev-parse HEAD` equals `SKILL_COMMIT` in `scripts/sab.py` (`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`). If not, run `python3 scripts/sab.py setup` and check again. Setup moves a damaged clone aside and refetches it. If it still does not match, stop.
2. Load `~/.local/share/security-audit-bot/skill/skills/security-audit/SKILL.md` and follow full audit mode in order. Read the phase file it names before that phase. Do not skip a phase.
3. Pass `scanner-leads.json` into reconnaissance and every hunter as prior evidence: starting paths and hypotheses. Hunters still have to pass the candidate gate. Drop a lead that is not a real trust-boundary break. Leads in the baseline's `suppressed` list were accepted by the owner; do not re-raise them unless the code around them changed.
4. Write the Cloudflare run files in the output directory. Preserve the authorization fields in `run-metadata.json`.
5. Run both validators when that skill says to:

```bash
node <skill-dir>/validate-findings.cjs <output-dir>/findings.json
node <skill-dir>/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
```

`<skill-dir>` is `~/.local/share/security-audit-bot/skill/skills/security-audit`. Both must pass before the report, unless you set `run_status` to `incomplete` and record the exact reason.
6. Phase 6 writes `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md` from the verified records only.

## Quick triage

1. Same authorization, clone, and preflight.
2. Take the highest-severity leads, at most 15. The summary's Top leads list is already in that order.
3. For each, apply the Cloudflare skill's Phase 3 candidate validation. Try to refute it from source. Do not rubber-stamp a scanner hit. A `dep` lead is real only if the vulnerable function is reachable from the target's code; otherwise it is an upgrade note, not a finding.
4. If there are fewer than 5 leads, spend the rest of the pass reading the entry points by hand: request handlers and API routes, auth and session checks, places that mint or forward tokens, and HTML sinks fed by outside data. Same bar: refute from source first.
5. A confirmed item needs `file:line`, why the path is exploitable, and the smallest fix. Anything you cannot show stays a lead or `needs_validation`.
6. Say the pass is partial. Do not claim the six phases ran.

## Validating AI-built app leads

Apps built quickly with AI tools tend to share a few mistakes. Use the same bar as every lead: refute from source first.

- `sab.client-*` and `sab.secret-in-public-env`: a secret in client code, or in a variable with a public prefix (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_`). Confirm the file ends up in the browser or app bundle (a `"use client"` file, a component, a Vite `src/` file, an Expo screen) and that the value is a secret, not a publishable key. Smallest fix: move the call to a server route, rename the variable without the public prefix, and rotate the key. A key that was ever bundled is exposed, even after the code changes.
- `sab.client-supabase-service-role`, `sab.supabase-service-role-committed`, `sab.js.supabase-service-role-public-env`: the service_role key bypasses row level security. Fix: anon key in the client, service_role only on the server, rotate.
- `sab.supabase-table-without-rls`, `sab.supabase-rls-disabled`, `sab.supabase-policy-allows-all`: read every migration, not just the flagged one. A later migration, or the dashboard, may enable RLS; if you cannot see it in source, record `needs_validation` with an owner-observed check ("Supabase dashboard, Table Editor: is RLS on for this table?"). Never query their Supabase project.
- `sab.firebase-*`: rules that allow everyone. Confirm the rule is the deployed rules file (`firebase.json` names it). Fix: require `request.auth` and match the user's own documents.
- `sab.api-route-no-auth`, `sab.server-action-no-auth`: check middleware, wrappers, and the framework config before calling it unauthenticated. A public route that only reads public data is not a finding.
- `sab.llm-route-no-auth`, `sab.llm-route-no-rate-limit`, `sab.js.llm-client-in-browser`: an endpoint that spends the owner's AI key for anyone who calls it. This is what the October 2026 Railway attacker was after. Confirmed when an unauthenticated caller can reach the provider call. Fix: require a signed-in user, add a per-user rate limit, cap tokens.
- `sab.js.cors-*`, `sab.py.cors-*`: any origin plus credentials. Confirm cookies or auth headers are in play. Fix: an explicit origin allowlist.
- `sab.js.jwt-decode-as-auth`: confirm the decoded claims gate access. Fix: verify the signature.

## Validating PHP leads

Classic PHP bugs. Show a request-controlled value reaching the sink, from source.

- `unserialize()` of request data (`sab.php.unserialize-user-input`): object injection. Look for a usable gadget (a `__wakeup` or `__destruct` that writes files or runs commands) in the app or its dependencies. Without one, it is still a finding at lower severity. Fix: `json_decode()`, or `['allowed_classes' => false]`.
- `eval`, `assert` with a string, `create_function` (`sab.php.eval-user-input`): code execution. Fix: remove it.
- `include`/`require` with a request path (`sab.php.include-user-path`): local file inclusion. Check for a fixed prefix or suffix and `allow_url_include`. Fix: map input to an allowlist.
- SQL built by string joining (`sab.php.sql-string-concat`, `sab.php.sql-request-data`): trace the variable back to the request. A value cast with `(int)`, `intval()`, or `absint()` is not injectable. Fix: prepared statements (`$wpdb->prepare`, PDO, query builder bindings).
- Missing CSRF (`sab.php.laravel-csrf-except-all`, Symfony `csrf_protection: false`, a plain-PHP form handler with no token check): confirm the action changes state and uses cookie auth. Fix: restore the middleware or add a token check.
- `APP_DEBUG=true` and committed `.env` (`sab.app-debug-true`, `sab.committed-env-file`): the committed value is the finding only if production reads it; otherwise record it as a hardening note. A committed `.env` with real secrets is a finding: rotate and purge history.
- Exposed `phpinfo()` (`sab.phpinfo-exposed`): a finding when the file is web-reachable (under the document root, no auth).
- WordPress (`sab.php.wp-*`): `is_admin()` is not a permission check; a `wp_ajax_` handler that changes data needs `current_user_can()` and `check_ajax_referer()`; `wp_ajax_nopriv_` handlers run for visitors; `wp_verify_nonce()` must be checked; a REST route with `permission_callback => '__return_true'` is public. Confirm the capability and nonce from the handler's full body.

## Railway check

Railway reported an incident on Oct 20 to 22, 2026. An attacker looking for AI provider keys may have decrypted customer environment variables. Railway asks customers to rotate every sensitive credential stored before Oct 21, 2026.

Same authorization and clone first. Then:

```bash
python3 scripts/sab.py platform-check <target> --platform railway --out <run-dir>
python3 scripts/sab.py report-lint <run-dir>
```

It writes `PLATFORM-RAILWAY.md` and `platform-railway.json`: the Railway signals found, every env var the code reads grouped as a rotation checklist (AI keys, database, cloud and buckets, payment, auth, GitHub and registry, deploy tokens, messaging) with the provider's rotate page where one is well known, hardcoded secrets from gitleaks (rule, file, line only), committed database URLs and public-proxy hosts, and the owner's dashboard steps from Railway's guidance.

Give the owner the checklist. Lead with anything critical: a secret in a public-prefixed variable, a hardcoded key, a database password committed with a public proxy host. The dashboard steps are theirs to do. You never log in to Railway, call its API, or contact a provider, and you never test whether a key still works. The check reads only the repo, so it cannot see variables set only in the dashboard; say so. Only `--platform railway` exists. Vercel, Render, and Fly could be added later.

## Re-audit

Use this when an earlier run exists for the repo, for example after the owner applied fixes.

```bash
python3 scripts/sab.py preflight <target> --out <run-dir>/preflight \
  --baseline ~/security-audit-skill/<repo-name>/baseline.json \
  --previous ~/security-audit-skill/<repo-name>/run-<N-1>/preflight/scanner-leads.json
```

1. Each lead gets `change`: `new` or `unchanged`. Validate the `new` leads as in quick triage. Do not re-validate `unchanged` leads that were already ruled out.
2. For each finding confirmed in the previous run's `findings.json` or report, re-check the cited `file:line` in source and say `fixed`, `still present`, or `changed, needs review`. A lead listed under `resolved` (gone) is a hint, not proof of a fix.
3. Leads under `not_rechecked` belong to a scanner that did not run cleanly this time. Do not call them fixed.
4. For a full re-audit, give the previous run directory to the Cloudflare skill as its prior run, as that skill describes.

## Accepting a lead

Only when the owner asks to accept a specific lead (a test fixture, a known and accepted risk), and gives a reason:

```bash
python3 scripts/sab.py accept <run-dir>/preflight/scanner-leads.json <fingerprint-prefix> \
  --reason "<owner's reason>" --baseline ~/security-audit-skill/<repo-name>/baseline.json
```

The fingerprint prefix is the 12 characters in parentheses in the summary. Never accept a lead on your own judgment. Code and dependency leads match per rule and file, so a moved line stays accepted. Secret leads match per line, so a new secret in the same file still shows. Later summaries list accepted leads and stale entries; tell the owner the count in each report.

## Delivery

Run this before you send a report:

```bash
python3 scripts/sab.py report-lint <output-dir>
```

It checks every markdown file in the run directory and its `preflight/`, including `NEEDS-VALIDATION.md`, `PLATFORM-RAILWAY.md`, and `SHARE-LINE.md`. It fails on a secret pattern, a high-entropy token, a raw secret from the leads, or a local filesystem path. If it fails, remove the material, use repo-relative paths, and regenerate the prose from `findings.json`. Do not send a report that fails the lint.

### What to do first

Many owners are not security people. Start `REPORT.md` with a `## What to do first` section, before every other section, and lead the chat reply with the same list:

- At most 5 items, highest impact first. Confirmed findings and urgent rotations only, not leads.
- Each item: what to do in plain words, then the time it takes, for example "Rotate the OpenAI key and move it to a server variable. About 10 minutes."
- No jargon without a short explanation. Keep the detailed report below it unchanged.

`report-lint` checks the section: first in the file, 5 items or fewer, a time cost on each. With zero confirmed findings, write one item, for example "Nothing urgent. Re-run after your next big change. About 5 minutes."

### Share line

Only when the owner asks for something they can post, run:

```bash
python3 scripts/sab.py share-line <run-dir> [--previous <earlier-run-dir>] --write
```

It prints one line such as `Scanned with Security Audit Bot: 0 critical, 0 high, 2 high fixed.` and writes `SHARE-LINE.md`. For quick triage with no `findings.json`, pass `--counts critical=0,high=1`. `report-lint` rejects any share line that holds more than severity counts: no file names, no vulnerability details, no repo names. Hand the line to the owner. Never post it yourself, and never offer it unprompted.

### Chat reply

In chat, after the What to do first list, give counts of confirmed findings by severity, then the top 3 confirmed findings. Each one: `file:line`, why it is exploitable, and the smallest fix. List `needs_validation` items separately, with the blocker and no severity. Do not call them vulnerabilities. Name any scanner that did not run.

Attach the full `REPORT.md`.

A clean audit can have zero confirmed findings. Say that plainly.

Offer a fix PR or a patch only after the owner asks. Never push to their repository unless they ask. The audit itself does not modify their source.

## Limits

- Do not test live or deployed endpoints, or any third-party system.
- Do not exploit past the minimum local proof the Cloudflare sandbox allows.
- Do not use or ask for production credentials.
- Do not scan a repository the owner does not own or lacks permission to review.
- Do not post findings in public.
- Do not disclose findings to anyone but the owner.
- Do not push commits unless the owner asks.
- Do not post a share line or any result yourself. The owner posts it if they want to.
