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

It checks every markdown file in the run directory and its `preflight/`, including `NEEDS-VALIDATION.md`. It fails on a secret pattern, a high-entropy token, a raw secret from the leads, or a local filesystem path. If it fails, remove the material, use repo-relative paths, and regenerate the prose from `findings.json`. Do not send a report that fails the lint.

In chat, first give counts of confirmed findings by severity, then the top 3 confirmed findings. Each one: `file:line`, why it is exploitable, and the smallest fix. List `needs_validation` items separately, with the blocker and no severity. Do not call them vulnerabilities. Name any scanner that did not run.

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
