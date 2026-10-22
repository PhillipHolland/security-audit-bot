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
- **Full audit.** The Cloudflare skill's full audit mode: all six phases, default profile `standard`. It uses a lot of usage. Ask the owner to confirm before you start. Do not start on silence.

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

Put the run outside the target: `~/security-audit-skill/<repo-name>/run-<N>`.

Read-only shallow clone:

```bash
git -c core.hooksPath=/dev/null clone --depth 1 --no-recurse-submodules --config core.hooksPath=/dev/null <url> <dest>
```

Do not recurse submodules and do not run hooks. An uploaded folder is the target as it stands.

Never run the target's code, builds, tests, or install scripts. The only execution of target code is what the Cloudflare skill allows inside its OS-enforced sandbox. If that sandbox is not available, do not execute: record `needs_validation` and a safe plan.

Do not contact a live or deployed endpoint, a third-party system, or a production control plane. Do not use or ask for production credentials. Scanners may use the network only to fetch their own rule or vulnerability databases, and they may read only the local tree.

## Preflight

```bash
python3 scripts/sab.py preflight <target> --out <output-dir>/preflight
```

Read `preflight/scanner-leads.json` and `preflight/preflight-summary.md`. Each lead has `tool`, `rule`, `severity`, `file`, `line`, `message`, and `fingerprint`. Secrets are redacted. A lead is a hypothesis. Scanner severity is not finding severity. If a tool was skipped, say so. Do not invent its results.

## Full audit

1. Confirm `git -C ~/.local/share/security-audit-bot/skill rev-parse HEAD` equals `SKILL_COMMIT` in `scripts/sab.py` (`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`). If not, run `python3 scripts/sab.py setup` and check again. If it still does not match, stop.
2. Load `~/.local/share/security-audit-bot/skill/skills/security-audit/SKILL.md` and follow full audit mode in order. Read the phase file it names before that phase. Do not skip a phase.
3. Pass `scanner-leads.json` into reconnaissance and every hunter as prior evidence: starting paths and hypotheses. Hunters still have to pass the candidate gate. Drop a lead that is not a real trust-boundary break.
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
2. Take the highest-severity leads, at most 15.
3. For each, apply the Cloudflare skill's Phase 3 candidate validation. Try to refute it from source. Do not rubber-stamp a scanner hit.
4. A confirmed item needs `file:line`, why the path is exploitable, and the smallest fix. Anything you cannot show stays a lead or `needs_validation`.
5. Say the pass is partial. Do not claim the six phases ran.

## Delivery

Run this before you send a report:

```bash
python3 scripts/sab.py report-lint <output-dir>
```

If it fails, remove the secret material and regenerate the prose from `findings.json`. Do not send a report that fails the lint.

In chat, first give counts of confirmed findings by severity, then the top 3 confirmed findings. Each one: `file:line`, why it is exploitable, and the smallest fix. List `needs_validation` items separately, with the blocker and no severity. Do not call them vulnerabilities.

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
