# Security Audit Bot

Version 0.1.0.

Point this bot at a GitHub repository or a folder you own or are allowed to review. It returns a verified, prioritized security report and the smallest fix for each confirmed finding. Findings stay private to you.

Scanner hits are leads. A lead is not a finding until [Cloudflare's security-audit skill](https://github.com/cloudflare/security-audit-skill) validates it. That skill is MIT-licensed and pinned at `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`. This repo does not copy it. `scripts/sab.py setup` clones that commit into `~/.local/share/security-audit-bot/skill` and checks the hash.

## How a run works

1. You state that the code is yours or that you have permission. `sab.py check-authorization` records that in `run-metadata.json`. For a GitHub URL, a logged-in `gh` also checks `repos/<owner>/<repo>` permissions.
2. The bot clones the repo shallow and read-only (`core.hooksPath=/dev/null`, no submodule recursion) or uses the folder you uploaded. It does not run the project's code, builds, tests, or install scripts.
3. `sab.py preflight` runs the scanners that fit the tree and writes `scanner-leads.json` plus `preflight-summary.md`. Secrets are reduced to a rule, file, line, and fingerprint.
4. Quick triage validates the top leads. A full audit runs the skill's six phases: reconnaissance, coverage-led hunting, candidate validation, `findings.json` checked by `validate-findings.cjs` and `validate-coverage-ledger.cjs`, independent verification, and `REPORT.md`. A full audit uses a lot of usage; the bot asks first.
5. `sab.py report-lint` rejects a report that contains a secret pattern, a high-entropy token, or a raw secret still present in the leads.

The bot does not test live systems, ask for production credentials, publish findings, or push commits unless you ask.

## Install

On the Linux host, as the bot user (Python 3, git, curl, and Node; no sudo):

```bash
git clone <this-repo> ~/security-audit-bot
cd ~/security-audit-bot
python3 scripts/sab.py setup
```

Setup installs the pinned skill and any missing scanners under `~/.local` (`pip install --user`, `pipx` for Semgrep when it is present, and checked GitHub release binaries). A tool that cannot be installed is skipped. Add `~/.local/bin` to `PATH` if you want to run the tools yourself. `sab.py` looks there either way.

Use this repository as the specialist's working directory. The skills are `skills/security-audit-bot` and `skills/security-audit-getting-started`.

## Commands

```bash
python3 scripts/sab.py setup
python3 scripts/sab.py check-authorization <git-url-or-path> --affirm "this is my code" --metadata run-metadata.json
python3 scripts/sab.py preflight <repo-path> --out <dir>
python3 scripts/sab.py report-lint <dir>
```

`scanner-leads.json` leads use `{tool, rule, severity, file, line, message, fingerprint}`.

## Pin update

1. Pick a new commit of `cloudflare/security-audit-skill` that still contains `skills/security-audit`.
2. Change `SKILL_COMMIT` in `scripts/sab.py`.
3. Update the same hash in this README and in `NOTICE`.
4. On the bot host, run `python3 scripts/sab.py setup`. It fetches that commit and will not report success if `HEAD` differs.
5. Refresh `SHA256SUMS` (`shasum -a 256 scripts/sab.py`).
6. Commit. Do not copy the skill files into this repo.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests use fictional fixtures and do not use the network.

## Credits

Cloudflare, Inc. wrote the security-audit skill (MIT). See `NOTICE` for that license and for the license of each scanner.
