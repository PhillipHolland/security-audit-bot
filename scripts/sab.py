#!/usr/bin/env python3
"""Security Audit Bot preflight, setup, authorization, platform check, share line, and report lint."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.3.0"
SKILL_REPO = "https://github.com/cloudflare/security-audit-skill"
SKILL_COMMIT = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
PER_TOOL_CAP = 100
LEAD_KEYS = ("tool", "rule", "severity", "file", "line", "message", "fingerprint", "kind", "also_reported_by")
BASELINE_VERSION = 1

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_MAP = {
    "critical": "critical",
    "crit": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "warn": "medium",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "note": "info",
    "unknown": "info",
    "negligible": "info",
}

SCANNER_ORDER = (
    "sab-checks",
    "semgrep",
    "gitleaks",
    "osv-scanner",
    "trivy",
    "zizmor",
    "bandit",
    "npm-audit",
    "pip-audit",
    "checkov",
    "composer-audit",
)
TIMEOUTS = {
    "sab-checks": 120,
    "composer-audit": 180,
    "semgrep": 300,
    "gitleaks": 180,
    "osv-scanner": 180,
    "trivy": 300,
    "zizmor": 120,
    "bandit": 180,
    "npm-audit": 180,
    "pip-audit": 180,
    "checkov": 300,
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    "vendor",
    ".tox",
    ".hg",
    ".svn",
}
ENV_KEEP = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "XDG_CACHE_HOME",
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
}

SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"gho_[A-Za-z0-9]{36}"),
    re.compile(r"ghu_[A-Za-z0-9]{36}"),
    re.compile(r"ghs_[A-Za-z0-9]{36}"),
    re.compile(r"ghr_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"sk_live_[A-Za-z0-9]{8,}"),
    re.compile(r"rk_live_[A-Za-z0-9]{8,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    ),
)
TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
HEX_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
CHECKSUM_RE = re.compile(r"^([a-fA-F0-9]{64})\s+\*?(\S+)$")
AFFIRM_MARKERS = ("this is my code", "i have permission")

# What the audit loses when a scanner is missing. Printed by setup and preflight.
SCANNER_PURPOSE = {
    "semgrep": "code-pattern leads (injection, unsafe APIs) for most languages",
    "gitleaks": "hard-coded secret leads in files and git history",
    "osv-scanner": "known-vulnerable dependency leads from lockfiles",
    "trivy": "dependency, misconfiguration, and secret leads",
    "zizmor": "GitHub Actions workflow leads",
    "bandit": "Python code-pattern leads",
    "npm-audit": "npm dependency leads from package-lock.json",
    "pip-audit": "Python dependency leads from requirements files",
    "checkov": "Terraform and Kubernetes misconfiguration leads",
    "sab-checks": "built-in checks: secrets in client bundles, open Supabase/Firebase data, unauthenticated API and LLM routes, committed env files, PHP debug settings",
    "composer-audit": "PHP dependency leads from composer.lock (osv-scanner and trivy also read it)",
}
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
# Semgrep registry packs per detected framework. Checked against the registry on 2026-10-24.
SEMGREP_FRAMEWORK_PACKS = {
    "php": "p/php",
    "laravel": "r/php.laravel",
    "wordpress": "p/wordpress",
    "symfony": "r/php.symfony",
}


def data_dir():
    return Path.home() / ".local" / "share" / "security-audit-bot"


def skill_clone_dir():
    return data_dir() / "skill"


def bindir():
    return Path.home() / ".local" / "bin"


def venv_root():
    return data_dir() / "venvs"


def scanner_cache_dir():
    return data_dir() / "scanner-cache"


def which(name):
    local = bindir() / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    for candidate in sorted(venv_root().glob(f"*/bin/{name}")):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def scanner_env(home, cache=None):
    # Isolated HOME so a scanner cannot read host credentials or cloud config.
    # The cache (vulnerability databases, rule downloads) is shared across runs so
    # each preflight does not re-download it. It never holds target code.
    skip = {"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"}
    env = {key: os.environ[key] for key in ENV_KEEP if key in os.environ and key not in skip}
    env.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    local = str(bindir())
    if local not in env["PATH"].split(os.pathsep):
        env["PATH"] = local + os.pathsep + env["PATH"]
    home = Path(home)
    env["HOME"] = str(home)
    env["XDG_CACHE_HOME"] = str(Path(cache) if cache else home / "cache")
    env["XDG_CONFIG_HOME"] = str(home / "config")
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_VERSION_CHECK"] = "0"
    return env


def run_cmd(argv, timeout, cwd=None, env=None):
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return subprocess.CompletedProcess(list(argv), 124, out, (err or "") + "\ntimed out")
    except OSError as exc:
        return subprocess.CompletedProcess(list(argv), 127, "", str(exc))


def normalize_severity(value):
    if value is None:
        return "info"
    key = str(value).strip().lower()
    if key in _SEVERITY_MAP:
        return _SEVERITY_MAP[key]
    try:
        score = float(key)
    except ValueError:
        return "info"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def fingerprint_for(*parts):
    blob = "\n".join("" if part is None else str(part) for part in parts)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def as_line(value):
    try:
        line = int(value)
    except (TypeError, ValueError):
        return 1
    return line if line > 0 else 1


def relativize(path, root):
    if path is None:
        return ""
    raw = str(path).replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    if not raw:
        return ""
    root_s = str(Path(root).resolve()).replace("\\", "/") if root else ""
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        try:
            rel = os.path.relpath(raw, root_s or ".").replace("\\", "/")
        except ValueError:
            return Path(raw).name
        if rel == ".." or rel.startswith("../"):
            return Path(raw).name
        return rel
    return raw


def strip_secrets(text, extra=None):
    if not text:
        return ""
    secrets = [item for item in (extra or []) if isinstance(item, str) and len(item) >= 4]
    secrets.sort(key=len, reverse=True)
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def clean_message(text, extra=None):
    text = strip_secrets(text or "", extra)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 400:
        text = text[:397] + "..."
    return text


def make_lead(tool, rule, severity, file, line, message, fingerprint, secrets=None):
    secret_values = [item for item in (secrets or []) if isinstance(item, str)]
    msg = clean_message(message, secret_values) or str(rule or tool)
    fp = str(fingerprint or "")
    for secret in secret_values:
        if secret and secret in fp:
            fp = ""
            break
    if not fp.startswith("sha256:"):
        fp = fingerprint_for(tool, rule, file, line, msg)
    lead = {
        "tool": str(tool),
        "rule": str(rule or "unknown")[:200],
        "severity": normalize_severity(severity),
        "file": str(file or "").replace("\\", "/"),
        "line": as_line(line),
        "message": msg,
        "fingerprint": fp,
        "kind": "code",
        "also_reported_by": [],
    }
    return {key: lead[key] for key in LEAD_KEYS}


def shannon(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _entropy_token(token):
    if len(token) < 24 or HEX_RE.fullmatch(token):
        return False
    if token.count(token[0]) == len(token):
        return False
    classes = 0
    if re.search(r"[a-z]", token):
        classes += 1
    if re.search(r"[A-Z]", token):
        classes += 1
    if re.search(r"[0-9]", token):
        classes += 1
    if classes < 3:
        return False
    return shannon(token) >= 3.5


def extract_secrets(text):
    found = []
    if not text:
        return found
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            found.append(match.group(0))
    for match in TOKEN_RE.finditer(text):
        token = match.group(0)
        if _entropy_token(token):
            found.append(token)
    return found


def tag_lead(lead, kind, package=None, ids=None):
    """Attach private merge metadata. Stripped before anything is written."""
    meta = {"kind": kind}
    if kind == "dep":
        meta["package"] = str(package or "").lower()
        meta["ids"] = sorted({str(item) for item in (ids or []) if item})
    lead["_meta"] = meta
    lead["kind"] = kind
    return lead


def lead_kind(lead):
    meta = lead.get("_meta") or {}
    kind = meta.get("kind") or lead.get("kind")
    if kind:
        return kind
    return "secret" if lead.get("tool") == "gitleaks" else "code"


def stable_key(lead):
    """Line-insensitive identity for baselines and run-to-run comparison.

    Secrets keep the line so accepting one never hides a new secret in the same file.
    """
    if lead_kind(lead) == "secret":
        parts = ("secret", lead.get("file"), lead.get("line"), lead.get("rule"))
    else:
        parts = (lead.get("tool"), lead.get("rule"), lead.get("file"), lead.get("message"))
    return fingerprint_for(*parts)


def merge_cross_tool(leads):
    """Fold the same dependency advisory or the same secret reported by several tools into one lead."""
    merged = []
    for lead in leads:
        meta = lead.get("_meta") or {}
        kind = meta.get("kind")
        target = None
        if kind in ("dep", "secret"):
            for prev in merged:
                pmeta = prev.get("_meta") or {}
                if pmeta.get("kind") != kind or prev["file"] != lead["file"]:
                    continue
                if lead["tool"] == prev["tool"] or lead["tool"] in prev["also_reported_by"]:
                    continue
                if kind == "dep" and (pmeta.get("package") != meta.get("package") or not set(pmeta.get("ids") or []) & set(meta.get("ids") or [])):
                    continue
                if kind == "secret" and prev["line"] != lead["line"]:
                    continue
                target = prev
                break
        if target is None:
            lead.setdefault("also_reported_by", [])
            merged.append(lead)
            continue
        target["also_reported_by"] = sorted(set(target["also_reported_by"]) | {lead["tool"]})
        if SEVERITY_RANK[lead["severity"]] < SEVERITY_RANK[target["severity"]]:
            target["severity"] = lead["severity"]
        if kind == "dep":
            target["_meta"]["ids"] = sorted(set(target["_meta"]["ids"]) | set(meta.get("ids") or []))
    return merged


def public_lead(lead):
    out = {key: lead[key] for key in LEAD_KEYS if key in lead}
    out.setdefault("also_reported_by", [])
    out["kind"] = lead_kind(lead)
    for key in ("change",):
        if key in lead:
            out[key] = lead[key]
    return out


def dedupe_leads(leads):
    best = {}
    order = []
    for lead in leads:
        key = (lead["tool"], lead["rule"], lead["file"], lead["line"])
        if key not in best:
            best[key] = lead
            order.append(key)
            continue
        if SEVERITY_RANK[lead["severity"]] < SEVERITY_RANK[best[key]["severity"]]:
            best[key] = lead
    return [best[key] for key in order]


def cap_leads(leads, cap=PER_TOOL_CAP):
    grouped = {}
    for lead in leads:
        grouped.setdefault(lead["tool"], []).append(lead)
    kept = []
    truncated = {}
    for tool, items in grouped.items():
        items.sort(key=lambda item: (SEVERITY_RANK[item["severity"]], item["file"], item["line"], item["rule"]))
        if len(items) > cap:
            truncated[tool] = len(items) - cap
            items = items[:cap]
        kept.extend(items)
    kept.sort(key=lambda item: (SEVERITY_RANK[item["severity"]], item["tool"], item["file"], item["line"], item["rule"]))
    return kept, truncated


def parse_json_output(text):
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        starts = [pos for pos in (raw.find("{"), raw.find("[")) if pos >= 0]
        if not starts:
            return None
        try:
            return json.loads(raw[min(starts):])
        except json.JSONDecodeError:
            return None


def normalize_semgrep(payload, root):
    results = []
    if isinstance(payload, dict):
        results = payload.get("results") or []
    elif isinstance(payload, list):
        results = payload
    leads = []
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        message = extra.get("message") or item.get("check_id") or "semgrep"
        rule_id = str(item.get("check_id") or "")
        leads.append(
            tag_lead(make_lead(
                "semgrep",
                item.get("check_id") or "semgrep",
                extra.get("severity"),
                relativize(item.get("path"), root),
                start.get("line") or item.get("line"),
                message,
                fingerprint_for(
                    "semgrep",
                    item.get("check_id"),
                    item.get("path"),
                    start.get("line"),
                    message,
                ),
            ), "secret" if ".secrets." in rule_id else "code")
        )
    return leads


def normalize_gitleaks(payload, root):
    items = payload if isinstance(payload, list) else (payload or {}).get("findings") or []
    if isinstance(payload, dict) and not items:
        items = payload.get("Leaks") or payload.get("leaks") or []
    leads = []
    for item in items:
        if not isinstance(item, dict):
            continue
        secret = item.get("Secret") or item.get("secret") or ""
        match = item.get("Match") or item.get("match") or ""
        rule = item.get("RuleID") or item.get("RuleId") or item.get("rule") or "secret"
        path = item.get("File") or item.get("file") or ""
        line = item.get("StartLine") or item.get("startLine") or item.get("line")
        message = item.get("Description") or item.get("description") or rule
        leads.append(
            tag_lead(make_lead(
                "gitleaks",
                rule,
                "high",
                relativize(path, root),
                line,
                message,
                fingerprint_for("gitleaks", rule, path, line, secret or match or message),
                secrets=[secret, match],
            ), "secret")
        )
    return leads


def _osv_severity(vuln):
    for item in vuln.get("severity") or []:
        if not isinstance(item, dict) or item.get("score") in (None, ""):
            continue
        score = item.get("score")
        try:
            float(score)
        except (TypeError, ValueError):
            named = normalize_severity(score)
            if named != "info":
                return named
            continue
        return normalize_severity(score)
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        return normalize_severity(db.get("severity"))
    return "medium"


def normalize_osv(payload, root):
    results = []
    if isinstance(payload, dict):
        results = payload.get("results") or []
    leads = []
    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        path = source.get("path") if isinstance(source, dict) else ""
        file = relativize(path, root)
        for package in result.get("packages") or []:
            if not isinstance(package, dict):
                continue
            meta = package.get("package") or {}
            name = meta.get("name") or "dependency"
            version = meta.get("version") or ""
            vulns = {}
            for vuln in package.get("vulnerabilities") or []:
                if isinstance(vuln, dict) and vuln.get("id"):
                    vulns[vuln["id"]] = vuln
            groups = package.get("groups") or []
            emitted = set()
            grouped_ids = []
            for group in groups:
                if not isinstance(group, dict):
                    continue
                ids = [vid for vid in (group.get("ids") or []) if vid]
                if ids:
                    grouped_ids.append(ids)
                    emitted.add(ids[0])
            if not grouped_ids:
                grouped_ids = [[vid] for vid in vulns]
            else:
                for vid in vulns:
                    if vid not in {item for ids in grouped_ids for item in ids}:
                        grouped_ids.append([vid])
            for ids in grouped_ids:
                vid = ids[0]
                vuln = vulns.get(vid, {"id": vid, "summary": ""})
                summary = vuln.get("summary") or vuln.get("details") or vid
                label = f"{name}@{version}: {summary}" if version else f"{name}: {summary}"
                aliases = list(ids)
                for vid_alias in ids:
                    aliases.extend((vulns.get(vid_alias) or {}).get("aliases") or [])
                leads.append(
                    tag_lead(make_lead(
                        "osv-scanner",
                        vid,
                        _osv_severity(vuln),
                        file,
                        1,
                        label,
                        fingerprint_for("osv-scanner", vid, file, name, version),
                    ), "dep", name, aliases)
                )
    return leads


def normalize_trivy(payload, root):
    blocks = []
    if isinstance(payload, dict):
        blocks = payload.get("Results") or payload.get("results") or []
    elif isinstance(payload, list):
        blocks = payload
    leads = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        target = block.get("Target") or block.get("target") or ""
        file = relativize(target, root)
        for vuln in block.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vid = vuln.get("VulnerabilityID") or "vuln"
            pkg = vuln.get("PkgName") or "package"
            ver = vuln.get("InstalledVersion") or ""
            title = vuln.get("Title") or vid
            leads.append(
                tag_lead(make_lead(
                    "trivy",
                    vid,
                    vuln.get("Severity"),
                    file,
                    1,
                    f"{pkg}@{ver}: {title}" if ver else f"{pkg}: {title}",
                    fingerprint_for("trivy", vid, file, pkg, ver),
                ), "dep", pkg, [vid, *(vuln.get("VendorIDs") or [])])
            )
        for misconfig in block.get("Misconfigurations") or []:
            if not isinstance(misconfig, dict):
                continue
            cause = misconfig.get("CauseMetadata") or {}
            line = cause.get("StartLine") if isinstance(cause, dict) else 1
            leads.append(
                make_lead(
                    "trivy",
                    misconfig.get("ID") or misconfig.get("AVDID") or "misconfig",
                    misconfig.get("Severity"),
                    file,
                    line,
                    misconfig.get("Title") or misconfig.get("Description") or "misconfig",
                    fingerprint_for("trivy", misconfig.get("ID"), file, line),
                )
            )
        for secret in block.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            raw = secret.get("Match") or secret.get("Secret") or ""
            line = secret.get("StartLine") or 1
            leads.append(
                tag_lead(make_lead(
                    "trivy",
                    secret.get("RuleID") or secret.get("RuleId") or "secret",
                    secret.get("Severity") or "high",
                    file,
                    line,
                    secret.get("Title") or secret.get("RuleID") or "secret",
                    fingerprint_for("trivy-secret", secret.get("RuleID"), file, line, raw),
                    secrets=[raw, secret.get("Match") or "", secret.get("Secret") or ""],
                ), "secret")
            )
    return leads


def _zizmor_location(loc):
    concrete = (loc or {}).get("concrete") or {}
    location = concrete.get("location") or {}
    start = location.get("start_point") or {}
    if "row" in start:
        line = as_line(int(start.get("row") or 0) + 1)
    else:
        line = as_line(start.get("line"))
    path = location.get("path") or ""
    symbolic = (loc or {}).get("symbolic") or {}
    key = symbolic.get("key") or {}
    if not path and isinstance(key, dict):
        local = key.get("Local") or key.get("local") or {}
        if isinstance(local, dict):
            path = local.get("verbatim_path") or local.get("given_path") or local.get("givenPath") or ""
    return path, line


def normalize_zizmor(payload, root):
    items = payload if isinstance(payload, list) else (payload or {}).get("findings") or []
    leads = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = item.get("ident") or item.get("rule") or "zizmor"
        determinations = item.get("determinations") or {}
        severity = determinations.get("severity") if isinstance(determinations, dict) else item.get("severity")
        message = item.get("desc") or item.get("message") or rule
        locations = item.get("locations") or [{}]
        for loc in locations:
            path, line = _zizmor_location(loc if isinstance(loc, dict) else {})
            leads.append(
                make_lead(
                    "zizmor",
                    rule,
                    severity,
                    relativize(path, root),
                    line,
                    message,
                    fingerprint_for("zizmor", rule, path, line, message),
                )
            )
    return leads


def normalize_bandit(payload, root):
    results = (payload or {}).get("results") if isinstance(payload, dict) else payload
    leads = []
    for item in results or []:
        if not isinstance(item, dict):
            continue
        rule = item.get("test_id") or item.get("test_name") or "bandit"
        name = item.get("test_name") or rule
        text = item.get("issue_text") or ""
        leads.append(
            make_lead(
                "bandit",
                rule,
                item.get("issue_severity"),
                relativize(item.get("filename"), root),
                item.get("line_number"),
                f"{name}: {text}" if text else name,
                fingerprint_for("bandit", rule, item.get("filename"), item.get("line_number")),
            )
        )
    return leads


def normalize_npm_audit(payload, root, lockfile):
    leads = []
    file = relativize(lockfile, root) if lockfile else "package.json"
    if not isinstance(payload, dict):
        return leads
    vulns = payload.get("vulnerabilities")
    if isinstance(vulns, dict):
        for name, info in vulns.items():
            if not isinstance(info, dict):
                continue
            title = ""
            source = ""
            for via in info.get("via") or []:
                if isinstance(via, dict):
                    title = title or via.get("title") or ""
                    source = source or str(via.get("source") or via.get("url") or "")
                elif isinstance(via, str) and not title:
                    title = via
            rule = f"npm:{name}" + (f":{source}" if source and source != name else "")
            ghsa = re.findall(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", json.dumps(info.get("via") or []))
            leads.append(
                tag_lead(make_lead(
                    "npm-audit",
                    rule[:200],
                    info.get("severity"),
                    file,
                    1,
                    f"{name}: {title}" if title else str(name),
                    fingerprint_for("npm-audit", rule, file, name),
                ), "dep", name, ghsa)
            )
    advisories = payload.get("advisories")
    if isinstance(advisories, dict):
        for key, info in advisories.items():
            if not isinstance(info, dict):
                continue
            name = info.get("module_name") or key
            leads.append(
                make_lead(
                    "npm-audit",
                    f"npm:{name}:{key}",
                    info.get("severity"),
                    file,
                    1,
                    f"{name}: {info.get('title') or key}",
                    fingerprint_for("npm-audit", key, file, name),
                )
            )
    return leads


def normalize_pip_audit(payload, root, req_file):
    leads = []
    deps = []
    if isinstance(payload, dict):
        deps = payload.get("dependencies") or payload.get("packages") or []
    elif isinstance(payload, list):
        deps = payload
    file = relativize(req_file, root) if req_file else ""
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name") or "package"
        version = dep.get("version") or ""
        for vuln in dep.get("vulns") or dep.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vid = vuln.get("id") or "vuln"
            leads.append(
                tag_lead(make_lead(
                    "pip-audit",
                    vid,
                    "medium",
                    file,
                    1,
                    f"{name}@{version}: {vuln.get('description') or vid}" if version else f"{name}: {vid}",
                    fingerprint_for("pip-audit", vid, file, name, version),
                ), "dep", name, [vid, *(vuln.get("aliases") or [])])
            )
    return leads


def normalize_checkov(payload, root):
    blocks = payload if isinstance(payload, list) else [payload]
    leads = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        failed = ((block.get("results") or {}).get("failed_checks")) or []
        for item in failed:
            if not isinstance(item, dict):
                continue
            span = item.get("file_line_range") or [1]
            line = span[0] if isinstance(span, list) and span else 1
            leads.append(
                make_lead(
                    "checkov",
                    item.get("check_id") or "checkov",
                    item.get("severity") or "medium",
                    relativize(item.get("file_path") or item.get("file_abs_path"), root),
                    line,
                    item.get("check_name") or item.get("check_id") or "misconfig",
                    fingerprint_for("checkov", item.get("check_id"), item.get("file_path"), line, item.get("resource")),
                )
            )
    return leads


def iter_files(root, limit=20000):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            count += 1
            if count > limit:
                return
            yield Path(dirpath) / name


def detect_ecosystems(root):
    root = Path(root)
    found = set()
    yaml_reads = 0
    php_reads = 0
    for path in iter_files(root):
        name = path.name
        lower = name.lower()
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if name.endswith(".py"):
            found.add("python")
        if name in {
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "pdm.lock",
            "uv.lock",
            "setup.py",
            "setup.cfg",
            "pyproject.toml",
        } or (name.startswith("requirements") and name.endswith(".txt")):
            found.update(("python", "python-deps"))
        if name == "package.json":
            found.add("node")
        if name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
            found.update(("node", "node-lock"))
        if name in {"go.mod", "go.sum"}:
            found.add("go")
        if name in {"Cargo.toml", "Cargo.lock"}:
            found.add("rust")
        if name in {"Gemfile", "Gemfile.lock"}:
            found.add("ruby")
        if name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
            found.add("java")
        if name in {"composer.json", "composer.lock"} or lower.endswith(".php"):
            found.add("php")
        if name == "composer.lock":
            found.add("php-lock")
        if name in {"wp-config.php", "wp-config-sample.php"} or "/wp-content/" in f"/{rel}":
            found.add("wordpress")
        if name == "artisan" and path.parent == root:
            found.add("laravel")
        if name == "composer.json":
            try:
                blob = path.read_text(encoding="utf-8", errors="ignore")[:65536]
            except OSError:
                blob = ""
            if '"laravel/framework"' in blob:
                found.add("laravel")
            if re.search(r'"symfony/(?:framework-bundle|http-kernel)"', blob):
                found.add("symfony")
            if re.search(r'"(?:johnpbloch|roots)/wordpress', blob) or '"wpackagist-' in blob:
                found.add("wordpress")
        if lower.endswith(".php") and path.parent.name and "wordpress" not in found and php_reads < 200:
            php_reads += 1
            try:
                with open(path, "rb") as handle:
                    head = handle.read(2048).decode("utf-8", "ignore")
            except OSError:
                head = ""
            if re.search(r"(?m)^\s*\*?\s*Plugin Name:", head) or "add_action(" in head:
                found.add("wordpress")
        if name in RAILWAY_FILES:
            found.add("railway")
        if name.endswith(".tf") or name.endswith(".tf.json"):
            found.add("terraform")
        if name == "Dockerfile" or name.startswith("Dockerfile.") or lower.endswith(".dockerfile"):
            found.add("docker")
        if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            found.add("docker")
        if "/.github/workflows/" in f"/{rel}" and lower.endswith((".yml", ".yaml")):
            found.add("github-actions")
        if name in {"action.yml", "action.yaml"}:
            found.add("github-actions")
        if yaml_reads < 400 and lower.endswith((".yml", ".yaml")) and "kubernetes" not in found:
            yaml_reads += 1
            try:
                blob = path.read_text(encoding="utf-8", errors="ignore")[:4096]
            except OSError:
                blob = ""
            if "apiVersion:" in blob and re.search(r"(?m)^kind:\s+\S+", blob):
                found.add("kubernetes")
    return sorted(found)


def applicable_scanners(ecosystems):
    ecos = set(ecosystems)
    selected = {"sab-checks", "semgrep", "gitleaks", "trivy"}
    if ecos & {"python-deps", "node", "node-lock", "go", "rust", "ruby", "java", "php-lock"}:
        selected.add("osv-scanner")
    if "php-lock" in ecos:
        selected.add("composer-audit")
    if "python" in ecos:
        selected.add("bandit")
    if "python-deps" in ecos:
        selected.add("pip-audit")
    if "node-lock" in ecos:
        selected.add("npm-audit")
    if "github-actions" in ecos:
        selected.add("zizmor")
    if ecos & {"terraform", "kubernetes"}:
        selected.add("checkov")
    return [name for name in SCANNER_ORDER if name in selected]


def requirement_files(root):
    found = []
    for path in iter_files(root):
        name = path.name
        if name == "requirements.txt" or (name.startswith("requirements") and name.endswith(".txt")):
            found.append(path)
        elif name.endswith(".txt") and path.parent.name == "requirements":
            found.append(path)
    return found


def lockfile_dirs(root):
    found = []
    seen = set()
    for path in iter_files(root):
        if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            parent = path.parent.resolve()
            if parent not in seen:
                seen.add(parent)
                found.append(parent)
    return found


def assert_safe_repo(path):
    resolved = Path(path).resolve()
    if resolved == Path("/").resolve() or resolved == Path.home().resolve():
        raise ValueError("refusing to scan the filesystem root or the home directory")
    if not resolved.is_dir():
        raise ValueError("repo path is not a directory")
    return resolved


_NOTE_HINT = re.compile(r"(?i)\b(error|fatal|failed|failure|not found|no package|unable|denied|invalid|timed out)\b")


def scrub_paths(text, root=None):
    """Replace absolute local paths so notes never carry the host layout."""
    if not text:
        return ""
    if root:
        text = text.replace(str(root), "<target>")
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "~")
    return re.sub(r"(?<![\w<~])/(?:home|Users|tmp|var/folders|private)/[^\s'\"]+", "<path>", text)


def _note_from_result(result, root=None):
    lines = [line.strip() for line in (result.stderr or result.stdout or "").splitlines() if line.strip()]
    if not lines:
        return f"exit {result.returncode}"
    hinted = [line for line in lines if _NOTE_HINT.search(line)]
    return clean_message(scrub_paths((hinted or lines)[-1 if not hinted else 0], root))


def _run_json_command(argv, timeout, cwd, runner, env):
    result = runner(argv, timeout=timeout, cwd=cwd, env=env)
    payload = parse_json_output(result.stdout)
    if payload is None and result.returncode == 124:
        return None, "timed out"
    if payload is None:
        return None, _note_from_result(result, cwd) or f"exit {result.returncode}"
    note = "" if result.returncode in (0, 1) else f"exit {result.returncode}"
    return payload, note


def semgrep_configs(ecosystems=(), rules_dir=None):
    """Registry packs plus this repo's local rules. Framework packs only when the framework is present."""
    configs = ["p/security-audit", "p/owasp-top-ten", "p/secrets"]
    for eco in ("php", "laravel", "wordpress", "symfony"):
        if eco in ecosystems:
            configs.append(SEMGREP_FRAMEWORK_PACKS[eco])
    local = Path(rules_dir) if rules_dir else RULES_DIR
    if local.is_dir():
        configs.extend(str(path) for path in sorted(local.glob("*.yml")))
    return configs


def execute_scanner(name, root, runner, which_fn, env, ecosystems=()):
    if name == "sab-checks":
        return run_builtin_checks(root), ""

    if name == "composer-audit":
        return run_composer_audit(root, runner, which_fn, env)

    if name == "semgrep":
        binary = which_fn("semgrep")
        if not binary:
            return [], "not installed"
        argv = [
            binary, "scan", "--disable-version-check", "--metrics=off", "--quiet", "--json",
            "--timeout", "30",
        ]
        for config in semgrep_configs(ecosystems):
            argv += ["--config", config]
        argv += [
            "--exclude", ".git", "--exclude", "node_modules", "--exclude", ".venv",
            "--exclude", "venv", "--exclude", "dist", "--exclude", "build",
            str(root),
        ]
        payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
        if payload is None:
            return [], note or "semgrep failed"
        return normalize_semgrep(payload, root), note

    if name == "gitleaks":
        binary = which_fn("gitleaks")
        if not binary:
            return [], "not installed"
        handle, raw_path = tempfile.mkstemp(prefix="sab-gitleaks-", suffix=".json")
        os.close(handle)
        os.chmod(raw_path, 0o600)
        report = Path(raw_path)
        argv = [
            binary, "detect", "--source", str(root), "--report-format", "json",
            "--report-path", str(report), "--no-banner", "--exit-code", "0",
        ]
        if not (root / ".git").exists():
            argv.append("--no-git")
        try:
            result = runner(argv, timeout=TIMEOUTS[name], cwd=str(root), env=env)
            if not report.exists():
                if result.returncode == 124:
                    return [], "timed out"
                if result.returncode == 0:
                    return [], ""
                return [], _note_from_result(result) or "gitleaks produced no report"
            try:
                raw = report.read_text(encoding="utf-8")
                payload = [] if not raw.strip() else json.loads(raw)
            except (OSError, json.JSONDecodeError):
                return [], "unreadable gitleaks report"
            note = "" if result.returncode in (0, 1) else f"exit {result.returncode}"
            return normalize_gitleaks(payload, root), note
        finally:
            if report.exists():
                try:
                    size = report.stat().st_size
                    report.write_bytes(b"\0" * min(size, 1024 * 1024))
                except OSError:
                    pass
                report.unlink(missing_ok=True)

    if name == "osv-scanner":
        binary = which_fn("osv-scanner")
        if not binary:
            return [], "not installed"
        attempts = [
            [binary, "scan", "source", "-r", "--format", "json", str(root)],
            [binary, "-r", "--format", "json", str(root)],
        ]
        last = "osv-scanner failed"
        for argv in attempts:
            payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
            if payload is not None:
                return normalize_osv(payload, root), note
            if "no package sources" in (note or "").lower():
                return [], "no lockfile or manifest osv-scanner can read"
            last = note or last
        return [], last

    if name == "trivy":
        binary = which_fn("trivy")
        if not binary:
            return [], "not installed"
        common = [binary, "fs", "--format", "json", "--quiet", "--skip-version-check"]
        if env.get("XDG_CACHE_HOME"):
            common += ["--cache-dir", str(Path(env["XDG_CACHE_HOME"]) / "trivy")]
        attempts = [
            (common + ["--scanners", "vuln,misconfig,secret", str(root)], ""),
            (common + ["--offline-scan", "--skip-db-update", "--scanners", "vuln,misconfig,secret", str(root)], "offline scan"),
            (common + ["--scanners", "misconfig,secret", str(root)], "vulnerability database unavailable"),
        ]
        last = "trivy failed"
        for argv, hint in attempts:
            payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
            if payload is not None:
                extra = hint if hint and hint not in (note or "") else ""
                joined = "; ".join(part for part in (extra, note) if part)
                return normalize_trivy(payload, root), joined
            last = note or last
        return [], last

    if name == "zizmor":
        binary = which_fn("zizmor")
        if not binary:
            return [], "not installed"
        argv = [binary, "--offline", "--format=json", str(root)]
        payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
        if payload is None:
            return [], note or "zizmor failed"
        return normalize_zizmor(payload, root), note

    if name == "bandit":
        binary = which_fn("bandit")
        if not binary:
            return [], "not installed"
        argv = [
            binary, "-r", str(root), "-f", "json", "-q", "--exit-zero",
            "-x", ".git,node_modules,.venv,venv,dist,build,__pycache__",
        ]
        payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
        if payload is None:
            return [], note or "bandit failed"
        return normalize_bandit(payload, root), note

    if name == "npm-audit":
        binary = which_fn("npm")
        if not binary:
            return [], "npm not installed"
        dirs = lockfile_dirs(root)
        if not dirs:
            return [], "no package-lock.json"
        leads = []
        notes = []
        for directory in dirs:
            lock = directory / "package-lock.json"
            if not lock.exists():
                lock = directory / "npm-shrinkwrap.json"
            argv = [binary, "audit", "--json", "--package-lock-only"]
            payload, note = _run_json_command(argv, TIMEOUTS[name], str(directory), runner, env)
            if payload is None:
                payload, note = _run_json_command(argv + ["--offline"], TIMEOUTS[name], str(directory), runner, env)
                note = "; ".join(part for part in ("offline", note) if part)
            if payload is None:
                notes.append(note or "npm audit failed")
                continue
            leads.extend(normalize_npm_audit(payload, root, lock))
            if note:
                notes.append(note)
        return leads, "; ".join(notes)

    if name == "pip-audit":
        binary = which_fn("pip-audit")
        if not binary:
            return [], "not installed"
        files = requirement_files(root)
        if not files:
            return [], "no requirements.txt (lockfiles are left to osv-scanner)"
        leads = []
        notes = []
        for req in files:
            argv = [binary, "-f", "json", "--progress-spinner", "off", "--disable-pip", "-r", str(req)]
            payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
            if payload is None:
                notes.append(note or f"pip-audit failed for {req.name}")
                continue
            leads.extend(normalize_pip_audit(payload, root, req))
            if note:
                notes.append(note)
        return leads, "; ".join(notes)

    if name == "checkov":
        binary = which_fn("checkov")
        if not binary:
            return [], "not installed"
        argv = [
            binary, "-d", str(root), "--framework", "terraform,kubernetes",
            "-o", "json", "--quiet", "--compact", "--soft-fail",
            "--download-external-modules", "false",
        ]
        payload, note = _run_json_command(argv, TIMEOUTS[name], str(root), runner, env)
        if payload is None:
            return [], note or "checkov failed"
        return normalize_checkov(payload, root), note

    return [], "unknown scanner"


# ---------------------------------------------------------------------------
# Built-in checks (tool "sab-checks"). Cheap, file-structure checks that the
# registry scanners do not cover well: AI-built app mistakes, open Supabase and
# Firebase data, committed env files, and PHP debug settings. Every result is a
# lead, never a finding. Messages never carry a secret value.
# ---------------------------------------------------------------------------

TEXT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte", ".astro",
    ".py", ".php", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".html", ".sql", ".json",
    ".yml", ".yaml", ".toml", ".rules", ".env", ".example", ".sample", ".template",
}
CLIENT_SUFFIXES = {".jsx", ".tsx", ".vue", ".svelte", ".astro", ".html"}
CLIENT_DIRS = {"components", "public", "static", "client", "frontend", "www", "assets", "hooks", "screens", "views"}
SERVER_DIRS = {"api", "server", "servers", "backend", "functions", "supabase", "scripts", "migrations", "lib-server", "edge"}
PUBLIC_ENV_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "GATSBY_", "PUBLIC_")
PUBLIC_ENV_RE = re.compile(r"\b((?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)[A-Z0-9_]+)\b")
SECRETISH_NAME_RE = re.compile(
    r"SECRET|PRIVATE|SERVICE_ROLE|SERVICE_KEY|PASSWORD|PASSWD|ADMIN_KEY|OPENAI|ANTHROPIC|CLAUDE|XAI|GROK|"
    r"OPENROUTER|GROQ|GEMINI|MISTRAL|REPLICATE|ELEVENLABS|DEEPSEEK|PERPLEXITY|COHERE|TOGETHER|HUGGING|HF_TOKEN|"
    r"STRIPE_SK|DATABASE_URL|DB_PASS|AWS_SECRET|JWT|RESEND|SENDGRID|TWILIO_AUTH|GITHUB_TOKEN|ACCESS_TOKEN"
)
PUBLIC_BY_DESIGN_RE = re.compile(r"ANON|PUBLISHABLE|PUBLIC_KEY|_PK$|SITE_KEY|MEASUREMENT|DSN$|URL$|DOMAIN$|PROJECT_ID")
# Secret key literals that must never ship to a browser or app bundle.
CLIENT_SECRET_LITERALS = (
    ("anthropic-key", "Anthropic secret key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openrouter-key", "OpenRouter secret key", re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}")),
    ("openai-key", "OpenAI secret key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("xai-key", "xAI secret key", re.compile(r"xai-[A-Za-z0-9]{32,}")),
    ("groq-key", "Groq secret key", re.compile(r"gsk_[A-Za-z0-9]{32,}")),
    ("stripe-secret-key", "Stripe secret or restricted key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("supabase-secret-key", "Supabase secret key", re.compile(r"sb_secret_[A-Za-z0-9_\-]{16,}")),
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-]{10,}")
ROUTE_PATH_RE = re.compile(
    r"(?:^|/)app/(?:.*/)?route\.(?:[cm]?[jt]s)$|(?:^|/)pages/api/.+\.(?:[cm]?[jt]sx?)$|\+server\.(?:[jt]s)$|"
    r"^api/.+\.(?:[cm]?[jt]s|py)$|(?:^|/)src/pages/api/.+\.(?:[jt]s)$|(?:^|/)functions/.+\.(?:[cm]?[jt]s)$"
)
SERVER_ROUTE_RE = re.compile(
    r"\b(?:app|router|server|api|fastify)\.(?:post|put|patch|delete|all)\s*\(|"
    r"@(?:app|router|bp|blueprint|api)\.(?:post|put|patch|delete|route)\s*\(|"
    r"\bexport\s+(?:async\s+)?(?:function|const)\s+(?:POST|PUT|PATCH|DELETE)\b|"
    r"\bexport\s+default\s+(?:async\s+)?function\s+handler\b|Deno\.serve\s*\(|\bserve\s*\(\s*async"
)
MUTATING_EXPORT_RE = re.compile(r"\bexport\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b")
AUTH_HINT_RE = re.compile(
    r"(?i)\bauth\s*\(|getServerSession|getSession|currentUser|getUser\s*\(|getAuth\s*\(|requireAuth|requireUser|"
    r"isAuthenticated|withAuth|clerk|verifyToken|verifyIdToken|jwt\.verify|jwtVerify|supabase\.auth|"
    r"authorization|x-api-key|getToken|passport\.authenticate|ensureLoggedIn|constructEvent|verifySignature|"
    r"verify_signature|webhook|Depends\s*\(\s*get_current|login_required|current_user|@require|unauthori[sz]ed|"
    r"status\s*[:=(]\s*40[13]|\b40[13]\b|session"
)
RATE_LIMIT_HINT_RE = re.compile(
    r"(?i)rate[\s_\-]?limit|ratelimit|limiter|throttl|slowapi|slowDown|upstash|quota|leakybucket|tokenbucket"
)
LLM_CALL_RE = re.compile(
    r"""(?x)
    from\s+['"](?:openai|@anthropic-ai/sdk|@ai-sdk/[\w-]+|ai|groq-sdk|@google/generative-ai|@google/genai|
        @mistralai/mistralai|replicate|together-ai|@openrouter/[\w-]+|@xai-org/[\w-]+)['"]
    | require\(\s*['"](?:openai|@anthropic-ai/sdk|groq-sdk|replicate)['"]\s*\)
    | api\.openai\.com | api\.anthropic\.com | api\.x\.ai | openrouter\.ai/api | generativelanguage\.googleapis\.com
    | api\.groq\.com | api\.mistral\.ai | api\.deepseek\.com
    | ^\s*(?:import\s+(?:openai|anthropic)|from\s+(?:openai|anthropic|litellm)\s+import)
    """,
    re.M,
)
ENV_FILE_RE = re.compile(r"^\.env(?:\.[A-Za-z0-9_\-]+)*$")
ENV_EXAMPLE_RE = re.compile(r"(?i)\.(?:example|sample|template|dist|defaults?|schema|tpl)$")
ENV_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
SECRET_VAR_NAME_RE = re.compile(r"(?i)secret|token|password|passwd|private|api_?key|access_?key|_key$|database_url|dsn|credential")


def _read_text(path, limit=512 * 1024):
    try:
        if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            return ""
        with open(path, "rb") as handle:
            data = handle.read(limit)
    except OSError:
        return ""
    if b"\0" in data[:4096]:
        return ""
    return data.decode("utf-8", "replace")


def _line_of(text, index):
    return text.count("\n", 0, index) + 1


def _strip_line_comments(text):
    # Good enough for hint matching: drop // and # comments and /* */ blocks.
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"(?m)(^|\s)(?://|#).*$", r"\1", text)


def jwt_role(token):
    """The 'role' claim of a JWT-shaped string, or ''. Used to spot a Supabase service_role key."""
    match = JWT_RE.search(token or "")
    if not match:
        return ""
    body = match.group(1)
    try:
        import base64
        decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace")
        claims = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return ""
    return str(claims.get("role") or "") if isinstance(claims, dict) else ""


def project_flags(root):
    flags = set()
    for name in ("vite.config.js", "vite.config.ts", "vite.config.mjs", "vite.config.mts"):
        if (root / name).exists():
            flags.add("vite")
    pkg = _read_text(root / "package.json", 256 * 1024)
    if '"expo"' in pkg or (root / "app.json").exists() and '"expo"' in _read_text(root / "app.json", 64 * 1024):
        flags.add("expo")
    if '"next"' in pkg:
        flags.add("next")
    if (root / "supabase").is_dir() or "@supabase/" in pkg:
        flags.add("supabase")
    for name in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"):
        text = _read_text(root / name, 64 * 1024)
        if text and AUTH_HINT_RE.search(text):
            flags.add("auth-middleware")
    return flags


def is_client_file(rel, text, flags):
    parts = rel.split("/")
    lower = rel.lower()
    suffix = Path(rel).suffix.lower()
    if any(part in SERVER_DIRS for part in parts[:-1]) or ROUTE_PATH_RE.search(rel):
        return False
    if re.search(r"(?:^|/)(?:server|actions?)\.[cm]?[jt]sx?$|\.server\.[cm]?[jt]sx?$", lower):
        return False
    head = text[:300]
    if re.search(r"""^\s*['"]use server['"]""", head, re.M):
        return False
    if re.search(r"""^\s*['"]use client['"]""", head, re.M):
        return True
    if suffix in CLIENT_SUFFIXES:
        return True
    if suffix not in {".js", ".mjs", ".jsx", ".ts", ".tsx"}:
        return False
    if any(part in CLIENT_DIRS for part in parts[:-1]):
        return True
    if "vite" in flags and parts[0] == "src":
        return True
    if "expo" in flags and parts[0] in {"app", "src", "screens", "components"}:
        return True
    return False


def _check_lead(rule, severity, rel, line, message, kind="code", secrets=None):
    lead = make_lead(
        "sab-checks", f"sab.{rule}", severity, rel, line, message,
        fingerprint_for("sab-checks", rule, rel, line), secrets=secrets,
    )
    return tag_lead(lead, kind)


def check_env_file(rel, name, text):
    leads = []
    if not ENV_FILE_RE.match(name):
        return leads
    if ENV_EXAMPLE_RE.search(name):
        return leads
    has_secret = False
    debug_line = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        match = ENV_ASSIGN_RE.match(raw)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip().strip("'\"")
        if value and SECRET_VAR_NAME_RE.search(key) and not re.fullmatch(r"(?i)(changeme|xxx+|your[_\-].*|<.*>|\$\{.*\}|placeholder|todo|none|null|false|true)", value):
            has_secret = True
        if key == "APP_DEBUG" and value.lower() in {"true", "1", "on", "yes"}:
            debug_line = number
    leads.append(_check_lead(
        "committed-env-file", "high" if has_secret else "low", rel, 1,
        "An environment file is in the tree. In a fresh clone that means it is committed. "
        + ("It assigns secret-looking variables; rotate them and remove the file from git history." if has_secret
           else "Confirm it holds no real values, then add it to .gitignore."),
    ))
    if debug_line:
        leads.append(_check_lead(
            "app-debug-true", "medium", rel, debug_line,
            "APP_DEBUG is true in a committed env file. If this reaches production, error pages show stack traces and config.",
        ))
    return leads


def check_public_env_names(rel, text, is_env):
    """Public-prefixed variables (shipped to every browser) that look like secrets."""
    leads = []
    seen = set()
    for match in PUBLIC_ENV_RE.finditer(text):
        name = match.group(1)
        rest = name.split("_", 1)[1] if name.startswith("PUBLIC_") else name[len(next(p for p in PUBLIC_ENV_PREFIXES if name.startswith(p))):]
        line = _line_of(text, match.start())
        value_secret = ""
        if is_env:
            line_text = text.splitlines()[line - 1] if line - 1 < len(text.splitlines()) else ""
            assign = ENV_ASSIGN_RE.match(line_text)
            if assign and assign.group(1) == name:
                value = assign.group(2).strip().strip("'\"")
                if any(pattern.search(value) for _, _, pattern in CLIENT_SECRET_LITERALS) or jwt_role(value) == "service_role":
                    value_secret = value
        named_secret = SECRETISH_NAME_RE.search(rest) and not PUBLIC_BY_DESIGN_RE.search(rest)
        if not (named_secret or value_secret) or name in seen:
            continue
        seen.add(name)
        why = "holds a secret-format value" if value_secret else "has a secret-looking name"
        leads.append(_check_lead(
            "secret-in-public-env", "high", rel, line,
            f"{name} {why}. Variables with this prefix are bundled into the client and readable by anyone. "
            "Move it to a server-only variable, call the provider from the server, and rotate the key.",
            kind="secret" if value_secret else "code", secrets=[value_secret] if value_secret else None,
        ))
    return leads


def check_client_secrets(rel, text):
    leads = []
    for rule, label, pattern in CLIENT_SECRET_LITERALS:
        for match in pattern.finditer(text):
            leads.append(_check_lead(
                f"client-{rule}", "critical", rel, _line_of(text, match.start()),
                f"{label} in client-side code. Anyone who loads the app can copy it. Rotate it now and call the provider from a server route.",
                kind="secret", secrets=[match.group(0)],
            ))
            break
    for match in JWT_RE.finditer(text):
        if jwt_role(match.group(0)) == "service_role":
            leads.append(_check_lead(
                "client-supabase-service-role", "critical", rel, _line_of(text, match.start()),
                "Supabase service_role key in client-side code. It bypasses row level security for every table. Rotate it and use the anon key in the client.",
                kind="secret", secrets=[match.group(0)],
            ))
            break
    match = re.search(r"\b[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*\b", text)
    if match and not PUBLIC_ENV_RE.match(match.group(0)):
        leads.append(_check_lead(
            "client-service-role-ref", "high", rel, _line_of(text, match.start()),
            f"Client-side file reads {match.group(0)}. The service_role key must stay on the server.",
        ))
    return leads


def check_jwt_anywhere(rel, text):
    for match in JWT_RE.finditer(text):
        if jwt_role(match.group(0)) == "service_role":
            return [_check_lead(
                "supabase-service-role-committed", "high", rel, _line_of(text, match.start()),
                "A Supabase service_role key is committed. Rotate it in the Supabase dashboard and load it from a server-only variable.",
                kind="secret", secrets=[match.group(0)],
            )]
    return []


_SQL_IDENT = r'(?:"?(?P<schema>[A-Za-z_][\w]*)"?\.)?"?(?P<table>[A-Za-z_][\w]*)"?'


def check_supabase_sql(sql_files):
    """Tables created in the public schema with no 'enable row level security' anywhere in the migrations."""
    created = {}
    rls = set()
    leads = []
    for rel, text in sql_files:
        clean = re.sub(r"--[^\n]*", "", text)
        clean = re.sub(r"/\*.*?\*/", " ", clean, flags=re.S)
        for match in re.finditer(r"(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?" + _SQL_IDENT, clean):
            schema = (match.group("schema") or "public").lower()
            if schema != "public":
                continue
            table = match.group("table").lower()
            created.setdefault(table, (rel, _line_of(clean, match.start())))
        for match in re.finditer(
            r"(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + _SQL_IDENT + r"\s+(enable|disable|force)\s+row\s+level\s+security",
            clean,
        ):
            table = match.group("table").lower()
            if match.group(3).lower() == "disable":
                rls.discard(table)
                leads.append(_check_lead(
                    "supabase-rls-disabled", "high", rel, _line_of(clean, match.start()),
                    f"Row level security is turned off for table {table}. With the anon key, anyone can read and write it.",
                ))
            else:
                rls.add(table)
        for match in re.finditer(
            r"(?is)\bcreate\s+policy\s+.{0,200}?\bon\s+" + _SQL_IDENT + r"(?P<body>.{0,300}?);",
            clean,
        ):
            body = match.group("body")
            if re.search(r"(?i)\b(using|with\s+check)\s*\(\s*true\s*\)", body) and not re.search(r"(?i)\bfor\s+select\b", body):
                leads.append(_check_lead(
                    "supabase-policy-allows-all", "medium", rel, _line_of(clean, match.start()),
                    f"A write policy on {match.group('table').lower()} uses true, so any caller passes it. Check that this is intended.",
                ))
    for table, (rel, line) in sorted(created.items()):
        if table not in rls:
            leads.append(_check_lead(
                "supabase-table-without-rls", "high", rel, line,
                f"Table {table} is created in the public schema and no migration enables row level security on it. "
                "With the anon key, anyone can read and write it. Add: alter table " + table + " enable row level security; then add policies.",
            ))
    return leads


def check_firebase_rules(rel, name, text):
    leads = []
    if name == "database.rules.json" or (name.endswith(".json") and '".read"' in text and '"rules"' in text):
        for match in re.finditer(r'"\.(read|write)"\s*:\s*(?:true|"true")', text):
            leads.append(_check_lead(
                "firebase-rtdb-open", "high", rel, _line_of(text, match.start()),
                f"Realtime Database rules allow {match.group(1)} for everyone. Require request auth and scope rules to the user.",
            ))
        return leads
    if not (name.endswith(".rules") or "service cloud.firestore" in text or "service firebase.storage" in text):
        return leads
    clean = re.sub(r"//[^\n]*", "", text)
    patterns = (
        (r"\ballow\s+[a-z ,]+:\s*if\s+true\s*;", "rules allow access for everyone (if true)"),
        (r"\ballow\s+[a-z ,]+\s*;", "rules allow access with no condition"),
        (r"request\.time\s*<\s*timestamp\.date\s*\(", "rules are in test mode: open to everyone until a date"),
    )
    for pattern, label in patterns:
        for match in re.finditer(pattern, clean):
            leads.append(_check_lead(
                "firebase-rules-open", "high", rel, _line_of(clean, match.start()),
                f"Firebase {label}. Require request.auth and match the user's own documents.",
            ))
    return leads


def check_route(rel, text, flags):
    """API and LLM routes with no visible auth check, and LLM routes with no rate limit."""
    code = _strip_line_comments(text)
    is_route = bool(ROUTE_PATH_RE.search(rel)) or bool(SERVER_ROUTE_RE.search(code))
    if not is_route:
        return []
    has_auth = bool(AUTH_HINT_RE.search(code))
    calls_llm = bool(LLM_CALL_RE.search(code))
    middleware = "auth-middleware" in flags and ROUTE_PATH_RE.search(rel)
    note = " A middleware file has auth code; check its matcher covers this route." if middleware else ""
    if calls_llm:
        line = _line_of(code, LLM_CALL_RE.search(code).start())
        if not has_auth:
            return [_check_lead(
                "llm-route-no-auth", "low" if middleware else "high", rel, line,
                "This route calls an AI provider with your key and has no visible auth check. Anyone who finds it can spend your credits. "
                "Require a signed-in user, and add a per-user rate limit." + note,
            )]
        if not RATE_LIMIT_HINT_RE.search(code):
            return [_check_lead(
                "llm-route-no-rate-limit", "medium", rel, line,
                "This route calls an AI provider and has no visible rate limit. One account can run up the bill. Add a per-user limit.",
            )]
        return []
    if has_auth:
        return []
    mutating = MUTATING_EXPORT_RE.search(code) or re.search(
        r"\b(?:app|router|server|api|fastify)\.(?:post|put|patch|delete)\s*\(|@(?:app|router|api)\.(?:post|put|patch|delete)\s*\(|methods\s*=\s*\[[^\]]*['\"](?:POST|PUT|PATCH|DELETE)", code
    )
    if not mutating:
        return []
    return [_check_lead(
        "api-route-no-auth", "low" if middleware else "medium", rel, _line_of(code, mutating.start()),
        "This route changes data and has no visible auth check. Confirm it is meant to be public; if not, require a signed-in user." + note,
    )]


def check_php(rel, text):
    leads = []
    match = re.search(r"(?<![\w>$])phpinfo\s*\(", _strip_line_comments(text))
    if match:
        leads.append(_check_lead(
            "phpinfo-exposed", "medium", rel, _line_of(_strip_line_comments(text), match.start()),
            "phpinfo() prints server configuration and environment variables. Delete the file or the call.",
        ))
    if rel.endswith("config/app.php"):
        match = re.search(r"['\"]debug['\"]\s*=>\s*true\b", text)
        if match:
            leads.append(_check_lead(
                "app-debug-true", "medium", rel, _line_of(text, match.start()),
                "Laravel debug is hard-coded to true. Use env('APP_DEBUG', false).",
            ))
    return leads


def run_builtin_checks(root, limit=20000):
    root = Path(root)
    flags = project_flags(root)
    leads = []
    sql_files = []
    for path in iter_files(root, limit=limit):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        name = path.name
        suffix = path.suffix.lower()
        is_env = bool(ENV_FILE_RE.match(name))
        if not (is_env or suffix in TEXT_SUFFIXES or name in {"firestore.rules", "storage.rules"}):
            continue
        text = _read_text(path)
        if not text:
            continue
        if is_env:
            leads.extend(check_env_file(rel, name, text))
            leads.extend(check_public_env_names(rel, text, is_env=True))
            continue
        if suffix == ".sql" and "supabase" in flags:
            sql_files.append((rel, text))
            continue
        if suffix in {".rules", ".json"}:
            leads.extend(check_firebase_rules(rel, name, text))
            continue
        if suffix == ".php":
            leads.extend(check_php(rel, text))
        if suffix in {".yml", ".yaml", ".toml"}:
            continue
        client = is_client_file(rel, text, flags)
        if client:
            leads.extend(check_client_secrets(rel, text))
        else:
            leads.extend(check_jwt_anywhere(rel, text))
        leads.extend(check_public_env_names(rel, text, is_env=False))
        if suffix in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py"}:
            leads.extend(check_route(rel, text, flags))
    leads.extend(check_supabase_sql(sql_files))
    return leads


def normalize_composer_audit(payload, root, lockfile):
    leads = []
    if not isinstance(payload, dict):
        return leads
    file = relativize(lockfile, root) if lockfile else "composer.lock"
    advisories = payload.get("advisories") or {}
    if isinstance(advisories, list):
        advisories = {str(index): item for index, item in enumerate(advisories)}
    for package, items in advisories.items() if isinstance(advisories, dict) else []:
        if isinstance(items, dict):
            items = list(items.values())
        for item in items or []:
            if not isinstance(item, dict):
                continue
            name = item.get("packageName") or package
            vid = item.get("advisoryId") or item.get("cve") or "advisory"
            ids = [vid, item.get("cve")]
            ids += re.findall(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", json.dumps(item.get("sources") or []))
            title = item.get("title") or vid
            versions = item.get("affectedVersions") or ""
            leads.append(tag_lead(make_lead(
                "composer-audit",
                vid,
                item.get("severity") or "medium",
                file,
                1,
                f"{name}: {title}" + (f" (affected {versions})" if versions else ""),
                fingerprint_for("composer-audit", vid, file, name),
            ), "dep", name, ids))
    return leads


def composer_dirs(root):
    found = []
    for path in iter_files(root):
        if path.name == "composer.lock":
            found.append(path.parent)
    return found


def run_composer_audit(root, runner, which_fn, env):
    binary = which_fn("composer")
    if not binary:
        return [], "composer not installed; osv-scanner and trivy read composer.lock instead"
    dirs = composer_dirs(root)
    if not dirs:
        return [], "no composer.lock"
    leads, notes = [], []
    for directory in dirs:
        # --no-plugins and --no-scripts: never run the project's Composer code.
        argv = [binary, "audit", "--locked", "--format=json", "--no-interaction", "--no-plugins", "--no-scripts",
                "--working-dir", str(directory)]
        result = runner(argv, timeout=TIMEOUTS["composer-audit"], cwd=str(directory), env=env)
        payload = parse_json_output(result.stdout)
        if payload is None:
            notes.append("timed out" if result.returncode == 124 else (_note_from_result(result, root) or "composer audit failed"))
            continue
        leads.extend(normalize_composer_audit(payload, root, directory / "composer.lock"))
    return leads, "; ".join(notes)


SOURCE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs", ".rb", ".java", ".kt",
    ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".scala", ".sh", ".tf", ".sql",
    ".vue", ".svelte", ".html",
}


def size_profile(root):
    """Rough size of the tree. Used to tell the owner what a full audit is likely to cost."""
    files = source_files = source_lines = 0
    for path in iter_files(root):
        files += 1
        if path.suffix.lower() not in SOURCE_SUFFIXES or path.is_symlink():
            continue
        source_files += 1
        try:
            with open(path, "rb") as handle:
                source_lines += handle.read(2 * 1024 * 1024).count(b"\n")
        except OSError:
            continue
    if source_lines < 5000:
        size_class = "small"
    elif source_lines < 50000:
        size_class = "medium"
    else:
        size_class = "large"
    return {"files": files, "source_files": source_files, "source_lines": source_lines, "class": size_class}


SIZE_ADVICE = {
    "small": "A full audit at the standard profile stays fairly small.",
    "medium": "A full audit is a long standard run; a budget or a scoped run keeps it bounded.",
    "large": "A full audit is heavy; propose a scoped run, or a budget, before a standard run.",
}


def load_baseline(path):
    if not path:
        return {"version": BASELINE_VERSION, "entries": []}
    source = Path(path)
    if not source.exists():
        return {"version": BASELINE_VERSION, "entries": []}
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError(f"{source.name} is not a baseline file")
    return data


def apply_baseline(leads, baseline):
    """Split leads into (kept, suppressed, stale entries). Entries match on stable key or fingerprint."""
    entries = [entry for entry in baseline.get("entries") or [] if isinstance(entry, dict)]
    by_key = {entry.get("key"): entry for entry in entries if entry.get("key")}
    by_fp = {entry.get("fingerprint"): entry for entry in entries if entry.get("fingerprint")}
    kept, suppressed, used = [], [], set()
    for lead in leads:
        entry = by_key.get(stable_key(lead)) or by_fp.get(lead["fingerprint"])
        if entry is None:
            kept.append(lead)
            continue
        used.add(id(entry))
        item = dict(lead)
        item["accepted_reason"] = entry.get("reason", "")
        item["accepted_at"] = entry.get("accepted_at", "")
        suppressed.append(item)
    stale = [entry for entry in entries if id(entry) not in used]
    return kept, suppressed, stale


def compare_with_previous(leads, previous_doc, tool_rows):
    """Mark leads new or unchanged and list previous leads that are gone.

    A previous lead only counts as resolved when its tool ran cleanly this time and was not capped.
    """
    previous = [lead for lead in (previous_doc.get("leads") or []) if isinstance(lead, dict)]
    previous += [lead for lead in (previous_doc.get("suppressed") or []) if isinstance(lead, dict)]
    prev_keys = {stable_key(lead) for lead in previous}
    current_keys = set()
    for lead in leads:
        key = stable_key(lead)
        current_keys.add(key)
        lead["change"] = "unchanged" if key in prev_keys else "new"
    reliable = {
        row["tool"] for row in tool_rows
        if row["status"] == "ok" and "capped" not in (row.get("note") or "")
    }
    resolved, unverified = [], []
    for lead in previous:
        if stable_key(lead) in current_keys:
            continue
        tools = {lead.get("tool"), *(lead.get("also_reported_by") or [])}
        public = {key: lead.get(key) for key in ("tool", "rule", "severity", "file", "line", "message", "fingerprint")}
        (resolved if tools & reliable else unverified).append(public)
    return resolved, unverified


def _lead_line(lead):
    also = f" (also {', '.join(lead['also_reported_by'])})" if lead.get("also_reported_by") else ""
    change = f" [{lead['change']}]" if lead.get("change") else ""
    return (
        f"- {lead['severity']}{change} `{lead['tool']}`{also} {lead['file']}:{lead['line']} "
        f"{lead['rule']} — {lead['message']} ({lead['fingerprint'][7:19]})"
    )


def render_summary(target_name, ecosystems, tool_rows, leads, truncated, size=None,
                   suppressed=None, stale=None, comparison=None):
    lines = [
        "# Preflight summary",
        "",
        f"Target: {target_name}",
        "",
        "Scanner output is a set of leads. A lead is not a finding until the audit skill validates it.",
        "",
        "## Ecosystems",
        "",
    ]
    lines.append(", ".join(ecosystems) if ecosystems else "(none detected)")
    if "railway" in ecosystems:
        lines.extend([
            "",
            "Railway config found. Run `sab.py platform-check <target> --platform railway --out <run-dir>` for the "
            "October 2026 incident rotation checklist.",
        ])
    if size:
        lines.extend([
            "",
            "## Size",
            "",
            f"{size['source_files']} source files, about {size['source_lines']} lines ({size['files']} files in all). "
            f"Class: {size['class']}. {SIZE_ADVICE[size['class']]}",
        ])
    lines.extend(["", "## Tools", "", "| Tool | Status | Leads | Seconds | Note |", "| --- | --- | --- | --- | --- |"])
    for row in tool_rows:
        note = (row.get("note") or "").replace("|", "/")
        lines.append(f"| {row['tool']} | {row['status']} | {row['leads']} | {row.get('seconds', '')} | {note} |")
    missing = [row["tool"] for row in tool_rows if row["status"] != "ok" and row["tool"] in SCANNER_PURPOSE]
    if missing:
        lines.extend(["", "Not covered this run:"])
        for name in missing:
            lines.append(f"- {name}: {SCANNER_PURPOSE[name]}")
    if truncated:
        lines.extend(["", "## Truncated", ""])
        for tool, count in sorted(truncated.items()):
            lines.append(f"- {tool}: dropped {count} lower-severity leads (cap {PER_TOOL_CAP})")
    counts = Counter(lead["severity"] for lead in leads)
    lines.extend(["", "## Lead counts", ""])
    lines.append(", ".join(f"{name} {counts[name]}" for name in SEVERITY_RANK if counts[name]) or "none")
    merged = sum(1 for lead in leads if lead.get("also_reported_by"))
    if merged:
        lines.append(f"{merged} leads were reported by more than one scanner and are listed once.")
    if comparison is not None:
        resolved, unverified = comparison
        new = sum(1 for lead in leads if lead.get("change") == "new")
        lines.extend([
            "",
            "## Changes since the previous run",
            "",
            f"{new} new, {len(leads) - new} unchanged, {len(resolved)} gone. "
            "A gone lead is not proof of a fix; re-check the finding in source.",
        ])
        for lead in resolved[:15]:
            lines.append(f"- gone: `{lead['tool']}` {lead['file']}:{lead['line']} {lead['rule']}")
        if unverified:
            lines.append(f"{len(unverified)} previous leads were not re-checked because their scanner did not run cleanly.")
    if suppressed:
        lines.extend(["", "## Accepted in baseline", "", f"{len(suppressed)} leads hidden by the baseline:"])
        for lead in suppressed[:15]:
            lines.append(f"- `{lead['tool']}` {lead['file']}:{lead['line']} {lead['rule']} — {lead['accepted_reason']}")
    if stale:
        lines.append(f"{len(stale)} baseline entries matched nothing this run; they may be safe to remove.")
    lines.extend(["", "## Top leads", ""])
    if not leads:
        lines.append("No leads.")
    else:
        ordered = sorted(leads, key=lambda lead: (0 if lead.get("change") == "new" else 1, SEVERITY_RANK[lead["severity"]]))
        for lead in ordered[:15]:
            lines.append(_lead_line(lead))
    lines.append("")
    return "\n".join(lines)


def run_preflight(repo_path, out_dir, which_fn=which, runner=run_cmd, cap=PER_TOOL_CAP,
                  baseline_path=None, previous_path=None, cache_dir=None):
    root = assert_safe_repo(repo_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    baseline = load_baseline(baseline_path)
    previous_doc = None
    if previous_path:
        previous_doc = json.loads(Path(previous_path).read_text(encoding="utf-8"))
        if not isinstance(previous_doc, dict):
            raise ValueError("previous scanner-leads.json is not a preflight document")
    ecosystems = detect_ecosystems(root)
    size = size_profile(root)
    selected = applicable_scanners(ecosystems)
    tool_home = out / ".tool-home"
    (tool_home / "config").mkdir(parents=True, exist_ok=True)
    env = scanner_env(tool_home, cache=cache_dir or scanner_cache_dir())
    leads = []
    tool_rows = []
    try:
        for name in selected:
            started = time.monotonic()
            try:
                found, note = execute_scanner(name, root, runner, which_fn, env, ecosystems)
            except Exception as exc:  # noqa: BLE001 — one scanner must not abort the rest
                found, note = [], clean_message(scrub_paths(str(exc), root)) or "failed"
            note = scrub_paths(note or "", root)
            if found:
                status = "ok"
            elif note and (
                "not installed" in note or note.startswith("no ") or "left to osv-scanner" in note
            ):
                status = "skipped"
            elif note:
                status = "error"
            else:
                status = "ok"
            leads.extend(found)
            tool_rows.append({
                "tool": name, "status": status, "leads": len(found), "note": note or "",
                "seconds": round(time.monotonic() - started, 1),
            })
    finally:
        shutil.rmtree(tool_home, ignore_errors=True)
    leads = merge_cross_tool(dedupe_leads(leads))
    leads, suppressed, stale = apply_baseline(leads, baseline)
    leads, truncated = cap_leads(leads, cap=cap)
    for row in tool_rows:
        row["leads"] = sum(1 for lead in leads if lead["tool"] == row["tool"])
        if truncated.get(row["tool"]):
            extra = f"capped, dropped {truncated[row['tool']]}"
            row["note"] = "; ".join(part for part in (row["note"], extra) if part)
    comparison = compare_with_previous(leads, previous_doc, tool_rows) if previous_doc is not None else None
    public = [public_lead(lead) for lead in leads]
    document = {
        "version": VERSION,
        "target_name": root.name,
        "ecosystems": ecosystems,
        "size": size,
        "tools": tool_rows,
        "leads": public,
        "truncated": truncated,
        "suppressed": [
            {**public_lead(lead), "accepted_reason": lead["accepted_reason"], "accepted_at": lead["accepted_at"]}
            for lead in suppressed
        ],
        "baseline_stale": stale,
    }
    if comparison is not None:
        document["resolved"], document["not_rechecked"] = comparison
    (out / "scanner-leads.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    summary = render_summary(root.name, ecosystems, tool_rows, public, truncated, size=size,
                             suppressed=document["suppressed"], stale=stale, comparison=comparison)
    (out / "preflight-summary.md").write_text(summary, encoding="utf-8")
    return document


# ---------------------------------------------------------------------------
# Platform check (`sab.py platform-check --platform railway`). Repository-only:
# it lists the env vars the code reads as a rotation checklist, flags hardcoded
# secrets and public database hosts, and prints the owner's dashboard steps.
# It never contacts the platform or any provider. Only Railway is built.
# ---------------------------------------------------------------------------

RAILWAY_FILES = {"railway.json", "railway.toml", "nixpacks.toml"}
ENV_REF_PATTERNS = (
    re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"process\.env\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]"),
    re.compile(r"import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"(?:Deno\.env\.get|Bun\.env\.get)\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"Bun\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"os\.environ\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"(?:os\.environ\.get|os\.getenv|environ\.get)\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"(?<![\w>])getenv\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"\$_ENV\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"(?<![\w>$:])env\(\s*['\"]([A-Z_][A-Z0-9_]*)['\"]"),
    re.compile(r"ENV(?:\.fetch\(|\[)\s*['\"]([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"os\.(?:Getenv|LookupEnv)\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\""),
    re.compile(r"env::var(?:_os)?\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\""),
    re.compile(r"System\.getenv\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\""),
    re.compile(r"Environment\.GetEnvironmentVariable\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\""),
)
ENV_DESTRUCTURE_RE = re.compile(r"\{([^{}]{1,600})\}\s*=\s*(?:process\.env|import\.meta\.env)\b")
COMPOSE_REF_RE = re.compile(r"\$\{\{?\s*(?:shared\.|[A-Za-z0-9_-]+\.)?([A-Z][A-Z0-9_]*)\s*(?::-[^}]*)?\}\}?")
CI_SECRET_RE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
NOT_SECRET_NAMES = {
    "NODE_ENV", "PORT", "HOST", "HOSTNAME", "PWD", "HOME", "PATH", "TZ", "CI", "DEBUG", "LOG_LEVEL", "ENV",
    "ENVIRONMENT", "APP_ENV", "APP_NAME", "APP_URL", "NODE_OPTIONS", "PYTHONPATH", "LANG", "USER", "SHELL",
    "TERM", "BASE_URL", "PUBLIC_URL", "SITE_URL", "NEXT_RUNTIME", "VERCEL_ENV", "VERCEL_URL", "MODE", "DEV",
    "PROD", "SSR", "APP_DEBUG", "GITHUB_ACTIONS", "GITHUB_SHA", "GITHUB_REF", "GITHUB_REPOSITORY", "RUNNER_OS",
}
# Name pattern -> group. First match wins, so order matters.
ENV_GROUPS = (
    ("platform", re.compile(r"^RAILWAY_(?:API_)?TOKEN$|^(?:VERCEL|NETLIFY|FLY_API|RENDER_API|HEROKU_API|CLOUDFLARE_API)_?(?:TOKEN|KEY)")),
    ("ai", re.compile(r"OPENAI|ANTHROPIC|CLAUDE|XAI|GROK|OPENROUTER|GROQ|GEMINI|GOOGLE_GENERATIVE|GOOGLE_AI|MISTRAL|"
                      r"REPLICATE|ELEVENLABS|DEEPSEEK|PERPLEXITY|COHERE|TOGETHER|HUGGING|^HF_|FIREWORKS|VOYAGE|PINECONE|"
                      r"LANGCHAIN|LANGSMITH|AI_GATEWAY|AZURE_OPENAI|DEEPGRAM|ASSEMBLYAI|FAL_KEY|^FAL_|RUNWAY|LUMA")),
    ("database", re.compile(r"DATABASE|_DB_|^DB_|POSTGRES|^PG[A-Z]|MYSQL|MARIADB|MONGO|REDIS|UPSTASH|NEON|TURSO|LIBSQL|"
                            r"SUPABASE_SERVICE|SUPABASE_SECRET|SUPABASE_DB|PLANETSCALE|COCKROACH|CLICKHOUSE|ELASTIC|"
                            r"KV_REST|KV_URL|^KV_")),
    ("cloud", re.compile(r"^AWS_|^S3_|_S3_|BUCKET|^R2_|_R2_|CLOUDFLARE|^GCS_|^GCP_|GOOGLE_APPLICATION_CREDENTIALS|"
                         r"GOOGLE_CLOUD|FIREBASE_(?:ADMIN|SERVICE|PRIVATE)|AZURE_|CLOUDINARY|UPLOADTHING|BLOB_READ_WRITE|"
                         r"^ACCESS_KEY_ID$|^SECRET_ACCESS_KEY$|SPACES_|^B2_|BACKBLAZE|MINIO")),
    ("payment", re.compile(r"STRIPE|PAYPAL|LEMON_?SQUEEZY|PADDLE|BRAINTREE|SQUARE_|RAZORPAY|POLAR_|REVENUECAT|COINBASE")),
    ("github", re.compile(r"GITHUB|^GH_|GHCR|DOCKER|REGISTRY|NPM_TOKEN|NODE_AUTH_TOKEN|GITLAB|BITBUCKET|CR_PAT")),
    ("auth", re.compile(r"JWT|SESSION|NEXTAUTH|AUTH_SECRET|^AUTH_|BETTER_AUTH|CLERK|AUTH0|LUCIA|KINDE|WORKOS|STYTCH|"
                        r"FIREBASE|SUPABASE_JWT|APP_KEY|^SECRET_KEY$|SECRET_KEY_BASE|COOKIE|OAUTH|CLIENT_SECRET|"
                        r"ENCRYPTION_KEY|SIGNING|HMAC|PRIVATE_KEY|PASSPORT|DJANGO_SECRET|FLASK_SECRET")),
    ("messaging", re.compile(r"RESEND|SENDGRID|MAILGUN|POSTMARK|SMTP|MAIL_PASSWORD|TWILIO|SLACK|DISCORD|TELEGRAM|"
                             r"PUSHER|ONESIGNAL|EXPO_ACCESS|NOVU|LOOPS|BREVO|SES_")),
    ("other", re.compile(r"KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS$|PRIVATE|CREDENTIAL|DSN|WEBHOOK|SALT|API_")),
)
ENV_GROUP_TITLES = {
    "ai": "AI provider keys",
    "database": "Database URLs and passwords",
    "cloud": "Cloud and storage bucket keys",
    "payment": "Payment keys",
    "auth": "Auth, session, and JWT secrets",
    "github": "GitHub and container registry tokens",
    "platform": "Deploy platform tokens",
    "messaging": "Email, SMS, and chat keys",
    "other": "Other secrets",
}
ENV_GROUP_ORDER = ("ai", "database", "cloud", "payment", "auth", "github", "platform", "messaging", "other")
# Where to rotate, for providers with a stable, well-known page. Name pattern -> (provider, URL).
ROTATE_LINKS = (
    (r"OPENAI", "OpenAI", "https://platform.openai.com/api-keys"),
    (r"ANTHROPIC|CLAUDE", "Anthropic", "https://console.anthropic.com/settings/keys"),
    (r"XAI|GROK", "xAI", "https://console.x.ai"),
    (r"OPENROUTER", "OpenRouter", "https://openrouter.ai/settings/keys"),
    (r"GROQ", "Groq", "https://console.groq.com/keys"),
    (r"GEMINI|GOOGLE_GENERATIVE|GOOGLE_AI", "Google AI Studio", "https://aistudio.google.com/app/apikey"),
    (r"MISTRAL", "Mistral", "https://console.mistral.ai/api-keys"),
    (r"REPLICATE", "Replicate", "https://replicate.com/account/api-tokens"),
    (r"HUGGING|^HF_", "Hugging Face", "https://huggingface.co/settings/tokens"),
    (r"ELEVENLABS", "ElevenLabs", "https://elevenlabs.io/app/settings/api-keys"),
    (r"STRIPE", "Stripe", "https://dashboard.stripe.com/apikeys"),
    (r"SUPABASE", "Supabase", "https://supabase.com/dashboard/project/_/settings/api-keys"),
    (r"CLERK", "Clerk", "https://dashboard.clerk.com"),
    (r"^AWS_|^S3_|_S3_", "AWS IAM", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    (r"CLOUDFLARE|^R2_|_R2_", "Cloudflare", "https://dash.cloudflare.com/profile/api-tokens"),
    (r"GITHUB|^GH_|GHCR|CR_PAT", "GitHub", "https://github.com/settings/tokens"),
    (r"DOCKER", "Docker Hub", "https://app.docker.com/settings/personal-access-tokens"),
    (r"RESEND", "Resend", "https://resend.com/api-keys"),
    (r"SENDGRID", "SendGrid", "https://app.sendgrid.com/settings/api_keys"),
    (r"TWILIO", "Twilio", "https://console.twilio.com"),
    (r"^RAILWAY_(?:API_)?TOKEN$", "Railway", "https://railway.com/account/tokens"),
    (r"VERCEL", "Vercel", "https://vercel.com/account/tokens"),
)
RAILWAY_PROVIDED = re.compile(r"^RAILWAY_(?!(?:API_)?TOKEN$)")
RAILWAY_HOST_RE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:proxy\.rlwy\.net|railway\.app|railway\.internal|up\.railway\.app)\b")
PUBLIC_PROXY_RE = re.compile(r"\b[a-z0-9-]+\.proxy\.rlwy\.net\b|\bcontainers-[a-z0-9-]+\.railway\.app\b")
DB_URL_RE = re.compile(
    r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://([^\s:/'\"@]+):([^\s@'\"]+)@([^\s/:'\"?]+)"
)
PUBLIC_DB_VAR_RE = re.compile(r"\b((?:DATABASE|POSTGRES|PG|MYSQL|MONGO|REDIS)[A-Z_]*_PUBLIC_URL|DATABASE_PUBLIC_URL)\b")
DEV_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "db", "postgres", "mysql", "redis", "mongo", "example.com"}

RAILWAY_GUIDANCE = {
    "title": "Railway check",
    "sources": [
        "https://blog.railway.com/p/preliminary-report-october-security-incident",
        "https://railway.com/changelog/2026-10-23-october-21-security-incident.md",
        "https://blog.railway.com/p/security-disclosure-recommendation-redeploy-buckets-and-reconnect-github-after-the-credential-reset",
    ],
    "why": (
        "Railway reported a security incident between Oct 20 and Oct 22, 2026. An attacker looking for AI provider API keys "
        "may have decrypted some customers' environment variables. Railway recommends rotating every sensitive credential "
        "stored on Railway before Oct 21, 2026, even if you were not notified."
    ),
    "owner_steps": [
        "Rotate every sensitive variable stored on Railway before Oct 21, 2026. Use the rotation checklist above. Create the new key, "
        "paste it into the service's Variables tab, redeploy, then delete the old key at the provider. A key a provider already "
        "revoked still needs a new one.",
        "Remove public network access to databases. In each database service, open Settings, Networking, and remove the public "
        "TCP proxy. Connect apps over the private network (`*.railway.internal`, the `DATABASE_URL` variable, not `DATABASE_PUBLIC_URL`).",
        "Review GitHub access. Read your security log (https://github.com/settings/security-log) and, for an organization, its audit "
        "log. Review installed apps (https://github.com/settings/installations) and authorized OAuth apps "
        "(https://github.com/settings/applications). Remove anything you do not recognize. Reconnect the Railway app when asked.",
        "Revoke old GitHub registry tokens. Railway removed the GitHub tokens it stored as registry credentials, but those tokens "
        "still work on GitHub until you revoke them. Delete them at https://github.com/settings/tokens, create a new one with only "
        "`read:packages`, paste it under the service's Settings, Source, Registry Credentials, and redeploy.",
        "Check container registry audit logs (GitHub Container Registry, Docker Hub, others) for pushes, pulls, or new tokens you "
        "did not make between Oct 20 and Oct 22, 2026.",
        "Storage buckets: Railway reset the S3 keys (`ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`) for every bucket. Redeploy each service "
        "that reads them so it picks up the new values. Rotate bucket keys you copied anywhere else.",
        "Railway API tokens and CLI sessions were revoked. Create new tokens, replace `RAILWAY_TOKEN` or `RAILWAY_API_TOKEN` in "
        "your CI secrets, and run `railway login` again.",
        "Read your workspace audit log in Railway. Resets done by Railway show the actor type Railway Staff. Export entries you "
        "want to keep.",
    ],
}
PLATFORMS = {"railway": RAILWAY_GUIDANCE}
LATER_PLATFORMS = ("vercel", "render", "fly")


def classify_env_var(name):
    if name in NOT_SECRET_NAMES:
        return "config"
    if RAILWAY_PROVIDED.match(name):
        return "provided"
    if name.startswith(PUBLIC_ENV_PREFIXES):
        rest = name[len(next(p for p in PUBLIC_ENV_PREFIXES if name.startswith(p))):]
        if SECRETISH_NAME_RE.search(rest) and not PUBLIC_BY_DESIGN_RE.search(rest):
            return "public-secret"
        return "public"
    for group, pattern in ENV_GROUPS:
        if pattern.search(name):
            if group == "database" and re.search(r"(?:_|^)(?:NAME|PORT|HOST|USER|SSL|POOL|SCHEMA|TIMEOUT)$", name):
                return "config"
            return group
    return "config"


def rotate_link(name):
    for pattern, provider, url in ROTATE_LINKS:
        if re.search(pattern, name):
            return provider, url
    return "", ""


def collect_env_refs(root, limit=20000):
    """Env var name -> list of (file, line). Reads source, env templates, compose and Railway config, and CI workflows."""
    refs = {}
    ci = {}

    def add(store, name, rel, line):
        if len(name) < 2 or name.lower() == name:
            return
        store.setdefault(name, [])
        if len(store[name]) < 20:
            store[name].append((rel, line))

    for path in iter_files(root, limit=limit):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        name = path.name
        suffix = path.suffix.lower()
        is_env = bool(ENV_FILE_RE.match(name))
        workflow = "/.github/workflows/" in f"/{rel}" and suffix in {".yml", ".yaml"}
        compose = name in RAILWAY_FILES or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "Procfile"}
        if not (is_env or workflow or compose or suffix in SOURCE_SUFFIXES or suffix in {".mts", ".cts", ".astro"}):
            continue
        text = _read_text(path)
        if not text:
            continue
        if is_env:
            for number, raw in enumerate(text.splitlines(), start=1):
                match = ENV_ASSIGN_RE.match(raw)
                if match:
                    add(refs, match.group(1), rel, number)
            continue
        if workflow:
            for match in CI_SECRET_RE.finditer(text):
                add(ci, match.group(1), rel, _line_of(text, match.start()))
            continue
        if compose:
            for match in COMPOSE_REF_RE.finditer(text):
                add(refs, match.group(1), rel, _line_of(text, match.start()))
            continue
        for pattern in ENV_REF_PATTERNS:
            for match in pattern.finditer(text):
                add(refs, match.group(1), rel, _line_of(text, match.start()))
        for match in ENV_DESTRUCTURE_RE.finditer(text):
            line = _line_of(text, match.start())
            for part in match.group(1).split(","):
                token = part.strip().split(":")[0].split("=")[0].strip()
                if re.fullmatch(r"[A-Z][A-Z0-9_]+", token):
                    add(refs, token, rel, line)
    return refs, ci


def detect_railway(root, limit=20000):
    signals = []
    seen = set()
    for path in iter_files(root, limit=limit):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        name = path.name
        if name in RAILWAY_FILES:
            signals.append({"file": rel, "line": 1, "signal": f"{name} config file", "strength": "strong"})
            continue
        if name == "Procfile":
            signals.append({"file": rel, "line": 1, "signal": "Procfile (also used by Heroku and others)", "strength": "weak"})
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES | {".yml", ".yaml", ".toml", ".json", ".md", ".env", ".example"} and not ENV_FILE_RE.match(name):
            continue
        text = _read_text(path, 256 * 1024)
        if not text:
            continue
        for regex, label in (
            (re.compile(r"\bRAILWAY_[A-Z0-9_]+"), "reads a RAILWAY_* variable"),
            (RAILWAY_HOST_RE, "names a Railway host"),
            (re.compile(r"railway\s+(?:up|deploy|run|link)\b|railwayapp/cli|@railway/cli"), "uses the Railway CLI"),
        ):
            match = regex.search(text)
            if match and (rel, label) not in seen:
                seen.add((rel, label))
                if name.lower().endswith(".md") and label != "names a Railway host":
                    continue
                signals.append({"file": rel, "line": _line_of(text, match.start()), "signal": label,
                                "strength": "weak" if name.lower().endswith(".md") else "strong"})
    return signals


def find_db_exposure(root, limit=20000):
    """Committed DB URLs with passwords, Railway public proxy hosts, and code that reads *_PUBLIC_URL database vars."""
    items = []
    for path in iter_files(root, limit=limit):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        name = path.name
        suffix = path.suffix.lower()
        if not (ENV_FILE_RE.match(name) or suffix in TEXT_SUFFIXES or suffix in SOURCE_SUFFIXES or name in RAILWAY_FILES):
            continue
        text = _read_text(path)
        if not text:
            continue
        for match in DB_URL_RE.finditer(text):
            user, password, host = match.group(2), match.group(3), match.group(4).lower()
            if host in DEV_HOSTS or "." not in host or password.startswith(("$", "<", "{", "%")) or password.lower() in {"password", "pass", "secret", "postgres", "changeme"}:
                continue
            public = bool(PUBLIC_PROXY_RE.search(host))
            items.append({
                "file": rel, "line": _line_of(text, match.start()),
                "kind": "public-proxy-url-with-password" if public else "db-url-with-password",
                "severity": "critical" if public else "high",
                "message": (f"A {match.group(1)} connection string with a password is committed"
                            + (" and points at Railway's public TCP proxy." if public else ".")
                            + " Rotate the database password and load the URL from a variable."),
                "_secret": [password, match.group(0)],
            })
        for match in PUBLIC_PROXY_RE.finditer(text):
            line = _line_of(text, match.start())
            if any(item["file"] == rel and item["line"] == line for item in items):
                continue
            items.append({
                "file": rel, "line": line, "kind": "public-proxy-host", "severity": "medium",
                "message": "Names a Railway public TCP proxy host. Connect over the private network instead and remove the public proxy.",
            })
        for match in PUBLIC_DB_VAR_RE.finditer(text):
            if ENV_FILE_RE.match(name):
                continue
            items.append({
                "file": rel, "line": _line_of(text, match.start()), "kind": "public-db-variable", "severity": "medium",
                "message": f"Code reads {match.group(1)}, which goes through the public proxy. Use the private DATABASE_URL instead.",
            })
            break
    return items


def build_platform_report(root, platform_name="railway", which_fn=which, runner=run_cmd, cache_dir=None):
    root = assert_safe_repo(root)
    guidance = PLATFORMS[platform_name]
    signals = detect_railway(root)
    refs, ci = collect_env_refs(root)
    groups = {}
    for name, where in sorted(refs.items()):
        group = classify_env_var(name)
        provider, url = rotate_link(name)
        groups.setdefault(group, []).append({
            "name": name, "files": len({file for file, _ in where}), "first": f"{where[0][0]}:{where[0][1]}",
            "provider": provider, "rotate_url": url,
        })
    tool_home = Path(tempfile.mkdtemp(prefix="sab-platform-"))
    try:
        (tool_home / "config").mkdir(parents=True, exist_ok=True)
        env = scanner_env(tool_home, cache=cache_dir or scanner_cache_dir())
        secret_leads, gitleaks_note = execute_scanner("gitleaks", root, runner, which_fn, env)
    finally:
        shutil.rmtree(tool_home, ignore_errors=True)
    exposure = find_db_exposure(root)
    hardcoded = [
        {"rule": lead["rule"], "file": lead["file"], "line": lead["line"], "fingerprint": lead["fingerprint"]}
        for lead in secret_leads
    ]
    return {
        "version": VERSION,
        "platform": platform_name,
        "target_name": root.name,
        "detected": any(item["strength"] == "strong" for item in signals),
        "signals": signals[:30],
        "env_groups": groups,
        "ci_secrets": sorted(ci),
        "hardcoded_secrets": hardcoded,
        "gitleaks_note": gitleaks_note or "",
        "db_exposure": [{key: value for key, value in item.items() if not key.startswith("_")} for item in exposure],
        "sources": guidance["sources"],
    }


def _env_item_line(item):
    where = f"read in {item['files']} file{'s' if item['files'] != 1 else ''}, first at {item['first']}"
    link = f" Rotate: {item['provider']}, {item['rotate_url']}." if item["rotate_url"] else ""
    return f"- [ ] `{item['name']}` ({where}).{link}"


def render_platform_report(doc):
    guidance = PLATFORMS[doc["platform"]]
    groups = doc["env_groups"]
    rotate_count = sum(len(groups.get(group, [])) for group in ENV_GROUP_ORDER) + len(groups.get("public-secret", []))
    lines = [
        f"# {guidance['title']}",
        "",
        f"Target: {doc['target_name']}. This check reads the repository only. It does not contact Railway or any provider, "
        "and it never shows a secret value.",
        "",
        "## Why",
        "",
        guidance["why"],
        "",
        "Sources:",
    ]
    lines.extend(f"- {url}" for url in guidance["sources"])
    lines.extend(["", "## Railway in this repo", ""])
    if doc["signals"]:
        lines.append("Railway use detected." if doc["detected"] else "Only weak signals found. If you deploy on Railway, the checklist still applies.")
        for item in doc["signals"][:10]:
            lines.append(f"- {item['file']}:{item['line']} {item['signal']}")
    else:
        lines.append("No Railway signals found. If you deploy on Railway anyway, the checklist still applies.")
    lines.extend([
        "",
        f"## Rotation checklist ({rotate_count} variables)",
        "",
        "These are the variables the code reads. Rotate each one that was stored on Railway before Oct 21, 2026: create the new "
        "value at the provider, paste it into Railway, redeploy, then delete the old one.",
    ])
    if groups.get("public-secret"):
        lines.extend(["", "### Secret-looking variables with a public prefix (fix first)", "",
                      "These prefixes are bundled into the browser or app. Rotate them and move them to server-only names."])
        lines.extend(_env_item_line(item) for item in groups["public-secret"])
    for group in ENV_GROUP_ORDER:
        if groups.get(group):
            lines.extend(["", f"### {ENV_GROUP_TITLES[group]}", ""])
            lines.extend(_env_item_line(item) for item in groups[group])
    if not rotate_count:
        lines.extend(["", "No secret-looking variables found in the code. Variables set only in the Railway dashboard still need rotating."])
    if doc["ci_secrets"]:
        lines.extend(["", "### CI secrets", "",
                      "Your workflows use these secrets. Replace any that hold a Railway token or a key you also stored on Railway: "
                      + ", ".join(f"`{name}`" for name in doc["ci_secrets"][:40]) + "."])
    quiet = [item["name"] for item in groups.get("provided", [])] + [item["name"] for item in groups.get("public", [])] + [item["name"] for item in groups.get("config", [])]
    if quiet:
        lines.extend(["", "Not on the checklist (set by Railway, public by design, or plain config): "
                      + ", ".join(f"`{name}`" for name in quiet[:40]) + "."])
    lines.extend(["", "## Hardcoded secrets", ""])
    if doc["gitleaks_note"] and not doc["hardcoded_secrets"]:
        lines.append(f"gitleaks did not run cleanly ({doc['gitleaks_note']}). This section is not covered.")
    elif not doc["hardcoded_secrets"]:
        lines.append("gitleaks found none in the files or git history it could read.")
    else:
        lines.append(f"gitleaks found {len(doc['hardcoded_secrets'])}. Values are not shown. Rotate each one, then move it to a "
                     "Railway variable. Deleting it from the code is not enough, because git history keeps it.")
        for item in doc["hardcoded_secrets"][:30]:
            lines.append(f"- [ ] {item['file']}:{item['line']} {item['rule']} ({item['fingerprint'][7:19]})")
    lines.extend(["", "## Database exposure", ""])
    if not doc["db_exposure"]:
        lines.append("No committed database passwords, public proxy hosts, or public database variables found in code.")
    for item in doc["db_exposure"][:30]:
        lines.append(f"- [ ] {item['severity']} {item['file']}:{item['line']} {item['message']}")
    lines.extend(["", "## Your steps in the Railway dashboard", "",
                  "Only you can do these. The bot never logs in to Railway or any provider."])
    lines.extend(f"- [ ] {step}" for step in guidance["owner_steps"])
    lines.extend(["", "## Other platforms", "",
                  "Only Railway is built. The same check could cover Vercel, Render, or Fly later.", ""])
    return "\n".join(lines)


def cmd_platform_check(argv, which_fn=which, runner=run_cmd):
    parser = argparse.ArgumentParser(prog="sab.py platform-check")
    parser.add_argument("repo_path")
    parser.add_argument("--platform", default="railway")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    platform_name = args.platform.lower()
    if platform_name not in PLATFORMS:
        later = " Vercel, Render, and Fly are possible later." if platform_name in LATER_PLATFORMS else ""
        print(f"platform '{args.platform}' is not built yet; only railway is.{later}", file=sys.stderr)
        return 2
    try:
        doc = build_platform_report(args.repo_path, platform_name, which_fn=which_fn, runner=runner)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"platform-{platform_name}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (out / f"PLATFORM-{platform_name.upper()}.md").write_text(render_platform_report(doc), encoding="utf-8")
    rotate = sum(len(doc["env_groups"].get(group, [])) for group in (*ENV_GROUP_ORDER, "public-secret"))
    print(
        f"{platform_name}: detected={'yes' if doc['detected'] else 'no'}, {rotate} variables to rotate, "
        f"{len(doc['hardcoded_secrets'])} hardcoded secrets, {len(doc['db_exposure'])} database exposure items -> {out}"
    )
    return 0


# ---------------------------------------------------------------------------
# Owner-only share line. Detail-free by construction and checked by report-lint.
# ---------------------------------------------------------------------------

SHARE_PREFIX = "Scanned with Security Audit Bot: "
SHARE_FILE = "SHARE-LINE.md"
SHARE_ITEM_RE = re.compile(r"^(?:\d{1,4} (?:critical|high|medium|low)(?: fixed)?|no confirmed findings)$")
SHARE_SEVERITIES = ("critical", "high", "medium", "low")


def confirmed_counts(findings):
    counts = Counter()
    fingerprints = {}
    for item in findings if isinstance(findings, list) else []:
        if not isinstance(item, dict) or item.get("verdict") != "confirmed":
            continue
        severity = str((item.get("severity") or {}).get("overall_severity") or "").lower()
        if severity in SHARE_SEVERITIES:
            counts[severity] += 1
            fingerprints[str(item.get("fingerprint") or "")] = severity
    return counts, fingerprints


def build_share_line(open_counts, fixed_counts=None):
    fixed_counts = fixed_counts or Counter()
    items = []
    if not any(open_counts.values()) and not any(fixed_counts.values()):
        items.append("no confirmed findings")
    else:
        for severity in SHARE_SEVERITIES:
            if severity in ("critical", "high") or open_counts.get(severity):
                items.append(f"{open_counts.get(severity, 0)} {severity}")
        for severity in SHARE_SEVERITIES:
            if fixed_counts.get(severity):
                items.append(f"{fixed_counts[severity]} {severity} fixed")
    return SHARE_PREFIX + ", ".join(items) + "."


def share_line_problems(text):
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        return [f"{SHARE_FILE}: must be exactly one line"]
    line = lines[0].strip()
    if len(line) > 160:
        return [f"{SHARE_FILE}: longer than 160 characters"]
    if not line.startswith(SHARE_PREFIX) or not line.endswith("."):
        return [f"{SHARE_FILE}: must read '{SHARE_PREFIX}<counts>.'"]
    body = line[len(SHARE_PREFIX):-1]
    bad = [item for item in body.split(", ") if not SHARE_ITEM_RE.match(item)]
    if bad:
        return [f"{SHARE_FILE}: only severity counts are allowed (no file names, paths, or details)"]
    return []


def _parse_counts(text):
    counts = Counter()
    for part in (text or "").split(","):
        if not part.strip():
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key not in SHARE_SEVERITIES or not value.strip().isdigit():
            raise ValueError("counts look like critical=0,high=2")
        counts[key] = int(value)
    return counts


def cmd_share_line(argv):
    parser = argparse.ArgumentParser(prog="sab.py share-line")
    parser.add_argument("run_dir")
    parser.add_argument("--previous", default=None, help="an earlier run directory; findings confirmed there and gone now count as fixed")
    parser.add_argument("--counts", default=None, help="open counts when there is no findings.json, e.g. critical=0,high=1")
    parser.add_argument("--fixed", default=None, help="fixed counts, e.g. high=2")
    parser.add_argument("--write", action="store_true", help=f"also write {SHARE_FILE} into the run directory")
    args = parser.parse_args(argv)
    run = Path(args.run_dir)
    try:
        if args.counts is not None:
            open_counts, current = _parse_counts(args.counts), {}
        else:
            findings = json.loads((run / "findings.json").read_text(encoding="utf-8"))
            open_counts, current = confirmed_counts(findings)
        fixed = _parse_counts(args.fixed) if args.fixed else Counter()
        if args.previous:
            previous = json.loads((Path(args.previous) / "findings.json").read_text(encoding="utf-8"))
            _, before = confirmed_counts(previous)
            for fingerprint, severity in before.items():
                if fingerprint not in current:
                    fixed[severity] += 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    line = build_share_line(open_counts, fixed)
    if share_line_problems(line):
        print("could not build a clean share line", file=sys.stderr)
        return 1
    if args.write:
        (run / SHARE_FILE).write_text(line + "\n", encoding="utf-8")
    print(line)
    return 0


def host_platform():
    system = sys.platform
    if system.startswith("linux"):
        osname = "linux"
    elif system == "darwin":
        osname = "darwin"
    else:
        osname = system
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "x64"
    elif machine in {"aarch64", "arm64"}:
        arch = "arm64"
    elif machine in {"i386", "i686", "x86"}:
        arch = "x86"
    else:
        arch = machine
    return osname, arch


def choose_checksum_asset(names):
    hits = []
    for name in names:
        lower = name.lower()
        if "sigstore" in lower or lower.endswith((".sig", ".pem", ".asc")):
            continue
        if "checksum" in lower or "sha256sum" in lower or lower.endswith("sha256sums"):
            hits.append(name)
    if not hits:
        return None
    hits.sort(key=lambda name: (0 if name.lower().endswith(".txt") else 1, len(name)))
    return hits[0]


def choose_gitleaks_asset(names, osname, arch):
    token = {"x86": "x32"}.get(arch, arch)
    suffix = f"_{osname}_{token}.tar.gz"
    matches = [name for name in names if name.startswith("gitleaks_") and name.endswith(suffix)]
    return matches[0] if len(matches) == 1 else None


def choose_osv_asset(names, osname, arch):
    mapped = {"x64": "amd64", "arm64": "arm64"}.get(arch)
    if not mapped:
        return None
    name = f"osv-scanner_{osname}_{mapped}"
    return name if name in names else None


def choose_trivy_asset(names, osname, arch):
    table = {
        ("linux", "x64"): "Linux-64bit.tar.gz",
        ("linux", "arm64"): "Linux-ARM64.tar.gz",
        ("linux", "x86"): "Linux-32bit.tar.gz",
        ("darwin", "x64"): "macOS-64bit.tar.gz",
        ("darwin", "arm64"): "macOS-ARM64.tar.gz",
    }
    suffix = table.get((osname, arch))
    if not suffix:
        return None
    matches = [
        name for name in names
        if name.startswith("trivy_") and name.endswith(suffix) and "sigstore" not in name
    ]
    return matches[0] if len(matches) == 1 else None


def lookup_checksum(text, filename):
    for line in (text or "").splitlines():
        match = CHECKSUM_RE.match(line.strip())
        if match and match.group(2) == filename:
            return match.group(1).lower()
    return None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url, dest):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "security-audit-bot", "Accept": "application/octet-stream"},
    )
    with urllib.request.urlopen(request, timeout=120) as response, open(dest, "wb") as handle:
        shutil.copyfileobj(response, handle)


def _github_latest(repo):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"User-Agent": "security-audit-bot", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _install_binary_bytes(data, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _extract_named_binary(archive, binary_names, dest):
    names = set(binary_names)
    if str(archive).endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as bundle:
            chosen = None
            for member in bundle.getmembers():
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if any(part == ".." for part in parts):
                    continue
                if Path(member.name).name in names:
                    chosen = member
                    break
            if chosen is None:
                raise RuntimeError("archive did not contain the expected binary")
            extracted = bundle.extractfile(chosen)
            if extracted is None:
                raise RuntimeError("could not read archive member")
            _install_binary_bytes(extracted.read(), dest)
        return
    if str(archive).endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            chosen = None
            for info in bundle.infolist():
                parts = Path(info.filename).parts
                if any(part == ".." for part in parts):
                    continue
                if Path(info.filename).name in names:
                    chosen = info
                    break
            if chosen is None:
                raise RuntimeError("archive did not contain the expected binary")
            _install_binary_bytes(bundle.read(chosen), dest)
        return
    _install_binary_bytes(Path(archive).read_bytes(), dest)


def install_github_release(repo, chooser, binary_names, dest_name):
    osname, arch = host_platform()
    try:
        release = _github_latest(repo)
    except Exception as exc:  # noqa: BLE001 — install failure is a skip, not a crash
        return "skipped", clean_message(str(exc)) or "release lookup failed"
    assets = release.get("assets") or []
    by_name = {asset.get("name"): asset for asset in assets if asset.get("name") and asset.get("browser_download_url")}
    names = list(by_name)
    checksum_name = choose_checksum_asset(names)
    asset_name = chooser(names, osname, arch)
    if not checksum_name or not asset_name:
        return "skipped", "no matching release asset or checksum file"
    tmp = Path(tempfile.mkdtemp(prefix="sab-inst-"))
    try:
        sum_path = tmp / checksum_name
        bin_path = tmp / asset_name
        _download(by_name[checksum_name]["browser_download_url"], sum_path)
        _download(by_name[asset_name]["browser_download_url"], bin_path)
        expected = lookup_checksum(sum_path.read_text(encoding="utf-8", errors="replace"), asset_name)
        if not expected:
            return "skipped", "checksum entry missing; refused to install"
        if sha256_file(bin_path) != expected:
            return "skipped", "checksum mismatch; refused to install"
        _extract_named_binary(bin_path, binary_names, bindir() / dest_name)
    except Exception as exc:  # noqa: BLE001
        return "skipped", clean_message(str(exc)) or "install failed"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return "ok", "installed"


def _pip_install(package, runner):
    argv = [sys.executable, "-m", "pip", "install", "--user", "--disable-pip-version-check", package]
    result = runner(argv, timeout=300, cwd=None, env=os.environ.copy())
    if result.returncode != 0:
        return False, _note_from_result(result) or "pip install failed"
    return True, "installed with pip --user"


def _venv_install(package, binary, runner):
    # One private venv per tool. Works on PEP 668 hosts where pip --user is blocked.
    root = venv_root() / package
    python = root / "bin" / "python"
    if not python.exists():
        made = runner([sys.executable, "-m", "venv", str(root)], timeout=180, cwd=None, env=os.environ.copy())
        if made.returncode != 0:
            return False, "could not create a venv: " + (_note_from_result(made) or "python3 -m venv failed")
    argv = [str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", package]
    result = runner(argv, timeout=900, cwd=None, env=os.environ.copy())
    if result.returncode != 0:
        return False, "venv pip install failed: " + (_note_from_result(result) or f"exit {result.returncode}")
    exe = root / "bin" / binary
    if not exe.exists():
        return False, f"{binary} missing after venv install"
    link = bindir() / binary
    if not link.exists() and not link.is_symlink():
        try:
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(exe)
        except OSError:
            pass
    return True, "installed in a private venv"


def install_python_tool(package, binary, runner, which_fn, prefer_pipx=False):
    if which_fn(binary):
        return "ok", "already installed"
    if prefer_pipx and which_fn("pipx"):
        result = runner(["pipx", "install", package], timeout=600, cwd=None, env=os.environ.copy())
        if result.returncode == 0 and which_fn(binary):
            return "ok", "installed with pipx"
    ok, pip_note = _pip_install(package, runner)
    if ok and which_fn(binary):
        return "ok", pip_note
    ok, note = _venv_install(package, binary, runner)
    if ok and which_fn(binary):
        return "ok", note
    return "skipped", note if pip_note in note else f"{note} (pip --user: {pip_note})"


def _git(dest, args, runner):
    argv = ["git", "-c", "core.hooksPath=/dev/null", "-c", "advice.detachedHead=false", *args]
    return runner(argv, timeout=180, cwd=str(dest), env=os.environ.copy())


def _readable_git_dir(dest, runner):
    probe = _git(dest, ["rev-parse", "--absolute-git-dir"], runner)
    if probe.returncode != 0:
        return False
    got = (probe.stdout or "").strip()
    try:
        return Path(got).resolve() == (dest / ".git").resolve()
    except OSError:
        return False


def _config_names_pin(dest):
    try:
        text = (dest / ".git" / "config").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return SKILL_REPO in text


def install_skill(runner=run_cmd):
    dest = skill_clone_dir()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and any(dest.iterdir()) and not (dest / ".git").exists():
        return "skipped", f"{dest} exists but is not a git clone; move it aside and rerun setup"
    if dest.exists() and (dest / ".git").exists() and not _readable_git_dir(dest, runner):
        # A copied or interrupted clone (e.g. .git/objects missing). Keep it, move it aside, refetch.
        if not _config_names_pin(dest):
            return "skipped", f"{dest} has an unreadable .git that is not the pinned skill; move it aside and rerun setup"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        aside = dest.with_name(f"{dest.name}.damaged-{stamp}")
        dest.rename(aside)
    if not dest.exists():
        dest.mkdir(parents=True)
        init = _git(dest, ["init"], runner)
        if init.returncode != 0:
            return "skipped", _note_from_result(init) or "git init failed"
        add = _git(dest, ["remote", "add", "origin", SKILL_REPO], runner)
        if add.returncode != 0:
            return "skipped", _note_from_result(add) or "git remote add failed"
    else:
        remote = _git(dest, ["remote", "get-url", "origin"], runner)
        url = (remote.stdout or "").strip()
        if remote.returncode != 0:
            return "skipped", f"{dest} has no origin remote; move it aside and rerun setup"
        if SKILL_REPO not in url:
            return "skipped", f"{dest} points at a different remote; refusing to replace it"
    head = _git(dest, ["rev-parse", "HEAD"], runner)
    if head.returncode == 0 and (head.stdout or "").strip() == SKILL_COMMIT:
        skill_md = dest / "skills" / "security-audit" / "SKILL.md"
        if skill_md.is_file():
            return "ok", SKILL_COMMIT
    fetched = _git(dest, ["fetch", "--depth", "1", "origin", SKILL_COMMIT], runner)
    if fetched.returncode != 0:
        return "skipped", _note_from_result(fetched) or "git fetch of pin failed"
    checked = _git(dest, ["checkout", "--detach", "FETCH_HEAD"], runner)
    if checked.returncode != 0:
        return "skipped", _note_from_result(checked) or "git checkout of pin failed"
    head = _git(dest, ["rev-parse", "HEAD"], runner)
    got = (head.stdout or "").strip()
    skill_md = dest / "skills" / "security-audit" / "SKILL.md"
    if got != SKILL_COMMIT or not skill_md.is_file():
        return "skipped", f"pin mismatch: {got or 'unknown'}"
    return "ok", SKILL_COMMIT


def tool_version(binary, which_fn, runner):
    path = which_fn(binary)
    if not path:
        return ""
    argv_sets = {
        "gitleaks": [[path, "version"], [path, "--version"]],
        "trivy": [[path, "--version"], [path, "version"]],
    }
    options = argv_sets.get(binary, [[path, "--version"], [path, "version"]])
    for argv in options:
        result = runner(argv, timeout=20, cwd=None, env=scanner_env(data_dir() / "tool-home"))
        text = (result.stdout or result.stderr or "").strip().splitlines()
        if result.returncode == 0 and text:
            return clean_message(text[0])[:80]
    return ""


def print_table(rows):
    headers = ("tool", "version", "status")
    widths = [len(item) for item in headers]
    rendered = []
    for tool, version, status in rows:
        cells = (tool, version or "-", status)
        rendered.append(cells)
        widths = [max(widths[i], len(cells[i])) for i in range(3)]
    print(f"{headers[0]:<{widths[0]}}  {headers[1]:<{widths[1]}}  {headers[2]}")
    for cells in rendered:
        print(f"{cells[0]:<{widths[0]}}  {cells[1]:<{widths[1]}}  {cells[2]}")


def cmd_setup(which_fn=which, runner=run_cmd):
    rows = []
    skill_status, skill_detail = install_skill(runner)
    rows.append(("cloudflare-skill", skill_detail if skill_status == "ok" else "-", f"{skill_status}: {skill_detail}" if skill_status != "ok" else "ok"))
    for binary in ("git", "node", "gh"):
        version = tool_version(binary, which_fn, runner)
        rows.append((binary, version, "ok" if version or which_fn(binary) else "missing"))
    pip_tools = (
        ("semgrep", "semgrep", True),
        ("zizmor", "zizmor", False),
        ("bandit", "bandit", False),
        ("pip-audit", "pip-audit", False),
        ("checkov", "checkov", False),
    )
    for package, binary, pipx in pip_tools:
        status, note = install_python_tool(package, binary, runner, which_fn, prefer_pipx=pipx)
        version = tool_version(binary, which_fn, runner) if status == "ok" else ""
        rows.append((binary, version, "ok" if status == "ok" else f"skipped: {note}"))
    binaries = (
        ("gitleaks", "gitleaks/gitleaks", choose_gitleaks_asset, ("gitleaks",), "gitleaks"),
        ("osv-scanner", "google/osv-scanner", choose_osv_asset, ("osv-scanner",), "osv-scanner"),
        ("trivy", "aquasecurity/trivy", choose_trivy_asset, ("trivy",), "trivy"),
    )
    for binary, repo, chooser, members, dest_name in binaries:
        if which_fn(binary):
            rows.append((binary, tool_version(binary, which_fn, runner), "ok"))
            continue
        status, note = install_github_release(repo, chooser, members, dest_name)
        version = tool_version(binary, which_fn, runner) if status == "ok" else ""
        rows.append((binary, version, "ok" if status == "ok" else f"skipped: {note}"))
    npm_version = tool_version("npm", which_fn, runner)
    rows.append(("npm", npm_version, "ok" if which_fn("npm") else "skipped: not installed"))
    print_table(rows)
    missing = [row[0] for row in rows if row[0] in SCANNER_PURPOSE and row[2] != "ok"]
    if missing:
        print("\nMissing scanners. Preflight still runs; these leads will be absent:")
        for name in missing:
            print(f"- {name}: {SCANNER_PURPOSE[name]}")
    if skill_status != "ok":
        print("\nThe pinned Cloudflare skill is not ready. Do not start an audit until setup reports it ok.")
    local = str(bindir())
    if local not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"\n{local} is not on PATH. sab.py still looks there; shells need it for direct use.")
    return 0 if skill_status == "ok" else 1


def parse_github(value):
    raw = (value or "").strip()
    rest = None
    for prefix in (
        "https://github.com/",
        "http://github.com/",
        "https://www.github.com/",
        "http://www.github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ):
        if raw.lower().startswith(prefix.lower()):
            rest = raw[len(prefix):]
            break
    if rest is None:
        return None
    rest = rest.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = [part for part in rest.split("/") if part]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        return None
    return owner, repo


def parse_target(value):
    raw = (value or "").strip()
    if not raw:
        return {"kind": "invalid", "raw": raw, "display": ""}
    if re.match(r"^https?://([^/]*\.)?github\.com/|^git@github\.com:|^ssh://git@github\.com/", raw, re.I):
        parsed = parse_github(raw)
        if not parsed:
            return {"kind": "invalid", "raw": raw, "display": raw}
        owner, repo = parsed
        return {"kind": "github", "raw": raw, "owner": owner, "repo": repo, "display": f"{owner}/{repo}"}
    if re.match(r"^(https?://|git://|ssh://|git@)", raw):
        return {"kind": "git", "raw": raw, "display": raw}
    return {"kind": "path", "raw": raw, "display": Path(raw).name or raw}


def affirmation_ok(text):
    if not text or not str(text).strip():
        return False
    folded = re.sub(r"\s+", " ", str(text)).strip().lower()
    return any(marker in folded for marker in AFFIRM_MARKERS)


def permissions_allow(permissions):
    if not isinstance(permissions, dict):
        return False
    return any(permissions.get(key) is True for key in ("admin", "maintain", "push", "triage", "pull"))


def gh_api_argv(gh_bin, owner, repo):
    return [gh_bin, "api", f"repos/{owner}/{repo}", "--jq", ".permissions"]


def decide_authorization(target, affirm=None, gh_logged_in=False, permissions=None, permissions_error=None, path_exists=None):
    parsed = parse_target(target)
    if parsed["kind"] == "invalid":
        return {"status": "refused", "reason": "could not parse the target", "target": parsed, "github_permissions": None}
    if parsed["kind"] == "path":
        exists = Path(parsed["raw"]).expanduser().exists() if path_exists is None else bool(path_exists)
        if not exists:
            return {"status": "refused", "reason": "path not found", "target": parsed, "github_permissions": None}
        resolved = Path(parsed["raw"]).expanduser().resolve()
        if resolved == Path("/").resolve() or resolved == Path.home().resolve():
            return {
                "status": "refused",
                "reason": "refusing to scan the filesystem root or the home directory",
                "target": parsed,
                "github_permissions": None,
            }
    perms_out = None
    if parsed["kind"] == "github" and gh_logged_in:
        if permissions_error:
            return {
                "status": "refused",
                "reason": permissions_error,
                "target": parsed,
                "github_permissions": None,
            }
        if not permissions_allow(permissions):
            return {
                "status": "refused",
                "reason": "github token has no access to this repository",
                "target": parsed,
                "github_permissions": permissions if isinstance(permissions, dict) else None,
            }
        perms_out = permissions
    if affirm and str(affirm).strip() and not affirmation_ok(affirm):
        return {
            "status": "refused",
            "reason": 'statement must include "this is my code" or "I have permission"',
            "target": parsed,
            "github_permissions": perms_out,
        }
    if not affirmation_ok(affirm):
        return {
            "status": "needs_affirmation",
            "reason": 'ask the owner to state "this is my code / I have permission"',
            "target": parsed,
            "github_permissions": perms_out,
        }
    return {
        "status": "authorized",
        "reason": "owner statement recorded",
        "target": parsed,
        "github_permissions": perms_out,
        "statement": str(affirm).strip(),
    }


def collect_github_access(parsed, which_fn, runner):
    if parsed.get("kind") != "github":
        return False, None, None
    gh_bin = which_fn("gh")
    if not gh_bin:
        return False, None, None
    status = runner([gh_bin, "auth", "status"], timeout=20, cwd=None, env=os.environ.copy())
    if status.returncode != 0:
        return False, None, None
    api = runner(gh_api_argv(gh_bin, parsed["owner"], parsed["repo"]), timeout=30, cwd=None, env=os.environ.copy())
    if api.returncode != 0:
        return True, None, clean_message(api.stderr) or "github permissions check failed"
    try:
        payload = json.loads(api.stdout or "")
    except json.JSONDecodeError:
        return True, None, "github permissions response was not JSON"
    if not isinstance(payload, dict):
        return True, None, "github permissions were empty"
    return True, payload, None


def write_run_metadata(path, decision):
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if dest.exists():
        try:
            loaded = json.loads(dest.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, json.JSONDecodeError):
            existing = {}
    target = decision["target"]
    existing.update(
        {
            "version": VERSION,
            "authorized": True,
            "statement": decision["statement"],
            "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": target.get("raw"),
            "kind": target.get("kind"),
            "display": target.get("display"),
            "owner": target.get("owner"),
            "repo": target.get("repo"),
            "github_permissions": decision.get("github_permissions"),
        }
    )
    dest.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest


def cmd_check_authorization(argv, which_fn=which, runner=run_cmd):
    parser = argparse.ArgumentParser(prog="sab.py check-authorization")
    parser.add_argument("target")
    parser.add_argument("--affirm", default=None)
    parser.add_argument("--metadata", default="run-metadata.json")
    args = parser.parse_args(argv)
    parsed = parse_target(args.target)
    logged_in, permissions, error = collect_github_access(parsed, which_fn, runner)
    decision = decide_authorization(
        args.target,
        affirm=args.affirm,
        gh_logged_in=logged_in,
        permissions=permissions,
        permissions_error=error,
    )
    public = {
        "status": decision["status"],
        "reason": decision["reason"],
        "target": decision["target"].get("display"),
        "kind": decision["target"].get("kind"),
        "github_permissions": decision.get("github_permissions"),
    }
    if decision["status"] == "authorized":
        write_run_metadata(args.metadata, decision)
        public["metadata"] = str(args.metadata)
    print(json.dumps(public, indent=2, sort_keys=True))
    return {"authorized": 0, "needs_affirmation": 2, "refused": 1}[decision["status"]]


def _metadata_lines(text):
    return text.splitlines()


LOCAL_PATH_RE = re.compile(r"(?<![\w.])(?:/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|/root)(?=/|\b)|[A-Za-z]:\\Users\\[^\\\s]+")
REPORT_FILES = ("REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md")


FIRST_STEPS_RE = re.compile(r"(?im)^#{1,3}\s+what to do first\b.*$")
TIME_COST_RE = re.compile(
    r"(?i)\b(?:about\s+|under\s+|~\s*)?\d+(?:\s*(?:-|–|to)\s*\d+)?\s*(?:min|mins|minutes?|hours?|hrs?|h|days?)\b"
)
FIRST_STEPS_MAX = 5


def first_steps_problems(text):
    """The plain-English 'What to do first' list: at most 5 items, each with a fix and a time cost, before the details."""
    match = FIRST_STEPS_RE.search(text)
    if not match:
        return []
    problems = []
    before = text[:match.start()]
    if re.search(r"(?m)^##\s+", before):
        problems.append("REPORT.md: 'What to do first' must be the first section")
    rest = text[match.end():]
    end = re.search(r"(?m)^#{1,3}\s+", rest)
    section = rest[:end.start()] if end else rest
    items = [line.strip() for line in section.splitlines() if re.match(r"^\s*(?:[-*]|\d+[.)])\s+", line)]
    if not items:
        problems.append("REPORT.md: 'What to do first' has no items")
    if len(items) > FIRST_STEPS_MAX:
        problems.append(f"REPORT.md: 'What to do first' has {len(items)} items (at most {FIRST_STEPS_MAX})")
    for number, item in enumerate(items, start=1):
        if not TIME_COST_RE.search(item):
            problems.append(f"REPORT.md: 'What to do first' item {number} has no time cost (for example 'about 10 minutes')")
    return problems


def lint_reports(directory):
    root = Path(directory)
    named = [root / name for name in REPORT_FILES]
    extra_primary = list(root.glob("PLATFORM-*.md")) + ([root / SHARE_FILE] if (root / SHARE_FILE).is_file() else [])
    if not any(path.is_file() for path in named[:2]) and not extra_primary:
        return ["no REPORT.md or FINDINGS-DETAIL.md"]
    # Every markdown file the owner may receive, not only the two main reports.
    present = sorted({path for path in named if path.is_file()} | set(root.glob("*.md")) | set((root / "preflight").glob("*.md")))
    problems = []
    lead_secrets = []
    lead_files = [root / "scanner-leads.json", root / "preflight" / "scanner-leads.json"]
    for leads_path in lead_files:
        if not leads_path.is_file():
            continue
        try:
            payload = json.loads(leads_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        leads = payload.get("leads") if isinstance(payload, dict) else payload
        for lead in leads or []:
            if not isinstance(lead, dict):
                continue
            for key in ("rule", "message", "file", "fingerprint"):
                value = lead.get(key)
                if isinstance(value, str):
                    lead_secrets.extend(extract_secrets(value))
    lead_secrets = sorted(set(lead_secrets), key=len, reverse=True)
    for path in present:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            problems.append(f"{path.name}: {exc}")
            continue
        lines = _metadata_lines(text)
        seen = set()
        if path.name == "REPORT.md":
            problems.extend(first_steps_problems(text))
        if path.name == SHARE_FILE:
            problems.extend(share_line_problems(text))
        for index, line in enumerate(lines, start=1):
            if LOCAL_PATH_RE.search(line):
                problems.append(f"{path.name}:{index}: local filesystem path (use repo-relative paths)")
        for secret in lead_secrets:
            if secret and secret in text:
                line_no = next((index + 1 for index, line in enumerate(lines) if secret in line), 1)
                label = secret[:4] + "…"
                item = (path.name, line_no, f"raw secret from leads {label}")
                if item not in seen:
                    seen.add(item)
                    problems.append(f"{path.name}:{line_no}: raw secret from leads {label}")
        for index, line in enumerate(lines, start=1):
            for secret in extract_secrets(line):
                if any(secret in lead for lead in lead_secrets):
                    continue
                label = secret[:4] + "…"
                item = (path.name, index, label)
                if item in seen:
                    continue
                seen.add(item)
                kind = "high-entropy" if _entropy_token(secret) and not any(
                    pattern.fullmatch(secret) for pattern in SECRET_PATTERNS
                ) else "secret pattern"
                problems.append(f"{path.name}:{index}: {kind} {label}")
    return problems


def cmd_report_lint(argv):
    parser = argparse.ArgumentParser(prog="sab.py report-lint")
    parser.add_argument("directory")
    args = parser.parse_args(argv)
    problems = lint_reports(args.directory)
    if problems:
        for problem in problems:
            print(problem)
        return 1
    print("ok")
    return 0


def accept_lead(leads_path, fingerprint, reason, baseline_path):
    if not reason or len(reason.strip()) < 5:
        raise ValueError("a reason is required (why the owner accepts this lead)")
    doc = json.loads(Path(leads_path).read_text(encoding="utf-8"))
    leads = doc.get("leads") if isinstance(doc, dict) else doc
    wanted = fingerprint.strip()
    if not wanted.startswith("sha256:"):
        wanted = "sha256:" + wanted
    if len(wanted) < len("sha256:") + 8:
        raise ValueError("give at least 8 characters of the fingerprint")
    matches = [lead for lead in leads or [] if isinstance(lead, dict) and str(lead.get("fingerprint", "")).startswith(wanted)]
    if len(matches) != 1:
        raise ValueError(f"fingerprint matched {len(matches)} leads; give more characters")
    lead = matches[0]
    baseline = load_baseline(baseline_path)
    key = stable_key(lead)
    entries = [entry for entry in baseline["entries"] if entry.get("key") != key]
    entry = {
        "key": key,
        "fingerprint": lead["fingerprint"],
        "tool": lead.get("tool"),
        "rule": lead.get("rule"),
        "file": lead.get("file"),
        "line": lead.get("line"),
        "kind": lead_kind(lead),
        "reason": clean_message(reason),
        "accepted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    entries.append(entry)
    baseline["version"] = BASELINE_VERSION
    baseline["entries"] = entries
    dest = Path(baseline_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return entry


def cmd_accept(argv):
    parser = argparse.ArgumentParser(prog="sab.py accept")
    parser.add_argument("leads", help="scanner-leads.json from a preflight run")
    parser.add_argument("fingerprint", help="lead fingerprint or a unique prefix (8+ hex chars)")
    parser.add_argument("--reason", required=True)
    parser.add_argument("--baseline", required=True)
    args = parser.parse_args(argv)
    try:
        entry = accept_lead(args.leads, args.fingerprint, args.reason, args.baseline)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(entry, indent=2, sort_keys=True))
    return 0


def cmd_preflight(argv, which_fn=which, runner=run_cmd):
    parser = argparse.ArgumentParser(prog="sab.py preflight")
    parser.add_argument("repo_path")
    parser.add_argument("--out", required=True)
    parser.add_argument("--baseline", default=None, help="accepted-leads file; matching leads are hidden and listed")
    parser.add_argument("--previous", default=None, help="scanner-leads.json from an earlier run, to mark new and gone leads")
    args = parser.parse_args(argv)
    try:
        document = run_preflight(
            args.repo_path, args.out, which_fn=which_fn, runner=runner,
            baseline_path=args.baseline, previous_path=args.previous,
        )
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    extra = ""
    if "resolved" in document:
        new = sum(1 for lead in document["leads"] if lead.get("change") == "new")
        extra = f" ({new} new, {len(document['resolved'])} gone)"
    if document["suppressed"]:
        extra += f", {len(document['suppressed'])} accepted in baseline"
    print(f"leads {len(document['leads'])}{extra} -> {args.out}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="sab.py")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("setup")
    pre = sub.add_parser("preflight")
    pre.add_argument("repo_path")
    pre.add_argument("--out", required=True)
    pre.add_argument("--baseline", default=None)
    pre.add_argument("--previous", default=None)
    acc = sub.add_parser("accept")
    acc.add_argument("leads")
    acc.add_argument("fingerprint")
    acc.add_argument("--reason", required=True)
    acc.add_argument("--baseline", required=True)
    auth = sub.add_parser("check-authorization")
    auth.add_argument("target")
    auth.add_argument("--affirm", default=None)
    auth.add_argument("--metadata", default="run-metadata.json")
    lint = sub.add_parser("report-lint")
    lint.add_argument("directory")
    plat = sub.add_parser("platform-check", help="repository-only incident checklist; only railway is built")
    plat.add_argument("repo_path")
    plat.add_argument("--platform", default="railway")
    plat.add_argument("--out", required=True)
    share = sub.add_parser("share-line", help="one detail-free line the owner may post themselves")
    share.add_argument("run_dir")
    share.add_argument("--previous", default=None)
    share.add_argument("--counts", default=None)
    share.add_argument("--fixed", default=None)
    share.add_argument("--write", action="store_true")
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        build_parser().print_help()
        return 2
    if argv[0] == "--version":
        print(VERSION)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "setup":
        return cmd_setup()
    if cmd == "preflight":
        return cmd_preflight(rest)
    if cmd == "check-authorization":
        return cmd_check_authorization(rest)
    if cmd == "report-lint":
        return cmd_report_lint(rest)
    if cmd == "accept":
        return cmd_accept(rest)
    if cmd == "platform-check":
        return cmd_platform_check(rest)
    if cmd == "share-line":
        return cmd_share_line(rest)
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
