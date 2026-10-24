#!/usr/bin/env python3
"""Security Audit Bot preflight, setup, authorization, and report lint."""

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
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.0"
SKILL_REPO = "https://github.com/cloudflare/security-audit-skill"
SKILL_COMMIT = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
PER_TOOL_CAP = 100
LEAD_KEYS = ("tool", "rule", "severity", "file", "line", "message", "fingerprint")

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
    "semgrep",
    "gitleaks",
    "osv-scanner",
    "trivy",
    "zizmor",
    "bandit",
    "npm-audit",
    "pip-audit",
    "checkov",
)
TIMEOUTS = {
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


def scanner_env(home):
    # Isolated HOME so a scanner cannot read host credentials or cloud config.
    skip = {"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"}
    env = {key: os.environ[key] for key in ENV_KEEP if key in os.environ and key not in skip}
    env.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    local = str(bindir())
    if local not in env["PATH"].split(os.pathsep):
        env["PATH"] = local + os.pathsep + env["PATH"]
    home = Path(home)
    env["HOME"] = str(home)
    env["XDG_CACHE_HOME"] = str(home / "cache")
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
        leads.append(
            make_lead(
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
            )
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
            make_lead(
                "gitleaks",
                rule,
                "high",
                relativize(path, root),
                line,
                message,
                fingerprint_for("gitleaks", rule, path, line, secret or match or message),
                secrets=[secret, match],
            )
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
                leads.append(
                    make_lead(
                        "osv-scanner",
                        vid,
                        _osv_severity(vuln),
                        file,
                        1,
                        label,
                        fingerprint_for("osv-scanner", vid, file, name, version),
                    )
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
                make_lead(
                    "trivy",
                    vid,
                    vuln.get("Severity"),
                    file,
                    1,
                    f"{pkg}@{ver}: {title}" if ver else f"{pkg}: {title}",
                    fingerprint_for("trivy", vid, file, pkg, ver),
                )
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
                make_lead(
                    "trivy",
                    secret.get("RuleID") or secret.get("RuleId") or "secret",
                    secret.get("Severity") or "high",
                    file,
                    line,
                    secret.get("Title") or secret.get("RuleID") or "secret",
                    fingerprint_for("trivy-secret", secret.get("RuleID"), file, line, raw),
                    secrets=[raw, secret.get("Match") or "", secret.get("Secret") or ""],
                )
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
            leads.append(
                make_lead(
                    "npm-audit",
                    rule[:200],
                    info.get("severity"),
                    file,
                    1,
                    f"{name}: {title}" if title else str(name),
                    fingerprint_for("npm-audit", rule, file, name),
                )
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
                make_lead(
                    "pip-audit",
                    vid,
                    "medium",
                    file,
                    1,
                    f"{name}@{version}: {vuln.get('description') or vid}" if version else f"{name}: {vid}",
                    fingerprint_for("pip-audit", vid, file, name, version),
                )
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
        if name in {"composer.json", "composer.lock"}:
            found.add("php")
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
    selected = {"semgrep", "gitleaks", "trivy"}
    if ecos & {"python-deps", "node", "node-lock", "go", "rust", "ruby", "java", "php"}:
        selected.add("osv-scanner")
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


def _note_from_result(result):
    text = (result.stderr or result.stdout or "").strip().splitlines()
    return clean_message(text[0] if text else f"exit {result.returncode}")


def _run_json_command(argv, timeout, cwd, runner, env):
    result = runner(argv, timeout=timeout, cwd=cwd, env=env)
    payload = parse_json_output(result.stdout)
    if payload is None and result.returncode == 124:
        return None, "timed out"
    if payload is None:
        return None, _note_from_result(result) or f"exit {result.returncode}"
    note = "" if result.returncode in (0, 1) else f"exit {result.returncode}"
    return payload, note


def execute_scanner(name, root, runner, which_fn, env):
    if name == "semgrep":
        binary = which_fn("semgrep")
        if not binary:
            return [], "not installed"
        argv = [
            binary, "scan", "--disable-version-check", "--metrics=off", "--quiet", "--json",
            "--timeout", "30",
            "--config", "p/security-audit",
            "--config", "p/owasp-top-ten",
            "--config", "p/secrets",
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
            last = note or last
        return [], last

    if name == "trivy":
        binary = which_fn("trivy")
        if not binary:
            return [], "not installed"
        common = [binary, "fs", "--format", "json", "--quiet", "--skip-version-check"]
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


def render_summary(target_name, ecosystems, tool_rows, leads, truncated):
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
    lines.extend(["", "## Tools", "", "| Tool | Status | Leads | Note |", "| --- | --- | --- | --- |"])
    for row in tool_rows:
        note = (row.get("note") or "").replace("|", "/")
        lines.append(f"| {row['tool']} | {row['status']} | {row['leads']} | {note} |")
    if truncated:
        lines.extend(["", "## Truncated", ""])
        for tool, count in sorted(truncated.items()):
            lines.append(f"- {tool}: dropped {count} lower-severity leads (cap {PER_TOOL_CAP})")
    lines.extend(["", "## Top leads", ""])
    if not leads:
        lines.append("No leads.")
    else:
        for lead in leads[:15]:
            lines.append(
                f"- {lead['severity']} `{lead['tool']}` {lead['file']}:{lead['line']} {lead['rule']} — {lead['message']}"
            )
    lines.append("")
    return "\n".join(lines)


def run_preflight(repo_path, out_dir, which_fn=which, runner=run_cmd, cap=PER_TOOL_CAP):
    root = assert_safe_repo(repo_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ecosystems = detect_ecosystems(root)
    selected = applicable_scanners(ecosystems)
    tool_home = out / ".tool-home"
    (tool_home / "cache").mkdir(parents=True, exist_ok=True)
    (tool_home / "config").mkdir(parents=True, exist_ok=True)
    env = scanner_env(tool_home)
    leads = []
    tool_rows = []
    for name in selected:
        try:
            found, note = execute_scanner(name, root, runner, which_fn, env)
        except Exception as exc:  # noqa: BLE001 — one scanner must not abort the rest
            found, note = [], clean_message(str(exc)) or "failed"
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
        tool_rows.append({"tool": name, "status": status, "leads": len(found), "note": note or ""})
    leads = dedupe_leads(leads)
    leads, truncated = cap_leads(leads, cap=cap)
    for row in tool_rows:
        row["leads"] = sum(1 for lead in leads if lead["tool"] == row["tool"])
        if truncated.get(row["tool"]):
            extra = f"capped, dropped {truncated[row['tool']]}"
            row["note"] = "; ".join(part for part in (row["note"], extra) if part)
    document = {
        "version": VERSION,
        "target_name": root.name,
        "ecosystems": ecosystems,
        "tools": tool_rows,
        "leads": leads,
        "truncated": truncated,
    }
    (out / "scanner-leads.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    summary = render_summary(root.name, ecosystems, tool_rows, leads, truncated)
    (out / "preflight-summary.md").write_text(summary, encoding="utf-8")
    return document


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


def lint_reports(directory):
    root = Path(directory)
    files = [root / "REPORT.md", root / "FINDINGS-DETAIL.md"]
    present = [path for path in files if path.is_file()]
    problems = []
    if not present:
        return ["no REPORT.md or FINDINGS-DETAIL.md"]
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


def cmd_preflight(argv, which_fn=which, runner=run_cmd):
    parser = argparse.ArgumentParser(prog="sab.py preflight")
    parser.add_argument("repo_path")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        document = run_preflight(args.repo_path, args.out, which_fn=which_fn, runner=runner)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"leads {len(document['leads'])} -> {args.out}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="sab.py")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("setup")
    pre = sub.add_parser("preflight")
    pre.add_argument("repo_path")
    pre.add_argument("--out", required=True)
    auth = sub.add_parser("check-authorization")
    auth.add_argument("target")
    auth.add_argument("--affirm", default=None)
    auth.add_argument("--metadata", default="run-metadata.json")
    lint = sub.add_parser("report-lint")
    lint.add_argument("directory")
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
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
