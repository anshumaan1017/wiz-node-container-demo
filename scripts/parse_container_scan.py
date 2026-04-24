#!/usr/bin/env python3
"""
parse_container_scan.py — Wiz Unified Security Scan Parser
===========================================================

Processes ALL scan outputs from the Wiz unified pipeline:
  1. Container image SARIF  (wizcli docker scan --driver mountWithLayers)
  2. SCA directory SARIF     (wizcli dir scan)
  3. IaC Dockerfile SARIF    (wizcli iac scan)
  4. Per-layer JSON          (image-layers.json from mountWithLayers)

Produces:
  filtered/image-filtered.sarif  — Container image findings (OS noise removed)
  filtered/sca-filtered.sarif    — SCA findings (all kept, deduplicated)
  filtered/iac-filtered.sarif    — IaC findings (all kept)
  GitHub Step Summary            — Markdown tables per scan type
  CI console output              — Severity-sorted tabular reports

FILTER RULES (Container Image SARIF):
  Application packages  → ALL severities kept (developer-owned, always actionable)
  OS packages           → CRITICAL / HIGH with a fixedVersion only (eliminates ~90% noise)

DEDUPLICATION:
  Each result gets a deterministic fingerprint: hash(ruleId + packageName + packageVersion)
  Duplicate results with the same fingerprint are collapsed to a single entry.

SARIF LIFECYCLE (via GitHub Security categories):
  • Same category per push = GitHub compares current vs previous upload
  • Findings NOT in the new upload are auto-closed
  • New findings open as new alerts
  • No manual cleanup or overwrite logic needed
"""

import argparse
import copy
import hashlib
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEV_RANK = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3,
    "LOW": 2, "INFO": 1, "INFORMATIONAL": 1, "UNKNOWN": 0,
}

SEV_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🔵", "INFO": "⚪", "INFORMATIONAL": "⚪",
}

CVSS_MAP = {
    "CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5",
    "LOW": "3.0", "INFORMATIONAL": "0.5", "INFO": "0.5",
}

# ---------------------------------------------------------------------------
# JSON / SARIF helpers
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict | None:
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(data: dict, path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_str(obj: dict, *keys, default="") -> str:
    for k in keys:
        v = obj.get(k)
        if v is not None and str(v).strip() not in ("", "-", "N/A", "none", "None"):
            return str(v).strip()
    return default


def get_severity(result: dict, rule_map: dict) -> str:
    props = result.get("properties", {})
    sev = get_str(props, "severity", "Severity").upper()
    if sev in SEV_RANK:
        return sev

    rule = rule_map.get(result.get("ruleId", ""), {})
    sev = get_str(rule.get("properties", {}), "severity", "Severity").upper()
    if sev in SEV_RANK:
        return sev

    # Check security-severity CVSS score on rule
    ss = get_str(rule.get("properties", {}), "security-severity")
    if ss:
        try:
            score = float(ss)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            elif score > 0.0:
                return "LOW"
        except ValueError:
            pass

    # Fall back to SARIF level
    level = result.get("level", "note")
    return {"error": "HIGH", "warning": "MEDIUM"}.get(level, "LOW")


def get_fixed_version(result: dict, rule_map: dict) -> str:
    props = result.get("properties", {})
    fv = get_str(props, "fixedVersion", "fixed_version", "fixVersion",
                 "remediationVersion", "remediation")
    if fv:
        return fv
    rule = rule_map.get(result.get("ruleId", ""), {})
    return get_str(rule.get("properties", {}), "fixedVersion", "fixed_version")


def get_package_name_ver(result: dict, rule_map: dict) -> tuple:
    props = result.get("properties", {})
    name = get_str(props, "packageName", "package_name", "name")
    ver = get_str(props, "packageVersion", "package_version", "version")

    if not name:
        rule = rule_map.get(result.get("ruleId", ""), {})
        desc = get_str(rule.get("shortDescription", {}), "text")
        m = re.search(r" in ([^\s]+)\s+([\d][\S]*)", desc)
        if m:
            name, ver = m.group(1), m.group(2)
        else:
            name = result.get("ruleId", "")

    return name, ver


def get_source_path(result: dict) -> str:
    for loc in result.get("locations", []):
        try:
            uri = (loc.get("physicalLocation", {})
                      .get("artifactLocation", {})
                      .get("uri", ""))
            if uri:
                return uri.replace("file:///", "/").replace("file://", "/")
        except Exception:
            pass
    return ""


def fingerprint(result: dict, rule_map: dict) -> str:
    """Deterministic fingerprint for deduplication."""
    rule_id = result.get("ruleId", "")
    name, ver = get_package_name_ver(result, rule_map)
    src = get_source_path(result)
    key = f"{rule_id}|{name}|{ver}|{src}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def enrich_sarif_rules(sarif: dict):
    """Add security-severity to rules that lack it (required for GitHub Security severity display)."""
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_map = {r["id"]: r for r in rules if "id" in r}
        for rule in rules:
            props = rule.get("properties", {})
            if "security-severity" not in props:
                sev = get_str(props, "severity", "Severity").upper()
                if sev in CVSS_MAP:
                    if "properties" not in rule:
                        rule["properties"] = {}
                    rule["properties"]["security-severity"] = CVSS_MAP[sev]


# ---------------------------------------------------------------------------
# Classification: OS vs APP
# ---------------------------------------------------------------------------

def classify_result(result: dict, rule_map: dict) -> str:
    """Return 'APP' or 'OS'."""
    props = result.get("properties", {})

    # 1. Explicit packageType field
    pt = get_str(props, "packageType", "type", "package_type").upper()
    if "APP" in pt or "APPLICATION" in pt:
        return "APP"
    if pt == "OS":
        return "OS"

    # 2. Location URI heuristics
    src = get_source_path(result)
    app_indicators = ("/app/", "node_modules", "package.json", "package-lock.json",
                      "yarn.lock", "pnpm-lock", ".npm", "requirements.txt",
                      "Gemfile", "go.sum", "Cargo.lock", "composer.lock")
    if src and any(ind in src for ind in app_indicators):
        return "APP"

    # 3. Rule helpUri heuristic
    rule = rule_map.get(result.get("ruleId", ""), {})
    help_uri = get_str(rule, "helpUri", "helpURI")
    if not help_uri:
        help_uri = get_str(rule.get("help", {}), "text", "markdown")
    app_domains = ("github.com/advisories", "npmjs.com", "snyk.io", "ghsa",
                   "nodesecurity.io", "pypi.org")
    os_domains = ("security-tracker.debian.org", "ubuntu.com/security",
                  "access.redhat.com", "nvd.nist.gov", "cve.org")
    if any(x in help_uri for x in app_domains):
        return "APP"
    if any(x in help_uri for x in os_domains):
        return "OS"

    # 4. Message text heuristic
    msg = result.get("message", {}).get("text", "")
    if any(ind in msg for ind in app_indicators):
        return "APP"

    return "OS"


def is_actionable_os(result: dict, rule_map: dict) -> bool:
    """OS finding is actionable only if severity >= HIGH AND a fix exists."""
    sev = get_severity(result, rule_map)
    if SEV_RANK.get(sev, 0) < 4:
        return False
    return bool(get_fixed_version(result, rule_map))


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_results(results: list, rule_map: dict) -> list:
    """Remove duplicate results based on deterministic fingerprint."""
    seen = set()
    unique = []
    for r in results:
        fp = fingerprint(r, rule_map)
        if fp not in seen:
            seen.add(fp)
            # Embed fingerprint for GitHub's partialFingerprints
            if "partialFingerprints" not in r:
                r["partialFingerprints"] = {}
            r["partialFingerprints"]["wiz-dedup-v1"] = fp
            unique.append(r)
    return unique


# ---------------------------------------------------------------------------
# Per-layer analysis
# ---------------------------------------------------------------------------

def parse_layers(layers_path: str) -> dict:
    """Parse image-layers.json and return layer summary."""
    data = load_json(layers_path)
    if not data:
        return {}

    summary = {"total_layers": 0, "layers": []}

    # Handle different Wiz layer JSON formats
    layers = []
    if isinstance(data, list):
        layers = data
    elif isinstance(data, dict):
        layers = data.get("layers", data.get("results", []))

    summary["total_layers"] = len(layers)

    for i, layer in enumerate(layers):
        if isinstance(layer, dict):
            vulns = layer.get("vulnerabilities", layer.get("results", []))
            cmd = layer.get("command", layer.get("createdBy", f"Layer {i}"))
            summary["layers"].append({
                "index": i,
                "command": cmd[:80] if isinstance(cmd, str) else str(cmd)[:80],
                "vuln_count": len(vulns) if isinstance(vulns, list) else 0,
            })

    return summary


# ---------------------------------------------------------------------------
# SARIF filtering pipeline
# ---------------------------------------------------------------------------

def filter_image_sarif(sarif: dict) -> tuple:
    """Filter container image SARIF: keep all APP + actionable OS findings.
    Returns (filtered_sarif, stats_dict).
    """
    if not sarif or not sarif.get("runs"):
        return sarif, {}

    run = sarif["runs"][0]
    results = run.get("results", [])
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    rule_map = {r["id"]: r for r in rules if "id" in r}

    app_findings = []
    os_signal = []
    os_suppressed = []

    for result in results:
        pkg_type = classify_result(result, rule_map)
        if pkg_type == "APP":
            app_findings.append(result)
        elif is_actionable_os(result, rule_map):
            os_signal.append(result)
        else:
            os_suppressed.append(result)

    def sev_key(r):
        return -SEV_RANK.get(get_severity(r, rule_map), 0)

    app_findings.sort(key=sev_key)
    os_signal.sort(key=sev_key)

    # Deduplicate
    keep = deduplicate_results(app_findings + os_signal, rule_map)
    keep_ids = {r.get("ruleId") for r in keep}
    kept_rules = [rule for rule in rules if rule.get("id") in keep_ids]

    filtered = copy.deepcopy(sarif)
    frun = filtered["runs"][0]
    frun["results"] = keep
    frun["tool"]["driver"]["rules"] = kept_rules

    # Enrich with security-severity
    enrich_sarif_rules(filtered)

    stats = {
        "total_raw": len(results),
        "app_kept": len(app_findings),
        "os_actionable": len(os_signal),
        "os_suppressed": len(os_suppressed),
        "final_kept": len(keep),
        "app_counts": sev_counts(app_findings, rule_map),
        "os_sig_counts": sev_counts(os_signal, rule_map),
        "app_findings": app_findings,
        "os_signal": os_signal,
        "rule_map": rule_map,
    }

    return filtered, stats


def filter_sca_sarif(sarif: dict) -> tuple:
    """SCA SARIF: keep all findings, deduplicate, enrich security-severity."""
    if not sarif or not sarif.get("runs"):
        return sarif, {}

    run = sarif["runs"][0]
    results = run.get("results", [])
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    rule_map = {r["id"]: r for r in rules if "id" in r}

    deduped = deduplicate_results(list(results), rule_map)

    filtered = copy.deepcopy(sarif)
    filtered["runs"][0]["results"] = deduped
    enrich_sarif_rules(filtered)

    stats = {
        "total_raw": len(results),
        "final_kept": len(deduped),
        "sev_counts": sev_counts(deduped, rule_map),
        "rule_map": rule_map,
        "results": deduped,
    }

    return filtered, stats


def filter_iac_sarif(sarif: dict) -> tuple:
    """IaC SARIF: keep all findings, enrich security-severity."""
    if not sarif or not sarif.get("runs"):
        return sarif, {}

    run = sarif["runs"][0]
    results = run.get("results", [])
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    rule_map = {r["id"]: r for r in rules if "id" in r}

    deduped = deduplicate_results(list(results), rule_map)

    filtered = copy.deepcopy(sarif)
    filtered["runs"][0]["results"] = deduped
    enrich_sarif_rules(filtered)

    stats = {
        "total_raw": len(results),
        "final_kept": len(deduped),
        "sev_counts": sev_counts(deduped, rule_map),
        "rule_map": rule_map,
        "results": deduped,
    }

    return filtered, stats


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def sev_counts(findings: list, rule_map: dict) -> dict:
    counts = {}
    for r in findings:
        s = get_severity(r, rule_map)
        counts[s] = counts.get(s, 0) + 1
    return counts


def md_table(rows: list, headers: list) -> str:
    if not rows:
        return "_No findings._\n\n"
    sep = ["---"] * len(headers)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n\n"


def fmt_src(src: str, max_len: int = 40) -> str:
    s = src.replace("/app/node_modules/", "…/").replace("/app/", "")
    if len(s) > max_len:
        s = "…" + s[-(max_len - 1):]
    return s


def sev_badge(sev: str) -> str:
    return f"{SEV_EMOJI.get(sev, '⚪')} {sev}"


# ---------------------------------------------------------------------------
# Console + Step Summary reporting
# ---------------------------------------------------------------------------

def print_image_report(stats: dict):
    if not stats:
        print("  (no container image scan data)")
        return

    rule_map = stats["rule_map"]
    bar = "=" * 80

    print(f"\n{bar}")
    print("  CONTAINER IMAGE SCAN — PARSED RESULTS")
    print(bar)
    print(f"  Raw findings total  : {stats['total_raw']}")
    print(f"  Application pkgs    : {stats['app_kept']}  "
          f"(C:{stats['app_counts'].get('CRITICAL',0)} "
          f"H:{stats['app_counts'].get('HIGH',0)} "
          f"M:{stats['app_counts'].get('MEDIUM',0)} "
          f"L:{stats['app_counts'].get('LOW',0)})")
    print(f"  OS pkgs actionable  : {stats['os_actionable']}  "
          f"(HIGH/CRIT + fix exists)")
    print(f"  OS pkgs suppressed  : {stats['os_suppressed']}  "
          f"(no fix or severity < HIGH)")
    print(f"  Final kept (dedup)  : {stats['final_kept']}")
    print(bar)

    if stats.get("app_findings"):
        print("\n  APPLICATION PACKAGES  (developer-owned dependencies):")
        print(f"  {'Package':<22} {'CVE':<20} {'Severity':<10} "
              f"{'Version':<12} {'Fixed In':<16} Source")
        print("  " + "-" * 100)
        for r in stats["app_findings"][:50]:  # cap at 50 for readability
            cve = r.get("ruleId", "")
            name, ver = get_package_name_ver(r, rule_map)
            sev = get_severity(r, rule_map)
            fv = get_fixed_version(r, rule_map) or "—"
            src = fmt_src(get_source_path(r), 35)
            print(f"  {name:<22} {cve:<20} {sev:<10} {ver:<12} {fv:<16} {src}")

    if stats.get("os_signal"):
        print(f"\n  OS PACKAGES — ACTIONABLE  (HIGH/CRIT + fix available):")
        print(f"  {'Package':<26} {'CVE':<20} {'Severity':<10} "
              f"{'Version':<26} Fix Available")
        print("  " + "-" * 100)
        for r in stats["os_signal"][:50]:
            cve = r.get("ruleId", "")
            name, ver = get_package_name_ver(r, rule_map)
            sev = get_severity(r, rule_map)
            fv = get_fixed_version(r, rule_map)
            print(f"  {name:<26} {cve:<20} {sev:<10} {ver:<26} {fv}")


def print_sca_report(stats: dict):
    if not stats:
        print("  (no SCA scan data)")
        return

    rule_map = stats["rule_map"]
    sc = stats["sev_counts"]
    print(f"\n  SCA — SOURCE DEPENDENCY VULNERABILITIES")
    print(f"  Raw: {stats['total_raw']} | After dedup: {stats['final_kept']}  "
          f"(C:{sc.get('CRITICAL',0)} H:{sc.get('HIGH',0)} "
          f"M:{sc.get('MEDIUM',0)} L:{sc.get('LOW',0)})")

    if stats.get("results"):
        print(f"  {'Package':<30} {'CVE':<22} {'Severity':<10} "
              f"{'Version':<15} {'Fixed In':<15}")
        print("  " + "-" * 95)
        for r in stats["results"][:30]:
            cve = r.get("ruleId", "")
            name, ver = get_package_name_ver(r, rule_map)
            sev = get_severity(r, rule_map)
            fv = get_fixed_version(r, rule_map) or "—"
            print(f"  {name:<30} {cve:<22} {sev:<10} {ver:<15} {fv:<15}")


def print_iac_report(stats: dict):
    if not stats:
        print("  (no IaC scan data)")
        return

    rule_map = stats["rule_map"]
    sc = stats["sev_counts"]
    print(f"\n  IaC — DOCKERFILE MISCONFIGURATION FINDINGS")
    print(f"  Raw: {stats['total_raw']} | After dedup: {stats['final_kept']}  "
          f"(C:{sc.get('CRITICAL',0)} H:{sc.get('HIGH',0)} "
          f"M:{sc.get('MEDIUM',0)} L:{sc.get('LOW',0)})")

    if stats.get("results"):
        print(f"  {'Rule ID':<30} {'Severity':<12} Description")
        print("  " + "-" * 95)
        for r in stats["results"][:30]:
            rid = r.get("ruleId", "")
            sev = get_severity(r, rule_map)
            msg = r.get("message", {}).get("text", "")[:60]
            print(f"  {rid:<30} {sev:<12} {msg}")


def write_step_summary(image_stats, sca_stats, iac_stats, layer_summary):
    """Write GitHub Actions Step Summary markdown."""
    md = []
    md.append("## 🔍 Wiz Unified Security Scan — Findings Report\n\n")

    # ── Overview table ──
    md.append("### Overview\n\n")
    overview_rows = []

    if image_stats:
        overview_rows.append([
            "Container Image (APP)",
            f"**{image_stats['app_kept']}**",
            image_stats['app_counts'].get('CRITICAL', 0),
            image_stats['app_counts'].get('HIGH', 0),
            image_stats['app_counts'].get('MEDIUM', 0),
            image_stats['app_counts'].get('LOW', 0),
            "All severities — npm + app deps",
        ])
        overview_rows.append([
            "Container Image (OS actionable)",
            f"**{image_stats['os_actionable']}**",
            image_stats['os_sig_counts'].get('CRITICAL', 0),
            image_stats['os_sig_counts'].get('HIGH', 0),
            "—", "—",
            "HIGH/CRIT with fix only",
        ])
        overview_rows.append([
            "Container Image (OS suppressed)",
            f"~~{image_stats['os_suppressed']}~~",
            "—", "—", "—", "—",
            "No fix or severity < HIGH",
        ])

    if sca_stats:
        sc = sca_stats["sev_counts"]
        overview_rows.append([
            "SCA (source deps)",
            f"**{sca_stats['final_kept']}**",
            sc.get('CRITICAL', 0), sc.get('HIGH', 0),
            sc.get('MEDIUM', 0), sc.get('LOW', 0),
            "package.json dependencies",
        ])

    if iac_stats:
        ic = iac_stats["sev_counts"]
        overview_rows.append([
            "IaC (Dockerfile)",
            f"**{iac_stats['final_kept']}**",
            ic.get('CRITICAL', 0), ic.get('HIGH', 0),
            ic.get('MEDIUM', 0), ic.get('LOW', 0),
            "Dockerfile misconfigurations",
        ])

    md.append(md_table(overview_rows,
                       ["Category", "Count", "Critical", "High", "Medium", "Low", "Notes"]))

    # ── Application packages detail ──
    if image_stats and image_stats.get("app_findings"):
        rule_map = image_stats["rule_map"]
        md.append(f"### 📦 Application Packages ({image_stats['app_kept']} findings)\n\n")
        md.append("> All severities shown — developer-owned dependencies.\n\n")
        rows = []
        for r in image_stats["app_findings"][:50]:
            cve = r.get("ruleId", "")
            name, ver = get_package_name_ver(r, rule_map)
            sev = get_severity(r, rule_map)
            fv = get_fixed_version(r, rule_map) or "—"
            src = fmt_src(get_source_path(r), 45)
            exploit = "💥" if r.get("properties", {}).get("hasPublicExploit") else ""
            rows.append([f"`{name}`", cve, sev_badge(sev), exploit, ver, fv, f"`{src}`"])
        md.append(md_table(rows,
                           ["Package", "CVE", "Severity", "Exploit", "Version", "Fixed In", "Source"]))

    # ── OS actionable detail ──
    if image_stats and image_stats.get("os_signal"):
        rule_map = image_stats["rule_map"]
        md.append(f"### 🐧 OS Packages — Actionable ({image_stats['os_actionable']} findings)\n\n")
        md.append(f"> HIGH/CRIT with fix. **{image_stats['os_suppressed']}** lower/no-fix suppressed.\n\n")
        rows = []
        for r in image_stats["os_signal"][:50]:
            cve = r.get("ruleId", "")
            name, ver = get_package_name_ver(r, rule_map)
            sev = get_severity(r, rule_map)
            fv = get_fixed_version(r, rule_map)
            rows.append([f"`{name}`", cve, sev_badge(sev), ver, fv])
        md.append(md_table(rows,
                           ["Package", "CVE", "Severity", "Current Version", "Fix Available"]))

    # ── SCA detail ──
    if sca_stats and sca_stats.get("results"):
        rule_map = sca_stats["rule_map"]
        md.append(f"### 🔗 SCA — Source Dependencies ({sca_stats['final_kept']} findings)\n\n")
        rows = []
        for r in sca_stats["results"][:30]:
            cve = r.get("ruleId", "")
            name, ver = get_package_name_ver(r, rule_map)
            sev = get_severity(r, rule_map)
            fv = get_fixed_version(r, rule_map) or "—"
            rows.append([f"`{name}`", cve, sev_badge(sev), ver, fv])
        md.append(md_table(rows,
                           ["Package", "CVE", "Severity", "Version", "Fixed In"]))

    # ── IaC detail ──
    if iac_stats and iac_stats.get("results"):
        rule_map = iac_stats["rule_map"]
        md.append(f"### 🐳 IaC — Dockerfile Findings ({iac_stats['final_kept']} findings)\n\n")
        rows = []
        for r in iac_stats["results"][:30]:
            rid = r.get("ruleId", "")
            sev = get_severity(r, rule_map)
            msg = r.get("message", {}).get("text", "")[:80]
            rows.append([rid, sev_badge(sev), msg])
        md.append(md_table(rows, ["Rule", "Severity", "Description"]))

    # ── Layer breakdown ──
    if layer_summary and layer_summary.get("layers"):
        md.append(f"### 🧅 Per-Layer Breakdown ({layer_summary['total_layers']} layers)\n\n")
        rows = []
        for layer in layer_summary["layers"]:
            rows.append([
                layer["index"],
                layer["vuln_count"],
                f"`{layer['command']}`",
            ])
        md.append(md_table(rows, ["Layer", "Vulns", "Command"]))

    return "".join(md)


# ---------------------------------------------------------------------------
# Ensure valid SARIF structure
# ---------------------------------------------------------------------------

def ensure_valid_sarif(sarif: dict) -> dict:
    """Ensure the SARIF has required fields for GitHub upload."""
    if not sarif:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Wiz", "rules": []}},
                "results": [],
            }],
        }

    if "version" not in sarif:
        sarif["version"] = "2.1.0"
    if "$schema" not in sarif:
        sarif["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    for run in sarif.get("runs", []):
        if "tool" not in run:
            run["tool"] = {"driver": {"name": "Wiz", "rules": []}}
        if "results" not in run:
            run["results"] = []

    return sarif


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Wiz Unified Security Scan SARIF Parser")
    parser.add_argument("--image-sarif", default="image.sarif",
                        help="Container image SARIF from wizcli docker scan")
    parser.add_argument("--sca-sarif", default="dir.sarif",
                        help="SCA SARIF from wizcli dir scan")
    parser.add_argument("--iac-sarif", default="dockerfile.sarif",
                        help="IaC SARIF from wizcli iac scan")
    parser.add_argument("--layers-json", default="image-layers.json",
                        help="Per-layer JSON from --driver mountWithLayers")
    parser.add_argument("--output-dir", default="filtered",
                        help="Directory for filtered SARIF output")

    # Legacy positional args support (backward compat)
    parser.add_argument("legacy_in", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("legacy_out", nargs="?", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Legacy mode: parse_container_scan.py image.sarif image-filtered.sarif
    if args.legacy_in and args.legacy_out:
        sarif = load_json(args.legacy_in)
        if not sarif:
            print(f"::error::SARIF file not found: {args.legacy_in}")
            sys.exit(1)
        filtered, stats = filter_image_sarif(sarif)
        save_json(filtered, args.legacy_out)
        print_image_report(stats)
        return

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    bar = "=" * 80
    print(f"\n{bar}")
    print("  WIZ UNIFIED SECURITY SCAN — PARSER")
    print(bar)

    # ── Container Image ──
    image_stats = None
    image_sarif = load_json(args.image_sarif)
    if image_sarif:
        filtered_image, image_stats = filter_image_sarif(image_sarif)
        filtered_image = ensure_valid_sarif(filtered_image)
        save_json(filtered_image, os.path.join(output_dir, "image-filtered.sarif"))
        print_image_report(image_stats)
    else:
        print(f"\n  [SKIP] Container image SARIF not found: {args.image_sarif}")
        # Write empty SARIF so category upload doesn't break
        save_json(ensure_valid_sarif(None), os.path.join(output_dir, "image-filtered.sarif"))

    # ── SCA ──
    sca_stats = None
    sca_sarif = load_json(args.sca_sarif)
    if sca_sarif:
        filtered_sca, sca_stats = filter_sca_sarif(sca_sarif)
        filtered_sca = ensure_valid_sarif(filtered_sca)
        save_json(filtered_sca, os.path.join(output_dir, "sca-filtered.sarif"))
        print_sca_report(sca_stats)
    else:
        print(f"\n  [SKIP] SCA SARIF not found: {args.sca_sarif}")
        save_json(ensure_valid_sarif(None), os.path.join(output_dir, "sca-filtered.sarif"))

    # ── IaC ──
    iac_stats = None
    iac_sarif = load_json(args.iac_sarif)
    if iac_sarif:
        filtered_iac, iac_stats = filter_iac_sarif(iac_sarif)
        filtered_iac = ensure_valid_sarif(filtered_iac)
        save_json(filtered_iac, os.path.join(output_dir, "iac-filtered.sarif"))
        print_iac_report(iac_stats)
    else:
        print(f"\n  [SKIP] IaC SARIF not found: {args.iac_sarif}")
        save_json(ensure_valid_sarif(None), os.path.join(output_dir, "iac-filtered.sarif"))

    # ── Layers ──
    layer_summary = parse_layers(args.layers_json)
    if layer_summary and layer_summary.get("layers"):
        print(f"\n  PER-LAYER BREAKDOWN ({layer_summary['total_layers']} layers):")
        for layer in layer_summary["layers"]:
            print(f"    Layer {layer['index']:>2}: {layer['vuln_count']:>4} vulns | {layer['command']}")

    # ── Step Summary ──
    summary_md = write_step_summary(image_stats, sca_stats, iac_stats, layer_summary)
    ghs = os.environ.get("GITHUB_STEP_SUMMARY")
    if ghs:
        with open(ghs, "a", encoding="utf-8") as f:
            f.write(summary_md)

    # Also write to file for artifact archival
    summary_path = os.path.join(output_dir, "wiz-summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_md)

    # ── Final summary notice ──
    parts = []
    if image_stats:
        parts.append(f"Image: {image_stats['final_kept']} kept / {image_stats['total_raw']} raw")
    if sca_stats:
        parts.append(f"SCA: {sca_stats['final_kept']}")
    if iac_stats:
        parts.append(f"IaC: {iac_stats['final_kept']}")
    notice = " | ".join(parts) if parts else "No scan data found"

    print(f"\n{bar}")
    print(f"  SUMMARY: {notice}")
    print(bar)
    print(f"  Filtered SARIFs written to: {output_dir}/")
    print(f"  Step Summary: {summary_path}")
    print(f"::notice title=Wiz Parser::{notice}")


if __name__ == "__main__":
    main()
