#!/usr/bin/env python3
"""
parse_container_scan.py — Wiz Container Scan noise reducer

Reads  : image.sarif  (produced by: wizcli docker scan --output image.sarif,sarif,vulnerabilities)
Writes : image-filtered.sarif  (uploaded to GitHub Security tab)
         GitHub Step Summary    (clean policy-focused tables)
         CI console output      (severity-sorted tables)

FILTER RULES
  Application packages  →  ALL severities kept (developer-owned, always actionable)
  OS packages           →  CRITICAL / HIGH with a fixedVersion only (eliminates ~90% noise)
"""

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


# ---------------------------------------------------------------------------
# SARIF helpers
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_str(obj: dict, *keys, default="") -> str:
    for k in keys:
        v = obj.get(k)
        if v is not None and str(v).strip() not in ("", "-", "N/A", "none", "None"):
            return str(v).strip()
    return default


def get_severity(result: dict, rule_map: dict) -> str:
    """Resolve severity string: result.properties → rule.properties → SARIF level."""
    props = result.get("properties", {})
    sev = get_str(props, "severity", "Severity").upper()
    if sev in SEV_RANK:
        return sev

    rule = rule_map.get(result.get("ruleId", ""), {})
    sev = get_str(rule.get("properties", {}), "severity", "Severity").upper()
    if sev in SEV_RANK:
        return sev

    # Fall back to SARIF level
    level = result.get("level", "note")
    return {"error": "HIGH", "warning": "MEDIUM"}.get(level, "LOW")


def get_fixed_version(result: dict, rule_map: dict) -> str:
    """Extract fixedVersion from result or rule properties."""
    props = result.get("properties", {})
    fv = get_str(props, "fixedVersion", "fixed_version", "fixVersion",
                 "remediationVersion", "remediation")
    if fv:
        return fv
    rule = rule_map.get(result.get("ruleId", ""), {})
    return get_str(rule.get("properties", {}), "fixedVersion", "fixed_version")


def get_package_name_ver(result: dict, rule_map: dict) -> tuple:
    """Return (packageName, packageVersion)."""
    props = result.get("properties", {})
    name = get_str(props, "packageName", "package_name", "name")
    ver  = get_str(props, "packageVersion", "package_version", "version")

    if not name:
        rule = rule_map.get(result.get("ruleId", ""), {})
        # Try rule shortDescription: "CVE-XXXX in <pkg> <version>"
        desc = get_str(rule.get("shortDescription", {}), "text")
        m = re.search(r" in ([^\s]+)\s+([\d][\S]*)", desc)
        if m:
            name, ver = m.group(1), m.group(2)
        else:
            name = result.get("ruleId", "")

    return name, ver


def get_source_path(result: dict) -> str:
    """Extract the artifact/file path from locations[]."""
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


def classify_result(result: dict, rule_map: dict) -> str:
    """Return 'APP' or 'OS'."""
    props = result.get("properties", {})

    # 1. Explicit packageType field (wizcli v1 SARIF)
    pt = get_str(props, "packageType", "type", "package_type").upper()
    if "APP" in pt or "APPLICATION" in pt:
        return "APP"
    if pt == "OS":
        return "OS"

    # 2. Location URI — app packages live under /app/
    src = get_source_path(result)
    if src and ("/app/" in src or "node_modules" in src or "package.json" in src):
        return "APP"

    # 3. Rule helpUri heuristic
    rule = rule_map.get(result.get("ruleId", ""), {})
    help_uri = get_str(rule, "helpUri", "helpURI")
    if not help_uri:
        help_uri = get_str(rule.get("help", {}), "text", "markdown")
    if any(x in help_uri for x in ("github.com/advisories", "npmjs.com", "snyk.io", "ghsa")):
        return "APP"
    if any(x in help_uri for x in ("security-tracker.debian.org", "ubuntu.com/security",
                                    "access.redhat.com", "nvd.nist.gov")):
        return "OS"

    # 4. Message text heuristic
    msg = result.get("message", {}).get("text", "")
    if "/app/" in msg or "package.json" in msg or "node_modules" in msg:
        return "APP"

    return "OS"  # default — conservative (don't misclassify OS as APP)


def is_actionable_os(result: dict, rule_map: dict) -> bool:
    """OS finding is actionable only if severity >= HIGH AND a fix exists."""
    sev = get_severity(result, rule_map)
    if SEV_RANK.get(sev, 0) < 4:   # below HIGH
        return False
    return bool(get_fixed_version(result, rule_map))


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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sarif_in  = sys.argv[1] if len(sys.argv) > 1 else "image.sarif"
    sarif_out = sys.argv[2] if len(sys.argv) > 2 else "image-filtered.sarif"

    if not os.path.exists(sarif_in):
        print(f"::error::SARIF file not found: {sarif_in}")
        sys.exit(1)

    sarif   = load_json(sarif_in)
    runs    = sarif.get("runs", [])
    if not runs:
        print("::warning::No runs in SARIF — nothing to parse")
        sys.exit(0)

    run      = runs[0]
    results  = run.get("results", [])
    rules    = run.get("tool", {}).get("driver", {}).get("rules", [])
    rule_map = {r["id"]: r for r in rules if "id" in r}

    # ── Classify ────────────────────────────────────────────────────────────
    app_findings  = []
    os_signal     = []
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

    # Counts
    app_c     = sev_counts(app_findings, rule_map)
    os_sig_c  = sev_counts(os_signal, rule_map)
    total_raw = len(results)
    t_app     = len(app_findings)
    t_os_sig  = len(os_signal)
    t_os_sup  = len(os_suppressed)

    # ── CI console output ───────────────────────────────────────────────────
    bar = "=" * 72
    print(f"\n{bar}")
    print("  WIZ CONTAINER SCAN — PARSED RESULTS")
    print(bar)
    print(f"  Raw findings total  : {total_raw}")
    print(f"  Application pkgs    : {t_app}  "
          f"(C:{app_c.get('CRITICAL',0)} H:{app_c.get('HIGH',0)} "
          f"M:{app_c.get('MEDIUM',0)} L:{app_c.get('LOW',0)})")
    print(f"  OS pkgs actionable  : {t_os_sig}  "
          f"(HIGH/CRIT + fix exists)  "
          f"C:{os_sig_c.get('CRITICAL',0)} H:{os_sig_c.get('HIGH',0)}")
    print(f"  OS pkgs suppressed  : {t_os_sup}  "
          f"(no fix or severity < HIGH — not uploaded to Security tab)")
    print(bar)

    if app_findings:
        print("\n  APPLICATION PACKAGES  (developer-owned npm dependencies):")
        print(f"  {'Package':<22} {'CVE':<20} {'Severity':<10} "
              f"{'Version':<12} {'Fixed In':<16} Source")
        print("  " + "-" * 96)
        for r in app_findings:
            cve        = r.get("ruleId", "")
            name, ver  = get_package_name_ver(r, rule_map)
            sev        = get_severity(r, rule_map)
            fv         = get_fixed_version(r, rule_map) or "—"
            src        = fmt_src(get_source_path(r), 35)
            exploit    = " 💥" if r.get("properties", {}).get("hasPublicExploit") else "   "
            print(f"  {name:<22} {cve:<20} {sev:<10}{exploit} {ver:<12} {fv:<16} {src}")

    if os_signal:
        print(f"\n  OS PACKAGES — ACTIONABLE  (HIGH/CRIT + fix available):")
        print(f"  {'Package':<26} {'CVE':<20} {'Severity':<10} "
              f"{'Version':<26} Fix Available")
        print("  " + "-" * 96)
        for r in os_signal:
            cve        = r.get("ruleId", "")
            name, ver  = get_package_name_ver(r, rule_map)
            sev        = get_severity(r, rule_map)
            fv         = get_fixed_version(r, rule_map)
            exploit    = " 💥" if r.get("properties", {}).get("hasPublicExploit") else "   "
            print(f"  {name:<26} {cve:<20} {sev:<10}{exploit} {ver:<26} {fv}")

    print()

    # ── GitHub Step Summary ─────────────────────────────────────────────────
    md = []
    md.append("## 🔍 Wiz Container Scan — Findings Report\n\n")
    md.append("> Filtered view: **application packages** (all severities) "
              "+ **OS packages** (HIGH/CRITICAL with a fix only). "
              f"Full SARIF archived as build artifact.\n\n")

    md.append("### Overview\n\n")
    md.append(md_table([
        ["Application packages",  f"**{t_app}**",
         app_c.get("CRITICAL", 0), app_c.get("HIGH", 0),
         app_c.get("MEDIUM", 0),   app_c.get("LOW", 0),
         "All severities — direct + transitive npm deps"],
        ["OS packages (actionable)", f"**{t_os_sig}**",
         os_sig_c.get("CRITICAL", 0), os_sig_c.get("HIGH", 0),
         "—", "—",
         "HIGH/CRIT with fix → uploaded to Security tab"],
        ["OS packages (suppressed)", f"~~{t_os_sup}~~",
         "—", "—", "—", "—",
         "No fix available OR severity < HIGH"],
    ], ["Category", "Count", "Critical", "High", "Medium", "Low", "Notes"]))

    # App table
    md.append(f"### Application Packages ({t_app} findings)\n\n")
    md.append("> All severities shown — developer-owned npm dependencies.\n\n")
    app_rows = []
    for r in app_findings:
        cve       = r.get("ruleId", "")
        name, ver = get_package_name_ver(r, rule_map)
        sev       = get_severity(r, rule_map)
        fv        = get_fixed_version(r, rule_map) or "—"
        src       = fmt_src(get_source_path(r), 45)
        exploit   = "💥" if r.get("properties", {}).get("hasPublicExploit") else ""
        policy    = "❌" if (r.get("properties", {}).get("failedPolicies") or
                             r.get("properties", {}).get("failedPolicy")) else ""
        app_rows.append([
            f"`{name}`", cve,
            f"{SEV_EMOJI.get(sev, '⚪')} {sev}",
            exploit, ver, fv, f"`{src}`", policy,
        ])
    md.append(md_table(app_rows,
                       ["Package", "CVE", "Severity", "Exploit",
                        "Version", "Fixed In", "Source", "Policy"]))

    # OS actionable table
    md.append(f"### OS Packages — Actionable ({t_os_sig} findings)\n\n")
    md.append(f"> HIGH/CRIT with a fix available. "
              f"**{t_os_sup}** lower-severity / no-fix OS findings suppressed.\n\n")
    os_rows = []
    for r in os_signal:
        cve       = r.get("ruleId", "")
        name, ver = get_package_name_ver(r, rule_map)
        sev       = get_severity(r, rule_map)
        fv        = get_fixed_version(r, rule_map)
        exploit   = "💥" if r.get("properties", {}).get("hasPublicExploit") else ""
        os_rows.append([
            f"`{name}`", cve,
            f"{SEV_EMOJI.get(sev, '⚪')} {sev}",
            exploit, ver, fv,
        ])
    md.append(md_table(os_rows,
                       ["Package", "CVE", "Severity", "Exploit",
                        "Current Version", "Fix Available"]))

    ghs = os.environ.get("GITHUB_STEP_SUMMARY")
    if ghs:
        with open(ghs, "a", encoding="utf-8") as f:
            f.write("".join(md))
        print(f"::notice title=Container Scan Summary::"
              f"App: {t_app} | OS actionable: {t_os_sig} | "
              f"OS suppressed: {t_os_sup} (raw total: {total_raw})")

    # ── Write filtered SARIF ────────────────────────────────────────────────
    keep        = app_findings + os_signal
    keep_ids    = {r.get("ruleId") for r in keep}
    kept_rules  = [rule for rule in rules if rule.get("id") in keep_ids]

    import copy
    filtered = copy.deepcopy(sarif)
    frun = filtered["runs"][0]
    frun["results"] = keep
    frun["tool"]["driver"]["rules"] = kept_rules

    with open(sarif_out, "w", encoding="utf-8") as f:
        json.dump(filtered, f, indent=2)

    print(f"✔ Filtered SARIF → {sarif_out}  "
          f"({len(keep)} findings kept, {total_raw - len(keep)} suppressed)")


if __name__ == "__main__":
    main()
