<#
.SYNOPSIS
  Unified Wiz security scan enricher — Container Image + Per-Layer + SCA + IaC.
  Produces: ANSI-colored tabular CI logs, enriched SARIF files, GitHub Job Summary markdown.

.DESCRIPTION
  Input files (all optional — missing files are skipped gracefully):
    image.sarif        — Wiz container image vulnerability SARIF
    image-layers.json  — Wiz per-layer vulnerability JSON (from --driver mountWithLayers)
    dir.sarif          — Wiz SCA source-dependency vulnerability SARIF
    dockerfile.sarif   — Wiz IaC Dockerfile misconfiguration SARIF

  Output files:
    wiz-summary.md     — GitHub Job Summary markdown (all 4 scan types)
    Each SARIF is enriched in-place with security-severity CVSS scores.

  CVSS thresholds (per org spec):
    CRITICAL=9.5  HIGH=8.0  MEDIUM=5.5  LOW=3.0  INFORMATIONAL=0.5  UNKNOWN=0.0
#>
param(
  [string]$ImageSarifPath       = "image.sarif",
  [string]$ImageLayersPath      = "image-layers.json",
  [string]$DirSarifPath         = "dir.sarif",
  [string]$DockerfileSarifPath  = "dockerfile.sarif",
  [string]$SummaryMarkdownPath  = "wiz-summary.md",
  [string]$GitHubRunUrl         = "",
  [string]$AppSecContact        = "appsec@devsecopswithanshu.com"
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
if ([string]::IsNullOrWhiteSpace($AppSecContact)) {
  $AppSecContact = "appsec@devsecopswithanshu.com"
}

$esc        = [char]27
$validSevs  = [System.Collections.Generic.HashSet[string]]@("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL")

# Script-level severity order for Sort-Object closures (must use $script: prefix inside scriptblocks)
$script:sevOrd = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFORMATIONAL=4; INFO=4; UNKNOWN=5 }

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

function Get-Json([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
    return $null
  }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -Depth 100)
  }
  catch {
    Write-Host "[WARN] Cannot parse JSON: $Path — $($_.Exception.Message)"
    return $null
  }
}

function Safe-Str($v, [string]$default = "") {
  if ($null -eq $v) { return $default }
  $s = [string]$v
  return [string]::IsNullOrWhiteSpace($s) ? $default : $s.Trim()
}

function Safe-Int($v) {
  if ($null -eq $v) { return 0 }
  try { return [int]$v } catch { return 0 }
}

function Trunc([string]$s, [int]$max) {
  if (-not $s) { return "" }
  if ($s.Length -le $max) { return $s }
  return $s.Substring(0, [Math]::Max(0, $max - 1)) + [char]0x2026
}

# Get or set a property on PSCustomObject OR IDictionary (OrderedDictionary) safely
function Set-Prop($obj, [string]$name, $value) {
  if ($null -eq $obj) { return }
  if ($obj -is [System.Collections.IDictionary]) {
    $obj[$name] = $value
  } else {
    $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
  }
}

function Get-Prop($obj, [string]$name, $default = $null) {
  if ($null -eq $obj) { return $default }
  if ($obj -is [System.Collections.IDictionary]) {
    return $obj.Contains($name) ? $obj[$name] : $default
  }
  $p = $obj.PSObject.Properties[$name]
  return ($null -ne $p) ? $p.Value : $default
}

function Sev-Color([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "1;37;41"  }   # white on red
    "HIGH"     { return "1;31"     }   # bold red
    "MEDIUM"   { return "1;33"     }   # bold yellow
    "LOW"      { return "1;32"     }   # bold green
    default    { return "0;37"     }   # grey
  }
}

function Sev-GhaLevel([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "error"   }
    "HIGH"     { return "error"   }
    "MEDIUM"   { return "warning" }
    default    { return "note"    }
  }
}

function Sec-Sev([string]$s) {
  # Org-defined CVSS thresholds
  switch ($s.ToUpper()) {
    "CRITICAL"      { return "9.5" }
    "HIGH"          { return "8.0" }
    "MEDIUM"        { return "5.5" }
    "LOW"           { return "3.0" }
    "INFORMATIONAL" { return "0.5" }
    default         { return "0.0" }
  }
}

function Sev-Rank([string]$s) {
  # Null-safe sort key
  $k = [string]$s
  $v = $script:sevOrd[$k]
  return ($null -ne $v) ? [int]$v : 99
}

# ── Parse "Key: value" lines from Wiz SARIF message.text ──────────────────────
# Handles Wiz formats:
#   Package: openssl (1.1.1k)       Installed Version: 1.1.1k    Fixed Version: 1.1.1l
#   CVE: CVE-2023-1234              Severity: HIGH               Description: ...
#   Rule: WIZ-IAC-001               Resource: ./Dockerfile
function Parse-MsgText([string]$text) {
  $f = [ordered]@{}
  if (-not $text) { return $f }
  foreach ($line in ($text -split "`n")) {
    $line = $line.TrimEnd("`r")
    # Key: alphanumeric+space+/- starting with letter, at most 60 chars
    if ($line -match "^([A-Za-z][A-Za-z0-9 /\-\.]{0,58}):\s*(.*)$") {
      $k = $Matches[1].Trim().ToLower()
      $v = $Matches[2].Trim()
      if (-not $f.Contains($k)) { $f[$k] = $v }
    }
  }
  # Multi-line description: grab everything after "Description:" label
  $di = $text.IndexOf("Description:")
  if ($di -ge 0) {
    $descFull = $text.Substring($di + 12).Trim()
    # Only first line for display
    $f["description"] = ($descFull -split "`n")[0].TrimEnd("`r").Trim()
  }
  return $f
}

# ── Multi-source severity resolution ─────────────────────────────────────────
function Resolve-Sev([object]$result, [hashtable]$ruleMap) {
  $msgText = Safe-Str (Get-Prop $result.message "text" "") ""
  $fields  = Parse-MsgText -text $msgText

  # Source 1 — message.text "Severity: X" (most explicit)
  $sev = Safe-Str $fields["severity"] ""
  if ($sev -and $validSevs.Contains($sev.ToUpper())) { return $sev.ToUpper() }

  # Source 2 — result.properties.severity (Wiz primary field)
  $ps = Safe-Str (Get-Prop $result.properties "severity" "") ""
  if ($ps -and $validSevs.Contains($ps.ToUpper())) { return $ps.ToUpper() }

  # Source 3 — rule.properties.severity / security-severity
  $rid  = Safe-Str $result.ruleId ""
  $rule = if ($rid -and $ruleMap.ContainsKey($rid)) { $ruleMap[$rid] } else { $null }
  if ($rule -and $rule.properties) {
    $rs = Safe-Str (Get-Prop $rule.properties "severity" "") ""
    if ($rs -and $validSevs.Contains($rs.ToUpper())) { return $rs.ToUpper() }

    $ss = Safe-Str (Get-Prop $rule.properties "security-severity" "") ""
    if ($ss) {
      $score = [double]0
      if ([double]::TryParse($ss, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$score)) {
        if     ($score -ge 9.0) { return "CRITICAL" }
        elseif ($score -ge 7.0) { return "HIGH" }
        elseif ($score -ge 4.0) { return "MEDIUM" }
        elseif ($score -gt 0.0) { return "LOW" }
        else                    { return "INFORMATIONAL" }
      }
    }
  }

  # Source 4 — SARIF result.level / rule.defaultConfiguration.level
  $lvl = Safe-Str $result.level ""
  if (-not $lvl -and $rule -and $rule.defaultConfiguration) {
    $lvl = Safe-Str $rule.defaultConfiguration.level ""
  }
  switch ($lvl.ToLower()) {
    "error"   { return "HIGH" }
    "warning" { return "MEDIUM" }
    "note"    { return "LOW" }
    "none"    { return "INFORMATIONAL" }
  }
  return "UNKNOWN"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SARIF ENRICHMENT — Adds security-severity, tags, [Wiz Cloud] naming
# Modifies the sarif object in-place; also writes updated levels on results.
# ═══════════════════════════════════════════════════════════════════════════════
function Enrich-Sarif([object]$sarif, [string]$ScanType = "container") {
  if (-not $sarif) { return $sarif }
  if (-not $sarif.runs) { return $sarif }

  $driverNames = @{ container = "WizCLI-Container"; sca = "WizCLI-SCA"; iac = "WizCLI-IaC" }

  foreach ($run in $sarif.runs) {
    # Build rule lookup
    $ruleMap = @{}
    $rules = Get-Prop $run.tool.driver "rules" $null
    if ($rules) { foreach ($r in $rules) { if ($r -and $r.id) { $ruleMap[[string]$r.id] = $r } } }

    # Pass 1 — resolve severity per result; track highest sev per rule; collect package info
    $ruleSevMap = @{}
    $rulePkgMap = @{}   # ruleId → {pkg, ver} — used for enriched GitHub Security alert titles
    if ($run.results) {
      foreach ($res in $run.results) {
        if (-not $res) { continue }
        $sev = Resolve-Sev -result $res -ruleMap $ruleMap
        # Update SARIF level so GitHub Code Scanning colours it correctly
        $res | Add-Member -NotePropertyName level -NotePropertyValue (Sev-GhaLevel -s $sev) -Force
        $rid = Safe-Str $res.ruleId ""
        if ($rid) {
          if (-not $ruleSevMap.ContainsKey($rid)) {
            $ruleSevMap[$rid] = $sev
          } elseif ((Sev-Rank $sev) -lt (Sev-Rank $ruleSevMap[$rid])) {
            $ruleSevMap[$rid] = $sev
          }
          # Collect first-seen package/component info for enriched alert titles
          if (-not $rulePkgMap.ContainsKey($rid)) {
            $msgText = Safe-Str (Get-Prop $res.message "text" "") ""
            $f = Parse-MsgText -text $msgText
            $pkg = Safe-Str $f["package"] ""
            if ($pkg -match "^(.+?)\s*\(") { $pkg = $Matches[1].Trim() }
            if (-not $pkg) { $pkg = Safe-Str $f["component"] "" }
            if (-not $pkg) { $pkg = Safe-Str $f["library"] "" }
            $ver = Safe-Str $f["installed version"] ""
            if (-not $ver) { $ver = Safe-Str $f["version"] "" }
            if (-not $ver) {
              $pkgRaw = Safe-Str $f["package"] ""
              if ($pkgRaw -match "\(([^)]+)\)$") { $ver = $Matches[1].Trim() }
            }
            if ($pkg) { $rulePkgMap[$rid] = @{ pkg = $pkg; ver = $ver } }
          }
        }
      }
    }

    # Pass 2 — enrich rules with security-severity, tags, [Wiz Cloud] naming
    if ($rules) {
      foreach ($r in $rules) {
        if (-not $r -or -not $r.id) { continue }
        $rid = [string]$r.id
        $sev = if ($ruleSevMap.ContainsKey($rid)) { $ruleSevMap[$rid] } else { "UNKNOWN" }

        # Ensure properties object exists
        if ($null -eq (Get-Prop $r "properties" $null)) {
          $r | Add-Member -NotePropertyName properties -NotePropertyValue ([PSCustomObject]@{}) -Force
        }

        # Set security-severity (CVSS score string)
        Set-Prop $r.properties "security-severity" (Sec-Sev -s $sev)

        # Maintain tags array
        $existingTags = @()
        $rawTags = Get-Prop $r.properties "tags" $null
        if ($rawTags) { $existingTags = @($rawTags) }
        if ($existingTags -notcontains "security") { $existingTags += "security" }
        if ($existingTags -notcontains "wiz")      { $existingTags += "wiz" }
        Set-Prop $r.properties "tags" $existingTags

        # Also stamp the resolved severity string
        Set-Prop $r.properties "severity" $sev

        # rule.name — clean "[Wiz Cloud] CVE-XXXX" identifier (strip any existing [Wiz*] prefix)
        $rawName  = Safe-Str (Get-Prop $r "name" "") $rid
        $baseName = $rawName -replace "^\[Wiz[^\]]*\]\s*", ""
        $r | Add-Member -NotePropertyName name -NotePropertyValue "[Wiz Cloud] $baseName" -Force

        # rule.shortDescription.text — enriched title shown in GitHub Security tab as the alert title
        # Format: "[Wiz Cloud] CVE-XXXX | package installed-version"
        $pkgInfo   = if ($rulePkgMap.ContainsKey($rid)) { $rulePkgMap[$rid] } else { $null }
        $pkgSuffix = if ($pkgInfo -and $pkgInfo.pkg) {
          $vs = if ($pkgInfo.ver) { " $($pkgInfo.ver)" } else { "" }
          " | $($pkgInfo.pkg)$vs"
        } else { "" }
        $enrichedTitle = "[Wiz Cloud] $baseName$pkgSuffix"
        if ($null -eq $r.shortDescription) {
          $r | Add-Member -NotePropertyName shortDescription -NotePropertyValue ([PSCustomObject]@{ text = $enrichedTitle }) -Force
        } else {
          $r.shortDescription | Add-Member -NotePropertyName text -NotePropertyValue $enrichedTitle -Force
        }
        if ($null -eq $r.fullDescription) {
          $r | Add-Member -NotePropertyName fullDescription -NotePropertyValue ([PSCustomObject]@{ text = $enrichedTitle }) -Force
        }
      }
    }

    # Set tool driver name for differentiation in GitHub Security → Tool filter
    if ($run.tool -and $run.tool.driver) {
      $dName = if ($driverNames.ContainsKey($ScanType)) { $driverNames[$ScanType] } else { "WizCLI" }
      $run.tool.driver | Add-Member -NotePropertyName name -NotePropertyValue $dName -Force
    }
  }
  return $sarif
}

# ═══════════════════════════════════════════════════════════════════════════════
# ROW EXTRACTION — Converts SARIF into display rows for tables
# ═══════════════════════════════════════════════════════════════════════════════
function Get-SarifRows([object]$sarif) {
  $rows = [System.Collections.Generic.List[object]]::new()
  if (-not $sarif -or -not $sarif.runs) { return $rows }

  foreach ($run in $sarif.runs) {
    $ruleMap = @{}
    $rules = Get-Prop $run.tool.driver "rules" $null
    if ($rules) { foreach ($r in $rules) { if ($r -and $r.id) { $ruleMap[[string]$r.id] = $r } } }

    if (-not $run.results) { continue }
    foreach ($res in $run.results) {
      if (-not $res) { continue }

      $rid  = Safe-Str $res.ruleId "N/A"
      $sev  = Resolve-Sev -result $res -ruleMap $ruleMap
      $rule = if ($ruleMap.ContainsKey($rid)) { $ruleMap[$rid] } else { $null }

      # ── Message text field extraction ────────────────────────────────────
      $msgText = Safe-Str (Get-Prop $res.message "text" "") ""
      $f       = Parse-MsgText -text $msgText

      # Component: check "component", then "package" (Wiz container format)
      $component = Safe-Str $f["component"] ""
      if (-not $component) {
        $pkg = Safe-Str $f["package"] ""
        if ($pkg) {
          # Wiz format: "openssl (1.1.1k)" — strip version in parens
          $component = if ($pkg -match "^(.+?)\s*\(") { $Matches[1].Trim() } else { $pkg }
        }
      }
      if (-not $component) {
        # IaC: try "resource" field
        $component = Safe-Str $f["resource"] ""
      }
      if (-not $component -and $rule -and $rule.name) {
        $component = ([string]$rule.name) -replace "^\[Wiz[^\]]*\]\s*", ""
      }
      if (-not $component) { $component = "N/A" }

      # Version: check "version", then "installed version" (Wiz container format)
      $version = Safe-Str $f["version"] ""
      if (-not $version) { $version = Safe-Str $f["installed version"] "" }
      # Also try to extract from "Package: name (ver)" parenthesised format
      if (-not $version) {
        $pkg = Safe-Str $f["package"] ""
        if ($pkg -match "\(([^)]+)\)$") { $version = $Matches[1].Trim() }
      }
      if (-not $version) { $version = "N/A" }

      # Fixed version: check both "fixed version" and "fix"
      $fixed = Safe-Str $f["fixed version"] ""
      if (-not $fixed) { $fixed = Safe-Str $f["fix"] "" }
      if (-not $fixed) { $fixed = Safe-Str $f["fixedversion"] "" }
      if (-not $fixed) { $fixed = "N/A" }

      # CVE / rule display: check "cve", "vulnerability", then fall back to ruleId
      $cveId = Safe-Str $f["cve"] ""
      if (-not $cveId) { $cveId = Safe-Str $f["vulnerability"] "" }
      if (-not $cveId) { $cveId = Safe-Str $f["rule"] "" }
      if (-not $cveId) { $cveId = $rid }

      # Description
      $desc = Safe-Str $f["description"] ""
      if (-not $desc -and $rule -and $rule.shortDescription -and $rule.shortDescription.text) {
        $desc = ([string]$rule.shortDescription.text) -replace "^\[Wiz[^\]]*\]\s*", ""
      }
      if (-not $desc -and $msgText) { $desc = ($msgText -split "`n")[0].Trim() }

      # Remediation
      $rem = Safe-Str $f["remediation"] ""

      # Display rule: use human-readable name for long UUID IaC rules
      $displayRule = $rid
      if ($rule -and $rule.name) {
        $rName = ([string]$rule.name) -replace "^\[Wiz[^\]]*\]\s*", ""
        # Use human name when ruleId is a UUID (IaC) or very long opaque string
        if ($rid -match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$") {
          $displayRule = $rName
        } elseif ($rid -match "^CVE-\d{4}-\d+$") {
          $displayRule = $rid  # Keep CVE IDs as-is
        }
      }

      # File / location
      $filePath = "N/A"
      if ($res.locations -and @($res.locations).Count -gt 0) {
        $loc = @($res.locations)[0]
        if ($loc -and $loc.physicalLocation -and $loc.physicalLocation.artifactLocation) {
          $uri = $loc.physicalLocation.artifactLocation.uri
          if ($uri) { $filePath = [string]$uri }
        }
      }

      $rows.Add([ordered]@{
        ruleId      = $rid
        displayRule = $displayRule
        cveId       = $cveId
        severity    = $sev
        component   = $component
        version     = $version
        fixed       = $fixed
        remediation = $rem
        desc        = $desc
        file        = $filePath
      })
    }
  }

  return ($rows | Sort-Object { Sev-Rank $_.severity })
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONSOLE TABLE PRINTER
# ═══════════════════════════════════════════════════════════════════════════════
function Print-Section([string]$title, $rows, [string]$scanType = "") {
  $cnt = if ($rows) { @($rows).Count } else { 0 }

  Write-Host ""
  Write-Host "::group::$title ($cnt findings)"
  Write-Host "${esc}[1m╔══════════════════════════════════════════════════════════════════════╗${esc}[0m"
  Write-Host "${esc}[1m║  $($title.PadRight(68))║${esc}[0m"
  Write-Host "${esc}[1m╚══════════════════════════════════════════════════════════════════════╝${esc}[0m"

  if ($cnt -eq 0) {
    Write-Host "  ${esc}[1;32m✔ No findings.${esc}[0m"
    Write-Host "::endgroup::"
    return
  }

  $hdr = "  {0,-38} {1,-24} {2,-10} {3,-18} {4,-18} {5,-30} {6}" -f `
    "RULE / CVE", "COMPONENT", "SEVERITY", "VERSION", "FIXED", "FILE", "DESCRIPTION"
  Write-Host $hdr
  Write-Host ("  " + ("─" * 170))

  foreach ($r in $rows) {
    $col  = Sev-Color -s $r.severity
    $line = "  ${esc}[${col}m{0,-38}${esc}[0m {1,-24} ${esc}[${col}m{2,-10}${esc}[0m {3,-18} {4,-18} {5,-30} {6}" -f `
      (Trunc $r.displayRule 38),
      (Trunc $r.component   24),
      $r.severity,
      (Trunc $r.version     18),
      (Trunc $r.fixed       18),
      (Trunc $r.file        30),
      (Trunc $r.desc        60)
    Write-Host $line
  }

  # Severity summary bar
  $cnts = @{}
  foreach ($r in $rows) {
    $s = [string]$r.severity
    $cnts[$s] = (Safe-Int $cnts[$s]) + 1
  }
  $parts = @("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL","UNKNOWN") |
    Where-Object { $cnts[$_] } |
    ForEach-Object { $c = Sev-Color -s $_; "${esc}[${c}m${_}: $($cnts[$_])${esc}[0m" }

  Write-Host ""
  Write-Host "  ┌─ Severity Summary: $($parts -join '  │  ') ─┐"

  # GHA annotations for critical/high
  foreach ($r in ($rows | Where-Object { $_.severity -in @("CRITICAL","HIGH") } | Select-Object -First 20)) {
    $lvl = Sev-GhaLevel $r.severity
    Write-Host "::${lvl} title=[Wiz Cloud] $($r.severity) in $($r.component)::$($r.cveId) — $($r.component) $($r.version) — Fix: $($r.fixed)"
  }

  Write-Host "::endgroup::"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Container Image Vulnerabilities  (image.sarif)
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "${esc}[1;36m══════════════════════════════════════════════════════${esc}[0m"
Write-Host "${esc}[1;36m  WIZ SECURITY SCAN — UNIFIED REPORT${esc}[0m"
Write-Host "${esc}[1;36m══════════════════════════════════════════════════════${esc}[0m"

$imageSarif    = Get-Json -Path $ImageSarifPath
$containerRows = @()

if ($imageSarif) {
  Write-Host ""
  Write-Host "::group::Enriching image.sarif (Container Vulnerabilities)"
  $imageSarif = Enrich-Sarif -sarif $imageSarif -ScanType "container"
  $imageSarif | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $ImageSarifPath -Encoding utf8NoBOM
  Write-Host "  ✔ image.sarif enriched and written back."
  Write-Host "::endgroup::"
  $containerRows = @(Get-SarifRows -sarif $imageSarif)
  Print-Section -title "Container Image Vulnerabilities (image.sarif)" -rows $containerRows -scanType "container"
} else {
  Write-Host "[INFO] image.sarif not found — skipping container enrichment: $ImageSarifPath"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Per-Layer Vulnerability Report  (image-layers.json)
# ═══════════════════════════════════════════════════════════════════════════════
$layerJson   = Get-Json -Path $ImageLayersPath
$layerGroups = [ordered]@{}

if ($layerJson) {
  # Wiz JSON: top-level result object with osPackages / libraries / applications
  $lr = if ((Get-Prop $layerJson "result" $null)) { $layerJson.result } else { $layerJson }

  $allPkgs = [System.Collections.Generic.List[object]]::new()
  foreach ($key in @("osPackages","libraries","applications")) {
    $items = Get-Prop $lr $key $null
    if ($items) { foreach ($i in $items) { if ($i) { $allPkgs.Add($i) } } }
  }

  Write-Host ""
  Write-Host "::group::Parsing image-layers.json ($($allPkgs.Count) packages found)"

  foreach ($pkg in $allPkgs) {
    if (-not $pkg) { continue }

    $vulns = Get-Prop $pkg "vulnerabilities" $null
    if (-not $vulns -or @($vulns).Count -eq 0) { continue }

    $meta = Get-Prop $pkg "layerMetadata" $null
    if ($null -eq $meta) { continue }

    # Digest / layer ID — try multiple field names Wiz uses
    $lid = ""
    foreach ($fn in @("id","layerId","layerID","digest","layerDigest","sha","hash","shortId")) {
      $v = Get-Prop $meta $fn $null
      if ($v) { $lid = [string]$v; break }
    }
    if (-not $lid) { $lid = "layer-unknown" }

    # Dockerfile instruction — "details" is Wiz's field name
    $instr = ""
    foreach ($fn in @("details","createdBy","instruction","command","cmd","layerInstruction","step")) {
      $v = Get-Prop $meta $fn $null
      if ($v) { $instr = [string]$v; break }
    }

    # Layer order index
    $lidx = 9999
    foreach ($fn in @("index","layerIndex","order","position")) {
      $v = Get-Prop $meta $fn $null
      if ($null -ne $v) { try { $lidx = [int]$v; break } catch {} }
    }

    $isBase = ((Get-Prop $meta "isBaseLayer" $null) -eq $true)

    if (-not $layerGroups.Contains($lid)) {
      $layerGroups[$lid] = [ordered]@{
        index    = $lidx
        instr    = $instr
        isBase   = $isBase
        findings = [System.Collections.Generic.List[object]]::new()
      }
    }

    foreach ($v in $vulns) {
      if (-not $v) { continue }
      $vsev = (Safe-Str (Get-Prop $v "severity" "UNKNOWN") "UNKNOWN").ToUpper()
      if ($vsev -eq "INFO") { $vsev = "INFORMATIONAL" }
      $layerGroups[$lid].findings.Add([ordered]@{
        cve = Safe-Str (Get-Prop $v "name" "N/A") "N/A"
        sev = $vsev
        pkg = Safe-Str (Get-Prop $pkg "name" "N/A") "N/A"
        ver = Safe-Str (Get-Prop $pkg "version" "N/A") "N/A"
        fix = Safe-Str (Get-Prop $v "fixedVersion" "no fix") "no fix"
      })
    }
  }

  Write-Host "  Layers with vulnerabilities: $($layerGroups.Count)"
  Write-Host "::endgroup::"

  # ── Cross-layer CVE deduplication ────────────────────────────────────────────
  # Base image CVEs propagate to every subsequent layer in the Wiz per-layer scan.
  # We only show a CVE at the FIRST layer (lowest index) that introduces it, so
  # each vulnerability appears exactly once in the report.
  $globalFirstLid = @{}   # "pkg|cve" → digest of the layer that introduces it
  foreach ($entry in ($layerGroups.GetEnumerator() | Sort-Object { [int]$_.Value.index })) {
    $lid = $entry.Key
    foreach ($lf in $entry.Value.findings) {
      $k = "$($lf.pkg)|$($lf.cve)"
      if (-not $globalFirstLid.ContainsKey($k)) { $globalFirstLid[$k] = $lid }
    }
  }
  # Rebuild each layer's findings keeping only CVEs introduced by that layer
  foreach ($lid in @($layerGroups.Keys)) {
    $seenInLayer = @{}
    $newFinds    = [System.Collections.Generic.List[object]]::new()
    foreach ($lf in ($layerGroups[$lid]['findings'] | Sort-Object { Sev-Rank $_.sev })) {
      $k = "$($lf.pkg)|$($lf.cve)"
      if ($globalFirstLid[$k] -eq $lid -and -not $seenInLayer.ContainsKey($k)) {
        $seenInLayer[$k] = 1
        $newFinds.Add($lf)
      }
    }
    $layerGroups[$lid]['findings'] = $newFinds
  }

  if ($layerGroups.Count -gt 0) {
    Write-Host ""
    Write-Host "::group::Per-Layer Vulnerability Report ($($layerGroups.Count) layers with findings)"
    Write-Host "${esc}[1m╔══════════════════════════════════════════════════════════════════════╗${esc}[0m"
    Write-Host "${esc}[1m║  PER-LAYER VULNERABILITY BREAKDOWN                                   ║${esc}[0m"
    Write-Host "${esc}[1m╚══════════════════════════════════════════════════════════════════════╝${esc}[0m"

    $lIdx = 0
    $sortedLayers = $layerGroups.GetEnumerator() | Sort-Object { [int]$_.Value.index }

    foreach ($entry in $sortedLayers) {
      $lIdx++
      $lid    = $entry.Key
      $lpay   = $entry.Value
      $lfinds = @($lpay.findings)

      # Skip layers where all CVEs were inherited from an earlier layer
      if ($lfinds.Count -eq 0) { continue }

      $lc = @($lfinds | Where-Object { $_.sev -eq "CRITICAL" }).Count
      $lh = @($lfinds | Where-Object { $_.sev -eq "HIGH" }).Count
      $lm = @($lfinds | Where-Object { $_.sev -eq "MEDIUM" }).Count
      $ll = @($lfinds | Where-Object { $_.sev -eq "LOW" }).Count
      $li = @($lfinds | Where-Object { $_.sev -eq "INFORMATIONAL" }).Count
      $btag = if ($lpay.isBase) { " ${esc}[1;34m[BASE IMAGE]${esc}[0m" } else { "" }

      Write-Host ""
      Write-Host "${esc}[1;36m▶ Layer #${lIdx}${esc}[0m${btag}  ${esc}[2m$(Trunc $lid 72)${esc}[0m"
      if ($lpay.instr) {
        Write-Host "  ${esc}[2mInstruction: $(Trunc $lpay.instr 180)${esc}[0m"
      }
      Write-Host ("  Total: $($lfinds.Count)  " +
        "${esc}[1;37;41m CRIT:$lc ${esc}[0m " +
        "${esc}[1;31m HIGH:$lh ${esc}[0m " +
        "${esc}[1;33m MED:$lm ${esc}[0m " +
        "${esc}[1;32m LOW:$ll ${esc}[0m " +
        "${esc}[0;37m INFO:$li ${esc}[0m")

      # Dedup by pkg+cve, sort by severity
      $seen    = @{}
      $deduped = [System.Collections.Generic.List[object]]::new()
      foreach ($lf in ($lfinds | Sort-Object { Sev-Rank $_.sev })) {
        $k = "$($lf.pkg)|$($lf.cve)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $deduped.Add($lf) }
      }

      Write-Host "  $("{0,-22} {1,-10} {2,-30} {3,-20} {4}" -f "CVE","SEVERITY","PACKAGE","VERSION","FIXED")"
      Write-Host "  $("─" * 110)"
      foreach ($lf in ($deduped | Select-Object -First 10)) {
        $col = Sev-Color -s $lf.sev
        Write-Host ("  ${esc}[${col}m$("{0,-22}" -f (Trunc $lf.cve 22))${esc}[0m " +
          "$("{0,-10} {1,-30} {2,-20} {3}" -f $lf.sev, (Trunc $lf.pkg 30), (Trunc $lf.ver 20), (Trunc $lf.fix 20))")
      }
      if ($deduped.Count -gt 10) {
        Write-Host "  ${esc}[2m  … and $($deduped.Count - 10) more unique vulnerabilities in this layer${esc}[0m"
      }
    }
    Write-Host ""
    Write-Host "::endgroup::"
  } else {
    Write-Host "[INFO] No layer vulnerability findings in: $ImageLayersPath"
  }
} else {
  Write-Host "[INFO] image-layers.json not found — skipping layer report: $ImageLayersPath"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Source Dependencies (SCA)  (dir.sarif)
# ═══════════════════════════════════════════════════════════════════════════════
$scaSarif = Get-Json -Path $DirSarifPath
$scaRows  = @()

if ($scaSarif) {
  Write-Host ""
  Write-Host "::group::Enriching dir.sarif (SCA — Source Dependencies)"
  $scaSarif = Enrich-Sarif -sarif $scaSarif -ScanType "sca"
  $scaSarif | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $DirSarifPath -Encoding utf8NoBOM
  Write-Host "  ✔ dir.sarif enriched and written back."
  Write-Host "::endgroup::"
  $scaRows = @(Get-SarifRows -sarif $scaSarif)
  Print-Section -title "Source Dependencies — SCA (dir.sarif)" -rows $scaRows -scanType "sca"
} else {
  Write-Host "[INFO] dir.sarif not found — skipping SCA enrichment: $DirSarifPath"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Dockerfile Misconfigurations (IaC)  (dockerfile.sarif)
# ═══════════════════════════════════════════════════════════════════════════════
$iacSarif = Get-Json -Path $DockerfileSarifPath
$iacRows  = @()

if ($iacSarif) {
  Write-Host ""
  Write-Host "::group::Enriching dockerfile.sarif (IaC — Dockerfile Misconfigurations)"
  $iacSarif = Enrich-Sarif -sarif $iacSarif -ScanType "iac"
  $iacSarif | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $DockerfileSarifPath -Encoding utf8NoBOM
  Write-Host "  ✔ dockerfile.sarif enriched and written back."
  Write-Host "::endgroup::"
  $iacRows = @(Get-SarifRows -sarif $iacSarif)
  Print-Section -title "Dockerfile Misconfigurations — IaC (dockerfile.sarif)" -rows $iacRows -scanType "iac"
} else {
  Write-Host "[INFO] dockerfile.sarif not found — skipping IaC enrichment: $DockerfileSarifPath"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — GitHub Job Summary (Markdown)
# ═══════════════════════════════════════════════════════════════════════════════
function Count-Sev($rows, [string]$sev) {
  if (-not $rows -or @($rows).Count -eq 0) { return 0 }
  return @($rows | Where-Object { $_.severity -eq $sev }).Count
}

$cCrit = Count-Sev $containerRows "CRITICAL"; $cHigh = Count-Sev $containerRows "HIGH"
$cMed  = Count-Sev $containerRows "MEDIUM";   $cLow  = Count-Sev $containerRows "LOW"
$sCrit = Count-Sev $scaRows "CRITICAL";       $sHigh = Count-Sev $scaRows "HIGH"
$sMed  = Count-Sev $scaRows "MEDIUM";         $sLow  = Count-Sev $scaRows "LOW"
$iCrit = Count-Sev $iacRows "CRITICAL";       $iHigh = Count-Sev $iacRows "HIGH"
$iMed  = Count-Sev $iacRows "MEDIUM";         $iLow  = Count-Sev $iacRows "LOW"

$totalCrit = $cCrit + $sCrit + $iCrit
$totalHigh = $cHigh + $sHigh + $iHigh

$statusBadge = if ($totalCrit -gt 0) { "🔴 CRITICAL issues found" }
               elseif ($totalHigh -gt 0) { "🟠 HIGH issues found" }
               else { "🟢 No critical/high issues" }

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Wiz Security Scan Report")
$md.Add("")
$md.Add("**Status:** $statusBadge")
$md.Add("")
if ($GitHubRunUrl) { $md.Add("> **CI Run:** [$GitHubRunUrl]($GitHubRunUrl)") }
$md.Add("> **AppSec Contact:** $AppSecContact")
$md.Add("")

# ── Summary table ─────────────────────────────────────────────────────────────
$md.Add("## Scan Summary")
$md.Add("")
$md.Add("| Scan Type | Total | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |")
$md.Add("|---|---:|---:|---:|---:|---:|")
$md.Add("| 🐳 Container Image | $($containerRows.Count) | $cCrit | $cHigh | $cMed | $cLow |")
$md.Add("| 📦 Source Dependencies (SCA) | $($scaRows.Count) | $sCrit | $sHigh | $sMed | $sLow |")
$md.Add("| 🏗️ Dockerfile IaC | $($iacRows.Count) | $iCrit | $iHigh | $iMed | $iLow |")
$md.Add("| **🔁 Layers Analyzed** | **$($layerGroups.Count)** | | | | |")
$md.Add("")

# ── Container findings ────────────────────────────────────────────────────────
if ($containerRows.Count -gt 0) {
  $md.Add("## 🐳 Container Image Findings")
  $md.Add("")
  $md.Add("> Scan type: ``wizcli docker scan --driver mountWithLayers``")
  $md.Add("")
  $md.Add("| CVE / Rule | Component | Severity | Installed | Fixed | Description |")
  $md.Add("|---|---|---|---|---|---|")
  foreach ($r in ($containerRows | Select-Object -First 200)) {
    $d   = (Trunc $r.desc 120) -replace '\|', '&#124;'
    $sev = $r.severity
    $badge = switch ($sev) { "CRITICAL" {"🔴"} "HIGH" {"🟠"} "MEDIUM" {"🟡"} "LOW" {"🟢"} default {"⚪"} }
    $md.Add("| ``$($r.displayRule)`` | $($r.component) | $badge $sev | $($r.version) | $($r.fixed) | $d |")
  }
  if ($containerRows.Count -gt 200) {
    $md.Add("")
    $md.Add("_$($containerRows.Count - 200) additional findings omitted — see uploaded SARIF artifact for full list._")
  }
  $md.Add("")
}

# ── Per-layer breakdown ────────────────────────────────────────────────────────
if ($layerGroups.Count -gt 0) {
  $md.Add("## 🔁 Per-Layer Vulnerability Report")
  $md.Add("")
  $md.Add("<details><summary>Expand layer-by-layer breakdown ($($layerGroups.Count) layers with findings)</summary>")
  $md.Add("")

  $lIdx = 0
  foreach ($entry in ($layerGroups.GetEnumerator() | Sort-Object { [int]$_.Value.index })) {
    $lIdx++
    $lid    = $entry.Key
    $lpay   = $entry.Value
    $lfinds = @($lpay.findings)
    if ($lfinds.Count -eq 0) { continue }   # skip layers with only inherited CVEs
    $lc = @($lfinds | Where-Object { $_.sev -eq "CRITICAL" }).Count
    $lh = @($lfinds | Where-Object { $_.sev -eq "HIGH" }).Count
    $lm = @($lfinds | Where-Object { $_.sev -eq "MEDIUM" }).Count
    $ll = @($lfinds | Where-Object { $_.sev -eq "LOW" }).Count
    $btag = if ($lpay.isBase) { " · **BASE IMAGE**" } else { "" }

    $md.Add("### Layer \#${lIdx}${btag}")
    $md.Add("- **Digest:** ``$(Trunc $lid 72)``")
    if ($lpay.instr) { $md.Add("- **Instruction:** ``$(Trunc $lpay.instr 200)``") }
    $md.Add("- **Findings:** $($lfinds.Count) — 🔴 Crit: $lc | 🟠 High: $lh | 🟡 Med: $lm | 🟢 Low: $ll")
    $md.Add("")

    $seen    = @{}
    $deduped = [System.Collections.Generic.List[object]]::new()
    foreach ($lf in ($lfinds | Sort-Object { Sev-Rank $_.sev })) {
      $k = "$($lf.pkg)|$($lf.cve)"
      if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $deduped.Add($lf) }
    }
    $md.Add("| CVE | Severity | Package | Version | Fixed |")
    $md.Add("|---|---|---|---|---|")
    foreach ($lf in ($deduped | Select-Object -First 10)) {
      $badge = switch ($lf.sev) { "CRITICAL"{"🔴"} "HIGH"{"🟠"} "MEDIUM"{"🟡"} "LOW"{"🟢"} default{"⚪"} }
      $md.Add("| $($lf.cve) | $badge $($lf.sev) | $($lf.pkg) | $($lf.ver) | $($lf.fix) |")
    }
    if ($deduped.Count -gt 10) { $md.Add("_… and $($deduped.Count - 10) more unique vulnerabilities in this layer_") }
    $md.Add("")
  }
  $md.Add("</details>")
  $md.Add("")
}

# ── SCA findings ──────────────────────────────────────────────────────────────
if ($scaRows.Count -gt 0) {
  $md.Add("## 📦 Source Dependencies — SCA Findings")
  $md.Add("")
  $md.Add("> Scan type: ``wizcli dir scan``")
  $md.Add("")
  $md.Add("| Rule / CVE | Component | Severity | Version | Fixed | File | Description |")
  $md.Add("|---|---|---|---|---|---|---|")
  foreach ($r in ($scaRows | Select-Object -First 100)) {
    $d    = (Trunc $r.desc 100) -replace '\|', '&#124;'
    $sev  = $r.severity
    $badge = switch ($sev) { "CRITICAL"{"🔴"} "HIGH"{"🟠"} "MEDIUM"{"🟡"} "LOW"{"🟢"} default{"⚪"} }
    $md.Add("| ``$($r.displayRule)`` | $($r.component) | $badge $sev | $($r.version) | $($r.fixed) | $($r.file) | $d |")
  }
  if ($scaRows.Count -gt 100) { $md.Add("_$($scaRows.Count - 100) additional rows omitted_") }
  $md.Add("")
}

# ── IaC findings ──────────────────────────────────────────────────────────────
if ($iacRows.Count -gt 0) {
  $md.Add("## 🏗️ Dockerfile Misconfigurations — IaC Findings")
  $md.Add("")
  $md.Add("> Scan type: ``wizcli iac scan``")
  $md.Add("")
  $md.Add("| Rule | Severity | File | Line | Description |")
  $md.Add("|---|---|---|---|---|")
  foreach ($r in ($iacRows | Select-Object -First 100)) {
    $d    = (Trunc $r.desc 160) -replace '\|', '&#124;'
    $sev  = $r.severity
    $badge = switch ($sev) { "CRITICAL"{"🔴"} "HIGH"{"🟠"} "MEDIUM"{"🟡"} "LOW"{"🟢"} default{"⚪"} }
    $md.Add("| ``$($r.displayRule)`` | $badge $sev | $($r.file) | | $d |")
  }
  $md.Add("")
}

# ── Footer ─────────────────────────────────────────────────────────────────────
$md.Add("---")
$md.Add("_Scan powered by [Wiz](https://www.wiz.io) · AppSec: $AppSecContact_")
$md.Add("")

$md | Set-Content -LiteralPath $SummaryMarkdownPath -Encoding utf8NoBOM
Write-Host ""
Write-Host "✔ Summary written: $SummaryMarkdownPath ($($md.Count) lines)"

# ── Final GHA notices ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "::notice title=Wiz Scan Complete::Container: $($containerRows.Count) findings ($cCrit CRIT / $cHigh HIGH) | SCA: $($scaRows.Count) ($sCrit/$sHigh) | IaC: $($iacRows.Count) ($iCrit/$iHigh) | Layers: $($layerGroups.Count)"
Write-Host "::notice title=AppSec Contact::$AppSecContact"
if ($GitHubRunUrl) { Write-Host "::notice title=CI Run::$GitHubRunUrl" }

exit 0
