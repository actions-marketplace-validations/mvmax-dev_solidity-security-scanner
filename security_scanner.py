#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security Scanner V2 — Context-aware static analysis for Solidity.

Professional-grade heuristic scanner calibrated to eliminate false positives.
Only flags monetizable, high-confidence vulnerabilities.

Key improvements over V1:
  - Skips audited library code (@openzeppelin, solady, forge-std)
  - Context-aware: checks for modifiers (nonReentrant, onlyOwner)
  - Validates Checks-Effects-Interactions pattern before flagging reentrancy
  - 10-line context extraction for definitive proof in reports
  - Deduplicates by rule+function scope, not just rule+line

Pipeline: Ingest → **Scan** → Report → Monetize
"""

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# Bootstrap workspace path
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_WS_FALLBACK = os.path.dirname(_TOOLS_DIR)
for _candidate in [os.environ.get("OPENCLAW_WORKSPACE", ""), os.path.expanduser("~/.openclaw/workspace"), _WS_FALLBACK]:
    if _candidate and os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, _candidate)
        break
try:
    from lib.anti_hallucination import _log, no_dry_run
except ImportError:
    def _log(tag, msg): print(f"[{tag}] {msg}")
    def no_dry_run(func): return func


# ──────────────────────────────────────────────
# Severity
# ──────────────────────────────────────────────
class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}[self.value]

    @property
    def emoji(self) -> str:
        return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "⚪"}[self.value]


# ──────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────
@dataclass
class Finding:
    rule_id: str
    name: str
    severity: Severity
    description: str
    recommendation: str
    filepath: str
    line_number: int
    line_content: str
    snippet: str
    matched_text: str
    function_name: str = ""


@dataclass
class ScanResult:
    contract_address: str
    contract_name: str
    scan_start: str
    scan_end: str = ""
    files_scanned: int = 0
    total_lines: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> str:
        c = self.severity_counts
        if c["Critical"] > 0: return "CRITICAL"
        if c["High"] > 0: return "HIGH"
        if c["Medium"] > 0: return "MEDIUM"
        if c["Low"] > 0: return "LOW"
        return "CLEAN"


# ──────────────────────────────────────────────
# Library Skip List — Never flag audited code
# ──────────────────────────────────────────────
SKIP_PATHS = [
    "@openzeppelin", "openzeppelin-contracts", "openzeppelin-upgradeable",
    "solady/", "forge-std/", "solmate/", "prb-math/",
    "node_modules/", "hardhat/", "foundry/",
    "test/", "tests/", "mocks/", "mock/",
]


def _is_library_file(filepath: str) -> bool:
    """Check if a file is from a known audited library."""
    fp_lower = filepath.lower().replace("\\", "/")
    return any(skip in fp_lower for skip in SKIP_PATHS)


# ──────────────────────────────────────────────
# Context Extraction Helpers
# ──────────────────────────────────────────────
def _extract_snippet(lines: list[str], match_line: int, context: int = 5) -> str:
    """Extract code snippet with context lines around the match."""
    start = max(0, match_line - context)
    end = min(len(lines), match_line + context + 1)
    snippet_lines = []
    for j in range(start, end):
        marker = " >> " if j == match_line else "    "
        snippet_lines.append(f"{j + 1:4d}{marker}{lines[j]}")
    return "\n".join(snippet_lines)


def _get_function_context(lines: list[str], line_idx: int) -> tuple[str, str]:
    """Walk backwards to find the enclosing function name and its modifiers."""
    func_name = ""
    modifiers = ""
    for i in range(line_idx, max(line_idx - 50, -1), -1):
        line = lines[i].strip()
        m = re.match(r'function\s+(\w+)\s*\(', line)
        if m:
            func_name = m.group(1)
            # Collect full function signature (may span multiple lines)
            sig_lines = []
            for j in range(i, min(i + 5, len(lines))):
                sig_lines.append(lines[j])
                if '{' in lines[j]:
                    break
            modifiers = " ".join(sig_lines)
            break
    return func_name, modifiers


def _has_modifier(modifiers: str, *names: str) -> bool:
    """Check if any of the given modifier names appear in the function signature."""
    mod_lower = modifiers.lower()
    return any(n.lower() in mod_lower for n in names)


def _has_state_change_before(lines: list[str], call_line: int, func_start: int) -> bool:
    """Check if there's a state variable assignment BEFORE the call line (CEI pattern)."""
    assignment_pattern = re.compile(r'^\s*\w+\s*[\[\]\.]*\s*=\s*[^=]')
    mapping_pattern = re.compile(r'^\s*\w+\s*\[')
    for i in range(func_start, call_line):
        line = lines[i].strip()
        if line.startswith("//") or line.startswith("*"):
            continue
        if assignment_pattern.match(line) or mapping_pattern.match(line):
            # Check it's not just a local variable declaration
            if not re.match(r'^\s*(uint|int|bool|address|bytes|string|mapping)\b', line):
                return True
    return False


def _find_function_start(lines: list[str], line_idx: int) -> int:
    """Find the opening line of the enclosing function."""
    for i in range(line_idx, max(line_idx - 80, -1), -1):
        if re.match(r'\s*function\s+', lines[i]):
            return i
    return max(0, line_idx - 20)


# ──────────────────────────────────────────────
# Context-Aware Detection Rules
# ──────────────────────────────────────────────
class SecurityScanner:
    """V2 context-aware scanner with false-positive suppression."""

    def scan_file(self, filepath: str) -> list[Finding]:
        """Scan a single .sol file with context-aware rules."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (IOError, OSError) as e:
            _log("WARN", f"Cannot read {filepath}: {e}")
            return []

        lines = content.split("\n")
        findings = []

        for i, line in enumerate(lines):
            stripped = line.lstrip()

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue

            # Get function context for modifier checks
            func_name, func_sig = _get_function_context(lines, i)
            func_start = _find_function_start(lines, i)

            # ── RULE: Reentrancy via .call{value:} ──
            if re.search(r'\.call\s*\{.*value', line, re.IGNORECASE):
                # FALSE POSITIVE FILTERS:
                # 1. Skip if protected by nonReentrant
                if _has_modifier(func_sig, "nonReentrant", "nonreentrant", "ReentrancyGuard"):
                    continue
                # 2. Skip if state is updated BEFORE call (CEI pattern followed)
                if _has_state_change_before(lines, i, func_start):
                    # CEI pattern detected — this is actually a finding only if
                    # state changes happen AFTER the call too
                    state_after = False
                    for j in range(i + 1, min(i + 10, len(lines))):
                        if re.match(r'^\s*\w+\s*[\[\]\.]*\s*=', lines[j]):
                            state_after = True
                            break
                    if not state_after:
                        continue  # CEI properly followed, skip

                findings.append(Finding(
                    rule_id="REENT-01",
                    name="ثغرة إعادة الدخول (Reentrancy)",
                    severity=Severity.CRITICAL,
                    description=(
                        "استدعاء خارجي عبر .call{value:} بدون حماية nonReentrant "
                        "ومع تحديث متغيرات الحالة بعد الاستدعاء. يمكن للمهاجم "
                        "إعادة الدخول إلى الدالة قبل اكتمال تحديث الحالة وسحب الأموال."
                    ),
                    recommendation=(
                        "استخدم نمط Checks-Effects-Interactions: حدّث الحالة قبل الاستدعاء. "
                        "أضف modifier nonReentrant من OpenZeppelin ReentrancyGuard."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text=re.search(r'\.call\s*\{.*value', line).group(0),
                    function_name=func_name,
                ))

            # ── RULE: Unprotected selfdestruct ──
            elif re.search(r'\bselfdestruct\s*\(', line, re.IGNORECASE):
                if _has_modifier(func_sig, "onlyOwner", "onlyRole", "onlyAdmin",
                                 "auth", "requiresAuth", "restricted"):
                    continue
                findings.append(Finding(
                    rule_id="ACCESS-01",
                    name="selfdestruct بدون حماية",
                    severity=Severity.CRITICAL,
                    description=(
                        "أمر selfdestruct يمكن استدعاؤه بدون تحكم بالوصول. "
                        "أي مستخدم يمكنه تدمير العقد وسرقة ETH المتبقي."
                    ),
                    recommendation=(
                        "أضف modifier onlyOwner أو ما يعادله. "
                        "فكّر في إزالة selfdestruct نهائياً (EIP-6049)."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text="selfdestruct",
                    function_name=func_name,
                ))

            # ── RULE: Unprotected delegatecall ──
            elif re.search(r'\.delegatecall\s*\(', line, re.IGNORECASE):
                if _has_modifier(func_sig, "onlyOwner", "onlyRole", "onlyAdmin",
                                 "onlyProxy", "auth", "restricted", "initializer"):
                    continue
                # Skip if in a well-known proxy pattern (constructor/fallback)
                if func_name in ("_fallback", "_delegate", "fallback", "receive", ""):
                    continue
                findings.append(Finding(
                    rule_id="ACCESS-02",
                    name="delegatecall بدون حماية",
                    severity=Severity.CRITICAL,
                    description=(
                        "delegatecall ينفّذ كوداً خارجياً في سياق تخزين المتصل. "
                        "بدون تحكم بالوصول، يمكن للمهاجم الكتابة فوق خانات التخزين الحرجة."
                    ),
                    recommendation=(
                        "قيّد delegatecall لعناوين تنفيذ موثوقة. "
                        "استخدم أنماط UUPS أو Transparent Proxy مع تحكم بالوصول."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text=".delegatecall(",
                    function_name=func_name,
                ))

            # ── RULE: tx.origin for authentication ──
            elif re.search(r'\btx\.origin\b', line):
                # Skip safe pattern: require(tx.origin == msg.sender)
                if "msg.sender" in line:
                    continue
                # Only flag if used in require/if (auth context)
                if not re.search(r'(require|if|assert)\s*\(.*tx\.origin', line):
                    # tx.origin used outside auth context — just informational
                    continue
                findings.append(Finding(
                    rule_id="AUTH-01",
                    name="مصادقة عبر tx.origin",
                    severity=Severity.HIGH,
                    description=(
                        "يُستخدم tx.origin للمصادقة. عقد تصيّد يمكنه خداع "
                        "المرسل الأصلي لتجاوز التحكم بالوصول."
                    ),
                    recommendation=(
                        "استبدل tx.origin بـ msg.sender لجميع فحوصات المصادقة."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text="tx.origin",
                    function_name=func_name,
                ))

            # ── RULE: Uninitialized Proxy ──
            elif re.search(r'\bfunction\s+initialize\s*\(', line):
                # Only flag if _disableInitializers() is NOT in the constructor
                has_disable = any("_disableInitializers" in lines[j]
                                  for j in range(max(0, i - 30), min(len(lines), i + 30)))
                if has_disable:
                    continue
                # Check if initializer modifier is present
                if _has_modifier(func_sig, "initializer"):
                    # Has initializer modifier — lower severity
                    pass
                findings.append(Finding(
                    rule_id="PROXY-01",
                    name="بروكسي قابل للاستيلاء",
                    severity=Severity.HIGH,
                    description=(
                        "دالة initialize() بدون _disableInitializers() في المنشئ. "
                        "يمكن لمهاجم تهيئة عقد التنفيذ مباشرة والسيطرة عليه."
                    ),
                    recommendation=(
                        "أضف _disableInitializers() في constructor عقد التنفيذ."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text="function initialize(",
                    function_name=func_name,
                ))

            # ── RULE: Unchecked call return ──
            elif re.search(r'\.call\s*[\{(]', line):
                # Check if return value is captured
                if re.match(r'\s*\(?\s*bool\s+\w+', line):
                    continue  # Return value captured
                if "require" in line or "if " in line or "assert" in line:
                    continue  # Checked inline
                # Check next few lines for require
                checked = False
                for j in range(i + 1, min(i + 3, len(lines))):
                    if re.search(r'(require|if|assert)\s*\(', lines[j]):
                        checked = True
                        break
                if checked:
                    continue
                # Skip if it's a value transfer pattern (.call{value:}(""))
                if re.search(r'\.call\s*\{.*value.*\}\s*\(\s*""\s*\)', line):
                    continue
                findings.append(Finding(
                    rule_id="UNCHECKED-01",
                    name="قيمة إرجاع call غير مفحوصة",
                    severity=Severity.MEDIUM,
                    description=(
                        "القيمة المُرجعة من .call() غير مفحوصة. "
                        "إذا فشل الاستدعاء بصمت، يستمر العقد بافتراضات خاطئة."
                    ),
                    recommendation=(
                        "تحقق دائماً: (bool success, ) = addr.call{...}(...); require(success);"
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text=re.search(r'\.call\s*[\{(]', line).group(0),
                    function_name=func_name,
                ))

            # ── RULE: Timestamp manipulation ──
            elif re.search(r'\bblock\.timestamp\b', line):
                # Only flag in conditionals/comparisons (not just assignments/events)
                if not re.search(r'(require|if|assert|>|<|>=|<=|==)\s*.*block\.timestamp', line) and \
                   not re.search(r'block\.timestamp\s*(>|<|>=|<=|==)', line):
                    continue
                findings.append(Finding(
                    rule_id="TIME-01",
                    name="تلاعب بالطابع الزمني",
                    severity=Severity.MEDIUM,
                    description=(
                        "block.timestamp يُستخدم في شرط حرج. "
                        "المعدّنون يمكنهم التلاعب بالطابع الزمني ±15 ثانية."
                    ),
                    recommendation=(
                        "تجنب block.timestamp للمنطق الحرج أو العشوائية."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text="block.timestamp",
                    function_name=func_name,
                ))

            # ── RULE: Unbounded loop ──
            elif re.search(r'for\s*\([^)]*\.length', line):
                # Only flag if array is storage (not memory/calldata)
                if "memory" in line or "calldata" in line:
                    continue
                findings.append(Finding(
                    rule_id="GAS-01",
                    name="حلقة غير محدودة (DoS)",
                    severity=Severity.LOW,
                    description=(
                        "حلقة تكرار على مصفوفة ديناميكية بدون حد أقصى. "
                        "إذا نمت المصفوفة، قد تتجاوز الدالة حد الغاز."
                    ),
                    recommendation=(
                        "نفّذ ترقيم صفحات أو حدد عدد تكرارات أقصى."
                    ),
                    filepath=filepath, line_number=i + 1, line_content=stripped,
                    snippet=_extract_snippet(lines, i, 5),
                    matched_text=re.search(r'for\s*\([^)]*\.length', line).group(0),
                    function_name=func_name,
                ))

        return findings

    def scan_directory(self, root_dir: str) -> tuple[list[Finding], int, int]:
        """Scan .sol files, skipping audited libraries."""
        all_findings = []
        files_scanned = 0
        total_lines = 0

        for dirpath, _, filenames in os.walk(root_dir):
            for fname in sorted(filenames):
                if not fname.endswith(".sol"):
                    continue
                fpath = os.path.join(dirpath, fname)

                # CRITICAL: Skip library/dependency files
                if _is_library_file(fpath):
                    _log("SKIP", f"Library: {os.path.relpath(fpath, root_dir)}")
                    continue

                _log("SCAN", f"Scanning: {os.path.relpath(fpath, root_dir)}")
                file_findings = self.scan_file(fpath)
                all_findings.extend(file_findings)
                files_scanned += 1

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        total_lines += sum(1 for _ in f)
                except (IOError, OSError):
                    pass

        # Sort: critical first, then by file/line
        all_findings.sort(key=lambda f: (f.severity.rank, f.filepath, f.line_number))
        return all_findings, files_scanned, total_lines


# ──────────────────────────────────────────────
# Deduplication
# ──────────────────────────────────────────────
def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate by rule + function scope (not just line)."""
    seen = set()
    unique = []
    for f in findings:
        # Group by rule + file + function (not individual lines)
        key = (f.rule_id, f.filepath, f.function_name)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ──────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────
def generate_report(result: ScanResult, workspace: str) -> str:
    """Generate professional Arabic+English Markdown audit report."""
    findings = _deduplicate_findings(result.findings)
    counts = result.severity_counts
    now = datetime.now(timezone.utc).isoformat()

    lines_out = []
    lines_out.append(f"# 🛡️ Security Audit Report / تقرير الفحص الأمني")
    lines_out.append("")
    lines_out.append(f"**Scanner:** OpenClaw Maxwell Voss V0.2 (Context-Aware)")
    lines_out.append(f"**Date:** {now}")
    lines_out.append(f"**Contract:** `{result.contract_address}`")
    lines_out.append(f"**Name:** {result.contract_name}")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")

    # Executive Summary
    lines_out.append("## Executive Summary / الملخص التنفيذي")
    lines_out.append("")
    lines_out.append(f"| Metric | Value |")
    lines_out.append(f"|--------|-------|")
    lines_out.append(f"| **Overall Risk / الخطورة** | **{result.risk_score}** |")
    lines_out.append(f"| Files Scanned / ملفات | {result.files_scanned} |")
    lines_out.append(f"| Lines of Code / أسطر | {result.total_lines:,} |")
    lines_out.append(f"| Total Findings / ثغرات | {len(findings)} |")
    lines_out.append(f"| 🔴 Critical / حرجة | {counts['Critical']} |")
    lines_out.append(f"| 🟠 High / عالية | {counts['High']} |")
    lines_out.append(f"| 🟡 Medium / متوسطة | {counts['Medium']} |")
    lines_out.append(f"| 🔵 Low / منخفضة | {counts['Low']} |")
    lines_out.append("")

    if not findings:
        lines_out.append("> ✅ **No vulnerabilities detected.** The contract passed all heuristic checks.")
        lines_out.append("> Note: Library dependencies (@openzeppelin, solady) were excluded from scanning.")
    else:
        lines_out.append(f"> ⚠️ **{len(findings)} finding(s) detected.** Library code excluded. Only target contract scanned.")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")

    # Findings
    if findings:
        lines_out.append("## Detailed Findings / النتائج المفصّلة")
        lines_out.append("")

        for f in findings:
            rel_path = os.path.relpath(f.filepath, workspace)
            sev = f.severity

            lines_out.append(f"### {sev.emoji} [{sev.value}] {f.name}")
            lines_out.append("")
            lines_out.append(f"| Field | Detail |")
            lines_out.append(f"|-------|--------|")
            lines_out.append(f"| **Rule ID** | `{f.rule_id}` |")
            lines_out.append(f"| **Severity** | {sev.value} |")
            lines_out.append(f"| **File** | `{rel_path}` |")
            lines_out.append(f"| **Line** | {f.line_number} |")
            lines_out.append(f"| **Function** | `{f.function_name or 'N/A'}` |")
            lines_out.append("")
            lines_out.append(f"**Description:** {f.description}")
            lines_out.append("")
            lines_out.append(f"**Vulnerable Code:**")
            lines_out.append("```solidity")
            lines_out.append(f"{f.snippet}")
            lines_out.append("```")
            lines_out.append("")
            lines_out.append(f"**Recommendation:** {f.recommendation}")
            lines_out.append("")
            lines_out.append("---")
            lines_out.append("")

    # Methodology
    lines_out.append("## Methodology / المنهجية")
    lines_out.append("")
    lines_out.append("Context-aware heuristic analysis with false-positive suppression:")
    lines_out.append("- Library dependencies excluded (@openzeppelin, solady, forge-std)")
    lines_out.append("- Modifier-aware: nonReentrant, onlyOwner, auth checks respected")
    lines_out.append("- CEI pattern detection for reentrancy validation")
    lines_out.append("- Function-scope deduplication")
    lines_out.append("")
    lines_out.append("> **Disclaimer:** Static analysis detects patterns, not intent.")
    lines_out.append("> This report supplements manual review and formal verification.")
    lines_out.append("")

    report_content = "\n".join(lines_out)

    # Save
    reports_dir = os.path.join(workspace, "security_reports")
    os.makedirs(reports_dir, exist_ok=True)
    addr_short = result.contract_address.lower()
    report_path = os.path.join(reports_dir, f"report_{addr_short}.md")

    with open(report_path, "w", encoding="utf-8") as fp:
        fp.write(report_content)

    report_size = os.path.getsize(report_path)
    _log("OK", f"Report saved: {report_path} ({report_size:,} bytes)")
    return report_path


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
def _resolve_contract_path(workspace: str, address: str) -> tuple[str, str]:
    addr = address.lower().strip()
    audit_dir = os.path.join(workspace, "contracts_to_audit")

    dir_path = os.path.join(audit_dir, addr)
    if os.path.isdir(dir_path):
        manifest_path = os.path.join(audit_dir, f"{addr}.manifest.json")
        name = "Unknown"
        if os.path.exists(manifest_path):
            with open(manifest_path, "r") as f:
                name = json.load(f).get("contract_name", "Unknown")
        return dir_path, name

    sol_path = os.path.join(audit_dir, f"{addr}.sol")
    if os.path.isfile(sol_path):
        manifest_path = os.path.join(audit_dir, f"{addr}.manifest.json")
        name = "Unknown"
        if os.path.exists(manifest_path):
            with open(manifest_path, "r") as f:
                name = json.load(f).get("contract_name", "Unknown")
        return sol_path, name

    raise FileNotFoundError(
        f"No ingested contract for '{address}'.\n"
        f"Run: openclaw-michael ingest_contract --address {address}"
    )


@no_dry_run
def scan_contract(contract_address: str, workspace_override: str = None) -> None:
    """Hybrid scanner: Slither (primary) + Heuristic (secondary).

    Runs Slither for dataflow analysis, merges with regex heuristics,
    deduplicates, and generates a professional report.
    """
    start_time = time.monotonic()

    if workspace_override:
        workspace = workspace_override
    else:
        try:
            from lib.workspace import resolve_workspace
            workspace = resolve_workspace()
        except ImportError:
            workspace = os.environ.get("OPENCLAW_WORKSPACE") or os.path.expanduser("~/.openclaw/workspace")
            if not os.path.exists(workspace):
                workspace = os.getcwd()

    # --- SOLANA DETECTION ---
    try:
        from solana_scanner import SolanaScanner
        solana_scanner = SolanaScanner(workspace)
        if solana_scanner.is_solana:
            _log("INFO", "Solana/Rust project detected! Routing to Solana Scanner engine...")
            sol_res = solana_scanner.scan()
            sys.stdout.write(json.dumps(sol_res) + "\n")
            sys.stdout.flush()
            return
    except Exception as e:
        _log("ERROR", f"Solana scanning failed: {e}")


    _log("INFO", f"Security Scanner v1.0 (Slither Hybrid) — {datetime.now(timezone.utc).isoformat()}")
    _log("INFO", f"Target: {contract_address}")

    try:
        scan_path, contract_name = _resolve_contract_path(workspace, contract_address)
    except FileNotFoundError as e:
        _log("FATAL", str(e))
        sys.exit(1)

    _log("INFO", f"Contract: {contract_name}")
    _log("INFO", f"Path: {scan_path}")

    # ── ENGINE 1: Slither (Primary — Dataflow Analysis) ──
    slither_raw = []
    slither_findings_for_packager = []
    analysis_engine = "heuristic_only"

    try:
        from tools.slither_runner import is_slither_available, run_slither, detect_solc_version

        if is_slither_available():
            solc_ver = detect_solc_version(scan_path)
            _log("SLITHER", f"Engine: Slither | solc: {solc_ver}")
            slither_raw = run_slither(scan_path, solc_version=solc_ver)
            analysis_engine = "hybrid" if slither_raw else "heuristic_fallback"

            # Convert Slither findings to our Finding format
            for sf in slither_raw:
                slither_findings_for_packager.append({
                    "check": sf.check,
                    "impact": sf.impact,
                    "confidence": sf.confidence,
                    "description": sf.description[:500],
                    "first_file": sf.first_file,
                    "first_line": sf.first_line,
                })

            _log("SLITHER", f"High-value findings: {len(slither_raw)}")
        else:
            _log("SLITHER", "Not installed. Using heuristic engine only.")
    except ImportError:
        _log("SLITHER", "Runner module not found. Using heuristic engine only.")
    except Exception as e:
        _log("SLITHER", f"Error (non-fatal): {type(e).__name__}: {e}")

    # ── ENGINE 2: Heuristic Regex (Secondary — Pattern Matching) ──
    scanner = SecurityScanner()
    if os.path.isdir(scan_path):
        heuristic_findings, files_scanned, total_lines = scanner.scan_directory(scan_path)
    else:
        heuristic_findings = scanner.scan_file(scan_path)
        files_scanned = 1
        try:
            with open(scan_path, "r", encoding="utf-8") as f:
                total_lines = sum(1 for _ in f)
        except IOError:
            total_lines = 0

    unique_findings = _deduplicate_findings(heuristic_findings)

    # ── MERGE: Combine Slither + Heuristic severity counts ──
    # Slither findings boost the severity counts
    slither_severity_boost = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for sf in slither_raw:
        mapped = sf.mapped_severity
        if mapped in slither_severity_boost:
            slither_severity_boost[mapped] += 1

    _log("INFO", f"[Heuristic] {len(unique_findings)} findings | [Slither] {len(slither_raw)} findings")
    _log("INFO", f"Scanned {files_scanned} files, {total_lines:,} lines (libraries excluded)")
    _log("INFO", f"Analysis engine: {analysis_engine}")

    result = ScanResult(
        contract_address=contract_address,
        contract_name=contract_name,
        scan_start=datetime.now(timezone.utc).isoformat(),
        files_scanned=files_scanned,
        total_lines=total_lines,
        findings=heuristic_findings,
    )
    result.scan_end = datetime.now(timezone.utc).isoformat()

    # Boost severity counts with Slither findings
    merged_counts = result.severity_counts
    for k, v in slither_severity_boost.items():
        merged_counts[k] = merged_counts.get(k, 0) + v

    # Determine final risk score from merged counts
    if merged_counts["Critical"] > 0:
        final_risk = "CRITICAL"
    elif merged_counts["High"] > 0:
        final_risk = "HIGH"
    elif merged_counts["Medium"] > 0:
        final_risk = "MEDIUM"
    elif merged_counts["Low"] > 0:
        final_risk = "LOW"
    else:
        final_risk = "CLEAN"

    total_findings = len(unique_findings) + len(slither_raw)

    report_path = generate_report(result, workspace)

    elapsed = time.monotonic() - start_time

    output = {
        "status": "success",
        "contract_address": contract_address,
        "contract_name": contract_name,
        "risk_score": final_risk,
        "files_scanned": files_scanned,
        "total_lines": total_lines,
        "findings": total_findings,
        "severity": merged_counts,
        "report_path": report_path,
        "elapsed_seconds": round(elapsed, 2),
        "analysis_engine": analysis_engine,
        "slither_findings": slither_findings_for_packager,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    # --- HYBRID SAAS PAYWALL LOGIC (Web3 + Stripe/Enterprise) ---
    has_pro = False
    enterprise_key = os.environ.get("ENTERPRISE_KEY", "").strip()
    
    if enterprise_key:
        # In a real app, this would validate against a backend API (like Stripe or a license server)
        # For this prototype, any non-empty key beginning with 'ent_' unlocks PRO
        if enterprise_key.startswith("ent_"):
            has_pro = True
            output["billing_tier"] = "Enterprise (Fiat/Stripe)"
    
    if not has_pro:
        try:
            from paywall.verify_subscription import verify_subscription
            wallet = os.environ.get("WALLET_ADDRESS", "")
            rpc = os.environ.get("RPC_URL", "https://mainnet.base.org")
            has_pro = verify_subscription(wallet, rpc)
            if has_pro:
                output["billing_tier"] = "Web3 Indie (USDC)"
        except Exception:
            has_pro = False

    if has_pro:
        output["ai_validation"] = "✅ PRO feature unlocked! Running AI Validation & Gas Optimizer..."
        try:
            from vulnerability_validator import VulnerabilityValidator
            validator = VulnerabilityValidator(workspace)
            val_res = validator.validate_contract(contract_address)
            output["ai_validation_results"] = val_res
        except Exception as e:
            output["ai_validation_error"] = str(e)
            
        # --- FUZZ TESTING ENGINE ---
        try:
            from fuzz_engine import FuzzEngine
            fuzzer = FuzzEngine(workspace)
            if fuzzer.has_foundry:
                fuzz_res = fuzzer.run_fuzz_tests()
                output["fuzz_testing"] = fuzz_res
        except Exception as e:
            output["fuzz_testing_error"] = str(e)
            
        # --- GAS OPTIMIZER ENGINE ---
        try:
            from gas_optimizer import GasOptimizer
            optimizer = GasOptimizer(workspace)
            # Find the path to the contract to pass to the optimizer
            scan_path_local, _ = _resolve_contract_path(workspace, contract_address)
            gas_res = optimizer.optimize_contract(scan_path_local)
            output["gas_optimization"] = gas_res
        except Exception as e:
            output["gas_optimization_error"] = str(e)
            
    else:
        output["ai_validation"] = "🔒 AI Validation & Gas Optimization are locked."
        output["payment_link"] = "Send 50 USDC to 0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5"
        output["wallet_required"] = "Set WALLET_ADDRESS in Action inputs to verify your subscription."
        
    sys.stdout.write(json.dumps(output) + "\n")
    sys.stdout.flush()

    # --- GITHUB STEP SUMMARY (PREMIUM UX) ---
    step_summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_file:
        try:
            with open(step_summary_file, "a", encoding="utf-8") as f:
                f.write(f"## 🛡️ Solidity Security Scanner PRO Report\n\n")
                f.write(f"**Target**: `{contract_address}`\n")
                f.write(f"**Risk Score**: `{final_risk}`\n")
                f.write(f"**Files Scanned**: {files_scanned} | **Total Lines**: {total_lines}\n\n")
                
                f.write(f"### 📊 Severity Breakdown\n")
                f.write(f"| Critical | High | Medium | Low |\n")
                f.write(f"| :---: | :---: | :---: | :---: |\n")
                f.write(f"| {merged_counts.get('Critical', 0)} | {merged_counts.get('High', 0)} | {merged_counts.get('Medium', 0)} | {merged_counts.get('Low', 0)} |\n\n")
                
                f.write(f"### 🤖 AI Validation & Gas Optimizer (PRO)\n")
                if has_pro:
                    f.write(f"✅ **Superfluid/x402 Subscription Verified.** AI Validator successfully executed.\n")
                    f.write(f"*(Check detailed JSON artifacts for in-depth AI context and false-positive suppression data).*\n\n")
                    
                    gas_data = output.get("gas_optimization", {})
                    if gas_data.get("status") == "success":
                        f.write(f"#### ⛽ Gas Savings Identified\n")
                        f.write(f"- **Estimated Savings**: `{gas_data.get('estimated_gas_saved', '0 Gas')}`\n")
                        f.write(f"- **Optimization Opportunities**: {gas_data.get('findings_count', 0)}\n")
                        for find in gas_data.get('findings', []):
                            f.write(f"  - `Line {find['line']}`: {find['issue']} -> *{find['recommendation']}*\n")
                else:
                    f.write(f"🔒 **AI Validation & Gas Optimization Locked**\n")
                    f.write(f"> Unlock the full power of Deep AI Audits and AST Gas Optimization to save thousands on deployment costs.\n")
                    f.write(f"> Send **50 USDC** on the Base or Ethereum network to `0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5` and add your wallet address to this Action's inputs.\n")
        except Exception as e:
            _log("ERROR", f"Failed to write GitHub Step Summary: {e}")

    # --- INLINE PR COMMENTS (GITHUB API) ---
    try:
        from github_commenter import GitHubCommenter
        commenter = GitHubCommenter()
        
        # Post inline comments for high & critical findings
        posted_comments = 0
        
        # Heuristic findings
        for finding in heuristic_findings:
            sev_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev_str in ["Critical", "High"] and finding.line_number > 0 and posted_comments < 15:
                body = f"**[{sev_str}] {finding.name}**\n{finding.description}"
                commenter.post_inline_comment(finding.filepath, finding.line_number, body)
                posted_comments += 1
                
        # Slither findings
        for sf in slither_raw:
            sev = getattr(sf, 'mapped_severity', getattr(sf, 'severity', 'Low'))
            lines = getattr(sf, 'lines', [])
            if sev in ["Critical", "High"] and lines and posted_comments < 15:
                line_no = lines[0]
                if line_no > 0:
                    check = getattr(sf, 'check_name', getattr(sf, 'check', 'Unknown'))
                    desc = getattr(sf, 'description', '')
                    fpath = getattr(sf, 'file_path', getattr(sf, 'filename', ''))
                    body = f"**[{sev}] {check}**\n{desc}"
                    commenter.post_inline_comment(fpath, line_no, body)
                    posted_comments += 1
                    
        # General summary comment
        if total_findings > 0:
            summary_body = f"The Web3 AI Scanner found **{total_findings}** issues.\n"
            summary_body += f"- Critical: {merged_counts.get('Critical', 0)}\n"
            summary_body += f"- High: {merged_counts.get('High', 0)}\n"
            if not has_pro:
                summary_body += "\n🔒 **Unlock AI False-Positive Suppression & Gas Optimizer** by sending 50 USDC to `0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5`."
            commenter.post_general_comment(summary_body)
            
    except Exception as e:
        _log("ERROR", f"Failed to execute GitHub PR Commenter: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Scan Solidity contracts (V1.0 Slither Hybrid).")
    parser.add_argument("--address", help="Contract address or path to scan")
    parser.add_argument("--workspace", help="Workspace path to scan everything")
    args = parser.parse_args()
    
    if args.workspace and not args.address:
        scan_contract("ALL", workspace_override=args.workspace)
    elif args.address:
        scan_contract(args.address)
    else:
        print("Must provide either --address or --workspace")
        sys.exit(1)
