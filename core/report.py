"""
Markdown report generator: compiles all phase findings into a single .md report.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from core.config import Config


def _md_cell(text: str) -> str:
    """Make a string safe for a Markdown table cell / single-line context.

    Escapes pipes (column separators) and collapses newlines to spaces so a
    finding title/value can't break table layout or headings.
    """
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def _fence(content: str) -> str:
    """Return a backtick fence guaranteed longer than any backtick run in content.

    CommonMark allows fences of arbitrary length; using one longer than the
    longest internal run prevents the content from closing the block early.
    """
    longest = 0
    run = 0
    for ch in content:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return "`" * max(3, longest + 1)


def _md_image(caption: str, path: str) -> str:
    """Build a Markdown image that survives special chars in the caption/path."""
    alt = str(caption).replace("[", "\\[").replace("]", "\\]").replace("\n", " ").strip()
    # Angle-bracket form tolerates spaces and parentheses in the path.
    safe_path = str(path).replace("<", "%3C").replace(">", "%3E")
    return f"![{alt}](<{safe_path}>)"


AI_PROMPT = """ROLE: You are a senior Android application penetration tester triaging the RAW output of an
automated SAST/DAST tool (TrashDroid). Automated tooling over-reports — much of what follows is noise:
regex/keyword matches on harmless strings, third-party SDK artifacts, expected platform behaviour, or
issues that only matter on an already-compromised device. The tool's own Severity / Confidence /
"CVSS (estimated)" fields are HEURISTIC — treat them as hints, not ground truth.

PRIMARY OBJECTIVE: Separate real, exploitable findings from false positives. Do NOT just restate the
tool's output. Be skeptical; when the evidence is thin, say so.

For EVERY finding assign a verdict:
  - CONFIRMED      : concrete evidence of a real, exploitable weakness.
  - LIKELY         : probably real but needs ONE manual check (state exactly what to verify).
  - FALSE POSITIVE : noise — give the one-line reason.
  - INFORMATIONAL  : true but not a vulnerability by itself (attack surface / defence-in-depth gap).

Treat the following as FALSE POSITIVE / low-signal UNLESS corroborated by concrete evidence:
  - "Sensitive data" / "PII" regex or Presidio hits where the matched text is a KEY NAME, label,
    enum, placeholder, file path, or framework constant — not an actual secret VALUE.
  - Items owned by a third-party SDK (Firebase, Google, Microsoft Intune/MAM, analytics/crash SDKs)
    rather than the app's own code or the user's data.
  - "Recoverable only on a rooted device" items (app-data / SharedPreferences / DB pulls, memory
    dump, ADB backup): they presuppose device compromise — rate REAL-WORLD risk accordingly, do not
    inflate.
  - OAuth/SSO redirect / deep-link schemes (e.g. msauth.*, fb*, google*) and framework-generated
    intent filters — usually not injectable app entry points.
  - Exported library/framework components (androidx.*, com.google.android.gms.*, com.google.firebase.*)
    flagged as attack surface — not app-owned entry points.
  - allowBackup / debuggable / cleartext flags reported without demonstrated sensitive exposure —
    verify the real data at risk before rating.

For CONFIRMED and LIKELY findings only:
  1. Re-derive a context-aware CVSS 3.1 vector + score from the attack prerequisites
     (network vs local-app / cross-app IPC vs physical/rooted access) — do not copy the tool's estimate.
  2. Map to the specific OWASP MASVS control and MASTG test id.
  3. Give concrete, code-level remediation.
  4. For each High/Critical, write a Jira-ready ticket: title, severity, steps to reproduce, impact, fix.

OUTPUT, in this order:
  A. Executive summary (2-4 sentences) — the real risk posture, noise excluded.
  B. Triage table covering EVERY finding: Finding | Verdict | Real severity | One-line justification.
  C. Detailed write-ups + Jira tickets — CONFIRMED/LIKELY High & Critical only.
  D. "To manually verify" — the checks that would resolve the LIKELY items.
Spend no more than one table row on anything you rule a FALSE POSITIVE."""

EXPECTED_PHASES = [
    "Phase I — Drozer Component Testing",
    "Phase III — Local File System Analysis",
    "Phase IV — Dump File Verification",
    "Phase V — Logcat Monitoring",
    "Phase VI — Memory Analysis",
    "Phase VII — ADB Backup Analysis",
    "Phase VIII — Manifest Analysis",
    "Phase IX — Post-Logout Access Control",
]

# Base CVSS 3.1 metrics per severity bucket. The numeric score is computed from
# these (see _cvss31_base_score) so the score and vector can never disagree.
# Metric order follows the canonical CVSS:3.1 vector string.
_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_BASE_METRICS_BY_SEVERITY: dict[str, dict[str, str]] = {
    "Critical": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "High":     {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "L"},
    "Medium":   {"AV": "N", "AC": "L", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "Low":      {"AV": "N", "AC": "H", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
}

# CVSS 3.1 metric weights.
_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weight depends on Scope.
_PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def _cvss31_roundup(value: float) -> float:
    """Official CVSS 3.1 roundup: smallest one-decimal number >= value (integer-math safe)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def _cvss31_base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS 3.1 base score from a metrics dict (AV/AC/PR/UI/S/C/I/A)."""
    scope = metrics["S"]
    iss = 1 - (
        (1 - _CVSS_WEIGHTS["C"][metrics["C"]])
        * (1 - _CVSS_WEIGHTS["I"][metrics["I"]])
        * (1 - _CVSS_WEIGHTS["A"][metrics["A"]])
    )
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = (
        8.22
        * _CVSS_WEIGHTS["AV"][metrics["AV"]]
        * _CVSS_WEIGHTS["AC"][metrics["AC"]]
        * _PR_WEIGHTS[scope][metrics["PR"]]
        * _CVSS_WEIGHTS["UI"][metrics["UI"]]
    )

    if impact <= 0:
        return 0.0
    if scope == "U":
        return _cvss31_roundup(min(impact + exploitability, 10))
    return _cvss31_roundup(min(1.08 * (impact + exploitability), 10))


def _contextual_cvss(severity: str, title: str, detail: str) -> tuple[str, str]:
    """Derive a context-aware CVSS 3.1 vector and a score computed from that vector.

    The Attack Vector is adjusted by finding type; the score is always recomputed
    from the final metrics so the two can never disagree.
    """
    if severity not in _BASE_METRICS_BY_SEVERITY:
        return "0.0", "N/A"

    text = f"{title}\n{detail}".lower()
    metrics = dict(_BASE_METRICS_BY_SEVERITY[severity])

    # Adjust Attack Vector based on finding context.
    if any(kw in text for kw in ["backup", "usb", "physical"]):
        metrics["AV"] = "P"  # Physical access required
    elif any(kw in text for kw in ["exported", "component", "activity accessible", "post-logout", "intent"]):
        metrics["AV"] = "L"  # Local — requires code on the same device
    elif any(kw in text for kw in ["cleartext", "http://", "network", "mitm"]):
        metrics["AV"] = "N"  # Network-based
    elif any(kw in text for kw in ["sql injection", "path traversal", "content provider"]):
        metrics["AV"] = "L"  # Local unless exposed via deep link

    vector = "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in _METRIC_ORDER)
    score = _cvss31_base_score(metrics)
    return f"{score:.1f}", vector


def _dedupe_findings(config: Config) -> dict[str, list[dict]]:
    """Merge duplicate findings by (phase, title, severity, status)."""
    deduped: dict[str, list[dict]] = {}
    grouped: dict[tuple[str, str, str, str], list[str]] = {}

    for phase_name, phase_findings in config.findings.items():
        for f in phase_findings:
            key = (phase_name, f["title"], f["severity"], f["status"])
            grouped.setdefault(key, []).append(f["detail"])

    for (phase_name, title, severity, status), details in grouped.items():
        merged_detail: str
        if len(details) == 1:
            merged_detail = details[0]
        else:
            variant_lines = [f"Variant {idx}: {d}" for idx, d in enumerate(details, 1)]
            merged_detail = "\n\n---\n\n".join(variant_lines)
        deduped.setdefault(phase_name, []).append(
            {
                "title": title,
                "severity": severity,
                "status": status,
                "detail": merged_detail,
                "occurrences": len(details),
            }
        )

    return deduped


def _confidence_for_finding(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    if any(k in text for k in ["not confirmed", "no evidence", "may indicate", "might"]):
        return "Needs manual validation"
    if any(k in text for k in ["confirmed", "verified via", "dumpsys verification", "logcat evidence"]):
        return "Confirmed"
    return "Likely"


def _remediation_for_finding(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    if "exported components without permission" in text:
        return (
            "Apply explicit permission protection on exported components (prefer signature-level custom permissions). "
            "Set `android:exported=\"false\"` for non-essential external entry points and validate all incoming intents."
        )
    if "activity accessible after logout" in text or "broken access control" in text or "post-logout" in text:
        return (
            "Enforce server-side session validation on every privileged screen/API call. "
            "Clear auth/session tokens on logout and validate auth state in activity onResume(). "
            "Mark sensitive activities non-exported unless externally required."
        )
    if "exported activity" in text or "exported service" in text or "broadcast receiver" in text:
        return (
            "Set component `android:exported=\"false\"` unless external invocation is required. "
            "For required exports, protect with custom signature-level permission and strict "
            "input validation for all intent extras."
        )
    if "logcat" in text or "sensitive data leaked" in text:
        return (
            "Remove sensitive fields from logs, add redaction helpers, and disable verbose logging "
            "in production builds. Add CI checks to block logging of tokens, PII, and credentials."
        )
    if "sql" in text and "logcat" in text:
        return (
            "Avoid logging SQL statements and bind parameters in release builds. "
            "Use structured logging with allowlisted keys only."
        )
    if "backup" in text:
        return (
            "Set `android:allowBackup=\"false\"` for production unless a justified requirement exists. "
            "If backups are required, encrypt sensitive data at rest and exclude secrets from backup."
        )
    if "manifest" in text or "network security" in text:
        return (
            "Harden manifest defaults: reduce exported surface, define permission guards, and add "
            "a strict network security config that forbids cleartext and limits trust anchors."
        )
    return "Perform root-cause analysis, implement least-privilege controls, and re-run this phase to verify closure."


def _business_impact_for_finding(title: str, detail: str) -> str:
    text = f"{title}\n{detail}".lower()
    if "broadcast receiver" in text:
        return "Unprotected receivers can allow external apps to trigger internal actions and abuse business logic."
    if "post-logout" in text or "access control" in text:
        return "Unauthorized account access after logout can lead to privacy breach and account takeover risk."
    if "exported" in text:
        return "Exposed app components can be abused by other apps to trigger unintended privileged behavior."
    if "sensitive data leaked" in text or "logcat" in text:
        return "PII/token leakage in logs can be harvested on rooted/debuggable devices, increasing data exposure."
    if "backup" in text:
        return "Backup exposure may allow offline extraction of local application data."
    return "Security control weakness increases risk of confidentiality/integrity impact under adversarial conditions."


def _phase_coverage(config: Config, deduped_findings: dict[str, list[dict]]) -> list[dict]:
    executed_phases = {entry["phase"] for entry in config.commands_log}
    coverage: list[dict] = []
    for phase in EXPECTED_PHASES:
        ran = phase in executed_phases or phase in deduped_findings
        findings_count = len(deduped_findings.get(phase, []))
        status = "Skipped"
        if ran and findings_count > 0:
            status = "Executed (findings)"
        elif ran:
            status = "Executed (no findings)"
        coverage.append({"phase": phase, "status": status, "findings": findings_count})
    return coverage


def _jira_block(phase_name: str, finding: dict, cvss_score: str, remediation: str, description: str) -> str:
    return (
        f"Summary: {finding['title']}\n"
        f"Issue Type: Security Vulnerability\n"
        f"Priority: {finding['severity']}\n"
        f"Phase: {phase_name}\n"
        f"CVSS: {cvss_score}\n"
        f"Description: {description[:1200]}\n"
        f"Remediation: {remediation}\n"
        "Definition of Done: Fix deployed, regression test added, and DAST re-run confirms closure."
    )


def _extract_target_from_title(title: str) -> str:
    if ":" not in title:
        return ""
    return title.split(":", 1)[1].strip()


def _best_command_evidence(commands_log: list[dict], phase_name: str, finding: dict) -> str:
    """
    Pull the most relevant command evidence for sparse findings.
    Preference: phase + target component in cmd/stdout/stderr.
    """
    target = _extract_target_from_title(finding["title"]).lower()
    phase_entries = [e for e in commands_log if e.get("phase") == phase_name]
    if not phase_entries:
        return ""

    best = None
    best_score = -1
    for entry in phase_entries:
        cmd = entry.get("cmd", "")
        stdout = entry.get("stdout", "")
        stderr = entry.get("stderr", "")
        blob = f"{cmd}\n{stdout}\n{stderr}".lower()
        score = 0
        if target and target in blob:
            score += 5
        if "start" in finding["title"].lower() and "start" in cmd.lower():
            score += 2
        if "broadcast" in finding["title"].lower() and "broadcast" in cmd.lower():
            score += 2
        if "service" in finding["title"].lower() and "service" in cmd.lower():
            score += 2
        if score > best_score:
            best_score = score
            best = entry

    if not best:
        best = phase_entries[-1]
    cmd = best.get("cmd", "")
    stdout = (best.get("stdout") or "").strip()
    stderr = (best.get("stderr") or "").strip()
    rc = best.get("rc", 0)
    return (
        f"Fallback command evidence:\n"
        f"- cmd: {cmd}\n"
        f"- rc: {rc}\n"
        f"- stdout: {(stdout[:600] if stdout else '(empty)')}\n"
        f"- stderr: {(stderr[:600] if stderr else '(empty)')}"
    )


def _normalize_detail(phase_name: str, finding: dict, commands_log: list[dict]) -> str:
    """Fill sparse details with command evidence so findings remain reviewable."""
    detail = finding["detail"]
    sparse = False
    if not detail.strip():
        sparse = True
    if re.search(r"Output:\s*$", detail, re.IGNORECASE | re.MULTILINE):
        sparse = True
    if "Output:\n\n" in detail:
        sparse = True
    if sparse:
        fallback = _best_command_evidence(commands_log, phase_name, finding)
        if fallback:
            return (
                detail.rstrip() +
                "\n\nNo direct module output was captured for this finding. "
                "Use command/screenshot evidence below.\n\n" +
                fallback
            ).strip()
    return detail


def _target_match_tokens(target: str) -> tuple[str, list[str]]:
    """Break a finding target into a full lowercased form plus match tokens.

    Returns (full, tokens) where `full` is the whole lowercased target and
    `tokens` are its alphanumeric segments (len > 2), with the last dotted
    segment — the short class name — included as a strong-match token.
    """
    full = target.lower().strip()
    if not full:
        return "", []
    tokens = {seg for seg in re.split(r"[^a-z0-9]+", full) if len(seg) > 2}
    # Short class/component name (last dotted segment), e.g. com.x.MyService -> myservice
    dotted = [seg for seg in full.split(".") if seg]
    if dotted:
        short = re.sub(r"[^a-z0-9]+", "", dotted[-1])
        if len(short) > 2:
            tokens.add(short)
    return full, sorted(tokens)


def _screenshots_for_finding(
    screenshots: list[dict],
    phase_name: str,
    finding: dict,
    used_paths: set[str],
) -> list[dict]:
    """Match screenshots to a finding by target tokens, with keyword fallbacks.

    Precise but not all-or-nothing: a finding with a clear target prefers
    captions that mention it, but still falls back to keyword/long-token scoring
    so findings with generic captions (e.g. providers) keep their evidence.
    """
    title = finding["title"].lower()
    full_target, target_tokens = _target_match_tokens(_extract_target_from_title(finding["title"]))

    candidates: list[tuple[int, dict]] = []
    for ss in screenshots:
        if ss["phase"] != phase_name or ss["path"] in used_paths:
            continue
        caption = ss["caption"].lower()
        score = 0
        if full_target and full_target in caption:
            score += 10
        if any(tok in caption for tok in target_tokens):
            score += 6
        if "activity" in title and "activity" in caption:
            score += 2
        if "service" in title and "service" in caption:
            score += 2
        if "receiver" in title and "receiver" in caption:
            score += 2
        if "post-logout" in title and "post-logout" in caption:
            score += 2
        for token in title.split():
            if len(token) > 10 and token in caption:
                score += 1
        if score > 0:
            candidates.append((score, ss))

    candidates.sort(key=lambda x: x[0], reverse=True)
    matched = [ss for _, ss in candidates[:3]]
    for ss in matched:
        used_paths.add(ss["path"])
    return matched


class ReportGenerator:
    def __init__(self, config: Config, device_info: dict):
        self.config = config
        self.device_info = device_info

    @staticmethod
    def _extract_entity_type(finding: dict) -> str | None:
        """Extract PII entity type from a Presidio-detected finding."""
        detail = finding.get("detail", "")
        if "Entity type:" in detail:
            match = re.search(r"Entity type:\s*(\S+)", detail)
            return match.group(1) if match else None
        title = finding.get("title", "")
        if title.startswith("PII detected:"):
            match = re.match(r"PII detected:\s*(\S+)", title)
            return match.group(1) if match else None
        return None

    @staticmethod
    def _extract_confidence_score(finding: dict) -> float | None:
        """Extract average confidence score from a Presidio-detected finding."""
        detail = finding.get("detail", "")
        match = re.search(r"Avg confidence:\s*([\d.]+)", detail)
        return float(match.group(1)) if match else None

    def generate(self) -> str:
        c = self.config
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_name = f"DAST_Report_{c.package_name}_{c.timestamp}.md"
        report_path = c.output_dir / report_name
        deduped_findings = _dedupe_findings(c)
        coverage = _phase_coverage(c, deduped_findings)

        sections: list[str] = []
        used_screenshot_paths: set[str] = set()

        # ── AI prompt ──
        if c.report_mode == "internal":
            sections.append(f"```\n{AI_PROMPT}\n```\n")

        # ── Header ──
        sections.append(f"# Android DAST Report — `{c.package_name}`\n")
        sections.append(f"**Generated:** {now}  ")
        sections.append(f"**Device:** {self.device_info.get('model', 'N/A')} "
                        f"(Android {self.device_info.get('android_version', 'N/A')}, "
                        f"SDK {self.device_info.get('sdk', 'N/A')})  ")
        sections.append(f"**Device ID:** `{c.device_id}`  ")
        if c.apk_path:
            sections.append(f"**APK:** `{c.apk_path}`  ")
        if getattr(c, "apk_hash", None):
            sections.append(f"**APK SHA-256:** `{c.apk_hash}`  ")
        sections.append(f"**Pre-installed:** {'Yes' if c.is_preinstalled else 'No'}  ")
        sections.append(f"**Tested logged in:** {'Yes' if c.logged_in else 'No'}\n")

        # ── Executive Summary ──
        sections.append("---\n## Executive Summary\n")
        total = sum(len(v) for v in deduped_findings.values())
        raw_total = sum(len(v) for v in c.findings.values())
        severity_counts: dict[str, int] = {}
        confirmed_count = 0
        for phase_findings in deduped_findings.values():
            for f in phase_findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                if _confidence_for_finding(f["title"], f["detail"]) == "Confirmed":
                    confirmed_count += 1

        sections.append(f"A total of **{total}** finding(s) were identified across "
                        f"**{len([p for p in coverage if p['status'] != 'Skipped'])}** executed phase(s).\n")
        if raw_total != total:
            sections.append(
                f"Deduplication merged repeated entries: raw findings **{raw_total}** -> unique findings **{total}**.\n"
            )
        sections.append(f"Confirmed findings (high-confidence evidence): **{confirmed_count}**.\n")
        if severity_counts:
            sections.append("| Severity | Count |")
            sections.append("|----------|-------|")
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if sev in severity_counts:
                    sections.append(f"| {sev} | {severity_counts[sev]} |")
            sections.append("")

        sections.append("## Phase Coverage\n")
        sections.append("| Phase | Status | Findings |")
        sections.append("|-------|--------|----------|")
        for row in coverage:
            sections.append(f"| {row['phase']} | {row['status']} | {row['findings']} |")
        sections.append("")

        # ── PII Entity Summary (Presidio-detected findings only) ──
        pii_entities: dict[str, dict] = {}  # entity_type -> {count, severities, scores}
        for phase_findings in deduped_findings.values():
            for f in phase_findings:
                detail = f.get("detail", "")
                # Parse entity type from Presidio-style findings
                if "Entity type:" in detail:
                    entity_match = re.search(r"Entity type:\s*(\S+)", detail)
                    if entity_match:
                        etype = entity_match.group(1)
                        score_match = re.search(r"Avg confidence:\s*([\d.]+)", detail)
                        avg_score = float(score_match.group(1)) if score_match else 0.0
                        count_match = re.search(r"Occurrences:\s*(\d+)", detail)
                        count = int(count_match.group(1)) if count_match else 1
                        if etype not in pii_entities:
                            pii_entities[etype] = {"count": 0, "severity": f["severity"], "scores": []}
                        pii_entities[etype]["count"] += count
                        pii_entities[etype]["scores"].append(avg_score)
                elif f.get("title", "").startswith("PII detected:"):
                    # Parse from title format: "PII detected: ENTITY_TYPE (N occurrences)"
                    title_match = re.match(r"PII detected:\s*(\S+)\s*\((\d+)", f["title"])
                    if title_match:
                        etype = title_match.group(1)
                        count = int(title_match.group(2))
                        if etype not in pii_entities:
                            pii_entities[etype] = {"count": 0, "severity": f["severity"], "scores": []}
                        pii_entities[etype]["count"] += count

        if pii_entities:
            sections.append("## PII Entities Detected\n")
            sections.append("| Entity Type | Count | Highest Severity | Avg Confidence |")
            sections.append("|-------------|-------|------------------|----------------|")
            for etype, info in sorted(pii_entities.items(), key=lambda x: x[1]["count"], reverse=True):
                avg_conf = sum(info["scores"]) / len(info["scores"]) if info["scores"] else 0.0
                sections.append(f"| {_md_cell(etype)} | {info['count']} | {info['severity']} | {avg_conf:.2f} |")
            sections.append("")

        # ── Per-phase findings ──
        sections.append("---\n## Detailed Findings\n")
        for phase_name in EXPECTED_PHASES:
            phase_findings = deduped_findings.get(phase_name, [])
            sections.append(f"### {phase_name}\n")
            phase_state = next((x for x in coverage if x["phase"] == phase_name), None)
            if phase_state and phase_state["status"] == "Skipped":
                sections.append("_Phase skipped in this execution._\n")
                continue
            if phase_state and phase_state["status"] == "Executed (no findings)":
                sections.append("_Executed: no findings detected in this phase._\n")
            else:
                for i, f in enumerate(phase_findings, 1):
                    normalized_detail = _normalize_detail(phase_name, f, c.commands_log)
                    cvss_score, cvss_vector = _contextual_cvss(f["severity"], f["title"], normalized_detail)
                    confidence = _confidence_for_finding(f["title"], normalized_detail)
                    remediation = _remediation_for_finding(f["title"], normalized_detail)
                    impact = _business_impact_for_finding(f["title"], normalized_detail)

                    sections.append(f"#### {i}. {_md_cell(f['title'])}\n")
                    sections.append(f"- **Severity:** {f['severity']}")
                    sections.append(f"- **Status:** {f['status']}")
                    sections.append(f"- **Confidence:** {confidence}")
                    if confidence == "Confirmed":
                        sections.append("> **HIGHLIGHT: CONFIRMED EVIDENCE**")
                    sections.append(f"- **CVSS (estimated):** {cvss_score}")
                    sections.append(f"- **CVSS Vector (estimated):** `{cvss_vector}`")
                    if f.get("occurrences", 1) > 1:
                        sections.append(f"- **Occurrences merged:** {f['occurrences']}")
                    sections.append(f"- **Business Impact:** {impact}")
                    sections.append(f"- **Remediation:** {remediation}")
                    sections.append("- **Detail:**\n")
                    detail_text = normalized_detail
                    total_len = len(detail_text)
                    if total_len > 3000:
                        detail_text = detail_text[:3000] + f"\n\n[... truncated — {total_len - 3000} more characters omitted ...]"
                    dfence = _fence(detail_text)
                    sections.append(f"{dfence}\n{detail_text}\n{dfence}\n")
                    if f["severity"] in {"High", "Critical"}:
                        sections.append("- **Jira Draft:**")
                        jira_text = _jira_block(phase_name, f, cvss_score, remediation, normalized_detail)
                        jfence = _fence(jira_text)
                        sections.append(jfence)
                        sections.append(jira_text)
                        sections.append(f"{jfence}\n")

                    matched_screenshots = _screenshots_for_finding(
                        c.screenshots,
                        phase_name,
                        {"title": f["title"], "detail": normalized_detail},
                        used_screenshot_paths,
                    )
                    if matched_screenshots:
                        sections.append("- **Screenshots (evidence):**")
                        for ss in matched_screenshots:
                            sections.append(f"  - {_md_cell(ss['caption'])}")
                            sections.append(_md_image(ss['caption'], ss['path']))
                        sections.append("")

            # Keep any unmatched screenshots in the same phase section (no global screenshot section).
            phase_unmapped = [
                ss for ss in c.screenshots
                if ss["phase"] == phase_name and ss["path"] not in used_screenshot_paths
            ]
            if phase_unmapped:
                sections.append("**Additional evidence captured in this phase:**")
                for ss in phase_unmapped:
                    sections.append(f"- {_md_cell(ss['caption'])}")
                    sections.append(_md_image(ss['caption'], ss['path']))
                    used_screenshot_paths.add(ss["path"])
                sections.append("")

        sections.append("---\n## Missing/Manual Steps Recommended\n")
        sections.append(
            "- Validate authorization on backend APIs directly (token replay / IDOR checks), not only via UI activity launches."
        )
        sections.append("- Test TLS interception and certificate pinning behavior using MITM setup.")
        sections.append("- Perform static secret scan on APK/resources and compare with dynamic leakage findings.")
        sections.append("- Re-test critical flows with non-owner/low-privileged roles where applicable.")
        sections.append("- Add negative test evidence for blocked paths (proof of mitigation/denial).")
        sections.append("")

        # ── Commands log ──
        sections.append("---\n## Commands Executed\n")
        sections.append("<details><summary>Click to expand full command log</summary>\n")
        for entry in c.commands_log:
            sections.append(f"**Phase:** {_md_cell(entry['phase'])}  ")
            cmd_text = f"$ {entry['cmd']}"
            cfence = _fence(cmd_text)
            sections.append(f"{cfence}bash\n{cmd_text}\n{cfence}")
            sections.append(f"- rc: `{entry.get('rc', 0)}`")
            if entry["stdout"]:
                stdout_trimmed = entry["stdout"][:2000]
                ofence = _fence(stdout_trimmed)
                sections.append(f"{ofence}\n{stdout_trimmed}\n{ofence}")
            if entry["stderr"]:
                stderr_trimmed = entry["stderr"][:1000]
                efence = _fence(stderr_trimmed)
                sections.append(f"**stderr:**\n{efence}\n{stderr_trimmed}\n{efence}")
            sections.append("")
        sections.append("</details>\n")

        # ── Risk summary table ──
        sections.append("---\n## Risk Summary\n")
        sections.append("| # | Finding | Phase | Severity | Status | Confidence |")
        sections.append("|---|---------|-------|----------|--------|------------|")
        idx = 1
        for phase_name, phase_findings in deduped_findings.items():
            for f in phase_findings:
                normalized_detail = _normalize_detail(phase_name, f, c.commands_log)
                confidence = _confidence_for_finding(f["title"], normalized_detail)
                confidence_cell = "**CONFIRMED**" if confidence == "Confirmed" else confidence
                sections.append(
                    f"| {idx} | {_md_cell(f['title'])} | {_md_cell(phase_name)} | {f['severity']} | {f['status']} | {confidence_cell} |"
                )
                idx += 1
        sections.append("")

        full_report = "\n".join(sections)
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(full_report, encoding="utf-8")
        except OSError as e:
            raise RuntimeError(f"Failed to write report to {report_path}: {e}") from e

        # ── JSON findings export ──
        json_findings = []
        for phase_name, phase_findings in deduped_findings.items():
            for f in phase_findings:
                normalized_detail = _normalize_detail(phase_name, f, c.commands_log)
                cvss_score, cvss_vector = _contextual_cvss(f["severity"], f["title"], normalized_detail)
                json_findings.append({
                    "phase": phase_name,
                    "title": f["title"],
                    "severity": f["severity"],
                    "status": f["status"],
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "confidence": _confidence_for_finding(f["title"], normalized_detail),
                    "remediation": _remediation_for_finding(f["title"], normalized_detail),
                    "business_impact": _business_impact_for_finding(f["title"], normalized_detail),
                    "occurrences": f.get("occurrences", 1),
                    "detail": normalized_detail[:5000],
                    # PII entity metadata (populated for Presidio-detected findings)
                    "entity_type": self._extract_entity_type(f),
                    "confidence_score": self._extract_confidence_score(f),
                })

        json_export = {
            "package": c.package_name,
            "device_id": c.device_id,
            "apk_hash": getattr(c, "apk_hash", None),
            "timestamp": now,
            "total_findings": len(json_findings),
            "severity_counts": severity_counts,
            "findings": json_findings,
        }
        json_path = c.output_dir / f"findings_{c.package_name}_{c.timestamp}.json"
        try:
            json_path.write_text(json.dumps(json_export, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

        return str(report_path)
