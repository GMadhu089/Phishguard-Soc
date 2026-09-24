"""
report_generator.py

Builds a structured IncidentReport from every analysis stage's output and
renders it as Markdown and JSON.

Deliberately includes, per project design:
- A clear separation between WHAT THE EMAIL ANALYZER KNOWS and WHAT
  REQUIRES SIEM/EDR/PROXY DATA (this tool cannot prove endpoint compromise
  or that a user clicked a link — it can only say a suspicious link/
  attachment was present in the email).
- Standing SOC scope-investigation questions for the analyst.
- Example Splunk/Wazuh-style investigation queries built from the
  extracted IOCs, since the person building this project has that
  background — but these are illustrative, not executed by this tool.
- An explicit ALERT vs INCIDENT distinction in the analyst assessment.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.analysis.attachment_analyzer import AttachmentAnalysis
from src.analysis.auth_analyzer import AuthAnalysis
from src.analysis.domain_analyzer import DomainHeuristicResult
from src.analysis.header_analyzer import HeaderAnomalies
from src.analysis.ioc_extractor import IOC
from src.analysis.url_analyzer import ExtractedURL
from src.detection.correlation import CorrelationResult
from src.detection.rules import FiredRule
from src.detection.scoring import RiskAssessment
from src.intelligence.virustotal import VTLookupResult
from src.mitre.mapper import MitreMapping
from src.parser.header_parser import ParsedHeaders

_SCOPE_QUESTIONS = [
    "Did the user click the URL?",
    "Did the user enter credentials?",
    "Did the user open the attachment?",
    "Did other users receive the same or a similar email?",
    "Was the sender or sending domain blocked at the email gateway?",
    "Did the URL appear in proxy/web-gateway logs?",
    "Did the domain appear in DNS query logs?",
    "Did endpoint telemetry (EDR/Sysmon) show process execution tied to this attachment?",
]


@dataclass
class IncidentReport:
    incident_id: str
    generated_at: str
    subject: Optional[str]
    sender: Optional[str]
    recipient: Optional[str]
    reply_to: Optional[str]
    return_path: Optional[str]
    verdict: str
    severity: str
    risk_score: int
    risk_contributing_factors: list
    auth_summary: dict
    header_anomalies: dict
    urls: list
    domains: list
    candidate_ips: list
    attachments: list
    iocs: list
    threat_intel: list
    detection_rules: list
    correlation: dict
    mitre: list
    scope_questions: list = field(default_factory=lambda: list(_SCOPE_QUESTIONS))
    known_vs_unknown: dict = field(
        default_factory=lambda: {
            "what_this_tool_knows": (
                "Header/authentication analysis, URL and domain structure, attachment "
                "metadata and hashes, and optional threat-intelligence lookups performed "
                "against those static indicators."
            ),
            "what_requires_other_data": (
                "Whether the user actually clicked a link, entered credentials, or opened "
                "an attachment; whether malicious code executed on an endpoint; and whether "
                "other users received the same email. These require EDR, proxy, DNS, and "
                "mailbox-search data from your SIEM/EDR platform (e.g. Splunk, Wazuh) and are "
                "outside this tool's scope."
            ),
        }
    )
    alert_vs_incident_note: str = (
        "This report describes an ALERT: a suspicious email was identified through static "
        "analysis. It becomes an INCIDENT only if corroborating evidence (e.g. endpoint "
        "telemetry showing execution, or confirmed credential entry) is found elsewhere. "
        "This tool alone cannot confirm compromise."
    )
    example_siem_queries: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)
    escalation_recommendation: str = ""


def build_report(
    incident_id: str,
    headers: ParsedHeaders,
    auth: AuthAnalysis,
    header_anomalies: HeaderAnomalies,
    urls: list[ExtractedURL],
    domain_results: list[DomainHeuristicResult],
    attachments: list[AttachmentAnalysis],
    iocs: list[IOC],
    vt_results: list[VTLookupResult],
    fired_rules: list[FiredRule],
    correlation: CorrelationResult,
    risk: RiskAssessment,
    mitre_mappings: list[MitreMapping],
    spf_verification=None,
    dkim_signature=None,
    dmarc_verification=None,
) -> IncidentReport:
    report = IncidentReport(
        incident_id=incident_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        subject=headers.subject,
        sender=headers.from_,
        recipient=headers.to,
        reply_to=headers.reply_to,
        return_path=headers.return_path,
        verdict=risk.verdict,
        severity=risk.severity,
        risk_score=risk.score,
        risk_contributing_factors=[asdict(f) for f in risk.contributing_factors],
        auth_summary={
        "spf": auth.spf.result,
        "dkim": auth.dkim.result,
        "dkim_domain": auth.dkim.domain,
        "dmarc": auth.dmarc.result,
        "dmarc_policy": auth.dmarc.policy,
        "data_source_note": auth.data_source_note,
        "dmarc_alignment_note": auth.dmarc_alignment_note,
        "independent_dkim": (
            {
                "domain": dkim_signature.domain,
                "selector": dkim_signature.selector,
                "algorithm": dkim_signature.algorithm,
                "canonicalization": dkim_signature.canonicalization,
                "signed_headers": dkim_signature.signed_headers,
                "body_hash": dkim_signature.body_hash,
                "verified": dkim_signature.verified,
            }
            if dkim_signature
            else None
        ),
        "independent_spf": (
            {
                "domain": spf_verification.domain,
                "ip_address": spf_verification.ip_address,
                "result": spf_verification.result,
                "spf_record": spf_verification.spf_record,
                "reason": spf_verification.reason,
            }
            if spf_verification
            else None
        ),
        "independent_dmarc": (
            {
                "domain": dmarc_verification.domain,
                "result": dmarc_verification.result,
                "policy": dmarc_verification.policy,
                "record": dmarc_verification.record,
                "reason": dmarc_verification.reason,
            }
            if dmarc_verification
            else None
        ),
},
        header_anomalies={
            "from_reply_to_mismatch": header_anomalies.from_reply_to_mismatch,
            "suspicious_display_name": header_anomalies.suspicious_display_name,
            "display_name_claimed_brand": header_anomalies.display_name_claimed_brand,
            "notes": header_anomalies.notes,
        },
        urls=[
            {
                "url": u.url,
                "source": u.source,
                "hostname": u.hostname,
                "suspicious_flags": u.suspicious_flags,
                "visible_href_mismatch": u.visible_href_mismatch,
                "visible_text": u.visible_text,
            }
            for u in urls
        ],
        domains=[
            {"domain": d.domain, "heuristic_flags": d.heuristic_flags, "label_source": d.label_source}
            for d in domain_results
            if d.heuristic_flags
        ],
        candidate_ips=[
            {"ip": c.ip, "scope": c.scope, "source_header_index": c.source_header_index}
            for c in headers.candidate_ips
        ],
        attachments=[
            {
                "filename": a.filename,
                "extension": a.extension,
                "sha256": a.sha256,
                "sha1": a.sha1,
                "md5": a.md5,
                "is_risky_extension": a.is_risky_extension,
                "notes": a.notes,
            }
            for a in attachments
        ],
        iocs=[{"type": i.type, "value": i.value, "source": i.source, "confidence": i.confidence} for i in iocs],
        threat_intel=[
            {
                "ioc_type": v.ioc_type,
                "ioc_value": v.ioc_value,
                "available": v.available,
                "malicious_votes": v.malicious_votes,
                "error": v.error,
            }
            for v in vt_results
        ],
        detection_rules=[
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "evidence": r.evidence,
                "score_contribution": r.score_contribution,
                "severity_contribution": r.severity_contribution,
                "mitre_technique": r.mitre_technique,
                "false_positive_note": r.false_positive_note,
            }
            for r in fired_rules
        ],
        correlation={
            "fired": correlation.fired,
            "independent_categories": correlation.independent_categories,
            "contributing_rule_ids": correlation.contributing_rule_ids,
            "score_contribution": correlation.score_contribution,
            "evidence": correlation.evidence,
            "false_positive_note": correlation.false_positive_note,
        },
        mitre=[
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "reason": m.reason,
                "evidence": m.evidence,
                "detection": m.detection,
            }
            for m in mitre_mappings
        ],
    )

    report.example_siem_queries = _build_example_queries(iocs)
    report.recommended_actions = _build_recommended_actions(risk, fired_rules)
    report.escalation_recommendation = _build_escalation_recommendation(risk)

    return report


def _build_example_queries(iocs: list[IOC]) -> list[dict]:
    """
    Illustrative Splunk/Wazuh-style queries for the analyst to adapt to
    their own index/sourcetype naming. Not executed by this tool.
    """
    queries = []
    domains = [i.value for i in iocs if i.type == "domain"]
    ips = [i.value for i in iocs if i.type == "ipv4"]
    hashes = [i.value for i in iocs if i.type == "sha256"]

    if domains:
        queries.append({
            "platform": "Splunk",
            "purpose": "Find DNS/proxy activity to a suspicious domain",
            "query": f'index=proxy OR index=dns dest_domain IN ({", ".join(domains[:3])}) '
                     f'| stats count by src_ip, user, dest_domain',
        })
    if ips:
        queries.append({
            "platform": "Splunk",
            "purpose": "Find network connections to a suspicious IP",
            "query": f'index=firewall OR index=proxy dest_ip IN ({", ".join(ips[:3])}) '
                     f'| stats count by src_ip, dest_ip, user',
        })
    if hashes:
        queries.append({
            "platform": "Wazuh",
            "purpose": "Search endpoint telemetry for a known file hash",
            "query": f'rule.groups:"sysmon" AND data.sha256:({" OR ".join(hashes[:3])})',
        })

    return queries


def _build_recommended_actions(risk: RiskAssessment, fired_rules: list[FiredRule]) -> list[str]:
    actions = []
    if risk.verdict == "CLEAN":
        actions.append("No action required beyond standard mailbox hygiene.")
        return actions

    actions.append("Do not click any links or open any attachments from this email.")
    if any(r.rule_id == "RULE-006" for r in fired_rules):
        actions.append("Block the destination domain/URL at the web proxy or secure email gateway.")
    if any(r.rule_id == "RULE-007" for r in fired_rules):
        actions.append("Quarantine the attachment; do not open on any endpoint outside a sandbox.")
    if any(r.rule_id in ("RULE-001", "RULE-009") for r in fired_rules):
        actions.append("Verify sender legitimacy via an out-of-band channel before trusting any reply.")
    actions.append("Search mail logs for other recipients of the same or a similar message.")
    actions.append("If the user may have interacted with the email, check EDR/proxy logs per the scope questions above.")
    return actions


def _build_escalation_recommendation(risk: RiskAssessment) -> str:
    if risk.severity in ("CRITICAL", "HIGH"):
        return (
            f"Escalate to Tier 2 / IR immediately. Severity {risk.severity} with a risk score "
            f"of {risk.score}/100 warrants prompt investigation beyond L1 triage."
        )
    if risk.severity == "MEDIUM":
        return (
            "Continue L1 investigation using the scope questions above; escalate to Tier 2 if "
            "any indicator of user interaction or endpoint execution is found."
        )
    if risk.severity == "LOW":
        return "Document and monitor; escalate only if new corroborating evidence appears."
    return "No escalation needed; email does not meet the criteria for a suspicious alert."


def render_markdown(report: IncidentReport) -> str:
    lines = []
    lines.append(f"# PhishGuard SOC — Incident Report {report.incident_id}")
    lines.append("")
    lines.append(f"**Generated:** {report.generated_at}")
    lines.append(f"**Verdict:** {report.verdict}")
    lines.append(f"**Severity:** {report.severity}")
    lines.append(f"**Risk Score:** {report.risk_score}/100")
    lines.append("")
    lines.append("> This tool is an automated first-level phishing email triage and "
                  "investigation assistant. It does not replace Microsoft Defender, "
                  "Proofpoint, Mimecast, VirusTotal, or your SIEM.")
    lines.append("")

    lines.append("## Email Details")
    lines.append(f"- **Subject:** {report.subject or '(missing)'}")
    lines.append(f"- **From:** {report.sender or '(missing)'}")
    lines.append(f"- **To:** {report.recipient or '(missing)'}")
    lines.append(f"- **Reply-To:** {report.reply_to or '(not present)'}")
    lines.append(f"- **Return-Path:** {report.return_path or '(not present)'}")
    lines.append("")

    lines.append("## Authentication Results")
    a = report.auth_summary
    
    if a.get("independent_dkim"):
        dkim = a["independent_dkim"]
        lines.append("")
        lines.append("### DKIM Signature")
        lines.append(f"- **Domain:** `{dkim['domain'] or 'unknown'}`")
        lines.append(f"- **Selector:** `{dkim['selector'] or 'unknown'}`")
        lines.append(f"- **Algorithm:** `{dkim['algorithm'] or 'unknown'}`")
        lines.append(
            f"- **Canonicalization:** `{dkim['canonicalization'] or 'unknown'}`"
        )
        lines.append(
            f"- **Signed headers:** `{dkim['signed_headers'] or 'unknown'}`"
        )
        lines.append(f"- **Body hash:** `{dkim['body_hash'] or 'unknown'}`")
        lines.append(
        f"- **Cryptographic verification:** "
        f"{'PASS' if dkim['verified'] is True else 'FAIL' if dkim['verified'] is False else 'NOT VERIFIED'}"
        )

        lines.append(f"- **SPF:** {a['spf'] or 'unknown'}")
        lines.append(
            f"- **DKIM:** {a['dkim'] or 'unknown'}"
            + (f" (d={a['dkim_domain']})" if a["dkim_domain"] else "")
        )
        lines.append(
            f"- **DMARC:** {a['dmarc'] or 'unknown'}"
            + (f" (p={a['dmarc_policy']})" if a["dmarc_policy"] else "")
        )
    if a.get("independent_dmarc"):
        dmarc = a["independent_dmarc"]
        lines.append("")
        lines.append("### Independent DMARC Verification")
        lines.append(f"- **Domain:** `{dmarc['domain'] or 'unknown'}`")
        lines.append(f"- **Result:** `{dmarc['result'] or 'unknown'}`")
        lines.append(f"- **Policy:** `{dmarc['policy'] or 'unknown'}`")
        lines.append(f"- **Record:** `{dmarc['record'] or 'not found'}`")
        lines.append(f"- **Reason:** {dmarc['reason'] or 'No additional information.'}")

    if a.get("independent_spf"):
        isp = a["independent_spf"]
        lines.append("")
        lines.append("### Independent SPF Verification")
        lines.append(f"- **Result:** {isp['result'].upper()}")
        lines.append(f"- **Domain:** `{isp['domain']}`")
        lines.append(f"- **IP evaluated:** `{isp['ip_address']}`")
        lines.append(f"- **Reason:** {isp['reason']}")
    else:
        lines.append("")
        lines.append("- **Independent SPF verification:** Not available")

    lines.append(f"- {a['dmarc_alignment_note']}")
    lines.append(f"- *{a['data_source_note']}*")
    lines.append("")

    if report.header_anomalies["notes"]:
        lines.append("## Header Anomalies")
        for note in report.header_anomalies["notes"]:
            lines.append(f"- {note}")
        lines.append("")

    lines.append(f"## URLs ({len(report.urls)})")
    if report.urls:
        for u in report.urls:
            flags = f" — flags: {', '.join(u['suspicious_flags'])}" if u["suspicious_flags"] else ""
            lines.append(f"- `{u['url']}`{flags}")
    else:
        lines.append("- None found.")
    lines.append("")

    if report.domains:
        lines.append(f"## Domains with Local Heuristic Flags ({len(report.domains)})")
        for d in report.domains:
            lines.append(f"- `{d['domain']}` ({d['label_source']}): {', '.join(d['heuristic_flags'])}")
        lines.append("")

    lines.append(f"## Candidate IPs from Received Headers ({len(report.candidate_ips)})")
    if report.candidate_ips:
        for c in report.candidate_ips:
            lines.append(f"- `{c['ip']}` [{c['scope']}] (hop {c['source_header_index']})")
        lines.append("*Received headers can be forged by any hop; do not assume the first or "
                      "last IP is the attacker without further correlation.*")
    else:
        lines.append("- None found.")
    lines.append("")

    lines.append(f"## Attachments ({len(report.attachments)})")
    if report.attachments:
        for att in report.attachments:
            risky = " ⚠️ RISKY EXTENSION" if att["is_risky_extension"] else ""
            lines.append(f"- `{att['filename']}` ({att['extension']}){risky}")
            lines.append(f"  - SHA-256: `{att['sha256']}`")
    else:
        lines.append("- None found.")
    lines.append("")

    lines.append(f"## IOCs ({len(report.iocs)})")
    if report.iocs:
        for i in report.iocs:
            lines.append(f"- **{i['type']}**: `{i['value']}` (source: {i['source']}, confidence: {i['confidence']})")
    else:
        lines.append("- None extracted.")
    lines.append("")

    if report.threat_intel:
        lines.append("## Threat Intelligence (VirusTotal)")
        for v in report.threat_intel:
            if v["available"]:
                lines.append(f"- `{v['ioc_value']}`: {v['malicious_votes']} malicious vote(s)")
            else:
                lines.append(f"- `{v['ioc_value']}`: unavailable ({v['error']})")
        lines.append("")

    lines.append(f"## Detection Rules Triggered ({len(report.detection_rules)})")
    for r in report.detection_rules:
        lines.append(f"### {r['rule_id']} — {r['name']} (+{r['score_contribution']} pts, "
                      f"{r['severity_contribution']} severity)")
        lines.append(f"{r['description']}")
        for ev in r["evidence"]:
            lines.append(f"  - Evidence: {ev}")
        if r["mitre_technique"]:
            lines.append(f"  - MITRE ATT&CK: {r['mitre_technique']}")
        lines.append(f"  - *False-positive note: {r['false_positive_note']}*")
        lines.append("")

    if report.correlation["fired"]:
        lines.append("## Correlation (RULE-010)")
        lines.append(f"Independent evidence categories: {', '.join(report.correlation['independent_categories'])}")
        for ev in report.correlation["evidence"]:
            lines.append(f"- {ev}")
        lines.append(f"*{report.correlation['false_positive_note']}*")
        lines.append("")

    lines.append("## Risk Score Breakdown")
    lines.append(f"**Total: {report.risk_score}/100**")
    lines.append("")
    lines.append("| Rule | Points |")
    lines.append("|---|---|")
    for f in report.risk_contributing_factors:
        lines.append(f"| {f['rule_id']} {f['name']} | +{f['points']} |")
    lines.append("")

    if report.mitre:
        lines.append("## MITRE ATT&CK Mapping")
        for m in report.mitre:
            lines.append(f"### {m['technique_id']} — {m['technique_name']}")
            lines.append(f"{m['reason']}")
            lines.append(f"- Detected by: {m['detection']}")
            lines.append("")

    lines.append("## Analyst Assessment")
    lines.append(report.alert_vs_incident_note)
    lines.append("")
    lines.append("**What this tool knows:** " + report.known_vs_unknown["what_this_tool_knows"])
    lines.append("")
    lines.append("**What requires SIEM/EDR/proxy data:** " + report.known_vs_unknown["what_requires_other_data"])
    lines.append("")

    lines.append("## Scope Investigation Questions")
    for q in report.scope_questions:
        lines.append(f"- [ ] {q}")
    lines.append("")

    if report.example_siem_queries:
        lines.append("## Example SIEM/EDR Investigation Queries (illustrative — adapt to your environment)")
        for q in report.example_siem_queries:
            lines.append(f"**{q['platform']} — {q['purpose']}**")
            lines.append(f"```\n{q['query']}\n```")
        lines.append("")

    lines.append("## Recommended Actions")
    for action in report.recommended_actions:
        lines.append(f"- {action}")
    lines.append("")

    lines.append("## Escalation Recommendation")
    lines.append(report.escalation_recommendation)
    lines.append("")

    return "\n".join(lines)

def render_html(report: IncidentReport) -> str:
    """Render the incident report as a professional browser-friendly HTML document."""

    a = report.auth_summary

    def esc(value) -> str:
        import html
        return html.escape(str(value if value is not None else ""))

    # -----------------------------
    # Authentication sections
    # -----------------------------
    auth_rows = f"""
        <tr>
            <th>SPF</th>
            <td>{esc(a.get("spf") or "unknown")}</td>
        </tr>
        <tr>
            <th>DKIM</th>
            <td>{esc(a.get("dkim") or "unknown")}</td>
        </tr>
        <tr>
            <th>DMARC</th>
            <td>{esc(a.get("dmarc") or "unknown")}</td>
        </tr>
    """

    independent_spf = a.get("independent_spf")
    if independent_spf:
        independent_spf_html = f"""
        <div class="auth-card">
            <h3>Independent SPF Verification</h3>
            <table>
                <tr><th>Result</th><td>{esc(independent_spf.get("result", "unknown")).upper()}</td></tr>
                <tr><th>Domain</th><td><code>{esc(independent_spf.get("domain", "unknown"))}</code></td></tr>
                <tr><th>IP Evaluated</th><td><code>{esc(independent_spf.get("ip_address", "unknown"))}</code></td></tr>
                <tr><th>Reason</th><td>{esc(independent_spf.get("reason", "No additional information."))}</td></tr>
            </table>
        </div>
        """
    else:
        independent_spf_html = """
        <div class="auth-card">
            <h3>Independent SPF Verification</h3>
            <p>Not available.</p>
        </div>
        """

    independent_dkim = a.get("independent_dkim")
    if independent_dkim:
        dkim_status = (
            "PASS"
            if independent_dkim.get("verified") is True
            else "FAIL"
            if independent_dkim.get("verified") is False
            else "NOT VERIFIED"
        )

        independent_dkim_html = f"""
        <div class="auth-card">
            <h3>Independent DKIM Verification</h3>
            <table>
                <tr><th>Domain</th><td><code>{esc(independent_dkim.get("domain", "unknown"))}</code></td></tr>
                <tr><th>Selector</th><td><code>{esc(independent_dkim.get("selector", "unknown"))}</code></td></tr>
                <tr><th>Algorithm</th><td>{esc(independent_dkim.get("algorithm", "unknown"))}</td></tr>
                <tr><th>Canonicalization</th><td>{esc(independent_dkim.get("canonicalization", "unknown"))}</td></tr>
                <tr><th>Signed Headers</th><td><code>{esc(independent_dkim.get("signed_headers", "unknown"))}</code></td></tr>
                <tr><th>Body Hash</th><td><code>{esc(independent_dkim.get("body_hash", "unknown"))}</code></td></tr>
                <tr><th>Cryptographic Verification</th><td>{dkim_status}</td></tr>
            </table>
        </div>
        """
    else:
        independent_dkim_html = ""

    independent_dmarc = a.get("independent_dmarc")
    if independent_dmarc:
        independent_dmarc_html = f"""
        <div class="auth-card">
            <h3>Independent DMARC Verification</h3>
            <table>
                <tr><th>Domain</th><td><code>{esc(independent_dmarc.get("domain", "unknown"))}</code></td></tr>
                <tr><th>Result</th><td>{esc(independent_dmarc.get("result", "unknown")).upper()}</td></tr>
                <tr><th>Policy</th><td>{esc(independent_dmarc.get("policy", "unknown"))}</td></tr>
                <tr><th>Record</th><td><code>{esc(independent_dmarc.get("record", "not found"))}</code></td></tr>
                <tr><th>Reason</th><td>{esc(independent_dmarc.get("reason", "No additional information."))}</td></tr>
            </table>
        </div>
        """
    else:
        independent_dmarc_html = ""

    # -----------------------------
    # URLs
    # -----------------------------
    url_rows = ""

    for u in report.urls:
        flags = ", ".join(u["suspicious_flags"]) if u["suspicious_flags"] else "None"

        url_rows += f"""
        <tr>
            <td>{esc(u["url"])}</td>
            <td>{esc(u["hostname"])}</td>
            <td>{esc(flags)}</td>
        </tr>
        """

    if not url_rows:
        url_rows = """
        <tr>
            <td colspan="3">No URLs found.</td>
        </tr>
        """

    # -----------------------------
    # Candidate IPs
    # -----------------------------
    ip_rows = ""

    for ip in report.candidate_ips:
        ip_rows += f"""
        <tr>
            <td><code>{esc(ip["ip"])}</code></td>
            <td>{esc(ip["scope"])}</td>
            <td>{esc(ip["source_header_index"])}</td>
        </tr>
        """

    if not ip_rows:
        ip_rows = """
        <tr>
            <td colspan="3">No candidate IPs found.</td>
        </tr>
        """

    # -----------------------------
    # Attachments
    # -----------------------------
    attachment_rows = ""

    for att in report.attachments:
        attachment_rows += f"""
        <tr>
            <td>{esc(att["filename"])}</td>
            <td>{esc(att["extension"])}</td>
            <td>{esc(att["sha256"])}</td>
            <td>{esc(att["notes"])}</td>
        </tr>
        """

    if not attachment_rows:
        attachment_rows = """
        <tr>
            <td colspan="4">No attachments found.</td>
        </tr>
        """

    # -----------------------------
    # IOCs
    # -----------------------------
    ioc_rows = ""

    for ioc in report.iocs:
        ioc_rows += f"""
        <tr>
            <td>{esc(ioc["type"])}</td>
            <td><code>{esc(ioc["value"])}</code></td>
            <td>{esc(ioc["source"])}</td>
            <td>{esc(ioc["confidence"])}</td>
        </tr>
        """

    if not ioc_rows:
        ioc_rows = """
        <tr>
            <td colspan="4">No IOCs extracted.</td>
        </tr>
        """

    # -----------------------------
    # Detection rules
    # -----------------------------
    rule_html = ""

    for rule in report.detection_rules:
        evidence_html = ""

        for evidence in rule["evidence"]:
            evidence_html += f"<li>{esc(evidence)}</li>"

        mitre_html = ""

        if rule["mitre_technique"]:
            mitre_html = f"""
            <p>
                <strong>MITRE ATT&CK:</strong>
                {esc(rule["mitre_technique"])}
            </p>
            """

        rule_html += f"""
        <div class="rule-card">
            <h3>{esc(rule["rule_id"])} — {esc(rule["name"])}</h3>

            <p>
                <strong>Score:</strong>
                +{esc(rule["score_contribution"])} points
            </p>

            <p>{esc(rule["description"])}</p>

            <strong>Evidence</strong>
            <ul>
                {evidence_html}
            </ul>

            {mitre_html}

            <p class="false-positive">
                <strong>False-positive note:</strong>
                {esc(rule["false_positive_note"])}
            </p>
        </div>
        """

    # -----------------------------
    # Risk factors
    # -----------------------------
    risk_rows = ""

    for factor in report.risk_contributing_factors:
        risk_rows += f"""
        <tr>
            <td>{esc(factor["rule_id"])}</td>
            <td>{esc(factor["name"])}</td>
            <td>+{esc(factor["points"])}</td>
        </tr>
        """

    # -----------------------------
    # MITRE
    # -----------------------------
    mitre_html = ""

    for mapping in report.mitre:
        mitre_html += f"""
        <div class="mitre-card">
            <h3>
                {esc(mapping["technique_id"])}
                — {esc(mapping["technique_name"])}
            </h3>

            <p>{esc(mapping["reason"])}</p>

            <p>
                <strong>Detected by:</strong>
                {esc(mapping["detection"])}
            </p>
        </div>
        """

    # -----------------------------
    # Scope questions
    # -----------------------------
    scope_html = ""

    for question in report.scope_questions:
        scope_html += f"""
        <li>
            <input type="checkbox">
            {esc(question)}
        </li>
        """

    # -----------------------------
    # SIEM queries
    # -----------------------------
    query_html = ""

    for query in report.example_siem_queries:
        query_html += f"""
        <div class="query-card">
            <h3>{esc(query["platform"])} — {esc(query["purpose"])}</h3>
            <pre>{esc(query["query"])}</pre>
        </div>
        """

    # -----------------------------
    # Recommended actions
    # -----------------------------
    actions_html = ""

    for action in report.recommended_actions:
        actions_html += f"<li>{esc(action)}</li>"

    # -----------------------------
    # Threat intelligence
    # -----------------------------
    vt_rows = ""

    for result in report.threat_intel:
        if result["available"]:
            status = f'{result["malicious_votes"]} malicious vote(s)'
        else:
            status = f'Unavailable: {result["error"]}'

        vt_rows += f"""
        <tr>
            <td><code>{esc(result["ioc_value"])}</code></td>
            <td>{esc(status)}</td>
        </tr>
        """

    if not vt_rows:
        vt_rows = """
        <tr>
            <td colspan="2">No VirusTotal results.</td>
        </tr>
        """

    # -----------------------------
    # Main HTML
    # -----------------------------
    return f"""<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>
        PhishGuard SOC — {esc(report.incident_id)}
    </title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f1f5f9;
            color: #1e293b;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px;
        }}

        .header {{
            background: #0f172a;
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 25px;
        }}

        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 28px;
        }}

        .header p {{
            margin: 4px 0;
            color: #cbd5e1;
        }}

        .card {{
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 2px 6px rgba(15, 23, 42, 0.05);
        }}

        h2 {{
            color: #2563eb;
            border-bottom: 2px solid #dbeafe;
            padding-bottom: 8px;
            margin-top: 0;
        }}

        h3 {{
            color: #2563eb;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}

        th,
        td {{
            text-align: left;
            padding: 11px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}

        th {{
            background: #f8fafc;
            font-weight: 600;
        }}

        code {{
            background: #f1f5f9;
            padding: 3px 6px;
            border-radius: 4px;
            word-break: break-word;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}

        .summary-box {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #e2e8f0;
            text-align: center;
        }}

        .summary-box .label {{
            color: #64748b;
            font-size: 14px;
        }}

        .summary-box .value {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 5px;
        }}

        .verdict {{
            color: #b45309;
        }}

        .critical {{
            color: #dc2626;
        }}

        .score {{
            color: #7c3aed;
        }}

        .auth-card {{
            background: #f8fafc;
            border: 1px solid #dbeafe;
            border-radius: 8px;
            padding: 18px;
            margin-top: 15px;
        }}

        .rule-card {{
            border-left: 4px solid #2563eb;
            background: #f8fafc;
            padding: 18px;
            margin: 15px 0;
            border-radius: 6px;
        }}

        .false-positive {{
            background: #fff7ed;
            border-left: 3px solid #f97316;
            padding: 10px;
        }}

        .mitre-card {{
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 18px;
            border-radius: 8px;
            margin: 12px 0;
        }}

        .query-card {{
            margin: 15px 0;
        }}

        pre {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
        }}

        .actions li,
        .scope li {{
            margin: 8px 0;
        }}

        .escalation {{
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-left: 5px solid #dc2626;
            padding: 18px;
            border-radius: 8px;
            font-weight: 600;
        }}

        .note {{
            background: #f8fafc;
            border-left: 4px solid #64748b;
            padding: 15px;
            margin-top: 15px;
        }}

        .footer {{
            text-align: center;
            color: #64748b;
            font-size: 13px;
            margin-top: 30px;
            padding: 20px;
        }}

        @media (max-width: 800px) {{
            .summary {{
                grid-template-columns: 1fr;
            }}

            .container {{
                padding: 15px;
            }}

            table {{
                display: block;
                overflow-x: auto;
            }}
        }}

    </style>
</head>

<body>

<div class="container">

    <div class="header">
        <h1>PhishGuard SOC</h1>
        <p>Incident Report: {esc(report.incident_id)}</p>
        <p>Generated: {esc(report.generated_at)}</p>
    </div>

    <div class="summary">

        <div class="summary-box">
            <div class="label">Verdict</div>
            <div class="value verdict">{esc(report.verdict)}</div>
        </div>

        <div class="summary-box">
            <div class="label">Severity</div>
            <div class="value critical">{esc(report.severity)}</div>
        </div>

        <div class="summary-box">
            <div class="label">Risk Score</div>
            <div class="value score">{esc(report.risk_score)}/100</div>
        </div>

    </div>

    <div class="card">

        <h2>Email Details</h2>

        <table>
            <tr><th>Subject</th><td>{esc(report.subject or "(missing)")}</td></tr>
            <tr><th>From</th><td>{esc(report.sender or "(missing)")}</td></tr>
            <tr><th>To</th><td>{esc(report.recipient or "(missing)")}</td></tr>
            <tr><th>Reply-To</th><td>{esc(report.reply_to or "(not present)")}</td></tr>
            <tr><th>Return-Path</th><td>{esc(report.return_path or "(not present)")}</td></tr>
        </table>

    </div>

    <div class="card">

        <h2>Authentication Results</h2>

        <table>
            {auth_rows}
        </table>

        {independent_dkim_html}

        {independent_spf_html}

        {independent_dmarc_html}

        <div class="note">
            <strong>Authentication notes:</strong><br>
            {esc(a.get("dmarc_alignment_note", ""))}
            <br><br>
            {esc(a.get("data_source_note", ""))}
        </div>

    </div>

    <div class="card">

        <h2>Header Anomalies</h2>

        {''.join(f'<p>• {esc(note)}</p>' for note in report.header_anomalies["notes"])
        if report.header_anomalies["notes"]
        else "<p>No header anomalies detected.</p>"}

    </div>

    <div class="card">

        <h2>URLs</h2>

        <table>
            <tr>
                <th>URL</th>
                <th>Hostname</th>
                <th>Flags</th>
            </tr>

            {url_rows}
        </table>

    </div>

    <div class="card">

        <h2>Candidate IPs</h2>

        <table>
            <tr>
                <th>IP Address</th>
                <th>Scope</th>
                <th>Hop</th>
            </tr>

            {ip_rows}
        </table>

    </div>

    <div class="card">

        <h2>Attachments</h2>

        <table>
            <tr>
                <th>Filename</th>
                <th>Extension</th>
                <th>SHA-256</th>
                <th>Notes</th>
            </tr>

            {attachment_rows}
        </table>

    </div>

    <div class="card">

        <h2>IOCs</h2>

        <table>
            <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Source</th>
                <th>Confidence</th>
            </tr>

            {ioc_rows}
        </table>

    </div>

    <div class="card">

        <h2>Threat Intelligence — VirusTotal</h2>

        <table>
            <tr>
                <th>IOC</th>
                <th>Status</th>
            </tr>

            {vt_rows}
        </table>

    </div>

    <div class="card">

        <h2>Detection Rules Triggered</h2>

        {rule_html}

    </div>

    <div class="card">

        <h2>Correlation</h2>

        <p>
            <strong>Independent evidence categories:</strong>
            {esc(", ".join(report.correlation["independent_categories"]))}
        </p>

        <p>
            <strong>Contributing rules:</strong>
            {esc(", ".join(report.correlation["contributing_rule_ids"]))}
        </p>

        <p>
            {esc(report.correlation["false_positive_note"])}
        </p>

    </div>

    <div class="card">

        <h2>Risk Score Breakdown</h2>

        <table>
            <tr>
                <th>Rule</th>
                <th>Name</th>
                <th>Points</th>
            </tr>

            {risk_rows}

            <tr>
                <th colspan="2">Total</th>
                <th>{esc(report.risk_score)}/100</th>
            </tr>
        </table>

    </div>

    <div class="card">

        <h2>MITRE ATT&CK Mapping</h2>

        {mitre_html if mitre_html else "<p>No MITRE ATT&CK mapping available.</p>"}

    </div>

    <div class="card">

        <h2>Analyst Assessment</h2>

        <p>{esc(report.alert_vs_incident_note)}</p>

        <div class="note">
            <strong>What this tool knows:</strong><br>
            {esc(report.known_vs_unknown["what_this_tool_knows"])}
        </div>

        <div class="note">
            <strong>What requires SIEM/EDR/proxy data:</strong><br>
            {esc(report.known_vs_unknown["what_requires_other_data"])}
        </div>

    </div>

    <div class="card">

        <h2>Scope Investigation Questions</h2>

        <ul class="scope">
            {scope_html}
        </ul>

    </div>

    <div class="card">

        <h2>Example SIEM/EDR Investigation Queries</h2>

        {query_html if query_html else "<p>No example queries available.</p>"}

    </div>

    <div class="card">

        <h2>Recommended Actions</h2>

        <ul class="actions">
            {actions_html}
        </ul>

    </div>

    <div class="card">

        <h2>Escalation Recommendation</h2>

        <div class="escalation">
            {esc(report.escalation_recommendation)}
        </div>

    </div>

    <div class="footer">
        PhishGuard SOC — Automated First-Level Phishing Email Triage
    </div>

</div>

</body>
</html>
"""


def save_report(report: IncidentReport, output_dir: str = "reports") -> tuple[str, str]:
    """Writes both Markdown and JSON reports. Returns (md_path, json_path)."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / f"{report.incident_id}.md"
    json_path = out_dir / f"{report.incident_id}.json"

    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

    html_path = out_dir / f"{report.incident_id}.html"
    html_path.write_text(render_html(report), encoding="utf-8")

    return str(md_path), str(json_path)
