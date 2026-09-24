"""
main.py — PhishGuard SOC CLI entrypoint.

Full pipeline: parse .eml -> extract headers/auth -> analyze headers/URLs/
domains/attachments -> extract IOCs -> optional VirusTotal enrichment ->
detection rules -> correlation -> risk scoring -> MITRE mapping ->
Markdown + JSON report generation.

The .eml file may be located ANYWHERE on disk — it does not need to be
copied into samples/. If no path is given on the command line, you'll be
prompted for one interactively (paste or drag-and-drop the file into the
terminal).

Usage:
    python -m src.main analyze samples/phishing/example.eml
    python -m src.main analyze "C:\\Users\\madhu\\Downloads\\suspicious email.eml"
    python -m src.main analyze --verbose
    python -m src.main analyze                    # prompts interactively
"""

from __future__ import annotations

import argparse
import re
import os
import sys
from dotenv import load_dotenv
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.analysis.attachment_analyzer import analyze_attachments
from src.analysis.auth_analyzer import analyze_authentication
from src.analysis.domain_analyzer import analyze_domain
from src.analysis.header_analyzer import analyze_headers
from src.analysis.ioc_extractor import extract_iocs
from src.analysis.url_analyzer import extract_urls_from_html, extract_urls_from_text
from src.detection.correlation import evaluate_correlation
from src.detection.rules import RuleContext, evaluate_rules
from src.detection.scoring import calculate_risk
from src.intelligence.virustotal import lookup_domain, lookup_hash
from src.intelligence.spf_verifier import verify_spf
from src.intelligence.dkim_verifier import extract_dkim_signature, verify_dkim
from src.intelligence.dmarc_verifier import verify_dmarc
from src.mitre.mapper import map_techniques
from src.parser.email_parser import EmailParseError, load_eml_file
from src.parser.header_parser import parse_headers
from src.reporting.report_generator import build_report, save_report
from src.utils.file_input import InvalidEmlPathError, validate_eml_path
from src.utils.logger import get_logger

logger = get_logger(__name__)
load_dotenv()

BANNER_WIDTH = 44


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard-soc",
        description="Automated first-level phishing email triage and investigation assistant.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a .eml file")
    analyze_parser.add_argument(
        "eml_path", nargs="?", default=None,
        help="Path to the .eml file to analyze, anywhere on disk. "
             "If omitted, you'll be prompted for a path interactively.",
    )
    analyze_parser.add_argument(
        "--verbose", action="store_true",
        help="Print full per-stage diagnostic detail in addition to the summary.",
    )
    analyze_parser.add_argument(
        "--output-dir", default="reports",
        help="Directory to write the Markdown/JSON report to (default: reports/).",
    )

    return parser


def _make_incident_id(eml_path: str) -> str:
    stem = os.path.splitext(os.path.basename(eml_path))[0]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"INC-{timestamp}-{stem}"


def _print_banner() -> None:
    print("=" * BANNER_WIDTH)
    print("PHISHGUARD SOC")
    print("PHISHING EMAIL ANALYZER")
    print("=" * BANNER_WIDTH)


def _prompt_for_eml_path() -> Optional[Path]:
    """
    Interactive fallback when no path is given on the command line.
    Loops on invalid input (friendly message, no traceback) until a valid
    .eml path is entered, or the user cancels with Ctrl+C / Ctrl+D.

    Supports pasting or dragging-and-dropping a file into the terminal —
    most terminals (including Windows Command Prompt / PowerShell) insert
    the dropped file's path as text, sometimes wrapped in quotes, which
    validate_eml_path/clean_path_input already handles.
    """
    print()
    print("Enter the path to your .eml file:")
    while True:
        try:
            raw = input("> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        try:
            return validate_eml_path(raw)
        except InvalidEmlPathError as exc:
            print(f"  {exc}")
            print("Please try again, or press Ctrl+C to cancel.")
            print()
            print("Enter the path to your .eml file:")


def run_analyze(eml_path: Optional[str], verbose: bool, output_dir: str) -> int:
    _print_banner()

    if eml_path is None:
        resolved_path = _prompt_for_eml_path()
        if resolved_path is None:
            print("\nNo file provided. Exiting.")
            return 1
    else:
        try:
            resolved_path = validate_eml_path(eml_path)
        except InvalidEmlPathError as exc:
            print(f"\nERROR: {exc}")
            return 1

    eml_path_str = str(resolved_path)

    try:
        parsed_email = load_eml_file(eml_path_str)
    except EmailParseError as exc:
        logger.error("Failed to load email: %s", exc)
        print(f"\nERROR: {exc}")
        return 1

    for warning in parsed_email.parse_warnings:
        logger.warning(warning)

    # --- Parsing & header/auth analysis ---
    headers = parse_headers(parsed_email.raw_message)
        # --- DKIM signature extraction ---
    dkim_signature = extract_dkim_signature(headers.dkim_signatures)
    # print("DEBUG DKIM HEADERS:", headers.dkim_signatures)
    # print("DEBUG DKIM SIGNATURE:", dkim_signature)
    dkim_verified = verify_dkim(parsed_email.raw_message)
    if dkim_signature:
        dkim_signature.verified = dkim_verified
    # dmarc_verification = None
    # if from_domain:
    #     dmarc_verification = verify_dmarc(from_domain)
    auth = analyze_authentication(headers.authentication_results, headers.from_)
    header_anomalies = analyze_headers(headers.from_, headers.reply_to)
    

    # --- URL & domain analysis ---
    urls = extract_urls_from_text(parsed_email.text_body) + extract_urls_from_html(parsed_email.html_body)
    unique_hostnames = sorted({u.hostname for u in urls if u.hostname})
    domain_results = [analyze_domain(host) for host in unique_hostnames]

    # --- Attachment analysis ---
    attachment_results = analyze_attachments(parsed_email.attachments)

    # --- IOC extraction ---
    iocs = extract_iocs(headers, urls, attachment_results)

    # --- Optional threat intelligence ---
    vt_results = []
    # --- Independent SPF verification ---
    # --- Independent SPF verification ---
    spf_verification = None

    from_domain = None
    if headers.from_:
        match = re.search(r"@([a-zA-Z0-9.\-]+)", headers.from_)
        if match:
            from_domain = match.group(1).lower()

    dmarc_verification = None
    if from_domain:
        dmarc_verification = verify_dmarc(from_domain)


    public_ips = [
        candidate.ip
        for candidate in headers.candidate_ips
        if candidate.scope == "public"
    ]

    if from_domain and public_ips:
        spf_verification = verify_spf(
            from_domain,
            public_ips[-1],
        )

    vt_enabled = bool(os.getenv("VT_API_KEY"))
    if vt_enabled:
        logger.info("VT_API_KEY present — enriching a subset of IOCs.")
        for domain in unique_hostnames[:3]:
            vt_results.append(lookup_domain(domain))
        for att in attachment_results:
            if att.sha256:
                vt_results.append(lookup_hash(att.sha256))

    # --- Detection, correlation, scoring, MITRE ---
    rule_context = RuleContext(
        header_anomalies=header_anomalies,
        auth=auth,
        urls=urls,
        domain_results=domain_results,
        attachments=attachment_results,
        vt_results=vt_results,
        subject=headers.subject or "",
        body=parsed_email.text_body or "",
    )
    fired_rules = evaluate_rules(rule_context)
    correlation = evaluate_correlation(fired_rules)
    risk = calculate_risk(fired_rules, correlation)
    mitre_mappings = map_techniques(fired_rules)

    # --- Report generation ---
    incident_id = _make_incident_id(eml_path_str)
    report = build_report(
        incident_id=incident_id,
        headers=headers,
        auth=auth,
        header_anomalies=header_anomalies,
        urls=urls,
        domain_results=domain_results,
        attachments=attachment_results,
        iocs=iocs,
        vt_results=vt_results,
        fired_rules=fired_rules,
        correlation=correlation,
        risk=risk,
        mitre_mappings=mitre_mappings,
        spf_verification=spf_verification,
        dkim_signature=dkim_signature,
        dmarc_verification=dmarc_verification,
    )
    md_path, json_path = save_report(report, output_dir=output_dir)

    # --- CLI summary output ---
    suspicious_urls = [u for u in urls if u.suspicious_flags]
    risky_attachments = [a for a in attachment_results if a.is_risky_extension]

    print(f"\nSource File:\n{eml_path_str}")

    print(f"\nVerdict: {risk.verdict}")
    print(f"Severity: {risk.severity}")
    print(f"Risk Score: {risk.score}/100")

    print(f"\nSender:\n{headers.from_ or '(missing)'}")
    print(f"\nReply-To:\n{headers.reply_to or '(not present)'}")

    print(f"\nSPF:\n{(auth.spf.result or 'UNKNOWN').upper()}")
    print(f"\nDKIM:\n{(auth.dkim.result or 'UNKNOWN').upper()}")
    print(f"\nDMARC:\n{(auth.dmarc.result or 'UNKNOWN').upper()}")

    print(f"\nURLs:\n{len(urls)}")
    print(f"\nSuspicious URLs:\n{len(suspicious_urls)}")

    print(f"\nAttachments:\n{len(attachment_results)}")
    print(f"\nSuspicious Attachments:\n{len(risky_attachments)}")

    print(f"\nIOCs:\n{len(iocs)}")

    if not vt_enabled:
        print("\nThreat Intelligence:\nVT_API_KEY not set — VirusTotal enrichment skipped.")

    if mitre_mappings:
        print(f"\nMITRE:\n{', '.join(m.technique_id for m in mitre_mappings)}")

    print(f"\nReport:\n{md_path}")

    if verbose:
        _print_verbose_detail(headers, header_anomalies, urls, domain_results,
                               attachment_results, iocs, fired_rules, correlation)

    print("\n" + "=" * BANNER_WIDTH)
    return 0


def _print_verbose_detail(headers, header_anomalies, urls, domain_results,
                           attachment_results, iocs, fired_rules, correlation) -> None:
    print("\n" + "-" * BANNER_WIDTH)
    print("VERBOSE DETAIL")
    print("-" * BANNER_WIDTH)

    print(f"\nReturn-Path: {headers.return_path or '(not present)'}")
    print(f"Subject: {headers.subject or '(missing)'}")
    print(f"Received hops: {len(headers.received)}")
    for c in headers.candidate_ips:
        print(f"  - {c.ip} [{c.scope}] (hop {c.source_header_index})")
    if headers.missing_headers:
        print(f"Missing headers: {', '.join(headers.missing_headers)}")

    if header_anomalies.from_reply_to_mismatch:
        print(f"\nHeader anomaly: From/Reply-To mismatch "
              f"({header_anomalies.from_domain} vs {header_anomalies.reply_to_domain})")
    if header_anomalies.suspicious_display_name:
        print(f"Header anomaly: display name claims '{header_anomalies.display_name_claimed_brand}'")

    for u in urls:
        if u.suspicious_flags:
            print(f"\nURL: {u.url}\n  flags: {', '.join(u.suspicious_flags)}")

    for d in domain_results:
        if d.heuristic_flags:
            print(f"\nDomain: {d.domain}\n  flags: {', '.join(d.heuristic_flags)}")

    for a in attachment_results:
        print(f"\nAttachment: {a.filename} ({a.extension}) sha256={a.sha256}")

    print(f"\nIOCs ({len(iocs)}):")
    for ioc in iocs:
        print(f"  - [{ioc.type}] {ioc.value} (source={ioc.source}, confidence={ioc.confidence})")

    print(f"\nDetection rules fired ({len(fired_rules)}):")
    for rule in fired_rules:
        print(f"  - {rule.rule_id} {rule.name} (+{rule.score_contribution})")

    if correlation.fired:
        print(f"\nCorrelation fired: categories={correlation.independent_categories} "
              f"(+{correlation.score_contribution})")


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        return run_analyze(args.eml_path, args.verbose, args.output_dir)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
