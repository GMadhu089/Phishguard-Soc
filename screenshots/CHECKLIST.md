# Screenshot Checklist

Capture these AFTER you've run the project yourself and confirmed it
works. Do not fabricate or mock any of these — every one should be a
real screenshot of your own terminal/browser/editor. Save each as a
`.png` in this folder using the suggested filename.

1. **`01_github_repo.png`** — Your GitHub repository's main page, showing
   the file tree and README rendered.
2. **`02_architecture_diagram.png`** — The architecture diagram from
   `docs/architecture.md`, rendered (e.g. paste into a Markdown previewer
   or take a screenshot of the code block as displayed on GitHub).
3. **`03_terminal_running_analysis.png`** — Terminal showing the full
   command and output of `python -m src.main analyze
   samples/phishing/credential_harvest_example.eml`.
4. **`04_email_header_analysis.png`** — Terminal or report excerpt
   showing the Sender/Reply-To/header anomaly output.
5. **`05_spf_dkim_dmarc_result.png`** — The SPF/DKIM/DMARC section of the
   CLI output or the generated Markdown report.
6. **`06_url_analysis.png`** — The URLs / Suspicious URLs section,
   ideally from a sample with a visible/href mismatch (ties to RULE-006).
7. **`07_ioc_extraction.png`** — The IOCs section of a generated report,
   showing types, sources, and confidence levels.
8. **`08_threat_intelligence_result.png`** — If you've configured a real
   `VT_API_KEY`: a VirusTotal enrichment result in the report. If you
   haven't, screenshot the "VT_API_KEY not set — enrichment skipped"
   message instead — that's a legitimate, honest screenshot of the
   graceful-degradation behavior and is worth showing too.
9. **`09_detection_rules.png`** — The "Detection Rules Triggered" section
   of a generated Markdown report, showing evidence and false-positive
   notes.
10. **`10_risk_score.png`** — The Risk Score Breakdown table from a
    generated report.
11. **`11_mitre_attack_mapping.png`** — The MITRE ATT&CK Mapping section
    of a generated report.
12. **`12_final_report.png`** — A full generated Markdown report, opened
    in a Markdown previewer (VS Code, GitHub, etc.) so formatting is
    visible.
13. **`13_test_results.png`** — Terminal output of `pytest tests/ -v`
    showing all tests passing.

Do not create fake screenshots or Photoshop results you didn't actually
produce — an interviewer who asks you to walk through your project live
will notice immediately if the screenshots don't match reality.
