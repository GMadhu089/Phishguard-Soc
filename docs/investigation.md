# Investigation Guide

## SOC Workflow

```
ALERT
  |
  v
VALIDATE          <- confirm the .eml is genuine, not a test/simulation
  |
  v
ANALYZE EMAIL     <- this tool: headers, auth, URLs, domains, attachments
  |
  v
EXTRACT IOCS      <- this tool: deduplicated, typed, confidence-scored
  |
  v
ENRICH IOCS       <- this tool (optional): VirusTotal, if VT_API_KEY set
  |
  v
CORRELATE         <- this tool: RULE-010, independent-category correlation
  |
  v
ASSESS SEVERITY   <- this tool: risk score + severity band
  |
  v
CHECK USER IMPACT <- ANALYST, using SIEM/EDR/proxy — outside this tool's scope
  |
  v
RECOMMEND RESPONSE <- this tool suggests actions; analyst decides
  |
  v
ESCALATE IF REQUIRED
```

Everything above the "CHECK USER IMPACT" line, this tool does for you.
Everything from that point on requires data this tool does not have.

## Alert vs. Incident

A suspicious email identified by this tool is an **ALERT** — evidence
that a phishing attempt was *delivered*, not evidence that it *succeeded*.
It becomes an **INCIDENT** only when corroborating evidence is found
elsewhere: endpoint telemetry showing execution, proxy logs showing the
user reached the malicious URL, or confirmation the user entered
credentials. This distinction matters for accurate incident metrics and
for not over-reporting — every generated report states this explicitly.

## Scope Investigation Questions

Every generated report includes this checklist. These are the questions
this tool CANNOT answer on its own:

- Did the user click the URL?
- Did the user enter credentials?
- Did the user open the attachment?
- Did other users receive the same or a similar email?
- Was the sender or sending domain blocked at the email gateway?
- Did the URL appear in proxy/web-gateway logs?
- Did the domain appear in DNS query logs?
- Did endpoint telemetry (EDR/Sysmon) show process execution tied to this
  attachment?

## What This Tool Knows vs. What Requires SIEM/EDR

| This tool knows | Requires SIEM/EDR/proxy |
|---|---|
| Header/authentication analysis | Whether the user clicked a link |
| URL and domain structure | Whether credentials were entered |
| Attachment metadata and hashes | Whether an attachment executed |
| Threat-intel lookups on static IOCs | Whether other users got the same email |

## Extending Into Splunk / Wazuh

This tool is not a SIEM and does not query one. Every generated report
includes illustrative example queries (see `report_generator.py`,
`_build_example_queries`) built from the extracted IOCs, e.g.:

```
# Splunk — DNS/proxy activity to a suspicious domain
index=proxy OR index=dns dest_domain IN (microsoft-login-example.test)
| stats count by src_ip, user, dest_domain

# Wazuh — endpoint telemetry for a known file hash
rule.groups:"sysmon" AND data.sha256:(<hash>)
```

Adapt index/sourcetype names to your own environment. The general
investigation flow from an IOC to scope is:

```
IOC -> SIEM search -> affected user -> affected endpoint
     -> network activity -> process activity -> scope
```

This is documented as guidance, not implemented as a live integration —
Splunk/Wazuh access is optional and never required to use this tool.
