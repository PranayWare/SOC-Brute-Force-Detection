# SOP-SOC-001: Brute Force Alert Triage

## Purpose
Defines the standard Tier 1 analyst workflow when the "T1110.001 Brute
Force - Password Guessing" correlation rule fires, so any analyst can
execute the triage consistently without guessing.

## Trigger
Alert: **"T1110.001 Brute Force - Password Guessing"** fires in SIEM
(source: `detection_rule.md`)

## SLA
Initial triage must begin within **5 minutes** of alert generation.

## Tier 1 Analyst Steps

**1. Validate**
- Open the alert in the SIEM console
- Note: source `clientip`, timestamp, target host/endpoint, attempt count

**2. Context check**
- Search recent history for the source IP:
  `index="main" clientip=<IP>` — check for prior alerts or a pattern of
  activity from this source
- Check threat intelligence reputation for the IP:
  ```
  curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<IP>" \
    -H "Key: <API_KEY>" -H "Accept: application/json"
  ```
  Record the abuse confidence score returned.

  **Validated call (31 Jul 2026)** — tested against a known-clean IP
  (8.8.8.8) to confirm the check integrates correctly:
  ```json
  {"data":{"ipAddress":"8.8.8.8","isPublic":true,"ipVersion":4,
  "isWhitelisted":true,"abuseConfidenceScore":0,"countryCode":"US",
  "usageType":"Content Delivery Network","isp":"Google LLC",
  "domain":"google.com","hostnames":["dns.google"],"isTor":false,
  "totalReports":50,"numDistinctUsers":27}}
  ```
  `abuseConfidenceScore: 0` and `isWhitelisted: true` correctly reflect a
  clean, trusted IP — confirming the check would flag a genuinely
  malicious source with a nonzero score instead.

**3. Determine disposition**

| Condition | Disposition | Action |
|---|---|---|
| ≥5 attempts, ≥3 distinct usernames, external/unknown IP, threat intel flags malicious or unknown | **True Positive** | Escalate to Tier 2 (Incident Response) |
| Known vulnerability scanner IP, internal admin/QA tool, IP on allowlist | **Benign** | Suppress alert, add/confirm IP in `known_scanners.csv` lookup, document reason |
| Borderline count (5-7), single username, ambiguous threat intel result | **Uncertain** | Monitor for 15 minutes, re-run search, re-evaluate with fresh data |

**4. Document**
Update the alert ticket with: disposition, supporting evidence (screenshot
or exported search results), threat intel result, analyst initials,
timestamp of triage completion.

**5. Handoff (if escalated)**
Brief Tier 2 verbally or via ticket note using the escalation template
below. Do not close the Tier 1 ticket until Tier 2 confirms receipt.

## Escalation Ticket Template

```
Ticket ID: BRUTE-YYYYMMDD-###
Source IP: <IP>
Target Host/Endpoint: <host>
Attempt Count: <count>
Usernames Attempted: <list>
Time Window: <start> - <end>
Threat Intel Result: <clean / malicious / unknown> (AbuseIPDB score: <score>)
Disposition: <True Positive / Escalated>
Analyst: <name>
Triage Completed: <timestamp>
```

## Revision History
| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | [DATE] | Initial SOP creation | [YOUR NAME] |
