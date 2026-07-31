# SOC Detection Pack: Brute Force (T1110.001)

A self-contained detection engineering artifact built from a DVWA
(Damn Vulnerable Web Application) brute-force lab, covering the full
SOC lifecycle: detection logic, false-positive tuning, vendor-agnostic
rule portability, and Tier 1 triage procedure.

## Why this exists
Most entry-level SOC candidates can either run a Splunk search or
describe SOC concepts in theory. This pack does both: a tested
correlation rule plus the operational runbook a Tier 1 analyst follows
when it fires — the two things a real SOC actually runs on.

## Highlight: found and fixed a real false-positive gap
The first version of the detection rule used the number of distinct
*query strings* as a proxy for distinct usernames attempted. Testing
showed this was wrong — a single user retrying one username with
different passwords still produced "distinct" query strings, causing a
false positive. Fixed by extracting the username field directly with
regex and re-validating against both a genuine multi-username attack
and a single-username retry. See the "Tuning Iteration" section in
[`detection_rule.md`](./detection_rule.md) for the full before/after
comparison with real test data.

## Contents

| File | What it is |
|---|---|
| [`detection_rule.md`](./detection_rule.md) | SPL correlation rule, MITRE ATT&CK mapping, false-positive tuning logic (with live test iteration), and a vendor-agnostic Sigma version of the same rule |
| [`triage_sop.md`](./triage_sop.md) | Tier 1 analyst SOP: validation steps, live-tested threat-intel check (AbuseIPDB), disposition criteria, escalation ticket template |

## Environment
- **Lab:** DVWA running in Docker
- **SIEM:** Splunk (local instance, DVWA access logs indexed)
- **Attack simulated:** Manual brute-force login attempts against the
  DVWA Brute Force module, varying username/password combinations
- **Technique mapped:** [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

## What this demonstrates
- Detection engineering: writing correlation logic, not just running
  pre-built searches
- False-positive tuning discipline, validated iteratively against live
  test data — not just theoretical logic
- SIEM portability thinking: same logic expressed in Sigma so it isn't
  locked to one vendor's query language
- Operational documentation: an SOP a Tier 1 analyst could execute
  without prior context, with a clear disposition tree and SLA
- MITRE ATT&CK-based thinking throughout
- Real threat-intelligence API integration (AbuseIPDB)
