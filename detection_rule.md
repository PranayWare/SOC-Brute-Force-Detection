# Detection: T1110.001 — Brute Force: Password Guessing

## Overview
Detects repeated password-guessing attempts against a web login endpoint by
correlating a burst of failed POST requests from a single source within a
short time window.

- **MITRE ATT&CK Technique:** T1110.001 – Brute Force: Password Guessing
- **Data Source:** Web access logs (Apache/Nginx combined log format)
- **Environment tested:** DVWA (Damn Vulnerable Web Application), Brute Force module
- **SIEM:** Splunk (Docker lab environment)

## Logic

- **Source:** `index="main" source="dvwa_access.log" sourcetype="access_combined"`
- **Trigger condition:** ≥5 GET requests to `/vulnerabilities/brute/`
  from the same `clientip` within a rolling 2-minute window
- **Severity:** High
- **MITRE Technique tag:** T1110.001

> Note: DVWA's Brute Force module submits credentials via GET (query string
> parameters `username`, `password`, `Login`), not POST — confirmed from raw
> log inspection during lab testing.

## SPL — Correlation Rule

```spl
index="main" source="dvwa_access.log"
uri_path="/vulnerabilities/brute/" method=GET uri_query="*"
| bin _time span=2m
| stats count dc(uri_query) as unique_attempts by clientip _time uri_path
| where count >= 5
| eval severity="high", mitre_technique="T1110.001"
| table _time clientip count unique_attempts severity mitre_technique
```

**Validation run (live lab data, 31 Jul 2026):**

Generated 5 manual login attempts against the DVWA Brute Force module.
Rule fired correctly on the first execution:

```
_time                  clientip       count   unique_attempts   severity   mitre_technique
2026-07-31 19:16:00    172.17.0.1     5       5                 high       T1110.001
```

5 attempts submitted → 5 detected, correctly bucketed within the 2-minute
window, correctly tagged high severity with the MITRE technique attached.
Screenshot: [ATTACH SCREENSHOT HERE]

## False Positive Tuning

1. **Known scanner exclusion** — maintain a lookup table of internal
   vulnerability-scanner IPs and exclude them from `clientip`:
   ```spl
   | lookup known_scanners.csv clientip OUTPUT is_scanner
   | where is_scanner!="true"
   ```
2. **Require multiple distinct usernames** — a single user retrying a
   forgotten password against the same account is not a brute-force
   attempt; it's normal user behavior. Require at least 3 distinct
   usernames attempted before escalating severity to high.
3. **Internal/trusted subnet allowlist** — internal admin/QA testing tools
   hitting the login endpoint repeatedly (e.g. automated smoke tests)
   should be excluded via a CIDR allowlist, not just individual IPs.

### Tuning Iteration — Live Test

**First version of the rule** counted `dc(uri_query)` (distinct full query
strings) as a proxy for "distinct usernames." Testing exposed a gap: an
attacker/user submitting the **same username with different passwords**
still produces a distinct query string every attempt (since the password
changes), so the naive version treated it as high severity — a false
positive on legitimate repeated-login behavior.

**Fix:** extract the username specifically with `rex` instead of relying
on the whole query string, then count distinct usernames.

```spl
index="main" source="dvwa_access.log"
uri_path="/vulnerabilities/brute/" method=GET uri_query="*"
| rex field=uri_query "username=(?<attempted_user>[^&]+)"
| bin _time span=2m
| stats count dc(attempted_user) as unique_usernames by clientip _time uri_path
| eval severity=if(count>=5 AND unique_usernames>=3, "high", "low-monitor")
| eval mitre_technique="T1110.001"
| table _time clientip count unique_usernames severity mitre_technique
```

**Validated result (live lab data, 31 Jul 2026):**

| Test scenario | count | unique_usernames | severity |
|---|---|---|---|
| Same username, 6 password attempts (simulated false positive) | 6 | 2 | **low-monitor** |
| Distinct usernames, 5+ attempts (genuine brute force pattern) | 10 | 5 | **high** |

The tuned rule correctly suppresses the single-account retry scenario
while still flagging the multi-username pattern as high severity —
confirming the false-positive filter discriminates real credential
stuffing from normal user error.

## Sigma Rule (vendor-agnostic version)

Written so the same detection logic can be converted to QRadar AQL,
Sentinel KQL, or ArcSight syntax without rewriting from scratch.

```yaml
title: Brute Force - Password Guessing (Web Login)
id: 7c1e2f3a-4b8d-4e6a-9c2f-1a3b5d7e9f01
status: experimental
description: Detects repeated failed login POST requests from a single source in a short window
references:
    - https://attack.mitre.org/techniques/T1110/001/
tags:
    - attack.credential_access
    - attack.t1110.001
logsource:
    category: webserver
detection:
    selection:
        cs-method: GET
        cs-uri-stem|contains: '/vulnerabilities/brute/'
    timeframe: 2m
    condition: selection | count() by c-ip > 5
falsepositives:
    - Internal vulnerability scanners
    - Automated QA/smoke tests
level: high
```

**Converted via sigconverter.io (pySigma) to Splunk target:**

```spl
"cs-method"="GET" "cs-uri-stem"="*/vulnerabilities/brute/*"
```

Note: the automated conversion carries over the base match logic (method
+ URI path) but not the `timeframe`/`count() > 5` aggregation — Sigma's
correlation/threshold logic is backend-specific and doesn't always
auto-translate cleanly. In practice this means the converted query is a
starting point requiring the analyst to manually add the equivalent
`bin`/`stats`/`where` aggregation for the target SIEM (as done by hand in
the SPL version above) — a good example of why understanding the
underlying logic matters more than relying on the converter alone.
