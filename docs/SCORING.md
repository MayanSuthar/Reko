# Reko Scoring System

> *How Reko turns raw probe results into prioritised, actionable findings.*

---

## Overview

Every finding Reko produces carries a numeric **score** between `0.00` and `1.00`
and a **priority label** (CRITICAL / HIGH / MEDIUM / LOW / INFO).
These are computed automatically — no manual tuning required per scan.

The score answers one question: **"How urgently should a tester look at this?"**

---

## The Formula

```
score = (confidence × 0.4) + (impact × 0.6)
```

Two inputs. One output. The weighting is intentional:

| Input | Weight | Question it answers |
|---|---|---|
| **Confidence** | 40% | How certain are we this finding is real? |
| **Impact** | 60% | How bad is this if an attacker exploits it? |

Impact is weighted higher than confidence because a finding you are 95% sure about
that leads to root is more urgent than one you are 100% sure about that only
discloses a version number.

---

## Confidence

Confidence is set by each module based on how the finding was detected.

| Confidence | Value | Meaning | Example |
|---|---|---|---|
| Confirmed | 0.99 | Direct proof observed | vsftpd port 6200 opened after trigger |
| Direct read | 0.95 | Read from live response | FTP banner with exact version string |
| Inferred | 0.90 | Strong indicators | TLS 1.0 accepted in ClientHello |
| Heuristic | 0.85 | Pattern-based | HTTP response size compared to homepage |
| Low signal | 0.70–0.80 | Weak indicators | Banner partially matching a pattern |

### Real examples from the Metasploitable 2 scan

```
vsftpd backdoor confirmed (port 6200 open)       confidence = 0.99
FTP banner read directly                          confidence = 0.95
SMBv1 selected in Negotiate response              confidence = 0.99
DNS recursion (answer received for google.com)    confidence = 0.95
Tomcat Manager 200 OK with valid credentials      confidence = 0.99
```

---

## Impact

Impact is determined in two layers.

### Layer 1 — Service base weight

Each service has a baseline impact defined in SERVICE_BASE_WEIGHT.
This reflects the historical exploitability of that protocol:

```
smb          = 0.90   MS17-010, null sessions, relay attacks
rdp          = 0.85   BlueKeep, credential exposure
ftp          = 0.80   anonymous access, backdoors
vnc          = 0.80   no-auth desktop takeover
mssql        = 0.78   SA login, xp_cmdshell
oracle_tns   = 0.75   SID enum, default credentials
mysql        = 0.75   root empty password, INTO OUTFILE RCE
postgresql   = 0.70   trust auth, COPY TO PROGRAM RCE
ldap         = 0.70   anonymous bind, user enumeration
snmp         = 0.70   community strings, full MIB walk
nfs          = 0.68   world-readable filesystem exports
http         = 0.60   highly finding-dependent
ssh          = 0.45   requires credentials to exploit
dns          = 0.40   amplification, zone transfer
ident        = 0.20   username disclosure only
```

### Layer 2 — Finding-specific override

Each specific finding overrides the base weight based on what was found.
A severe finding raises impact well above the service baseline:

| Finding | Base service | Override | Reason |
|---|---|---|---|
| vsftpd 2.3.4 backdoor | 0.80 ftp | **0.99** | Unauthenticated root shell |
| FTP anonymous write | 0.80 ftp | 0.90 | Upload arbitrary files |
| FTP anonymous login | 0.80 ftp | 0.85 | Unauthenticated file read |
| FTP no TLS | 0.80 ftp | 0.55 | Credentials in cleartext |
| FTP banner disclosure | 0.80 ftp | 0.35 | Information only |
| SMBv1 active | 0.90 smb | 0.90 | EternalBlue exploit surface |
| SMB null session shares | 0.90 smb | 0.85 | Unauthenticated enumeration |
| SMB signing disabled | 0.90 smb | 0.75 | NTLM relay attack vector |
| PostgreSQL trust auth | 0.70 pg | 0.90 | No password = superuser |
| Tomcat Manager default creds | 0.60 http | 0.95 | WAR upload = RCE |
| phpinfo.php accessible | 0.60 http | 0.75 | Config and path disclosure |
| Missing CSP header | 0.60 http | 0.65 | XSS amplification |
| Server header | 0.60 http | 0.35 | Version disclosure only |

---

## Score Calculation — Step by Step

### Example 1: vsftpd 2.3.4 Backdoor (maximum possible score)

```
confidence = 0.99   port 6200 confirmed open — absolute proof
impact     = 0.99   unauthenticated root shell — maximum severity

score = (0.99 × 0.4) + (0.99 × 0.6)
      = 0.396 + 0.594
      = 0.990  →  CRITICAL
```

### Example 2: Tomcat Manager with tomcat:tomcat

```
confidence = 0.99   HTTP 200 received with valid credentials
impact     = 0.95   WAR file upload = arbitrary code execution

score = (0.99 × 0.4) + (0.95 × 0.6)
      = 0.396 + 0.570
      = 0.966  →  CRITICAL
```

### Example 3: SMBv1 active

```
confidence = 0.99   server responded with SMB1 magic bytes in Negotiate
impact     = 0.90   EternalBlue / WannaCry exploit surface

score = (0.99 × 0.4) + (0.90 × 0.6)
      = 0.396 + 0.540
      = 0.936  →  CRITICAL
```

### Example 4: FTP no FTPS/AUTH TLS

```
confidence = 0.95   server returned 530 to AUTH TLS command
impact     = 0.55   credentials in cleartext — real risk, not direct exploit

score = (0.95 × 0.4) + (0.55 × 0.6)
      = 0.380 + 0.330
      = 0.710  →  HIGH
```

### Example 5: FTP banner disclosure (plain)

```
confidence = 0.95   banner read directly
impact     = 0.35   version info only — no direct exploit path

score = (0.95 × 0.4) + (0.35 × 0.6)
      = 0.380 + 0.210
      = 0.590  →  MEDIUM
```

### Example 6: MySQL 5.0.x version (CVE-enriched)

```
confidence = 0.95   handshake read directly
impact     = 0.65   CVE-2012-2122 known for this version (raised from 0.35)

score = (0.95 × 0.4) + (0.65 × 0.6)
      = 0.380 + 0.390
      = 0.770  →  HIGH
```

The CVE lookup raised impact from 0.35 to 0.65 because MySQL 5.0.x has a known
public exploit with an ExploitDB entry. Without the CVE match this would have
scored MEDIUM. With it, the tester is told it is HIGH and given the exploit link.

---

## Priority Thresholds

```
score >= 0.85   CRITICAL   exploit immediately
score >= 0.65   HIGH       address within 24 hours
score >= 0.40   MEDIUM     address in current sprint
score >= 0.20   LOW        track and remediate
score  < 0.20   INFO       awareness only
```

### Why these specific values?

| Threshold | Reasoning |
|---|---|
| 0.85 CRITICAL | Requires very high confidence AND high impact simultaneously. Reserved for confirmed exploits and auth bypasses. |
| 0.65 HIGH | Captures cleartext credential exposure, deprecated protocols, and CVE-known versions. |
| 0.40 MEDIUM | Configuration weaknesses that are real but need attacker positioning or extra conditions. |
| 0.20 LOW | Present but not directly useful without significant additional context. |

---

## CVE Impact Adjustment

When cve_lookup() matches a version disclosure, impact is automatically raised:

```
Plain version disclosure (no CVE):         impact = 0.35
CVE match with HIGH severity:              impact = 0.50
CVE match with CRITICAL severity:          impact = 0.75
```

The same banner disclosure finding scores differently based on the version:

```
vsftpd 2.3.3 banner (no CVE match)     score 0.59   MEDIUM
vsftpd 2.3.4 banner (CVE-2011-2523)    score 0.83   HIGH
```

CVE-enriched findings also carry the ExploitDB URL in evidence fields so the
tester can go directly to the exploit without searching.

---

## Score Distribution — Metasploitable 2 Full Scan

Results from: nmap -sV -p- --script reko.nse --script-args reko.aggression=1

```
CRITICAL   17  ████████████████████
HIGH       23  ███████████████████████
MEDIUM     15  ███████████████
LOW         0
INFO        0
──────────────────────────────────
Total: 55 findings
Scan time: 270 seconds
False positives: 0
```

Top 5 scored findings:

| Score | Priority | Finding |
|---|---|---|
| 0.99 | CRITICAL | vsftpd 2.3.4 backdoor — root shell on port 6200 |
| 0.97 | CRITICAL | Tomcat Manager tomcat:tomcat — WAR upload RCE |
| 0.94 | CRITICAL | SMBv1 active — EternalBlue/WannaCry surface |
| 0.94 | CRITICAL | Ghostcat CVE-2020-1938 — web.xml read confirmed |
| 0.91 | CRITICAL | SMB null session — 5 shares enumerated |

---

## JSON Schema

In reko.output=json mode, every finding follows this structure:

```json
{
  "id": "reko-192-168-1-1-21-1234567890-ftp-1",
  "host": "192.168.1.1",
  "port": 21,
  "service": "ftp",
  "title": "vsftpd 2.3.4 BACKDOOR CONFIRMED",
  "description": "The vsftpd 2.3.4 backdoor was triggered...",
  "evidence": {
    "cve": "CVE-2011-2523",
    "backdoor_port": "6200",
    "exploit_cmd": "nc 192.168.1.1 6200",
    "metasploit": "exploit/unix/ftp/vsftpd_234_backdoor"
  },
  "confidence": 0.99,
  "impact_weight": 0.99,
  "score": 0.99,
  "priority": "CRITICAL",
  "module": "ftp",
  "reko_version": "0.1.0-dev",
  "scan_metadata": {
    "scan_id": "reko-192-168-1-1-21-1234567890",
    "timestamp": "2026-04-27T11:46:00Z"
  }
}
```

---

## Redaction

When reko.redact=true (default), sensitive evidence fields are replaced:

```
evidence.password    →  [REDACTED]
evidence.credential  →  [REDACTED]
evidence.hash        →  [REDACTED]
evidence.secret      →  [REDACTED]
evidence.token       →  [REDACTED]
```

Set reko.redact=false only during authorised engagements where you need
plaintext credential output in the report.

---

*Part of the Reko project — github.com/MayanSuthar/reko*
