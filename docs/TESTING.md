# Reko Testing & Validation Guide

> *Structured test plan for validating Reko against Metasploitable 2.*
> *Results from this guide feed directly into research paper Section 6.*

---

## Environment Setup

### Required Software

| Component | Version | Purpose |
|---|---|---|
| Kali Linux / ParrotOS | Latest | Attacker machine running Nmap + Reko |
| Nmap | >= 7.80 | Script engine runtime |
| Metasploitable 2 | SourceForge | Vulnerable target VM |
| VirtualBox / VMware | Any recent | VM hypervisor |
| Python 3 | 3.8+ | Post-processing JSON output |
| jq | Any | Pretty-print JSON in terminal |

### Network Configuration

Both VMs must be on the same **Host-Only adapter** so they can communicate
but are isolated from the internet. This prevents accidental scanning of real hosts.

```bash
# VirtualBox: File → Host Network Manager → Create
# Set both VMs: Settings → Network → Adapter 2 → Host-Only Adapter

# Verify connectivity from Kali
ping <metasploitable-ip>        # should reply

# Find Metasploitable IP
sudo nmap -sn 192.168.56.0/24   # adjust subnet to match your range
```

### Install Reko

```bash
# Option A: from parts (recommended - easier to update)
cat reko_part1.lua reko_part2.lua reko_part3.lua reko_part4.lua > reko.nse

# Option B: use pre-assembled file
# Download reko.nse directly

# Install
sudo cp reko.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb

# Verify — should show all script arguments and categories
nmap --script-help reko.nse
```

---

## Known Vulnerabilities on Metasploitable 2

These are the ground-truth findings Reko should detect.
Use this as your coverage checklist.

| Port | Service | Vulnerability | Expected Priority |
|---|---|---|---|
| 21 | vsftpd 2.3.4 | CVE-2011-2523 backdoor (port 6200) | CRITICAL |
| 21 | vsftpd 2.3.4 | Anonymous FTP login | CRITICAL |
| 22 | OpenSSH 4.7p1 | Version disclosure + weak ciphers | MEDIUM |
| 23 | telnetd | Plaintext credentials (msfadmin/msfadmin) | HIGH |
| 25 | Postfix | VRFY user enumeration | HIGH |
| 53 | BIND 9.4.2 | Open recursion + version disclosure | HIGH |
| 80 | Apache 2.2.8 | phpinfo, DVWA, Mutillidae, TikiWiki, TWiki | CRITICAL |
| 139/445 | Samba | SMBv1 + null session + signing disabled | CRITICAL |
| 2049 | NFS | World-accessible exports | CRITICAL |
| 2121 | ProFTPD 1.3.1 | CVE-2010-4221 + no TLS | HIGH |
| 3306 | MySQL 5.0.51a | CVE-2012-2122 + root empty password | HIGH |
| 5432 | PostgreSQL 8.3 | MD5 auth (deprecated) | HIGH |
| 5900 | VNC 3.3 | DES-based weak auth | HIGH |
| 6667 | UnrealIRCd | CVE-2010-2075 backdoor | CRITICAL |
| 8009 | AJP | Ghostcat CVE-2020-1938 | CRITICAL |
| 8180 | Tomcat | Manager panel tomcat:tomcat + WAR RCE | CRITICAL |

---

## Test Cases

### TC-1 — Syntax Check

**Purpose:** Verify the script loads without Lua errors before touching any target.

```bash
nmap --script-help reko.nse
```

**Expected output:**
```
reko
Categories: discovery safe
...
Script arguments:
  reko.aggression  : 0=passive only (default), 1=safe-active, 2=full-active
  reko.timeout     : per-module socket timeout in ms (default 5000)
  reko.output      : "text" (default) | "json" | "both"
  reko.modules     : comma-separated list of modules to run (default: all)
  reko.loglevel    : 0=errors only, 1=warnings, 2=info (default 1)
  reko.redact      : true=redact sensitive fields in output (default true)
```

**Pass criteria:** No Lua errors. All 6 script arguments listed.

---

### TC-2 — Localhost Smoke Test

**Purpose:** Confirm the script executes and returns output before scanning
a real target.

```bash
nmap -sV --script reko.nse 127.0.0.1
```

**Pass criteria:** Script runs. No runtime errors in output.

---

### TC-3 — Passive Scan (aggression=0)

**Purpose:** Confirm passive-only mode does not perform any active checks
(no login attempts, no backdoor probes). Validates the aggression system.

```bash
time nmap -sV --script reko.nse \
  --script-args reko.aggression=0 \
  <metasploitable-ip> 2>&1 | tee reko_passive.txt
```

**Record:**
- Total scan time (from `time` output): ___________
- Total findings: ___________
- CRITICAL findings: ___________
- HIGH findings: ___________
- Ports that fired modules: ___________

**Pass criteria:**
- No anonymous login attempts (check — should not see "230 Login successful")
- No backdoor probe (port 6200 not mentioned)
- No credential tests in output

---

### TC-4 — Full Active Scan (aggression=1) — PRIMARY BENCHMARK

**Purpose:** The main data point for research paper Section 6.2.
All active checks enabled including credential tests and exploit probes.

```bash
time nmap -sV -p- --script reko.nse \
  --script-args reko.aggression=1 \
  <metasploitable-ip> 2>&1 | tee reko_active.txt
```

**Record:**
- Total scan time: ___________
- Total findings: ___________
- CRITICAL findings: ___________
- HIGH findings: ___________
- MEDIUM findings: ___________
- Attack path summaries generated: ___________

**Expected CRITICAL findings:**

```
[ ] vsftpd 2.3.4 BACKDOOR CONFIRMED — port 6200 root shell
[ ] FTP anonymous login permitted
[ ] SMBv1 active — EternalBlue/WannaCry risk
[ ] SMB null session exposes shares
[ ] SMB signing DISABLED — relay attack risk
[ ] Ghostcat CVE-2020-1938 — web.xml read confirmed
[ ] Tomcat Manager tomcat:tomcat — WAR upload RCE
[ ] phpinfo.php accessible
[ ] DVWA login page found
[ ] Mutillidae vulnerable app found
```

---

### TC-5 — JSON Output Mode

**Purpose:** Verify JSON output is valid and machine-parseable.
Supports the integration claim in the research paper.

```bash
nmap -sV --script reko.nse \
  --script-args reko.aggression=1,reko.output=json \
  <metasploitable-ip> > reko_output.json

# Validate JSON is parseable
cat reko_output.json | python3 -m json.tool | head -50

# Count findings by priority
cat reko_output.json | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
priorities = []
for v in data.values():
    if isinstance(v, list):
        for f in v:
            if isinstance(f, dict) and 'priority' in f:
                priorities.append(f['priority'])
print(dict(Counter(priorities)))
"

# Count by priority using grep (simpler)
grep -o '"priority":"[^"]*"' reko_output.json | sort | uniq -c | sort -rn
```

**Pass criteria:** Valid JSON. All findings have score, priority, confidence, impact fields.

---

### TC-6 — Single Module Isolation

**Purpose:** Verify the `reko.modules` filter works correctly.
Only the specified module should fire.

```bash
# Test SMB module only
nmap -p 139,445 -sV --script reko.nse \
  --script-args reko.modules=smb,reko.aggression=1 \
  <metasploitable-ip>

# Test FTP module only
nmap -p 21 -sV --script reko.nse \
  --script-args reko.modules=ftp,reko.aggression=1 \
  <metasploitable-ip>

# Test HTTP module only
nmap -p 80,8180 -sV --script reko.nse \
  --script-args reko.modules=http,reko.aggression=1 \
  <metasploitable-ip>
```

**Pass criteria:** Only the specified module fires. Other ports produce no reko output.

---

### TC-7 — Manual Enumeration Timing Comparison

**Purpose:** Core data for research paper Section 6.2.
Time manual enumeration against Reko and record the difference.

**Step 1 — Time the manual workflow:**

```bash
time (
  nmap -sV <metasploitable-ip> && \
  nmap --script ftp-anon -p 21 <metasploitable-ip> && \
  nmap --script ssh2-enum-algos -p 22 <metasploitable-ip> && \
  nmap --script smb-security-mode -p 445 <metasploitable-ip> && \
  nmap --script smb-enum-shares -p 445 <metasploitable-ip> && \
  nmap --script mysql-empty-password -p 3306 <metasploitable-ip> && \
  nmap --script http-headers,http-git -p 80 <metasploitable-ip> && \
  nmap --script dns-recursion -p 53 <metasploitable-ip>
) 2>&1 | tee manual_enum.txt
```

**Step 2 — Time Reko doing all of the above in one command:**

```bash
time nmap -sV -p 21,22,25,53,80,111,139,445,2049,2121,3306,5432,5900,6667,8009,8180 \
  --script reko.nse \
  --script-args reko.aggression=1 \
  <metasploitable-ip> 2>&1 | tee reko_targeted.txt
```

**Record for paper:**

| Approach | Time (seconds) | Findings count | Tools required |
|---|---|---|---|
| Manual (8 scripts) | ___ | ___ | 8 |
| Reko passive | ___ | ___ | 1 |
| Reko active | ___ | ___ | 1 |

---

## Coverage Checklist

Fill in during TC-4. Mark each known vulnerability:
- `✓` = Reko found it
- `✗` = missed (false negative)
- `FP` = false positive reported

| Port | Service | Vulnerability | Reko Result | Score | Priority |
|---|---|---|---|---|---|
| 21 | FTP | vsftpd 2.3.4 backdoor | | | |
| 21 | FTP | Anonymous login | | | |
| 21 | FTP | No FTPS | | | |
| 22 | SSH | OpenSSH version disclosure | | | |
| 23 | Telnet | Cleartext service | | | |
| 25 | SMTP | VRFY user enumeration | | | |
| 53 | DNS | Open recursion | | | |
| 53 | DNS | BIND version disclosure | | | |
| 80 | HTTP | phpinfo.php | | | |
| 80 | HTTP | DVWA found | | | |
| 80 | HTTP | Mutillidae found | | | |
| 80 | HTTP | Missing security headers | | | |
| 80 | HTTP | TRACE XST enabled | | | |
| 111 | RPC | NFS/mountd via portmapper | | | |
| 139 | SMB | SMBv1 active | | | |
| 139 | SMB | Null session shares | | | |
| 139 | SMB | Signing disabled | | | |
| 2049 | NFS | World-accessible export | | | |
| 2121 | FTP | ProFTPD CVE-2010-4221 | | | |
| 3306 | MySQL | CVE-2012-2122 | | | |
| 5432 | PgSQL | MD5 auth deprecated | | | |
| 5900 | VNC | DES-based auth (type 2) | | | |
| 6667 | IRC | UnrealIRCd CVE-2010-2075 | | | |
| 8009 | AJP | Ghostcat CVE-2020-1938 | | | |
| 8180 | HTTP | Tomcat Manager default creds | | | |

---

## False Positive / Negative Log

Record any incorrect findings for research paper Section 6.4.

| Port | Module | Finding Title | Type | Root Cause | Notes |
|---|---|---|---|---|---|
| | | | FP / FN | | |
| | | | FP / FN | | |
| | | | FP / FN | | |

**False positive rate formula:**
```
FP rate = (false positives / total findings) × 100
```

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `too many local variables` | Lua 5.1 limit hit | Ensure parts assembled in correct order |
| `variable 'smb' is not declared` | SMB require missing | Check Part 1 has `local smb = require "smb"` |
| `unfinished string` | Literal newline in Lua string | Re-download Part 1 (fixed version) |
| Module not firing on port | Port not in PORT_SERVICE_MAP | Check Part 1 PORT_SERVICE_MAP for that port |
| VNC produces no output | RFB 3.3 protocol not handled | Ensure Part 4 has dual 3.3/3.7 handler |
| MySQL empty-password not found | old_password auth switch | Part 3 has mysql_try_empty_password_old_auth fix |
| NFS no findings on 2049 | mountd on dynamic port | Part 3 queries portmapper first |
| No output from any module | Wrong scan syntax | Add `-sV` flag — NSE needs service detection |
| Script runs but scan ends in 1s | No hosts up | Check network/firewall, add `--send-eth` on some VMs |
| IRC version shows unknown | Banner regex mismatch | UnrealIRCd banner format varies by version |

---

## Research Paper Data Template

### Section 6.2 — Comparison vs Manual Enumeration

```
Manual enumeration using 8 separate Nmap scripts required [MANUAL_TIME] seconds
to complete and produced [MANUAL_FINDINGS] findings across [MANUAL_PORTS] ports.
Reko, executing all checks in a single command with aggression=1, completed the
same scope in [REKO_TIME] seconds — a [SPEEDUP]x reduction in enumeration time.

Reko produced [REKO_FINDINGS] total findings, [REKO_CRITICAL] of which were
CRITICAL priority, surfaced at the top of the output without manual parsing.
The attack path summary block identified [NUM_PATHS] ranked exploitation paths
with exact commands, eliminating the need for post-processing.
```

### Section 6.3 — Chart Data

Use findings from TC-3 and TC-4 to build:

1. **Bar chart — Scan time comparison**
   X-axis: Manual | Reko passive | Reko active
   Y-axis: seconds

2. **Bar chart — Findings by priority**
   X-axis: CRITICAL | HIGH | MEDIUM | LOW | INFO
   Y-axis: count (from TC-4)

3. **Pie chart — Coverage**
   Slice 1: vulnerabilities Reko found
   Slice 2: false positives
   Slice 3: missed (false negatives)

4. **Table — Manual vs Reko finding comparison**
   Rows: each known vulnerability
   Columns: found by manual? | found by Reko? | Reko priority | Reko score

### Section 6.4 — False Positive/Negative Analysis

```
During testing against Metasploitable 2, Reko produced [FP_COUNT] false
positives across [TOTAL] total findings, yielding a false positive rate
of [FP_RATE]%.

[If FP_COUNT > 0:]
False positives were observed in [MODULE] module where [CONDITION] caused
[FINDING] to be flagged incorrectly. [MITIGATION OR EXPLANATION].

[FN_COUNT] false negatives were recorded — [EXAMPLE] was not detected
because [REASON]. Future work will address this via [IMPROVEMENT].
```

---

## Verified Results — Metasploitable 2

These are the confirmed results from the Reko development test runs.
Use as a reference baseline.

```
Scan command:  nmap -sV -p- --script reko.nse --script-args reko.aggression=1
Scan time:     270 seconds (full -p- scan)
               ~40 seconds (targeted ports only)

Findings:      55 total
               CRITICAL:  17
               HIGH:      23
               MEDIUM:    15
               LOW:        0
               INFO:       0

False positives:    0
False negatives:    2 (MySQL root creds, IRC version extraction)

Top findings:
  0.99  CRITICAL  vsftpd 2.3.4 backdoor — root shell on port 6200
  0.97  CRITICAL  Tomcat Manager tomcat:tomcat — WAR RCE
  0.94  CRITICAL  SMBv1 + signing disabled — EternalBlue/SambaCry
  0.94  CRITICAL  Ghostcat CVE-2020-1938 — web.xml read confirmed
  0.91  CRITICAL  SMB null session — 5 shares (ADMIN$/IPC$/opt/print$/tmp)
  0.88  CRITICAL  Mutillidae vulnerable web app found
  0.86  CRITICAL  DVWA login page found
  0.85  CRITICAL  Directory listing at /test/
  0.85  CRITICAL  phpinfo.php — 48KB response
  0.83  HIGH      vsftpd 2.3.4 banner + CVE-2011-2523 + ExploitDB link

Attack paths generated: 3
  Path 1: vsftpd backdoor — nc <target> 6200 (root shell, immediate)
  Path 2: Ghostcat — python3 ghostcat.py -f /WEB-INF/web.xml
  Path 3: Tomcat Manager WAR upload — Metasploit tomcat_mgr_upload
```

---

*Part of the Reko project — github.com/MayanSuthar/reko*
