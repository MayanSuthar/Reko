<div align="center">

```
██████╗ ███████╗██╗  ██╗ ██████╗
██╔══██╗██╔════╝██║ ██╔╝██╔═══██╗
██████╔╝█████╗  █████╔╝ ██║   ██║
██╔══██╗██╔══╝  ██╔═██╗ ██║   ██║
██║  ██║███████╗██║  ██╗╚██████╔╝
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝
```

**Automated Active & Passive Network Enumeration Framework**

[![Nmap NSE](https://img.shields.io/badge/Nmap-NSE%20Script-4A90D9?style=flat-square&logo=nmap)](https://nmap.org/book/nse.html)
[![Language](https://img.shields.io/badge/Language-Lua%205.1-000080?style=flat-square)](https://www.lua.org/)
[![License](https://img.shields.io/badge/License-Same%20as%20Nmap-green?style=flat-square)](https://nmap.org/book/man-legal.html)
[![Services](https://img.shields.io/badge/Services-29%20Modules-red?style=flat-square)](#modules)
[![Author](https://img.shields.io/badge/Author-Mayan%20Suthar-blueviolet?style=flat-square)](https://github.com/MayanSuthar)
[![Institution](https://img.shields.io/badge/SPUPSC-M.Tech%20Cyber%20Security-orange?style=flat-square)](#)

> *One script. 29 services. Prioritised findings. CTF-ready.*

</div>

---

## What is Reko?

**Reko** is a single Nmap NSE script that replaces an entire pentesting toolkit for the enumeration phase. Instead of running 8 separate tools and manually correlating their outputs, you run one command and get a prioritised, scored report across 29 network services in under 5 minutes.

It was built to solve three specific problems that every penetration tester faces:

| Problem | How Reko Solves It |
|---|---|
| **Fragmentation** — 8 tools, 8 formats, manual correlation | One `.nse` file, one command, one unified output |
| **No prioritisation** — every finding looks equal | Scoring engine ranks findings CRITICAL → INFO automatically |
| **Speed** — setup time kills CTF engagements | `nmap --script reko.nse <target>` is the entire workflow |

---

## Quick Start

```bash
# Install
sudo cp reko.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb

# Passive scan (safe for all environments)
nmap -sV --script reko.nse <target>

# Full active scan (credential checks + exploit probes)
nmap -sV --script reko.nse --script-args reko.aggression=1 <target>

# Full port scan with active checks (recommended for CTF/labs)
nmap -sV -p- --script reko.nse --script-args reko.aggression=1 <target>

# JSON output for integration
nmap -sV --script reko.nse --script-args reko.output=json <target>

# Single module only
nmap -p 445 -sV --script reko.nse --script-args reko.modules=smb <target>
```

---

## Real Output — Metasploitable 2

```
21/tcp open ftp vsftpd 2.3.4
| reko:
| [CRITICAL][192.168.100.60:21][FTP] vsftpd 2.3.4 BACKDOOR CONFIRMED on port 6200
|   Connect: nc 192.168.100.60 6200  →  root shell
|   evidence.cve = CVE-2011-2523
|   confidence=0.99  impact=0.99

| [CRITICAL][192.168.100.60:21][FTP] FTP anonymous login permitted  (score: 0.91)
|   evidence.server_reply = 230 Login successful.

8180/tcp open http Apache Tomcat/Coyote JSP engine 1.1
| reko:
| [CRITICAL][192.168.100.60:8180][HTTP] Tomcat Manager: tomcat:tomcat  (score: 0.97)
|   WAR upload = Remote Code Execution
|   evidence.attack_cmd = msfconsole: use multi/http/tomcat_mgr_deploy

| ═══════════════════════════════════════════════════════
| REKO ATTACK PATH SUMMARY — 192.168.100.60
| 26 CRITICAL/HIGH findings across 5 ports
| ═══════════════════════════════════════════════════════
|
| ► PATH 1 — RCE: Tomcat Manager WAR Upload
|   HOW:
|     1. msfconsole: use multi/http/tomcat_mgr_upload
|     2. set RHOSTS 192.168.100.60; set RPORT 8180
|     3. set HttpUsername tomcat; set HttpPassword tomcat; run
```

---

## Features

### Scoring Engine
Every finding is scored using the formula:

```
score = (confidence × 0.4) + (impact × 0.6)
```

| Score | Priority | Meaning |
|---|---|---|
| ≥ 0.85 | 🔴 CRITICAL | Direct path to compromise — exploit immediately |
| ≥ 0.65 | 🟠 HIGH | Serious risk — exploit or remediate within 24h |
| ≥ 0.40 | 🟡 MEDIUM | Real weakness — needs conditions to exploit |
| ≥ 0.20 | 🟢 LOW | Informational risk |
| < 0.20 | ⚪ INFO | Context only |

### Attack Path Summary
After scanning 4+ ports, Reko synthesises all findings into ranked attack paths with exact commands:

```
► PATH 1 — IMMEDIATE ROOT: vsftpd 2.3.4 Backdoor
  WHY: CVE-2011-2523 — send USER user:) to trigger, connect port 6200
  HOW:
    1. nc <target> 6200
    2. id  →  you are root
```

### CVE Lookup Table
Version disclosures automatically include CVE numbers and ExploitDB links:
```
[HIGH] FTP banner — CVE-2011-2523 known
  evidence.cve = CVE-2011-2523
  evidence.exploit_db = https://www.exploit-db.com/exploits/17491
```

### CTF Wordlist (100+ paths)
HTTP module includes CTF-specific paths: `/dvwa/`, `/mutillidae/`, `/flag.txt`, `/user.txt`, `/root.txt`, `/.ssh/id_rsa`, `/jenkins/script`, Spring Actuator endpoints, web shells.

---

## Modules

| # | Service | Port(s) | Key Checks |
|---|---|---|---|
| 1 | FTP | 21, 2121 | Banner, anonymous login, write probe, **vsftpd 2.3.4 backdoor (CVE-2011-2523)** |
| 2 | SSH | 22 | Banner, KEX_INIT algorithm audit, weak cipher/MAC/KEX detection |
| 3 | Telnet | 23 | Banner, cleartext flag, **credential testing (msfadmin, admin, root)** |
| 4 | SMTP | 25 | Banner, EHLO caps, STARTTLS, open-relay test, VRFY/EXPN user enum |
| 5 | DNS | 53 | version.bind, open recursion, SOA/NS/MX, AXFR zone transfer |
| 6 | HTTP | 80, 8080, 8180 | Headers, 100+ path probe, TRACE XST, **Tomcat Manager cred check** |
| 7 | HTTPS/TLS | 443, 8443 | Protocol versions, cipher audit, cert expiry, self-signed, HSTS |
| 8 | Kerberos | 88, 464 | Realm discovery, AS-REP Roasting probe |
| 9 | POP3 | 110 | Banner, CAPA, STARTTLS |
| 10 | Ident | 113 | Username disclosure |
| 11 | RPC | 111, 135 | Portmapper dump, NFS exposure, MS-RPC EPM |
| 12 | NetBIOS-NS | 137 | NBSTAT name table, DC identification `<1C>` |
| 13 | SMB | 139, 445 | SMBv1 detection, **null session share enum**, signing audit |
| 14 | IMAP | 143 | Banner, CAPABILITY, STARTTLS, AUTH mechs |
| 15 | SNMP | 161 | 15 community string probes, MIB-II system info |
| 16 | LDAP | 389, 3268 | Anonymous bind, Root DSE, user enumeration |
| 17 | HTTPS | 443 | TLS protocol/cipher audit, certificate analysis |
| 18 | SMB | 445 | (same as 139) |
| 19 | Java RMI | 1099, 1100 | JRMI handshake, registry list(), bound objects |
| 20 | MSSQL | 1433 | TDS PreLogin, version, encryption audit, SA creds |
| 21 | Oracle TNS | 1521 | Listener version, service/SID enumeration |
| 22 | NFS | 2049 | Export listing via portmapper, world-accessible mounts |
| 23 | MySQL | 3306 | Handshake, version, SSL flag, root empty-password |
| 24 | RDP | 3389 | X.224 CC, NLA check, BlueKeep exposure |
| 25 | PostgreSQL | 5432 | Startup, **trust auth detection**, MD5/SCRAM audit |
| 26 | VNC | 5900 | RFB 3.3+3.7 dual handler, no-auth type 1, DES type 2 |
| 27 | SIP | 5060 | OPTIONS probe, user enumeration via REGISTER |
| 28 | AJP | 8009 | Connector exposure, **Ghostcat CVE-2020-1938** |
| 29 | IRC | 6667, 6697 | UnrealIRCd version, **CVE-2010-2075 backdoor probe** |

---

## Script Arguments

| Argument | Values | Default | Description |
|---|---|---|---|
| `reko.aggression` | 0, 1 | 0 | 0 = passive only; 1 = active checks (credential tests, exploit probes) |
| `reko.output` | text, json, both | text | Output format |
| `reko.modules` | comma-separated | all | Run specific modules only: `reko.modules=smb,http` |
| `reko.timeout` | milliseconds | 5000 | Per-module socket timeout |
| `reko.loglevel` | 0, 1, 2 | 1 | 0=errors, 1=warnings, 2=info (verbose) |
| `reko.redact` | true, false | true | Redact passwords in output |

---

## Installation

### Requirements
- Nmap ≥ 7.80 with NSE support
- Kali Linux / ParrotOS recommended
- Root/sudo for full scan capabilities

### Install

```bash
# Clone the repository
git clone https://github.com/MayanSuthar/reko.git
cd reko

# Install script
sudo cp reko.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb

# Verify
nmap --script-help reko.nse
```


---

## Usage Examples

```bash
# 1. Quick passive scan — safe for production environments
nmap -sV --script reko.nse 10.10.10.1

# 2. CTF/lab — full port scan with all active checks
nmap -sV -p- --script reko.nse --script-args reko.aggression=1 10.10.10.1

# 3. Targeted — scan only specific ports Reko covers
nmap -sV -p 21,22,23,25,53,80,111,139,445,1099,2049,2121,3306,5432,5900,6667,8009,8180 \
  --script reko.nse --script-args reko.aggression=1 10.10.10.1

# 4. JSON output for further processing
nmap -sV --script reko.nse --script-args reko.output=json 10.10.10.1 > results.json

# 5. Verbose debug mode
nmap -sV --script reko.nse --script-args reko.aggression=1,reko.loglevel=2 10.10.10.1

# 6. Single module with active checks
nmap -p 445 -sV --script reko.nse --script-args reko.modules=smb,reko.aggression=1 10.10.10.1

# 7. Count findings by priority (requires JSON output)
nmap -sV --script reko.nse --script-args reko.output=json 10.10.10.1 \
  | grep -o '"priority":"[^"]*"' | sort | uniq -c | sort -rn
```

---

## Comparison with Existing Tools

| Tool | Services | Prioritisation | Single Command | CVE Lookup | Attack Paths | License |
|---|---|---|---|---|---|---|
| **Reko** | **29** | **✅ Scored** | **✅ Yes** | **✅ Built-in** | **✅ Yes** | Free |
| AutoRecon | ~20 | ❌ Raw output | ❌ Multi-tool | ❌ No | ❌ No | Free |
| Nmap (default NSE) | ~25 | ❌ No scoring | ✅ Yes | ❌ No | ❌ No | Free |
| Nessus Pro | ~50 | ✅ CVSS | ❌ Setup required | ✅ Yes | ❌ No | Paid |
| Metasploit auxiliary | ~15 | ❌ No scoring | ❌ Multi-step | ✅ Partial | ❌ No | Free |

---

## Tested Against

| Target | Environment | Key Findings |
|---|---|---|
| Metasploitable 2 | VirtualBox lab | vsftpd backdoor ✓, Tomcat Manager ✓, SMB null session ✓, Ghostcat ✓ |
| HackTheBox (Easy) | CTF | Full enumeration in <5 min |
| DVWA / Mutillidae | Web lab | 100+ path wordlist found all apps |

---

## Responsible Use

> ⚠️ **This tool is intended for authorised penetration testing, CTF competitions, and security research only.**
>
> Running Reko against systems you do not own or do not have explicit written permission to test is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and equivalent laws worldwide.
>
> The author assumes no liability for misuse of this tool.

**Ethical use only:**
- ✅ Your own lab/VMs
- ✅ CTF platforms (HackTheBox, TryHackMe, PentesterLab)
- ✅ Systems with explicit written authorisation
- ❌ Production systems without permission
- ❌ Public infrastructure

---

## Research Context

Reko was developed as part of M.Tech research in Cyber Security at **Sardar Patel University of Police, Security and Criminal Justice (SPUPSC)**.

**Research paper:** *Reko — An Automated Active and Passive Network Enumeration Framework for Prioritized Attack Path Discovery*

**Supervisors:** Dr. Arjun Choudhary & Dr. Vikas Sihag

**Academic Session:** 2025–2027

---

## File Structure

```
reko/
├── reko.nse              ← Complete assembled script (install this)
├── docs/
│   ├── SCORING.md        ← How the scoring formula works
│   ├── MODULES.md        ← Detailed module documentation
│   └── TESTING.md        ← Day 9 testing guide
├── examples/
│   ├── metasploitable2_passive.txt   ← Sample passive scan output
│   ├── metasploitable2_active.txt    ← Sample active scan output
│   └── json_output_sample.json       ← Sample JSON output
├── tests/
│   └── test_commands.sh  ← All test commands for validation
├── LICENSE
└── README.md
```

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

Areas for contribution:
- Additional CVE entries in `CVE_DB`
- New service modules
- False positive reduction
- Additional CTF wordlist paths
- Performance improvements

---

## Author

**Mayan Suthar**
- GitHub: [@MayanSuthar](https://github.com/MayanSuthar)
- Medium: [@mayan230848](https://medium.com/@mayan230848)
- LinkedIn: [mayan-suthar](https://linkedin.com/in/mayan-suthar-5625b1229/)
- Institution: SPUPSC | M.Tech Cyber Security 2025–2027

---

## License

Same as Nmap — see [https://nmap.org/book/man-legal.html](https://nmap.org/book/man-legal.html)

---

<div align="center">

**root@nullyblissful:~# nmap --script reko.nse target**

*Built for pentesters. Tuned for CTF. Backed by research.*

</div>
