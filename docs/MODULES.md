# Reko Module Reference

> *Complete documentation for all 29 service modules.*

Every module follows the same pattern:
- **Passive checks** run at `reko.aggression=0` (default) — safe for any environment
- **Active checks** run at `reko.aggression=1` — credential tests and exploit probes
- All findings use the canonical scoring schema documented in `SCORING.md`

---

## Module Index

| # | Module Key | Port(s) | Protocol | Aggression |
|---|---|---|---|---|
| 1 | [ftp](#1-ftp) | 21, 2121, 990 | TCP | 0 + 1 |
| 2 | [ssh](#2-ssh) | 22 | TCP | 0 |
| 3 | [telnet](#3-telnet) | 23 | TCP | 0 + 1 |
| 4 | [smtp](#4-smtp) | 25 | TCP | 0 + 1 |
| 5 | [dns](#5-dns) | 53 | TCP + UDP | 0 + 1 |
| 6 | [http](#6-http) | 80, 8080, 8180, 8888 | TCP | 0 + 1 |
| 7 | [https](#7-https) | 443, 8443 | TCP | 0 |
| 8 | [kerberos](#8-kerberos) | 88, 464 | TCP | 0 + 1 |
| 9 | [pop3](#9-pop3) | 110 | TCP | 0 |
| 10 | [ident](#10-ident) | 113 | TCP | 0 |
| 11 | [ntp](#11-ntp) | 123 | UDP | 0 |
| 12 | [netbios_ns](#12-netbios_ns) | 137 | UDP | 0 |
| 13 | [smb](#13-smb) | 139, 445 | TCP | 0 + 1 |
| 14 | [imap](#14-imap) | 143 | TCP | 0 |
| 15 | [snmp](#15-snmp) | 161 | UDP | 0 + 1 |
| 16 | [ldap](#16-ldap) | 389, 3268 | TCP | 0 + 1 |
| 17 | [java_rmi](#17-java_rmi) | 1099, 1100 | TCP | 0 |
| 18 | [mssql](#18-mssql) | 1433 | TCP | 0 + 1 |
| 19 | [oracle_tns](#19-oracle_tns) | 1521 | TCP | 0 + 1 |
| 20 | [nfs](#20-nfs) | 2049 | TCP | 0 + 1 |
| 21 | [mysql](#21-mysql) | 3306 | TCP | 0 + 1 |
| 22 | [rdp](#22-rdp) | 3389 | TCP | 0 |
| 23 | [postgresql](#23-postgresql) | 5432 | TCP | 0 + 1 |
| 24 | [vnc](#24-vnc) | 5900 | TCP | 0 |
| 25 | [sip](#25-sip) | 5060 | UDP | 0 + 1 |
| 26 | [ajp](#26-ajp) | 8009 | TCP | 0 |
| 27 | [irc](#27-irc) | 6667, 6697 | TCP | 0 + 1 |
| 28 | [rpc](#28-rpc) | 111, 135 | TCP | 0 |
| 29 | [telnet](#3-telnet) | 23 | TCP | 0 + 1 |

---

## 1. FTP

**Ports:** 21, 2121, 990  
**Protocol:** TCP  
**Base weight:** 0.80

### What it checks

**Passive (aggression=0):**
- Banner grab — extracts software name and version from the 220 greeting
- AUTH TLS probe — sends `AUTH TLS`, checks for 234 response (FTPS supported)
- CVE lookup — automatically matches version against CVE_DB

**Active (aggression=1):**
- Anonymous login — sends `USER anonymous` / `PASS reko@reko.local`
- Home directory listing — PASV + LIST (up to 4 KB, 20 entries)
- Write permission probe — sends `MKD canary_name` + immediate `QUIT` to check if writable
- **vsftpd 2.3.4 backdoor probe** — sends `USER backdoor:)` then checks if port 6200 opens

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.99 | vsftpd 2.3.4 backdoor — root shell | Port 6200 opens after trigger |
| 0.91 | Anonymous login permitted | 230 response to anonymous credentials |
| 0.88 | Anonymous directory listed | Successful PASV + LIST |
| 0.90 | Anonymous write access | 257 response to MKD |
| 0.71 | No FTPS (cleartext) | 530 response to AUTH TLS |
| 0.83 | Banner with known CVE | CVE_DB match on version string |

### Notable CVEs covered

| Version | CVE | Severity |
|---|---|---|
| vsftpd 2.3.4 | CVE-2011-2523 | CRITICAL — backdoor, root shell |
| ProFTPD 1.3.1 | CVE-2010-4221 | HIGH — buffer overflow via TELNET_IAC |
| ProFTPD 1.3.3 | CVE-2011-4130 | CRITICAL — mod_copy SITE CPFR/CPTO RCE |

---

## 2. SSH

**Ports:** 22  
**Protocol:** TCP  
**Base weight:** 0.45

### What it checks

**Passive only:**
- Banner grab — protocol version, software name, comments
- SSHv1 detection — if major version == 1, immediate CRITICAL
- KEX_INIT binary packet reader — reads RFC 4253 SSH_MSG_KEXINIT (type byte 20)
- Weak key exchange algorithms (SHA-1 based, DH-group1, 1024-bit)
- Weak host key types (ssh-dss / DSA)
- Weak ciphers (RC4/arcfour, 3DES-CBC, AES-CBC, DES, none)
- Weak MACs (HMAC-MD5, HMAC-SHA1 without ETM)
- Pre-auth zlib compression (CRIME oracle risk)
- CVE lookup on OpenSSH version

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | SSHv1 protocol active | proto_major == 1 in banner |
| 0.71 | Weak KEX algorithms | DH-group1, SHA-1 KEX detected |
| 0.71 | Weak ciphers offered | RC4, 3DES, AES-CBC in KEX_INIT |
| 0.71 | Weak MACs offered | HMAC-MD5, SHA1 without ETM |
| 0.59 | Pre-auth zlib compression | zlib (not zlib@openssh.com) |
| 0.56 | Banner disclosed | Version string read |

### Notable CVEs covered

| Version | CVE | Severity |
|---|---|---|
| OpenSSH 4.x (Debian) | CVE-2008-0166 | CRITICAL — predictable key generation |
| OpenSSH 7.2p2 | CVE-2016-0777 | MEDIUM — roaming feature leaks keys |

---

## 3. Telnet

**Ports:** 23  
**Protocol:** TCP  
**Base weight:** 0.80

### What it checks

**Passive:**
- IAC negotiation byte stripping (0xFF sequences removed before parsing)
- Banner text extraction
- Cleartext protocol flagged HIGH always

**Active (aggression=1):**
- Credential testing with 8 default pairs:
  `msfadmin/msfadmin`, `admin/admin`, `root/root`, `root/(empty)`,
  `user/user`, `guest/guest`, `admin/password`, `admin/1234`
- Shell detection via prompt indicators: `$`, `#`, `%`, `>`
- Also checks for `last login` and `welcome` text

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.99 | Shell access via default credentials | Prompt or welcome text after login |
| 0.83 | Telnet cleartext service active | Any response on port 23 |

---

## 4. SMTP

**Ports:** 25  
**Protocol:** TCP  
**Base weight:** 0.50

### What it checks

**Passive:**
- Banner grab — MTA software, version, hostname from 220 greeting
- EHLO capability enumeration — all advertised extensions listed
- STARTTLS presence check

**Active (aggression=1):**
- Open relay test — `MAIL FROM:<probe@reko-scanner.invalid>` then `RCPT TO:<victim@relay-target.invalid>`
  — sends RSET immediately, DATA is **never** sent
- VRFY user enumeration — 10 common usernames tested
- EXPN mailing list probe — 9 common list names tested

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | Open relay confirmed | 250 response to external RCPT TO |
| 0.77 | VRFY user enumeration enabled | 2xx response to VRFY probe |
| 0.71 | EXPN mailing lists exposed | 2xx response to EXPN probe |
| 0.71 | No STARTTLS | STARTTLS absent from EHLO response |
| 0.56 | Banner disclosed | 220 greeting parsed |

### Tested usernames (VRFY)
`root`, `admin`, `administrator`, `postmaster`, `webmaster`,
`info`, `support`, `helpdesk`, `noreply`, `mailer-daemon`

---

## 5. DNS

**Ports:** 53 (TCP + UDP)  
**Protocol:** TCP for AXFR, UDP for queries  
**Base weight:** 0.40

### What it checks

**Passive:**
- version.bind CHAOS TXT query — extracts server software version
- Open recursion check — queries `google.com A`, checks for answer section
- Common record enumeration — SOA, NS, MX, TXT for inferred domain

**Active (aggression=1):**
- AXFR zone transfer — TCP query for the inferred domain
- Detects successful transfer (ancount >= 2 = SOA + records)

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | AXFR zone transfer succeeded | ancount >= 2 in TCP AXFR response |
| 0.77 | Open recursion enabled | Answer received for external name |
| 0.59 | Version string disclosed | version.bind TXT response |
| 0.54 | Common records enumerated | SOA/NS/MX answers returned |

---

## 6. HTTP

**Ports:** 80, 8080, 8180, 8888  
**Protocol:** TCP  
**Base weight:** 0.60

### What it checks

**Passive:**
- Server header fingerprinting (software + version)
- Technology stack headers (X-Powered-By, X-Generator, X-AspNet-Version)
- 6-header security audit: HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy
- Dangerous HTTP methods via OPTIONS (PUT, DELETE, TRACE, CONNECT)
- Redirect chain follower (5 hops) + open-redirect detection
- robots.txt Disallow path extraction
- 100+ path probe (see wordlist below)

**Active (aggression=1):**
- Directory listing detection (Index of / Directory listing in body)
- XST TRACE test — sends canary header, checks if server echoes it back
- **Tomcat Manager credential check** — probes `/manager/html`, tests:
  `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret`, `admin:(empty)`,
  `tomcat:password`, `manager:manager`

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.97 | Tomcat Manager — default creds | HTTP 200 after Basic auth |
| 0.99 | CVE path accessible (.git, .env, web shell) | 200 + non-trivial body |
| 0.88 | CTF web app found (DVWA, Mutillidae) | 200 on CTF wordlist path |
| 0.85 | Directory listing enabled | "Index of" in response body |
| 0.77 | All 6 security headers missing | Absent from response headers |
| 0.71 | TRACE XST enabled | Canary header echoed back |
| 0.80 | PUT/DELETE/TRACE methods | Listed in Allow header |

### CTF Wordlist (selected paths)

```
Web applications:  /dvwa/ /mutillidae/ /phpmyadmin/ /tikiwiki/ /twiki/ /webdav/
Admin panels:      /manager/html /admin/ /administrator /wp-admin/ /jmx-console/
Diagnostic pages:  /phpinfo.php /server-status /_profiler /telescope /actuator/env
Sensitive configs: /.env /.env.local /.env.production /web.config /wp-config.php.bak
Source control:    /.git/HEAD /.git/config /.svn/entries /.hg/store/00manifest.i
Database dumps:    /db.sql /dump.sql /backup.zip /backup.tar.gz
CTF flags:         /flag /flag.txt /flag.php /.flag /user.txt /root.txt /proof.txt
SSH keys:          /.ssh/id_rsa /.ssh/authorized_keys
Web shells:        /shell.php /cmd.php /c99.php /r57.php /webshell.php
CI/Debug:          /jenkins/script /actuator/heapdump /swagger-ui.html /console
```

---

## 7. HTTPS

**Ports:** 443, 8443  
**Protocol:** TCP (TLS)  
**Base weight:** 0.60

### What it checks

**Passive only:**
- Protocol versions — SSLv2, SSLv3, TLS 1.0, TLS 1.1 (all deprecated)
- TLS 1.2 cipher suite audit — NULL, EXPORT, RC4, 3DES, anonymous ciphers
- Certificate fetch and inspection:
  - Self-signed detection (Issuer == Subject)
  - Expiry check (expired + < 30 days warning)
  - Weak signature algorithm (MD5, SHA-1)
  - Wildcard certificate detection
  - SAN (Subject Alternative Name) extraction
- HSTS header presence on HTTPS response

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | SSLv2/SSLv3 supported | ClientHello accepted |
| 0.85 | NULL/EXPORT/anonymous ciphers | Cipher in weak pattern list |
| 0.85 | Certificate expired | notAfter < current time |
| 0.77 | TLS 1.0/1.1 supported | ClientHello accepted |
| 0.71 | Self-signed certificate | Issuer == Subject fields |
| 0.71 | SHA-1 signed certificate | sig_algorithm contains sha1 |
| 0.71 | No HSTS on HTTPS endpoint | Header absent from response |

---

## 8. Kerberos

**Ports:** 88, 464  
**Protocol:** TCP  
**Base weight:** 0.65

### What it checks

**Passive:**
- AS-REQ probe (minimal DER/ASN.1 packet, RFC 4120) to an invalid username
- KDC reachability + realm name extraction from KRB-ERROR response
- Pre-authentication bypass detection (AS-REP returned without credentials)

**Active (aggression=1):**
- AS-REP Roasting probe for 12 common service account names:
  `krbtgt`, `svc_backup`, `svc_sql`, `svc_web`, `svc_iis`, `svc_exchange`,
  `svc_scan`, `sqlservice`, `service`, `backup`, `administrator`, `admin`

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | AS-REP roastable accounts found | AS-REP returned without pre-auth |
| 0.94 | Pre-auth globally disabled | AS-REP to invalid probe user |
| 0.57 | KDC realm name disclosed | realm field in KRB-ERROR |

---

## 9. POP3

**Ports:** 110  
**Protocol:** TCP  
**Base weight:** 0.50

### What it checks

**Passive:**
- Banner grab from +OK greeting
- CAPA command — full capability list
- STARTTLS (STLS) presence check

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.71 | No STARTTLS — cleartext credentials | STLS absent from CAPA |
| 0.50 | Banner disclosed | +OK greeting parsed |

---

## 10. Ident

**Ports:** 113  
**Protocol:** TCP  
**Base weight:** 0.20

### What it checks

**Passive:**
- Queries: `22, <random_port>` to get the username owning the SSH process
- Parses USERID response field

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.51 | Service username disclosed | USERID field in response |
| 0.38 | Ident service active | Any response on port 113 |

---

## 11. NTP

**Ports:** 123  
**Protocol:** UDP  
**Base weight:** 0.30

### What it checks

**Passive:**
- Standard client request (mode 3) — extracts version, stratum, reference ID
- monlist probe (REQ_MON_GETLIST_1) — checks response size (> 48 bytes = amplification risk)
- Mode 6 readvar query — checks if unauthenticated control access is allowed

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.84 | monlist enabled — DDoS amplification (CVE-2013-5211) | Response > 48 bytes |
| 0.71 | Mode 6 unauthenticated control access | Mode 6 response with R bit set |
| 0.51 | Version/stratum disclosed | Standard client response parsed |

---

## 12. NetBIOS-NS

**Ports:** 137  
**Protocol:** UDP  
**Base weight:** 0.30

### What it checks

**Passive:**
- NBSTAT wildcard query — retrieves full name table
- Decodes all 18 NetBIOS name suffix types
- Extracts computer name (0x00 unique) and domain name (0x00 group)
- Domain Controller identification via `<1C>` group name
- Master Browser identification via `<1B>` unique name

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.68 | Domain Controller identified | <1C> group name present |
| 0.62 | Master Browser role active | <1B> unique name present |
| 0.56 | Name table exposed | Any NBSTAT response |

---

## 13. SMB

**Ports:** 139, 445  
**Protocol:** TCP  
**Base weight:** 0.90

### What it checks

**Passive:**
- Raw SMBv1 Negotiate packet — sends full dialect list (SMBv1 through SMBv2.???)
- SMBv1 detection — checks if server responds with SMB1 magic bytes (0xFF SMB)
- SMB signing status — reads Security Mode byte: required / enabled-not-required / disabled
- OS, LAN Manager, domain extraction from Negotiate response

**Active (aggression=1):**
- Null session share enumeration via NSE smb library
- ADMIN$, IPC$, C$ accessibility check

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | SMBv1 active — EternalBlue/WannaCry | SMB1 magic in response |
| 0.91 | Null session exposes shares | smb.share_get_list() succeeds |
| 0.85 | SMB signing disabled | Security Mode byte bit check |
| 0.71 | SMB signing not required | Enabled but not enforced |
| 0.59 | OS/domain info disclosed | String extraction from Negotiate |

### SambaCry note

When SMBv1 is confirmed on a Linux/Samba host, the attack path summary
automatically suggests `exploit/linux/samba/is_known_pipename` (CVE-2017-7494)
in addition to the Windows EternalBlue path.

---

## 14. IMAP

**Ports:** 143  
**Protocol:** TCP  
**Base weight:** 0.50

### What it checks

**Passive:**
- Banner grab — software extraction from `* OK` greeting
- CAPABILITY command — full extension list
- STARTTLS presence check
- AUTH mechanism audit — flags AUTH=PLAIN and AUTH=LOGIN as weak

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.71 | No STARTTLS — cleartext | STARTTLS absent from CAPABILITY |
| 0.67 | AUTH PLAIN/LOGIN advertised | AUTH= mechs in CAPABILITY |
| 0.56 | Banner disclosed | Software extracted from greeting |

---

## 15. SNMP

**Ports:** 161  
**Protocol:** UDP  
**Base weight:** 0.70

### What it checks

**Passive:**
- Community string probe — 15 strings tested with GetRequest for sysDescr OID
- System MIB-II info — sysDescr, sysName, sysLocation, sysContact, sysUpTime
- SNMPv2c BER-encoded GetRequest builder

**Active (aggression=1):**
- Interface table walk (ifDescr, ifPhysAddress)
- Running process list (hrSWRunName)

### Tested community strings

`public`, `private`, `community`, `manager`, `snmpd`, `admin`, `cisco`,
`monitor`, `default`, `guest`, `read`, `write`, `all`, `network`, `system`

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.84 | Default community string accepted | Valid response to GetRequest |
| 0.67 | System information enumerated | MIB-II values retrieved |

---

## 16. LDAP

**Ports:** 389, 3268 (Global Catalog)  
**Protocol:** TCP  
**Base weight:** 0.70

### What it checks

**Passive:**
- Anonymous BindRequest (LDAPv3, RFC 4511) — result code 0 = anonymous bind works
- Root DSE search — namingContexts, defaultNamingContext, supportedSASLMechanisms, dnsHostName

**Active (aggression=1):**
- User object enumeration under base DN (objectClass=user)
- Up to 20 accounts sampled

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.88 | Anonymous bind permitted | Result code 0 in BindResponse |
| 0.94 | User accounts enumerable anon | User objects returned from search |
| 0.59 | Root DSE info disclosed | namingContexts and SASL mechs returned |

---

## 17. Java RMI

**Ports:** 1099, 1100  
**Protocol:** TCP  
**Base weight:** 0.35

### What it checks

**Passive:**
- JRMI magic handshake (0x4A 0x52 0x4D 0x49) + StreamProtocol
- Checks for PROTOCOL_ACK (0x4E) in response
- Registry list() call using method hash 0x2DDE99200D4F7BAD
- Bound object name extraction from serialised response (TC_STRING 0x74 markers)

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.71 | Bound RMI objects exposed | Object names extracted from list() |
| 0.59 | RMI registry accessible | PROTOCOL_ACK received |

---

## 18. MSSQL

**Ports:** 1433  
**Protocol:** TCP (TDS)  
**Base weight:** 0.78

### What it checks

**Passive:**
- TDS PreLogin handshake — option header parsing extracts server version
- Product name mapping (SQL Server 7.0 through 2022)
- Encryption mode audit (ENCRYPT_OFF / ENCRYPT_NOT_SUP = cleartext credentials)

**Active (aggression=1):**
- SA default credential check via Login7 packet
  Tested: `sa/(empty)`, `sa/sa`, `sa/Password1`, `admin/admin`
- Checks for LOGINACK token (0xAD) in response

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.97 | SA default credentials accepted | LOGINACK token in Login7 response |
| 0.77 | Encryption not required | ENCRYPT_OFF or ENCRYPT_NOT_SUP |
| 0.62 | Version/product disclosed | PreLogin option header parsed |

---

## 19. Oracle TNS

**Ports:** 1521  
**Protocol:** TCP  
**Base weight:** 0.75

### What it checks

**Passive:**
- TNS CONNECT version request — listener version extraction
- TNS STATUS request — SERVICE_NAME and SID_NAME extraction

**Active (aggression=1):**
- Default SID probe — tests: `ORCL`, `XE`, `PROD`, `TEST`, `DB`, `ORACLE`,
  `PLSExtProc`, `CLRExtProc`, `XEXDB`
- Checks REDIRECT (0x05) or ACCEPT (0x02) response type

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.68 | Default SID accessible | REDIRECT or ACCEPT response |
| 0.62 | Service/SID names disclosed | STATUS response parsed |
| 0.59 | Listener version disclosed | VERSION response parsed |

---

## 20. NFS

**Ports:** 2049  
**Protocol:** TCP  
**Base weight:** 0.68

### What it checks

**Passive:**
- Queries portmapper (port 111) to find mountd's dynamic port
- PMAPPROC_EXPORT RPC to mountd — XDR linked-list export parser
- Client restriction analysis — detects `*`, `everyone`, or empty client list

**Active (aggression=1):**
- MNT RPC call to confirm the first export is actually mountable
- Checks for status=0 (success) + file handle in response

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | Mount confirmed without authentication | MNT RPC status=0 + file handle |
| 0.88 | World-accessible NFS export | Client list is * / empty / everyone |
| 0.59 | Export list disclosed | EXPORT RPC response parsed |

---

## 21. MySQL

**Ports:** 3306  
**Protocol:** TCP  
**Base weight:** 0.75

### What it checks

**Passive:**
- HandshakeV10 parser — version, capability bitmap, charset, auth plugin
- SSL capability flag (bit 11 of capabilities)
- Auth plugin audit — flags mysql_old_password and no-plugin as HIGH
- CVE lookup on version string

**Active (aggression=1):**
- Default credential test: `root/(empty)`, `root/root`, `root/mysql`, `admin/(empty)`
- Handles old_password auth switch (0xFE response) by sending null byte
- Checks OK packet (0x00) in response

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.97 | Root empty password accepted | OK packet after HandshakeResponse |
| 0.77 | Weak auth plugin (none/old) | Plugin absent or mysql_old_password |
| 0.77 | Version with CVE-2012-2122 | Version matches 5.0.x or 5.1.x |
| 0.71 | No SSL supported | SSL capability bit not set |

---

## 22. RDP

**Ports:** 3389  
**Protocol:** TCP  
**Base weight:** 0.85

### What it checks

**Passive:**
- X.224 Connection Request (TPKT + TPDU) — offers SSL + CredSSP protocols
- X.224 Connection Confirm parser — reads selected protocol byte
- NLA (Network Level Authentication) check
- Classic RC4 security detection

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.80 | NLA not required — BlueKeep exposure | Protocol 0 selected (classic RDP) |
| 0.77 | Classic RC4 security only | No TLS, no NLA in CC response |
| 0.54 | RDP service active | Any X.224 CC received |

---

## 23. PostgreSQL

**Ports:** 5432  
**Protocol:** TCP  
**Base weight:** 0.70

### What it checks

**Passive:**
- StartupMessage (protocol 3.0) — reads ParameterStatus messages
- Version extraction from server_version ParameterStatus
- Authentication type parsing:
  - Type 0 = AuthenticationOk = TRUST AUTH = no password required
  - Type 3 = plaintext password
  - Type 5 = MD5
  - Type 10 = SCRAM-SHA-256

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | Trust authentication — no password | AuthenticationOk (type 0) |
| 0.88 | Plaintext password auth | Auth type 3 |
| 0.71 | MD5 auth (deprecated) | Auth type 5 |
| 0.59 | SCRAM-SHA-256 (good) | Auth type 10 |
| 0.59 | Version disclosed | server_version ParameterStatus |

---

## 24. VNC

**Ports:** 5900  
**Protocol:** TCP  
**Base weight:** 0.80

### What it checks

**Passive:**
- RFB protocol version from banner (handles both 3.3 and 3.7+ formats)
- **RFB 3.3:** reads 4-byte uint32 security type directly
- **RFB 3.7+:** reads 1-byte count then N type bytes
- Security type classification: 1=None, 2=VNC-auth, 18=TLS/VeNCrypt

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.97 | No authentication (type 1) | Security type 1 offered |
| 0.71 | DES-based VNC auth (type 2) | Security type 2 offered |
| 0.68 | Old RFB protocol version | Major=3, minor < 7 |

---

## 25. SIP

**Ports:** 5060  
**Protocol:** UDP  
**Base weight:** 0.38

### What it checks

**Passive:**
- OPTIONS request — Server/User-Agent header extraction

**Active (aggression=1):**
- REGISTER-based user enumeration for 10 usernames:
  `admin`, `administrator`, `test`, `guest`, `100`, `200`, `1000`,
  `operator`, `reception`, `voicemail`
- 401/407 = user exists; 404 = not found

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.63 | User enumeration possible | 401/407 vs 404 response discrimination |
| 0.51 | Server software disclosed | Server/UA header in OPTIONS response |

---

## 26. AJP

**Ports:** 8009  
**Protocol:** TCP  
**Base weight:** 0.60

### What it checks

**Passive:**
- AJP connector accessibility — flagged HIGH always (should never be public)
- **Ghostcat CVE-2020-1938** — sends AJP FORWARD_REQUEST with:
  - `javax.servlet.include.request_uri = /`
  - `javax.servlet.include.path_info = /WEB-INF/web.xml`
  - `javax.servlet.include.servlet_path = /`
- Response checked for XML markers (web-app, servlet, <?xml, WEB-INF)

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.94 | Ghostcat CVE-2020-1938 confirmed | web.xml content in response |
| 0.77 | AJP connector publicly accessible | Any connection accepted on 8009 |

---

## 27. IRC

**Ports:** 6667, 6697  
**Protocol:** TCP  
**Base weight:** 0.55

### What it checks

**Passive:**
- Banner grab — UnrealIRCd version extraction
- Version 3.2.8.1 specific detection — flags CVE-2010-2075

**Active (aggression=1):**
- Backdoor probe: sends `AB;echo RKO_PROBE_$(id)\n`
- Checks response for `RKO_PROBE_` or `uid=` string

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.97 | UnrealIRCd backdoor RCE confirmed | RKO_PROBE_ or uid= in response |
| 0.88 | UnrealIRCd 3.2.8.1 detected | Version 3.2.8.1 in banner |
| 0.57 | IRC service active | Any banner response |

---

## 28. RPC

**Ports:** 111 (portmapper), 135 (MS-RPC)  
**Protocol:** TCP  
**Base weight:** 0.62

### What it checks

**Port 111 — Sun RPC portmapper:**
- PMAPPROC_DUMP request — lists all registered RPC programs
- XDR response parser — extracts program number, version, protocol, port
- High-value service identification (NFS, mountd)

**Port 135 — MS-RPC Endpoint Mapper:**
- DCE/RPC bind request to EPM UUID (E1AF8308-5D1F-11C9-91A4-08002B14A0FA)
- Checks for bind_ack (packet type 0x0C)

### Key findings

| Score | Finding | Trigger |
|---|---|---|
| 0.74 | NFS/mountd exposed via portmapper | Program 100005 in dump |
| 0.67 | MS-RPC endpoint mapper accessible | bind_ack received |
| 0.54 | RPC program list disclosed | DUMP response parsed |

---

## Adding Custom Modules

To add a new service module, append a `register_module()` call to the script
before the `action()` function:

```lua
register_module("myservice", function(ctx)
  local host_ip = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout

  -- Your probe logic here

  ctx:add_finding(
    "Finding title",
    "Description of what was found and why it matters.",
    {
      evidence_key = "evidence_value",
      remediation  = "How to fix this.",
    },
    0.95,   -- confidence (0.0 to 1.0)
    0.70    -- impact     (0.0 to 1.0)
  )
end)
```

Also add the port to `PORT_SERVICE_MAP` in Part 1:

```lua
[YOUR_PORT] = { key = "myservice", proto = "tcp" },
```

And a base weight to `SERVICE_BASE_WEIGHT`:

```lua
myservice = 0.60,
```

---

*Part of the Reko project — github.com/MayanSuthar/reko*
