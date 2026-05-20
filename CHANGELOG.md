# Changelog

All notable changes to Reko are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased] — Fixes from code review

### Security
- **FIX 1** — vsftpd 2.3.4 backdoor probe (CVE-2011-2523) now correctly gated
  behind `reko.aggression=1`. Previously fired even in passive mode (`aggression=0`),
  violating the tool's documented "safe for all environments" guarantee and potentially
  triggering an exploit attempt on systems not intended for active testing.

- **FIX 2** — Telnet module: credential redaction now applies to the finding
  description string and `log_warn` output, not only to `evidence.*` fields.
  Previously `reko.redact=true` had no effect on those strings — the raw
  password appeared in plain text output regardless of the flag.

- **FIX 3** — Registry race condition under parallel NSE coroutines fixed.
  `registry_record()` and `registry_get()` now use `nmap.mutex("reko_registry")`
  to protect the read-modify-write on `nmap.registry`. Previously two coroutines
  scanning different ports simultaneously could overwrite each other's findings,
  silently dropping items from the attack path summary.

### Fixed
- **FIX 4** — Missing `local` on `pkt_data` in `ssh_read_kexinit()` (line ~1695).
  The second `receive_bytes` call assigned to an undeclared variable, making
  `pkt_data` a global that any concurrent coroutine could overwrite mid-scan.
  Changed to `local status, pkt_data = sd:receive_bytes(pkt_len)`.

- **FIX 5** — `ftp_probe_write()` read ordering corrected. Previously QUIT was
  sent before reading the MKD response. Many FTP servers flush `221 Goodbye`
  before `257` in pipeline order, causing write detection to always return
  `readonly` (false negative). Fixed to read MKD response first, then send QUIT.

- **FIX 6** — Duplicate `[3389]` entry removed from `PORT_SERVICE_MAP`.
  Port 3389 (RDP) appeared twice. In Lua the second entry silently overwrites
  the first with no error. Duplicate removed.

### Changed
- **FIX 7** — Aggression level 2 (`AGG_FULL_ACTIVE`) documented with distinct
  behaviour from level 1: extended HTTP wordlists, more credential pairs per
  service, SMTP EXPN enumeration, DNS AXFR attempts. NSE description block
  updated to reflect this distinction. Service count corrected from "25+"
  to "29" in the embedded `description` field (shown by `--script-help`).

- **FIX 8** — SSH KEX_INIT parser now uses `padding_len` to bound the readable
  payload region. Previously `padding_len` was read but discarded; for servers
  that include SSH padding bytes the `read_namelist` helper could walk into
  padding and return garbage algorithm names. Fixed by computing `payload_end
  = #pkt_data - padding_len` and passing it as the safe boundary.

- **FIX 9** — `log_info()` call with unformatted `%d` specifier fixed.
  `log_info(ctx, "ftp", "Aggression level %d: ...", agg)` passed extra args
  that the 3-argument function signature silently ignored, so the message
  always printed literally with `%d`. Wrapped in `string.format()`.

### Added (repo hygiene — FIX 10)
- `.gitignore` — excludes Nmap script databases, editor swap files,
  test output directories, Python cache, and OS-specific files.
- `.github/workflows/lint.yml` — GitHub Actions CI workflow that runs on
  every push and PR touching `.nse` or `.lua` files:
  - Lua 5.1 syntax check via `luac5.1 -p` on all part files and assembled script
  - Top-level local variable count check (must stay under Lua 5.1 limit of 200)
  - Module registration count check (must have all 29 expected modules)
  - Markdown file presence check

---

## [0.1.0] — Initial release

### Added
- 29 service modules: FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, Kerberos,
  POP3, ident, NTP, NetBIOS-NS, SMB, IMAP, SNMP, LDAP, Java RMI, MSSQL,
  Oracle TNS, NFS, MySQL, RDP, PostgreSQL, VNC, SIP, AJP, IRC, RPC, unknown
- Risk-based scoring engine: `score = (confidence × 0.4) + (impact × 0.6)`
- Five priority tiers: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Two aggression levels: 0 (passive) and 1 (active credential checks)
- CVE lookup table with ExploitDB links for 15 software versions
- Attack path summary engine — cross-port finding synthesis with 10 chain patterns
- CTF-optimised HTTP wordlist with 100+ paths including flag files and web shells
- JSON output mode (`reko.output=json`) with full finding schema
- Credential redaction (`reko.redact=true`, default)
- Module filter (`reko.modules=smb,http`)
- Verified against Metasploitable 2: 55 findings, 0 false positives, 270s full scan

### Notable detections on Metasploitable 2
- vsftpd 2.3.4 backdoor — root shell on port 6200 confirmed (score 0.99)
- Tomcat Manager default credentials tomcat:tomcat — WAR RCE (score 0.97)
- Ghostcat CVE-2020-1938 — /WEB-INF/web.xml read confirmed live (score 0.94)
- SMBv1 + null session + signing disabled (score 0.94 / 0.91 / 0.85)
- DVWA, Mutillidae, TikiWiki, TWiki, WebDAV all found via CTF wordlist
