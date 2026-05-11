#!/bin/bash
# =============================================================================
# Reko NSE Script — Test Command Suite
# Target: Metasploitable 2 (adjust TARGET variable to your VM IP)
# Usage:  chmod +x test_commands.sh && ./test_commands.sh
#
# IMPORTANT: Only run against systems you own or have explicit permission to test.
# This script is intended for use in controlled lab environments only.
# =============================================================================

# Set your Metasploitable 2 IP here
TARGET="192.168.100.60"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# Output directory
OUTDIR="./reko_test_results"
mkdir -p "$OUTDIR"

echo -e "${BLUE}"
echo "============================================================"
echo "  Reko NSE Script — Test Suite"
echo "  Target: $TARGET"
echo "  Output: $OUTDIR/"
echo "============================================================"
echo -e "${NC}"

# =============================================================================
# TC-1: Syntax Check
# Verify the script loads without Lua errors
# =============================================================================
echo -e "${YELLOW}[TC-1] Syntax Check — verifying script loads cleanly${NC}"
nmap --script-help reko.nse 2>&1 | grep -E "Categories|reko.aggression|reko.output"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}  PASS: Script loaded successfully${NC}"
else
    echo -e "${RED}  FAIL: Script failed to load — check for Lua errors${NC}"
    exit 1
fi
echo ""

# =============================================================================
# TC-2: Localhost Smoke Test
# Confirm the script executes without runtime errors on localhost
# =============================================================================
echo -e "${YELLOW}[TC-2] Localhost Smoke Test${NC}"
nmap -sV --script reko.nse 127.0.0.1 2>&1 | tee "$OUTDIR/tc2_localhost.txt" | \
    grep -E "reko:|ERROR|error" | head -10
echo -e "${GREEN}  Output saved to $OUTDIR/tc2_localhost.txt${NC}"
echo ""

# =============================================================================
# TC-3: Passive Scan (aggression=0) with timing
# Validates that passive mode does NOT perform credential tests
# =============================================================================
echo -e "${YELLOW}[TC-3] Passive Scan (aggression=0)${NC}"
echo "  Running passive scan against $TARGET ..."
time nmap -sV \
    -p 21,22,23,25,53,80,111,139,445,1099,2049,2121,3306,5432,5900,6667,8009,8180 \
    --script reko.nse \
    --script-args reko.aggression=0 \
    "$TARGET" 2>&1 | tee "$OUTDIR/tc3_passive.txt"

echo ""
echo -e "${BLUE}  TC-3 Results:${NC}"
echo "  Total findings:"
grep -c "CRITICAL\|HIGH\|MEDIUM\|LOW\]\[" "$OUTDIR/tc3_passive.txt" 2>/dev/null || echo "  0"
echo "  CRITICAL:"
grep -c "\[CRITICAL\]" "$OUTDIR/tc3_passive.txt" 2>/dev/null || echo "  0"
echo "  HIGH:"
grep -c "\[HIGH\]" "$OUTDIR/tc3_passive.txt" 2>/dev/null || echo "  0"
echo "  MEDIUM:"
grep -c "\[MEDIUM\]" "$OUTDIR/tc3_passive.txt" 2>/dev/null || echo "  0"

# Validate passive mode did NOT attempt active checks
if grep -q "230 Login successful" "$OUTDIR/tc3_passive.txt" 2>/dev/null; then
    echo -e "${RED}  WARN: Anonymous FTP login found in passive scan — aggression=0 may be firing active checks${NC}"
else
    echo -e "${GREEN}  PASS: No anonymous login attempts in passive mode${NC}"
fi
echo ""

# =============================================================================
# TC-4: Full Active Scan (aggression=1) — PRIMARY BENCHMARK
# All checks enabled: credential tests + exploit probes
# =============================================================================
echo -e "${YELLOW}[TC-4] Full Active Scan (aggression=1) — PRIMARY BENCHMARK${NC}"
echo "  Running active scan against $TARGET (this may take 30-60 seconds) ..."
time nmap -sV \
    -p 21,22,23,25,53,80,111,139,445,1099,2049,2121,3306,5432,5900,6667,8009,8180 \
    --script reko.nse \
    --script-args reko.aggression=1 \
    "$TARGET" 2>&1 | tee "$OUTDIR/tc4_active.txt"

echo ""
echo -e "${BLUE}  TC-4 Results:${NC}"
echo "  CRITICAL findings:"
grep "\[CRITICAL\]" "$OUTDIR/tc4_active.txt" | grep -o "\[CRITICAL\].*score:.*" | head -10
echo ""
echo "  Key checks:"

if grep -q "BACKDOOR CONFIRMED" "$OUTDIR/tc4_active.txt"; then
    echo -e "${GREEN}  PASS: vsftpd 2.3.4 backdoor detected${NC}"
else
    echo -e "${RED}  MISS: vsftpd backdoor not detected${NC}"
fi

if grep -q "anonymous login permitted" "$OUTDIR/tc4_active.txt"; then
    echo -e "${GREEN}  PASS: FTP anonymous login detected${NC}"
else
    echo -e "${RED}  MISS: FTP anonymous login not detected${NC}"
fi

if grep -q "null session exposes" "$OUTDIR/tc4_active.txt"; then
    echo -e "${GREEN}  PASS: SMB null session share enumeration working${NC}"
else
    echo -e "${RED}  MISS: SMB null session not detected${NC}"
fi

if grep -q "tomcat:tomcat" "$OUTDIR/tc4_active.txt"; then
    echo -e "${GREEN}  PASS: Tomcat Manager default credentials found${NC}"
else
    echo -e "${RED}  MISS: Tomcat Manager credentials not found${NC}"
fi

if grep -q "Ghostcat" "$OUTDIR/tc4_active.txt"; then
    echo -e "${GREEN}  PASS: Ghostcat CVE-2020-1938 detected${NC}"
else
    echo -e "${RED}  MISS: Ghostcat not detected${NC}"
fi

if grep -q "ATTACK PATH SUMMARY" "$OUTDIR/tc4_active.txt"; then
    echo -e "${GREEN}  PASS: Attack path summary generated${NC}"
else
    echo -e "${YELLOW}  NOTE: Attack path summary not generated (needs 4+ ports)${NC}"
fi
echo ""

# =============================================================================
# TC-5: JSON Output Mode
# Verify JSON is valid and machine-parseable
# =============================================================================
echo -e "${YELLOW}[TC-5] JSON Output Mode${NC}"
nmap -sV \
    -p 21,22,80,139,445,8009,8180 \
    --script reko.nse \
    --script-args reko.output=json \
    "$TARGET" > "$OUTDIR/tc5_output.json" 2>&1

# Validate JSON is parseable and count findings
python3 - << 'EOF'
import json, sys, re

with open('./reko_test_results/tc5_output.json') as f:
    raw = f.read()

# Extract JSON objects from nmap output
json_objects = re.findall(r'\|[_]?reko: (\{.*\})', raw)
findings = []
for obj in json_objects:
    try:
        data = json.loads(obj)
        if 'findings' in data:
            findings.extend(data['findings'])
    except:
        pass

from collections import Counter
if findings:
    priorities = Counter(f.get('priority','?') for f in findings)
    print(f"  PASS: JSON parsed successfully — {len(findings)} findings")
    for p in ['CRITICAL','HIGH','MEDIUM','LOW']:
        if priorities.get(p):
            print(f"    {p}: {priorities[p]}")
    # Validate schema
    required = ['id','host','port','service','title','score','priority','confidence']
    f0 = findings[0]
    missing = [k for k in required if k not in f0]
    if missing:
        print(f"  WARN: Missing schema fields: {missing}")
    else:
        print(f"  PASS: All required JSON schema fields present")
else:
    print("  WARN: No JSON findings parsed — check reko.output=json is working")
EOF
echo -e "${GREEN}  Output saved to $OUTDIR/tc5_output.json${NC}"
echo ""

# =============================================================================
# TC-6: Single Module Isolation
# Verify reko.modules filter works correctly
# =============================================================================
echo -e "${YELLOW}[TC-6] Single Module Isolation${NC}"

echo "  Testing SMB module in isolation (port 445) ..."
nmap -p 445 -sV --script reko.nse \
    --script-args reko.modules=smb,reko.aggression=1 \
    "$TARGET" 2>&1 | tee "$OUTDIR/tc6_smb_only.txt" | \
    grep -E "reko:|service=|CRITICAL|HIGH|MEDIUM"

echo ""
echo "  Testing FTP module in isolation (port 21) ..."
nmap -p 21 -sV --script reko.nse \
    --script-args reko.modules=ftp,reko.aggression=1 \
    "$TARGET" 2>&1 | tee "$OUTDIR/tc6_ftp_only.txt" | \
    grep -E "reko:|service=|CRITICAL|HIGH|MEDIUM"

echo ""
echo "  Testing HTTP module in isolation (port 80) ..."
nmap -p 80 -sV --script reko.nse \
    --script-args reko.modules=http,reko.aggression=1 \
    "$TARGET" 2>&1 | tee "$OUTDIR/tc6_http_only.txt" | \
    grep -E "reko:|service=|CRITICAL|HIGH|MEDIUM"
echo ""

# =============================================================================
# TC-7: Manual Enumeration Timing Comparison
# Times manual approach vs Reko for research paper Section 6.2
# =============================================================================
echo -e "${YELLOW}[TC-7] Manual Enumeration Timing Comparison${NC}"

echo "  Step 1/2 — Timing manual enumeration (8 separate scripts) ..."
{ time nmap -sV "$TARGET" \
    && nmap --script ftp-anon -p 21 "$TARGET" \
    && nmap --script ssh2-enum-algos -p 22 "$TARGET" \
    && nmap --script smb-security-mode -p 445 "$TARGET" \
    && nmap --script smb-enum-shares -p 445 "$TARGET" \
    && nmap --script mysql-empty-password -p 3306 "$TARGET" \
    && nmap --script http-headers,http-git -p 80 "$TARGET" \
    && nmap --script dns-recursion -p 53 "$TARGET" ; \
} 2>&1 | tee "$OUTDIR/tc7_manual.txt" | grep "Nmap done\|real"

echo ""
echo "  Step 2/2 — Timing Reko (single command) ..."
{ time nmap -sV \
    -p 21,22,25,53,80,111,139,445,2049,2121,3306,5432,5900,6667,8009,8180 \
    --script reko.nse \
    --script-args reko.aggression=1 \
    "$TARGET" ; \
} 2>&1 | tee "$OUTDIR/tc7_reko.txt" | grep "Nmap done\|real"

echo ""
echo -e "${BLUE}  TC-7 Comparison:${NC}"
echo "  Manual time:"
grep "real" "$OUTDIR/tc7_manual.txt" | tail -1
echo "  Reko time:"
grep "real" "$OUTDIR/tc7_reko.txt" | tail -1
echo ""

# =============================================================================
# FULL PORT SCAN — for complete results
# =============================================================================
echo -e "${YELLOW}[FULL] Full port scan with all active checks (-p-)${NC}"
echo "  NOTE: This scan covers all 65535 ports and takes ~4-5 minutes."
read -p "  Run full port scan? [y/N] " run_full
if [[ "$run_full" =~ ^[Yy]$ ]]; then
    echo "  Running full scan ..."
    time nmap -sV -p- \
        --script reko.nse \
        --script-args reko.aggression=1 \
        "$TARGET" 2>&1 | tee "$OUTDIR/full_scan.txt"
    echo -e "${GREEN}  Full scan saved to $OUTDIR/full_scan.txt${NC}"
fi
echo ""

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "${BLUE}"
echo "============================================================"
echo "  Test Suite Complete"
echo "  Results saved to: $OUTDIR/"
echo ""
echo "  Files generated:"
ls -lh "$OUTDIR/" 2>/dev/null
echo ""
echo "  Quick finding counts (TC-4 active scan):"
echo -n "  CRITICAL: "; grep -c "\[CRITICAL\]" "$OUTDIR/tc4_active.txt" 2>/dev/null || echo 0
echo -n "  HIGH:     "; grep -c "\[HIGH\]"     "$OUTDIR/tc4_active.txt" 2>/dev/null || echo 0
echo -n "  MEDIUM:   "; grep -c "\[MEDIUM\]"   "$OUTDIR/tc4_active.txt" 2>/dev/null || echo 0
echo "============================================================"
echo -e "${NC}"
