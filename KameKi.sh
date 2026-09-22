#!/usr/bin/env bash
#
# va-recon.sh - Authenticated VA recon and inventory collection
#
# Reads from current directory:
#   targets.txt  - one IP or hostname per line
#   user.txt     - single line, DOMAIN\user  or  user
#   pass.txt     - single line, the password
#
# Produces:
#   va-inventory-<date>.md   - consolidated markdown report
#   va-raw-<date>/           - raw tool output for evidence
#
# NOTE: this is an inventory and evidence pack, not a PCI DSS VA report.
#       No CVE mapping or CVSS scoring is performed by this stack.
#
set -uo pipefail

DATE=$(date +%F)
STAMP=$(date +"%Y-%m-%d %H:%M:%S %Z")
RAW="va-raw-${DATE}"
MD="va-inventory-${DATE}.md"

TARGETS="targets.txt"
USERFILE="user.txt"
PASSFILE="pass.txt"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'

info() { echo "${GRN}[+]${RST} $*"; }
warn() { echo "${YEL}[!]${RST} $*"; }
err()  { echo "${RED}[-]${RST} $*"; }

# ---------------------------------------------------------------
# 1. Dependency check
# ---------------------------------------------------------------
info "Checking required tools"

MISSING=0
declare -A INSTALL_HINT=(
  [nmap]="sudo apt install nmap -y"
  [nxc]="pipx install git+https://github.com/Pennyw0rth/NetExec"
  [nuclei]="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [awk]="sudo apt install gawk -y"
  [jq]="sudo apt install jq -y"
)

for tool in nmap nxc nuclei awk jq; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "    %-10s %s\n" "$tool" "ok"
  else
    printf "    %-10s %s\n" "$tool" "MISSING  ->  ${INSTALL_HINT[$tool]}"
    MISSING=1
  fi
done

if [ "$MISSING" -eq 1 ]; then
  err "Install the missing tools above, then re-run."
  exit 1
fi

# ---------------------------------------------------------------
# 2. Input validation
# ---------------------------------------------------------------
for f in "$TARGETS" "$USERFILE" "$PASSFILE"; do
  if [ ! -s "$f" ]; then
    err "Missing or empty: $f (expected in current directory)"
    exit 1
  fi
done

USER=$(head -n1 "$USERFILE" | tr -d '\r\n')
PASS=$(head -n1 "$PASSFILE" | tr -d '\r\n')
TARGET_COUNT=$(grep -cve '^\s*$' "$TARGETS")

if [ -z "$USER" ] || [ -z "$PASS" ]; then
  err "user.txt or pass.txt is empty"
  exit 1
fi

# warn if credential files are world readable
for f in "$USERFILE" "$PASSFILE"; do
  PERM=$(stat -c "%a" "$f")
  if [ "${PERM: -1}" != "0" ] || [ "${PERM: -2:1}" != "0" ]; then
    warn "$f is readable beyond owner (mode $PERM). Run: chmod 600 $f"
  fi
done

mkdir -p "$RAW"

info "Targets: $TARGET_COUNT"
info "User:    $USER"
info "Raw output: $RAW/"
echo

# ---------------------------------------------------------------
# 3. Host discovery
# ---------------------------------------------------------------
info "Stage 1/6  Host discovery"
nmap -sn -PE -PS445,3389,22 -iL "$TARGETS" -oG "$RAW/discovery.gnmap" \
     -oN "$RAW/discovery.txt" >/dev/null 2>&1
awk '/Up$/{print $2}' "$RAW/discovery.gnmap" | sort -u > "$RAW/live.txt"
LIVE_COUNT=$(wc -l < "$RAW/live.txt")
info "    live hosts: $LIVE_COUNT of $TARGET_COUNT"

# hosts that did not respond to discovery
grep -vf "$RAW/live.txt" "$TARGETS" 2>/dev/null | grep -ve '^\s*$' > "$RAW/no-response.txt" || true

# ---------------------------------------------------------------
# 4. Authentication status
# ---------------------------------------------------------------
info "Stage 2/6  SMB authentication check"
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --continue-on-success \
    > "$RAW/auth-status.txt" 2>&1

grep '\[+\]' "$RAW/auth-status.txt" | awk '{print $2}' | sort -u > "$RAW/auth-ok.txt" || true
grep '\[-\]' "$RAW/auth-status.txt" | awk '{print $2}' | sort -u > "$RAW/auth-fail.txt" || true
AUTH_OK=$(wc -l < "$RAW/auth-ok.txt")
AUTH_FAIL=$(wc -l < "$RAW/auth-fail.txt")
info "    authenticated: $AUTH_OK   failed: $AUTH_FAIL"

if [ "$AUTH_OK" -eq 0 ]; then
  warn "No hosts authenticated. Check credential format (DOMAIN\\\\user) and account rights."
fi

# ---------------------------------------------------------------
# 5. Authenticated inventory
# ---------------------------------------------------------------
info "Stage 3/6  Patch level and OS inventory"
nxc smb "$TARGETS" -u "$USER" -p "$PASS" \
    -x 'wmic qfe get HotFixID,InstalledOn /format:csv' \
    > "$RAW/hotfixes.txt" 2>&1

nxc smb "$TARGETS" -u "$USER" -p "$PASS" \
    -x 'wmic os get Caption,BuildNumber,LastBootUpTime /format:csv' \
    > "$RAW/osinfo.txt" 2>&1

info "Stage 4/6  Configuration inventory"
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --pass-pol \
    > "$RAW/password-policy.txt" 2>&1
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --local-groups Administrators \
    > "$RAW/local-admins.txt" 2>&1
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --shares \
    > "$RAW/shares.txt" 2>&1
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --users \
    > "$RAW/domain-users.txt" 2>&1

# ---------------------------------------------------------------
# 6. SMB security posture (unauthenticated)
# ---------------------------------------------------------------
info "Stage 5/6  SMB signing and protocol check"
if [ "$LIVE_COUNT" -gt 0 ]; then
  nmap -Pn -p445 --script smb-protocols,smb-security-mode,smb2-security-mode \
       -iL "$RAW/live.txt" -oN "$RAW/smb-security.txt" >/dev/null 2>&1

  # nxc reports signing cleanly in its banner line
  grep -oP 'signing:\w+' "$RAW/auth-status.txt" | sort | uniq -c \
       > "$RAW/signing-summary.txt" 2>/dev/null || true
fi

# ---------------------------------------------------------------
# 7. Web layer
# ---------------------------------------------------------------
info "Stage 6/6  Web service discovery and nuclei"
if [ "$LIVE_COUNT" -gt 0 ]; then
  nmap -Pn -p80,443,8000,8080,8443,9443 --open -iL "$RAW/live.txt" \
       -oG "$RAW/web.gnmap" >/dev/null 2>&1
  awk '/Ports:/{print $2}' "$RAW/web.gnmap" | sort -u > "$RAW/web-hosts.txt"
  WEB_COUNT=$(wc -l < "$RAW/web-hosts.txt")
  info "    web hosts: $WEB_COUNT"

  if [ "$WEB_COUNT" -gt 0 ]; then
    nuclei -l "$RAW/web-hosts.txt" -severity critical,high,medium \
           -j -o "$RAW/nuclei.json" -rl 50 -c 20 -silent >/dev/null 2>&1 || true
  fi
else
  WEB_COUNT=0
fi

# ---------------------------------------------------------------
# 8. Markdown report
# ---------------------------------------------------------------
info "Building $MD"

NUCLEI_CRIT=0; NUCLEI_HIGH=0; NUCLEI_MED=0
if [ -s "$RAW/nuclei.json" ]; then
  NUCLEI_CRIT=$(jq -r 'select(.info.severity=="critical")' "$RAW/nuclei.json" 2>/dev/null | grep -c '^{' || echo 0)
  NUCLEI_HIGH=$(jq -r 'select(.info.severity=="high")' "$RAW/nuclei.json" 2>/dev/null | grep -c '^{' || echo 0)
  NUCLEI_MED=$(jq -r 'select(.info.severity=="medium")' "$RAW/nuclei.json" 2>/dev/null | grep -c '^{' || echo 0)
fi

{
echo "# Authenticated VA Inventory"
echo
echo "**Generated:** $STAMP  "
echo "**Scan account:** \`$USER\`  "
echo "**Raw evidence:** \`$RAW/\`"
echo
echo "> Scope note: this document is an asset, patch and configuration inventory"
echo "> produced by nmap, NetExec and nuclei. It does not perform CVE mapping or"
echo "> CVSS scoring and is not a PCI DSS vulnerability assessment report."
echo
echo "---"
echo
echo "## Coverage Summary"
echo
echo "| Metric | Count |"
echo "| --- | --- |"
echo "| Targets supplied | $TARGET_COUNT |"
echo "| Responded to discovery | $LIVE_COUNT |"
echo "| No response | $((TARGET_COUNT - LIVE_COUNT)) |"
echo "| SMB authentication succeeded | $AUTH_OK |"
echo "| SMB authentication failed | $AUTH_FAIL |"
echo "| Web services found | $WEB_COUNT |"
echo

# coverage warning
if [ "$LIVE_COUNT" -gt 0 ]; then
  PCT=$(( AUTH_OK * 100 / LIVE_COUNT ))
  echo "**Authenticated coverage: ${PCT}% of live hosts.**"
  echo
  if [ "$PCT" -lt 80 ]; then
    echo "> Coverage below 80%. Findings in this report reflect only the hosts that"
    echo "> authenticated. Hosts under \"Authentication Failed\" have not been assessed"
    echo "> at patch or configuration level and must be resolved before the results"
    echo "> are treated as representative of the estate."
    echo
  fi
fi

echo "---"
echo
echo "## Authentication Failed"
echo
if [ -s "$RAW/auth-fail.txt" ]; then
  echo '```'
  cat "$RAW/auth-fail.txt"
  echo '```'
else
  echo "_None. All reachable hosts authenticated._"
fi
echo

echo "## No Response to Discovery"
echo
if [ -s "$RAW/no-response.txt" ]; then
  echo "These may be decommissioned, powered off, or filtered from the scanner's"
  echo "network position. Confirm with the client before treating them as out of scope."
  echo
  echo '```'
  cat "$RAW/no-response.txt"
  echo '```'
else
  echo "_All targets responded._"
fi
echo

echo "---"
echo
echo "## Operating System Inventory"
echo
echo '```'
grep -E '\[\*\]' "$RAW/auth-status.txt" 2>/dev/null | head -200 || echo "No data"
echo '```'
echo

echo "## SMB Signing and Protocol"
echo
echo "Hosts without required SMB signing are exposed to NTLM relay."
echo
echo '```'
if [ -s "$RAW/signing-summary.txt" ]; then cat "$RAW/signing-summary.txt"; fi
grep -E 'signing:False' "$RAW/auth-status.txt" 2>/dev/null | head -100 || echo "None found"
echo '```'
echo
echo "SMBv1 status:"
echo
echo '```'
grep -A3 'smb-protocols' "$RAW/smb-security.txt" 2>/dev/null | grep -E 'SMBv1|NT LM 0.12' | head -50 || echo "No SMBv1 detected"
echo '```'
echo

echo "## Patch Level"
echo
echo "Full output in \`$RAW/hotfixes.txt\`. Most recent hotfix per host:"
echo
echo '```'
head -150 "$RAW/hotfixes.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "## Password Policy"
echo
echo '```'
head -80 "$RAW/password-policy.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "## Local Administrators"
echo
echo '```'
head -150 "$RAW/local-admins.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "## Shares"
echo
echo '```'
head -150 "$RAW/shares.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "---"
echo
echo "## Web Layer Findings"
echo
echo "| Severity | Count |"
echo "| --- | --- |"
echo "| Critical | $NUCLEI_CRIT |"
echo "| High | $NUCLEI_HIGH |"
echo "| Medium | $NUCLEI_MED |"
echo
if [ -s "$RAW/nuclei.json" ]; then
  echo '```'
  jq -r 'select(.info.severity=="critical" or .info.severity=="high") | "\(.info.severity | ascii_upcase)  \(.host)  \(.info.name)"' \
     "$RAW/nuclei.json" 2>/dev/null | head -60
  echo '```'
else
  echo "_No web findings, or no web services in scope._"
fi
echo

echo "---"
echo
echo "## Files"
echo
echo "| File | Contents |"
echo "| --- | --- |"
echo "| \`$RAW/auth-status.txt\` | Per host authentication result |"
echo "| \`$RAW/auth-ok.txt\` | Hosts that authenticated |"
echo "| \`$RAW/auth-fail.txt\` | Hosts that did not authenticate |"
echo "| \`$RAW/live.txt\` | Hosts responding to discovery |"
echo "| \`$RAW/no-response.txt\` | Targets with no response |"
echo "| \`$RAW/hotfixes.txt\` | Installed hotfixes per host |"
echo "| \`$RAW/osinfo.txt\` | OS caption and build per host |"
echo "| \`$RAW/password-policy.txt\` | Domain or local password policy |"
echo "| \`$RAW/local-admins.txt\` | Local Administrators membership |"
echo "| \`$RAW/shares.txt\` | Accessible shares |"
echo "| \`$RAW/smb-security.txt\` | nmap SMB protocol and signing |"
echo "| \`$RAW/nuclei.json\` | Web findings, JSON |"
echo
echo "## Next Steps"
echo
echo "1. Resolve every host under Authentication Failed before treating coverage as complete."
echo "2. Confirm with the client that no-response hosts are genuinely out of service."
echo "3. Map build numbers and hotfix levels against vendor advisories, or run a"
echo "   CVE-aware scanner, to convert this inventory into assessed findings."
echo
} > "$MD"

echo
info "Done"
echo "    Report: $MD"
echo "    Raw:    $RAW/"
echo
echo "    Live $LIVE_COUNT/$TARGET_COUNT   Auth OK $AUTH_OK   Auth FAIL $AUTH_FAIL"
