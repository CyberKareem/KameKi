#!/usr/bin/env bash
#
# kameki.sh - Authenticated VA with CVE mapping
#
# Reads from the current directory:
#   targets.txt  - one IP or hostname per line
#   user.txt     - one or more accounts, DOMAIN\user or user@domain
#   pass.txt     - one or more passwords
#
# Produces:
#   kameki-<date>.md     - consolidated report
#   kameki-raw-<date>/   - raw tool output for evidence
#
# CVE coverage:
#   Windows patch level  - WES-NG against MSRC data (authenticated)
#   Network services     - nmap vulners or vulscan against service versions
#   Web applications     - nuclei templates
#
# Known limitation: WES-NG reports missing patches based on installed hotfix
# list and does not fully model update supersedence. Expect false positives,
# particularly on fully patched Server 2022 hosts. Validate before reporting.
#
set -uo pipefail

DATE=$(date +%F)
STAMP=$(date +"%Y-%m-%d %H:%M:%S %Z")
RAW="kameki-raw-${DATE}"
MD="kameki-${DATE}.md"

TARGETS="targets.txt"
USERFILE="user.txt"
PASSFILE="pass.txt"

MIN_CVSS="${MIN_CVSS:-5.0}"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'
info() { echo "${GRN}[+]${RST} $*"; }
warn() { echo "${YEL}[!]${RST} $*"; }
err()  { echo "${RED}[-]${RST} $*"; }

# ---------------------------------------------------------------
# 1. Dependency check
# ---------------------------------------------------------------
info "Checking required tools"

MISSING=0
declare -A HINT=(
  [nmap]="sudo apt install nmap -y"
  [nxc]="pipx install git+https://github.com/Pennyw0rth/NetExec"
  [nuclei]="download the binary from github.com/projectdiscovery/nuclei/releases"
  [awk]="sudo apt install gawk -y"
  [jq]="sudo apt install jq -y"
)

for tool in nmap nxc nuclei awk jq; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "    %-10s %s\n" "$tool" "ok"
  else
    printf "    %-10s %s\n" "$tool" "MISSING  ->  ${HINT[$tool]}"
    MISSING=1
  fi
done

# WES-NG ships as either "wes" or "wes.py" depending on how it was installed
WES=""
for candidate in wes wes.py; do
  if command -v "$candidate" >/dev/null 2>&1; then
    WES="$candidate"
    break
  fi
done
if [ -n "$WES" ]; then
  printf "    %-10s %s\n" "wes" "ok ($WES)"
else
  printf "    %-10s %s\n" "wes" "MISSING  ->  pipx install wesng   (then: wes --update)"
  MISSING=1
fi

# CVE engine for network services: vulners needs internet, vulscan is offline
NSE_DIR=$(nmap --datadir 2>/dev/null; echo "/usr/share/nmap/scripts")
SERVICE_CVE_ENGINE="none"
if [ -f /usr/share/nmap/scripts/vulners.nse ] || [ -f "$HOME/.nmap/scripts/vulners.nse" ]; then
  SERVICE_CVE_ENGINE="vulners"
elif [ -d /usr/share/nmap/scripts/vulscan ]; then
  SERVICE_CVE_ENGINE="vulscan"
fi
printf "    %-10s %s\n" "svc-cve" "$SERVICE_CVE_ENGINE"

if [ "$SERVICE_CVE_ENGINE" = "none" ]; then
  warn "No service CVE engine found. Install one of:"
  echo "        vulners (needs internet at scan time):"
  echo "          sudo wget -O /usr/share/nmap/scripts/vulners.nse \\"
  echo "            https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"
  echo "          sudo nmap --script-updatedb"
  echo "        vulscan (offline CVE database):"
  echo "          sudo git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan"
  echo "          sudo nmap --script-updatedb"
  MISSING=1
fi

if [ "$MISSING" -eq 1 ]; then
  err "Install the missing components above, then re-run."
  exit 1
fi

# ---------------------------------------------------------------
# 2. Input validation
# ---------------------------------------------------------------
for f in "$TARGETS" "$USERFILE" "$PASSFILE"; do
  [ -s "$f" ] || { err "Missing or empty: $f (expected in current directory)"; exit 1; }
done

USER_COUNT=$(grep -cve '^\s*$' "$USERFILE")
PASS_COUNT=$(grep -cve '^\s*$' "$PASSFILE")
TARGET_COUNT=$(grep -cve '^\s*$' "$TARGETS")

if [ "$USER_COUNT" -eq 1 ] && [ "$PASS_COUNT" -eq 1 ]; then
  USER=$(head -n1 "$USERFILE" | tr -d '\r\n')
  PASS=$(head -n1 "$PASSFILE" | tr -d '\r\n')
  CRED_LABEL="$USER"
  MULTI=0
else
  USER="$USERFILE"
  PASS="$PASSFILE"
  CRED_LABEL="$USER_COUNT user(s) x $PASS_COUNT password(s)"
  MULTI=1
  COMBOS=$(( USER_COUNT * PASS_COUNT ))
  echo
  warn "Multi-credential mode: $COMBOS combinations per host, $(( COMBOS * TARGET_COUNT )) attempts total."
  warn "This is a password spray. It can lock out accounts and will trigger SOC alerts."
  read -rp "    Type YES to continue: " CONFIRM
  [ "$CONFIRM" = "YES" ] || { err "Aborted."; exit 1; }
  echo
fi

for f in "$USERFILE" "$PASSFILE"; do
  PERM=$(stat -c "%a" "$f")
  [ "$PERM" = "600" ] || warn "$f is mode $PERM. Run: chmod 600 $f"
done

mkdir -p "$RAW" "$RAW/systeminfo" "$RAW/wes"

info "Targets: $TARGET_COUNT"
info "Creds:   $CRED_LABEL"
info "Output:  $RAW/"
echo

# ---------------------------------------------------------------
# 3. Host discovery
# ---------------------------------------------------------------
info "Stage 1/8  Host discovery"
nmap -sn -PE -PS445,3389,22 -iL "$TARGETS" -oG "$RAW/discovery.gnmap" \
     -oN "$RAW/discovery.txt" >/dev/null 2>&1
awk '/Up$/{print $2}' "$RAW/discovery.gnmap" | sort -u > "$RAW/live.txt"
LIVE_COUNT=$(wc -l < "$RAW/live.txt")
grep -vxFf "$RAW/live.txt" "$TARGETS" 2>/dev/null | grep -ve '^\s*$' > "$RAW/no-response.txt" || true
info "    live: $LIVE_COUNT of $TARGET_COUNT"

# ---------------------------------------------------------------
# 4. Authentication check
# ---------------------------------------------------------------
info "Stage 2/8  SMB authentication"
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --continue-on-success \
    > "$RAW/auth-status.txt" 2>&1

grep '\[+\]' "$RAW/auth-status.txt" | awk '{print $2}' | sort -u > "$RAW/auth-ok.txt" || true
grep '\[-\]' "$RAW/auth-status.txt" | awk '{print $2}' | sort -u > "$RAW/auth-fail-raw.txt" || true
if [ -s "$RAW/auth-ok.txt" ]; then
  grep -vxFf "$RAW/auth-ok.txt" "$RAW/auth-fail-raw.txt" > "$RAW/auth-fail.txt" 2>/dev/null || : > "$RAW/auth-fail.txt"
else
  cp "$RAW/auth-fail-raw.txt" "$RAW/auth-fail.txt" 2>/dev/null || : > "$RAW/auth-fail.txt"
fi
grep '\[+\]' "$RAW/auth-status.txt" | sed -E 's/.*\[\+\][[:space:]]*//' | sort -u > "$RAW/working-creds.txt" || true

AUTH_OK=$(wc -l < "$RAW/auth-ok.txt")
AUTH_FAIL=$(wc -l < "$RAW/auth-fail.txt")
info "    authenticated: $AUTH_OK   failed: $AUTH_FAIL"

if [ "$AUTH_OK" -eq 0 ]; then
  warn "No hosts authenticated. Windows CVE mapping will be skipped."
  warn "Check credential format (DOMAIN\\\\user vs user@domain) and account rights."
fi

# ---------------------------------------------------------------
# 5. Collect systeminfo per host for CVE mapping
# ---------------------------------------------------------------
info "Stage 3/8  Collecting systeminfo from authenticated hosts"
SYSINFO_OK=0
if [ -s "$RAW/auth-ok.txt" ]; then
  while read -r host; do
    [ -z "$host" ] && continue
    out="$RAW/systeminfo/${host}.txt"
    nxc smb "$host" -u "$USER" -p "$PASS" -x 'systeminfo' 2>/dev/null \
      | sed -E 's/^SMB[[:space:]]+\S+[[:space:]]+[0-9]+[[:space:]]+\S+[[:space:]]+//' \
      | grep -v '^\[' > "$out"
    if grep -qi 'OS Name' "$out" 2>/dev/null; then
      SYSINFO_OK=$((SYSINFO_OK+1))
      printf "    %-18s collected\n" "$host"
    else
      rm -f "$out"
      printf "    %-18s no systeminfo (cmd exec blocked?)\n" "$host"
    fi
  done < "$RAW/auth-ok.txt"
fi
info "    systeminfo collected: $SYSINFO_OK"

# ---------------------------------------------------------------
# 6. Windows patch-level CVE mapping via WES-NG
# ---------------------------------------------------------------
info "Stage 4/8  Windows CVE mapping (WES-NG)"
WIN_CVE_TOTAL=0
WIN_CVE_CRIT=0
: > "$RAW/windows-cves.csv"

if [ "$SYSINFO_OK" -gt 0 ]; then
  if [ ! -f definitions.zip ] && [ ! -f "$HOME/definitions.zip" ]; then
    warn "WES-NG definitions not found. Fetching (needs internet)."
    "$WES" --update >/dev/null 2>&1 || warn "    definition update failed, results may be stale"
  fi

  echo "Host,CVE,Severity,AffectedProduct,MissingKB,Title" > "$RAW/windows-cves.csv"
  for f in "$RAW"/systeminfo/*.txt; do
    [ -e "$f" ] || continue
    h=$(basename "$f" .txt)
    "$WES" "$f" -o "$RAW/wes/${h}.csv" >/dev/null 2>&1 || continue
    if [ -s "$RAW/wes/${h}.csv" ]; then
      tail -n +2 "$RAW/wes/${h}.csv" | awk -F',' -v H="$h" \
        '{print H","$3","$7","$2","$8","$4}' >> "$RAW/windows-cves.csv" 2>/dev/null || true
    fi
  done

  WIN_CVE_TOTAL=$(( $(wc -l < "$RAW/windows-cves.csv") - 1 ))
  [ "$WIN_CVE_TOTAL" -lt 0 ] && WIN_CVE_TOTAL=0
  WIN_CVE_CRIT=$(grep -ci 'critical' "$RAW/windows-cves.csv" 2>/dev/null || echo 0)
  info "    Windows CVEs: $WIN_CVE_TOTAL   critical: $WIN_CVE_CRIT"
else
  warn "    skipped, no systeminfo output available"
fi

# ---------------------------------------------------------------
# 7. Network service CVE mapping
# ---------------------------------------------------------------
info "Stage 5/8  Service version scan and CVE mapping ($SERVICE_CVE_ENGINE)"
SVC_CVE_COUNT=0
if [ "$LIVE_COUNT" -gt 0 ]; then
  if [ "$SERVICE_CVE_ENGINE" = "vulners" ]; then
    nmap -sV -Pn --script vulners --script-args "mincvss=$MIN_CVSS" \
         -iL "$RAW/live.txt" -oN "$RAW/service-cves.txt" >/dev/null 2>&1
  else
    nmap -sV -Pn --script vulscan/vulscan.nse --script-args vulscandb=cve.csv \
         -iL "$RAW/live.txt" -oN "$RAW/service-cves.txt" >/dev/null 2>&1
  fi
  grep -oE 'CVE-[0-9]{4}-[0-9]+' "$RAW/service-cves.txt" 2>/dev/null | sort -u > "$RAW/service-cve-list.txt" || true
  SVC_CVE_COUNT=$(wc -l < "$RAW/service-cve-list.txt" 2>/dev/null || echo 0)
  info "    unique service CVEs: $SVC_CVE_COUNT"
fi

# ---------------------------------------------------------------
# 8. Configuration inventory
# ---------------------------------------------------------------
info "Stage 6/8  Configuration inventory"
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --pass-pol > "$RAW/password-policy.txt" 2>&1
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --local-groups Administrators > "$RAW/local-admins.txt" 2>&1
nxc smb "$TARGETS" -u "$USER" -p "$PASS" --shares > "$RAW/shares.txt" 2>&1

# ---------------------------------------------------------------
# 9. SMB security posture
# ---------------------------------------------------------------
info "Stage 7/8  SMB signing and protocol"
if [ "$LIVE_COUNT" -gt 0 ]; then
  nmap -Pn -p445 --script smb-protocols,smb-security-mode,smb2-security-mode \
       -iL "$RAW/live.txt" -oN "$RAW/smb-security.txt" >/dev/null 2>&1
fi
grep -oP 'signing:\w+' "$RAW/auth-status.txt" 2>/dev/null | sort | uniq -c > "$RAW/signing-summary.txt" || true
NO_SIGNING=$(grep -c 'signing:False' "$RAW/auth-status.txt" 2>/dev/null || echo 0)

# ---------------------------------------------------------------
# 10. Web layer
# ---------------------------------------------------------------
info "Stage 8/8  Web discovery and nuclei"
WEB_COUNT=0
NUC_CRIT=0; NUC_HIGH=0; NUC_MED=0
if [ "$LIVE_COUNT" -gt 0 ]; then
  nmap -Pn -p80,443,8000,8080,8443,9443 --open -iL "$RAW/live.txt" \
       -oG "$RAW/web.gnmap" >/dev/null 2>&1
  awk '/Ports:/{print $2}' "$RAW/web.gnmap" | sort -u > "$RAW/web-hosts.txt"
  WEB_COUNT=$(wc -l < "$RAW/web-hosts.txt")
  info "    web hosts: $WEB_COUNT"
  if [ "$WEB_COUNT" -gt 0 ]; then
    nuclei -l "$RAW/web-hosts.txt" -severity critical,high,medium \
           -j -o "$RAW/nuclei.json" -rl 50 -c 20 -silent >/dev/null 2>&1 || true
    if [ -s "$RAW/nuclei.json" ]; then
      NUC_CRIT=$(jq -r 'select(.info.severity=="critical")|.host' "$RAW/nuclei.json" 2>/dev/null | wc -l)
      NUC_HIGH=$(jq -r 'select(.info.severity=="high")|.host' "$RAW/nuclei.json" 2>/dev/null | wc -l)
      NUC_MED=$(jq -r 'select(.info.severity=="medium")|.host' "$RAW/nuclei.json" 2>/dev/null | wc -l)
      jq -r '.info.reference[]? | select(test("CVE-"))' "$RAW/nuclei.json" 2>/dev/null \
        | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u > "$RAW/web-cve-list.txt" || true
    fi
  fi
fi

# ---------------------------------------------------------------
# 11. Report
# ---------------------------------------------------------------
info "Building $MD"

TOTAL_CVES=$(( WIN_CVE_TOTAL + SVC_CVE_COUNT ))
WEB_CVE_COUNT=$(wc -l < "$RAW/web-cve-list.txt" 2>/dev/null || echo 0)

{
echo "# Authenticated Vulnerability Assessment"
echo
echo "**Generated:** $STAMP  "
echo "**Credentials:** $CRED_LABEL  "
echo "**Raw evidence:** \`$RAW/\`"
echo
echo "---"
echo
echo "## Coverage"
echo
echo "| Metric | Count |"
echo "| --- | --- |"
echo "| Targets supplied | $TARGET_COUNT |"
echo "| Responded to discovery | $LIVE_COUNT |"
echo "| SMB authentication succeeded | $AUTH_OK |"
echo "| SMB authentication failed | $AUTH_FAIL |"
echo "| systeminfo collected | $SYSINFO_OK |"
echo "| Web services found | $WEB_COUNT |"
echo

if [ "$LIVE_COUNT" -gt 0 ]; then
  PCT=$(( AUTH_OK * 100 / LIVE_COUNT ))
  SPCT=$(( SYSINFO_OK * 100 / LIVE_COUNT ))
  echo "**Authenticated coverage: ${PCT}% of live hosts. Patch-level data: ${SPCT}%.**"
  echo
  if [ "$SPCT" -lt 80 ]; then
    echo "> Patch-level coverage is below 80%. Windows CVE results below reflect only"
    echo "> the $SYSINFO_OK host(s) where systeminfo was collected. The remaining hosts"
    echo "> have not been assessed at patch level and must be resolved before these"
    echo "> results are treated as representative of the estate."
    echo
  fi
fi

echo "---"
echo
echo "## CVE Summary"
echo
echo "| Source | Method | CVEs |"
echo "| --- | --- | --- |"
echo "| Windows patch level | WES-NG against MSRC data | $WIN_CVE_TOTAL |"
echo "| Network services | nmap $SERVICE_CVE_ENGINE, min CVSS $MIN_CVSS | $SVC_CVE_COUNT |"
echo "| Web applications | nuclei templates | $WEB_CVE_COUNT |"
echo "| **Total** | | **$(( TOTAL_CVES + WEB_CVE_COUNT ))** |"
echo
echo "> Validation note: WES-NG infers missing patches from the installed hotfix"
echo "> list and does not fully model cumulative update supersedence. Fully patched"
echo "> hosts can still be reported as vulnerable. Verify each finding against the"
echo "> host's build and UBR before it goes into a client report."
echo

echo "---"
echo
echo "## Windows Patch-Level CVEs"
echo
if [ "$WIN_CVE_TOTAL" -gt 0 ]; then
  echo "Critical severity, first 60 rows. Full set in \`$RAW/windows-cves.csv\`."
  echo
  echo '```'
  head -1 "$RAW/windows-cves.csv"
  grep -i 'critical' "$RAW/windows-cves.csv" | head -60
  echo '```'
  echo
  echo "Most affected hosts:"
  echo
  echo '```'
  tail -n +2 "$RAW/windows-cves.csv" | cut -d',' -f1 | sort | uniq -c | sort -rn | head -20
  echo '```'
else
  echo "_No data. Either no hosts authenticated, or systeminfo execution was blocked._"
fi
echo

echo "## Network Service CVEs"
echo
if [ "$SVC_CVE_COUNT" -gt 0 ]; then
  echo '```'
  grep -B3 'CVE-' "$RAW/service-cves.txt" 2>/dev/null | head -80
  echo '```'
else
  echo "_No service-level CVEs above CVSS $MIN_CVSS._"
fi
echo

echo "## Web Application Findings"
echo
echo "| Severity | Count |"
echo "| --- | --- |"
echo "| Critical | $NUC_CRIT |"
echo "| High | $NUC_HIGH |"
echo "| Medium | $NUC_MED |"
echo
if [ -s "$RAW/nuclei.json" ]; then
  echo '```'
  jq -r 'select(.info.severity=="critical" or .info.severity=="high")
         | "\(.info.severity|ascii_upcase)  \(.host)  \(.info.name)"' \
     "$RAW/nuclei.json" 2>/dev/null | head -60
  echo '```'
else
  echo "_No web findings, or no web services in scope._"
fi
echo

echo "---"
echo
echo "## SMB Signing"
echo
echo "Hosts without required SMB signing are exposed to NTLM relay: **$NO_SIGNING**"
echo
echo '```'
grep 'signing:False' "$RAW/auth-status.txt" 2>/dev/null | awk '{print $2, $4}' | sort -u | head -60 || echo "None"
echo '```'
echo

echo "## Authentication Failed"
echo
if [ -s "$RAW/auth-fail.txt" ]; then
  echo "These hosts have no patch-level assessment."
  echo
  echo '```'
  cat "$RAW/auth-fail.txt"
  echo '```'
else
  echo "_All reachable hosts authenticated._"
fi
echo

echo "## No Response to Discovery"
echo
if [ -s "$RAW/no-response.txt" ]; then
  echo '```'
  cat "$RAW/no-response.txt"
  echo '```'
else
  echo "_All targets responded._"
fi
echo

if [ "$MULTI" -eq 1 ] && [ -s "$RAW/working-creds.txt" ]; then
  echo "## Successful Credential Pairs"
  echo
  echo '```'
  head -100 "$RAW/working-creds.txt"
  echo '```'
  echo
fi

echo "## Password Policy"
echo
echo '```'
head -60 "$RAW/password-policy.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "## Local Administrators"
echo
echo '```'
head -100 "$RAW/local-admins.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "## Shares"
echo
echo '```'
head -100 "$RAW/shares.txt" 2>/dev/null || echo "No data"
echo '```'
echo

echo "---"
echo
echo "## Evidence Files"
echo
echo "| File | Contents |"
echo "| --- | --- |"
echo "| \`$RAW/windows-cves.csv\` | Windows CVEs per host, WES-NG |"
echo "| \`$RAW/wes/\` | Per host WES-NG output |"
echo "| \`$RAW/systeminfo/\` | Raw systeminfo per host |"
echo "| \`$RAW/service-cves.txt\` | nmap service CVE output |"
echo "| \`$RAW/nuclei.json\` | Web findings, JSON |"
echo "| \`$RAW/auth-status.txt\` | Per host authentication result |"
echo "| \`$RAW/auth-fail.txt\` | Hosts that did not authenticate |"
echo "| \`$RAW/no-response.txt\` | Targets with no response |"
echo "| \`$RAW/smb-security.txt\` | SMB protocol and signing |"
echo "| \`$RAW/password-policy.txt\` | Password policy |"
echo "| \`$RAW/local-admins.txt\` | Local Administrators membership |"
echo "| \`$RAW/shares.txt\` | Accessible shares |"
echo
echo "## Next Steps"
echo
echo "1. Validate Windows CVEs against host build and UBR before reporting."
echo "2. Resolve authentication failures, those hosts are unassessed."
echo "3. Confirm no-response hosts are genuinely out of service."
echo
} > "$MD"

echo
info "Done"
echo "    Report: $MD"
echo "    Raw:    $RAW/"
echo
echo "    Live $LIVE_COUNT/$TARGET_COUNT   Auth $AUTH_OK   Patch data $SYSINFO_OK"
echo "    CVEs: windows $WIN_CVE_TOTAL   service $SVC_CVE_COUNT   web $WEB_CVE_COUNT"
