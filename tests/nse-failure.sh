#!/usr/bin/env bash
#
#  Stage 3B failure-reporting regression test
#
#  Slices the real Stage 3B out of kameki.sh and drives it against a stubbed
#  nmap. No network, no root, no nmap needed.
#
#    ./tests/nse-failure.sh
#
#  What it guards against, which happened on a live PCI engagement:
#
#    nmap segfaulted on all 39 hosts with open ports. Its exit status was
#    discarded, so the stage printed
#
#      [+] NSE vulnerable states 0   service CVEs 0
#
#    and the report rendered "No NSE script reported a vulnerable state."
#    A tool that crashed 39 times was presented as a finding of absence.
#
#    Worse, the stage was still marked done, so RESUME=1 would skip it and
#    keep the empty output -- a crash turned into a permanent clean result.
#
#    The same estate had already produced a finding of this exact shape once:
#    a filtering device voided a port scan and the dropped packets read as
#    clean. Zero must never be printed as a result when nothing was assessed.
#
set -uo pipefail
SRC="${1:-}"
if [ -z "$SRC" ]; then
  for _c in "$(dirname "$0")/../kameki.sh" "$(dirname "$0")/../KameKi.sh"; do
    [ -f "$_c" ] && { SRC="$_c"; break; }
  done
fi
[ -f "$SRC" ] || { echo "cannot find kameki.sh" >&2; exit 2; }

PASS=0; FAIL=0
check(){ if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        got  %s\n        want %s\n' "$1" "$2" "$3"; fi; }

build(){ # $1 scenario, $2 workdir
  local sc="$1" w="$2" s e
  s=$(grep -n '^if \[ "\$RUN_SA" -eq 1 \]; then' "$SRC" | head -1 | cut -d: -f1)
  e=$(grep -n '#  Stage 4  Authentication' "$SRC" | head -1 | cut -d: -f1)
  [ -n "$s" ] && [ -n "$e" ] || { echo "cannot locate Stage 3B in $SRC" >&2; exit 2; }
  mkdir -p "$w/bin" "$w/raw/nse" "$w/raw/ports"
  {
    cat <<'P'
set -uo pipefail
step(){ printf '\n== %s\n' "$*"; }
info(){ printf '  [+] %s\n' "$*"; }
warn(){ printf '  [!] %s\n' "$*"; }
err(){  printf '  [x] %s\n' "$*"; }
dim(){  printf '      %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
cnt(){ [ -f "$1" ] || { echo 0; return 0; }
       local n; n=$(grep -c . "$1" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
gcntiE(){ local n; n=$(grep -ciE "$1" "$2" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
gcnt(){ local n; n=$(grep -c "$1" "$2" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
pool(){ "$@"; }
finish(){ :; }
is_done(){ [ "${RESUME:-0}" = "1" ] && [ -f "$RAW/.done-$1" ]; }
mark_done(){ touch "$RAW/.done-$1"; }
RUN_SA=1; JOBS=4; HOST_TIMEOUT=5m; MIN_CVSS=0
NSE_SET="vuln,safe"; SVC_CVE="${SVC_CVE:-vulners}"; HAVE_SPLOIT=0
P
    printf 'RAW=%q\nHOSTS_OPEN=3\n' "$w/raw"
    sed -n "${s},$((e-3))p" "$SRC"
    cat <<'T'
printf 'RETURNED hits=%s cves=%s scanned=%s failed=%s degraded=%s done=%s\n' \
  "$NSE_HITS" "$SVC_CVES" "$NSE_SCANNED" "$NSE_FAILED" "$NSE_DEGRADED" \
  "$([ -f "$RAW/.done-nse" ] && echo yes || echo no)"
T
  } > "$w/run.sh"

  # A stubbed nmap. SCENARIO decides how it behaves.
  cat > "$w/bin/nmap" <<'NMAP'
#!/usr/bin/env bash
out=""; scripts=""
while [ $# -gt 0 ]; do
  case "$1" in -oN) out="$2"; shift ;; --script) scripts="$2"; shift ;; esac
  shift
done
case "$SCENARIO" in
  allcrash)
    # Segmentation fault, every time, whatever the script set.
    exit 139 ;;
  cvecrash)
    # Crashes only with the service-CVE script, which is the real pattern.
    case "$scripts" in
      *vulners*|*vulscan*) exit 139 ;;
      *) printf 'Nmap scan report\n|_smb-vuln-ms17-010: VULNERABLE\n' > "$out"; exit 0 ;;
    esac ;;
  clean)
    printf 'Nmap scan report\n|_ssl-poodle: VULNERABLE\nCVE-2014-3566\n' > "$out"
    exit 0 ;;
  empty)
    # Exits 0 but writes nothing, which also means nothing was assessed.
    exit 0 ;;
esac
exit 0
NMAP
  chmod +x "$w/bin/nmap"
  printf '10.0.0.1 445,139\n10.0.0.2 443\n10.0.0.3 3389\n' > "$w/raw/ports/map.txt"
}

run(){ # $1 scenario [$2 extra env] -> the RETURNED line, plus the transcript
  local w; w=$(mktemp -d)
  build "$1" "$w"
  local out
  # env, not a bare assignment prefix: the value has to survive into run.sh,
  # whose prelude reads SVC_CVE from the environment.
  out=$(cd "$w" && env PATH="$w/bin:$PATH" SCENARIO="$1" ${2:+"$2"} bash run.sh 2>&1)
  printf '%s\n' "$out" > "$OUTFILE"
  printf '%s' "$(printf '%s' "$out" | sed -n 's/^RETURNED //p' | head -1)"
  rm -rf "$w"
}

OUTFILE=$(mktemp)
trap 'rm -f "$OUTFILE"' EXIT
saw(){ grep -qF -- "$1" "$OUTFILE"; }
checkout(){ if saw "$2"; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s  (not in the transcript)\n' "$1"
       tail -14 "$OUTFILE" | sed 's/^/        | /'; fi; }
checknot(){ if saw "$2"; then FAIL=$((FAIL+1)); printf '  FAIL  %s  (appeared)\n' "$1"
       tail -14 "$OUTFILE" | sed 's/^/        | /'
  else PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; fi; }

echo "Stage 3B failure reporting, file under test: $SRC"

echo
echo "a scan that works"
check "three hosts scanned, a finding, no failures" "$(run clean)" \
      "hits=3 cves=1 scanned=3 failed=0 degraded=0 done=yes"

echo
echo "nmap segfaults on every host"
R=$(run allcrash)
check "zero findings, zero scanned, three failures" "$R" \
      "hits=0 cves=0 scanned=0 failed=3 degraded=0 done=no"
checkout "the zeros are explicitly disclaimed" "The zeros above are not a"
checkout "and the segfault is named"           "segmentation fault"
checkout "with the remedy"                     "SVC_CVE_ENGINE=none"
# The whole point. Without this the report says "no vulnerable state found".
checknot "it does NOT claim an absence of findings" "No NSE script reported"

echo
echo "and the stage is NOT marked done, so a re-run tries again"
checkout "says why it is not marking it done" "not marking the stage done"

echo
echo "nmap crashes only with the service-CVE script"
R=$(run cvecrash)
check "recovered without it: findings present, coverage degraded" "$R" \
      "hits=3 cves=0 scanned=3 failed=3 degraded=3 done=yes"
checkout "the degradation is reported" "recovered without the service-CVE script"
checkout "and what was lost is named"  "no CVE mapping"

echo
echo "nmap exits 0 but writes nothing"
R=$(run empty)
check "treated as a failure, not as a clean host" "$R" \
      "hits=0 cves=0 scanned=0 failed=3 degraded=0 done=no"

echo
echo "the service-CVE script can be turned off"
R=$(run clean "SVC_CVE=none")
check "still scans, still finds, no CVE script" "$R" \
      "hits=3 cves=1 scanned=3 failed=0 degraded=0 done=yes"
checkout "and says so" "service-CVE mapping disabled"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
