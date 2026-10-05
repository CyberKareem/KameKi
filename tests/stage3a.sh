#!/usr/bin/env bash
#
#  Stage 3A regression test
#
#  Slices the real Stage 3A out of kameki.sh and runs it against a stubbed
#  kameki_gmp.py, so each way the stage can abandon is exercised as written
#  rather than as retyped here. It needs no Greenbone, no root and no network.
#
#    ./tests/stage3a.sh            # tests ../kameki.sh
#    ./tests/stage3a.sh path.sh    # tests a specific file
#
#  What it guards against, all of which shipped at least once:
#
#    A failed create_task left REPORT unassigned. The next line read it,
#    and under set -u that killed the whole run, so Stage 3B through 10
#    and the final report never happened because Greenbone declined once.
#
#    The CSV export was not guarded, so a stage that had already given up
#    still asked gvmd for a report id it had never been issued, and
#    counted whatever came back as findings.
#
#    The GMP password was passed to gvm-cli as --gmp-password, which put the
#    client's domain credential in this process's argv where `ps` showed it
#    to every other user on the box. The stub records its own argv and the
#    test fails if a secret appears there.
#
#    The scan credential was written to disk for the helper to read. The
#    test fails if that file still exists when the stage is done.
#
set -uo pipefail
# The script has been both KameKi.sh and kameki.sh. Resolve whichever is
# present, because a case-insensitive filesystem hides a wrong name and a
# case-sensitive one fails on it.
SRC="${1:-}"
if [ -z "$SRC" ]; then
  for _c in "$(dirname "$0")/../kameki.sh" "$(dirname "$0")/../KameKi.sh"; do
    [ -f "$_c" ] && { SRC="$_c"; break; }
  done
fi
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

SECRET='Sup3r-Secret-Dom@inPass'

build(){ # $1 scenario, $2 workdir -> writes $2/run.sh
  local sc="$1" w="$2" s e
  s=$(grep -n '#  Stage 3A' "$SRC" | head -1 | cut -d: -f1)
  e=$(grep -n '#  Stage 3B' "$SRC" | head -1 | cut -d: -f1)
  [ -n "$s" ] && [ -n "$e" ] || { echo "cannot locate Stage 3A in $SRC" >&2; exit 2; }

  # The real jgmp, lifted from the file under test rather than retyped.
  local jgmp_src; jgmp_src=$(grep -n '^jgmp(){' "$SRC" | head -1 | cut -d: -f1)
  [ -n "$jgmp_src" ] || { echo "cannot find jgmp in $SRC" >&2; exit 2; }

  {
    cat <<'PRELUDE'
set -uo pipefail
step(){ printf '\n== %s\n' "$*"; }
info(){ printf '  [+] %s\n' "$*"; }
warn(){ printf '  [!] %s\n' "$*"; }
err(){  printf '  [x] %s\n' "$*"; }
dim(){  printf '      %s\n' "$*"; }
cnt(){ [ -f "$1" ] || { echo 0; return 0; }
       local n; n=$(grep -c . "$1" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
sleep(){ :; }
PRELUDE
    sed -n "${jgmp_src}p" "$SRC"
    printf 'SCENARIO=%q\nRAW=%q\nSECRET=%q\n' "$sc" "$w/raw" "$SECRET"
    cat <<'STUB'
CSVB64=$(printf '%s\n%s\n%s\n' \
  'IP,Hostname,Port,Port Protocol,CVSS,Severity,Solution Type,NVT Name' \
  '"10.0.0.1","h1","445","tcp","7.5","High","VendorFix","SMB flaw CVE-2020-0796"' \
  '"10.0.0.2","h2","22","tcp","5.0","Medium","VendorFix","SSH weak cipher"' | base64 | tr -d '\n')

# Stands in for kameki_gmp.py. Records every argument it was handed, and the
# contents of whatever credential files it was pointed at, so the test can
# assert the secret travelled by path and not by argv.
gmp_py(){
  local sock="$1"; shift
  printf '%s\n' "$*" >> "$RAW/helper-argv.txt"
  local uf="" pf="" lf="" sf="" i=1
  # Pull the file paths back out of the arguments the stage built.
  local -a A=("$@")
  while [ "$i" -le "${#A[@]}" ]; do
    case "${A[$((i-1))]}" in
      --smb-login-file) lf="${A[$i]}" ;;
      --smb-pass-file)  sf="${A[$i]}" ;;
    esac
    i=$((i+1))
  done
  [ -n "$sf" ] && [ -f "$sf" ] && cat "$sf" >> "$RAW/helper-saw-pass.txt"
  [ -n "$lf" ] && [ -f "$lf" ] && printf '%s\n' "$sf" > "$RAW/helper-pass-path.txt"

  case "$1" in
    scan) ;;
    *)    echo '{"ok":true}'; return 0 ;;
  esac

  case "$SCENARIO" in
    nolib)
      echo '{"ok":false,"error":"python-gvm is not installed for any python on this box","hint":"sudo pip3 install --break-system-packages python-gvm"}'
      return 3 ;;
    authfail)
      echo '{"ok":false,"error":"GMP authentication failed: Authentication failed"}'
      return 1 ;;
    taskfail)
      echo '{"ok":false,"error":"gvmd refused the task"}'
      return 1 ;;
    startfail)
      echo '{"ok":false,"error":"the task was created but would not start","task":"cccc"}'
      return 1 ;;
    missingcfg)
      echo '{"ok":false,"error":"scan config '"'"'Full and fast'"'"' is not present on this gvmd","available":["Base","Discovery","Host Discovery"],"hint":"sync the GVMD data feed, then re-run: sudo greenbone-feed-sync --type gvmd-data && sudo systemctl restart gvmd"}'
      return 1 ;;
    nostatus)
      echo '{"ok":false,"error":"gvmd returned no status for this task","hint":"the task may have been removed, or gvmd restarted mid-scan. check: journalctl -u gvmd --since '"'"'1 hour ago'"'"'"}'
      return 1 ;;
  esac

  # happy and partial both produce a report.
  local st=Done
  [ "$SCENARIO" = partial ] && st=Stopped
  local csv="" xml="" ids=""
  i=1
  while [ "$i" -le "${#A[@]}" ]; do
    case "${A[$((i-1))]}" in
      --csv-out) csv="${A[$i]}" ;;
      --xml-out) xml="${A[$i]}" ;;
      --ids-out) ids="${A[$i]}" ;;
    esac
    i=$((i+1))
  done
  [ -n "$csv" ] && printf '%s' "$CSVB64" | base64 -d > "$csv" 2>/dev/null
  [ -n "$xml" ] && echo '<report/>' > "$xml"
  [ -n "$ids" ] && echo "task=cccc target=bbbb report=dddd" > "$ids"
  printf '{"ok":true,"status":"%s","progress":100,"task":"cccc","target":"bbbb","report":"dddd","hosts":2,"wrote":{"csv":200,"xml":10}}\n' "$st"
  return 0
}

RUN_NVT=1; NVT_FILES=95103; SCAN_CONFIG=fast
CFG_ID="daba56c8-73ec-11df-a475-002264764cea"; CFG_NAME="Full and fast"
RUN_NAME="regression"
NVT_U="MISK\\svc_scan"; NVT_P="$SECRET"; SSH_ON=0; SU=""; SP=""
ALIVE_TEST="ICMP, TCP-ACK Service & ARP Ping"; POLL=0; NVT_MAX_MIN=0
SOCK=/run/gvmd/gvmd.sock
T0=$(date +%s)
printf '10.0.0.1\n10.0.0.2\n' > targets.txt
: > "$RAW/helper-argv.txt"; : > "$RAW/helper-saw-pass.txt"
STUB
    sed -n "${s},$((e-1))p" "$SRC"
    cat <<'TAIL'
printf "RETURNED rows=%s high=%s med=%s nvt=%s\n" \
  "$NVT_ROWS" "$NVT_HIGH" "$NVT_MED" "$RUN_NVT"
# Read the ids the way the rest of the script does. Under set -u an
# unassigned one kills the run here, which is the bug this file was written
# for: a refused create_task left REPORT unset and Stages 3B through 10
# never happened.
printf 'IDS=%s|%s|%s\n' "$TASK" "$TARGET" "$REPORT"
printf 'IDSFILE=%s\n' "$(cat "$RAW/nvt/ids.txt" 2>/dev/null | tr -d '\n')"
# Did the secret ever reach the helper's argv?
if grep -qF -- "$SECRET" "$RAW/helper-argv.txt" 2>/dev/null; then
  echo "SECRET_IN_ARGV=yes"; else echo "SECRET_IN_ARGV=no"; fi
# Did the helper actually get it, by path?
if grep -qF -- "$SECRET" "$RAW/helper-saw-pass.txt" 2>/dev/null; then
  echo "HELPER_GOT_PASS=yes"; else echo "HELPER_GOT_PASS=no"; fi
# Is the credential file still on disk now the stage is finished?
P=$(cat "$RAW/helper-pass-path.txt" 2>/dev/null || true)
if [ -n "$P" ] && [ -e "$P" ]; then echo "PASSFILE_LEFT=yes"; else echo "PASSFILE_LEFT=no"; fi
TAIL
  } > "$w/run.sh"
}

run(){ # $1 scenario -> "exit|unbound|rows|high|returned|argv|got|left|nvt|ids"
  local w; w=$(mktemp -d); mkdir -p "$w/raw/nvt" "$w/raw/ports"
  build "$1" "$w"
  local out rc
  out=$(cd "$w" && bash run.sh 2>&1); rc=$?
  local ub=0 rows=- high=- ret=no
  printf '%s' "$out" | grep -q 'unbound variable' && ub=1
  if printf '%s' "$out" | grep -q '^RETURNED'; then
    ret=yes
    rows=$(printf '%s' "$out" | sed -n 's/^RETURNED rows=\([0-9]*\).*/\1/p' | head -1)
    high=$(printf '%s' "$out" | sed -n 's/.*high=\([ 0-9]*\) med=.*/\1/p' | tr -cd '0-9' | head -1)
  fi
  local argv got left nvt ids
  nvt=$(printf '%s' "$out" | sed -n 's/.*med=[ 0-9]* nvt=\([0-9]*\).*/\1/p' | head -1)
  ids=$(printf '%s' "$out" | sed -n 's/^IDS=//p' | head -1)
  local idsfile
  idsfile=$(printf '%s' "$out" | sed -n 's/^IDSFILE=//p' | head -1)
  argv=$(printf '%s' "$out" | sed -n 's/^SECRET_IN_ARGV=//p' | head -1)
  got=$(printf  '%s' "$out" | sed -n 's/^HELPER_GOT_PASS=//p' | head -1)
  left=$(printf '%s' "$out" | sed -n 's/^PASSFILE_LEFT=//p' | head -1)
  printf "%s\n" "$out" > "$OUTFILE"
  printf '%s|%s|%s|%s|%s|%s|%s|%s|nvt=%s' "$rc" "$ub" "${rows:-0}" "${high:-0}" \
         "$ret" "${argv:--}" "${got:--}" "${left:--}" "${nvt:--}"
  printf '|ids=%s' "${idsfile:--}"
  rm -rf "$w"
}

grepout(){ grep -qF -- "$1" "$OUTFILE"; }

PASS=0; FAIL=0
OUTFILE=$(mktemp)
trap 'rm -f "$OUTFILE"' EXIT
check(){ # $1 label, $2 got, $3 want
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        got  %s\n        want %s\n' "$1" "$2" "$3"
       tail -14 "$OUTFILE" | sed 's/^/        | /'; fi
}
checkout(){ # $1 label, $2 substring that must appear in the last transcript
  if grepout "$2"; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        %r not in the output\n' "$1" "$2"
       tail -14 "$OUTFILE" | sed 's/^/        | /'; fi
}

echo "stage 3A regression, file under test: $SRC"
echo
echo "a scan that runs to completion still parses its report"
check "happy: exit 0, no unbound, 2 rows, 1 high, returned" \
      "$(run happy)" "0|0|2|1|yes|no|yes|no|nvt=1|ids=task=cccc target=bbbb report=dddd"
checkout "and says the scan completed" "NVT scan complete"

echo
echo "the client's password travels by path, never in argv, and is cleaned up"
# The three flags after the pipe are the whole point: the secret was NOT in the
# helper's arguments, the helper DID receive it, and the file it was read from
# no longer exists.
check "partial scan: still exports, warns, secret handled" \
      "$(run partial)" "0|0|2|1|yes|no|yes|no|nvt=1|ids=task=cccc target=bbbb report=dddd"
checkout "and names the state it stopped in" "NVT scan Stopped"

echo
echo "a stage that gives up must give up quietly, not take the run with it"
check "task refused:  exit 0, no unbound, 0 findings, returned" \
      "$(run taskfail)"  "0|0|0|0|yes|no|yes|no|nvt=0|ids=task= target= report="
checkout "and names what gvmd said" "gvmd refused the task"
check "start refused: exit 0, no unbound, 0 findings, returned" \
      "$(run startfail)" "0|0|0|0|yes|no|yes|no|nvt=0|ids=task=cccc target= report="
checkout "and the task it did create is recorded" "task=cccc"
check "auth refused:  exit 0, no unbound, 0 findings, returned" \
      "$(run authfail)"  "0|0|0|0|yes|no|yes|no|nvt=0|ids=task= target= report="
checkout "and names the authentication failure" "GMP authentication failed"
check "no status:     exit 0, no unbound, 0 findings, returned" \
      "$(run nostatus)"  "0|0|0|0|yes|no|yes|no|nvt=0|ids=task= target= report="
checkout "and points at the journal" "journalctl -u gvmd"

echo
echo "a config the feed never delivered is named, with what is there"
check "missing config: exit 0, no unbound, 0 findings, returned" \
      "$(run missingcfg)" "0|0|0|0|yes|no|yes|no|nvt=0|ids=task= target= report="
checkout "names the config"        "is not present on this gvmd"
checkout "lists what gvmd has"    "Host Discovery"
checkout "gives the feed remedy"  "greenbone-feed-sync"

echo
echo "a missing python-gvm is reported as a missing library, not a bad password"
check "no library: exit 0, no unbound, 0 findings, returned" \
      "$(run nolib)" "0|0|0|0|yes|no|yes|no|nvt=0|ids=task= target= report="
checkout "names the library"  "python-gvm is not installed"
checkout "gives the install"  "pip3 install"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
