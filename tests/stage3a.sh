#!/usr/bin/env bash
#
#  Stage 3A regression test
#
#  Slices the real Stage 3A out of KameKi.sh and runs it against a stubbed
#  gvmd, so each way the stage can abandon is exercised as written rather
#  than as retyped here. It needs no Greenbone, no root and no network.
#
#    ./tests/stage3a.sh            # tests ../KameKi.sh
#    ./tests/stage3a.sh path.sh    # tests a specific file
#
#  What it guards against, both of which shipped once:
#
#    A failed create_task left REPORT unassigned. The next line read it,
#    and under set -u that killed the whole run, so Stage 3B through 10
#    and the final report never happened because Greenbone declined once.
#
#    The CSV export was not guarded, so a stage that had already given up
#    still asked gvmd for a report id it had never been issued, and
#    counted whatever came back as findings.
#
set -uo pipefail
SRC="${1:-$(dirname "$0")/../KameKi.sh}"
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

build(){ # $1 scenario, $2 workdir -> writes $2/run.sh
  local sc="$1" w="$2" s e
  s=$(grep -n '#  Stage 3A' "$SRC" | head -1 | cut -d: -f1)
  e=$(grep -n '#  Stage 3B' "$SRC" | head -1 | cut -d: -f1)
  [ -n "$s" ] && [ -n "$e" ] || { echo "cannot locate Stage 3A in $SRC" >&2; exit 2; }
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
    # the real extractors, lifted from the file under test
    sed -n '/^gmp_pairs(){/,/^}$/p'  "$SRC"
    sed -n '/^gmp_names(){/,/^}$/p'  "$SRC"
    sed -n '/^gmp_id_for(){/,/^}$/p' "$SRC"
    printf 'SCENARIO=%q\nRAW=%q\n' "$sc" "$w/raw"
    cat <<'STUB'
CFGXML='<get_configs_response status="200"><filters id="0"><name>get_configs</name></filters><config id="daba56c8-73ec-11df-a475-002264764cea"><owner><name>admin</name></owner><name>Full and fast</name></config></get_configs_response>'
SCNXML='<get_scanners_response status="200"><scanner id="08b69003-5fc2-4037-a479-93b440211c73"><owner><name>admin</name></owner><name>OpenVAS Default</name></scanner></get_scanners_response>'
FMTXML='<get_report_formats_response status="200"><report_format id="c1645568-627a-11e3-a660-406186ea4fc5"><owner><name>admin</name></owner><name>CSV Results</name></report_format></get_report_formats_response>'
CSVB64=$(printf '%s\n%s\n%s\n' \
  'IP,Hostname,Port,Port Protocol,CVSS,Severity,Solution Type,NVT Name' \
  '"10.0.0.1","h1","445","tcp","7.5","High","VendorFix","SMB flaw CVE-2020-0796"' \
  '"10.0.0.2","h2","22","tcp","5.0","Medium","VendorFix","SSH weak cipher"' | base64 | tr -d '\n')
gmp(){
  case "$1" in
    *get_version*)   if [ "$SCENARIO" = authfail ]
                     then echo '<get_version_response status="400" status_text="Authenticate first"/>'
                     else echo '<get_version_response status="200"><version>22.5</version></get_version_response>'; fi ;;
    *create_credential*)  echo '<create_credential_response status="201" id="aaaa1111-2222-3333-4444-555555555555"/>' ;;
    *create_target*)      echo '<create_target_response status="201" id="bbbb1111-2222-3333-4444-555555555555"/>' ;;
    *get_scanners*)       echo "$SCNXML" ;;
    *get_report_formats*) echo "$FMTXML" ;;
    *get_configs*)        echo "$CFGXML" ;;
    *create_task*)   if [ "$SCENARIO" = taskfail ]
                     then echo '<create_task_response status="404" status_text="Failed to find config"/>'
                     else echo '<create_task_response status="201" id="cccc1111-2222-3333-4444-555555555555"/>'; fi ;;
    *start_task*)    if [ "$SCENARIO" = startfail ]
                     then echo '<start_task_response status="400" status_text="Task must be New"/>'
                     else echo '<start_task_response status="202"><report_id>dddd1111-2222-3333-4444-555555555555</report_id></start_task_response>'; fi ;;
    *get_tasks*)     echo '<get_tasks_response status="200"><task><status>Done</status><progress>100</progress></task></get_tasks_response>' ;;
    *get_reports*)   printf '<get_reports_response status="200"><report><report_format></report_format>%s</report></get_reports_response>\n' "$CSVB64" ;;
    *)               echo '<response status="200"/>' ;;
  esac
}
RUN_NVT=1; NVT_FILES=95103; SCAN_CONFIG=fast
CFG_ID="daba56c8-73ec-11df-a475-002264764cea"; CFG_NAME="Full and fast"
FMT_CSV="c1645568-627a-11e3-a660-406186ea4fc5"
FMT_XML="a994b278-1f62-11e1-96ac-406186ea4fc5"
RUN_NAME="regression"; NVT_U="u"; NVT_P="p"; SSH_ON=0; SU=""; SP=""
ALIVE_TEST="ICMP Ping"; POLL=0; T0=$(date +%s)
printf '10.0.0.1\n10.0.0.2\n' > targets.txt
STUB
    # the stage itself, with only the live gvmd transport swapped out
    sed -n "${s},$((e-1))p" "$SRC" \
      | sed -e '/^gmp(){ gvmcli/d' -e 's|^GMPU=.*|GMPU=u; GMPP=p|'
    echo 'printf "RETURNED rows=%s high=%s med=%s nvt=%s\n" \'
    echo '  "$NVT_ROWS" "$NVT_HIGH" "$NVT_MED" "$RUN_NVT"'
  } > "$w/run.sh"
}

run(){ # $1 scenario -> echoes "exit|unbound|rows|high|returned"
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
  # run() is called inside a command substitution, so a variable set here
  # would not survive the subshell. The transcript goes to a file instead.
  printf "%s\n" "$out" > "$OUTFILE"
  printf '%s|%s|%s|%s|%s' "$rc" "$ub" "${rows:-0}" "${high:-0}" "$ret"
  rm -rf "$w"
}

PASS=0; FAIL=0
OUTFILE=$(mktemp)
trap 'rm -f "$OUTFILE"' EXIT
check(){ # $1 label, $2 got, $3 want
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        got  %s\n        want %s\n' "$1" "$2" "$3"
       tail -12 "$OUTFILE" | sed 's/^/        | /'; fi
}

echo "stage 3A regression, file under test: $SRC"
echo
echo "a scan that runs to completion still parses its report"
check "happy: exit 0, no unbound, 2 rows, 1 high, stage returned" "$(run happy)" "0|0|2|1|yes"
echo
echo "a stage that gives up must give up quietly, not take the run with it"
check "create_task refused: exit 0, no unbound, 0 findings, returned"  "$(run taskfail)"  "0|0|0|0|yes"
check "start_task refused:  exit 0, no unbound, 0 findings, returned"  "$(run startfail)" "0|0|0|0|yes"
check "GMP auth refused:    exit 0, no unbound, 0 findings, returned"  "$(run authfail)"  "0|0|0|0|yes"
echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
