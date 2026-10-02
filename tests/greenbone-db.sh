#!/usr/bin/env bash
#
#  Greenbone database provisioning regression test
#
#  Lifts gvmd_db_ready out of KameKi.sh and drives it against stubbed
#  postgres and gvmd. No PostgreSQL, no Greenbone, no root needed.
#
#    ./tests/greenbone-db.sh            # tests ../KameKi.sh
#    ./tests/greenbone-db.sh path.sh
#
#  What it guards against, which shipped once:
#
#    setup-greenbone started redis and ospd-openvas but never postgresql,
#    and never created gvmd's role, database or extensions. gvmd exits at
#    once without them, and the failure was reported as the single word
#    "failed" because the systemctl output was sent to /dev/null. The
#    operator was left with "check: systemctl status gvmd" and no reason.
#
set -uo pipefail
SRC="${1:-$(dirname "$0")/../KameKi.sh}"
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }
H=$(mktemp); trap 'rm -f "$H" /tmp/kameki-pgstate.$$' EXIT
sed -n '/^gvmd_db_ready(){/,/^}$/p' "$SRC" > "$H"
grep -q '^gvmd_db_ready(){' "$H" || {
  echo "gvmd_db_ready is not present in $SRC" >&2; exit 2; }

PASS=0; FAIL=0
t(){ if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
     else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        got  [%s]\n        want [%s]\n' "$1" "$2" "$3"; fi; }

GRN=''; YEL=''; RST=''; DIM=''
have(){ [ "$1" = psql ] || command -v "$1" >/dev/null 2>&1; }
dim(){ printf '      %s\n' "$*"; }
id(){ [ "${2:-}" = postgres ] && return 0; command id "$@"; }
STATE="/tmp/kameki-pgstate.$$"
# shellcheck disable=SC1090
. "$H"

# A stub standing in for `runuser -u postgres -- <cmd>`, backed by a file so
# the "already provisioned" case is a genuine second call, not a flag.
pg_stub(){ shift 3; local cmd="$1"; shift
  case "$cmd" in
    psql) case "$*" in
            *"pg_roles WHERE rolname"*)    grep -q role "$STATE" && echo 1 ;;
            *"pg_database WHERE datname"*) grep -q db   "$STATE" && echo 1 ;;
          esac ;;
    createuser) echo role >> "$STATE" ;;
    createdb)   echo db   >> "$STATE" ;;
  esac
  return 0; }

echo "a fresh box is provisioned end to end"
: > "$STATE"; runuser(){ pg_stub "$@"; }
OUT=$(gvmd_db_ready _gvm 2>&1); RC=$?
t "exits 0"                "$RC" 0
t "creates the role"       "$(printf '%s' "$OUT" | grep -c 'postgres role _gvm.*created')" 1
t "creates the database"   "$(printf '%s' "$OUT" | grep -c 'gvmd database.*created')" 1
t "creates the extensions" "$(printf '%s' "$OUT" | grep -c 'database extensions.*ok')" 1
t "migrates the schema"    "$(printf '%s' "$OUT" | grep -c 'schema migration.*ok')" 1

echo
echo "running it again changes nothing"
OUT=$(gvmd_db_ready _gvm 2>&1); RC=$?
t "still exits 0"          "$RC" 0
t "role not recreated"     "$(printf '%s' "$OUT" | grep -c 'postgres role')" 0
t "database not recreated" "$(printf '%s' "$OUT" | grep -c 'gvmd database')" 0

echo
echo "a postgres failure is reported in postgres's own words"
: > "$STATE"; echo role >> "$STATE"
runuser(){ shift 3; local cmd="$1"; shift
  case "$cmd" in
    psql) case "$*" in *rolname*) echo 1 ;; esac ;;
    createdb) echo "createdb: error: could not connect to server" >&2; return 1 ;;
  esac; return 0; }
OUT=$(gvmd_db_ready _gvm 2>&1); RC=$?
t "returns non-zero"       "$RC" 1
t "prints the real error"  "$(printf '%s' "$OUT" | grep -c 'could not connect to server')" 1

echo
echo "a gvmd migration failure is reported in gvmd's own words"
: > "$STATE"; echo role >> "$STATE"; echo db >> "$STATE"
runuser(){ shift 3; local cmd="$1"; shift
  case "$cmd" in
    psql) case "$*" in *rolname*|*datname*) echo 1 ;; esac ;;
    gvmd) echo "gvmd: database is wrong version" >&2; return 1 ;;
  esac; return 0; }
OUT=$(gvmd_db_ready _gvm 2>&1); RC=$?
t "returns non-zero"       "$RC" 1
t "prints the real error"  "$(printf '%s' "$OUT" | grep -c 'database is wrong version')" 1

echo
echo "setup starts postgres, provisions, then starts gvmd, in that order"
BLK=$(sed -n '/^cmd_setup_greenbone(){/,/wait for the socket/p' "$SRC")
PGN=$(printf '%s\n' "$BLK" | grep -n 'for svc in postgresql'        | head -1 | cut -d: -f1)
DBN=$(printf '%s\n' "$BLK" | grep -n 'gvmd_db_ready'               | head -1 | cut -d: -f1)
GVN=$(printf '%s\n' "$BLK" | grep -n 'systemctl enable --now gvmd' | head -1 | cut -d: -f1)
t "postgres before provisioning" "$([ -n "$PGN" ] && [ -n "$DBN" ] && [ "$PGN" -lt "$DBN" ] && echo yes)" yes
t "provisioning before gvmd"     "$([ -n "$DBN" ] && [ -n "$GVN" ] && [ "$DBN" -lt "$GVN" ] && echo yes)" yes
t "gvmd failure shows the journal" "$(printf '%s\n' "$BLK" | grep -c 'journalctl -u gvmd')" 1

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
