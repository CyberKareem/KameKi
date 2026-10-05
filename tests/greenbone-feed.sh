#!/usr/bin/env bash
#
#  Greenbone feed and restart-loop regression test
#
#  Lifts the feed and start-timeout helpers out of kameki.sh and drives them
#  against stubbed systemctl and greenbone-feed-sync. No Greenbone, no
#  network, no root.
#
#    ./tests/greenbone-feed.sh            # tests ../kameki.sh
#    ./tests/greenbone-feed.sh path.sh
#
#  What it guards against, which shipped once:
#
#    A machine finished setup-greenbone with 0 NVT plugins, 0 scan configs
#    and 0 report formats, because nothing in the script ever fetched the
#    feed; it only printed advice to run the sync by hand. gvmd meanwhile
#    queries ospd-openvas for the VT list during start, which on an empty
#    feed does not return inside systemd's 90s TimeoutStartSec, so systemd
#    killed and restarted gvmd indefinitely. One site reached restart
#    counter 493, and every feed import was truncated by the next restart.
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
H=$(mktemp); trap 'rm -f "$H"' EXIT
sed -n '/^GVMD_START_TIMEOUT=/,/^}$/p;/^gvmd_break_restart_loop(){/,/^}$/p;/^nvt_count(){/,/^}$/p;/^FEED_SYNC=/,/^}$/p' \
    "$SRC" > "$H"
for fn in gvmd_fix_start_timeout gvmd_break_restart_loop nvt_count greenbone_sync_feeds; do
  grep -q "^${fn}(){" "$H" || { echo "could not lift $fn from $SRC" >&2; exit 2; }
done

PASS=0; FAIL=0
t(){ if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
     else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        got  [%s]\n        want [%s]\n' "$1" "$2" "$3"; fi; }

GRN=''; YEL=''; RST=''; DIM=''
dim(){ printf '      %s\n' "$*"; }
warn(){ printf '  [!] %s\n' "$*"; }
have(){ case "$1" in greenbone-feed-sync) return "${NO_FEEDSYNC:-0}" ;; *) command -v "$1" >/dev/null 2>&1 ;; esac; }
WORK=$(mktemp -d); LOG="$WORK/calls"; : > "$LOG"
PLUG="$WORK/plugins"
# redirect the helpers' absolute paths into the sandbox
systemctl(){ echo "systemctl $*" >> "$LOG"
             case "$1" in show) echo "${NRESTARTS:-0}" ;; list-unit-files) return 0 ;; esac; return 0; }
greenbone-feed-sync(){ echo "feed-sync $*" >> "$LOG"
                       mkdir -p "$PLUG"; : > "$PLUG/x$RANDOM.nasl"; return "${SYNC_RC:-0}"; }
# shellcheck disable=SC1090
. "$H"
# re-point the two absolute paths the helpers use
eval "$(declare -f gvmd_fix_start_timeout | sed "s#/etc/systemd/system/gvmd.service.d#$WORK/dropin#")"
eval "$(declare -f nvt_count | sed "s#/var/lib/openvas/plugins#$PLUG#g")"
eval "$(declare -f greenbone_sync_feeds | sed "s#/var/lib/openvas/plugins#$PLUG#g")"

echo "a fresh machine has no plugins"
t "nvt_count on an absent dir" "$(nvt_count)" 0

echo
echo "the start timeout is raised, because 90s is what caused the loop"
OUT=$(GVMD_START_TIMEOUT=1800 gvmd_fix_start_timeout 2>&1)
CONF="$WORK/dropin/kameki-timeout.conf"
t "drop-in written"              "$([ -f "$CONF" ] && echo yes)" yes
t "TimeoutStartSec set"          "$(grep -c '^TimeoutStartSec=1800' "$CONF")" 1
t "restart limit lifted"         "$(grep -c '^StartLimitIntervalSec=0' "$CONF")" 1
t "daemon-reload issued"         "$(grep -c 'systemctl daemon-reload' "$LOG")" 1
t "honours GVMD_START_TIMEOUT"   "$(GVMD_START_TIMEOUT=600 gvmd_fix_start_timeout >/dev/null 2>&1; grep -c '^TimeoutStartSec=600' "$CONF")" 1

echo
echo "an existing restart loop is stopped before any feed work"
: > "$LOG"
OUT=$(NRESTARTS=493 gvmd_break_restart_loop 2>&1)
t "gvmd stopped"                 "$(grep -c 'systemctl stop gvmd' "$LOG")" 1
t "failed state cleared"         "$(grep -c 'systemctl reset-failed gvmd' "$LOG")" 1
t "the loop is reported"         "$(printf '%s' "$OUT" | grep -c '493 restarts')" 1
: > "$LOG"
OUT=$(NRESTARTS=0 gvmd_break_restart_loop 2>&1)
t "a healthy unit says nothing"  "$(printf '%s' "$OUT" | grep -c 'restarts')" 0

echo
echo "the feed is actually fetched, not merely recommended"
: > "$LOG"; rm -rf "$PLUG"
OUT=$(greenbone_sync_feeds 2>&1); RC=$?
t "exits 0"                      "$RC" 0
t "nvt synced"                   "$(grep -c 'feed-sync --type nvt' "$LOG")" 1
t "gvmd-data synced"             "$(grep -c 'feed-sync --type gvmd-data' "$LOG")" 1
t "scap synced"                  "$(grep -c 'feed-sync --type scap' "$LOG")" 1
t "cert synced"                  "$(grep -c 'feed-sync --type cert' "$LOG")" 1
t "gvmd-data is fetched first"   "$(grep -n 'feed-sync --type' "$LOG" | head -1 | grep -c gvmd-data)" 1
t "nvt comes before scap"        "$([ "$(grep -n 'type nvt'  "$LOG" | head -1 | cut -d: -f1)" \
                                     -lt "$(grep -n 'type scap' "$LOG" | head -1 | cut -d: -f1)" ] && echo yes)" yes
t "ospd reloaded after the sync" "$(grep -c 'systemctl restart ospd-openvas' "$LOG")" 1
t "plugin count reported"        "$(printf '%s' "$OUT" | grep -c 'NVT plugins')" 1
t "says rsync resumes"           "$(printf '%s' "$OUT" | grep -c 'rsync resumes')" 1

echo
echo "FEED_TYPES narrows the sync for a slow link"
: > "$LOG"
OUT=$(FEED_TYPES="gvmd-data nvt" greenbone_sync_feeds 2>&1)
t "only the two asked for"       "$(grep -c 'feed-sync --type' "$LOG")" 2
t "scap not fetched"             "$(grep -c 'type scap' "$LOG")" 0

echo
echo "a sync failure is reported, not swallowed"
: > "$LOG"
OUT=$(SYNC_RC=1 greenbone_sync_feeds 2>&1); RC=$?
t "returns non-zero"             "$RC" 1
t "names the failing feeds"      "$([ "$(printf '%s' "$OUT" | grep -c 'sync failed or was incomplete')" -ge 1 ] && echo yes)" yes

echo
echo "a missing greenbone-feed-sync is a clear message, not a crash"
OUT=$(NO_FEEDSYNC=1 greenbone_sync_feeds 2>&1); RC=$?
t "returns non-zero"             "$RC" 1
t "says what to install"         "$(printf '%s' "$OUT" | grep -c 'FEED_SYNC=0')" 1

echo
echo "setup runs them in the only order that works"
BLK=$(sed -n '/^cmd_setup_greenbone(){/,/admin user and credentials/p' "$SRC")
n(){ printf '%s\n' "$BLK" | grep -n "$1" | head -1 | cut -d: -f1; }
LOOP=$(n 'gvmd_break_restart_loop'); TMO=$(n 'gvmd_fix_start_timeout')
FEED=$(n 'greenbone_sync_feeds');    START=$(n 'systemctl enable --now gvmd')
t "loop broken before the feed"  "$([ -n "$LOOP" ] && [ -n "$FEED" ] && [ "$LOOP" -lt "$FEED" ] && echo yes)" yes
t "timeout raised before the feed" "$([ -n "$TMO" ] && [ -n "$FEED" ] && [ "$TMO" -lt "$FEED" ] && echo yes)" yes
t "feed fetched before gvmd starts" "$([ -n "$FEED" ] && [ -n "$START" ] && [ "$FEED" -lt "$START" ] && echo yes)" yes
t "socket wait outlasts 30s"     "$(printf '%s\n' "$BLK" | grep -c 'SOCK_WAIT:-300')" 1

rm -rf "$WORK"
echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
