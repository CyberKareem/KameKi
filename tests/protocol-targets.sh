#!/usr/bin/env bash
#
#  Protocol target list regression test
#
#  Lifts proto_list, net_open, nxcq and cnt out of KameKi.sh and exercises
#  them against the shape that caused a four-hour stall at a client: many
#  live hosts, very few with any open port.
#
#    ./tests/protocol-targets.sh            # tests ../KameKi.sh
#    ./tests/protocol-targets.sh path.sh
#
#  What it guards against, which shipped once:
#
#    Stages 4 to 7 pointed every nxc protocol at every live host. A TCP
#    connect to a FILTERED port does not fail, it blocks on SYN retries,
#    which is over two minutes per host on a default Linux. With 36 live
#    hosts, 5 protocols and no wall-clock cap anywhere, one firewalled
#    segment stalled the run for hours with nothing printed.
#
set -uo pipefail
SRC="${1:-$(dirname "$0")/../KameKi.sh}"
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

HELPERS=$(mktemp); trap 'rm -f "$HELPERS"' EXIT
sed -n '/^NXC_CAP=/,/^}$/p;/^proto_list(){/,/^}$/p;/^net_open(){/,/^}$/p;/^cnt(){/,/^}$/p' \
    "$SRC" > "$HELPERS"
for fn in proto_list net_open nxcq cnt; do
  grep -q "^${fn}(){\|^${fn}()" "$HELPERS" || { echo "could not lift $fn from $SRC" >&2; exit 2; }
done

PASS=0; FAIL=0
t(){ if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %-38s %s\n' "$1" "$2"
     else FAIL=$((FAIL+1)); printf '  FAIL  %-38s got %s, want %s\n' "$1" "$2" "$3"; fi; }

have(){ command -v "$1" >/dev/null 2>&1; }
# shellcheck disable=SC1090
. "$HELPERS"

RAW=$(mktemp -d); mkdir -p "$RAW/ports" "$RAW/targets"
seq 1 36 | sed 's|^|10.0.0.|' > "$RAW/live.txt"
cat > "$RAW/ports/map.txt" <<'MAP'
10.0.0.3 135,139,445,3389,5985
10.0.0.7 445,1433,3389
10.0.0.11 22,80
10.0.0.19 389,445,636,3389,5985
MAP

echo "a protocol gets only the hosts that answer on its own port"
t "smb, 445 or 139"    "$(proto_list smb 445 139)"     3
t "ldap, 389 or 636"   "$(proto_list ldap 389 636)"    1
t "mssql, 1433"        "$(proto_list mssql 1433)"      1
t "winrm, 5985 or 5986" "$(proto_list winrm 5985 5986)" 2
t "rdp, 3389"          "$(proto_list rdp 3389)"        3
t "ssh, 22"            "$(proto_list ssh 22)"          1
t "smb membership"     "$(paste -sd, - < "$RAW/targets/smb.txt")" "10.0.0.3,10.0.0.7,10.0.0.19"
t "a port nothing opens" "$(proto_list vnc 5900)"      0

echo
echo "the stall this prevents, counted in host-attempts"
BEFORE=$(( 36 * 5 ))
AFTER=$(( $(cnt "$RAW/targets/smb.txt") + $(cnt "$RAW/targets/ldap.txt") \
        + $(cnt "$RAW/targets/mssql.txt") + $(cnt "$RAW/targets/winrm.txt") \
        + $(cnt "$RAW/targets/rdp.txt") ))
printf '  five protocols over 36 live hosts: %s attempts before, %s after\n' "$BEFORE" "$AFTER"
t "attempts fall by at least 10x" "$([ $(( BEFORE / (AFTER>0?AFTER:1) )) -ge 10 ] && echo yes)" yes

echo
echo "an empty port map must not send every protocol at every live host"
: > "$RAW/ports/map.txt"
net_open(){ case "$1:$2" in 10.0.0.5:445|10.0.0.9:445) return 0 ;; *) return 1 ;; esac; }
t "falls back to a bounded direct probe" "$(proto_list smb 445 139)" 2
t "fallback membership" "$(paste -sd, - < "$RAW/targets/smb.txt")" "10.0.0.5,10.0.0.9"
net_open(){ return 1; }
t "nothing listening yields nothing"     "$(proto_list smb 445 139)" 0

echo
echo "every nxc call is bounded by wall clock"
if have timeout; then
  NXC_CAP=2
  nxc(){ sleep 60; }
  S=$(date +%s); nxcq smb whatever >/dev/null 2>&1; E=$(date +%s)
  t "a hanging nxc is killed inside 5s" "$([ $((E-S)) -lt 5 ] && echo yes)" yes
else
  echo "  SKIP  timeout(1) not available on this host"
fi

rm -rf "$RAW"
echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
