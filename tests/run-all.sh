#!/usr/bin/env bash
#
#  Every regression suite, in one command.
#
#    ./tests/run-all.sh
#
#  None of them need root or a network.
#
set -uo pipefail
cd "$(dirname "$0")/.."

# macOS system python caches bytecode outside the source tree and invalidates
# it on mtime+size, so an edit that keeps a file the same size in the same
# second can be missed and the PREVIOUS version silently tested. That happened
# while these suites were being written.
export PYTHONDONTWRITEBYTECODE=1

# The script has been both KameKi.sh and kameki.sh. A case-insensitive
# filesystem resolves either, so a wrong name here passes on macOS and fails
# on the Linux box this actually ships to.
SRC=""
for _c in kameki.sh KameKi.sh; do [ -f "$_c" ] && { SRC="$_c"; break; }; done
[ -n "$SRC" ] || { echo "cannot find kameki.sh next to tests/" >&2; exit 2; }
echo "script under test: $SRC"

PASS=0; FAIL=0; FAILED=""

run(){ # $1 label, $2... command
  local label="$1"; shift
  printf '\n────────────────────────────────────────────────────────\n'
  printf '%s\n' "$label"
  printf '────────────────────────────────────────────────────────\n'
  if "$@"; then PASS=$((PASS+1))
  else FAIL=$((FAIL+1)); FAILED="$FAILED
  $label"; fi
}

echo "kameKi regression suites"
echo "shell:  $(bash --version | head -1)"
echo "python: $(python3 --version 2>&1)"

run "bash syntax"               bash -n "$SRC"
run "Stage 3 failure report"    bash tests/nse-failure.sh
run "bundle archive"            bash tests/bundle-archive.sh
run "win_facts registry read"   bash tests/win-facts.sh
run "MSRC patch engine"         python3 tests/msrc.py
run "protocol targets"          bash tests/protocol-targets.sh

printf '\n════════════════════════════════════════════════════════\n'
if [ "$FAIL" -eq 0 ]; then
  printf '%d suites passed\n' "$PASS"
else
  printf '%d suites passed, %d FAILED:%s\n' "$PASS" "$FAIL" "$FAILED"
fi
[ "$FAIL" -eq 0 ]
