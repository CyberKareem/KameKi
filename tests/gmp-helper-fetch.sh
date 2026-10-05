#!/usr/bin/env bash
#
#  GMP helper discovery and self-fetch regression test
#
#  Slices gmp_py_find / gmp_py_interp / fetch_gmp_helper out of kameki.sh and
#  drives them against a stubbed curl. No network, no root, no Greenbone.
#
#    ./tests/gmp-helper-fetch.sh
#
#  What it guards against, which happened on a live PCI engagement:
#
#    kameki is installed by wget-ing the one script, which leaves
#    kameki_gmp.py behind. With no client to check with, setup-greenbone
#    could not verify the account it had just created, took its
#    "created, unverified" branch, and wrote a harvested password to
#    gmp-pass.txt that gvmd had never accepted. Every later Greenbone check
#    then failed as "gmp auth failed", which reads as a credential problem
#    and sends you looking in the wrong place entirely.
#
#    And a captive portal or a 404 page saved to that filename is worse than
#    no file at all: it would be discovered and then fail with a Python
#    syntax error instead of a clear missing-file message.
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

# A sandbox holding a fake "kameki.sh" that sources the real helpers, so
# BASH_SOURCE resolution is exercised the way it runs in production.
# Seal the PATH. The first version of this test left /usr/bin on it, so the
# "no curl on the box" case fell through to the real curl and actually fetched
# from github -- a unit test making a network call, and passing for the wrong
# reason. Only these tools are visible, and curl/wget only when stubbed.
seal_bin(){ # $1 bin dir
  local b="$1" t p
  mkdir -p "$b"
  for t in bash sh head grep rm sed cat ln chmod mktemp dirname readlink \
           python3 printf env tr; do
    p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$b/$t" 2>/dev/null
  done
}

build(){ # $1 workdir, $2 what a fetch should produce: good|html|empty|none
  local w="$1" kind="$2"
  seal_bin "$w/bin"
  {
    cat <<'P'
set -uo pipefail
err(){ printf '  [x] %s\n' "$*"; }
dim(){ printf '      %s\n' "$*"; }
warn(){ printf '  [!] %s\n' "$*"; }
P
    sed -n '/^have(){/p' "$SRC"
    sed -n '/^KAMEKI_GMP=""/,/^GMP_PY_INTERP=""/p' "$SRC"
    sed -n '/^gmp_py_find(){/,/^}$/p' "$SRC"
    sed -n '/^gmp_py_interp(){/,/^}$/p' "$SRC"
    sed -n '/^gmp_py_ready(){/p' "$SRC"
    sed -n '/^KAMEKI_RAW=/p' "$SRC"
    sed -n '/^fetch_gmp_helper(){/,/^}$/p' "$SRC"
    echo 'fetch_gmp_helper; echo "RC=$?"'
    echo 'gmp_py_find >/dev/null 2>&1 && echo "FOUND=yes" || echo "FOUND=no"'
  } > "$w/kameki.sh"

  # stub curl: the only network this test is allowed
  case "$kind" in
    good)  cat > "$w/bin/curl" <<'C'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out="$2"; shift; }; shift; done
printf '#!/usr/bin/env python3\n"""stub"""\ndef main():\n    pass\n' > "$out"
C
      ;;
    html)  cat > "$w/bin/curl" <<'C'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out="$2"; shift; }; shift; done
printf '<!DOCTYPE html><title>Sign in to the guest network</title>\n' > "$out"
C
      ;;
    empty) cat > "$w/bin/curl" <<'C'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out="$2"; shift; }; shift; done
: > "$out"
C
      ;;
    truncated) cat > "$w/bin/curl" <<'C'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out="$2"; shift; }; shift; done
# A transfer the filtering device cut off part way: the shebang arrived,
# the code did not. That is the realistic failure on the network kameki
# runs on, and it is the case the 'def main' check exists for.
printf '#!/usr/bin/env python3\\n"""Greenbone Management Protocol clien\\n' > "$out"
C
      ;;
    noshebang) cat > "$w/bin/curl" <<'C'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out="$2"; shift; }; shift; done
# A proxy error page that happens to contain the words grepped for further
# down. Only the first-line shebang check rejects this one.
printf '<html><body>502 Bad Gateway\\ndef main() upstream failed\\n</body></html>\\n' > "$out"
C
      ;;
    none)  : ;;   # no curl, no wget at all
  esac
  [ -f "$w/bin/curl" ] && chmod +x "$w/bin/curl"
}

run(){ # $1 kind, $2 preexisting helper? yes|no -> "RC|FOUND|looks"
  local w; w=$(mktemp -d)
  build "$w" "$1"
  if [ "$2" = yes ]; then
    # A distinctive marker, so an unnecessary re-fetch becomes visible: the
    # stub would overwrite this with its own text.
    printf '#!/usr/bin/env python3\n"""KEEP-THIS-EXACT-FILE"""\ndef main():\n    pass\n' \
      > "$w/kameki_gmp.py"
  fi
  local out; out=$(cd "$w" && PATH="$w/bin" "$w/bin/bash" kameki.sh 2>&1)
  local rc found looks=absent
  rc=$(printf '%s' "$out" | sed -n 's/^RC=//p' | head -1)
  found=$(printf '%s' "$out" | sed -n 's/^FOUND=//p' | head -1)
  if [ -f "$w/kameki_gmp.py" ]; then
    if head -1 "$w/kameki_gmp.py" | grep -q python; then looks=python; else looks=junk; fi
    grep -q 'KEEP-THIS-EXACT-FILE' "$w/kameki_gmp.py" && looks="$looks,kept"
  fi
  printf '%s|%s|%s' "${rc:--}" "${found:--}" "$looks"
  rm -rf "$w"
}

echo "GMP helper fetch regression, file under test: $SRC"

echo
echo "the helper is already there"
check "no fetch needed, found, and NOT overwritten" "$(run good yes)" "0|yes|python,kept"

echo
echo "only the script was downloaded, and the network works"
check "fetched, found, and it is python" "$(run good no)" "0|yes|python"

echo
echo "a captive portal answers instead of github"
# The whole point: a saved HTML page must be deleted, not left to be found
# and then blow up as a syntax error.
check "rejected, not found, nothing left behind" "$(run html no)" "1|no|absent"

echo
echo "the fetch returns nothing at all"
check "rejected, not found, nothing left behind" "$(run empty no)" "1|no|absent"

echo
echo "the transfer was cut off part way through"
check "a truncated python file is rejected" "$(run truncated no)" "1|no|absent"

echo
echo "a proxy error page containing the words we grep for"
check "rejected on the shebang, not the body" "$(run noshebang no)" "1|no|absent"

echo
echo "no curl and no wget on the box"
check "fails without creating anything" "$(run none no)" "1|no|absent"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
