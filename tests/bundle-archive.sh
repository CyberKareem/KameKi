#!/usr/bin/env bash
#
#  Bundle archive regression test
#
#  Slices the real tar_in out of kameki.sh and drives it with and without
#  zstd on PATH. Needs no root and no network.
#
#    ./tests/bundle-archive.sh
#
#  What it guards against, which shipped:
#
#    The offline bundle is the answer to a client network that blocks the
#    package mirror -- and it was compressed with zstd, which is itself one of
#    the packages such a network stops you installing. The bundle carried
#    zstd's own .deb inside, which is no help when you need zstd to open the
#    bundle to reach it. On a real PCI engagement apt could not fetch zstd and
#    the escape hatch was shut.
#
#    So: the outer archive must open with tools every box already has, and
#    extraction must still accept the older zstd bundles.
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

PASS=0; FAIL=0
check(){ # $1 label, $2 got, $3 want
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s\n        got  %s\n        want %s\n' "$1" "$2" "$3"; fi
}

# The helpers, lifted from the file under test rather than retyped here.
HELPERS=$(mktemp)
trap 'rm -f "$HELPERS"' EXIT
{
  cat <<'P'
set -uo pipefail
err(){ printf '  [x] %s\n' "$*"; }
dim(){ printf '      %s\n' "$*"; }
P
  sed -n '/^have(){/p'        "$SRC"
  sed -n '/^tar_in(){/,/^}$/p'  "$SRC"
} > "$HELPERS"
grep -q 'tar_in' "$HELPERS"  || { echo "cannot find tar_in in $SRC" >&2;  exit 2; }

HAVE_ZSTD=no; command -v zstd >/dev/null 2>&1 && HAVE_ZSTD=yes
TARKIND=bsd; tar --version 2>/dev/null | head -1 | grep -qi 'gnu tar' && TARKIND=gnu
echo "bundle archive regression, file under test: $SRC"
echo "zstd on this machine: $HAVE_ZSTD   tar: $TARKIND"

# bsdtar (macOS) sniffs the compression even when a decompressor flag is
# passed, so a behavioural test cannot tell `tar -xf` from `tar --zstd -xf`
# there. GNU tar, which is what runs on the Linux box this ships to, honours
# the flag and fails on a gzip file. Assert on the source so the rule holds on
# both: extraction must let tar decide, never force a codec.
echo
echo "extraction must not force a codec"
TIN=$(sed -n '/^tar_in(){/,/^}$/p' "$SRC")
case "$TIN" in
  *"--zstd"*|*"-czf"*|*"-xzf"*|*"-xjf"*|*"-xJf"*)
    check "tar_in passes no compression flag to tar" "forces a codec" "lets tar decide" ;;
  *) check "tar_in passes no compression flag to tar" "lets tar decide" "lets tar decide" ;;
esac
case "$TIN" in
  *'tar -xf "$a"'*) check "tar_in extracts with a plain tar -xf" yes yes ;;
  *)                check "tar_in extracts with a plain tar -xf" no yes ;;
esac

W=$(mktemp -d); trap 'rm -f "$HELPERS"; rm -rf "$W"' EXIT
mkdir -p "$W/payload"; echo "the feed" > "$W/payload/plugins.txt"

# --- a bundle built where zstd exists, opened where it does not -------------
echo
echo "the case that shut the escape hatch on site"
if [ "$HAVE_ZSTD" = yes ]; then
  ( cd "$W" && tar --zstd -cf old-style.tar.zst payload ) 2>/dev/null
  # Hide zstd the way a blocked apt mirror does.
  mkdir -p "$W/nozstd"
  for b in tar gzip cat sed grep printf; do
    p=$(command -v "$b" 2>/dev/null) && ln -sf "$p" "$W/nozstd/$b" 2>/dev/null
  done
  out=$(cd "$W" && PATH="$W/nozstd:/usr/bin:/bin" bash -c \
        "source '$HELPERS'; tar_in old-style.tar.zst -C . " 2>&1); rc=$?
  check "a zstd bundle with no zstd fails loudly, not silently" "$rc" "1"
  case "$out" in *"zstd is not installed"*) g=named ;; *) g="$out" ;; esac
  check "and names the cause" "$g" "named"
  case "$out" in *"rebuild the bundle with a newer kameki"*) g=remedy ;; *) g="no remedy" ;; esac
  check "and gives the remedy" "$g" "remedy"
else
  echo "  SKIP  no zstd here to build an old-style bundle with"
fi

# --- the new outer archive opens with nothing but tar+gzip -----------------
echo
echo "the new outer archive opens with tools every box has"
( cd "$W" && tar -czf new-style.tar.gz payload )
mkdir -p "$W/plain" "$W/dest"
for b in tar gzip; do p=$(command -v "$b") && ln -sf "$p" "$W/plain/$b"; done
out=$(cd "$W" && PATH="$W/plain:/usr/bin:/bin" bash -c \
      "source '$HELPERS'; tar_in new-style.tar.gz -C dest" 2>&1); rc=$?
check "gzip bundle extracts with no zstd present" "$rc" "0"
check "and the payload is really there" \
      "$(cat "$W/dest/payload/plugins.txt" 2>/dev/null)" "the feed"

# --- the bundle must name a format every box can open ----------------------
# There are no inner feed tarballs any more, so there is no format choice to
# make and no tar_out: cmd_bundle writes the one outer archive directly. If
# that line ever goes back to zstd, the escape hatch shuts again.
echo
echo "the bundle writes gzip, unconditionally"
BOUT=$(grep -n 'kameki-bundle-' "$SRC" | grep 'OUT=' | head -1)
case "$BOUT" in
  *'.tar.gz'*) check "cmd_bundle names a .tar.gz" yes yes ;;
  *)           check "cmd_bundle names a .tar.gz" "$BOUT" "a .tar.gz name" ;;
esac
case "$(grep -c 'tar -czf "$OUT" -C "$B" \.' "$SRC")" in
  1) check "and writes it with a plain tar -czf" yes yes ;;
  *) check "and writes it with a plain tar -czf" no yes ;;
esac

# --- round trip through the command cmd_bundle actually runs ---------------
echo
echo "round trip"
mkdir -p "$W/rt"
( cd "$W/payload" && tar -czf "$W/rt-arch.tar.gz" -C "$W/payload" . )
( cd "$W" && bash -c "source '$HELPERS'; tar_in rt-arch.tar.gz -C rt" ) >/dev/null 2>&1
check "what cmd_bundle writes, tar_in reads back" \
      "$(cat "$W/rt/plugins.txt" 2>/dev/null)" "the feed"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
