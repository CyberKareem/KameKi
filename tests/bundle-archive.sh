#!/usr/bin/env bash
#
#  Bundle archive regression test
#
#  Slices the real tar_in / tar_out out of KameKi.sh and drives them with and
#  without zstd on PATH. Needs no root and no network.
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
SRC="${1:-$(dirname "$0")/../KameKi.sh}"
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
  sed -n '/^tar_out(){/,/^}$/p' "$SRC"
} > "$HELPERS"
grep -q 'tar_in' "$HELPERS"  || { echo "cannot find tar_in in $SRC" >&2;  exit 2; }
grep -q 'tar_out' "$HELPERS" || { echo "cannot find tar_out in $SRC" >&2; exit 2; }

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

# --- tar_out picks a format and reports which ------------------------------
echo
echo "tar_out picks the best format available and says which"
got=$(cd "$W" && bash -c "source '$HELPERS'; tar_out inner -C payload ." 2>&1); rc=$?
check "tar_out succeeds" "$rc" "0"
if [ "$HAVE_ZSTD" = yes ]; then
  check "names a zstd archive when zstd is present" "${got##*/}" "inner.tar.zst"
else
  check "names a gzip archive when zstd is absent" "${got##*/}" "inner.tar.gz"
fi
check "and the file it named exists" "$([ -f "$W/$(basename "$got")" ] && echo yes || echo no)" "yes"

got=$(cd "$W" && PATH="$W/plain:/usr/bin:/bin" bash -c \
      "source '$HELPERS'; tar_out fallback -C payload ." 2>&1)
check "falls back to gzip when zstd is not on PATH" "${got##*/}" "fallback.tar.gz"

# --- round trip, both ways -------------------------------------------------
echo
echo "round trip"
mkdir -p "$W/rt"
a=$(cd "$W" && bash -c "source '$HELPERS'; tar_out rt-arch -C payload ." 2>&1)
( cd "$W" && bash -c "source '$HELPERS'; tar_in '$(basename "$a")' -C rt" ) >/dev/null 2>&1
check "what tar_out wrote, tar_in reads back" \
      "$(cat "$W/rt/plugins.txt" 2>/dev/null)" "the feed"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
