#!/usr/bin/env bash
#
#  Greenbone OCI feed transport regression test
#
#  Slices the OCI fetcher out of kameki.sh and drives it against a stubbed
#  registry and stubbed tarballs. No network, no root, no Greenbone.
#
#    ./tests/greenbone-oci.sh
#
#  What it guards against, all established by reading the real registry:
#
#    Every feed image is built on busybox, so the FIRST layer is a whole root
#    filesystem -- 2,275,512 bytes of /bin, byte-identical across repositories
#    and not feed data. For data-objects that base layer is also the BIGGEST
#    layer, so "fetch the largest layer" downloads the wrong thing and
#    extracts nothing at all.
#
#    The release directory inside the images is not fixed and is not the same
#    between repositories: the tests ship under var/lib/openvas/24.10/ while
#    the gvmd data objects ship under var/lib/gvm/data-objects/gvmd/20.08/.
#    Hardcoding a release produces a silently empty feed after a Greenbone
#    version bump.
#
#    A blob whose digest does not match must be discarded, not kept. gvmd
#    will load a truncated feed file and report whatever it happens to
#    contain, which is worse than having no feed.
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

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

HELPERS="$W/helpers.sh"
{
  echo 'set -uo pipefail'
  echo 'have(){ command -v "$1" >/dev/null 2>&1; }'
  echo 'info(){ printf "  [+] %s\n" "$*"; }'
  echo 'warn(){ printf "  [!] %s\n" "$*"; }'
  echo 'err(){  printf "  [x] %s\n" "$*"; }'
  echo 'dim(){  printf "      %s\n" "$*"; }'
  echo 'GRN=""; YEL=""; RST=""'
  sed -n '/^GB_REGISTRY=/,/^GB_RETRIES=/p'     "$SRC"
  sed -n '/^gb_oci_token(){/,/^}$/p'  "$SRC"
  sed -n '/^gb_oci_layers(){/,/^}$/p' "$SRC"
  sed -n '/^gb_oci_blob(){/,/^}$/p'   "$SRC"
  sed -n '/^gb_oci_pull(){/,/^}$/p'   "$SRC"
  sed -n '/^gb_account(){/,/^}$/p'    "$SRC"
} > "$HELPERS"
for fn in gb_oci_token gb_oci_layers gb_oci_blob gb_oci_pull; do
  grep -q "^$fn(){" "$HELPERS" || { echo "cannot find $fn in $SRC" >&2; exit 2; }
done

# --- build the fake registry content ---------------------------------------
R="$W/registry"; mkdir -p "$R/blobs"

# The busybox base layer: real content, no var/ at all. This is the layer that
# must be fetched and then contribute nothing.
mkdir -p "$W/base/bin" && echo 'not feed data' > "$W/base/bin/sh"
tar -czf "$R/blobs/base.tgz" -C "$W/base" bin

# vulnerability-tests: note the 24.10 release directory.
mkdir -p "$W/vt/var/lib/openvas/24.10/vt-data/nasl"
echo 'script_oid("1.2.3");' > "$W/vt/var/lib/openvas/24.10/vt-data/nasl/a.nasl"
echo 'script_oid("4.5.6");' > "$W/vt/var/lib/openvas/24.10/vt-data/nasl/b.nasl"
tar -czf "$R/blobs/vt.tgz" -C "$W/vt" var

# data-objects: a DIFFERENT release directory, 20.08.
mkdir -p "$W/do/var/lib/gvm/data-objects/gvmd/20.08/configs"
echo '<config/>' > "$W/do/var/lib/gvm/data-objects/gvmd/20.08/configs/full.xml"
tar -czf "$R/blobs/do.tgz" -C "$W/do" var

# notus-data: advisories arrive as a tarball inside the image.
mkdir -p "$W/nt/inner/advisories" "$W/nt/var/lib/notus"
echo '{"advisories":[]}' > "$W/nt/inner/advisories/ubuntu.notus"
tar -czf "$W/nt/var/lib/notus/notus-data.tar.gz" -C "$W/nt/inner" advisories
tar -czf "$R/blobs/nt.tgz" -C "$W/nt" var

dig(){ printf 'sha256:%s' "$(shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 \
       || sha256sum "$1" | cut -d' ' -f1)"; }
siz(){ wc -c < "$1" | tr -d ' '; }

BASE_D=$(dig "$R/blobs/base.tgz"); BASE_S=$(siz "$R/blobs/base.tgz")
VT_D=$(dig "$R/blobs/vt.tgz");     VT_S=$(siz "$R/blobs/vt.tgz")
DO_D=$(dig "$R/blobs/do.tgz");     DO_S=$(siz "$R/blobs/do.tgz")
NT_D=$(dig "$R/blobs/nt.tgz");     NT_S=$(siz "$R/blobs/nt.tgz")

# Named by digest, the way the registry serves them. A ":"-separated loop
# cannot be used here: the digest itself contains a colon.
cp "$R/blobs/base.tgz" "$R/blobs/$BASE_D"
cp "$R/blobs/vt.tgz"   "$R/blobs/$VT_D"
cp "$R/blobs/do.tgz"   "$R/blobs/$DO_D"
cp "$R/blobs/nt.tgz"   "$R/blobs/$NT_D"

# A valid tarball that is not any requested blob, for the corrupt case.
mkdir -p "$W/wrong/var/lib/openvas/99.99/vt-data/nasl"
echo 'wrong content' > "$W/wrong/var/lib/openvas/99.99/vt-data/nasl/wrong.nasl"
tar -czf "$R/blobs/wrong.tgz" -C "$W/wrong" var

# Manifests. data-objects deliberately lists the base layer FIRST and as the
# largest, which is what the real registry does.
mkdir -p "$R/manifests"
cat > "$R/manifests/vulnerability-tests" <<EOF
{"layers":[{"digest":"$BASE_D","size":$BASE_S},{"digest":"$VT_D","size":$VT_S}]}
EOF
cat > "$R/manifests/data-objects" <<EOF
{"layers":[{"digest":"$BASE_D","size":$BASE_S},{"digest":"$DO_D","size":$DO_S}]}
EOF
cat > "$R/manifests/notus-data" <<EOF
{"layers":[{"digest":"$BASE_D","size":$BASE_S},{"digest":"$NT_D","size":$NT_S}]}
EOF
# Layers that fetch cleanly but carry no var/ tree at all. Without this the
# "did any layer carry feed data" check is unreachable: a bad repo name fails
# at the manifest, a good one always has data, and nothing covers the middle.
cat > "$R/manifests/base-only" <<EOF
{"layers":[{"digest":"$BASE_D","size":$BASE_S}]}
EOF

# --- the stub curl ---------------------------------------------------------
mkdir -p "$W/bin"
bin_path(){
  local p; p=$(type -P "$1" 2>/dev/null)
  [ -n "$p" ] && [ -x "$p" ] && { printf '%s' "$p"; return 0; }
  for p in /usr/bin/"$1" /bin/"$1" /usr/local/bin/"$1"; do
    [ -x "$p" ] && { printf '%s' "$p"; return 0; }
  done
  return 1
}
for t in bash sh sed grep printf python3 tar gzip cat head wc cut rm mkdir \
         mktemp rmdir find id chown cp sleep sha256sum shasum tr basename dirname \
         tail touch seq; do
  p=$(bin_path "$t") && ln -sf "$p" "$W/bin/$t"
done
for t in tar python3 grep seq; do
  [ -x "$W/bin/$t" ] || { echo "cannot seal a PATH without $t" >&2; exit 2; }
done
# The helpers call sha256sum; on a mac only shasum exists, so provide it.
if [ ! -x "$W/bin/sha256sum" ]; then
  printf '#!/bin/sh\nexec shasum -a 256 "$@"\n' > "$W/bin/sha256sum"
  chmod +x "$W/bin/sha256sum"
fi

cat > "$W/bin/curl" <<CURL
#!/usr/bin/env bash
# Serves the fake registry from disk. MODE injects failures.
R="$R"
url=""; out=""; resume=0; hdr=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift ;;
    -C) resume=1; shift ;;
    -H) case "\$2" in Authorization:*) hdr="\$2" ;; esac; shift ;;
    http*|https*) url="\$1" ;;
  esac
  shift
done
echo "\$url" >> "$W/curl.log"
case "\$url" in
  *"/service/token"*)
    # Each token is good for a single blob request, which is what forces the
    # fetcher to re-mint one for a resumed transfer. A registry token really
    # does expire, and the blob that needs resuming is exactly the blob whose
    # transfer outlived its token.
    n=\$(cat "$W/tokens.n" 2>/dev/null || echo 0); n=\$((n+1))
    printf '%s' "\$n" > "$W/tokens.n"
    printf '{"token":"tok-%s"}' "\$n"
    exit 0 ;;
  *"/manifests/latest"*)
    repo=\$(printf '%s' "\$url" | sed -E 's|.*/community/([^/]+)/manifests.*|\\1|')
    # arm64 is listed FIRST, as it may be in any registry. Taking the first
    # child instead of selecting on architecture must therefore fail, not
    # silently happen to work.
    printf '{"manifests":[{"digest":"sha256:arm64-%s","platform":{"architecture":"arm64","os":"linux"}},{"digest":"sha256:child-%s","platform":{"architecture":"amd64","os":"linux"}}]}' "\$repo" "\$repo"
    exit 0 ;;
  *"/manifests/sha256:arm64-"*)
    # A manifest whose layer does not exist in this registry.
    printf '{"layers":[{"digest":"sha256:nonexistent-arm64-layer","size":1}]}'
    exit 0 ;;
  *"/manifests/sha256:child-"*)
    repo=\$(printf '%s' "\$url" | sed -E 's|.*/manifests/sha256:child-||')
    [ -f "\$R/manifests/\$repo" ] || exit 22
    cat "\$R/manifests/\$repo"; exit 0 ;;
  *"/blobs/"*)
    d=\$(printf '%s' "\$url" | sed -E 's|.*/blobs/||')
    src="\$R/blobs/\$d"
    [ -f "\$src" ] || exit 22
    # Spend the token. A token already used for a blob is refused, the way an
    # expired registry token is.
    tk=\$(printf '%s' "\$hdr" | sed -E 's/.*Bearer //')
    if [ -n "\$tk" ] && grep -qxF "\$tk" "$W/spent" 2>/dev/null; then exit 22; fi
    [ -n "\$tk" ] && echo "\$tk" >> "$W/spent"
    if [ "\${MODE:-}" = corrupt ]; then
      # A perfectly valid tarball carrying a var/ tree -- just not the one
      # whose digest was asked for. Only the digest check can tell.
      cat "\$R/blobs/wrong.tgz" > "\$out"; exit 0
    fi
    if [ "\${MODE:-}" = truncate ] && [ ! -f "\$out.tried" ]; then
      # First attempt dies half way, like a filtering device killing it.
      touch "\$out.tried"
      head -c \$(( \$(wc -c < "\$src") / 2 )) "\$src" > "\$out"
      exit 18
    fi
    if [ "\$resume" = 1 ] && [ -s "\$out" ]; then
      have=\$(wc -c < "\$out" | tr -d ' ')
      tail -c +\$(( have + 1 )) "\$src" >> "\$out"
    else
      cat "\$src" > "\$out"
    fi
    exit 0 ;;
esac
exit 22
CURL
chmod +x "$W/bin/curl"

pull(){ # $1 repo, $2 stage, MODE from env -> "rc|files"
  local st="$2" rc
  mkdir -p "$st"
  ( cd "$W" && PATH="$W/bin" MODE="${MODE:-}" "$W/bin/bash" -c \
      "source '$HELPERS'; GB_REGISTRY=fake.local; GB_RETRY_SLEEP=0; \
       gb_oci_pull '$1' '$st'" ) >/dev/null 2>&1
  rc=$?
  printf '%s|%s' "$rc" "$(cd "$st" 2>/dev/null && find var -type f 2>/dev/null | sort | tr '\n' ' ')"
}

echo "greenbone OCI transport regression, file under test: $SRC"

echo
echo "the busybox base layer is fetched and contributes nothing"
S="$W/s1"
check "pull succeeds, only the test files land" "$(MODE= pull vulnerability-tests "$S")" \
      "0|var/lib/openvas/24.10/vt-data/nasl/a.nasl var/lib/openvas/24.10/vt-data/nasl/b.nasl "
check "nothing from the base image was written" \
      "$([ -e "$S/bin" ] && echo leaked || echo clean)" "clean"
# Each blob is deleted as soon as it is unpacked, so peak disk is one layer
# and not the whole set. That is the difference between 224 MiB and 1.7 GiB
# when SCAP is included, on a client laptop with a full disk.
check "blobs are removed as they are unpacked" \
      "$(find "$S/.blobs" -type f 2>/dev/null | wc -l | tr -d ' ')" "0"

echo
echo "data-objects, whose base layer is also its biggest layer"
S="$W/s2"
check "the real data layer is found, not the biggest one" "$(MODE= pull data-objects "$S")" \
      "0|var/lib/gvm/data-objects/gvmd/20.08/configs/full.xml "
echo "   ^ 20.08, not 24.10: the release directory differs per repository,"
echo "     so it has to be discovered rather than assumed."

echo
echo "notus advisories arrive as a tarball inside the image"
S="$W/s3"
check "the inner tarball is staged" "$(MODE= pull notus-data "$S")" \
      "0|var/lib/notus/notus-data.tar.gz "

echo
echo "a transfer killed half way is resumed, not restarted"
S="$W/s4"
: > "$W/curl.log"
check "resumes and completes" "$(MODE=truncate pull vulnerability-tests "$S")" \
      "0|var/lib/openvas/24.10/vt-data/nasl/a.nasl var/lib/openvas/24.10/vt-data/nasl/b.nasl "
check "a fresh token was minted for the retry" \
      "$(grep -c '/service/token' "$W/curl.log" | tr -d ' ' | awk '$1>1{print "yes"} $1<=1{print "no"}')" "yes"

echo
echo "a blob whose digest does not match is discarded"
S="$W/s5"
check "pull fails rather than staging bad data" \
      "$(MODE=corrupt pull vulnerability-tests "$S" | cut -d'|' -f1)" "1"
check "and nothing was left behind" \
      "$(cd "$S" 2>/dev/null && find var -type f 2>/dev/null | wc -l | tr -d ' ')" "0"
check "and the wrong tarball's contents never appeared" \
      "$(cd "$S" 2>/dev/null && find var -name 'wrong.nasl' 2>/dev/null | wc -l | tr -d ' ')" "0"

echo
echo "a repository whose layers fetch but carry no feed data"
check "reported as a failure, not a success" "$(MODE= pull base-only "$W/s7")" "1|"

echo
echo "a mismatched blob is deleted, so the next attempt is not poisoned"
# Driven directly, because the damage from keeping the file shows up on the
# NEXT attempt: curl -C - appends the good bytes onto the bad ones.
BLOB="$W/direct.tgz"; rm -f "$BLOB" "$BLOB.tried"
( cd "$W" && PATH="$W/bin" MODE=corrupt "$W/bin/bash" -c \
    "source '$HELPERS'; GB_REGISTRY=fake.local; GB_RETRY_SLEEP=0; GB_RETRIES=1; \
     gb_oci_blob vulnerability-tests '$VT_D' '$BLOB' '$VT_S'" ) >/dev/null 2>&1
check "the mismatched file is gone" \
      "$([ -e "$BLOB" ] && echo kept || echo deleted)" "deleted"
( cd "$W" && PATH="$W/bin" MODE= "$W/bin/bash" -c \
    "source '$HELPERS'; GB_REGISTRY=fake.local; GB_RETRY_SLEEP=0; \
     gb_oci_blob vulnerability-tests '$VT_D' '$BLOB' '$VT_S'" ) >/dev/null 2>&1
check "a fresh attempt lands the real blob" \
      "$(shasum -a 256 "$BLOB" 2>/dev/null | cut -d' ' -f1)" "${VT_D#sha256:}"
check "and it unpacks" \
      "$(tar -tzf "$BLOB" 2>/dev/null | grep -cF '/a.nasl' | tr -d ' ')" "1"

echo
echo "a repository that does not exist"
S="$W/s6"
check "reports failure" "$(MODE= pull no-such-repo "$S" | cut -d'|' -f1)" "1"

echo
echo "only the amd64 image is selected"
# arm64 is listed first in the stub, so this fails if the code takes the
# first child rather than matching on architecture.
check "the arm64 child manifest was never requested" \
      "$(grep -c 'sha256:arm64-' "$W/curl.log" | tr -d ' ')" "0"
check "and no nonexistent arm64 layer was fetched" \
      "$(grep -c 'nonexistent-arm64-layer' "$W/curl.log" | tr -d ' ')" "0"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
