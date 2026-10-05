#!/usr/bin/env bash
#
#  win_facts regression test
#
#  Slices win_facts out of kameki.sh and drives it against a stubbed nxc, so
#  the registry parsing is exercised as written. No Windows host, no
#  credentials, no network.
#
#    ./tests/win-facts.sh
#
#  What it guards against:
#
#    UBR comes back from `reg query` as a REG_DWORD in hexadecimal -- 0xf5a,
#    not 3930. Reading that as decimal, or failing to read it, understates the
#    host's patch level and invents missing updates in the one engine built
#    specifically not to produce false positives.
#
#    InstallationType is what decides which cumulative line applies. Base
#    build 26100 is shared by Windows 11 24H2 and Windows Server 2025, and in
#    September 2026 they required revision 9445 and 33438. A host whose type
#    cannot be read must be reported as unassessed rather than guessed at.
#
#    Command execution over SMB is the first thing EDR blocks, and this scan
#    has already seen hosts authenticate and then return nothing. The
#    transport ladder must fall through, and must report which one worked --
#    PCI DSS 11.3.1.2.a asks for the collection method per host.
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

HELPERS=$(mktemp)
{
  echo 'set -uo pipefail'
  echo 'have(){ command -v "$1" >/dev/null 2>&1; }'
  echo 'U=svc_scan; P=secret'
  sed -n "/^WIN_CV_KEY=/p" "$SRC"
  sed -n '/^win_facts(){/,/^}$/p' "$SRC"
} > "$HELPERS"
grep -q 'win_facts' "$HELPERS" || { echo "cannot find win_facts in $SRC" >&2; exit 2; }

W=$(mktemp -d)
trap 'rm -f "$HELPERS"; rm -rf "$W"' EXIT
# Resolve to a real filesystem path. `command -v` returns the bare word for
# an alias or a shell builtin, and `ln -s grep grep` then makes a broken
# self-referential symlink -- which silently removes grep from the sealed PATH
# and makes every case fail for a reason that has nothing to do with the code
# under test. type -P skips aliases, functions and builtins.
bin_path(){
  local p
  p=$(type -P "$1" 2>/dev/null)
  [ -n "$p" ] && [ -x "$p" ] && { printf '%s' "$p"; return 0; }
  for p in /usr/bin/"$1" /bin/"$1" /usr/local/bin/"$1"; do
    [ -x "$p" ] && { printf '%s' "$p"; return 0; }
  done
  return 1
}

mkdir -p "$W/bin"
for t in bash sh sed grep printf python3 timeout cut head env tr sort awk; do
  p=$(bin_path "$t") && ln -sf "$p" "$W/bin/$t"
done
for t in sed grep python3; do
  [ -x "$W/bin/$t" ] || { echo "cannot seal a PATH without $t" >&2; exit 2; }
done
# GNU timeout may be absent on a dev machine; win_facts needs the name to exist.
[ -x "$W/bin/timeout" ] || printf '#!/bin/sh\nshift\nexec "$@"\n' > "$W/bin/timeout"
chmod +x "$W/bin/timeout"

# A stub nxc. SCENARIO decides which transport answers and with what, so the
# ladder and the parsing are both exercised.
cat > "$W/bin/nxc" <<'NXC'
#!/usr/bin/env bash
proto="$1"
mode=""
for a in "$@"; do case "$a" in -x) mode=x ;; -X) mode=X ;; esac; done
pfx="SMB         10.45.10.9      445    WINHOST         "
[ "$proto" = wmi ] && pfx="WMI         10.45.10.9      135    WINHOST         "

say(){ printf '%s%s\n' "$pfx" "$1"; }

banner(){
  say '[*] Windows Server 2022 Build 20348 x64 (name:WINHOST) (domain:corp.local) (signing:True) (SMBv1:False)'
  say '[+] corp.local\svc_scan:secret (Pwn3d!)'
}

case "$SCENARIO" in
  smb-reg)
    [ "$proto" = smb ] && [ "$mode" = x ] || exit 1
    banner
    say '[+] Executed command via wmiexec'
    say 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    say '    CurrentBuildNumber    REG_SZ    20348'
    say '    UBR    REG_DWORD    0xf5a'
    say '    ProductName    REG_SZ    Windows Server 2022 Standard'
    say '    InstallationType    REG_SZ    Server'
    ;;
  edr-blocks-x)
    # Authenticates, then returns nothing useful for -x. PowerShell works.
    if [ "$proto" = smb ] && [ "$mode" = x ]; then banner; say '[-] Execute command failed'; exit 0; fi
    if [ "$proto" = smb ] && [ "$mode" = X ]; then
      banner
      say 'CurrentBuildNumber : 26100'
      say 'UBR                : 9457'
      say 'ProductName        : Windows 11 Pro'
      say 'InstallationType   : Client'
      exit 0
    fi
    exit 1 ;;
  only-wmi)
    if [ "$proto" = smb ]; then banner; say '[-] Execute command failed'; exit 0; fi
    banner
    say '    CurrentBuildNumber    REG_SZ    17763'
    say '    UBR    REG_DWORD    0x241d'
    say '    ProductName    REG_SZ    Windows Server 2019 Datacenter'
    say '    InstallationType    REG_SZ    Server'
    ;;
  no-type)
    # InstallationType missing and ProductName gives nothing away.
    [ "$proto" = smb ] && [ "$mode" = x ] || exit 1
    banner
    say '    CurrentBuildNumber    REG_SZ    26100'
    say '    UBR    REG_DWORD    0x24ee'
    say '    ProductName    REG_SZ    Windows'
    ;;
  product-only)
    # No InstallationType, but the product name says Server.
    [ "$proto" = smb ] && [ "$mode" = x ] || exit 1
    banner
    say '    CurrentBuildNumber    REG_SZ    20348'
    say '    UBR    REG_DWORD    0x1'
    say '    ProductName    REG_SZ    Windows Server 2022 Datacenter'
    ;;
  no-ubr)
    [ "$proto" = smb ] && [ "$mode" = x ] || exit 1
    banner
    say '    CurrentBuildNumber    REG_SZ    20348'
    say '    ProductName    REG_SZ    Windows Server 2022 Standard'
    say '    InstallationType    REG_SZ    Server'
    ;;
  partial)
    # The output arrives but is cut short: UBR is there, the build is not.
    # This passes the "did we get anything" gate, so it is the only way to
    # reach the parser with no build -- and the parser must refuse it rather
    # than substituting a placeholder and assessing against the wrong line.
    [ "$proto" = smb ] && [ "$mode" = x ] || exit 1
    banner
    say '    UBR    REG_DWORD    0xf5a'
    say '    InstallationType    REG_SZ    Server'
    ;;
  dead)
    banner
    say '[-] Execute command failed'
    ;;
esac
exit 0
NXC
chmod +x "$W/bin/nxc"

facts(){ # $1 scenario -> the pipe-delimited facts, or "NONE"
  local out
  out=$(cd "$W" && PATH="$W/bin" SCENARIO="$1" "$W/bin/bash" -c \
        "source '$HELPERS'; win_facts 10.45.10.9 || echo NONE" 2>/dev/null | tail -1)
  printf '%s' "${out:-NONE}"
}

echo "win_facts regression, file under test: $SRC"

echo
echo "reg query over SMB, the ordinary case"
# 0xf5a is 3930. Read as decimal it is nothing, and the host's patch level
# would be unknown or understated.
check "build, hex UBR decoded, kind, method" "$(facts smb-reg)" \
      "20348|3930|server|Windows Server 2022 Standard|smb-reg"

echo
echo "EDR blocks command execution, PowerShell answers"
check "falls through and reports the transport that worked" "$(facts edr-blocks-x)" \
      "26100|9457|client|Windows 11 Pro|smb-ps"
echo "   ^ 26100 as a CLIENT. Server 2025 shares that build and needed 33438."

echo
echo "only WMI answers"
check "falls through twice, 0x241d decoded" "$(facts only-wmi)" \
      "17763|9245|server|Windows Server 2019 Datacenter|wmi-reg"

echo
echo "InstallationType missing"
check "kind left empty rather than guessed" "$(facts no-type)" \
      "26100|9454||Windows|smb-reg"
echo "   ^ empty kind: the stage reports the host unassessed instead of"
echo "     picking a cumulative line and inventing a missing patch."

echo
echo "InstallationType missing but the product name says Server"
check "falls back to the product name" "$(facts product-only)" \
      "20348|1|server|Windows Server 2022 Datacenter|smb-reg"

echo
echo "the build reads but the revision does not"
check "build kept, revision empty" "$(facts no-ubr)" \
      "20348||server|Windows Server 2022 Standard|smb-reg"

echo
echo "the output arrives but is cut short before the build"
check "refuses to assess rather than substituting a build" \
      "$(facts partial)" "NONE"

echo
echo "nothing can be read at all"
check "reports failure rather than inventing facts" "$(facts dead)" "NONE"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
