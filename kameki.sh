#!/usr/bin/env bash
#
#  kameki.sh  -  Authenticated vulnerability assessment, self provisioning
#
#  Subcommands
#    install            install every dependency (needs internet)
#    install --bundle F install from an offline bundle (no internet)
#    install --no-nvt   install without the Greenbone/NVT backend, the
#                       standalone engine is used instead
#    update             refresh templates, CVE data and definitions
#    setup-greenbone    certificates, services, admin user and GMP
#                       credentials. run by install automatically
#    bundle             build an offline bundle at the office
#    doctor             diagnose what is missing or broken, including auth
#    preflight          test credential formats safely against one host
#    run                run the assessment (default)
#    cleanup            shred credentials and remove artifacts
#
#  Engines
#    nvt         full Greenbone NVT feed (~100k scripts) over the gvmd
#                socket. No web UI.
#    standalone  WES-NG patch mapping, nmap NSE, service CVE mapping.
#    both        run both. ENGINE=auto picks this whenever Greenbone is
#                usable, because the two cover different ground and the
#                standalone results are not reproduced by the NVT feed.
#
#  On top of whichever engine runs, always: Active Directory assessment,
#  configuration audit, TLS, web, SNMP, CISA KEV correlation, attack path
#  derivation, risk scoring, and a self check on its own authentication
#  depth.
#
#  Typical first use:
#    ./kameki.sh install                   # at the office, with internet
#    ./kameki.sh bundle                    # build the portable bundle
#    # carry bundle to client, then on their machine:
#    ./kameki.sh install --bundle kameki-bundle-*.tar.gz
#    ./kameki.sh preflight                 # confirm credential format
#    ./kameki.sh run
#    ./kameki.sh cleanup                   # before you leave site
#
set -uo pipefail

# The scan needs root for nmap's raw sockets, but pipx installs nxc and wes
# into the INVOKING user's ~/.local/bin, and the WES definitions, the KEV
# cache and the shell history all live in that user's home. Under sudo, PATH
# and HOME point at root, so those tools report missing, the caches look
# absent, and cleanup scrubs root's history instead of the one where the
# credentials were actually typed. Re-point both at the invoking user so a
# privileged run sees exactly what an unprivileged one does.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  _KAMEKI_UH=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
  if [ -n "${_KAMEKI_UH:-}" ] && [ -d "${_KAMEKI_UH:-/nonexistent}" ]; then
    [ -d "$_KAMEKI_UH/.local/bin" ] && PATH="$_KAMEKI_UH/.local/bin:$PATH"
    HOME="$_KAMEKI_UH"
    export PATH HOME
  fi
  unset _KAMEKI_UH
fi

VERSION="2.0"
DATE=$(date +%F)
STAMP=$(date +"%Y-%m-%d %H:%M:%S %Z")
RAW="kameki-raw-${DATE}"
MD="kameki-${DATE}.md"
RUN_NAME="kameki-${DATE}-$$"
T0=$(date +%s)

# ---- tunables -------------------------------------------------------
ENGINE="${ENGINE:-auto}"
PROFILE="${PROFILE:-standard}"
JOBS="${JOBS:-16}"
NXC_THREADS="${NXC_THREADS:-32}"
MIN_CVSS="${MIN_CVSS:-4.0}"
NMAP_RATE="${NMAP_RATE:-2000}"
HOST_TIMEOUT="${HOST_TIMEOUT:-20m}"
RESUME="${RESUME:-0}"
POLL="${POLL:-60}"
# 0 means wait as long as the scan takes. A full NVT run against a large
# scope legitimately takes many hours, so this is not capped by default,
# but it is here for a link that drops mid-scan and leaves the task idle.
NVT_MAX_MIN="${NVT_MAX_MIN:-0}"
SCAN_CONFIG="${SCAN_CONFIG:-fast}"
ALIVE_TEST="${ALIVE_TEST:-ICMP, TCP-ACK Service & ARP Ping}"
DEPTH_WARN="${DEPTH_WARN:-3}"      # authenticated findings per host below which we warn
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Microsoft's own security data, as the Windows patch engine. One ~20 MB
# JSON per month over plain HTTPS, which is the point: the Greenbone feed is
# several GB over rsync/873 that a filtering client network kills, and its
# Windows content is a year stale regardless -- the newest Windows
# cumulative-update check in the community feed is dated 2025-10-15, and
# Server 2022 has two checks in total.
#
# Each document states, per CVE, the exact OS build that fixes it. Windows
# 10, 11 and Server 2016+ ship cumulative updates, so comparing the build a
# host reports against the build Microsoft requires IS the supersedence
# check: no version ranges, no CPE matching, nothing copied to the target.
MSRC_API="${MSRC_API:-https://api.msrc.microsoft.com/cvrf/v3.0/cvrf}"
MSRC_MONTHS="${MSRC_MONTHS:-6}"
MSRC_DIR="${MSRC_DIR:-$HOME/.kameki-msrc}"
MSRC_DB="${MSRC_DB:-$HOME/.kameki-msrc/patch-table.json}"

# ---- optional LLM annotation layer ----------------------------------
#  Any OpenAI compatible /v1/chat/completions endpoint: Ollama, vLLM,
#  LM Studio, llama.cpp server. Local by default and gated otherwise,
#  because scan data contains a client's internal network topology,
#  hostnames, patch state and directory structure.
#
#    LLM_ENDPOINT=http://localhost:11434/v1 LLM_MODEL=qwen2.5:72b ./kameki.sh run
#
#  The layer annotates findings the scanners produced. It never creates
#  findings, and the deterministic report is always written first.
LLM_ENDPOINT="${LLM_ENDPOINT:-}"
LLM_MODEL="${LLM_MODEL:-}"
LLM_KEY="${LLM_KEY:-}"
LLM_ALLOW_EXTERNAL="${LLM_ALLOW_EXTERNAL:-0}"
LLM_MAX_CALLS="${LLM_MAX_CALLS:-60}"
LLM_TIMEOUT="${LLM_TIMEOUT:-120}"

NUCLEI_VER="${NUCLEI_VER:-3.4.10}"
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip"
VULSCAN_REPO="https://github.com/scipag/vulscan"
TESTSSL_REPO="https://github.com/drwetter/testssl.sh"
NETEXEC_REPO="git+https://github.com/Pennyw0rth/NetExec"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; RST=$'\e[0m'
info(){ echo "${GRN}[+]${RST} $*"; }
warn(){ echo "${YEL}[!]${RST} $*"; }
err(){  echo "${RED}[-]${RST} $*"; }
step(){ echo; echo "${CYN}── $* ${RST}"; }
dim(){  echo "${DIM}    $*${RST}"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# zstd compresses the Greenbone feed far better than gzip, but it is not always
# installable on a client box -- on a recent Ubuntu behind a filtering proxy the
# apt mirror timed out and zstd was one of the packages that did not arrive.
# The bundle ships zstd's own .deb, which is no help at all when you need zstd
# to unpack the bundle to reach it. So the OUTER archive is always gzip, which
# every box already has, and only the inner feed archives use zstd when it is
# available. GNU tar sniffs the compression on extraction, so both old
# .tar.zst bundles and new .tar.gz ones unpack with the same command.
tar_in(){       # $1 archive, rest: passed to tar -> extract, whatever it is
  local a="$1"; shift
  case "$a" in
    *.zst|*.tzst)
      have zstd || {
        err "this bundle is zstd-compressed and zstd is not installed"
        dim "either: sudo apt install zstd -y"
        dim "or rebuild the bundle with a newer kameki, which uses gzip for the"
        dim "outer archive precisely so this cannot happen on a client box"
        return 1
      } ;;
  esac
  tar -xf "$a" "$@"
}
# tar_out BASE ARGS... -> writes BASE.tar.zst or BASE.tar.gz, echoes which
tar_out(){
  local base="$1"; shift
  if have zstd && tar --zstd -cf "$base.tar.zst" "$@" 2>/dev/null; then
    printf '%s' "$base.tar.zst"
  elif tar -czf "$base.tar.gz" "$@" 2>/dev/null; then
    printf '%s' "$base.tar.gz"
  else
    return 1
  fi
}
# Everything that talks to gvmd goes through kameki_gmp.py, which speaks GMP
# with python-gvm and parses the replies as XML.
#
# This used to be gvm-cli plus sed and grep, and it was wrong in ways that only
# showed up at client sites. gvmd puts an entire response on one line, so
# `grep -c '<config id='` answered 1 however many configs existed and the
# operator was told the feed had not imported. Worse, the first <name> inside a
# <config> is <owner><name>admin</name>, so every scan config was read as being
# called "admin" and the requested one never matched. The report blob sits after
# </report_format>, not inside <report>, so reading the wrong one wrote an empty
# CSV. None of that is fixable in a shell pipeline; it is three lines of
# ElementTree.
#
# gvm-cli also refuses to run as root by design, which forced a runuser wrapper
# that had to guess which account to drop to, and it took the GMP password as a
# command-line argument -- visible in `ps` to every user on the box, and left
# behind in shell history. python-gvm needs neither: the socket is opened as
# whoever invoked the script, and credentials are read from files.
KAMEKI_GMP=""
GMP_PY_INTERP=""

# kameki_gmp.py ships beside this script. When the script has been copied
# somewhere on its own, the usual install locations are tried before giving up.
gmp_py_find(){
  [ -n "$KAMEKI_GMP" ] && { printf '%s' "$KAMEKI_GMP"; return 0; }
  local self d c
  self="${BASH_SOURCE[0]:-$0}"
  # Follow a symlink, so /usr/local/bin/kameki -> /opt/kameki/kameki.sh works.
  while [ -L "$self" ]; do
    d=$(dirname -- "$self")
    self=$(readlink -- "$self")
    case "$self" in /*) ;; *) self="$d/$self" ;; esac
  done
  d=$(CDPATH= cd -- "$(dirname -- "$self")" 2>/dev/null && pwd -P) || d=""
  for c in "$d/kameki_gmp.py" /opt/kameki/kameki_gmp.py \
           /usr/local/lib/kameki/kameki_gmp.py \
           /usr/local/share/kameki/kameki_gmp.py; do
    [ -f "$c" ] && { KAMEKI_GMP="$c"; printf '%s' "$c"; return 0; }
  done
  return 1
}

# python-gvm has to be importable by whichever interpreter runs the helper.
# `pipx install gvm-tools` puts it in an isolated venv that the system python3
# cannot see, so that venv is one of the candidates rather than a reason to
# report the library missing.
gmp_py_interp(){
  [ -n "$GMP_PY_INTERP" ] && { printf '%s' "$GMP_PY_INTERP"; return 0; }
  local p
  for p in python3 python \
           "$HOME/.local/share/pipx/venvs/gvm-tools/bin/python" \
           "${SUDO_USER:+/home/$SUDO_USER/.local/share/pipx/venvs/gvm-tools/bin/python}" \
           /root/.local/share/pipx/venvs/gvm-tools/bin/python; do
    [ -n "$p" ] || continue
    command -v "$p" >/dev/null 2>&1 || [ -x "$p" ] || continue
    if "$p" -c 'import gvm' >/dev/null 2>&1; then
      GMP_PY_INTERP="$p"; printf '%s' "$p"; return 0
    fi
  done
  return 1
}

# 0 when a GMP conversation is actually possible.
gmp_py_ready(){ gmp_py_find >/dev/null 2>&1 && gmp_py_interp >/dev/null 2>&1; }

KAMEKI_RAW="${KAMEKI_RAW:-https://raw.githubusercontent.com/CyberKareem/KameKi/main}"
# kameki is routinely installed by wget-ing the one script, which leaves the
# GMP client behind. That is not a harmless omission: with no client to check
# with, setup-greenbone cannot verify the account it just created, takes its
# "created, unverified" branch, and writes a harvested password to
# gmp-pass.txt that gvmd never accepted. Every later Greenbone check then
# fails in a way that reads as a credential problem rather than a missing
# file. So fetch the helper next to ourselves when it is absent.
fetch_gmp_helper(){
  gmp_py_find >/dev/null 2>&1 && return 0
  local self d
  self="${BASH_SOURCE[0]:-$0}"
  d=$(CDPATH= cd -- "$(dirname -- "$self")" 2>/dev/null && pwd -P) || return 1
  [ -w "$d" ] || return 1
  if   have curl; then curl -fsSL "$KAMEKI_RAW/kameki_gmp.py" -o "$d/kameki_gmp.py" 2>/dev/null
  elif have wget; then wget -qO   "$d/kameki_gmp.py" "$KAMEKI_RAW/kameki_gmp.py" 2>/dev/null
  else return 1
  fi
  # A captive portal or an error page saved to that name is worse than nothing:
  # it would be found and then fail with a syntax error instead of a clear
  # missing-file message. Require it to look like the module it claims to be.
  if ! { [ -s "$d/kameki_gmp.py" ] \
         && head -1 "$d/kameki_gmp.py" | grep -q 'python' \
         && grep -q 'def main' "$d/kameki_gmp.py"; }; then
    rm -f "$d/kameki_gmp.py"
    return 1
  fi
  KAMEKI_GMP=""          # clear the cached miss so discovery runs again
  gmp_py_find >/dev/null 2>&1
}

# kameki_msrc.py sits beside this script, like the GMP client.
KAMEKI_MSRC=""
msrc_py_find(){
  [ -n "$KAMEKI_MSRC" ] && { printf '%s' "$KAMEKI_MSRC"; return 0; }
  local self d c
  self="${BASH_SOURCE[0]:-$0}"
  while [ -L "$self" ]; do
    d=$(dirname -- "$self"); self=$(readlink -- "$self")
    case "$self" in /*) ;; *) self="$d/$self" ;; esac
  done
  d=$(CDPATH= cd -- "$(dirname -- "$self")" 2>/dev/null && pwd -P) || d=""
  for c in "$d/kameki_msrc.py" /opt/kameki/kameki_msrc.py \
           /usr/local/lib/kameki/kameki_msrc.py; do
    [ -f "$c" ] && { KAMEKI_MSRC="$c"; printf '%s' "$c"; return 0; }
  done
  return 1
}
# Unlike the GMP client this needs no third-party library, only python3.
msrc_ready(){ have python3 && msrc_py_find >/dev/null 2>&1 && [ -s "$MSRC_DB" ]; }
msrc_py(){ python3 "$(msrc_py_find)" "$@"; }

# Same story as the GMP client: a one-file wget install leaves this behind,
# and then the whole Windows assessment silently falls back to WES-NG alone
# with nothing to say the authoritative check never ran.
fetch_msrc_helper(){
  msrc_py_find >/dev/null 2>&1 && return 0
  local self d
  self="${BASH_SOURCE[0]:-$0}"
  d=$(CDPATH= cd -- "$(dirname -- "$self")" 2>/dev/null && pwd -P) || return 1
  [ -w "$d" ] || return 1
  if   have curl; then curl -fsSL "$KAMEKI_RAW/kameki_msrc.py" -o "$d/kameki_msrc.py" 2>/dev/null
  elif have wget; then wget -qO   "$d/kameki_msrc.py" "$KAMEKI_RAW/kameki_msrc.py" 2>/dev/null
  else return 1
  fi
  if ! { [ -s "$d/kameki_msrc.py" ] \
         && head -1 "$d/kameki_msrc.py" | grep -q 'python' \
         && grep -q 'def main' "$d/kameki_msrc.py"; }; then
    rm -f "$d/kameki_msrc.py"
    return 1
  fi
  KAMEKI_MSRC=""
  msrc_py_find >/dev/null 2>&1
}

# msrc_months N -> the last N months as YYYY-Mon, newest first.
# The current month is published before its Patch Tuesday and is routinely
# almost empty -- 2026-Oct was 9,441 bytes against September's 20,303,321. It
# is still fetched, because kameki_msrc records it as an empty month rather
# than letting it narrow the data window unnoticed.
msrc_months(){
  python3 - "$1" <<'PYMONTHS'
import sys, datetime
n = int(sys.argv[1])
d = datetime.date.today().replace(day=1)
for _ in range(n):
    print("%d-%s" % (d.year, d.strftime("%b")))
    d = (d - datetime.timedelta(days=1)).replace(day=1)
PYMONTHS
}

# Fetch the monthly documents and compile the build table.
msrc_sync(){
  have python3 || { say_err "python3 is needed for the Windows patch engine"; return 1; }
  msrc_py_find >/dev/null 2>&1 || fetch_msrc_helper || {
    say_err "kameki_msrc.py is not beside this script and could not be fetched"
    return 1
  }
  mkdir -p "$MSRC_DIR/cvrf" || return 1
  local m got=0 miss="" url out
  for m in $(msrc_months "$MSRC_MONTHS"); do
    out="$MSRC_DIR/cvrf/$m.json"
    url="$MSRC_API/$m"
    # Short HTTPS requests with no authentication. --max-time is generous
    # because one month is up to 20 MB and a client link is slow.
    if curl -fsSL --retry 3 --retry-delay 2 --max-time 300 \
            -H 'Accept: application/json' "$url" -o "$out.part" 2>/dev/null \
       && [ -s "$out.part" ] \
       && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$out.part" 2>/dev/null
    then mv -f "$out.part" "$out"; got=$((got+1))
    else
      rm -f "$out.part"; miss="$miss $m"
      # A copy from an earlier run is still usable.
      [ -s "$out" ] && got=$((got+1))
    fi
  done
  [ -n "$miss" ] && dim "not fetched:$miss (copies already on disk are still used)"
  [ "$got" -gt 0 ] || { say_err "no MSRC documents available"; return 1; }
  msrc_py build --in "$MSRC_DIR/cvrf" --out "$MSRC_DB" \
    --fetched "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$MSRC_DIR/build.json" 2>&1 || {
      say_err "could not compile the MSRC patch table"
      head -3 "$MSRC_DIR/build.json" | sed 's/^/      /' >&2
      return 1
    }
  return 0
}

# One registry key carries everything the comparison needs:
# CurrentBuildNumber, UBR, ProductName and InstallationType.
#
# InstallationType is the host's own word for whether it is a Server or a
# Client, and that is what decides which cumulative line applies. Base build
# 26100 is shared by Windows 11 24H2 and Windows Server 2025, and in September
# 2026 they required revision 9445 and 33438 respectively -- so guessing wrong
# does not just mislabel the host, it invents a missing patch.
WIN_CV_KEY='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

# win_facts HOST -> "base|ubr|kind|product|method" on stdout, 1 if nothing
# could be read. Several transports are tried, because command execution over
# SMB is the first thing EDR blocks and this scan has already seen hosts
# authenticate and then return nothing. Which transport worked is recorded:
# PCI DSS 11.3.1.2.a asks for the collection method per host, not only the
# finding it produced.
win_facts(){
  local h="$1" raw="" m="" try=""
  for try in smb-reg smb-ps wmi-reg; do
    case "$try" in
      smb-reg) raw=$(timeout 90 nxc smb "$h" -u "$U" -p "$P" \
                       -x "reg query \"$WIN_CV_KEY\"" 2>/dev/null) ;;
      smb-ps)  raw=$(timeout 90 nxc smb "$h" -u "$U" -p "$P" \
                       -X "Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object CurrentBuildNumber,UBR,ProductName,InstallationType | Format-List" 2>/dev/null) ;;
      wmi-reg) have nxc && raw=$(timeout 90 nxc wmi "$h" -u "$U" -p "$P" \
                       -x "reg query \"$WIN_CV_KEY\"" 2>/dev/null) || raw="" ;;
    esac
    raw=$(printf '%s\n' "$raw" \
          | sed -E 's/^(SMB|WMI)[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+//' \
          | grep -v '^\[')
    if printf '%s' "$raw" | grep -qiE 'CurrentBuildNumber|CurrentBuild|UBR'; then
      m="$try"; break
    fi
    raw=""
  done
  [ -n "$raw" ] || return 1
  # The registry text travels in the environment, NOT on stdin: `python3 -`
  # reads the program from stdin, and the heredoc below already occupies it,
  # so anything piped in is silently discarded and the parse sees nothing.
  WIN_FACTS_RAW="$raw" python3 - "$m" <<'PYFACTS'
import os, re, sys
body = os.environ.get("WIN_FACTS_RAW", "")
method = sys.argv[1]


def grab(name):
    # reg query prints "NAME    REG_DWORD    0x1234"; PowerShell's Format-List
    # prints "Name : value". Accept either, and read hex as hex -- UBR comes
    # back as a REG_DWORD, so reading 0x1234 as decimal would understate the
    # patch level and invent missing updates.
    # (.+?) not (\S+): ProductName is "Windows Server 2022 Standard", four
    # words, and a single-token capture matches nothing at all rather than
    # matching part of it -- so the host's product, and with it the
    # client/server fallback, silently went missing.
    m = re.search(r'^\s*%s\s*(?::|\s)\s*(?:REG_\w+\s+)?(.+?)\s*$' % name,
                  body, re.I | re.M)
    if not m:
        return None
    value = m.group(1).strip()
    if value.lower().startswith('0x'):
        try:
            return str(int(value, 16))
        except ValueError:
            return None
    return value


base = grab('CurrentBuildNumber') or grab('CurrentBuild')
ubr = grab('UBR')
product = grab('ProductName') or ''
itype = (grab('InstallationType') or '').lower()
if itype.startswith('serv'):
    kind = 'server'
elif itype:
    kind = 'client'
elif 'server' in product.lower():
    kind = 'server'
else:
    kind = ''
if not base:
    sys.exit(1)
print('%s|%s|%s|%s|%s' % (base, ubr or '', kind, product.replace('|', ' '), method))
PYFACTS
}


# gmp_py SOCKET SUBCOMMAND... -> the helper's JSON on stdout, its exit status.
# Progress goes to stderr, so stdout stays a single parseable object.
gmp_py(){
  local sock="$1"; shift
  local py helper
  helper=$(gmp_py_find) || {
    printf '{"ok":false,"error":"kameki_gmp.py was not found next to %s"}\n' \
      "${BASH_SOURCE[0]:-$0}"
    return 1
  }
  py=$(gmp_py_interp) || {
    printf '%s\n' '{"ok":false,"error":"python-gvm is not installed for any python on this box","hint":"sudo pip3 install --break-system-packages python-gvm"}'
    return 1
  }
  "$py" "$helper" --socket "$sock" \
    --user-file "${GMP_UF:-gmp-user.txt}" \
    --pass-file "${GMP_PF:-gmp-pass.txt}" "$@"
}
# Point gmp_py at a different credential pair. setup-greenbone has to verify an
# account it has only just created, before gmp-user.txt exists, so the pair is
# written to a private directory instead of being passed as arguments.
GMP_UF=""
GMP_PF=""

# jgmp JSON FILTER -> that field, or empty. Keeps the jq noise in one place.
jgmp(){ printf '%s' "$1" | jq -r "$2" 2>/dev/null || true; }
# net_open HOST PORT -> 0 when a TCP connection succeeds inside five seconds.
# Client networks routinely block outbound 80 and 873, and finding that out
# after a long apt run or a 5 GB rsync attempt wastes site time.
net_open(){
  # Bounded by timeout(1) because a blackholed address otherwise stalls for
  # over a minute. Without timeout the probe cannot be bounded, so report
  # reachable rather than risk the stall this check exists to avoid.
  have timeout || return 0
  # /dev/tcp is built into the bash this script already requires, so it needs
  # no extra package and no nc variant that may or may not support -z.
  timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2 && exec 3<&-" >/dev/null 2>&1
}
cnt(){ [ -f "$1" ] || { echo 0; return 0; }
       local n; n=$(grep -c . "$1" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
# count matches safely: always one integer on stdout, never two, never empty.
# `grep -c` prints 0 AND exits 1 on no match, so a bare `|| echo 0` yields "0\n0"
# and every downstream $(( )) fails. head -1 collapses it.
gcnt(){ local n; n=$(grep -c "$@" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
gcnti(){ local n; n=$(grep -ci "$@" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
gcntE(){ local n; n=$(grep -cE "$@" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
gcntiE(){ local n; n=$(grep -ciE "$@" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
# grep -cve counts NON-matching lines; used for 'non-blank line count'
nblines(){ local n; n=$(grep -cve '^[[:space:]]*$' "$1" 2>/dev/null | head -1 | tr -cd '0-9'); echo "${n:-0}"; }
pool(){ while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 0.2; done; "$@" & }
finish(){ wait; }
is_done(){ [ "$RESUME" = "1" ] && [ -f "$RAW/.done-$1" ]; }
mark_done(){ touch "$RAW/.done-$1"; }

need_root(){ [ "$(id -u)" -eq 0 ] || { err "this needs root: sudo $0 $*"; exit 1; }; }

# ---------------------------------------------------------------------
#  Bounded nxc, and per-protocol target lists
#
#  A TCP connect to a filtered port does not fail, it blocks on SYN
#  retries, which is over two minutes per host on a default Linux. nxc has
#  no overall wall-clock cap of its own, so pointing five protocols at
#  every live host turns one firewalled segment into a stall of hours with
#  nothing printed. Both halves of that are fixed here: every call is
#  bounded, and each protocol is given only the hosts that answer on its
#  own port.
# ---------------------------------------------------------------------
NXC_CAP="${NXC_CAP:-15m}"
# Stage 10's tools had no bound at all, and testssl.sh with --sneaky is
# deliberately slow. On a filtered network a TLS handshake hangs rather than
# being refused, so one endpoint can hold a worker indefinitely: an eight hour
# Stage 10 on 39 hosts, with nothing on screen, was the result. Every external
# call in that stage is now capped, and anything cut short is recorded rather
# than counted as a clean endpoint.
TLS_CAP="${TLS_CAP:-10m}"      # per TLS endpoint
WEB_CAP="${WEB_CAP:-30m}"      # the whole nuclei run
SNMP_CAP="${SNMP_CAP:-10m}"    # the whole onesixtyone sweep
nxcq(){
  if have timeout; then timeout -k 20 "$NXC_CAP" nxc "$@"; else nxc "$@"; fi
}

proto_list(){   # $1 name, $2.. ports -> writes targets/$1.txt, echoes the count
  local name="$1"; shift
  local out="$RAW/targets/$name.txt" p h
  mkdir -p "$RAW/targets"; : > "$out"
  if [ -s "$RAW/ports/map.txt" ]; then
    for p in "$@"; do
      awk -v w="$p" '{n=split($2,a,",");for(i=1;i<=n;i++) if(a[i]==w) print $1}' \
          "$RAW/ports/map.txt"
    done | sort -uV > "$out"
  fi
  # The port scan can be dropped in transit and report nothing at all while
  # services are in fact listening. Only a COMPLETELY empty map triggers the
  # direct probe: a populated map means the scan worked, and is authoritative
  # about which ports are open. Falling back per protocol instead would spend
  # five seconds a host on every protocol the estate simply does not run.
  if [ ! -s "$out" ] && [ ! -s "$RAW/ports/map.txt" ] && [ -s "$RAW/live.txt" ]; then
    while read -r h; do
      [ -n "$h" ] || continue
      for p in "$@"; do
        if net_open "$h" "$p"; then echo "$h"; break; fi
      done
    done < "$RAW/live.txt" | sort -uV > "$out"
  fi
  cnt "$out"
}

# =====================================================================
#  LLM annotation layer
# =====================================================================
#  Design constraints, deliberate:
#    1. Local endpoints only, unless explicitly overridden. Scan data is
#       a client's internal topology and must not leave their estate.
#    2. The model annotates findings. It cannot create them. Every prompt
#       constrains output to the identifiers supplied.
#    3. The deterministic report is written first and is the deliverable.
#       LLM output is a separate, clearly marked section.
#    4. Responses are cached by content hash, so a rerun on the same data
#       does not re-query and does not drift.

LLM_ON=0
LLM_CALLS=0
LLM_CACHE="$HOME/.kameki-llm-cache"

llm_endpoint_is_local(){
  local h
  h=$(printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[:/].*$##')
  case "$h" in
    localhost|127.*|::1|0.0.0.0) return 0 ;;
    10.*|192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    *) return 1 ;;
  esac
}

llm_init(){
  [ -n "$LLM_ENDPOINT" ] || return 1
  if [ -z "$LLM_MODEL" ]; then
    warn "LLM_ENDPOINT set but LLM_MODEL is not, annotation layer disabled"
    return 1
  fi
  have curl || { warn "curl required for the LLM layer"; return 1; }

  if ! llm_endpoint_is_local "$LLM_ENDPOINT"; then
    if [ "$LLM_ALLOW_EXTERNAL" != "1" ]; then
      err "LLM_ENDPOINT is not a local address: $LLM_ENDPOINT"
      dim "scan data contains the client's internal hostnames, addresses,"
      dim "patch state and directory structure. Sending it to a third party"
      dim "processor is very likely outside your engagement terms."
      dim "if you have written authorisation, set LLM_ALLOW_EXTERNAL=1"
      return 1
    fi
    warn "using an EXTERNAL LLM endpoint: $LLM_ENDPOINT"
    warn "client scan data will leave this machine. confirm this is authorised."
  fi

  local probe
  probe=$(curl -s --max-time 15 "${LLM_ENDPOINT%/}/models" \
            ${LLM_KEY:+-H "Authorization: Bearer $LLM_KEY"} 2>&1)
  if ! echo "$probe" | grep -q '"'; then
    warn "LLM endpoint did not respond, annotation layer disabled"
    dim "tried: ${LLM_ENDPOINT%/}/models"
    return 1
  fi
  mkdir -p "$LLM_CACHE"
  LLM_ON=1
  info "LLM annotation layer: $LLM_MODEL at $LLM_ENDPOINT $(llm_endpoint_is_local "$LLM_ENDPOINT" && echo '(local)' || echo '(EXTERNAL)')"
  return 0
}

# llm_ask <system_prompt> <user_prompt>  -> model text on stdout, empty on failure
llm_ask(){
  [ "$LLM_ON" -eq 1 ] || return 1
  if [ "$LLM_CALLS" -ge "$LLM_MAX_CALLS" ]; then return 1; fi

  local sys="$1" usr="$2" key resp body
  key=$(printf '%s\n%s\n%s' "$LLM_MODEL" "$sys" "$usr" | sha256sum | cut -c1-40)
  if [ -f "$LLM_CACHE/$key" ]; then cat "$LLM_CACHE/$key"; return 0; fi

  body=$(jq -n --arg m "$LLM_MODEL" --arg s "$sys" --arg u "$usr" \
    '{model:$m, temperature:0, stream:false,
      messages:[{role:"system",content:$s},{role:"user",content:$u}]}')

  resp=$(curl -s --max-time "$LLM_TIMEOUT" "${LLM_ENDPOINT%/}/chat/completions" \
           -H 'Content-Type: application/json' \
           ${LLM_KEY:+-H "Authorization: Bearer $LLM_KEY"} \
           -d "$body" 2>/dev/null)
  LLM_CALLS=$((LLM_CALLS+1))

  local out
  out=$(printf '%s' "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null)
  # strip reasoning blocks some models emit
  out=$(printf '%s' "$out" | sed -E 's/<think>.*<\/think>//g' | sed '/^[[:space:]]*$/d')
  [ -n "$out" ] || return 1
  printf '%s' "$out" > "$LLM_CACHE/$key"
  printf '%s' "$out"
}


# =====================================================================
#  install
# =====================================================================
cmd_install(){
  local BUNDLE="" WITH_NVT=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --bundle) BUNDLE="$2"; shift 2 ;;
      --no-nvt) WITH_NVT=0; shift ;;
      *) shift ;;
    esac
  done

  step "kameki install  (offline bundle: ${BUNDLE:-none})"
  need_root install

  local OFF=0
  [ -n "$BUNDLE" ] && OFF=1

  if [ "$OFF" -eq 1 ]; then
    [ -f "$BUNDLE" ] || { err "bundle not found: $BUNDLE"; exit 1; }
    local B="/tmp/kameki-bundle-$$"
    mkdir -p "$B"
    info "unpacking bundle"
    if [[ "$BUNDLE" == *.zst ]]; then
      tar_in "$BUNDLE" -C "$B" || exit 1
    else
      tar -xzf "$BUNDLE" -C "$B"
    fi

    if [ -d "$B/deb" ]; then
      info "installing system packages from bundle"
      dpkg -i "$B"/deb/*.deb >/dev/null 2>&1 || apt-get -f install -y >/dev/null 2>&1
    fi
    if [ -d "$B/wheels" ]; then
      info "installing python tools from bundle"
      pip3 install --break-system-packages --no-index --find-links "$B/wheels" netexec wesng gvm-tools python-gvm >/dev/null 2>&1 \
        || warn "python tool install reported errors"
    fi
    [ -f "$B/nuclei" ]        && { install -m755 "$B/nuclei" /usr/local/bin/nuclei; info "nuclei installed"; }
    [ -d "$B/nuclei-templates" ] && { mkdir -p /root/.local/nuclei-templates; cp -r "$B/nuclei-templates/." /root/.local/nuclei-templates/; info "nuclei templates installed"; }
    [ -d "$B/vulscan" ]      && { cp -r "$B/vulscan" /usr/share/nmap/scripts/; nmap --script-updatedb >/dev/null 2>&1; info "vulscan installed"; }
    [ -d "$B/testssl.sh" ]   && { cp -r "$B/testssl.sh" /opt/; ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; info "testssl.sh installed"; }
    [ -f "$B/definitions.zip" ] && { cp "$B/definitions.zip" "${SUDO_USER:+/home/$SUDO_USER/}definitions.zip" 2>/dev/null || cp "$B/definitions.zip" /root/; info "WES-NG definitions installed"; }
    [ -f "$B/kev.json" ]     && { cp "$B/kev.json" "${SUDO_USER:+/home/$SUDO_USER/}.kameki-kev.json" 2>/dev/null || cp "$B/kev.json" /root/.kameki-kev.json; info "KEV catalogue installed"; }
    if [ -f "$B/msrc/patch-table.json" ]; then
      _MD="${SUDO_USER:+/home/$SUDO_USER}"; _MD="${_MD:-/root}/.kameki-msrc"
      mkdir -p "$_MD" && cp "$B/msrc/patch-table.json" "$_MD/patch-table.json" \
        && { [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$_MD" 2>/dev/null; \
             info "Microsoft patch data installed"; }
    fi
    [ -f "$B/kameki_msrc.py" ] && { cp "$B/kameki_msrc.py" "$(dirname -- "${BASH_SOURCE[0]:-$0}")/" 2>/dev/null && info "Windows patch engine installed"; }

    for FEEDTAR in "$B/openvas-feed.tar.zst" "$B/openvas-feed.tar.gz"; do
      [ -f "$FEEDTAR" ] && break
    done
    if [ -f "$FEEDTAR" ]; then
      info "restoring Greenbone NVT feed, this takes a few minutes"
      mkdir -p /var/lib/openvas
      tar_in "$FEEDTAR" -C /var/lib/openvas
      chown -R _gvm:_gvm /var/lib/openvas 2>/dev/null || true
      info "feed restored: $(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l) NVTs"
    fi
    for GVMTAR in "$B/gvm-data.tar.zst" "$B/gvm-data.tar.gz"; do
      [ -f "$GVMTAR" ] && break
    done
    if [ -f "$GVMTAR" ]; then
      info "restoring gvmd data"
      tar_in "$GVMTAR" -C /var/lib
      chown -R _gvm:_gvm /var/lib/gvm 2>/dev/null || true
    fi
    rm -rf "$B"
    info "offline install complete"
    dim "run: $0 doctor"
    return 0
  fi

  # ---- online install
  local DEGRADED=0

  # Check the two egress paths the online install needs before using them.
  if net_open archive.ubuntu.com 80 || net_open deb.debian.org 80 \
     || net_open security.ubuntu.com 80; then :; else
    warn "no outbound access to the distribution mirrors on port 80"
    dim "package installation will fail here. build a bundle where you do"
    dim "have internet, then carry it in:"
    dim "  sudo $0 bundle"
    dim "  sudo $0 install --bundle <file>"
    DEGRADED=1
  fi
  if [ "$WITH_NVT" -eq 1 ] && ! net_open feed.community.greenbone.net 873; then
    warn "no outbound access to the Greenbone feed on rsync port 873"
    dim "the NVT feed cannot sync on this network. the standalone engine"
    dim "needs no feed and produces a full assessment without it:"
    dim "  sudo $0 install --no-nvt"
  fi

  info "updating package lists"
  apt-get update -qq || { warn "apt update had errors"; DEGRADED=1; }

  info "installing system packages"
  # One apt-get call for the whole set is all-or-nothing when a name will not
  # resolve, and returns a single exit code when one download fails. Either way
  # the old code warned once and moved on, so a missing package was only
  # discovered later by doctor. Retry individually and name what is missing.
  local -a SYS_PKGS=(nmap jq gawk curl git zstd unzip python3-pip pipx
                     exploitdb onesixtyone poppler-utils)
  local MISSING_PKGS="" pkg
  if ! apt-get install -y -qq "${SYS_PKGS[@]}" >/dev/null 2>&1; then
    warn "bulk package install failed, retrying one at a time"
    for pkg in "${SYS_PKGS[@]}"; do
      apt-get install -y -qq "$pkg" >/dev/null 2>&1 \
        || MISSING_PKGS="$MISSING_PKGS $pkg"
    done
  fi
  if [ -n "$MISSING_PKGS" ]; then
    warn "could not install:$MISSING_PKGS"
    dim "nmap, jq, gawk and curl are required; the rest are optional"
    dim "install them by hand, or build a bundle where you have internet:"
    dim "  sudo $0 bundle    then on site:  sudo $0 install --bundle <file>"
    DEGRADED=1
  fi

  if [ "$WITH_NVT" -eq 1 ]; then
    info "installing Greenbone scanner backend"
    apt-get install -y -qq openvas-scanner ospd-openvas gvmd redis-server >/dev/null 2>&1 \
      || warn "Greenbone packages unavailable in this repo, standalone engine will be used"
  fi

  info "installing python tools"
  local PIPX_HOME_DIR="${SUDO_USER:+/home/$SUDO_USER/.local}"
  su "${SUDO_USER:-root}" -c "pipx install $NETEXEC_REPO" >/dev/null 2>&1 || \
    pip3 install --break-system-packages "$NETEXEC_REPO" >/dev/null 2>&1 || warn "netexec install failed"
  su "${SUDO_USER:-root}" -c "pipx install wesng" >/dev/null 2>&1 || \
    pip3 install --break-system-packages wesng >/dev/null 2>&1 || warn "wesng install failed"
  su "${SUDO_USER:-root}" -c "pipx install gvm-tools" >/dev/null 2>&1 || \
    pip3 install --break-system-packages gvm-tools >/dev/null 2>&1 || warn "gvm-tools install failed"
  # kameki_gmp.py needs the python-gvm LIBRARY importable, not the gvm-cli
  # binary. pipx hides gvm-tools' dependencies inside its own venv, which the
  # system interpreter cannot see -- but gmp_py_interp knows to look in that
  # venv, so a successful `pipx install gvm-tools` is already enough.
  #
  # Every route is tried because on a restricted client network the apt mirror
  # may not answer: python3-pip was one of the packages that failed to arrive
  # on a recent Ubuntu behind a filtering proxy, which left no pip to install
  # python-gvm with, and the old code then declared the NVT engine dead when
  # the pipx venv had the library all along.
  if fetch_gmp_helper; then dim "GMP client present ($(gmp_py_find))"
  else warn "kameki_gmp.py is missing and could not be fetched"
       dim "the NVT engine needs it. put it beside this script:"
       dim "  wget -O $(dirname -- "${BASH_SOURCE[0]:-$0}")/kameki_gmp.py \\"
       dim "    $KAMEKI_RAW/kameki_gmp.py"
  fi
  install_python_gvm(){
    gmp_py_interp >/dev/null 2>&1 && return 0
    pip3 install --break-system-packages python-gvm >/dev/null 2>&1 && return 0
    python3 -m pip install --break-system-packages python-gvm >/dev/null 2>&1 && return 0
    # Debian and Ubuntu package the library itself, no pip needed.
    apt-get install -y -qq python3-gvm >/dev/null 2>&1 && return 0
    # No pip at all? bootstrap one and retry.
    python3 -m ensurepip --upgrade >/dev/null 2>&1 \
      && python3 -m pip install --break-system-packages python-gvm >/dev/null 2>&1 \
      && return 0
    python3 -m pip install python-gvm >/dev/null 2>&1 && return 0
    GMP_PY_INTERP=""     # discovery may have cached a miss
    gmp_py_interp >/dev/null 2>&1
  }
  if install_python_gvm; then
    dim "python-gvm ok ($(gmp_py_interp))"
  else
    warn "python-gvm could not be installed, so the NVT engine is unavailable"
    dim "the standalone engine is unaffected and the run will still work"
    dim "to fix it later, any one of these is enough:"
    dim "  sudo apt install python3-gvm -y"
    dim "  sudo pip3 install --break-system-packages python-gvm"
    dim "  pipx install gvm-tools      (kameki finds the library in its venv)"
  fi
  su "${SUDO_USER:-root}" -c "pipx ensurepath" >/dev/null 2>&1 || true

  if ! have nuclei; then
    info "installing nuclei $NUCLEI_VER"
    local T; T=$(mktemp -d)
    if curl -sL --max-time 300 -o "$T/n.zip" "$NUCLEI_URL" && unzip -qo "$T/n.zip" -d "$T"; then
      install -m755 "$T/nuclei" /usr/local/bin/nuclei && info "nuclei installed"
    else
      warn "nuclei download failed, get the binary from github.com/projectdiscovery/nuclei/releases"
    fi
    rm -rf "$T"
  fi
  if [ ! -d /usr/share/nmap/scripts/vulscan ]; then
    info "installing vulscan offline CVE database"
    git clone -q --depth 1 "$VULSCAN_REPO" /usr/share/nmap/scripts/vulscan >/dev/null 2>&1 \
      && nmap --script-updatedb >/dev/null 2>&1 && info "vulscan installed" \
      || warn "vulscan clone failed"
  fi

  if [ ! -d /opt/testssl.sh ]; then
    info "installing testssl.sh"
    git clone -q --depth 1 "$TESTSSL_REPO" /opt/testssl.sh >/dev/null 2>&1 \
      && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && info "testssl.sh installed" \
      || warn "testssl.sh clone failed"
  fi

  # Every data source is refreshed by one pass, so installing and updating
  # cannot drift apart and each result is reported individually.
  cmd_update || DEGRADED=1

  if have gvmd && [ "$WITH_NVT" -eq 1 ]; then
    echo
    cmd_setup_greenbone || {
      warn "Greenbone is not usable yet; the standalone engine is unaffected"
      dim "retry later with: sudo $0 setup-greenbone"
    }
  fi

  echo
  if [ "$DEGRADED" -eq 1 ]; then
    warn "install finished with errors, some components are missing"
  else
    info "install complete"
  fi
  dim "open a new shell for PATH changes, then: $0 doctor"
}

# =====================================================================
#  bundle   (build at the office, carry to site)
# =====================================================================
cmd_bundle(){
  step "Building offline bundle"
  local OUT=""   # set once the archive is written, extension depends on zstd
  local B; B=$(mktemp -d)
  have zstd || dim "zstd absent, the bundle will use gzip and be larger"

  info "collecting python wheels"
  mkdir -p "$B/wheels"
  pip3 download -q -d "$B/wheels" "$NETEXEC_REPO" wesng gvm-tools python-gvm >/dev/null 2>&1 \
    || warn "wheel download incomplete"

  info "collecting system packages"
  mkdir -p "$B/deb"
  ( cd "$B/deb" && apt-get download nmap jq gawk curl git zstd unzip \
      exploitdb onesixtyone poppler-utils >/dev/null 2>&1 ) || warn "deb download incomplete"

  if have nuclei; then
    info "including nuclei binary and templates"
    cp "$(command -v nuclei)" "$B/nuclei"
    for d in "$HOME/.local/nuclei-templates" "$HOME/nuclei-templates"; do
      [ -d "$d" ] && { cp -r "$d" "$B/nuclei-templates"; break; }
    done
  fi
  [ -d /usr/share/nmap/scripts/vulscan ] && { info "including vulscan"; cp -r /usr/share/nmap/scripts/vulscan "$B/"; }
  [ -d /opt/testssl.sh ] && { info "including testssl.sh"; cp -r /opt/testssl.sh "$B/"; }
  for f in definitions.zip "$HOME/definitions.zip"; do
    [ -f "$f" ] && { info "including WES-NG definitions"; cp "$f" "$B/definitions.zip"; break; }
  done
  [ -f "$HOME/.kameki-kev.json" ] && cp "$HOME/.kameki-kev.json" "$B/kev.json"

  local NVTN=0
  [ -d /var/lib/openvas/plugins ] && NVTN=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l)
  if [ "$NVTN" -gt 10000 ]; then
    info "including Greenbone NVT feed ($NVTN scripts), this is the large part"
    tar_out "$B/openvas-feed" -C /var/lib/openvas plugins >/dev/null \
      || warn "feed archive failed, may need sudo"
    [ -d /var/lib/gvm ] && tar_out "$B/gvm-data" -C /var/lib gvm >/dev/null || true
  else
    warn "NVT feed not present or incomplete ($NVTN scripts), bundle will be standalone only"
    dim "run: sudo greenbone-feed-sync    then rebuild the bundle"
  fi

  cp "$0" "$B/kameki.sh"
  # The GMP client is not optional any more: without it the bundle installs a
  # kameKi that can only run the standalone engine.
  if P=$(gmp_py_find); then cp "$P" "$B/kameki_gmp.py"
  else warn "kameki_gmp.py not found, the bundle will have no NVT engine"; fi
  if P=$(msrc_py_find); then cp "$P" "$B/kameki_msrc.py"
  else warn "kameki_msrc.py not found, the bundle will have no Windows patch engine"; fi
  # The compiled table is a couple of MB and is the whole Windows patch engine,
  # so it rides along rather than being re-fetched on a network that cannot.
  if [ -s "$MSRC_DB" ]; then
    mkdir -p "$B/msrc"
    cp "$MSRC_DB" "$B/msrc/patch-table.json"
    info "including Microsoft patch data ($(du -h "$MSRC_DB" | cut -f1))"
  else
    warn "no compiled MSRC patch table, the bundle will have no Windows patch engine"
    dim "build it first with: sudo $0 update"
  fi
  cat > "$B/README.txt" <<EOF
kameki offline bundle, built $STAMP
NVT scripts included: $NVTN

On the target machine:
  sudo ./kameki.sh install --bundle $OUT
  ./kameki.sh doctor
EOF

  info "compressing"
  # Always gzip for the outer archive: it is mostly already-compressed
  # content, so zstd buys little, and it must unpack on a box where zstd may
  # be missing.
  OUT="kameki-bundle-${DATE}.tar.gz"
  tar -czf "$OUT" -C "$B" . && info "bundle: $OUT ($(du -h "$OUT" | cut -f1))"
  rm -rf "$B"
  dim "carry this to site, then: sudo ./kameki.sh install --bundle $OUT"
}

# =====================================================================
#  doctor
# =====================================================================
cmd_doctor(){
  step "kameki doctor  v$VERSION"
  local ISSUES=0

  echo "  tools"
  for t in nmap nxc nuclei jq awk curl; do
    if have "$t"; then printf "    %-14s ok\n" "$t"
    else printf "    %-14s ${RED}missing${RST}\n" "$t"; ISSUES=$((ISSUES+1)); fi
  done
  local WES=""; for c in wes wes.py; do have "$c" && { WES="$c"; break; }; done
  [ -n "$WES" ] && printf "    %-14s ok (%s)\n" "wes" "$WES" || { printf "    %-14s ${RED}missing${RST}\n" "wes"; ISSUES=$((ISSUES+1)); }
  for t in testssl.sh searchsploit onesixtyone; do
    have "$t" && printf "    %-14s ok\n" "$t" || printf "    %-14s ${YEL}absent (optional)${RST}\n" "$t"
  done
  # The NVT engine needs python-gvm and the helper, not gvm-cli.
  if gmp_py_ready; then
    printf "    %-14s ok (%s)\n" "python-gvm" "$(gmp_py_interp)"
  elif gmp_py_find >/dev/null 2>&1; then
    printf "    %-14s ${YEL}no python has it: sudo pip3 install --break-system-packages python-gvm${RST}\n" "python-gvm"
  else
    printf "    %-14s ${YEL}kameki_gmp.py is not beside this script${RST}\n" "kameki_gmp.py"
  fi

  echo
  echo "  data"
  local NVTN=0
  [ -d /var/lib/openvas/plugins ] && NVTN=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l)
  if [ "$NVTN" -ge 10000 ]; then printf "    %-14s ok (%s scripts)\n" "NVT feed" "$NVTN"
  else
    printf "    %-14s ${YEL}%s scripts, run: sudo greenbone-feed-sync${RST}\n" "NVT feed" "$NVTN"
    dim "with no feed the NVT engine cannot run whatever else is configured;"
    dim "the standalone engine is unaffected and needs no feed"
  fi
  [ -d /usr/share/nmap/scripts/vulscan ] && printf "    %-14s ok\n" "vulscan" || printf "    %-14s ${YEL}absent${RST}\n" "vulscan"
  { [ -f definitions.zip ] || [ -f "$HOME/definitions.zip" ]; } && printf "    %-14s ok\n" "wes defs" || printf "    %-14s ${YEL}run: wes --update${RST}\n" "wes defs"
  [ -f "$HOME/.kameki-kev.json" ] && printf "    %-14s ok\n" "KEV" || printf "    %-14s ${YEL}absent${RST}\n" "KEV"
  if msrc_ready; then
    local MW
    MW=$(msrc_py window --db "$MSRC_DB" 2>/dev/null \
         | python3 -c "import json,sys;w=json.load(sys.stdin)['window'];print('%s..%s, %d month(s)' % (w['earliest'],w['latest'],len(w['months_with_windows_data'])))" 2>/dev/null)
    printf "    %-14s ok (%s)\n" "MSRC data" "${MW:-compiled}"
  elif msrc_py_find >/dev/null 2>&1; then
    printf "    %-14s ${YEL}not compiled, run: sudo %s update${RST}\n" "MSRC data" "$0"
    dim "without it Windows patch level is assessed by WES-NG alone, which"
    dim "reports false positives by its own documentation"
  else
    printf "    %-14s ${YEL}kameki_msrc.py is not beside this script${RST}\n" "MSRC data"
  fi

  echo
  echo "  greenbone"
  local SOCK=""
  for s in /run/gvmd/gvmd.sock /var/run/gvmd/gvmd.sock /run/gvm/gvmd.sock /var/run/gvm/gvmd.sock; do
    [ -S "$s" ] && { SOCK="$s"; break; }
  done
  if [ -n "$SOCK" ]; then
    printf "    %-14s ok (%s)\n" "gvmd socket" "$SOCK"
    if [ -s gmp-user.txt ] && [ -s gmp-pass.txt ] && gmp_py_ready; then
      local R; R=$(gmp_py "$SOCK" check 2>&1)
      if printf '%s' "$R" | grep -q '"ok": *true'; then
        printf "    %-14s ok\n" "gmp auth"
      else
        printf "    %-14s ${RED}failed${RST}\n" "gmp auth"
        # Throwing this away made every GMP problem look identical and had to
        # be re-diagnosed by hand on site. Print what gvmd actually said.
        local GE; GE=$(jgmp "$R" '.error // empty')
        [ -z "$GE" ] && GE=$(printf '%s' "$R" | head -2 | tr '\n' ' ')
        dim "$GE"
        case "$GE" in
          *uthentication*|*uthenticate*)
            dim "gmp-pass.txt holds a password gvmd does not accept. The usual"
            dim "cause is an account created while no GMP client was installed,"
            dim "so it was written without ever being verified. Recreate it:"
            dim "  sudo FEED_SYNC=0 $0 setup-greenbone" ;;
          *)
            dim "recreate the account with: sudo FEED_SYNC=0 $0 setup-greenbone" ;;
        esac
        ISSUES=$((ISSUES+1))
      fi
    else
      printf "    %-14s ${YEL}gmp-user.txt / gmp-pass.txt not set${RST}\n" "gmp auth"
    fi
  else
    printf "    %-14s ${YEL}not running, standalone engine will be used${RST}\n" "gvmd socket"
  fi

  echo
  echo "  inputs"
  for f in targets.txt user.txt pass.txt; do
    if [ -s "$f" ]; then
      local m; m=$(stat -c '%a' "$f")
      if [ "$f" = "targets.txt" ]; then printf "    %-14s ok (%s lines)\n" "$f" "$(cnt "$f")"
      elif [ "$m" = "600" ]; then printf "    %-14s ok (mode 600)\n" "$f"
      else printf "    %-14s ${YEL}mode %s, run: chmod 600 %s${RST}\n" "$f" "$m" "$f"; fi
    else printf "    %-14s ${RED}missing${RST}\n" "$f"; ISSUES=$((ISSUES+1)); fi
  done
  for f in ssh-user.txt ssh-pass.txt gmp-user.txt gmp-pass.txt; do
    [ -s "$f" ] && printf "    %-14s ok\n" "$f" || printf "    %-14s ${DIM}absent (optional)${RST}\n" "$f"
  done

  echo
  echo "  network position"
  local MYIP; MYIP=$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127' | head -3 | tr '\n' ' ')
  printf "    %-14s %s\n" "local addr" "${MYIP:-unknown}"
  if [ -s targets.txt ]; then
    local FIRST; FIRST=$(grep -ve '^\s*$' targets.txt | head -n1)
    if have nmap; then
      local OPEN; OPEN=$(nmap -Pn -p445,3389,22 --host-timeout 20s "$FIRST" 2>/dev/null | grep -c '/open/\|open ')
      printf "    %-14s %s reachable port(s) on %s\n" "reachability" "$OPEN" "$FIRST"
      [ "$OPEN" -eq 0 ] && { warn "    no common ports reachable on the first target"; ISSUES=$((ISSUES+1)); }
    fi
  fi

  echo
  if [ "$ISSUES" -eq 0 ]; then info "no blocking issues. next: $0 preflight"
  else warn "$ISSUES issue(s) to resolve. see above."; fi
  return 0
}

# =====================================================================
#  preflight   (find the working credential format without a spray)
# =====================================================================
cmd_preflight(){
  step "Credential preflight"
  for f in targets.txt user.txt pass.txt; do
    [ -s "$f" ] || { err "missing: $f"; exit 1; }
  done
  have nxc || { err "nxc not installed. run: sudo $0 install"; exit 1; }

  local HOST; HOST=$(grep -ve '^[[:space:]]*$' targets.txt | head -n1)
  local BASE; BASE=$(head -n1 user.txt | tr -d '\r\n')
  local PASS; PASS=$(head -n1 pass.txt | tr -d '\r\n')

  info "probing a single host: $HOST"
  dim "this tries several credential formats against ONE host only"
  dim "at most a handful of failed logins, no estate-wide lockout risk"
  echo

  local BANNER; BANNER=$(nxc smb "$HOST" -u '' -p '' 2>&1 | head -3)
  local DOM;  DOM=$(echo "$BANNER"  | grep -oP '(?<=domain:)[^)]*' | head -1)
  local NAME; NAME=$(echo "$BANNER" | grep -oP '(?<=name:)[^)]*'   | head -1)
  [ -n "$DOM" ]  && info "domain seen on host: $DOM"
  [ -n "$NAME" ] && info "hostname: $NAME"
  echo

  local BARE="${BASE##*\\}"; BARE="${BARE%%@*}"
  local -a FORMATS=("$BASE")
  [ -n "$DOM" ] && FORMATS+=("$DOM\\$BARE" "$BARE@$DOM")
  [ -n "$DOM" ] && FORMATS+=("${DOM%%.*}\\$BARE")
  FORMATS+=("$BARE")

  local WORKING=""
  local -A SEEN=()
  for fmt in "${FORMATS[@]}"; do
    [ -n "${SEEN[$fmt]:-}" ] && continue
    SEEN[$fmt]=1
    printf "    %-34s " "$fmt"
    local OUT; OUT=$(nxc smb "$HOST" -u "$fmt" -p "$PASS" 2>&1)
    if echo "$OUT" | grep -q '\[+\]'; then
      local ADMIN=""; echo "$OUT" | grep -q 'Pwn3d' && ADMIN=" ${CYN}(admin)${RST}"
      echo "${GRN}success${RST}$ADMIN"
      [ -z "$WORKING" ] && WORKING="$fmt"
    else
      local REASON; REASON=$(echo "$OUT" | grep -oE 'STATUS_[A-Z_]+' | head -1)
      echo "${RED}failed${RST} ${DIM}${REASON:-no response}${RST}"
    fi
  done

  echo
  if [ -z "$WORKING" ]; then
    err "no credential format authenticated"
    dim "check the account is enabled and not locked"
    dim "check it has local admin on the target, standard users cannot read patch level"
    dim "if STATUS_LOGON_FAILURE on every format, the password is wrong or expired"
    dim "if STATUS_ACCOUNT_LOCKED_OUT, stop and have the client unlock before retrying"
    return 1
  fi

  info "working format: ${CYN}$WORKING${RST}"

  # does remote execution work? this is what patch level depends on
  printf "    %-34s " "remote command execution"
  local EX; EX=$(nxc smb "$HOST" -u "$WORKING" -p "$PASS" -x 'echo kameki' 2>&1)
  if echo "$EX" | grep -q 'kameki'; then
    echo "${GRN}works${RST}"
  else
    echo "${YEL}blocked${RST}"
    warn "authentication works but remote execution does not"
    dim "the standalone engine cannot read patch level without it"
    dim "likely EDR or policy. the Greenbone NVT engine uses registry reads"
    dim "instead and may still work, so prefer ENGINE=nvt on this estate"
  fi

  echo
  if [ "$WORKING" != "$BASE" ]; then
    read -rp "    write '$WORKING' to user.txt? [y/N] " A
    if [ "${A,,}" = "y" ]; then
      printf '%s\n' "$WORKING" > user.txt; chmod 600 user.txt
      info "user.txt updated"
    fi
  fi
  dim "next: $0 run"
}

# =====================================================================
#  cleanup
# =====================================================================
cmd_cleanup(){
  local PURGE=0 KEEP=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --purge) PURGE=1; shift ;;
      --keep-evidence) KEEP=1; shift ;;
      *) shift ;;
    esac
  done

  step "kameki cleanup"
  local SHRED="rm -f"; have shred && SHRED="shred -u -n3"

  echo "  credentials"
  for f in user.txt pass.txt ssh-user.txt ssh-pass.txt gmp-user.txt gmp-pass.txt; do
    if [ -f "$f" ]; then $SHRED "$f" 2>/dev/null && printf "    %-18s shredded\n" "$f"; fi
  done

  echo
  echo "  credential traces in evidence"
  local N=0
  for d in kameki-raw-*; do
    [ -d "$d" ] || continue
    for f in "$d"/working-creds.txt "$d"/ad/kerberoast-tickets.txt "$d"/ad/asrep-tickets.txt; do
      [ -f "$f" ] && { $SHRED "$f" 2>/dev/null; N=$((N+1)); }
    done
    if [ -d "$d/sysinfo" ]; then
      grep -rl 'Product ID\|Registered Owner' "$d/sysinfo" 2>/dev/null | while read -r x; do
        sed -i '/Product ID/d;/Registered Owner/d' "$x" 2>/dev/null
      done
    fi
  done
  printf "    %-18s %s file(s) removed\n" "hashes/tickets" "$N"

  echo
  echo "  shell history"
  if [ -f "$HOME/.bash_history" ]; then
    # kameKi no longer puts a GMP password in argv, but an older run may have
    # left one in this file, so the pattern stays.
    local H; H=$(gcntiE 'kameki|nxc |gvm-cli' "$HOME/.bash_history")
    sed -i '/nxc .*-p /d;/gvm-cli.*--gmp-password/d' "$HOME/.bash_history" 2>/dev/null
    printf "    %-18s %s line(s) scrubbed\n" "bash_history" "$H"
  fi

  if [ -d /run/gvmd ] && [ -s gmp-user.txt ]; then
    echo
    echo "  gvmd objects"
    dim "scan credentials are already deleted at the end of each run"
  fi

  if [ "$KEEP" -eq 0 ]; then
    echo
    echo "  evidence"
    for d in kameki-raw-*; do
      [ -d "$d" ] || continue
      local SZ; SZ=$(du -sh "$d" 2>/dev/null | cut -f1)
      read -rp "    remove $d ($SZ)? [y/N] " A
      [ "${A,,}" = "y" ] && { rm -rf "$d"; printf "    %-18s removed\n" "$d"; } \
                         || printf "    %-18s kept\n" "$d"
    done
  else
    info "evidence retained (--keep-evidence)"
  fi

  if [ "$PURGE" -eq 1 ]; then
    echo
    warn "--purge removes the installed tooling from this machine"
    read -rp "    proceed? [y/N] " A
    if [ "${A,,}" = "y" ]; then
      need_root cleanup --purge
      apt-get remove -y -qq openvas-scanner ospd-openvas gvmd >/dev/null 2>&1
      rm -rf /usr/share/nmap/scripts/vulscan /opt/testssl.sh /usr/local/bin/nuclei /usr/local/bin/testssl.sh
      rm -rf /var/lib/openvas/plugins
      su "${SUDO_USER:-root}" -c "pipx uninstall netexec; pipx uninstall wesng; pipx uninstall gvm-tools" >/dev/null 2>&1
      info "tooling removed"
    fi
  fi

  echo
  info "cleanup complete"
  [ "$KEEP" -eq 1 ] || dim "reports (kameki-*.md) were not touched, remove them manually if needed"
}

# =====================================================================
#  update   (refresh every data source; run at the end of install too)
# =====================================================================
user_home(){
  local h; h=$(getent passwd "${SUDO_USER:-root}" 2>/dev/null | cut -d: -f6)
  [ -n "$h" ] && echo "$h" || echo "${HOME:-/root}"
}

# pipx puts wes in the invoking user's ~/.local/bin, which is not on root's
# PATH during a sudo install. Resolving it only with `command -v` therefore
# found nothing and the definition update was skipped without a word.
find_wes(){
  local uh c; uh=$(user_home)
  for c in "$uh/.local/bin/wes" "$uh/.local/bin/wes.py" wes wes.py; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}

cmd_update(){
  local FAILED="" UH WESBIN
  UH=$(user_home)
  step "kameki update  (refreshing every data source)"

  if have nuclei; then
    printf "    %-22s" "nuclei templates"
    if nuclei -update-templates -silent >/dev/null 2>&1; then echo "${GRN}ok${RST}"
    else echo "${YEL}failed${RST}"; FAILED="$FAILED nuclei-templates"; fi
  fi

  if [ -d /usr/share/nmap/scripts/vulscan/.git ]; then
    printf "    %-22s" "vulscan CVE database"
    if ( cd /usr/share/nmap/scripts/vulscan && git pull -q ) >/dev/null 2>&1 \
       && nmap --script-updatedb >/dev/null 2>&1; then echo "${GRN}ok${RST}"
    else echo "${YEL}failed${RST}"; FAILED="$FAILED vulscan"; fi
  fi

  if [ -d /opt/testssl.sh/.git ]; then
    printf "    %-22s" "testssl.sh"
    if ( cd /opt/testssl.sh && git pull -q ) >/dev/null 2>&1; then echo "${GRN}ok${RST}"
    else echo "${YEL}failed${RST}"; FAILED="$FAILED testssl.sh"; fi
  fi

  printf "    %-22s" "WES-NG definitions"
  if WESBIN=$(find_wes); then
    # run as the invoking user, from their home, so definitions.zip lands
    # where doctor and the run stage look for it
    if ( cd "$UH" && su "${SUDO_USER:-root}" -c "'$WESBIN' --update" ) >/dev/null 2>&1
    then echo "${GRN}ok${RST}"
    else echo "${YEL}failed${RST}"; FAILED="$FAILED wes-definitions"; fi
  else
    echo "${YEL}wes not installed${RST}"; FAILED="$FAILED wes-definitions"
  fi

  printf "    %-22s" "CISA KEV catalogue"
  if curl -s --max-time 60 -o "$UH/.kameki-kev.json" "$KEV_URL" 2>/dev/null \
     && [ -s "$UH/.kameki-kev.json" ]; then echo "${GRN}ok${RST}"
  else echo "${YEL}failed${RST}"; FAILED="$FAILED kev"; fi

  printf "    %-22s" "MSRC patch data"
  MSRC_DIR="$UH/.kameki-msrc"
  MSRC_DB="$UH/.kameki-msrc/patch-table.json"
  if msrc_sync >/dev/null 2>&1; then
    local MW
    MW=$(msrc_py window --db "$MSRC_DB" 2>/dev/null \
         | python3 -c "import json,sys;w=json.load(sys.stdin)['window'];print('%s..%s' % (w['earliest'],w['latest']))" 2>/dev/null)
    echo "${GRN}ok${RST}${MW:+ ($MW)}"
    [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$UH/.kameki-msrc" 2>/dev/null
  else echo "${YEL}failed${RST}"; FAILED="$FAILED msrc"; fi

  echo
  if [ -n "$FAILED" ]; then
    warn "not refreshed:$FAILED"
    dim "re-run when you have internet: sudo $0 update"
    return 1
  fi
  info "all data sources current"
  return 0
}

# =====================================================================
#  setup-greenbone   (certificates, services, admin user, GMP credentials)
# =====================================================================
# Everything here is idempotent and fail-soft. Greenbone is optional, so a
# failure at any step leaves the standalone engine perfectly usable and must
# never abort the install. The feed itself is deliberately NOT synced here:
# it is ~5 GB over rsync/873 and routinely blocked on client networks, so it
# stays an explicit decision.
GVM_ACCOUNT=""            # the system account gvmd runs as
gvm_service_account(){
  local u
  for u in _gvm gvm; do id -u "$u" >/dev/null 2>&1 && { echo "$u"; return 0; }; done
  return 1
}

# Report a captured failure. A tool that fails silently is worse than one
# that fails loudly, because the blank line reads as a display bug rather
# than a missing message, so silence is named as silence.
say_err(){   # $1: captured output, $2.. a hint to print when it is empty
  if [ -n "${1:-}" ]; then printf '%s\n' "$1" | tail -8 | sed 's/^/      /'
  else shift; dim "the command printed nothing."; [ $# -gt 0 ] && dim "$*"; fi
}

# gvmd keeps every object it owns in PostgreSQL: the role, the database and
# two extensions. Without them it exits immediately at startup, which showed
# up only as "gvmd failed" with no reason, because nothing started postgres
# and nothing printed gvmd's own error.
gvmd_db_ready(){      # $1: the gvm service account, e.g. _gvm
  local acct="$1" out=""
  have psql || { dim "psql not found. install: apt-get install -y postgresql"; return 1; }
  id -u postgres >/dev/null 2>&1 || { dim "no postgres system account"; return 1; }
  _pg(){ runuser -u postgres -- "$@"; }

  if ! _pg psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$acct'" 2>/dev/null \
       | grep -q 1; then
    printf "    %-24s" "postgres role $acct"
    if out=$(_pg createuser -DRS "$acct" 2>&1); then echo "${GRN}created${RST}"
    else echo "${YEL}failed${RST}"; say_err "$out" "check: systemctl is-active postgresql"; return 1; fi
  fi

  if ! _pg psql -tAc "SELECT 1 FROM pg_database WHERE datname='gvmd'" 2>/dev/null \
       | grep -q 1; then
    printf "    %-24s" "gvmd database"
    if out=$(_pg createdb -O "$acct" gvmd 2>&1); then echo "${GRN}created${RST}"
    else echo "${YEL}failed${RST}"; say_err "$out" "check: systemctl is-active postgresql"; return 1; fi
  fi

  # Idempotent, so a partially provisioned box is repaired rather than
  # refused. gvmd needs the dba role and both extensions present.
  printf "    %-24s" "database extensions"
  out=$(_pg psql -q -d gvmd \
          -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' \
          -c 'CREATE EXTENSION IF NOT EXISTS "pgcrypto";' 2>&1)
  if [ -n "$out" ] && printf '%s' "$out" | grep -qi 'error'; then
    echo "${YEL}failed${RST}"; say_err "$out"; return 1
  fi
  _pg psql -q -d gvmd -c 'CREATE ROLE dba WITH SUPERUSER NOINHERIT;' >/dev/null 2>&1 || true
  _pg psql -q -d gvmd -c "GRANT dba TO \"$acct\";"             >/dev/null 2>&1 || true
  echo "${GRN}ok${RST}"

  # The schema is created by gvmd itself the first time it runs, so --migrate
  # is only meaningful once one exists. On a database created a moment ago
  # there is nothing to migrate and gvmd exits non-zero, which is not a
  # fault. Reporting that as "schema migration failed" sent the operator
  # looking for a database problem that was not there.
  printf "    %-24s" "schema"
  if ! _pg psql -d gvmd -tAc \
        "SELECT 1 FROM information_schema.tables WHERE table_name='meta'" \
        2>/dev/null | grep -q 1; then
    echo "${DIM}empty, gvmd creates it on first start${RST}"
    return 0
  fi
  if out=$(runuser -u "$acct" -- gvmd --migrate 2>&1); then
    echo "${GRN}up to date${RST}"
  else
    echo "${YEL}migration failed${RST}"
    say_err "$out" "gvmd will not migrate while an instance is running. \
stop it and re-run: systemctl stop gvmd"
    return 1
  fi
  return 0
}
# gvmd asks ospd-openvas for the VT list while it is starting. With an empty
# plugin directory, or a feed large enough to take minutes to enumerate, that
# request does not return inside systemd's default 90-second start timeout.
# systemd then kills gvmd and restarts it, forever: one site reached restart
# counter 493. Raising the timeout is what breaks the loop, and the loop has
# to be broken before a feed import, because an import takes longer than 90
# seconds and gets killed half way through every time.
GVMD_START_TIMEOUT="${GVMD_START_TIMEOUT:-1800}"
gvmd_fix_start_timeout(){
  local d=/etc/systemd/system/gvmd.service.d
  printf "    %-24s" "gvmd start timeout"
  mkdir -p "$d" 2>/dev/null || { echo "${YEL}cannot write $d${RST}"; return 1; }
  cat > "$d/kameki-timeout.conf" <<CONF
# Written by kameki. gvmd queries ospd-openvas for the VT list during start,
# which exceeds the packaged 90s TimeoutStartSec on a fresh or large feed.
# systemd killed and restarted gvmd indefinitely as a result.
[Unit]
StartLimitIntervalSec=0
[Service]
TimeoutStartSec=${GVMD_START_TIMEOUT}
Restart=on-failure
RestartSec=30
CONF
  systemctl daemon-reload >/dev/null 2>&1
  echo "${GRN}${GVMD_START_TIMEOUT}s${RST}"
}

# A gvmd already in a restart loop must be stopped before the feed work, or
# every import is cut short by the next restart.
gvmd_break_restart_loop(){
  local n
  n=$(systemctl show -p NRestarts --value gvmd 2>/dev/null | tr -cd '0-9')
  systemctl stop gvmd    >/dev/null 2>&1 || true
  systemctl reset-failed gvmd >/dev/null 2>&1 || true
  if [ -n "${n:-}" ] && [ "${n:-0}" -gt 3 ]; then
    printf "    %-24s" "restart loop"
    echo "${YEL}stopped after ${n} restarts${RST}"
  fi
}

nvt_count(){
  local n=0
  [ -d /var/lib/openvas/plugins ] \
    && n=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l | tr -cd '0-9')
  echo "${n:-0}"
}

# The feed is what every other number depends on. Nothing in this script used
# to fetch it, so a clean machine reached the end of setup with 0 plugins, 0
# scan configs and 0 report formats, and was told to go and run the sync by
# hand. It is run here instead. Output is not captured, so rsync progress is
# visible rather than the terminal appearing dead for an hour.
# ---------------------------------------------------------------------------
#  Greenbone feed over HTTPS, as OCI images, instead of rsync
#
#  The community feed is published as container images with the data baked in,
#  anonymous-pullable over 443 and rebuilt daily. That matters because rsync to
#  873 is what fails at client sites: it connects, starts transferring, and the
#  filtering device kills it -- "safe_read failed to read 1 bytes: Connection
#  timed out (110)". Registry blobs answer Range requests with 206, so a killed
#  transfer resumes where it stopped and is verified against its own digest.
#
#  Without SCAP the required set is about 270 MiB in resumable chunks rather
#  than several GB in one stream. SCAP is another 1.5 GiB and is NOT fetched by
#  default: gvmd runs without it, logging "No SCAP database found" and
#  continuing, and CVE references come from each test's own script_cve_id.
#
#  This does not make Greenbone a Windows engine. Its newest Windows
#  cumulative-update test is dated 2025-10-15 and Server 2022 has two tests in
#  total, so Windows patch level comes from the MSRC comparison. What this
#  rescues is the part of Greenbone that is genuinely current: Debian, Ubuntu,
#  SUSE and Fedora-family Linux via Notus.
# ---------------------------------------------------------------------------
GB_REGISTRY="${GB_REGISTRY:-registry.community.greenbone.net}"
GB_REPOS="${GB_REPOS:-vulnerability-tests notus-data data-objects report-formats cert-bund-data dfn-cert-data}"
GB_WITH_SCAP="${GB_WITH_SCAP:-0}"
# Back-off between resume attempts. Configurable so the regression suite
# can drive the failure paths without waiting out real sleeps.
GB_RETRY_SLEEP="${GB_RETRY_SLEEP:-3}"
GB_RETRIES="${GB_RETRIES:-5}"

# A pull token lasts 1800s and is re-minted for every attempt, because a blob
# that needs resuming is exactly the blob whose transfer outlived its token.
gb_oci_token(){
  curl -fsSL --max-time 60 \
    "https://$GB_REGISTRY/service/token?service=harbor-registry&scope=repository:community/$1:pull" \
    2>/dev/null | python3 -c 'import json,sys
try: sys.stdout.write(json.load(sys.stdin)["token"])
except Exception: sys.exit(1)'
}

# gb_oci_layers REPO -> "digest<TAB>size" a line, for the amd64 image.
gb_oci_layers(){
  local repo="$1" tok child
  tok=$(gb_oci_token "$repo") || return 1
  child=$(curl -fsSL --max-time 60 -H "Authorization: Bearer $tok" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
    "https://$GB_REGISTRY/v2/community/$repo/manifests/latest" 2>/dev/null \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
for m in d.get("manifests") or []:
    if (m.get("platform") or {}).get("architecture") == "amd64":
        sys.stdout.write(m["digest"]); break
else:
    sys.exit(1)') || return 1
  curl -fsSL --max-time 60 -H "Authorization: Bearer $tok" \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://$GB_REGISTRY/v2/community/$repo/manifests/$child" 2>/dev/null \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
for l in d.get("layers") or []:
    print("%s\t%d" % (l["digest"], l["size"]))'
}

# gb_oci_blob REPO DIGEST OUT SIZE -> resumable download, verified against the
# digest the registry itself published. A blob that fails verification is
# deleted: a half-written feed file is worse than none, because gvmd will load
# it and report whatever it happens to contain.
gb_oci_blob(){
  local repo="$1" dig="$2" out="$3" want="${4:-0}" try tok have
  for try in $(seq 1 "$GB_RETRIES"); do
    have=0; [ -f "$out" ] && have=$(wc -c < "$out" | tr -d ' ')
    [ "$want" -gt 0 ] && [ "$have" -eq "$want" ] && break
    tok=$(gb_oci_token "$repo") || { sleep "$GB_RETRY_SLEEP"; continue; }
    curl -fsSL --max-time 1800 --speed-time 60 --speed-limit 1024 \
      -C - -H "Authorization: Bearer $tok" \
      "https://$GB_REGISTRY/v2/community/$repo/blobs/$dig" -o "$out" 2>/dev/null
    have=0; [ -f "$out" ] && have=$(wc -c < "$out" | tr -d ' ')
    [ "$want" -gt 0 ] && [ "$have" -eq "$want" ] && break
    [ "$want" -eq 0 ] && [ "$have" -gt 0 ] && break
    dim "  resuming $(printf '%.20s' "${dig#sha256:}") at ${have} of ${want} bytes"
    sleep "$GB_RETRY_SLEEP"
  done
  [ -s "$out" ] || return 1
  if have sha256sum; then
    [ "sha256:$(sha256sum "$out" | cut -d' ' -f1)" = "$dig" ] && return 0
    err "digest mismatch on $(printf '%.20s' "${dig#sha256:}"), discarding"
    rm -f "$out"
    return 1
  fi
  return 0
}

# gb_oci_pull REPO STAGING -> every layer fetched and its var/ tree unpacked
# into STAGING, later layers overlaying earlier ones the way a container image
# is assembled.
#
# Only var/ is taken. Each image is built on busybox, so the first layer is a
# whole root filesystem -- 2.2 MiB of /bin that is not feed data and must not
# be written anywhere near /var/lib. Choosing "the biggest layer" would be
# worse than useless: for data-objects the base image IS the biggest layer, so
# that heuristic downloads the wrong thing and extracts nothing.
gb_oci_pull(){
  local repo="$1" stage="$2" dig size n=0 ok=0 tmp
  tmp="$stage/.blobs"; mkdir -p "$tmp" "$stage" || return 1
  local layers; layers=$(gb_oci_layers "$repo") || { err "$repo: no manifest"; return 1; }
  [ -n "$layers" ] || { err "$repo: manifest lists no layers"; return 1; }
  while IFS=$'\t' read -r dig size; do
    [ -n "$dig" ] || continue
    n=$((n+1))
    if gb_oci_blob "$repo" "$dig" "$tmp/${dig#sha256:}.tgz" "$size"; then
      # A layer with no var/ is the base image or a metadata layer; tar exits
      # non-zero and that is the expected, uninteresting case.
      tar -xzf "$tmp/${dig#sha256:}.tgz" -C "$stage" var 2>/dev/null && ok=$((ok+1))
      rm -f "$tmp/${dig#sha256:}.tgz"
    else
      err "$repo: layer $n could not be fetched"
      return 1
    fi
  done <<< "$layers"
  rmdir "$tmp" 2>/dev/null
  [ "$ok" -gt 0 ] || { err "$repo: no layer carried feed data"; return 1; }
  return 0
}

# Move a staged tree into place. Separate from the download so the placement
# rules can be tested without a network.
gb_oci_place(){
  local stage="$1" rel moved=0
  # The release directory inside each image is NOT fixed and is not the same
  # across repositories: the tests ship under var/lib/openvas/24.10/ while the
  # gvmd data objects ship under var/lib/gvm/data-objects/gvmd/20.08/. It is
  # discovered rather than assumed, so a Greenbone release bump does not
  # silently produce an empty feed.
  for rel in "$stage"/var/lib/openvas/*/vt-data/nasl; do
    [ -d "$rel" ] || continue
    mkdir -p /var/lib/openvas/plugins
    cp -a "$rel/." /var/lib/openvas/plugins/ 2>/dev/null && moved=$((moved+1))
    dim "  tests from $(basename "$(dirname "$(dirname "$rel")")")"
  done
  # Notus ships its advisories as a tarball inside the image.
  if [ -f "$stage/var/lib/notus/notus-data.tar.gz" ]; then
    mkdir -p /var/lib/notus
    tar -xzf "$stage/var/lib/notus/notus-data.tar.gz" -C /var/lib/notus/ 2>/dev/null \
      && moved=$((moved+1))
  fi
  for sub in data-objects cert-data scap-data report-formats; do
    [ -d "$stage/var/lib/gvm/$sub" ] || continue
    mkdir -p "/var/lib/gvm/$sub"
    cp -a "$stage/var/lib/gvm/$sub/." "/var/lib/gvm/$sub/" 2>/dev/null \
      && moved=$((moved+1))
  done
  # gvmd and the scanner run as the service account, not as root.
  local g; g=$(gb_account 2>/dev/null || echo _gvm)
  chown -R "$g:$g" /var/lib/openvas /var/lib/gvm /var/lib/notus 2>/dev/null || true
  [ "$moved" -gt 0 ]
}

# The service account the Greenbone packages use. Debian and Ubuntu use _gvm.
gb_account(){
  local a
  for a in _gvm gvm; do id -u "$a" >/dev/null 2>&1 && { printf '%s' "$a"; return 0; }; done
  printf '_gvm'
}

# Fetch the whole feed over HTTPS. Returns 0 when at least the vulnerability
# tests and Notus arrived, which is what an authenticated Linux scan needs.
gb_feed_oci(){
  local stage repo failed="" got=0
  stage=$(mktemp -d) || return 1
  local repos="$GB_REPOS"
  [ "$GB_WITH_SCAP" = "1" ] && repos="$repos scap-data"
  info "fetching the Greenbone feed over HTTPS from $GB_REGISTRY"
  dim "resumable, digest-verified, and about 270 MiB without SCAP"
  [ "$GB_WITH_SCAP" = "1" ] \
    && dim "SCAP included, another 1.5 GiB: GB_WITH_SCAP=0 to skip it" \
    || dim "SCAP skipped (1.5 GiB). gvmd runs without it; CVE references come"
  [ "$GB_WITH_SCAP" = "1" ] || dim "from each test's own script_cve_id. GB_WITH_SCAP=1 to include it"
  for repo in $repos; do
    printf "    %-22s" "$repo"
    if gb_oci_pull "$repo" "$stage" >/dev/null 2>&1; then
      echo "${GRN}ok${RST}"; got=$((got+1))
    else
      echo "${YEL}failed${RST}"; failed="$failed $repo"
    fi
  done
  if [ -n "$failed" ]; then
    warn "not fetched:$failed"
    dim "re-run to resume; partial blobs are discarded, completed ones are not"
  fi
  if [ "$got" -eq 0 ]; then rm -rf "$stage"; return 1; fi
  if gb_oci_place "$stage"; then
    local n=0
    [ -d /var/lib/openvas/plugins ] \
      && n=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l | tr -d ' ')
    info "feed in place, $n test scripts"
    rm -rf "$stage"
    [ -n "$failed" ] && return 1
    return 0
  fi
  err "nothing could be moved into place"
  rm -rf "$stage"
  return 1
}

FEED_SYNC="${FEED_SYNC:-1}"
# gvmd-data is a few megabytes and carries the scan configs, report formats
# and port lists, so it goes first: the operator sees "scan configs" stop
# reading zero within a minute instead of after the multi-gigabyte NVT
# download. nvt is what an actual scan needs. scap and cert are large and
# add CVE and advisory metadata only, so they come last and an interrupted
# run still leaves a usable scanner behind.
FEED_TYPES="${FEED_TYPES:-gvmd-data nvt scap cert}"
# auto  : HTTPS from the registry, rsync only if that cannot complete
# https : registry only, never rsync
# rsync : the old behaviour
FEED_TRANSPORT="${FEED_TRANSPORT:-auto}"
greenbone_sync_feeds(){
  have greenbone-feed-sync || {
    warn "greenbone-feed-sync is not installed, the feed cannot be fetched"
    dim "install the Greenbone tooling, or run with FEED_SYNC=0 to skip"
    return 1
  }
  local t rc=0 before after
  before=$(nvt_count)
  dim "fetching the Greenbone feeds. First run is several GB and can take"
  dim "a long time on a client link. Skip with FEED_SYNC=0 $0 setup-greenbone"
  dim "order: $FEED_TYPES. rsync resumes, so an interrupted sync continues"
  dim "where it stopped rather than starting again."
  for t in $FEED_TYPES; do
    echo
    dim "--- feed: $t"
    if greenbone-feed-sync --type "$t"; then dim "$t ok"
    else warn "$t sync failed or was incomplete"; rc=1; fi
  done
  after=$(nvt_count)
  echo
  printf "    %-24s%s\n" "NVT plugins" "$before -> $after"
  # ospd-openvas caches the plugin set in redis and only rereads it on start,
  # so gvmd would otherwise ask about a feed ospd has not loaded yet.
  if systemctl list-unit-files ospd-openvas.service >/dev/null 2>&1; then
    printf "    %-24s" "ospd-openvas reload"
    if systemctl restart ospd-openvas >/dev/null 2>&1; then echo "${GRN}ok${RST}"
    else echo "${YEL}failed${RST}"; fi
  fi
  return $rc
}
gvmd_socket(){
  local s
  for s in /run/gvmd/gvmd.sock /var/run/gvmd/gvmd.sock /run/gvm/gvmd.sock \
           /var/run/gvm/gvmd.sock "$HOME/.gvm/gvmd/gvmd.sock"; do
    [ -S "$s" ] && { echo "$s"; return 0; }
  done
  return 1
}

greenbone_ready_report(){
  local NVTS=0
  [ -d /var/lib/openvas/plugins ] \
    && NVTS=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l)

  # Scan configs, report formats and port lists come from the GVMD data feed,
  # which syncs separately from the NVT plugins. A machine can hold a hundred
  # thousand NVTs and still be unable to create a task because that feed never
  # arrived, so it is checked here rather than discovered mid-scan.
  local CFGS=0 RFMTS=0 SCANNERS=0 CFG_LIST="" FMT_LIST=""
  local WANT_CFG="${CFG_NAME:-Full and fast}" HAVE_CFG="" HAVE_CSV=""
  if [ -s gmp-user.txt ] && [ -s gmp-pass.txt ]; then
    CFG_LIST=$(jgmp "$(gmp_py "$SOCK" list --kind configs 2>/dev/null)" \
                     '(.items // [])[].name')
    FMT_LIST=$(jgmp "$(gmp_py "$SOCK" list --kind formats 2>/dev/null)" \
                     '(.items // [])[].name')
    SCANNERS=$(jgmp "$(gmp_py "$SOCK" list --kind scanners 2>/dev/null)" \
                     '(.items // []) | length' | tr -cd '0-9')
    CFGS=$(printf '%s' "$CFG_LIST" | grep -c . | tr -cd '0-9')
    RFMTS=$(printf '%s' "$FMT_LIST" | grep -c . | tr -cd '0-9')
    HAVE_CFG=$(printf '%s\n' "$CFG_LIST" | grep -Fxi "$WANT_CFG")
    HAVE_CSV=$(printf '%s\n' "$FMT_LIST" | grep -Fxi "CSV Results")
  fi
  CFGS="${CFGS:-0}"; RFMTS="${RFMTS:-0}"; SCANNERS="${SCANNERS:-0}"
  printf "    %-24s%s\n" "scan configs" \
    "$CFGS  ($(printf '%s' "$CFG_LIST" | paste -sd, - | cut -c1-64))"
  printf "    %-24s%s\n" "report formats" \
    "$RFMTS  ($(printf '%s' "$FMT_LIST" | paste -sd, - | cut -c1-64))"
  printf "    %-24s%s\n" "scanners" "$SCANNERS"

  if [ -z "$HAVE_CFG" ] || [ -z "$HAVE_CSV" ]; then
    echo
    warn "the GVMD data feed has not been imported, the NVT scan cannot run"
    [ -z "$HAVE_CFG" ] && dim "missing scan config:   \"$WANT_CFG\""
    [ -z "$HAVE_CSV" ] && dim "missing report format: \"CSV Results\""
    dim "$NVTS NVT plugins are present, but those come from a different feed."
    dim "scan configs, report formats and port lists live in"
    dim "/var/lib/gvm/data-objects/gvmd and sync separately:"
    dim "  sudo greenbone-feed-sync --type gvmd-data"
    dim "  sudo systemctl restart gvmd     # gvmd imports on start"
    dim "if the counts do not move after both, gvmd downloaded the data but"
    dim "did not import it. The usual reason is that systemd killed gvmd"
    dim "mid-import on its start timeout, which looks like a restart loop:"
    dim "  systemctl show -p NRestarts --value gvmd"
    dim "  journalctl -u gvmd --since '10 min ago'"
    return 1
  fi
  echo
  if [ "$NVTS" -ge 10000 ]; then
    info "Greenbone ready, $NVTS NVTs. the next run uses both engines"
    dim "confirm any time with: $0 doctor"
  else
    warn "Greenbone authenticates but the feed holds only $NVTS scripts"
    dim "the engine needs 10000. sudo greenbone-feed-sync   # ~5 GB, not run for you"
    dim "blocked on site? the standalone engine needs no feed"
  fi
}

# Before any credential work: without the helper the verification below cannot
# run, and an unverified password would be written as though it worked.
GMP_LAST=""        # whatever the helper said on the most recent check
GMP_BROKEN=0       # 1 when the client could not run, as opposed to being refused
# A helper that cannot run is not a bad account. The two are reported
# separately so a missing library is never presented as a wrong password,
# which previously sent people off rotating credentials that were fine.
gmp_auth_ok(){     # user pass socket -> 0 when gvmd actually accepts them
  GMP_BROKEN=0
  if ! gmp_py_ready; then
    GMP_BROKEN=1
    gmp_py_find >/dev/null 2>&1 \
      && GMP_LAST="python-gvm is not installed for any python on this box" \
      || GMP_LAST="kameki_gmp.py is not beside this script"
    return 1
  fi
  # The account being checked may not be on disk yet, so the pair is written to
  # a private directory and passed by path. It never appears in argv, which is
  # what the old --gmp-password did, visible in ps to every user on the box.
  local d o rc
  d=$(mktemp -d 2>/dev/null) || {
    GMP_LAST="cannot create a private directory to check the GMP credential"
    GMP_BROKEN=1; return 1
  }
  chmod 700 "$d" 2>/dev/null || true
  ( umask 077; printf '%s' "$1" > "$d/u"; printf '%s' "$2" > "$d/p" )
  GMP_UF="$d/u"; GMP_PF="$d/p"
  o=$(gmp_py "$3" check 2>&1); rc=$?
  GMP_UF=""; GMP_PF=""
  rm -rf "$d"
  # Report gvmd's own sentence where there is one; the raw JSON otherwise.
  local e; e=$(jgmp "$o" '.error // empty')
  [ -n "$e" ] && GMP_LAST="$e" || GMP_LAST="$o"
  [ "$rc" -eq 0 ] && return 0
  # Exit 3 is the helper's "library missing"; anything else is gvmd's answer.
  [ "$rc" -eq 3 ] && GMP_BROKEN=1
  return 1
}

_trim(){ printf '%s' "$1" | tr '\n' ' ' | tr -s ' ' | cut -c1-150; }

cmd_setup_greenbone(){
  need_root setup-greenbone
  step "Greenbone setup"

  if ! have gvmd; then
    warn "gvmd is not installed, nothing to set up"
    dim "the standalone engine needs none of this: $0 run"
    return 1
  fi

  # 1. certificates ---------------------------------------------------
  if have gvm-manage-certs; then
    printf "    %-24s" "certificates"
    if gvm-manage-certs -a >/dev/null 2>&1; then echo "${GRN}ok${RST}"
    else echo "${DIM}already present or not needed${RST}"; fi
  fi

  # 2. services -------------------------------------------------------
  local svc
  # redis ships under different unit names, and on some builds gvmd is happy
  # without a dedicated one, so the first that exists is used and a miss is
  # not an error.
  local redis_unit=""
  for svc in redis-server@openvas redis-server redis; do
    systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 \
      && { redis_unit="$svc"; break; }
  done
  # postgresql first: gvmd will not start without its database, and gvmd is
  # started last so the database exists by the time it runs.
  local out=""
  for svc in postgresql $redis_unit ospd-openvas; do
    systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 || continue
    printf "    %-24s" "$svc"
    if out=$(systemctl enable --now "$svc" 2>&1); then echo "${GRN}started${RST}"
    else
      echo "${YEL}failed${RST}"
      printf '%s\n' "$out" | tail -4 | sed 's/^/      /'
      systemctl status "$svc" --no-pager -n 6 2>&1 | sed 's/^/      /'
    fi
  done

  # Order matters from here, and this block has to come first. A gvmd in a
  # restart loop holds the database, so gvmd --migrate below cannot run, and
  # it truncates every feed import. The loop is broken and the start timeout
  # raised before anything touches the database or the feed, and gvmd is
  # started again only once the feed is on disk.
  if systemctl list-unit-files gvmd.service >/dev/null 2>&1; then
    gvmd_break_restart_loop
    gvmd_fix_start_timeout || true
  fi

  local GVM_ACCT
  if GVM_ACCT=$(gvm_service_account); then gvmd_db_ready "$GVM_ACCT" || true
  else dim "no _gvm or gvm account yet, skipping the database step"; fi

  # 3. feeds ----------------------------------------------------------
  # HTTPS first. rsync to 873 is the transport that fails at client sites --
  # it connects, transfers, and the filtering device kills it. The same data
  # is published as OCI images over 443 in resumable, digest-verified chunks,
  # so that is tried first and rsync is kept only as the fallback for a site
  # where the registry is blocked but 873 is not.
  if [ "$FEED_SYNC" = "1" ] && [ "$(nvt_count)" -lt 10000 ]; then
    if [ "$FEED_TRANSPORT" = "rsync" ]; then
      greenbone_sync_feeds || true
    elif gb_feed_oci; then
      :
    elif [ "$FEED_TRANSPORT" = "auto" ]; then
      warn "the registry did not serve the whole feed, falling back to rsync"
      dim "rsync is the transport that tends to fail here, so expect this to"
      dim "be slower and to need re-running. FEED_TRANSPORT=https to not try it"
      greenbone_sync_feeds || true
    fi
  else
    printf "    %-24s%s\n" "NVT plugins" "$(nvt_count)"
    [ "$FEED_SYNC" = "1" ] || dim "feed sync skipped, FEED_SYNC=0"
  fi

  # 4. gvmd -----------------------------------------------------------
  if systemctl list-unit-files gvmd.service >/dev/null 2>&1; then
    printf "    %-24s" "gvmd"
    # --now blocks until systemd decides the unit is up, which is now up to
    # GVMD_START_TIMEOUT, so this is the step that waits.
    if out=$(systemctl enable --now gvmd 2>&1); then echo "${GRN}started${RST}"
    else
      echo "${YEL}failed${RST}"
      printf '%s\n' "$out" | tail -4 | sed 's/^/      /'
      # Suppressing this is what made the failure unreadable before.
      journalctl -u gvmd -n 15 --no-pager 2>/dev/null | sed 's/^/      /' \
        || systemctl status gvmd --no-pager -n 10 2>&1 | sed 's/^/      /'
    fi
  fi

  # 5. wait for the socket --------------------------------------------
  # Thirty seconds was never enough on a first start: gvmd enumerates the VT
  # set before it listens, which is minutes on a full feed.
  printf "    %-24s" "gvmd socket"
  local waited=0 SOCK="" SOCK_WAIT="${SOCK_WAIT:-300}"
  while [ "$waited" -lt "$SOCK_WAIT" ]; do
    SOCK=$(gvmd_socket) && break
    sleep 3; waited=$((waited + 3))
    [ $((waited % 30)) -eq 0 ] && printf "."
  done
  if [ -z "$SOCK" ]; then
    echo "${YEL}not present after ${SOCK_WAIT}s${RST}"
    dim "the lines above are gvmd's own output. check these in order:"
    dim "  systemctl is-active postgresql ospd-openvas"
    dim "  sudo journalctl -u gvmd -n 40 --no-pager"
    dim "  systemctl show -p NRestarts --value gvmd    # a loop means it is"
    dim "    being killed before it finishes starting; raise the timeout with"
    dim "    GVMD_START_TIMEOUT=3600 sudo -E $0 setup-greenbone"
    dim "on Kali the packaged helper does all of this: sudo gvm-setup"
    dim "the standalone engine needs none of it: $0 run"
    return 1
  fi
  echo "${GRN}$SOCK${RST}"

  # 4. admin user and credentials -------------------------------------
  if [ -s gmp-user.txt ] && [ -s gmp-pass.txt ]; then
    printf "    %-24s" "GMP authentication"
    if gmp_auth_ok "$(head -n1 gmp-user.txt)" "$(head -n1 gmp-pass.txt)" "$SOCK"; then
      echo "${GRN}ok, existing credentials${RST}"
      greenbone_ready_report; return 0
    fi
    echo "${YEL}existing credentials rejected, replacing them${RST}"
  fi

  GVM_ACCOUNT=$(gvm_service_account) || {
    warn "no _gvm or gvm system account, cannot create the admin user"
    return 1
  }

  local GU="kameki-admin" GP
  GP=$(head -c 32 /dev/urandom | base64 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 24)
  [ -n "$GP" ] || GP=$(date +%s%N | sha256sum | head -c 24)

  printf "    %-24s" "admin user"
  # gvmd --help: "--role=<role>  Role for --create-user". Without it the
  # account is created, authenticates, and holds no permissions, so every GMP
  # call fails. That, not the password flags, is what broke earlier attempts:
  # --password and --new-password were valid all along.
  local made=0 f out="" harvest="" tried=""

  # 1. create with a role, then use the password gvmd prints
  out=$(runuser -u "$GVM_ACCOUNT" -- gvmd "--create-user=$GU" --role=Admin 2>&1)
  tried="$tried
      create --role=Admin  : $(_trim "$out")"
  harvest=$(printf '%s' "$out" \
            | sed -n "s/.*[Pp]assword[: ]*['\"]\\([^'\"]*\\)['\"].*/\\1/p" | tail -1)
  if [ -n "$harvest" ] && gmp_auth_ok "$GU" "$harvest" "$SOCK"; then
    GP="$harvest"; made=1
  else
    [ -n "$harvest" ] && tried="$tried
      auth as created      : $(_trim "$GMP_LAST")"
  fi

  # 2. account already existed: set a password we control
  if [ "$made" -eq 0 ]; then
    for f in --new-password --password; do
      out=$(runuser -u "$GVM_ACCOUNT" -- gvmd "--user=$GU" "$f=$GP" 2>&1)
      tried="$tried
      $f            : $(_trim "$out")"
      if gmp_auth_ok "$GU" "$GP" "$SOCK"; then made=1; break; fi
      tried="$tried
      auth after $f : $(_trim "$GMP_LAST")"
    done
  fi

  # 3. create and set in one call, for builds that prefer it
  if [ "$made" -eq 0 ]; then
    out=$(runuser -u "$GVM_ACCOUNT" -- gvmd "--create-user=$GU" --role=Admin \
                  "--password=$GP" 2>&1)
    tried="$tried
      create --password    : $(_trim "$out")"
    gmp_auth_ok "$GU" "$GP" "$SOCK" && made=1
  fi

  # A GMP client that cannot run is not a bad account. If the credentials
  # could not be checked because the checker is broken, keep them, say so
  # plainly, and point at the thing that actually needs fixing.
  if [ "$made" -eq 0 ] && [ "$GMP_BROKEN" -eq 1 ] && [ -n "$harvest" ]; then
    GP="$harvest"
    echo "${YEL}created, unverified${RST}"
    printf '%s\n' "$tried" | sed '/^$/d'
    echo
    warn "the account was created, the GMP client could not be used to check it"
    dim "$GMP_LAST"
    dim "the client failed rather than being refused, so the fault is in the"
    dim "client or its install, not in gvmd or the password. check by hand:"
    dim "  sudo pip3 install --break-system-packages python-gvm"
    dim "  $0 doctor"
    dim "the standalone engine needs no GMP client and is unaffected"
    made=1
  fi

  if [ "$made" -eq 0 ]; then
    echo "${RED}failed${RST}"
    dim "every attempt, in order:"
    printf '%s\n' "$tried" | sed '/^$/d'
    dim "recover by hand, then re-run this command:"
    dim "  sudo runuser -u $GVM_ACCOUNT -- gvmd --delete-user=$GU"
    dim "  sudo runuser -u $GVM_ACCOUNT -- gvmd --create-user=$GU --role=Admin"
    harvest=""; GP=""
    return 1
  fi
  harvest=""
  echo "${GRN}$GU${RST}"

  printf '%s\n' "$GU" > gmp-user.txt
  printf '%s\n' "$GP" > gmp-pass.txt
  chmod 600 gmp-user.txt gmp-pass.txt
  [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" gmp-user.txt gmp-pass.txt 2>/dev/null
  GP=""

  # 5. prove the files on disk work, not just the ones in memory --------
  printf "    %-24s" "GMP authentication"
  if gmp_auth_ok "$(head -n1 gmp-user.txt)" "$(head -n1 gmp-pass.txt)" "$SOCK"; then
    echo "${GRN}ok${RST}"
  elif [ "$GMP_BROKEN" -eq 1 ]; then
    echo "${YEL}not checked, the GMP client could not run${RST}"
    dim "$GMP_LAST"
    dim "credentials kept. install python-gvm, then: $0 doctor"
  else
    echo "${RED}failed${RST}"
    dim "gvmd refused these credentials:"
    printf '%s\n' "$GMP_LAST" | head -3 | sed 's/^/      /'
    dim "removing them so nothing later mistakes this for a working setup"
    rm -f gmp-user.txt gmp-pass.txt
    return 1
  fi
  printf "    %-24s%s\n" "credential files" "${GRN}gmp-user.txt, gmp-pass.txt, mode 600${RST}"

  greenbone_ready_report
  return 0
}

# =====================================================================
#  usage
# =====================================================================
cmd_usage(){
  sed -n '2,40p' "$0" | sed 's/^#//;s/^ //'
  exit 0
}

# =====================================================================
#  dispatch
# =====================================================================
SUB="${1:-run}"
case "$SUB" in
  install)   shift; cmd_install "$@"; exit $? ;;
  update)    shift; cmd_update "$@"; exit $? ;;
  setup-greenbone) shift; cmd_setup_greenbone "$@"; exit $? ;;
  bundle)    shift; cmd_bundle "$@"; exit $? ;;
  doctor)    shift; cmd_doctor "$@"; exit $? ;;
  preflight) shift; cmd_preflight "$@"; exit $? ;;
  cleanup)   shift; cmd_cleanup "$@"; exit $? ;;
  -h|--help|help) cmd_usage ;;
  run)       shift ;;
  --setup)   cmd_usage ;;
  *)         : ;;   # bare invocation means run
esac

# =====================================================================
#  R U N
# =====================================================================
case "$PROFILE" in
  quick)    PORTSPEC="--top-ports 1000";  NSE_SET="vuln" ;;
  standard) PORTSPEC="--top-ports 5000";  NSE_SET="vuln,safe" ;;
  deep)     PORTSPEC="-p-";               NSE_SET="vuln,safe" ;;
  *) err "PROFILE must be quick, standard or deep"; exit 1 ;;
esac

CFG_FAST="daba56c8-73ec-11df-a475-002264764cea"
CFG_ULTIMATE="698f691e-7489-11df-9d8c-002264764cea"
CFG_DEEP="708f25c4-7489-11df-8094-002264764cea"
CFG_DEEPULT="74db13d6-7489-11df-91b9-002264764cea"
FMT_CSV="c1645568-627a-11e3-a660-406186ea4fc5"
FMT_XML="a994b278-1f62-11e1-96ac-406186ea4fc5"
case "$SCAN_CONFIG" in
  fast)     CFG_ID="$CFG_FAST";     CFG_NAME="Full and fast" ;;
  ultimate) CFG_ID="$CFG_ULTIMATE"; CFG_NAME="Full and fast ultimate" ;;
  deep)     CFG_ID="$CFG_DEEP";     CFG_NAME="Full and very deep" ;;
  deepult)  CFG_ID="$CFG_DEEPULT";  CFG_NAME="Full and very deep ultimate" ;;
  *) err "SCAN_CONFIG must be fast, ultimate, deep or deepult"; exit 1 ;;
esac

# =====================================================================
#  1. Dependency check and engine selection
# =====================================================================
step "Dependencies and engine"
MISS=0
chk(){ if command -v "$1" >/dev/null 2>&1; then printf "    %-14s ok\n" "$1"; return 0
       else printf "    %-14s MISSING  ->  %s\n" "$1" "$2"; return 1; fi }

chk nmap   "sudo apt install nmap -y"                               || MISS=1
chk nxc    "pipx install git+https://github.com/Pennyw0rth/NetExec"  || MISS=1
chk nuclei "github.com/projectdiscovery/nuclei/releases"             || MISS=1
chk jq     "sudo apt install jq -y"                                  || MISS=1
[ "$MISS" -eq 1 ] && { err "Install the core tools above, then re-run."; exit 1; }

# --- nvt engine availability
NVT_READY=0; SOCK=""; NVT_FILES=0
# Count the feed unconditionally, the way doctor does. Counting it only when
# GMP credentials happen to exist left NVT_FILES at 0 and made the diagnostic
# below report "feed incomplete (0 NVTs)" on machines with a fully synced
# feed, sending people to re-run a 5 GB greenbone-feed-sync they did not need.
[ -d /var/lib/openvas/plugins ] \
  && NVT_FILES=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l)
if gmp_py_ready; then
  for s in /run/gvmd/gvmd.sock /var/run/gvmd/gvmd.sock /run/gvm/gvmd.sock \
           /var/run/gvm/gvmd.sock "$HOME/.gvm/gvmd/gvmd.sock"; do
    [ -S "$s" ] && { SOCK="$s"; break; }
  done
  if [ -n "$SOCK" ] && [ "$NVT_FILES" -ge 10000 ] \
     && [ -s gmp-user.txt ] && [ -s gmp-pass.txt ]; then
    NVT_READY=1
  fi
fi
if [ "$NVT_READY" -eq 1 ]; then
  printf "    %-14s ok  (%s NVTs, %s)\n" "greenbone" "$NVT_FILES" "$SOCK"
else
  printf "    %-14s %s\n" "greenbone" "unavailable"
  if ! gmp_py_ready; then
    gmp_py_find >/dev/null 2>&1 \
      && dim "python-gvm missing -> sudo pip3 install --break-system-packages python-gvm" \
      || dim "kameki_gmp.py is not beside this script, re-clone or re-install"
  fi
  [ -z "$SOCK" ] && dim "no gvmd socket. run: $0 --setup"
  [ -n "$SOCK" ] && [ "$NVT_FILES" -lt 10000 ] && dim "feed incomplete ($NVT_FILES NVTs). run: sudo greenbone-feed-sync"
  [ -n "$SOCK" ] && { [ -s gmp-user.txt ] && [ -s gmp-pass.txt ] || dim "gmp-user.txt and gmp-pass.txt not found"; }
fi

# --- standalone engine components
WES=""; for c in wes wes.py; do command -v "$c" >/dev/null 2>&1 && { WES="$c"; break; }; done
SVC_CVE="none"
# vulners reaches out to its API for every service and has segfaulted nmap on
# a whole estate; vulscan is a local CSV lookup and cannot. Both are NVD
# version matching and so share the same false-positive profile, which is why
# neither is load-bearing for patch level -- that comes from the MSRC build
# comparison. Reliability decides the default, so the local one wins.
# SVC_CVE_ENGINE=vulners|vulscan|none overrides.
SVC_CVE_ENGINE="${SVC_CVE_ENGINE:-auto}"
case "$SVC_CVE_ENGINE" in
  none)    SVC_CVE="none" ;;
  vulners) [ -f /usr/share/nmap/scripts/vulners.nse ] && SVC_CVE="vulners" \
             || { warn "SVC_CVE_ENGINE=vulners but vulners.nse is not installed"; } ;;
  vulscan) [ -d /usr/share/nmap/scripts/vulscan ] && SVC_CVE="vulscan" \
             || { warn "SVC_CVE_ENGINE=vulscan but vulscan is not installed"; } ;;
  *)       [ -f /usr/share/nmap/scripts/vulners.nse ] && SVC_CVE="vulners"
           [ -d /usr/share/nmap/scripts/vulscan ]     && SVC_CVE="vulscan" ;;
esac
SA_READY=0
[ -n "$WES" ] && SA_READY=1
printf "    %-14s %s\n" "standalone" "$([ $SA_READY -eq 1 ] && echo "ok  (wes: $WES, svc-cve: $SVC_CVE)" || echo "incomplete")"
[ -z "$WES" ] && dim "wes missing -> pipx install wesng && wes --update"
[ "$SVC_CVE" = "none" ] && dim "svc-cve missing -> sudo git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan && sudo nmap --script-updatedb"

# --- optional
HAVE_TESTSSL=0; HAVE_SPLOIT=0; HAVE_SNMP=0; HAVE_CURL=0
command -v testssl.sh   >/dev/null 2>&1 && HAVE_TESTSSL=1
command -v searchsploit >/dev/null 2>&1 && HAVE_SPLOIT=1
command -v onesixtyone  >/dev/null 2>&1 && HAVE_SNMP=1
command -v curl         >/dev/null 2>&1 && HAVE_CURL=1
echo "    ${DIM}optional: testssl.sh $HAVE_TESTSSL  searchsploit $HAVE_SPLOIT  onesixtyone $HAVE_SNMP${RST}"

# --- resolve engine
case "$ENGINE" in
  auto)
    # The two engines are complementary, not alternatives. Greenbone's NVTs do
    # not replace WES-NG patch mapping, the NSE vulnerability scripts or the
    # service version CVE mapping, so when both are usable, run both.
    if   [ "$NVT_READY" -eq 1 ] && [ "$SA_READY" -eq 1 ]; then ENGINE=both
    elif [ "$NVT_READY" -eq 1 ];                          then ENGINE=nvt
    else                                                       ENGINE=standalone
    fi ;;
  nvt)        [ "$NVT_READY" -eq 1 ] || { err "ENGINE=nvt but Greenbone is not available. Run: $0 --setup"; exit 1; } ;;
  standalone) : ;;
  both)
    if [ "$NVT_READY" -eq 0 ]; then
      warn "ENGINE=both but Greenbone is not available, running the standalone engine alone"
      ENGINE=standalone
    fi ;;
  *) err "ENGINE must be auto, nvt, standalone or both"; exit 1 ;;
esac
RUN_NVT=0; RUN_SA=0
case "$ENGINE" in
  nvt)        RUN_NVT=1 ;;
  standalone) RUN_SA=1 ;;
  both)       RUN_NVT=1; RUN_SA=1 ;;
esac
if [ "$RUN_SA" -eq 1 ] && [ "$SA_READY" -eq 0 ]; then
  err "standalone engine selected but WES-NG is not installed"
  dim "it is what maps a host's patch level to CVEs: pipx install wesng && wes --update"
  exit 1
fi
info "engine: ${CYN}$ENGINE${RST}"

# nmap needs raw sockets for the ICMP, ACK and UDP probes in Stage 1 and for
# -sS and -O in Stage 2. Unprivileged it silently falls back to TCP connect,
# so the run undercounts live hosts and skips OS detection while still looking
# like it completed. Say so rather than letting it pass unnoticed.
UNPRIV=0
if [ "$(id -u)" -ne 0 ]; then
  UNPRIV=1
  echo
  err "running without root, the scan cannot proceed:"
  dim "Stage 1 sends ICMP, ACK and UDP pings, which need raw sockets. nmap"
  dim "exits without scanning rather than degrading, so nothing is discovered."
  dim "Stage 2 would also lose -sS and OS detection entirely."
  dim "re-run as: sudo $0 run"
  echo
  exit 1
fi

# =====================================================================
#  2. Inputs
# =====================================================================
for f in targets.txt user.txt pass.txt; do
  [ -s "$f" ] || { err "Missing or empty: $f"; exit 1; }
done
UC=$(nblines user.txt); PC=$(nblines pass.txt)
NTARGETS=$(nblines targets.txt)

if [ "$UC" -eq 1 ] && [ "$PC" -eq 1 ]; then
  U=$(head -n1 user.txt | tr -d '\r\n'); P=$(head -n1 pass.txt | tr -d '\r\n')
  CREDLBL="$U"; MULTI=0
  NVT_U="$U"; NVT_P="$P"
else
  U="user.txt"; P="pass.txt"; CREDLBL="$UC user x $PC pass"; MULTI=1
  # A GMP credential object holds exactly one pair, but the standalone engine
  # iterates the files. Keep them separate so selecting the NVT engine no
  # longer silently reduces the standalone engine to the first pair.
  NVT_U=$(head -n1 user.txt | tr -d '\r\n'); NVT_P=$(head -n1 pass.txt | tr -d '\r\n')
  [ "$RUN_NVT" -eq 1 ] && warn "nvt engine takes one credential pair, using the first line of each; the standalone engine still uses all of them"
  if [ "$MULTI" -eq 1 ] && [ "$RUN_SA" -eq 1 ]; then
    echo; warn "Multi-credential: $(( UC * PC * NTARGETS )) attempts. This is a spray and can lock accounts."
    read -rp "    Type YES to continue: " C; [ "$C" = "YES" ] || { err "Aborted."; exit 1; }
  fi
fi

SSH_ON=0
if [ -s ssh-user.txt ] && [ -s ssh-pass.txt ]; then
  SU=$(head -n1 ssh-user.txt | tr -d '\r\n'); SP=$(head -n1 ssh-pass.txt | tr -d '\r\n')
  SSH_ON=1
fi
for f in user.txt pass.txt ssh-user.txt ssh-pass.txt gmp-user.txt gmp-pass.txt; do
  [ -f "$f" ] && [ "$(stat -c '%a' "$f")" != "600" ] && warn "$f is mode $(stat -c '%a' "$f"), run: chmod 600 $f"
done

mkdir -p "$RAW"/{sysinfo,wes,linux,tls,mods,nse,ports,ad,nvt}
info "profile $PROFILE   jobs $JOBS   targets $NTARGETS   windows creds $CREDLBL"
[ "$SSH_ON" -eq 1 ] && info "linux creds supplied"

# =====================================================================
#  3. CISA KEV catalogue
# =====================================================================
KEV_FILE="$HOME/.kameki-kev.json"; KEV_OK=0
if [ "$HAVE_CURL" -eq 1 ]; then
  if [ ! -f "$KEV_FILE" ] || find "$KEV_FILE" -mtime +7 2>/dev/null | grep -q .; then
    curl -s --max-time 45 -o "$KEV_FILE.tmp" "$KEV_URL" 2>/dev/null && mv "$KEV_FILE.tmp" "$KEV_FILE" || rm -f "$KEV_FILE.tmp"
  fi
fi
if [ -s "$KEV_FILE" ]; then
  jq -r '.vulnerabilities[].cveID' "$KEV_FILE" 2>/dev/null | sort -u > "$RAW/kev-all.txt"
  [ -s "$RAW/kev-all.txt" ] && KEV_OK=1
fi
[ "$KEV_OK" -eq 1 ] && info "KEV catalogue: $(cnt "$RAW/kev-all.txt") actively exploited CVEs" \
                    || warn "KEV catalogue unavailable, exploitation flags disabled"

# # =====================================================================
#  Stage 1  Discovery
# =====================================================================
step "Stage 1  Discovery"
if is_done discovery; then info "skipped (resume)"; else
  nmap -sn -PE -PP -PM -PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5985,8080 \
       -PA80,443,3389 -PU161 --min-rate "$NMAP_RATE" \
       -iL targets.txt -oG "$RAW/discovery.gnmap" -oN "$RAW/discovery.txt" >/dev/null 2>&1
  if [ ! -s "$RAW/discovery.gnmap" ]; then
    err "discovery produced no output, nmap did not run"
    dim "re-run with: sudo $0 run     and check: ip a"
    exit 1
  fi
  awk '/Up$/{print $2}' "$RAW/discovery.gnmap" | sort -uV > "$RAW/live.txt"
  grep -vxFf "$RAW/live.txt" targets.txt 2>/dev/null | grep -ve '^\s*$' > "$RAW/no-response.txt" || true
  mark_done discovery
fi
LIVE=$(cnt "$RAW/live.txt")
info "live $LIVE of $NTARGETS"
[ "$LIVE" -eq 0 ] && { err "No live hosts. Check network position: ip a"; exit 1; }

# =====================================================================
#  Stage 2  Port and service scan   (single pass, reused everywhere)
# =====================================================================
step "Stage 2  Port and service enumeration"
if is_done portscan; then info "skipped (resume)"; else
  dim "one pass, $PORTSPEC, results drive every later stage"
  nmap -sS -sV -O --osscan-guess --version-intensity 5 -Pn $PORTSPEC \
       --min-rate "$NMAP_RATE" --max-retries 2 --host-timeout "$HOST_TIMEOUT" --open \
       -iL "$RAW/live.txt" -oN "$RAW/services.txt" -oG "$RAW/services.gnmap" \
       -oX "$RAW/services.xml" >/dev/null 2>&1
  mark_done portscan
fi
awk '/Ports:/{ip=$2; ports="";
      for(i=1;i<=NF;i++) if($i ~ /\/open\//){split($i,b,"/"); gsub(/,/,"",b[1]); ports=ports b[1] ","}
      if(ports!=""){sub(/,$/,"",ports); print ip" "ports}}' \
    "$RAW/services.gnmap" 2>/dev/null > "$RAW/ports/map.txt" || true
HOSTS_OPEN=$(cnt "$RAW/ports/map.txt")
TOTAL_PORTS=$(awk '{n=split($2,a,","); s+=n} END{print s+0}' "$RAW/ports/map.txt" 2>/dev/null)
grep -E '^Nmap scan report|^Running:|^OS details:|^Service Info:' "$RAW/services.txt" > "$RAW/os-inventory.txt" 2>/dev/null || true
grep -iE 'Windows (XP|Vista|7|8|2003|2008|2012)|Ubuntu (1[0-6]|18)\.|CentOS [5-7]|Debian [5-9] ' \
     "$RAW/services.txt" > "$RAW/eol-os.txt" 2>/dev/null || true
EOL=$(cnt "$RAW/eol-os.txt")
info "hosts with open ports $HOSTS_OPEN   total open ports $TOTAL_PORTS   possible EOL $EOL"

# =====================================================================
#  Stage 3A  NVT engine  (Greenbone over the gvmd socket)
# =====================================================================
NVT_HIGH=0; NVT_MED=0; NVT_LOW=0; NVT_LOG=0; NVT_CVES=0
NVT_AUTH_HOSTS=0; NVT_HOSTS_F=0; NVT_UNAUTH=0; NVT_ROWS=0
# Every gvmd object id is declared here. Stage 3A can abandon at four
# separate points, and each one leaves a later reference pointing at a
# variable that was never assigned. Under set -u that is fatal, so a failed
# create_task took stages 3B to 10 and the final report down with it.
TASK=""; REPORT=""; TARGET=""; SMB_CRED=""; SSH_CRED=""
NVT_CSV="$RAW/nvt/results.csv"
: > "$RAW/cve-nvt.txt"

if [ "$RUN_NVT" -eq 1 ]; then
step "Stage 3A  Greenbone NVT scan  ($NVT_FILES scripts, $CFG_NAME)"

# One process, one authenticated connection, for the whole scan: create the
# credential and target, create and start the task, poll it, export the CSV and
# XML, and delete the credential again. That last step runs even when the scan
# fails, so an aborted run does not leave the client's domain password sitting
# in gvmd.
#
# The scan credential reaches the helper through files in a private directory,
# never through argv, so it is not visible in `ps` to anyone else on the box.
NVT_SECRETS=$(mktemp -d 2>/dev/null) || NVT_SECRETS=""
if [ -z "$NVT_SECRETS" ]; then
  err "cannot create a private directory for the scan credential"
  RUN_NVT=0
else
chmod 700 "$NVT_SECRETS" 2>/dev/null || true
( umask 077
  printf '%s' "$NVT_U" > "$NVT_SECRETS/smb-login"
  printf '%s' "$NVT_P" > "$NVT_SECRETS/smb-pass" )
NVT_SSH_ARGS=""
if [ "$SSH_ON" -eq 1 ] && [ -n "$SU" ]; then
  ( umask 077
    printf '%s' "$SU" > "$NVT_SECRETS/ssh-login"
    printf '%s' "$SP" > "$NVT_SECRETS/ssh-pass" )
  NVT_SSH_ARGS="--ssh-login-file $NVT_SECRETS/ssh-login --ssh-pass-file $NVT_SECRETS/ssh-pass"
fi

# shellcheck disable=SC2086  # NVT_SSH_ARGS is a deliberate pair of flags
SCAN_OUT=$(gmp_py "$SOCK" scan \
  --run-name     "$RUN_NAME" \
  --hosts-file   targets.txt \
  --config-name  "$CFG_NAME" \
  --config-id    "$CFG_ID" \
  --alive-test   "$ALIVE_TEST" \
  --smb-login-file "$NVT_SECRETS/smb-login" \
  --smb-pass-file  "$NVT_SECRETS/smb-pass" \
  $NVT_SSH_ARGS \
  --poll         "$POLL" \
  --max-minutes  "$NVT_MAX_MIN" \
  --csv-out      "$NVT_CSV" \
  --xml-out      "$RAW/nvt/report-full.xml")
SCAN_RC=$?
rm -rf "$NVT_SECRETS"
NVT_SECRETS=""

# Whatever happened, keep whichever ids the helper got as far as issuing. A
# scan that died after create_task still leaves a task in gvmd, and the id is
# what you need to find it.
TASK=$(jgmp "$SCAN_OUT" '.task // ""')
TARGET=$(jgmp "$SCAN_OUT" '.target // ""')
REPORT=$(jgmp "$SCAN_OUT" '.report // ""')

if [ "$SCAN_RC" -ne 0 ]; then
  err "the Greenbone NVT scan did not run"
  GMSG=$(jgmp "$SCAN_OUT" '.error // empty')
  if [ -n "$GMSG" ]; then dim "$GMSG"
  else printf '%s\n' "$SCAN_OUT" | head -3 | sed 's|^|      |'; fi
  GAVAIL=$(jgmp "$SCAN_OUT" '(.available // [])[]')
  if [ -n "$GAVAIL" ]; then
    dim "configs this gvmd does have:"
    printf '%s\n' "$GAVAIL" | head -12 | sed 's|^|        |'
  fi
  GHINT=$(jgmp "$SCAN_OUT" '.hint // empty')
  [ -n "$GHINT" ] && printf '%s\n' "$GHINT" | fold -s -w 64 | sed 's|^|      |'
  RUN_NVT=0
else
  NVT_STATUS=$(jgmp "$SCAN_OUT" '.status // ""')
  case "$NVT_STATUS" in
    Done) info "NVT scan complete" ;;
    "")   warn "NVT scan finished with no status reported" ;;
    *)    warn "NVT scan $NVT_STATUS, exporting what it produced" ;;
  esac
fi
# Written whatever happened. A scan that died after creating the task still
# leaves the ids behind, which is what you need to find it in gvmd afterwards.
echo "task=$TASK target=$TARGET report=$REPORT" > "$RAW/nvt/ids.txt"

if [ -s "$NVT_CSV" ]; then
  NVT_ROWS=$(( $(wc -l < "$NVT_CSV") - 1 ))
  NVT_HIGH=$(awk -F'","' 'NR>1 && tolower($6) ~ /high/'   "$NVT_CSV" 2>/dev/null | wc -l)
  NVT_MED=$(awk  -F'","' 'NR>1 && tolower($6) ~ /medium/' "$NVT_CSV" 2>/dev/null | wc -l)
  NVT_LOW=$(awk  -F'","' 'NR>1 && tolower($6) ~ /low/'    "$NVT_CSV" 2>/dev/null | wc -l)
  NVT_LOG=$(awk  -F'","' 'NR>1 && tolower($6) ~ /log/'    "$NVT_CSV" 2>/dev/null | wc -l)
  grep -oE 'CVE-[0-9]{4}-[0-9]+' "$NVT_CSV" 2>/dev/null | sort -u > "$RAW/cve-nvt.txt" || true
  NVT_CVES=$(cnt "$RAW/cve-nvt.txt")
  awk -F'","' 'NR>1{gsub(/^"/,"",$1); print $1}' "$NVT_CSV" 2>/dev/null | sort -uV > "$RAW/nvt/hosts-found.txt"
  NVT_HOSTS_F=$(cnt "$RAW/nvt/hosts-found.txt")
  grep -i 'Authenticated \(registry\|package\)-based' "$NVT_CSV" 2>/dev/null \
    | awk -F'","' '{gsub(/^"/,"",$1); print $1}' | sort -uV > "$RAW/nvt/authenticated-hosts.txt" || : > "$RAW/nvt/authenticated-hosts.txt"
  NVT_AUTH_HOSTS=$(cnt "$RAW/nvt/authenticated-hosts.txt")
  if [ -s "$RAW/nvt/authenticated-hosts.txt" ]; then
    grep -vxFf "$RAW/nvt/authenticated-hosts.txt" "$RAW/nvt/hosts-found.txt" > "$RAW/nvt/unauth-hosts.txt" 2>/dev/null || true
  else cp "$RAW/nvt/hosts-found.txt" "$RAW/nvt/unauth-hosts.txt" 2>/dev/null || true; fi
  NVT_UNAUTH=$(cnt "$RAW/nvt/unauth-hosts.txt")
  info "findings  high $NVT_HIGH  medium $NVT_MED  low $NVT_LOW  log $NVT_LOG   cves $NVT_CVES"
  info "authenticated checks on $NVT_AUTH_HOSTS of $NVT_HOSTS_F hosts with findings"
else
  err "CSV export failed, raw XML kept in $RAW/nvt/"
fi
fi
fi

# =====================================================================
#  Stage 3B  Standalone engine
# =====================================================================
NSE_HITS=0; SVC_CVES=0; SPLOIT=0; WIN_CVES=0; WIN_CRIT=0; SYSOK=0
: > "$RAW/cve-service.txt"; : > "$RAW/cve-windows.txt"; : > "$RAW/nse-all.txt"

if [ "$RUN_SA" -eq 1 ]; then
step "Stage 3B  NSE vulnerability scripts and service CVE mapping"
if is_done nse; then info "skipped (resume)"; else
  dim "targeting only discovered ports, $JOBS parallel workers"
  case "$SVC_CVE" in
    vulners) SCRIPTS="$NSE_SET,vulners"; SARGS="--script-args mincvss=$MIN_CVSS" ;;
    vulscan) SCRIPTS="$NSE_SET,vulscan/vulscan.nse"; SARGS="--script-args vulscandb=cve.csv" ;;
    *)       SCRIPTS="$NSE_SET"; SARGS=""
             dim "service-CVE mapping disabled, vulnerability scripts only" ;;
  esac
  : > "$RAW/nse-failed.txt"; : > "$RAW/nse-degraded.txt"
  # nmap's exit status was discarded, so a scan that crashed on every host
  # still reported "NSE vulnerable states 0  service CVEs 0" -- a tool failure
  # presented as a finding of absence. On a real engagement nmap segfaulted on
  # all 39 hosts and the stage reported zero as though it had looked.
  #
  # The CVE-mapping script is the usual culprit: vulners reaches out to its
  # API and has crashed whole estates. So a failed host is retried with just
  # the vulnerability scripts, which are the part worth having, and both the
  # failure and the reduced coverage are recorded.
  nse_host(){
    local ip="$1" ports="$2" out="$RAW/nse/$1.txt" rc
    nmap -sV -Pn -n -p "$ports" --script "$SCRIPTS" $SARGS --script-timeout 90s \
         --host-timeout "$HOST_TIMEOUT" "$ip" -oN "$out" >/dev/null 2>&1
    rc=$?
    { [ "$rc" -eq 0 ] && [ -s "$out" ]; } && return 0
    printf '%s\trc=%s\n' "$ip" "$rc" >> "$RAW/nse-failed.txt"
    if nmap -sV -Pn -n -p "$ports" --script "$NSE_SET" --script-timeout 90s \
            --host-timeout "$HOST_TIMEOUT" "$ip" -oN "$out" >/dev/null 2>&1 \
       && [ -s "$out" ]; then
      printf '%s\n' "$ip" >> "$RAW/nse-degraded.txt"
    fi
    return 0
  }
  N=0
  while read -r ip ports; do
    [ -z "$ip" ] && continue
    N=$((N+1)); printf "\r    scanning %d/%d" "$N" "$HOSTS_OPEN"
    pool nse_host "$ip" "$ports"
  done < "$RAW/ports/map.txt"
  finish; echo
  # Only mark the stage done if it produced something. Marking a stage that
  # failed on every host means a resumed run skips it and keeps the empty
  # output, which is how a crash becomes a permanent clean result.
  if ls "$RAW"/nse/*.txt >/dev/null 2>&1; then mark_done nse
  else warn "no host produced NSE output, not marking the stage done so a"
       dim "re-run will attempt it again rather than skipping it"; fi
fi
cat "$RAW"/nse/*.txt > "$RAW/nse-all.txt" 2>/dev/null || : > "$RAW/nse-all.txt"
NSE_HITS=$(gcntiE 'VULNERABLE' "$RAW/nse-all.txt")
grep -oE 'CVE-[0-9]{4}-[0-9]+' "$RAW/nse-all.txt" 2>/dev/null | sort -u > "$RAW/cve-service.txt" || true
SVC_CVES=$(cnt "$RAW/cve-service.txt")
NSE_FAILED=$(cnt "$RAW/nse-failed.txt")
NSE_DEGRADED=$(cnt "$RAW/nse-degraded.txt")
NSE_SCANNED=$(ls -1 "$RAW"/nse/*.txt 2>/dev/null | wc -l | tr -d ' ')
info "NSE vulnerable states $NSE_HITS   service CVEs $SVC_CVES"
info "hosts with output $NSE_SCANNED of $HOSTS_OPEN"
if [ "$NSE_SCANNED" -eq 0 ] && [ "$HOSTS_OPEN" -gt 0 ]; then
  err "Stage 3B produced no output for any host. The zeros above are not a"
  dim "result: nothing was assessed. Do not report them as an absence of"
  dim "findings. See $RAW/nse-failed.txt for nmap's exit status per host."
  dim "nmap exiting 139 is a segmentation fault, usually the service-CVE"
  dim "script. Re-run with SVC_CVE_ENGINE=none to drop it."
elif [ "$NSE_FAILED" -gt 0 ]; then
  warn "nmap failed on $NSE_FAILED of $HOSTS_OPEN host(s) with the full script set"
  [ "$NSE_DEGRADED" -gt 0 ] \
    && dim "$NSE_DEGRADED recovered without the service-CVE script, so those" \
    && dim "hosts have vulnerability-script coverage but no CVE mapping"
  dim "exit status per host in $RAW/nse-failed.txt. 139 is a segmentation"
  dim "fault; SVC_CVE_ENGINE=none drops the script that usually causes it"
fi

if [ "$HAVE_SPLOIT" -eq 1 ] && [ -s "$RAW/services.xml" ]; then
  searchsploit --nmap "$RAW/services.xml" > "$RAW/searchsploit.txt" 2>&1 || true
  SPLOIT=$(gcnt 'Exploit Title' "$RAW/searchsploit.txt")
  info "public exploit matches $SPLOIT"
fi
fi

# =====================================================================
#  Stage 4  Authentication across protocols
# =====================================================================
step "Stage 4  Authentication"
SMB_T=$(proto_list smb 445 139)
LDAP_T=$(proto_list ldap 389 636)
MSSQL_T=$(proto_list mssql 1433)
WINRM_T=$(proto_list winrm 5985 5986)
RDP_T=$(proto_list rdp 3389)
dim "targets by protocol, from the stage 2 port map"
printf "    %-8s%-6s%-8s%-6s%-8s%-6s%-8s%-6s%-8s%s\n" \
  "smb" "$SMB_T" "ldap" "$LDAP_T" "mssql" "$MSSQL_T" \
  "winrm" "$WINRM_T" "rdp" "$RDP_T"
dim "each call is capped at $NXC_CAP"
ap(){ local pr="$1" t="$RAW/targets/$1.txt"
      if [ ! -s "$t" ]; then
        printf 'no live host answered on the %s port, so this protocol was not attempted\n' \
               "$pr" > "$RAW/auth-$pr.txt"
        return 0
      fi
      nxcq "$pr" "$t" -u "$U" -p "$P" --continue-on-success \
           -t "$NXC_THREADS" > "$RAW/auth-$pr.txt" 2>&1; }
for pr in smb ldap mssql winrm rdp; do pool ap "$pr"; done
nullsess(){
  if [ ! -s "$RAW/targets/smb.txt" ]; then
    echo 'no live host answered on 445' > "$RAW/null-session.txt"; return 0
  fi
  nxcq smb "$RAW/targets/smb.txt" -u '' -p '' --shares \
       > "$RAW/null-session.txt" 2>&1
}
pool nullsess
finish

grep '\[+\]' "$RAW/auth-smb.txt" | awk '{print $2}' | sort -uV > "$RAW/auth-ok.txt"   || : > "$RAW/auth-ok.txt"
grep '\[-\]' "$RAW/auth-smb.txt" | awk '{print $2}' | sort -uV > "$RAW/auth-fail-raw.txt" || : > "$RAW/auth-fail-raw.txt"
if [ -s "$RAW/auth-ok.txt" ]; then
  grep -vxFf "$RAW/auth-ok.txt" "$RAW/auth-fail-raw.txt" > "$RAW/auth-fail.txt" 2>/dev/null || : > "$RAW/auth-fail.txt"
else cp "$RAW/auth-fail-raw.txt" "$RAW/auth-fail.txt" 2>/dev/null || : > "$RAW/auth-fail.txt"; fi
grep '\[+\]' "$RAW/auth-smb.txt" | sed -E 's/.*\[\+\][[:space:]]*//' | sort -u > "$RAW/working-creds.txt" || true

AUTH_OK=$(cnt "$RAW/auth-ok.txt"); AUTH_FAIL=$(cnt "$RAW/auth-fail.txt")
NOSIGN=$(gcnt 'signing:False' "$RAW/auth-smb.txt")
SMBV1=$(gcnt 'SMBv1:True' "$RAW/auth-smb.txt")
NULLS=$(gcnt '\[+\]' "$RAW/null-session.txt")
MSSQL_OK=$(gcnt '\[+\]' "$RAW/auth-mssql.txt")
WINRM_OK=$(gcnt '\[+\]' "$RAW/auth-winrm.txt")
info "smb $AUTH_OK ok / $AUTH_FAIL fail   no-signing $NOSIGN   smbv1 $SMBV1   null $NULLS   mssql $MSSQL_OK   winrm $WINRM_OK"
# A locked account is not a failed login, it is an incident in progress.
# Continuing sprays a locked account across the rest of the estate, and every
# attempt restarts the lockout window, so the run stops here.
LOCKED=$(gcnt 'STATUS_ACCOUNT_LOCKED_OUT' "$RAW/auth-smb.txt")
LOCKED_H=$(grep 'STATUS_ACCOUNT_LOCKED_OUT' "$RAW/auth-smb.txt" 2>/dev/null \
           | awk '{print $2}' | sort -u | wc -l | tr -cd '0-9')
LOCKED_H="${LOCKED_H:-0}"
if [ "$LOCKED" -gt 0 ]; then
  echo
  err "STOPPING: the account is locked out on ${LOCKED_H} host(s)"
  dim "$LOCKED lockout response(s) in this stage alone. Every further attempt"
  dim "extends the lockout window and delays recovery."
  dim ""
  dim "1. tell the client now, the account needs unlocking"
  dim "2. confirm the lockout threshold and observation window before retrying"
  dim "3. then: $0 preflight    to find the format against ONE host"
  dim ""
  dim "partial evidence kept in $RAW/"
  exit 1
fi
[ "$AUTH_OK" -eq 0 ] && { warn "No SMB authentication succeeded."; dim "try DOMAIN\\\\user, user@domain, or the NETBIOS name"; }

# =====================================================================
#  Stage 5  Exploit modules
# =====================================================================
step "Stage 5  Windows exploit modules"
MODS="ms17-010 zerologon petitpotam nopac smbghost printnightmare spooler webdav coerce_plus"
runmod(){ nxcq smb "$RAW/targets/smb.txt" -u "$U" -p "$P" -M "$1" \
                -t "$NXC_THREADS" > "$RAW/mods/$1.txt" 2>&1; }
if [ -s "$RAW/targets/smb.txt" ]; then
  for m in $MODS; do pool runmod "$m"; done
  finish
else
  dim "no live host answered on 445, so no module was attempted"
  for m in $MODS; do echo 'no SMB host in scope' > "$RAW/mods/$m.txt"; done
fi
: > "$RAW/vuln-summary.txt"; : > "$RAW/vuln-detail.txt"
for m in $MODS; do
  H=$(gcntiE 'VULNERABLE|is vulnerable' "$RAW/mods/$m.txt")
  if [ "$H" -gt 0 ]; then
    printf "    %-16s ${RED}%s vulnerable${RST}\n" "$m" "$H"
    echo "$m: $H" >> "$RAW/vuln-summary.txt"
    { echo "--- $m ---"; grep -iE 'VULNERABLE|is vulnerable' "$RAW/mods/$m.txt" | head -25; } >> "$RAW/vuln-detail.txt"
  else printf "    %-16s clear\n" "$m"; fi
done
MOD_VULN=$(awk -F': ' '{s+=$2} END{print s+0}' "$RAW/vuln-summary.txt" 2>/dev/null || echo 0)

# =====================================================================
#  Stage 6  Active Directory
# =====================================================================
step "Stage 6  Active Directory"
adr(){ local pr="$1" t="$RAW/targets/$1.txt"
       if [ ! -s "$t" ]; then
         printf 'no live host answered on the %s port\n' "$pr" > "$RAW/ad/$3.txt"
         return 0
       fi
       nxcq "$pr" "$t" -u "$U" -p "$P" $2 > "$RAW/ad/$3.txt" 2>&1; }
pool adr ldap "-M adcs"                    adcs
pool adr ldap "-M ldap-checker"            ldap-signing
pool adr ldap "--kerberoasting $RAW/ad/kerberoast-tickets.txt" kerberoast
pool adr ldap "--asreproast $RAW/ad/asrep-tickets.txt"         asreproast
pool adr ldap "-M find-delegation"         delegation
pool adr ldap "-M maq"                     machine-quota
pool adr ldap "-M user-desc"               user-descriptions
pool adr ldap "--password-not-required"    pwd-not-required
pool adr ldap "--trusted-for-delegation"   trusted-delegation
finish
ADCS_H=$(gcnti 'ESC\|Certificate Authority' "$RAW/ad/adcs.txt")
KERB_H=$(cat "$RAW/ad/kerberoast.txt" "$RAW/ad/kerberoast-tickets.txt" 2>/dev/null | grep -c 'krb5tgs' | head -1 | tr -cd '0-9')
KERB_H="${KERB_H:-0}"
ASREP_H=$(cat "$RAW/ad/asreproast.txt" "$RAW/ad/asrep-tickets.txt" 2>/dev/null | grep -c 'krb5asrep' | head -1 | tr -cd '0-9')
ASREP_H="${ASREP_H:-0}"
DELEG_H=$(gcnti 'delegation' "$RAW/ad/delegation.txt")
LDAPSIGN=$(gcnti 'not enforced\|is not being enforced\|channel binding' "$RAW/ad/ldap-signing.txt")
PWDNR=$(gcnti 'password not required\|PASSWD_NOTREQD' "$RAW/ad/pwd-not-required.txt")
info "adcs $ADCS_H   kerberoast $KERB_H   asrep $ASREP_H   delegation $DELEG_H   ldap-signing $LDAPSIGN"

# =====================================================================
#  Stage 7  Configuration audit
# =====================================================================
step "Stage 7  Configuration audit"
cf(){ nxcq smb "$RAW/targets/smb.txt" -u "$U" -p "$P" $1 \
           -t "$NXC_THREADS" > "$RAW/$2.txt" 2>&1; }
pool cf "--pass-pol"                     password-policy
pool cf "--local-groups Administrators"  local-admins
pool cf "--shares"                       shares
pool cf "--users"                        domain-users
pool cf "-M wcc"                         config-check
pool cf "-M enum_av"                     endpoint-protection
pool cf "-M gpp_password"                gpp-password
pool cf "-M gpp_autologin"               gpp-autologin
pool cf "-M laps"                        laps
finish
WCC_FAIL=$(gcntiE '\bFAIL\b|not compliant' "$RAW/config-check.txt")
GPP=$(gcnti 'password' "$RAW/gpp-password.txt")
WRITABLE=$(gcnti 'READ,WRITE' "$RAW/shares.txt")
info "config failures $WCC_FAIL   writable shares $WRITABLE   gpp $GPP"

# =====================================================================
#  Stage 8  Patch level  (standalone engine only, NVT covers this itself)
# =====================================================================
if [ "$RUN_SA" -eq 1 ]; then
step "Stage 8  Patch level collection and Windows CVE mapping"
if [ -s "$RAW/auth-ok.txt" ]; then
  grab(){ local h="$1" o="$RAW/sysinfo/$1.txt"
    nxc smb "$h" -u "$U" -p "$P" -x 'systeminfo' 2>/dev/null \
      | sed -E 's/^SMB[[:space:]]+\S+[[:space:]]+[0-9]+[[:space:]]+\S+[[:space:]]+//' \
      | grep -v '^\[' > "$o"
    grep -qi 'OS Name' "$o" 2>/dev/null || rm -f "$o"; }
  N=0; TOT=$(cnt "$RAW/auth-ok.txt")
  while read -r h; do [ -z "$h" ] && continue
    N=$((N+1)); printf "\r    collecting %d/%d" "$N" "$TOT"; pool grab "$h"
  done < "$RAW/auth-ok.txt"
  finish; echo
  SYSOK=$(ls -1 "$RAW"/sysinfo/*.txt 2>/dev/null | wc -l)
fi
info "systeminfo collected $SYSOK of $AUTH_OK authenticated"
: > "$RAW/windows-cves.csv"
if [ "$SYSOK" -gt 0 ]; then
  { [ -f definitions.zip ] || [ -f "$HOME/definitions.zip" ]; } || { warn "fetching WES-NG definitions"; "$WES" --update >/dev/null 2>&1 || warn "definition update failed"; }
  echo "Host,CVE,Severity,AffectedProduct,MissingKB,Title" > "$RAW/windows-cves.csv"
  wr(){ "$WES" "$1" -o "$RAW/wes/$(basename "$1" .txt).csv" >/dev/null 2>&1; }
  for f in "$RAW"/sysinfo/*.txt; do [ -e "$f" ] && pool wr "$f"; done
  finish
  for c in "$RAW"/wes/*.csv; do [ -e "$c" ] || continue
    h=$(basename "$c" .csv)
    tail -n +2 "$c" | awk -F',' -v H="$h" '{print H","$3","$7","$2","$8","$4}' >> "$RAW/windows-cves.csv" 2>/dev/null || true
  done
  WIN_CVES=$(( $(wc -l < "$RAW/windows-cves.csv") - 1 )); [ "$WIN_CVES" -lt 0 ] && WIN_CVES=0
  WIN_CRIT=$(gcnti 'critical' "$RAW/windows-cves.csv")
  grep -oE 'CVE-[0-9]{4}-[0-9]+' "$RAW/windows-cves.csv" 2>/dev/null | sort -u > "$RAW/cve-windows.txt" || true
  info "windows CVEs $WIN_CVES   critical $WIN_CRIT"
fi
fi

# ---------------------------------------------------------------------------
#  Windows patch level from Microsoft's own data
#
#  Runs alongside WES-NG rather than instead of it, because the two answer
#  different questions and have opposite error profiles:
#
#    WES-NG reads the hotfix list out of systeminfo and maps it against the
#    MSRC bulletin feed. It covers more than the OS -- Office, .NET, drivers --
#    but its own documentation says so plainly: "the data provided by
#    Microsoft's MSRC feed is frequently incomplete and false positives are
#    reported by wes.py". Its wiki shows a fully patched Windows 10 1803
#    reporting 97 vulnerabilities.
#
#    This compares the OS build the host itself reports against the build
#    Microsoft states fixes each CVE. For cumulative-update Windows that is
#    the supersedence check, complete, so it cannot report a patch the host
#    already has. It covers the OS only.
#
#  Both are recorded, each labelled with its method, so a reader can tell
#  an authoritative finding from an inferred one instead of having to trust
#  the pair equally.
# ---------------------------------------------------------------------------
MSRC_ASSESSED=0; MSRC_BEHIND=0; MSRC_CVES=0; MSRC_EXPL=0; MSRC_UNASSESSED=0
: > "$RAW/windows-patch-msrc.csv"
: > "$RAW/windows-patch-coverage.txt"
if [ "$AUTH_OK" -gt 0 ] && msrc_ready; then
  step "Stage 5B  Windows patch level  (Microsoft MSRC build comparison)"
  mkdir -p "$RAW/msrc"
  if is_done msrc; then info "skipped (resume)"; else
    echo "Host,Product,Build,InstalledUBR,RequiredUBR,Method,Assessed,Behind,CVEs,MaxCVSS,Exploited,CountIsFloor" \
      > "$RAW/windows-patch-coverage.csv"
    msrc_one(){
      local h="$1" facts base ubr kind product method out
      out="$RAW/msrc/$h.json"
      if ! facts=$(win_facts "$h"); then
        # Recorded, not dropped: a host that could not be read is a coverage
        # gap and belongs in the figures. PCI 11.3.1.2.a asks what was
        # collected per host, and "nothing" is an answer the report must carry.
        printf '%s,,,,,none,no,,,,,\n' "$h" >> "$RAW/windows-patch-coverage.csv"
        printf '%s\tno registry read\n' "$h" >> "$RAW/windows-patch-coverage.txt"
        return 0
      fi
      base=$(printf '%s' "$facts" | cut -d'|' -f1)
      ubr=$(printf  '%s' "$facts" | cut -d'|' -f2)
      kind=$(printf '%s' "$facts" | cut -d'|' -f3)
      product=$(printf '%s' "$facts" | cut -d'|' -f4)
      method=$(printf '%s' "$facts" | cut -d'|' -f5)
      # An unknown installation type is not guessed at. Server and client are
      # separate cumulative lines and picking the wrong one invents findings,
      # so the host is reported as unassessed instead.
      [ -n "$kind" ] || kind=unknown
      if [ "$kind" = unknown ]; then
        printf '%s,%s,%s.%s,%s,,%s,no,,,,,\n' \
          "$h" "$product" "$base" "$ubr" "$ubr" "$method" \
          >> "$RAW/windows-patch-coverage.csv"
        printf '%s\tinstallation type unknown, cumulative line undetermined\n' \
          "$h" >> "$RAW/windows-patch-coverage.txt"
        return 0
      fi
      msrc_py assess --db "$MSRC_DB" --base "$base" \
        ${ubr:+--ubr "$ubr"} --kind "$kind" --host "$h" > "$out" 2>/dev/null || true
      [ -s "$out" ] || { printf '%s\tassessment produced nothing\n' "$h" \
                           >> "$RAW/windows-patch-coverage.txt"; return 0; }
      python3 - "$h" "$product" "$method" "$out" \
        "$RAW/windows-patch-msrc.csv" "$RAW/windows-patch-coverage.csv" <<'PYROW'
import csv, json, sys
host, product, method, path, findings_csv, coverage_csv = sys.argv[1:7]
with open(path, encoding='utf-8') as fh:
    d = json.load(fh)
with open(coverage_csv, 'a', newline='', encoding='utf-8') as fh:
    csv.writer(fh).writerow([
        host, product,
        '%s.%s' % (d.get('base_build') or '', d.get('installed_ubr') or ''),
        d.get('installed_ubr') or '', d.get('required_ubr') or '', method,
        'yes' if d.get('assessed') else 'no',
        d.get('behind_by_levels') if d.get('assessed') else '',
        d.get('cve_count') if d.get('assessed') else '',
        d.get('max_cvss') if d.get('assessed') else '',
        len(d.get('exploited_cves') or []),
        'yes' if d.get('counts_are_a_floor') else '',
    ])
rows = d.get('findings') or []
if rows:
    with open(findings_csv, 'a', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        for f in rows:
            w.writerow([host, f.get('cve'), f.get('cvss'), f.get('severity'),
                        f.get('impact'), f.get('kb'), f.get('fixed_ubr'),
                        'yes' if f.get('exploited') else '',
                        'MSRC build comparison', f.get('vector')])
PYROW
    }
    N=0; TOT=$(cnt "$RAW/auth-ok.txt")
    while read -r h; do [ -z "$h" ] && continue
      N=$((N+1)); printf "\r    reading build %d/%d" "$N" "$TOT"
      pool msrc_one "$h"
    done < "$RAW/auth-ok.txt"
    finish; echo
    mark_done msrc
  fi

  # A header only once, and only if there are rows to head.
  if [ -s "$RAW/windows-patch-msrc.csv" ]; then
    { echo "Host,CVE,CVSS,Severity,Impact,MissingKB,FixedUBR,Exploited,Method,Vector"
      cat "$RAW/windows-patch-msrc.csv"; } > "$RAW/windows-patch-msrc.csv.tmp" \
      && mv -f "$RAW/windows-patch-msrc.csv.tmp" "$RAW/windows-patch-msrc.csv"
  fi
  if [ -s "$RAW/windows-patch-coverage.csv" ]; then
    MSRC_ASSESSED=$(awk -F',' 'NR>1 && $7=="yes"' "$RAW/windows-patch-coverage.csv" | wc -l | tr -d ' ')
    MSRC_UNASSESSED=$(awk -F',' 'NR>1 && $7!="yes"' "$RAW/windows-patch-coverage.csv" | wc -l | tr -d ' ')
    MSRC_BEHIND=$(awk -F',' 'NR>1 && $7=="yes" && $8+0>0' "$RAW/windows-patch-coverage.csv" | wc -l | tr -d ' ')
  fi
  MSRC_CVES=$(awk -F',' 'NR>1{print $2}' "$RAW/windows-patch-msrc.csv" 2>/dev/null | sort -u | grep -c . | tr -d ' ')
  MSRC_EXPL=$(awk -F',' 'NR>1 && $8=="yes"{print $2}' "$RAW/windows-patch-msrc.csv" 2>/dev/null | sort -u | grep -c . | tr -d ' ')
  info "assessed $MSRC_ASSESSED of $AUTH_OK authenticated, $MSRC_BEHIND behind"
  info "distinct CVEs $MSRC_CVES   actively exploited per Microsoft $MSRC_EXPL"
  [ "$MSRC_UNASSESSED" -gt 0 ] && \
    dim "$MSRC_UNASSESSED host(s) not assessed by this method, see windows-patch-coverage.csv"
  if awk -F',' 'NR>1 && $12=="yes"' "$RAW/windows-patch-coverage.csv" 2>/dev/null | grep -q .; then
    dim "some hosts sit below the oldest month held, so their CVE counts are a"
    dim "floor rather than a total. widen it with: MSRC_MONTHS=12 sudo $0 update"
  fi
elif [ "$AUTH_OK" -gt 0 ]; then
  if msrc_py_find >/dev/null 2>&1; then
    warn "Microsoft patch data not compiled, Windows patch level rests on WES-NG alone"
    dim "WES-NG reports false positives by its own documentation. fix with:"
    dim "  sudo $0 update"
  fi
fi

# =====================================================================
#  Stage 9  Linux
# =====================================================================
step "Stage 9  Linux authenticated collection"
LINUX_OK=0; LINUX_EOL=0
if [ "$SSH_ON" -eq 1 ]; then
  SSH_T=$(proto_list ssh 22)
  dim "ssh targets $SSH_T"
  nxcq ssh "$RAW/targets/ssh.txt" -u "$SU" -p "$SP" --continue-on-success \
       -t "$NXC_THREADS" > "$RAW/auth-ssh.txt" 2>&1
  grep '\[+\]' "$RAW/auth-ssh.txt" | awk '{print $2}' | sort -uV > "$RAW/ssh-ok.txt" || : > "$RAW/ssh-ok.txt"
  lg(){ nxc ssh "$1" -u "$SU" -p "$SP" -x 'cat /etc/os-release 2>/dev/null; echo ---KERNEL---; uname -r; echo ---SUDO---; sudo -n -l 2>/dev/null; echo ---SUID---; find / -perm -4000 -type f 2>/dev/null | head -40; echo ---PKGS---; (dpkg -l 2>/dev/null || rpm -qa 2>/dev/null)' 2>/dev/null > "$RAW/linux/$1.txt"; }
  while read -r h; do [ -n "$h" ] && pool lg "$h"; done < "$RAW/ssh-ok.txt"
  finish
  LINUX_OK=$(ls -1 "$RAW"/linux/*.txt 2>/dev/null | wc -l)
  grep -lriE 'VERSION_ID="?(1[0-8]\.|6|7)' "$RAW"/linux/ 2>/dev/null > "$RAW/linux-eol.txt" || : > "$RAW/linux-eol.txt"
  LINUX_EOL=$(cnt "$RAW/linux-eol.txt")
  info "linux collected $LINUX_OK   possible EOL $LINUX_EOL"
else
  warn "no SSH credentials, Linux hosts assessed unauthenticated only"
fi

# =====================================================================
#  Stage 10  TLS, SNMP, web
# =====================================================================
step "Stage 10  TLS, SNMP and web"
awk '{split($2,p,","); for(i in p) if(p[i]=="443"||p[i]=="8443"||p[i]=="636"||p[i]=="993"||p[i]=="995"||p[i]=="3389") print $1":"p[i]}' \
    "$RAW/ports/map.txt" 2>/dev/null | sort -u > "$RAW/tls-endpoints.txt" || : > "$RAW/tls-endpoints.txt"
TLSN=$(cnt "$RAW/tls-endpoints.txt"); TLS_ISSUES=0
if [ "$TLSN" -gt 0 ]; then
  if [ "$HAVE_TESTSSL" -eq 1 ]; then
    : > "$RAW/tls-timeout.txt"
    tl(){
      local e="$1" f rc
      f="$RAW/tls/$(echo "$e" | tr ':' '_').txt"
      if have timeout; then
        timeout -k 20 "$TLS_CAP" testssl.sh --quiet --color 0 --severity MEDIUM \
          --sneaky "$e" > "$f" 2>&1
        rc=$?
      else
        testssl.sh --quiet --color 0 --severity MEDIUM --sneaky "$e" > "$f" 2>&1
        rc=$?
      fi
      # 124 is timeout(1) killing it. An endpoint that was cut short has NOT
      # been assessed, and must not be read as one with no issues.
      [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] && printf '%s\n' "$e" >> "$RAW/tls-timeout.txt"
      return 0
    }
    dim "each endpoint capped at $TLS_CAP"
    while read -r e; do [ -n "$e" ] && pool tl "$e"; done < "$RAW/tls-endpoints.txt"
    finish
    TLS_ISSUES=$(grep -rhE 'VULNERABLE|NOT ok' "$RAW/tls/" 2>/dev/null | wc -l)
    TLS_CUT=$(cnt "$RAW/tls-timeout.txt")
    if [ "$TLS_CUT" -gt 0 ]; then
      warn "$TLS_CUT of $TLSN TLS endpoint(s) hit the ${TLS_CAP} cap and are not assessed"
      dim "listed in $RAW/tls-timeout.txt. raise with TLS_CAP=20m, or the"
      dim "endpoint is accepting connections and never completing a handshake"
    fi
  else
    nmap -Pn -n --script ssl-enum-ciphers,ssl-cert,ssl-dh-params,sslv2,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,rdp-enum-encryption \
         --script-timeout 90s --host-timeout "$HOST_TIMEOUT" \
         -p 443,8443,636,993,995,3389 -iL "$RAW/live.txt" -oN "$RAW/tls/nmap-ssl.txt" >/dev/null 2>&1
    TLS_ISSUES=$(gcntE 'VULNERABLE|SSLv2|SSLv3|TLSv1\.0|weak' "$RAW/tls/nmap-ssl.txt")
  fi
fi
SNMPN=0
if [ "$HAVE_SNMP" -eq 1 ]; then
  printf 'public\nprivate\ncisco\nmanager\nadmin\ncommunity\nsecret\n' > "$RAW/snmp-strings.txt"
  if have timeout; then
    timeout -k 20 "$SNMP_CAP" onesixtyone -c "$RAW/snmp-strings.txt" \
      -i "$RAW/live.txt" > "$RAW/snmp.txt" 2>&1 || true
  else
    onesixtyone -c "$RAW/snmp-strings.txt" -i "$RAW/live.txt" > "$RAW/snmp.txt" 2>&1 || true
  fi
  SNMPN=$(gcnt '^\[' "$RAW/snmp.txt")
fi
awk '{split($2,p,","); for(i in p) if(p[i]=="80"||p[i]=="443"||p[i]=="8000"||p[i]=="8080"||p[i]=="8443"||p[i]=="9443"){print $1; break}}' \
    "$RAW/ports/map.txt" 2>/dev/null | sort -u > "$RAW/web-hosts.txt" || : > "$RAW/web-hosts.txt"
WEBN=$(cnt "$RAW/web-hosts.txt"); NC=0; NH=0; NM=0; NL=0; : > "$RAW/cve-web.txt"
if [ "$WEBN" -gt 0 ]; then
  WEB_CUT=0
  if have timeout; then
    timeout -k 20 "$WEB_CAP" nuclei -l "$RAW/web-hosts.txt" \
      -severity critical,high,medium,low -j -o "$RAW/nuclei.json" \
      -rl 100 -c "$JOBS" -timeout 10 -retries 1 -silent >/dev/null 2>&1
    [ "$?" -eq 124 ] && WEB_CUT=1
  else
    nuclei -l "$RAW/web-hosts.txt" -severity critical,high,medium,low -j \
      -o "$RAW/nuclei.json" -rl 100 -c "$JOBS" -timeout 10 -retries 1 \
      -silent >/dev/null 2>&1 || true
  fi
  [ "$WEB_CUT" -eq 1 ] && {
    warn "the web scan hit the ${WEB_CAP} cap, its findings are partial"
    dim "raise with WEB_CAP=60m"
  }
  if [ -s "$RAW/nuclei.json" ]; then
    NC=$(jq -r 'select(.info.severity=="critical")|.host' "$RAW/nuclei.json" 2>/dev/null | wc -l)
    NH=$(jq -r 'select(.info.severity=="high")|.host'     "$RAW/nuclei.json" 2>/dev/null | wc -l)
    NM=$(jq -r 'select(.info.severity=="medium")|.host'   "$RAW/nuclei.json" 2>/dev/null | wc -l)
    NL=$(jq -r 'select(.info.severity=="low")|.host'      "$RAW/nuclei.json" 2>/dev/null | wc -l)
    jq -r '.info.reference[]?' "$RAW/nuclei.json" 2>/dev/null | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u > "$RAW/cve-web.txt" || true
  fi
fi
info "tls $TLSN endpoints / $TLS_ISSUES issues   snmp $SNMPN   web $WEBN hosts  C:$NC H:$NH M:$NM"

# =====================================================================
#  Correlation
# =====================================================================
step "Correlation and scoring"
cat "$RAW"/cve-*.txt 2>/dev/null | grep -E '^CVE-' | sort -u > "$RAW/cve-all.txt" || : > "$RAW/cve-all.txt"
ALL_CVES=$(cnt "$RAW/cve-all.txt")
KEV_HITS=0; : > "$RAW/cve-kev.txt"
if [ "$KEV_OK" -eq 1 ] && [ -s "$RAW/cve-all.txt" ]; then
  comm -12 "$RAW/cve-all.txt" "$RAW/kev-all.txt" > "$RAW/cve-kev.txt" 2>/dev/null || true
  KEV_HITS=$(cnt "$RAW/cve-kev.txt")
  [ "$KEV_HITS" -gt 0 ] && warn "CVEs on the CISA actively exploited list: $KEV_HITS"
fi

: > "$RAW/risk-scores.txt"
while read -r ip _; do
  [ -z "$ip" ] && continue; s=0
  s=$((s + $(gcnt "^$ip," "$RAW/windows-cves.csv") * 2))
  if [ -s "$NVT_CSV" ]; then
    s=$((s + $(awk -F'","' -v I="$ip" 'NR>1{gsub(/^"/,"",$1); if($1==I && tolower($6)~/high/) c++} END{print c+0}' "$NVT_CSV") * 60))
    s=$((s + $(awk -F'","' -v I="$ip" 'NR>1{gsub(/^"/,"",$1); if($1==I && tolower($6)~/medium/) c++} END{print c+0}' "$NVT_CSV") * 15))
  fi
  grep -q "$ip" "$RAW/vuln-detail.txt" 2>/dev/null && s=$((s+300))
  grep -q "$ip.*signing:False" "$RAW/auth-smb.txt" 2>/dev/null && s=$((s+80))
  grep -q "$ip.*SMBv1:True"    "$RAW/auth-smb.txt" 2>/dev/null && s=$((s+120))
  grep -q "$ip" "$RAW/null-session.txt" 2>/dev/null && s=$((s+60))
  grep -q "$ip" "$RAW/eol-os.txt" 2>/dev/null && s=$((s+200))
  s=$((s + $(gcntiE 'VULNERABLE' "$RAW/nse/${ip}.txt") * 40))
  s=$((s + $(jq -r --arg h "$ip" 'select(.host|test($h))|select(.info.severity=="critical" or .info.severity=="high")|.host' "$RAW/nuclei.json" 2>/dev/null | wc -l) * 50))
  [ "$s" -gt 1000 ] && s=1000
  [ "$s" -gt 0 ] && echo "$s $ip" >> "$RAW/risk-scores.txt"
done < "$RAW/ports/map.txt"
sort -rn "$RAW/risk-scores.txt" -o "$RAW/risk-scores.txt" 2>/dev/null || true

: > "$RAW/attack-paths.txt"
[ "$NOSIGN" -gt 0 ] && [ "$AUTH_OK" -gt 0 ] && echo "NTLM relay: $NOSIGN host(s) without SMB signing plus working domain credentials allows relay to those hosts." >> "$RAW/attack-paths.txt"
[ "$KERB_H" -gt 0 ]   && echo "Kerberoasting: $KERB_H service ticket(s) retrievable for offline cracking." >> "$RAW/attack-paths.txt"
[ "$ASREP_H" -gt 0 ]  && echo "AS-REP roasting: $ASREP_H account(s) without Kerberos pre-authentication." >> "$RAW/attack-paths.txt"
[ "$ADCS_H" -gt 0 ]   && echo "ADCS: certificate template or CA misconfiguration, review for ESC1 to ESC8 escalation." >> "$RAW/attack-paths.txt"
[ "$GPP" -gt 0 ]      && echo "Group Policy Preferences: credentials recoverable from SYSVOL, decryptable with the public Microsoft key." >> "$RAW/attack-paths.txt"
[ "$WRITABLE" -gt 0 ] && [ "$NOSIGN" -gt 0 ] && echo "Writable share plus unsigned SMB: enables SCF or LNK planting to coerce authentication." >> "$RAW/attack-paths.txt"
[ "$LDAPSIGN" -gt 0 ] && echo "LDAP signing or channel binding not enforced: relay to LDAP enables domain object modification." >> "$RAW/attack-paths.txt"
[ "$MOD_VULN" -gt 0 ] && echo "Confirmed exploitable services identified by module checks, see the exploit module section." >> "$RAW/attack-paths.txt"
PATHS=$(cnt "$RAW/attack-paths.txt")

T1=$(date +%s); MINS=$(( (T1-T0)/60 ))

# =====================================================================
#  Self check: did this scan actually assess anything?
# =====================================================================
step "Self check"
AUTH_FINDINGS=0; AUTH_DEPTH=0; DEPTH_VERDICT="unknown"
if [ "$RUN_NVT" -eq 1 ] && [ -s "$NVT_CSV" ]; then
  AUTH_FINDINGS=$(gcnti 'Authenticated \(registry\|package\)-based' "$NVT_CSV")
  [ "$NVT_AUTH_HOSTS" -gt 0 ] && AUTH_DEPTH=$(( AUTH_FINDINGS * 100 / NVT_AUTH_HOSTS ))
elif [ "$RUN_SA" -eq 1 ]; then
  AUTH_FINDINGS="$WIN_CVES"
  [ "$SYSOK" -gt 0 ] && AUTH_DEPTH=$(( AUTH_FINDINGS * 100 / SYSOK ))
fi
DEPTH_H=$(( AUTH_DEPTH / 100 ))
APCT=0; SPCT=0; NVT_APCT=0
[ "$LIVE" -gt 0 ] && { APCT=$(( AUTH_OK*100/LIVE )); SPCT=$(( SYSOK*100/LIVE )); }
[ "$NVT_HOSTS_F" -gt 0 ] && NVT_APCT=$(( NVT_AUTH_HOSTS*100/NVT_HOSTS_F ))
COVER_PCT=$([ "$RUN_NVT" -eq 1 ] && echo "$NVT_APCT" || echo "$SPCT")

if [ "$AUTH_FINDINGS" -eq 0 ]; then
  DEPTH_VERDICT="none"
  err "no authenticated findings were produced"
  dim "credentials may have authenticated but the authenticated check set did not run"
  dim "diagnose with: $0 preflight"
elif [ "$DEPTH_H" -lt "$DEPTH_WARN" ]; then
  DEPTH_VERDICT="shallow"
  warn "authentication depth is ${DEPTH_H}.$(printf '%02d' $((AUTH_DEPTH % 100))) findings per authenticated host"
  dim "a real authenticated assessment of a Windows estate yields many per host"
  dim "this looks like a scan that logged in but never examined patch level"
else
  DEPTH_VERDICT="ok"
  info "authentication depth ${DEPTH_H}.$(printf '%02d' $((AUTH_DEPTH % 100))) findings per authenticated host"
fi

# =====================================================================
#  LLM annotation  (optional, local by default, never creates findings)
# =====================================================================
LLM_FP_COUNT=0; LLM_HOSTS=0
: > "$RAW/llm-triage.md"; : > "$RAW/llm-narrative.md"; : > "$RAW/llm-paths.md"
: > "$RAW/llm-fp-candidates.txt"

if llm_init; then
step "LLM annotation"

# ---- 1. false positive triage on Windows patch findings -------------
#  This is the highest value use. WES-NG does not model cumulative
#  update supersedence, so fully patched hosts get flagged. The model
#  reasons over build, UBR and the installed hotfix list, which no rule
#  in this script can do. It classifies only the CVEs it is given.
if [ -s "$RAW/windows-cves.csv" ] && [ "$WIN_CVES" -gt 0 ]; then
  info "triaging Windows patch findings for supersedence"
  SYS_PROMPT='You analyse Windows patch data for a vulnerability assessment.

You receive a host OS caption, build number, UBR, the installed hotfix IDs, and a list of CVEs a scanner claims are unpatched. Microsoft ships cumulative updates that supersede individual security updates, so scanners that compare against a per-CVE patch list produce false positives on fully patched hosts.

Classify each supplied CVE. Rules you must follow:
- Only classify CVE identifiers present in the input. Never introduce another identifier.
- If a later cumulative update in the installed list plausibly supersedes the fix, classify it likely_false_positive.
- If the OS build predates the fix and no superseding update is installed, classify it likely_genuine.
- If you cannot determine it from the data given, classify it uncertain. Prefer uncertain over guessing.

Respond with JSON only, no prose outside it:
{"likely_false_positive":[],"likely_genuine":[],"uncertain":[],"reasoning":"two sentences"}'

  {
    echo "## Patch Finding Triage"
    echo
    echo "Supersedence analysis per host. This addresses the known WES-NG"
    echo "limitation where cumulative updates are not modelled."
    echo
  } >> "$RAW/llm-triage.md"

  for f in "$RAW"/sysinfo/*.txt; do
    [ -e "$f" ] || continue
    [ "$LLM_CALLS" -ge "$LLM_MAX_CALLS" ] && break
    h=$(basename "$f" .txt)
    hc=$(gcnt "^$h," "$RAW/windows-cves.csv")
    [ "$hc" -eq 0 ] && continue

    osline=$(grep -i '^OS Name' "$f" | head -1)
    osver=$(grep -i '^OS Version' "$f" | head -1)
    kbs=$(grep -oE 'KB[0-9]{6,7}' "$f" | sort -u | tr '\n' ' ')
    cves=$(grep "^$h," "$RAW/windows-cves.csv" | cut -d',' -f2 | grep '^CVE-' | sort -u | head -40 | tr '\n' ' ')
    [ -z "$cves" ] && continue

    USR="Host: $h
$osline
$osver
Installed hotfixes: ${kbs:-none listed}
CVEs the scanner claims are unpatched: $cves"

    printf "    %-18s " "$h"
    if ANS=$(llm_ask "$SYS_PROMPT" "$USR"); then
      CLEAN=$(printf '%s' "$ANS" | sed -n '/{/,/}/p')
      FP=$(printf '%s' "$CLEAN" | jq -r '.likely_false_positive[]?' 2>/dev/null)
      GEN=$(printf '%s' "$CLEAN" | jq -r '.likely_genuine[]?' 2>/dev/null)
      UNC=$(printf '%s' "$CLEAN" | jq -r '.uncertain[]?' 2>/dev/null)
      RSN=$(printf '%s' "$CLEAN" | jq -r '.reasoning // empty' 2>/dev/null)

      # refuse any identifier the model introduced that was not in the input
      VALID_FP=""
      for c in $FP; do
        case " $cves " in *" $c "*) VALID_FP="$VALID_FP $c" ;; esac
      done
      NFP=$(printf '%s' "$VALID_FP" | wc -w)
      LLM_FP_COUNT=$((LLM_FP_COUNT + NFP))
      LLM_HOSTS=$((LLM_HOSTS + 1))
      for c in $VALID_FP; do echo "$h,$c" >> "$RAW/llm-fp-candidates.txt"; done

      {
        echo "### $h"
        echo
        [ -n "$osline" ] && echo "\`$(echo "$osline" | tr -s ' ')\`"
        echo
        echo "| Class | Count | CVEs |"
        echo "| --- | ---: | --- |"
        echo "| Likely false positive | $NFP | $(echo $VALID_FP | tr ' ' ', ') |"
        echo "| Likely genuine | $(echo $GEN | wc -w) | $(echo $GEN | tr ' ' ', ') |"
        echo "| Uncertain | $(echo $UNC | wc -w) | $(echo $UNC | tr ' ' ', ') |"
        echo
        [ -n "$RSN" ] && { echo "> $RSN"; echo; }
      } >> "$RAW/llm-triage.md"
      echo "${GRN}$NFP likely FP${RST} of $hc"
    else
      echo "${DIM}skipped${RST}"
    fi
  done
  [ "$LLM_FP_COUNT" -gt 0 ] && warn "$LLM_FP_COUNT finding(s) flagged as likely false positives, verify before reporting"
fi

# ---- 2. executive narrative -----------------------------------------
#  Fed metrics only, never raw findings, to keep the hallucination
#  surface as small as possible.
if [ "$LLM_CALLS" -lt "$LLM_MAX_CALLS" ]; then
  info "drafting executive narrative"
  NAR_SYS='You write the executive summary of a vulnerability assessment for a technical audience such as a CISO or head of infrastructure.

Rules:
- Use only the figures supplied. Never state a number that is not in the input.
- If authentication depth is low, say plainly that the assessment did not verify patch level and the findings below it are therefore incomplete. Do not soften this.
- Three short paragraphs maximum. No headings, no bullet points, no preamble.
- Plain professional English. No marketing language, no filler.'

  NAR_USR="Hosts in scope: $NTARGETS
Hosts responding: $LIVE
Hosts where credentials took effect: $([ "$RUN_NVT" -eq 1 ] && echo "$NVT_AUTH_HOSTS" || echo "$SYSOK")
Authenticated coverage: ${COVER_PCT}%
Authenticated findings per authenticated host: ${DEPTH_H}.$(printf '%02d' $((AUTH_DEPTH % 100)))
Depth verdict: $DEPTH_VERDICT
Unique CVEs: $ALL_CVES
CVEs on the CISA actively exploited list: $KEV_HITS
Confirmed exploitable services: $MOD_VULN
Attack paths identified: $PATHS
Hosts without SMB signing: $NOSIGN
Hosts with SMBv1: $SMBV1
Kerberoastable accounts: $KERB_H
AS-REP roastable accounts: $ASREP_H
ADCS findings: $ADCS_H
End of life systems: $EOL
Hosts that failed authentication: $AUTH_FAIL"

  if NAR=$(llm_ask "$NAR_SYS" "$NAR_USR"); then
    printf '%s\n' "$NAR" > "$RAW/llm-narrative.md"
    info "narrative drafted"
  fi
fi

# ---- 3. attack path expansion ---------------------------------------
#  The hardcoded rules cover the common chains. This looks for
#  combinations the rules do not encode.
if [ "$PATHS" -gt 0 ] && [ "$LLM_CALLS" -lt "$LLM_MAX_CALLS" ]; then
  info "expanding attack path analysis"
  PATH_SYS='You are a penetration tester reviewing internal vulnerability assessment output.

Given a list of conditions found on a Windows domain estate, identify realistic attack chains that combine two or more of them. 

Rules:
- Base every chain only on the conditions listed. Do not assume conditions that are not stated.
- For each chain give: the conditions it combines, the sequence, and the outcome.
- Maximum five chains, ordered by likelihood of success.
- Be specific about technique names where they apply.
- Markdown bullet points. No preamble.'

  PATH_USR="Conditions found:
$(cat "$RAW/attack-paths.txt")
Hosts without SMB signing: $NOSIGN
Hosts with SMBv1 enabled: $SMBV1
Hosts allowing null sessions: $NULLS
Writable shares: $WRITABLE
Kerberoastable accounts: $KERB_H
AS-REP roastable accounts: $ASREP_H
ADCS findings: $ADCS_H
LDAP signing not enforced: $LDAPSIGN
GPP credential exposure: $GPP
Confirmed exploitable services: $MOD_VULN
Accounts with password not required: $PWDNR
Hosts where our credentials are local admin: $AUTH_OK"

  if EXP=$(llm_ask "$PATH_SYS" "$PATH_USR"); then
    printf '%s\n' "$EXP" > "$RAW/llm-paths.md"
    info "attack path analysis drafted"
  fi
fi

info "LLM calls used: $LLM_CALLS of $LLM_MAX_CALLS"
fi

# =====================================================================
#  Report
# =====================================================================
step "Building report"
{
echo "# Authenticated Vulnerability Assessment"
echo
echo "**Generated:** $STAMP  "
echo "**Runtime:** ${MINS} minutes  "
echo "**Engine:** \`$ENGINE\`$([ "$RUN_NVT" -eq 1 ] && echo "  (Greenbone $NVT_FILES NVTs, $CFG_NAME)")  "
[ "$UNPRIV" -eq 1 ] && echo "**Scan privilege:** unprivileged. nmap used TCP connect probes, so live-host discovery undercounts and OS detection did not run.  "
echo "**Profile:** \`$PROFILE\` ($PORTSPEC, $JOBS workers)  "
echo "**Windows credentials:** $CREDLBL  "
echo "**Linux credentials:** $([ "$SSH_ON" -eq 1 ] && echo supplied || echo "not supplied")  "
echo "**Evidence:** \`$RAW/\`"
echo
echo "---"
echo
echo "## 1. Executive Summary"
echo
echo "| | |"
echo "| --- | --- |"
echo "| Hosts in scope | $NTARGETS |"
echo "| Hosts responding | $LIVE |"
echo "| SMB authenticated | $AUTH_OK (${APCT}% of live) |"
[ "$RUN_NVT" -eq 1 ] && echo "| **NVT authenticated checks** | **$NVT_AUTH_HOSTS of $NVT_HOSTS_F hosts (${NVT_APCT}%)** |"
[ "$RUN_SA" -eq 1 ]  && echo "| Patch level collected | $SYSOK (${SPCT}% of live) |"
[ "$RUN_NVT" -eq 1 ] && echo "| NVT findings | high $NVT_HIGH, medium $NVT_MED, low $NVT_LOW |"
echo "| Unique CVEs | $ALL_CVES |"
echo "| **Actively exploited (CISA KEV)** | **$KEV_HITS** |"
echo "| Confirmed exploitable services | $MOD_VULN |"
echo "| Attack paths identified | $PATHS |"
echo
echo "### Did this assessment actually authenticate?"
echo
echo "Two axes. Breadth without depth is the failure mode that looks like success."
echo
echo '```'
printf "  breadth  %5s%%   hosts where credentials took effect\n" "$COVER_PCT"
printf "  depth    %2d.%02d     authenticated findings per such host\n" "$DEPTH_H" "$((AUTH_DEPTH % 100))"
echo '```'
echo
case "$DEPTH_VERDICT" in
  none)
    echo "> **No authenticated findings were produced.** Credentials may have been"
    echo "> accepted, but the authenticated check set did not execute. Patch level"
    echo "> was not examined on any host. This assessment is unauthenticated in"
    echo "> substance regardless of how it was configured."
    echo ;;
  shallow)
    echo "> **Authentication was shallow.** Credentials took effect on ${COVER_PCT}% of"
    echo "> hosts but produced only ${DEPTH_H}.$(printf '%02d' $((AUTH_DEPTH % 100))) authenticated finding(s) per host. A genuine"
    echo "> authenticated assessment of a Windows estate surfaces missing cumulative"
    echo "> updates, registry configuration and installed software on every host."
    echo "> Treat the patch-level conclusions in this report as unverified."
    echo ;;
esac
if [ "$COVER_PCT" -lt 80 ]; then
  echo "> **Coverage warning.** Authenticated assessment reached ${COVER_PCT}% of hosts."
  echo "> Patch level was not verified on the remainder."
  echo
fi
if [ "$PATHS" -gt 0 ]; then
  echo "### Attack paths"; echo
  while read -r l; do [ -n "$l" ] && echo "- $l"; done < "$RAW/attack-paths.txt"; echo
fi
if [ "$KEV_HITS" -gt 0 ]; then
  echo "### Actively exploited CVEs, remediate first"; echo
  echo '```'; cat "$RAW/cve-kev.txt"; echo '```'; echo
fi
echo "### Highest risk hosts"; echo
if [ -s "$RAW/risk-scores.txt" ]; then
  echo "| Risk | Host |"; echo "| --- | --- |"
  head -20 "$RAW/risk-scores.txt" | while read -r s h; do echo "| $s / 1000 | $h |"; done
else echo "_No scored hosts._"; fi
echo

echo "---"; echo
echo "## 2. Assessment Coverage"; echo
echo "| Check | Method | Result |"
echo "| --- | --- | --- |"
[ "$RUN_NVT" -eq 1 ] && echo "| Full NVT scan | Greenbone $NVT_FILES scripts | $NVT_ROWS findings, $NVT_CVES CVEs |"
[ "$RUN_SA" -eq 1 ]  && echo "| Windows patch level | WES-NG vs MSRC | $WIN_CVES CVEs, $WIN_CRIT critical |"
[ "$RUN_SA" -eq 1 ]  && echo "| NSE vulnerability scripts | nmap \`$NSE_SET\` | $NSE_HITS vulnerable states |"
[ "$RUN_SA" -eq 1 ]  && echo "| Service version CVEs | nmap $SVC_CVE | $SVC_CVES CVEs |"
[ "$SPLOIT" -gt 0 ]  && echo "| Public exploits | searchsploit | $SPLOIT matches |"
echo "| Windows exploit modules | NetExec, 9 modules | $MOD_VULN vulnerable |"
echo "| ADCS | NetExec adcs | $ADCS_H findings |"
echo "| Kerberoasting | NetExec | $KERB_H accounts |"
echo "| AS-REP roasting | NetExec | $ASREP_H accounts |"
echo "| Delegation | NetExec | $DELEG_H findings |"
echo "| LDAP signing | NetExec ldap-checker | $LDAPSIGN findings |"
echo "| SMB signing | NetExec | $NOSIGN unsigned |"
echo "| SMBv1 | NetExec | $SMBV1 hosts |"
echo "| Null sessions | NetExec | $NULLS hosts |"
echo "| GPP credentials | NetExec | $GPP findings |"
echo "| Config baseline | NetExec wcc | $WCC_FAIL failures |"
echo "| Writable shares | NetExec | $WRITABLE |"
echo "| TLS | $([ "$HAVE_TESTSSL" -eq 1 ] && echo testssl.sh || echo "nmap ssl scripts") | $TLS_ISSUES issues, $TLSN endpoints |"
echo "| Web applications | nuclei | C:$NC H:$NH M:$NM L:$NL |"
echo "| SNMP | onesixtyone | $SNMPN default strings |"
echo "| End of life OS | nmap fingerprint | $EOL windows, $LINUX_EOL linux |"
echo "| Linux inventory | SSH | $LINUX_OK hosts |"
echo
[ "$RUN_SA" -eq 1 ] && { echo "> **Validation note.** WES-NG infers missing patches from the installed hotfix"; \
  echo "> list and does not fully model cumulative update supersedence. Fully patched"; \
  echo "> hosts can be reported as vulnerable. Validate against build and UBR."; echo; }

if [ "$RUN_NVT" -eq 1 ] && [ -s "$NVT_CSV" ]; then
echo "---"; echo
echo "## 3. NVT Findings"; echo
echo "### High severity"; echo
echo '```'
awk -F'","' 'NR>1 && tolower($6) ~ /high/ {gsub(/^"/,"",$1); printf "%-16s %-10s %-6s %s\n",$1,$3,$5,substr($9,1,78)}' "$NVT_CSV" 2>/dev/null | head -120
echo '```'; echo
echo "### Medium severity"; echo
echo '```'
awk -F'","' 'NR>1 && tolower($6) ~ /medium/ {gsub(/^"/,"",$1); printf "%-16s %-10s %-6s %s\n",$1,$3,$5,substr($9,1,78)}' "$NVT_CSV" 2>/dev/null | head -100
echo '```'; echo
echo "### Findings per host"; echo
echo '```'
awk -F'","' 'NR>1{gsub(/^"/,"",$1); if(tolower($6)~/high|medium/) print $1}' "$NVT_CSV" 2>/dev/null | sort | uniq -c | sort -rn | head -40
echo '```'; echo
echo "### Detection method breakdown"; echo
echo "How each finding was actually determined. Authenticated checks are the ones that verify patch level."; echo
echo '```'
grep -oE 'Detection Reliability: [^"]*' "$NVT_CSV" 2>/dev/null | sort | uniq -c | sort -rn | head -12
echo '```'; echo
echo "### Hosts with authenticated checks"; echo
echo '```'; [ -s "$RAW/nvt/authenticated-hosts.txt" ] && cat "$RAW/nvt/authenticated-hosts.txt" || echo "None. Credentials did not take effect."; echo '```'; echo
echo "### Hosts assessed unauthenticated only"; echo
echo "Patch level unverified on these."; echo
echo '```'; [ -s "$RAW/nvt/unauth-hosts.txt" ] && head -80 "$RAW/nvt/unauth-hosts.txt" || echo "None"; echo '```'; echo
echo "### Top NVTs by frequency"; echo
echo '```'
awk -F'","' 'NR>1 && tolower($6)~/high|medium/{print substr($9,1,70)}' "$NVT_CSV" 2>/dev/null | sort | uniq -c | sort -rn | head -40
echo '```'; echo
fi

if [ "$RUN_SA" -eq 1 ]; then
echo "---"; echo
echo "## 3B. Windows Patch Level"; echo
echo "Two methods are reported separately because they have opposite error"
echo "profiles and must not be read as one number."; echo
echo "**MSRC build comparison** compares the OS build each host reports against"
echo "the build Microsoft states fixes each CVE. For cumulative-update Windows"
echo "that is the complete supersedence check, so it cannot report a patch the"
echo "host already has. It covers the operating system only."; echo
echo "**WES-NG** maps the hotfix list from \`systeminfo\` against the MSRC"
echo "bulletin feed. It reaches beyond the OS, but its own documentation states"
echo "that \"the data provided by Microsoft's MSRC feed is frequently incomplete"
echo "and false positives are reported by wes.py\". Treat its output as leads to"
echo "confirm, not as confirmed findings."; echo
echo "---"; echo
echo "### MSRC build comparison"; echo
if [ "$MSRC_ASSESSED" -gt 0 ]; then
  echo "Hosts assessed: **$MSRC_ASSESSED** of $AUTH_OK authenticated  "
  echo "Hosts behind the required build: **$MSRC_BEHIND**  "
  echo "Distinct CVEs: **$MSRC_CVES**  "
  echo "Actively exploited per Microsoft: **$MSRC_EXPL**"; echo
  if [ -s "$RAW/windows-patch-msrc.csv" ]; then
    echo "#### Highest scoring, with the KB that fixes each"; echo
    echo '```'
    { head -1 "$RAW/windows-patch-msrc.csv"
      tail -n +2 "$RAW/windows-patch-msrc.csv" \
        | sort -t',' -k3 -rn | head -40; } | cut -d',' -f1-9
    echo '```'; echo
  fi
  if awk -F',' 'NR>1 && $8=="yes"' "$RAW/windows-patch-msrc.csv" 2>/dev/null | grep -q .; then
    echo "#### Microsoft records these as exploited in the wild"; echo
    echo '```'
    awk -F',' 'NR>1 && $8=="yes"{print $1","$2","$3","$6}' \
      "$RAW/windows-patch-msrc.csv" | sort -u | head -40
    echo '```'; echo
  fi
  echo "#### Per-host coverage, including what could not be assessed"; echo
  echo "A host that could not be read is a coverage gap, not an absence of"
  echo "findings, and is listed here for that reason."; echo
  echo '```'; cat "$RAW/windows-patch-coverage.csv" | head -60; echo '```'; echo
  if awk -F',' 'NR>1 && $12=="yes"' "$RAW/windows-patch-coverage.csv" 2>/dev/null | grep -q .; then
    echo "> Some hosts sit below the oldest month in the data window, so their"
    echo "> CVE counts are a floor and not a total: updates released before the"
    echo "> window are missing as well and are not counted."; echo
  fi
else
  echo "_Not assessed. Either no host authenticated, or Microsoft's patch data"
  echo "was not compiled on this machine (\`sudo $0 update\`)._"; echo
fi
echo "### WES-NG, hotfix-list inference"; echo
if [ "$WIN_CVES" -gt 0 ]; then
  echo "### CVE count by host"; echo
  echo '```'; tail -n +2 "$RAW/windows-cves.csv" | cut -d',' -f1 | sort | uniq -c | sort -rn | head -40; echo '```'; echo
  echo "### Critical severity"; echo
  echo '```'; head -1 "$RAW/windows-cves.csv"; grep -i critical "$RAW/windows-cves.csv" | head -50; echo '```'
else echo "_No data. No hosts authenticated, or remote command execution was blocked._"; fi
echo
echo "## 3C. NSE Vulnerability Findings"; echo
if [ "$NSE_HITS" -gt 0 ]; then echo '```'; grep -B6 'VULNERABLE' "$RAW/nse-all.txt" 2>/dev/null | head -150; echo '```'
elif [ "${NSE_SCANNED:-0}" -eq 0 ] && [ "$HOSTS_OPEN" -gt 0 ]; then
  # Never "nothing found" when nothing was looked at. nmap segfaulted on
  # every host once and this section said no vulnerable state was reported,
  # which a reader would take as an assessment rather than a tool failure.
  echo "**Not assessed.** nmap produced no output for any of the $HOSTS_OPEN"
  echo "hosts with open ports, so this is a coverage gap and not a finding of"
  echo "absence. Per-host exit status is in \`$RAW/nse-failed.txt\`; status 139"
  echo "is a segmentation fault. Re-run with \`SVC_CVE_ENGINE=none\` to drop the"
  echo "service-CVE script, which is the usual cause."
else
  echo "_No NSE script reported a vulnerable state on the ${NSE_SCANNED:-0} host(s) assessed._"
  [ "${NSE_FAILED:-0}" -gt 0 ] && { echo; echo "${NSE_FAILED} host(s) failed the full script set; see \`$RAW/nse-failed.txt\`."; }
fi
echo
if [ "$SPLOIT" -gt 0 ]; then echo "### Public exploits"; echo; echo '```'; head -60 "$RAW/searchsploit.txt"; echo '```'; echo; fi
fi

echo "---"; echo
echo "## 4. Confirmed Exploitable"; echo
if [ -s "$RAW/vuln-summary.txt" ]; then
  echo '```'; cat "$RAW/vuln-summary.txt"; echo '```'; echo
  echo '```'; head -80 "$RAW/vuln-detail.txt"; echo '```'
else echo "_No hosts flagged by ms17-010, zerologon, petitpotam, nopac, smbghost, printnightmare, spooler, webdav or coerce_plus._"; fi
echo

echo "## 5. Active Directory"; echo
echo "### ADCS"; echo '```'; head -40 "$RAW/ad/adcs.txt" 2>/dev/null || echo "No data"; echo '```'; echo
echo "### Kerberoastable accounts"; echo '```'; grep -iE 'krb5tgs|sAMAccountName|\[\+\]' "$RAW/ad/kerberoast.txt" 2>/dev/null | head -30 || echo "None"; echo '```'; echo
echo "### AS-REP roastable accounts"; echo '```'; grep -iE 'krb5asrep|\[\+\]' "$RAW/ad/asreproast.txt" 2>/dev/null | head -30 || echo "None"; echo '```'; echo
echo "### Delegation"; echo '```'; head -30 "$RAW/ad/delegation.txt" 2>/dev/null || echo "No data"; echo '```'; echo
echo "### LDAP signing and channel binding"; echo '```'; head -30 "$RAW/ad/ldap-signing.txt" 2>/dev/null || echo "No data"; echo '```'; echo
echo "### Machine account quota"; echo '```'; grep -i quota "$RAW/ad/machine-quota.txt" 2>/dev/null | head -10 || echo "No data"; echo '```'; echo
echo "### Password not required"; echo '```'; head -20 "$RAW/ad/pwd-not-required.txt" 2>/dev/null || echo "None"; echo '```'; echo
echo "### Credentials in user descriptions"; echo '```'; grep -iE 'pass|pwd' "$RAW/ad/user-descriptions.txt" 2>/dev/null | head -20 || echo "None"; echo '```'; echo

echo "## 6. TLS"; echo
echo '```'
if [ "$HAVE_TESTSSL" -eq 1 ]; then grep -rhE 'VULNERABLE|NOT ok' "$RAW/tls/" 2>/dev/null | sort | uniq -c | sort -rn | head -60 || echo "No issues"
else grep -E 'VULNERABLE|SSLv2|SSLv3|TLSv1\.0|weak|expired' "$RAW/tls/nmap-ssl.txt" 2>/dev/null | head -60 || echo "No issues"; fi
echo '```'; echo

echo "## 7. Web Applications"; echo
echo "| Severity | Count |"; echo "| --- | --- |"
echo "| Critical | $NC |"; echo "| High | $NH |"; echo "| Medium | $NM |"; echo "| Low | $NL |"; echo
if [ -s "$RAW/nuclei.json" ]; then
  echo '```'
  jq -r 'select(.info.severity=="critical" or .info.severity=="high" or .info.severity=="medium")|"\(.info.severity|ascii_upcase)  \(.host)  \(.info.name)"' "$RAW/nuclei.json" 2>/dev/null | head -100
  echo '```'
else echo "_No web findings._"; fi
echo

echo "---"; echo
echo "## 8. Configuration"; echo
echo "SMB signing not required: **$NOSIGN**  "
echo "SMBv1 enabled: **$SMBV1**  "
echo "Null sessions permitted: **$NULLS**  "
echo "Writable shares: **$WRITABLE**"; echo
echo "### Hosts without SMB signing"; echo
echo '```'; grep 'signing:False' "$RAW/auth-smb.txt" 2>/dev/null | awk '{print $2,$4}' | sort -u | head -60 || echo "None"; echo '```'; echo
echo "### Configuration baseline failures"; echo '```'; head -100 "$RAW/config-check.txt" 2>/dev/null || echo "No data"; echo '```'; echo
echo "### Group Policy credential exposure"; echo '```'; grep -iE 'password|username' "$RAW/gpp-password.txt" "$RAW/gpp-autologin.txt" 2>/dev/null | head -30 || echo "None"; echo '```'; echo
echo "### Writable shares"; echo '```'; grep -i 'READ,WRITE' "$RAW/shares.txt" 2>/dev/null | head -60 || echo "None"; echo '```'; echo
echo "### Password policy"; echo '```'; head -60 "$RAW/password-policy.txt" 2>/dev/null; echo '```'; echo
echo "### Local administrators"; echo '```'; head -80 "$RAW/local-admins.txt" 2>/dev/null; echo '```'; echo
echo "### Endpoint protection"; echo '```'; head -60 "$RAW/endpoint-protection.txt" 2>/dev/null; echo '```'; echo

echo "## 9. End of Life Systems"; echo
echo "### Windows"; echo '```'; [ -s "$RAW/eol-os.txt" ] && cat "$RAW/eol-os.txt" || echo "None detected"; echo '```'; echo
echo "### Linux"; echo '```'; [ -s "$RAW/linux-eol.txt" ] && cat "$RAW/linux-eol.txt" || echo "None detected"; echo '```'; echo

echo "## 10. Other Protocols"; echo
echo "MSSQL authenticated: **$MSSQL_OK**  "
echo "WinRM authenticated: **$WINRM_OK**  "
echo "SNMP default strings: **$SNMPN**"; echo
[ "$SNMPN" -gt 0 ] && { echo '```'; cat "$RAW/snmp.txt"; echo '```'; echo; }

if [ "${NSE_FAILED:-0}" -gt 0 ] || [ "${TLS_CUT:-0}" -gt 0 ]; then
  echo "### Tooling that did not complete"; echo
  [ "${NSE_FAILED:-0}" -gt 0 ] && {
    echo "nmap failed on ${NSE_FAILED} of $HOSTS_OPEN host(s) with the full"
    echo "script set. ${NSE_DEGRADED:-0} recovered with the vulnerability"
    echo "scripts alone, so those hosts have no service-CVE mapping."; echo; }
  [ "${TLS_CUT:-0}" -gt 0 ] && {
    echo "${TLS_CUT} TLS endpoint(s) exceeded the ${TLS_CAP} cap and were not"
    echo "assessed; they are listed in \`$RAW/tls-timeout.txt\`."; echo; }
fi

echo "---"; echo
echo "## 10B. Vulnerability Data Provenance"; echo
echo "PCI DSS v4.0.1 requirement 11.3.1 requires that the scan tool \"is kept up"
echo "to date with the latest vulnerability information\", and testing procedure"
echo "11.3.1.c has the assessor examine that it is. This is that evidence: what"
echo "each data source was, when it was fetched, and the digest of the exact"
echo "bytes used."; echo
echo "| Source | Version or window | Fetched | Size | SHA-256 |"
echo "|---|---|---|---|---|"
if msrc_ready; then
  msrc_py window --db "$MSRC_DB" 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
w = d.get("window") or {}
rows = d.get("provenance") or []
months = ", ".join(w.get("months_with_windows_data") or []) or "none"
print("| MSRC CVRF (compiled table) | %s | %s | %d documents | - |"
      % (months, (rows[0].get("fetched") if rows else None) or "-", len(rows)))
for p in sorted(rows, key=lambda r: r.get("month") or ""):
    print("| %s | document v%s, released %s | %s | %s bytes | `%s` |"
          % (p.get("source") or "-", p.get("document_version") or "?",
             (p.get("current_release") or "?")[:10], p.get("fetched") or "-",
             p.get("bytes") or "?", (p.get("sha256") or "-")[:16] + "..."))
if w.get("empty_months"):
    print()
    print("Months fetched that carried no Windows build data: %s. These are"
          % ", ".join(w["empty_months"]))
    print("published before their Patch Tuesday; they are recorded so the window")
    print("is not narrowed without the reader being told.")
' 2>/dev/null
else
  echo "| MSRC CVRF | not compiled | - | - | - |"
fi
for _f in "$HOME/.kameki-kev.json:CISA KEV catalogue" \
          "$HOME/definitions.zip:WES-NG definitions"; do
  _p="${_f%%:*}"; _n="${_f#*:}"
  if [ -s "$_p" ]; then
    printf "| %s | - | %s | %s bytes | \`%s...\` |\n" "$_n" \
      "$(date -u -r "$_p" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo -)" \
      "$(wc -c < "$_p" | tr -d ' ')" \
      "$(sha256sum "$_p" 2>/dev/null | cut -c1-16 || echo '-')"
  else
    printf "| %s | absent | - | - | - |\n" "$_n"
  fi
done
if [ "$RUN_NVT" -eq 1 ]; then
  printf "| Greenbone NVT feed | %s scripts | - | - | - |\n" "$NVT_FILES"
  echo
  echo "> The Greenbone community feed's newest Windows cumulative-update check"
  echo "> is dated 2025-10-15, so its Windows patch coverage is not current."
  echo "> Windows patch level in this report rests on the MSRC build comparison"
  echo "> above, not on the NVT feed."
fi
echo
echo "---"; echo
echo "## 11. Coverage Gaps"; echo
echo "### SMB authentication failed"; echo
if [ -s "$RAW/auth-fail.txt" ]; then
  echo "No configuration or patch level assessment exists for these hosts."; echo
  echo '```'; cat "$RAW/auth-fail.txt"; echo '```'
else echo "_All reachable hosts authenticated._"; fi
echo
if [ "$RUN_SA" -eq 1 ] && [ "$AUTH_OK" -gt "$SYSOK" ]; then
  echo "### Authenticated but command execution blocked"; echo
  echo "$(( AUTH_OK - SYSOK )) host(s) authenticated but returned no systeminfo, likely EDR or policy restriction. Configuration data exists for them, patch level does not."; echo
fi
echo "### No response to discovery"; echo
if [ -s "$RAW/no-response.txt" ]; then echo '```'; cat "$RAW/no-response.txt"; echo '```'
else echo "_All targets responded._"; fi
echo
if [ "$MULTI" -eq 1 ] && [ -s "$RAW/working-creds.txt" ]; then
  echo "### Successful credential pairs"; echo; echo '```'; head -100 "$RAW/working-creds.txt"; echo '```'; echo
fi

echo "---"; echo
if [ "$LLM_ON" -eq 1 ]; then
echo "---"; echo
echo "## 11B. Machine Assisted Analysis"; echo
echo "> Everything in this section was produced by a language model"
echo "> (\`$LLM_MODEL\`) reasoning over the findings above. It annotates"
echo "> results the scanners produced and cannot introduce findings of its"
echo "> own. Sections 1 through 11 are deterministic and reproduce"
echo "> identically on a rerun; this section does not. Treat it as analyst"
echo "> assistance, verify before it reaches a client."
echo
if [ -s "$RAW/llm-narrative.md" ]; then
  echo "### Executive narrative"; echo
  cat "$RAW/llm-narrative.md"; echo
fi
if [ "$LLM_FP_COUNT" -gt 0 ]; then
  echo "### Suspected false positives"; echo
  echo "**$LLM_FP_COUNT finding(s)** across $LLM_HOSTS host(s) may be false"
  echo "positives caused by cumulative update supersedence, which WES-NG does"
  echo "not model. Verify each against the host build and UBR before removing"
  echo "or reporting it."
  echo
  echo '```'
  head -60 "$RAW/llm-fp-candidates.txt" 2>/dev/null
  echo '```'
  echo
  echo "Per host reasoning: \`$RAW/llm-triage.md\`"
  echo
fi
if [ -s "$RAW/llm-paths.md" ]; then
  echo "### Extended attack path analysis"; echo
  echo "Chains beyond the rules encoded in section 1."; echo
  cat "$RAW/llm-paths.md"; echo
fi
fi

echo "---"; echo
echo "## 12. OS Inventory"; echo
echo '```'; head -250 "$RAW/os-inventory.txt" 2>/dev/null; echo '```'; echo

echo "## 13. Evidence"; echo; echo "| File | Contents |"; echo "| --- | --- |"
echo "| \`$RAW/cve-all.txt\` | Every unique CVE, all sources |"
echo "| \`$RAW/cve-kev.txt\` | CVEs on the CISA exploited list |"
echo "| \`$RAW/risk-scores.txt\` | Per host risk score |"
echo "| \`$RAW/attack-paths.txt\` | Correlated attack paths |"
[ "$RUN_NVT" -eq 1 ] && echo "| \`$NVT_CSV\` | Greenbone CSV, all findings |"
[ "$RUN_NVT" -eq 1 ] && echo "| \`$RAW/nvt/report-full.xml\` | Greenbone XML, every field |"
[ "$RUN_NVT" -eq 1 ] && echo "| \`$RAW/nvt/authenticated-hosts.txt\` | Hosts where credentials took effect |"
[ "$RUN_SA" -eq 1 ]  && echo "| \`$RAW/windows-cves.csv\` | WES-NG Windows CVEs per host |"
[ "$RUN_SA" -eq 1 ]  && echo "| \`$RAW/sysinfo/\` | Raw systeminfo per host |"
[ "$RUN_SA" -eq 1 ]  && echo "| \`$RAW/nse/\` | NSE output per host |"
echo "| \`$RAW/mods/\` | Exploit module output |"
echo "| \`$RAW/ad/\` | Active Directory findings |"
echo "| \`$RAW/linux/\` | Linux inventory per host |"
echo "| \`$RAW/tls/\` | TLS assessment per endpoint |"
echo "| \`$RAW/nuclei.json\` | Web findings, JSON |"
echo "| \`$RAW/services.xml\` | Full nmap XML |"
echo "| \`$RAW/ports/map.txt\` | Open ports per host |"
echo
echo "## 14. Recommended Order of Work"; echo
N=1
[ "$KEV_HITS" -gt 0 ]  && { echo "$N. Remediate the $KEV_HITS actively exploited CVEs."; N=$((N+1)); }
[ "$MOD_VULN" -gt 0 ]  && { echo "$N. Patch the confirmed exploitable services."; N=$((N+1)); }
[ "$PATHS" -gt 0 ]     && { echo "$N. Break the attack paths in section 1."; N=$((N+1)); }
[ "$AUTH_FAIL" -gt 0 ] && { echo "$N. Resolve authentication on $AUTH_FAIL host(s), they are unassessed."; N=$((N+1)); }
[ "$RUN_SA" -eq 1 ]    && { echo "$N. Validate WES-NG findings against build and UBR before reporting."; N=$((N+1)); }
[ "$SSH_ON" -eq 0 ]    && echo "$N. Supply SSH credentials to assess Linux hosts at package level."
echo
} > "$MD"

echo
info "complete in ${MINS} minutes"
echo "    report   $MD"
echo "    evidence $RAW/"
echo
echo "    engine    $ENGINE"
echo "    coverage  live $LIVE/$NTARGETS   smb-auth $AUTH_OK (${APCT}%)$([ "$RUN_NVT" -eq 1 ] && echo "   nvt-auth $NVT_AUTH_HOSTS/$NVT_HOSTS_F (${NVT_APCT}%)")$([ "$RUN_SA" -eq 1 ] && echo "   patch-data $SYSOK")"
echo "    findings  cve $ALL_CVES   ${RED}kev $KEV_HITS${RST}   exploitable $MOD_VULN$([ "$RUN_NVT" -eq 1 ] && echo "   nvt high $NVT_HIGH med $NVT_MED")   web $((NC+NH+NM))   tls $TLS_ISSUES"
echo "    ad        adcs $ADCS_H   kerberoast $KERB_H   asrep $ASREP_H   ldap-sign $LDAPSIGN"
echo "    paths     $PATHS attack path(s)"
