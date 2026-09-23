#!/usr/bin/env bash
#
#  kameki.sh  -  Authenticated vulnerability assessment, self provisioning
#
#  Subcommands
#    install            install every dependency (needs internet)
#    install --bundle F install from an offline bundle (no internet)
#    bundle             build an offline bundle at the office
#    doctor             diagnose what is missing or broken, including auth
#    preflight          test credential formats safely against one host
#    run                run the assessment (default)
#    cleanup            shred credentials and remove artifacts
#
#  Engines
#    nvt         full Greenbone NVT feed (~100k scripts) over the gvmd
#                socket. No web UI. Used automatically when available.
#    standalone  WES-NG patch mapping, nmap NSE, service CVE mapping.
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
#    ./kameki.sh install --bundle kameki-bundle-*.tar.zst
#    ./kameki.sh preflight                 # confirm credential format
#    ./kameki.sh run
#    ./kameki.sh cleanup                   # before you leave site
#
set -uo pipefail

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
SCAN_CONFIG="${SCAN_CONFIG:-fast}"
ALIVE_TEST="${ALIVE_TEST:-ICMP, TCP-ACK Service & ARP Ping}"
DEPTH_WARN="${DEPTH_WARN:-3}"      # authenticated findings per host below which we warn
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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
cnt(){ [ -f "$1" ] && grep -c . "$1" 2>/dev/null || echo 0; }
pool(){ while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 0.2; done; "$@" & }
finish(){ wait; }
is_done(){ [ "$RESUME" = "1" ] && [ -f "$RAW/.done-$1" ]; }
mark_done(){ touch "$RAW/.done-$1"; }

need_root(){ [ "$(id -u)" -eq 0 ] || { err "this needs root: sudo $0 $*"; exit 1; }; }

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
      have zstd || { err "zstd required to unpack. apt install zstd"; exit 1; }
      tar --zstd -xf "$BUNDLE" -C "$B"
    else
      tar -xzf "$BUNDLE" -C "$B"
    fi

    if [ -d "$B/deb" ]; then
      info "installing system packages from bundle"
      dpkg -i "$B"/deb/*.deb >/dev/null 2>&1 || apt-get -f install -y >/dev/null 2>&1
    fi
    if [ -d "$B/wheels" ]; then
      info "installing python tools from bundle"
      pip3 install --break-system-packages --no-index --find-links "$B/wheels" netexec wesng gvm-tools >/dev/null 2>&1 \
        || warn "python tool install reported errors"
    fi
    [ -f "$B/nuclei" ]        && { install -m755 "$B/nuclei" /usr/local/bin/nuclei; info "nuclei installed"; }
    [ -d "$B/nuclei-templates" ] && { mkdir -p /root/.local/nuclei-templates; cp -r "$B/nuclei-templates/." /root/.local/nuclei-templates/; info "nuclei templates installed"; }
    [ -d "$B/vulscan" ]      && { cp -r "$B/vulscan" /usr/share/nmap/scripts/; nmap --script-updatedb >/dev/null 2>&1; info "vulscan installed"; }
    [ -d "$B/testssl.sh" ]   && { cp -r "$B/testssl.sh" /opt/; ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; info "testssl.sh installed"; }
    [ -f "$B/definitions.zip" ] && { cp "$B/definitions.zip" "${SUDO_USER:+/home/$SUDO_USER/}definitions.zip" 2>/dev/null || cp "$B/definitions.zip" /root/; info "WES-NG definitions installed"; }
    [ -f "$B/kev.json" ]     && { cp "$B/kev.json" "${SUDO_USER:+/home/$SUDO_USER/}.kameki-kev.json" 2>/dev/null || cp "$B/kev.json" /root/.kameki-kev.json; info "KEV catalogue installed"; }

    if [ -f "$B/openvas-feed.tar.zst" ]; then
      info "restoring Greenbone NVT feed, this takes a few minutes"
      mkdir -p /var/lib/openvas
      tar --zstd -xf "$B/openvas-feed.tar.zst" -C /var/lib/openvas
      chown -R _gvm:_gvm /var/lib/openvas 2>/dev/null || true
      info "feed restored: $(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l) NVTs"
    fi
    if [ -f "$B/gvm-data.tar.zst" ]; then
      info "restoring gvmd data"
      tar --zstd -xf "$B/gvm-data.tar.zst" -C /var/lib
      chown -R _gvm:_gvm /var/lib/gvm 2>/dev/null || true
    fi
    rm -rf "$B"
    info "offline install complete"
    dim "run: $0 doctor"
    return 0
  fi

  # ---- online install
  info "updating package lists"
  apt-get update -qq || warn "apt update had errors"

  info "installing system packages"
  apt-get install -y -qq nmap jq gawk curl git zstd unzip python3-pip pipx \
                         exploitdb onesixtyone poppler-utils >/dev/null 2>&1 \
    || warn "some system packages failed, continuing"

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
  have nuclei && { info "updating nuclei templates"; nuclei -update-templates -silent >/dev/null 2>&1 || warn "template update failed"; }

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

  info "fetching WES-NG definitions"
  local WESBIN=""; for c in wes wes.py; do have "$c" && { WESBIN="$c"; break; }; done
  [ -n "$WESBIN" ] && { su "${SUDO_USER:-root}" -c "$WESBIN --update" >/dev/null 2>&1 || warn "WES-NG definition update failed"; }

  info "fetching CISA KEV catalogue"
  curl -s --max-time 60 -o "${SUDO_USER:+/home/$SUDO_USER/}.kameki-kev.json" "$KEV_URL" 2>/dev/null \
    || curl -s --max-time 60 -o /root/.kameki-kev.json "$KEV_URL" 2>/dev/null || warn "KEV download failed"

  if have gvmd && [ "$WITH_NVT" -eq 1 ]; then
    echo
    warn "Greenbone needs one more manual step, it prints a password you must save:"
    dim "sudo gvm-setup"
    dim "sudo greenbone-feed-sync        # ~5 GB, do this before leaving the office"
    dim "then put the admin credentials in gmp-user.txt and gmp-pass.txt"
  fi

  echo
  info "install complete"
  dim "open a new shell for PATH changes, then: $0 doctor"
}

# =====================================================================
#  bundle   (build at the office, carry to site)
# =====================================================================
cmd_bundle(){
  step "Building offline bundle"
  local OUT="kameki-bundle-${DATE}.tar.zst"
  local B; B=$(mktemp -d)
  have zstd || { err "zstd required: sudo apt install zstd -y"; exit 1; }

  info "collecting python wheels"
  mkdir -p "$B/wheels"
  pip3 download -q -d "$B/wheels" "$NETEXEC_REPO" wesng gvm-tools >/dev/null 2>&1 \
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
    tar --zstd -cf "$B/openvas-feed.tar.zst" -C /var/lib/openvas plugins 2>/dev/null \
      || warn "feed archive failed, may need sudo"
    [ -d /var/lib/gvm ] && tar --zstd -cf "$B/gvm-data.tar.zst" -C /var/lib gvm 2>/dev/null || true
  else
    warn "NVT feed not present or incomplete ($NVTN scripts), bundle will be standalone only"
    dim "run: sudo greenbone-feed-sync    then rebuild the bundle"
  fi

  cp "$0" "$B/kameki.sh"
  cat > "$B/README.txt" <<EOF
kameki offline bundle, built $STAMP
NVT scripts included: $NVTN

On the target machine:
  sudo ./kameki.sh install --bundle $OUT
  ./kameki.sh doctor
EOF

  info "compressing"
  tar --zstd -cf "$OUT" -C "$B" . && info "bundle: $OUT ($(du -h "$OUT" | cut -f1))"
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
  for t in testssl.sh searchsploit onesixtyone gvm-cli; do
    have "$t" && printf "    %-14s ok\n" "$t" || printf "    %-14s ${YEL}absent (optional)${RST}\n" "$t"
  done

  echo
  echo "  data"
  local NVTN=0
  [ -d /var/lib/openvas/plugins ] && NVTN=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l)
  if [ "$NVTN" -ge 10000 ]; then printf "    %-14s ok (%s scripts)\n" "NVT feed" "$NVTN"
  else printf "    %-14s ${YEL}%s scripts, run: sudo greenbone-feed-sync${RST}\n" "NVT feed" "$NVTN"; fi
  [ -d /usr/share/nmap/scripts/vulscan ] && printf "    %-14s ok\n" "vulscan" || printf "    %-14s ${YEL}absent${RST}\n" "vulscan"
  { [ -f definitions.zip ] || [ -f "$HOME/definitions.zip" ]; } && printf "    %-14s ok\n" "wes defs" || printf "    %-14s ${YEL}run: wes --update${RST}\n" "wes defs"
  [ -f "$HOME/.kameki-kev.json" ] && printf "    %-14s ok\n" "KEV" || printf "    %-14s ${YEL}absent${RST}\n" "KEV"

  echo
  echo "  greenbone"
  local SOCK=""
  for s in /run/gvmd/gvmd.sock /var/run/gvmd/gvmd.sock /run/gvm/gvmd.sock /var/run/gvm/gvmd.sock; do
    [ -S "$s" ] && { SOCK="$s"; break; }
  done
  if [ -n "$SOCK" ]; then
    printf "    %-14s ok (%s)\n" "gvmd socket" "$SOCK"
    if [ -s gmp-user.txt ] && [ -s gmp-pass.txt ] && have gvm-cli; then
      local R; R=$(gvm-cli --gmp-username "$(head -n1 gmp-user.txt)" --gmp-password "$(head -n1 gmp-pass.txt)" \
                   socket --socketpath "$SOCK" --xml "<get_version/>" 2>&1)
      echo "$R" | grep -q 'status="200"' && printf "    %-14s ok\n" "gmp auth" \
        || { printf "    %-14s ${RED}failed${RST}\n" "gmp auth"; ISSUES=$((ISSUES+1)); }
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

  local HOST; HOST=$(grep -ve '^\s*$' targets.txt | head -n1)
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
    local H; H=$(grep -ciE 'kameki|nxc |gvm-cli' "$HOME/.bash_history" 2>/dev/null || echo 0)
    sed -i '/nxc .*-p /d;/gvm-cli.*--gmp-password/d' "$HOME/.bash_history" 2>/dev/null
    printf "    %-18s %s line(s) scrubbed\n" "bash_history" "$H"
  fi

  if [ -d /run/gvmd ] && have gvm-cli && [ -s gmp-user.txt ]; then
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
=====================================================================
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
if command -v gvm-cli >/dev/null 2>&1; then
  for s in /run/gvmd/gvmd.sock /var/run/gvmd/gvmd.sock /run/gvm/gvmd.sock \
           /var/run/gvm/gvmd.sock "$HOME/.gvm/gvmd/gvmd.sock"; do
    [ -S "$s" ] && { SOCK="$s"; break; }
  done
  if [ -n "$SOCK" ] && [ -s gmp-user.txt ] && [ -s gmp-pass.txt ]; then
    NVT_FILES=$(find /var/lib/openvas/plugins -name '*.nasl' 2>/dev/null | wc -l)
    [ "$NVT_FILES" -ge 10000 ] && NVT_READY=1
  fi
fi
if [ "$NVT_READY" -eq 1 ]; then
  printf "    %-14s ok  (%s NVTs, %s)\n" "greenbone" "$NVT_FILES" "$SOCK"
else
  printf "    %-14s %s\n" "greenbone" "unavailable"
  [ -z "$SOCK" ] && dim "no gvmd socket, or gvm-cli missing. run: $0 --setup"
  [ -n "$SOCK" ] && [ "$NVT_FILES" -lt 10000 ] && dim "feed incomplete ($NVT_FILES NVTs). run: sudo greenbone-feed-sync"
  [ -n "$SOCK" ] && { [ -s gmp-user.txt ] && [ -s gmp-pass.txt ] || dim "gmp-user.txt and gmp-pass.txt not found"; }
fi

# --- standalone engine components
WES=""; for c in wes wes.py; do command -v "$c" >/dev/null 2>&1 && { WES="$c"; break; }; done
SVC_CVE="none"
[ -d /usr/share/nmap/scripts/vulscan ]     && SVC_CVE="vulscan"
[ -f /usr/share/nmap/scripts/vulners.nse ] && SVC_CVE="vulners"
SA_READY=0
[ -n "$WES" ] && [ "$SVC_CVE" != "none" ] && SA_READY=1
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
  auto)       if [ "$NVT_READY" -eq 1 ]; then ENGINE=nvt; else ENGINE=standalone; fi ;;
  nvt)        [ "$NVT_READY" -eq 1 ] || { err "ENGINE=nvt but Greenbone is not available. Run: $0 --setup"; exit 1; } ;;
  standalone) : ;;
  both)       [ "$NVT_READY" -eq 1 ] || { err "ENGINE=both requires Greenbone."; exit 1; } ;;
  *) err "ENGINE must be auto, nvt, standalone or both"; exit 1 ;;
esac
RUN_NVT=0; RUN_SA=0
case "$ENGINE" in
  nvt)        RUN_NVT=1 ;;
  standalone) RUN_SA=1 ;;
  both)       RUN_NVT=1; RUN_SA=1 ;;
esac
if [ "$RUN_SA" -eq 1 ] && [ "$SA_READY" -eq 0 ]; then
  err "standalone engine selected but wes or the service CVE engine is missing"; exit 1
fi
info "engine: ${CYN}$ENGINE${RST}"

# =====================================================================
#  2. Inputs
# =====================================================================
for f in targets.txt user.txt pass.txt; do
  [ -s "$f" ] || { err "Missing or empty: $f"; exit 1; }
done
UC=$(grep -cve '^\s*$' user.txt); PC=$(grep -cve '^\s*$' pass.txt)
NTARGETS=$(grep -cve '^\s*$' targets.txt)

if [ "$UC" -eq 1 ] && [ "$PC" -eq 1 ]; then
  U=$(head -n1 user.txt | tr -d '\r\n'); P=$(head -n1 pass.txt | tr -d '\r\n')
  CREDLBL="$U"; MULTI=0
else
  U="user.txt"; P="pass.txt"; CREDLBL="$UC user x $PC pass"; MULTI=1
  [ "$RUN_NVT" -eq 1 ] && { warn "nvt engine takes a single credential pair; using the first line of each"; \
                            U=$(head -n1 user.txt | tr -d '\r\n'); P=$(head -n1 pass.txt | tr -d '\r\n'); }
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
NVT_CSV="$RAW/nvt/results.csv"
: > "$RAW/cve-nvt.txt"

if [ "$RUN_NVT" -eq 1 ]; then
step "Stage 3A  Greenbone NVT scan  ($NVT_FILES scripts, $CFG_NAME)"

GMPU=$(head -n1 gmp-user.txt | tr -d '\r\n'); GMPP=$(head -n1 gmp-pass.txt | tr -d '\r\n')
xesc(){ printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"; }
gmp(){ gvm-cli --gmp-username "$GMPU" --gmp-password "$GMPP" socket --socketpath "$SOCK" --xml "$1" 2>&1; }
xid(){  sed -n 's/.*id="\([a-f0-9][a-f0-9-]*\)".*/\1/p' | head -1; }
xtag(){ sed -n "s|.*<$1>\([^<]*\)</$1>.*|\1|p" | head -1; }

V=$(gmp "<get_version/>")
if ! echo "$V" | grep -q 'status="200"'; then
  err "GMP authentication failed"; echo "$V" | head -3; RUN_NVT=0
else
info "GMP $(echo "$V" | xtag version) authenticated"

R=$(gmp "<create_credential><name>kameki-smb-$RUN_NAME</name><type>up</type>
  <allow_insecure>1</allow_insecure><login>$(xesc "$U")</login>
  <password>$(xesc "$P")</password></create_credential>")
SMB_CRED=$(echo "$R" | xid)
[ -n "$SMB_CRED" ] || { err "SMB credential creation failed"; echo "$R" | head -3; }

SSH_CRED=""
if [ "$SSH_ON" -eq 1 ]; then
  R=$(gmp "<create_credential><name>kameki-ssh-$RUN_NAME</name><type>up</type>
    <allow_insecure>1</allow_insecure><login>$(xesc "$SU")</login>
    <password>$(xesc "$SP")</password></create_credential>")
  SSH_CRED=$(echo "$R" | xid)
fi

CREDXML="<smb_credential id=\"$SMB_CRED\"/>"
[ -n "$SSH_CRED" ] && CREDXML="$CREDXML<ssh_credential id=\"$SSH_CRED\" port=\"22\"/>"
HOSTS=$(grep -ve '^\s*$' targets.txt | tr '\n' ',' | sed 's/,$//')
R=$(gmp "<create_target><name>kameki-target-$RUN_NAME</name><hosts>$HOSTS</hosts>
  <alive_tests>$ALIVE_TEST</alive_tests>$CREDXML</create_target>")
TARGET=$(echo "$R" | xid)
[ -n "$TARGET" ] || { err "target creation failed"; echo "$R" | head -3; }

SCANNER=$(gmp "<get_scanners/>" | grep -o 'id="[a-f0-9-]*"[^>]*>[^<]*<name>OpenVAS' | xid)
[ -n "$SCANNER" ] || SCANNER="08b69003-5fc2-4037-a479-93b440211c73"

R=$(gmp "<create_task><name>$RUN_NAME</name><config id=\"$CFG_ID\"/>
  <target id=\"$TARGET\"/><scanner id=\"$SCANNER\"/>
  <preferences>
    <preference><scanner_name>max_checks</scanner_name><value>5</value></preference>
    <preference><scanner_name>max_hosts</scanner_name><value>20</value></preference>
  </preferences></create_task>")
TASK=$(echo "$R" | xid)
R=$(gmp "<start_task task_id=\"$TASK\"/>")
REPORT=$(echo "$R" | xtag report_id)
echo "task=$TASK target=$TARGET report=$REPORT" > "$RAW/nvt/ids.txt"
info "task $TASK   report $REPORT"
dim "polling every ${POLL}s"

LAST=-1
while true; do
  S=$(gmp "<get_tasks task_id=\"$TASK\"/>")
  ST=$(echo "$S" | xtag status); PR=$(echo "$S" | xtag progress); [ -z "$PR" ] && PR=0
  case "$ST" in
    Done) echo; info "NVT scan complete"; break ;;
    Stopped|Interrupted) echo; warn "NVT scan $ST at ${PR}%, exporting partial"; break ;;
    "") echo; err "lost contact with gvmd"; break ;;
  esac
  if [ "$PR" != "$LAST" ]; then
    printf "\r    %-12s %3s%%   %d min elapsed    " "$ST" "$PR" "$(( ($(date +%s)-T0)/60 ))"
    LAST="$PR"
  fi
  sleep "$POLL"
done

gmp "<get_reports report_id=\"$REPORT\" format_id=\"$FMT_CSV\" ignore_pagination=\"1\"
      details=\"1\" filter=\"levels=hmlg rows=-1\"/>" > "$RAW/nvt/csv.xml" 2>&1
sed -n 's|.*</report_format>\(.*\)</report>.*|\1|p' "$RAW/nvt/csv.xml" | base64 -d > "$NVT_CSV" 2>/dev/null
[ -s "$NVT_CSV" ] || grep -oE '[A-Za-z0-9+/=]{200,}' "$RAW/nvt/csv.xml" | head -1 | base64 -d > "$NVT_CSV" 2>/dev/null
gmp "<get_reports report_id=\"$REPORT\" format_id=\"$FMT_XML\" ignore_pagination=\"1\"
      details=\"1\" filter=\"levels=hmlg rows=-1\"/>" > "$RAW/nvt/report-full.xml" 2>&1

[ -n "$SMB_CRED" ] && gmp "<delete_credential credential_id=\"$SMB_CRED\" ultimate=\"1\"/>" >/dev/null 2>&1
[ -n "$SSH_CRED" ] && gmp "<delete_credential credential_id=\"$SSH_CRED\" ultimate=\"1\"/>" >/dev/null 2>&1
dim "scan credentials removed from gvmd"

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
  if [ "$SVC_CVE" = "vulners" ]; then SCRIPTS="$NSE_SET,vulners"; SARGS="--script-args mincvss=$MIN_CVSS"
  else SCRIPTS="$NSE_SET,vulscan/vulscan.nse"; SARGS="--script-args vulscandb=cve.csv"; fi
  nse_host(){ nmap -sV -Pn -n -p "$2" --script "$SCRIPTS" $SARGS --script-timeout 90s \
                   --host-timeout "$HOST_TIMEOUT" "$1" -oN "$RAW/nse/$1.txt" >/dev/null 2>&1; }
  N=0
  while read -r ip ports; do
    [ -z "$ip" ] && continue
    N=$((N+1)); printf "\r    scanning %d/%d" "$N" "$HOSTS_OPEN"
    pool nse_host "$ip" "$ports"
  done < "$RAW/ports/map.txt"
  finish; echo
  mark_done nse
fi
cat "$RAW"/nse/*.txt > "$RAW/nse-all.txt" 2>/dev/null || : > "$RAW/nse-all.txt"
NSE_HITS=$(grep -ciE 'VULNERABLE' "$RAW/nse-all.txt" 2>/dev/null || echo 0)
grep -oE 'CVE-[0-9]{4}-[0-9]+' "$RAW/nse-all.txt" 2>/dev/null | sort -u > "$RAW/cve-service.txt" || true
SVC_CVES=$(cnt "$RAW/cve-service.txt")
info "NSE vulnerable states $NSE_HITS   service CVEs $SVC_CVES"

if [ "$HAVE_SPLOIT" -eq 1 ] && [ -s "$RAW/services.xml" ]; then
  searchsploit --nmap "$RAW/services.xml" > "$RAW/searchsploit.txt" 2>&1 || true
  SPLOIT=$(grep -c 'Exploit Title' "$RAW/searchsploit.txt" 2>/dev/null || echo 0)
  info "public exploit matches $SPLOIT"
fi
fi

# =====================================================================
#  Stage 4  Authentication across protocols
# =====================================================================
step "Stage 4  Authentication"
ap(){ nxc "$1" "$RAW/live.txt" -u "$U" -p "$P" --continue-on-success -t "$NXC_THREADS" > "$RAW/auth-$1.txt" 2>&1; }
for pr in smb ldap mssql winrm rdp; do pool ap "$pr"; done
pool bash -c "nxc smb '$RAW/live.txt' -u '' -p '' --shares > '$RAW/null-session.txt' 2>&1"
finish

grep '\[+\]' "$RAW/auth-smb.txt" | awk '{print $2}' | sort -uV > "$RAW/auth-ok.txt"   || : > "$RAW/auth-ok.txt"
grep '\[-\]' "$RAW/auth-smb.txt" | awk '{print $2}' | sort -uV > "$RAW/auth-fail-raw.txt" || : > "$RAW/auth-fail-raw.txt"
if [ -s "$RAW/auth-ok.txt" ]; then
  grep -vxFf "$RAW/auth-ok.txt" "$RAW/auth-fail-raw.txt" > "$RAW/auth-fail.txt" 2>/dev/null || : > "$RAW/auth-fail.txt"
else cp "$RAW/auth-fail-raw.txt" "$RAW/auth-fail.txt" 2>/dev/null || : > "$RAW/auth-fail.txt"; fi
grep '\[+\]' "$RAW/auth-smb.txt" | sed -E 's/.*\[\+\][[:space:]]*//' | sort -u > "$RAW/working-creds.txt" || true

AUTH_OK=$(cnt "$RAW/auth-ok.txt"); AUTH_FAIL=$(cnt "$RAW/auth-fail.txt")
NOSIGN=$(grep -c 'signing:False' "$RAW/auth-smb.txt" 2>/dev/null || echo 0)
SMBV1=$(grep -c 'SMBv1:True' "$RAW/auth-smb.txt" 2>/dev/null || echo 0)
NULLS=$(grep -c '\[+\]' "$RAW/null-session.txt" 2>/dev/null || echo 0)
MSSQL_OK=$(grep -c '\[+\]' "$RAW/auth-mssql.txt" 2>/dev/null || echo 0)
WINRM_OK=$(grep -c '\[+\]' "$RAW/auth-winrm.txt" 2>/dev/null || echo 0)
info "smb $AUTH_OK ok / $AUTH_FAIL fail   no-signing $NOSIGN   smbv1 $SMBV1   null $NULLS   mssql $MSSQL_OK   winrm $WINRM_OK"
[ "$AUTH_OK" -eq 0 ] && { warn "No SMB authentication succeeded."; dim "try DOMAIN\\\\user, user@domain, or the NETBIOS name"; }

# =====================================================================
#  Stage 5  Exploit modules
# =====================================================================
step "Stage 5  Windows exploit modules"
MODS="ms17-010 zerologon petitpotam nopac smbghost printnightmare spooler webdav coerce_plus"
runmod(){ nxc smb "$RAW/live.txt" -u "$U" -p "$P" -M "$1" -t "$NXC_THREADS" > "$RAW/mods/$1.txt" 2>&1; }
for m in $MODS; do pool runmod "$m"; done
finish
: > "$RAW/vuln-summary.txt"; : > "$RAW/vuln-detail.txt"
for m in $MODS; do
  H=$(grep -ciE 'VULNERABLE|is vulnerable' "$RAW/mods/$m.txt" 2>/dev/null || echo 0)
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
adr(){ nxc "$1" "$RAW/live.txt" -u "$U" -p "$P" $2 > "$RAW/ad/$3.txt" 2>&1; }
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
ADCS_H=$(grep -ci 'ESC\|Certificate Authority' "$RAW/ad/adcs.txt" 2>/dev/null || echo 0)
KERB_H=$(cat "$RAW/ad/kerberoast.txt" "$RAW/ad/kerberoast-tickets.txt" 2>/dev/null | grep -c 'krb5tgs' || echo 0)
ASREP_H=$(cat "$RAW/ad/asreproast.txt" "$RAW/ad/asrep-tickets.txt" 2>/dev/null | grep -c 'krb5asrep' || echo 0)
DELEG_H=$(grep -ci 'delegation' "$RAW/ad/delegation.txt" 2>/dev/null || echo 0)
LDAPSIGN=$(grep -ci 'not enforced\|is not being enforced\|channel binding' "$RAW/ad/ldap-signing.txt" 2>/dev/null || echo 0)
PWDNR=$(grep -ci 'password not required\|PASSWD_NOTREQD' "$RAW/ad/pwd-not-required.txt" 2>/dev/null || echo 0)
info "adcs $ADCS_H   kerberoast $KERB_H   asrep $ASREP_H   delegation $DELEG_H   ldap-signing $LDAPSIGN"

# =====================================================================
#  Stage 7  Configuration audit
# =====================================================================
step "Stage 7  Configuration audit"
cf(){ nxc smb "$RAW/live.txt" -u "$U" -p "$P" $1 -t "$NXC_THREADS" > "$RAW/$2.txt" 2>&1; }
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
WCC_FAIL=$(grep -ciE '\bFAIL\b|not compliant' "$RAW/config-check.txt" 2>/dev/null || echo 0)
GPP=$(grep -ci 'password' "$RAW/gpp-password.txt" 2>/dev/null || echo 0)
WRITABLE=$(grep -ci 'READ,WRITE' "$RAW/shares.txt" 2>/dev/null || echo 0)
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
  WIN_CRIT=$(grep -ci 'critical' "$RAW/windows-cves.csv" 2>/dev/null || echo 0)
  grep -oE 'CVE-[0-9]{4}-[0-9]+' "$RAW/windows-cves.csv" 2>/dev/null | sort -u > "$RAW/cve-windows.txt" || true
  info "windows CVEs $WIN_CVES   critical $WIN_CRIT"
fi
fi

# =====================================================================
#  Stage 9  Linux
# =====================================================================
step "Stage 9  Linux authenticated collection"
LINUX_OK=0; LINUX_EOL=0
if [ "$SSH_ON" -eq 1 ]; then
  nxc ssh "$RAW/live.txt" -u "$SU" -p "$SP" --continue-on-success -t "$NXC_THREADS" > "$RAW/auth-ssh.txt" 2>&1
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
    tl(){ testssl.sh --quiet --color 0 --severity MEDIUM --sneaky "$1" > "$RAW/tls/$(echo "$1"|tr ':' '_').txt" 2>&1 || true; }
    while read -r e; do [ -n "$e" ] && pool tl "$e"; done < "$RAW/tls-endpoints.txt"
    finish
    TLS_ISSUES=$(grep -rhE 'VULNERABLE|NOT ok' "$RAW/tls/" 2>/dev/null | wc -l)
  else
    nmap -Pn -n --script ssl-enum-ciphers,ssl-cert,ssl-dh-params,sslv2,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,rdp-enum-encryption \
         -p 443,8443,636,993,995,3389 -iL "$RAW/live.txt" -oN "$RAW/tls/nmap-ssl.txt" >/dev/null 2>&1
    TLS_ISSUES=$(grep -cE 'VULNERABLE|SSLv2|SSLv3|TLSv1\.0|weak' "$RAW/tls/nmap-ssl.txt" 2>/dev/null || echo 0)
  fi
fi
SNMPN=0
if [ "$HAVE_SNMP" -eq 1 ]; then
  printf 'public\nprivate\ncisco\nmanager\nadmin\ncommunity\nsecret\n' > "$RAW/snmp-strings.txt"
  onesixtyone -c "$RAW/snmp-strings.txt" -i "$RAW/live.txt" > "$RAW/snmp.txt" 2>&1 || true
  SNMPN=$(grep -c '^\[' "$RAW/snmp.txt" 2>/dev/null || echo 0)
fi
awk '{split($2,p,","); for(i in p) if(p[i]=="80"||p[i]=="443"||p[i]=="8000"||p[i]=="8080"||p[i]=="8443"||p[i]=="9443"){print $1; break}}' \
    "$RAW/ports/map.txt" 2>/dev/null | sort -u > "$RAW/web-hosts.txt" || : > "$RAW/web-hosts.txt"
WEBN=$(cnt "$RAW/web-hosts.txt"); NC=0; NH=0; NM=0; NL=0; : > "$RAW/cve-web.txt"
if [ "$WEBN" -gt 0 ]; then
  nuclei -l "$RAW/web-hosts.txt" -severity critical,high,medium,low -j -o "$RAW/nuclei.json" \
         -rl 100 -c "$JOBS" -silent >/dev/null 2>&1 || true
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
  s=$((s + $(grep -c "^$ip," "$RAW/windows-cves.csv" 2>/dev/null || echo 0) * 2))
  if [ -s "$NVT_CSV" ]; then
    s=$((s + $(awk -F'","' -v I="$ip" 'NR>1{gsub(/^"/,"",$1); if($1==I && tolower($6)~/high/) c++} END{print c+0}' "$NVT_CSV") * 60))
    s=$((s + $(awk -F'","' -v I="$ip" 'NR>1{gsub(/^"/,"",$1); if($1==I && tolower($6)~/medium/) c++} END{print c+0}' "$NVT_CSV") * 15))
  fi
  grep -q "$ip" "$RAW/vuln-detail.txt" 2>/dev/null && s=$((s+300))
  grep -q "$ip.*signing:False" "$RAW/auth-smb.txt" 2>/dev/null && s=$((s+80))
  grep -q "$ip.*SMBv1:True"    "$RAW/auth-smb.txt" 2>/dev/null && s=$((s+120))
  grep -q "$ip" "$RAW/null-session.txt" 2>/dev/null && s=$((s+60))
  grep -q "$ip" "$RAW/eol-os.txt" 2>/dev/null && s=$((s+200))
  s=$((s + $(grep -ciE 'VULNERABLE' "$RAW/nse/${ip}.txt" 2>/dev/null || echo 0) * 40))
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
APCT=0; SPCT=0; NVT_APCT=0
[ "$LIVE" -gt 0 ] && { APCT=$(( AUTH_OK*100/LIVE )); SPCT=$(( SYSOK*100/LIVE )); }
[ "$NVT_HOSTS_F" -gt 0 ] && NVT_APCT=$(( NVT_AUTH_HOSTS*100/NVT_HOSTS_F ))

# =====================================================================
#  Self check: did this scan actually assess anything?
# =====================================================================
step "Self check"
AUTH_FINDINGS=0; AUTH_DEPTH=0; DEPTH_VERDICT="unknown"
if [ "$RUN_NVT" -eq 1 ] && [ -s "$NVT_CSV" ]; then
  AUTH_FINDINGS=$(grep -ci 'Authenticated \(registry\|package\)-based' "$NVT_CSV" 2>/dev/null || echo 0)
  [ "$NVT_AUTH_HOSTS" -gt 0 ] && AUTH_DEPTH=$(( AUTH_FINDINGS * 100 / NVT_AUTH_HOSTS ))
elif [ "$RUN_SA" -eq 1 ]; then
  AUTH_FINDINGS="$WIN_CVES"
  [ "$SYSOK" -gt 0 ] && AUTH_DEPTH=$(( AUTH_FINDINGS * 100 / SYSOK ))
fi
DEPTH_H=$(( AUTH_DEPTH / 100 ))

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
    hc=$(grep -c "^$h," "$RAW/windows-cves.csv" 2>/dev/null || echo 0)
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
Authenticated coverage: ${COVER_PCT:-0}%
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
COVER_PCT=$([ "$RUN_NVT" -eq 1 ] && echo "$NVT_APCT" || echo "$SPCT")
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
if [ "$WIN_CVES" -gt 0 ]; then
  echo "### CVE count by host"; echo
  echo '```'; tail -n +2 "$RAW/windows-cves.csv" | cut -d',' -f1 | sort | uniq -c | sort -rn | head -40; echo '```'; echo
  echo "### Critical severity"; echo
  echo '```'; head -1 "$RAW/windows-cves.csv"; grep -i critical "$RAW/windows-cves.csv" | head -50; echo '```'
else echo "_No data. No hosts authenticated, or remote command execution was blocked._"; fi
echo
echo "## 3C. NSE Vulnerability Findings"; echo
if [ "$NSE_HITS" -gt 0 ]; then echo '```'; grep -B6 'VULNERABLE' "$RAW/nse-all.txt" 2>/dev/null | head -150; echo '```'
else echo "_No NSE script reported a vulnerable state._"; fi
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

echo "## 13. Evidence"; echoecho "| File | Contents |"; echo "| --- | --- |"
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
