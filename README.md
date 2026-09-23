# KameKi

Authenticated vulnerability assessment that tells you when it failed.

KameKi is a single bash script that runs a full credentialed vulnerability
assessment against a Windows or mixed estate, and then audits its own work.
It reports not just what it found, but how much of the assessment was
actually authenticated, which is the one number commercial scanners do not
put on the summary page.

---

## Why this exists

A scan configured as "authenticated" can silently fall back to
unauthenticated banner checks. The login succeeds, the report fills with
several thousand version-string observations, and patch level is never
examined. The output looks complete. It is not.

This failure mode is invisible in every vendor summary page I have seen. It
shows up only if you count findings by detection method, which nobody does,
because no tool surfaces it.

A real example, from a commercial scan of a 322 host estate, configured as
authenticated:

```
  breadth   67.4%  ███████████████████░░░░░░░░░   hosts where credentials took effect
  depth      1.01  █░░░░░░░░░░░░░░░░░░░░░░░░░░░   authenticated findings per such host
```

Credentials worked on two thirds of the estate. They then produced one
trivial finding per host. Of 7,002 findings, 6,511 were remote banner
checks and 220 were authenticated. The entire report contained 38 unique
CVEs, none newer than six years old, on a production estate.

Nothing in that report said so. You had to parse it to find out.

KameKi measures this about itself, during the run, and says so at the top
of its own report.

---

## What it does

**Two detection engines, picked automatically.**

| Engine | Detection | Used when |
| --- | --- | --- |
| `nvt` | Full Greenbone NVT feed, roughly 100,000 scripts, driven over the gvmd socket. No web UI required. | Greenbone backend is installed and the feed is synced |
| `standalone` | WES-NG patch mapping against MSRC, nmap NSE vulnerability scripts, service version CVE mapping | Greenbone is unavailable |

**On top of whichever engine runs, always:**

- Active Directory: ADCS (ESC1 to ESC8), Kerberoasting, AS-REP roasting,
  delegation, LDAP signing and channel binding, machine account quota,
  accounts with password not required, credentials in user descriptions
- Exploit modules: ms17-010, zerologon, petitpotam, nopac, smbghost,
  printnightmare, spooler, webdav, coerce_plus
- Configuration: password policy, local administrators, writable shares,
  Group Policy Preferences credential exposure, LAPS, endpoint protection,
  configuration baseline
- SMB posture: signing, SMBv1, null sessions
- TLS via testssl.sh, or nmap ssl scripts as fallback
- Web applications via nuclei
- Linux: package inventory, kernel, sudo rights, SUID binaries, EOL distro
- SNMP default community strings
- CISA KEV correlation, so you know which findings are under active
  exploitation right now
- Attack path derivation, correlating findings the way a pentester would
- Per host risk scoring, 0 to 1000
- Explicit coverage reporting for every host that was not assessed

**And it provisions itself, including offline.**

---

## Install

### With internet

```bash
git clone https://github.com/CyberKareem/KameKi
cd KameKi
chmod +x kameki.sh
sudo ./kameki.sh install
```

That installs nmap, NetExec, nuclei and its templates, WES-NG with
definitions, vulscan, testssl.sh, searchsploit, onesixtyone, the KEV
catalogue, and the Greenbone scanner backend.

Greenbone needs two manual steps because `gvm-setup` prints a password you
must save:

```bash
sudo gvm-setup                 # save the admin password it prints
sudo greenbone-feed-sync       # about 5 GB, let it finish
sudo systemctl enable --now ospd-openvas gvmd
```

Verify:

```bash
./kameki.sh doctor
```

You want the NVT feed line showing 90,000 or more scripts.

### Without internet

Restricted networks frequently block the package CDNs, Docker Hub, external
DNS, or simply time out on large transfers. Build a portable bundle where
internet works, then carry it in.

```bash
# on a machine with internet, after a full install
./kameki.sh bundle
```

Produces `kameki-bundle-<date>.tar.zst`, roughly 6 to 8 GB. It contains the
python wheels, system packages, the nuclei binary and templates, vulscan,
testssl.sh, WES-NG definitions, the KEV catalogue, and the entire Greenbone
NVT feed.

On the target machine:

```bash
sudo ./kameki.sh install --bundle kameki-bundle-2026-09-23.tar.zst
```

No network access required. This also pins the feed version for the
engagement, which is better evidence practice than a feed that syncs
differently on every run.

---

## Usage

### Input files

All in the working directory.

| File | Contents | Required |
| --- | --- | --- |
| `targets.txt` | one IP or hostname per line | yes |
| `user.txt` | Windows account(s), one per line | yes |
| `pass.txt` | password(s), one per line | yes |
| `ssh-user.txt` | Linux account | optional |
| `ssh-pass.txt` | Linux password | optional |
| `gmp-user.txt` | gvmd admin user | nvt engine only |
| `gmp-pass.txt` | gvmd admin password | nvt engine only |

```bash
cat > targets.txt << 'EOF'
10.0.10.20
10.0.10.21
10.0.10.22
EOF

echo 'CORP\svc_scan'  > user.txt
echo 'ThePassword'    > pass.txt
echo 'admin'          > gmp-user.txt
echo 'TheGvmdPass'    > gmp-pass.txt

chmod 600 user.txt pass.txt gmp-user.txt gmp-pass.txt
```

### Preflight, do not skip this

```bash
./kameki.sh preflight
```

Credential format is the most common reason an authenticated scan quietly
becomes unauthenticated. Preflight reads the domain off one host's SMB
banner, derives the plausible formats, and tries each against that single
host:

```
    CORP\svc_scan                      success (admin)
    corp.local\svc_scan                failed  STATUS_LOGON_FAILURE
    svc_scan@corp.local                success
    remote command execution           works
```

At most a handful of failed logins against one host, so no estate-wide
lockout risk. It offers to write the working format back into `user.txt`.

It also tests remote command execution separately, because that fails
independently of login and is what patch level collection depends on. If
execution is blocked by EDR, prefer `ENGINE=nvt`, which reads the registry
directly instead of shelling out.

### Run

```bash
./kameki.sh run
```

```bash
PROFILE=deep JOBS=24 ./kameki.sh run    # all 65535 ports, more workers
ENGINE=nvt ./kameki.sh run              # force the Greenbone engine
ENGINE=both ./kameki.sh run             # run both, compare coverage
RESUME=1 ./kameki.sh run                # continue after an interruption
```

For 100 hosts on `standard`, expect 3 to 6 hours. Check progress at the one
hour mark rather than in the morning.

Watch for the self check near the end:

```
── Self check ──
[+] authentication depth 24.30 findings per authenticated host
```

If it reports `shallow` or `none`, stop and diagnose. Do not deliver.

### Cleanup

```bash
./kameki.sh cleanup
```

Shreds credential files, removes Kerberos tickets and captured hashes from
the evidence folder, strips licence keys and registered owner names out of
systeminfo dumps, scrubs passwords from shell history, and asks per folder
whether to delete evidence.

```bash
./kameki.sh cleanup --keep-evidence   # skip deletion prompts
./kameki.sh cleanup --purge           # also remove installed tooling
```

Copy the evidence folder to your own storage before running this if you
need it for reporting or a retest.

---

## Subcommands

| Command | Purpose |
| --- | --- |
| `install` | install every dependency, needs internet |
| `install --bundle F` | install from an offline bundle |
| `bundle` | build an offline bundle for transport |
| `doctor` | diagnose tools, feed, credentials, permissions, network position |
| `preflight` | find the working credential format without a spray |
| `run` | run the assessment, this is the default |
| `cleanup` | shred credentials and remove artifacts |

## Configuration

Environment variables, all optional.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENGINE` | `auto` | `auto`, `nvt`, `standalone`, `both` |
| `PROFILE` | `standard` | `quick` (top 1000 ports), `standard` (top 5000), `deep` (all 65535) |
| `JOBS` | `16` | parallel workers |
| `NXC_THREADS` | `32` | NetExec internal threads |
| `MIN_CVSS` | `4.0` | service CVE reporting floor |
| `NMAP_RATE` | `2000` | minimum packet rate |
| `HOST_TIMEOUT` | `20m` | per host nmap timeout |
| `SCAN_CONFIG` | `fast` | Greenbone config: `fast`, `ultimate`, `deep`, `deepult` |
| `DEPTH_WARN` | `3` | authenticated findings per host below which the self check warns |
| `RESUME` | `0` | set to `1` to skip completed stages |
| `POLL` | `60` | Greenbone progress poll interval, seconds |

---

## Machine assisted analysis (optional)

KameKi can annotate its findings with a language model through any
OpenAI compatible `/v1/chat/completions` endpoint: Ollama, vLLM, LM Studio,
llama.cpp server.

```bash
LLM_ENDPOINT=http://localhost:11434/v1 \
LLM_MODEL=qwen2.5:72b \
./kameki.sh run
```

It does three things:

**False positive triage.** The highest value use. WES-NG does not model
cumulative update supersedence, so fully patched hosts get flagged. The
model reasons over the OS build, UBR and installed hotfix list, which no
rule in the script can do, and classifies each claim as likely false
positive, likely genuine, or uncertain.

**Executive narrative.** Fed the metrics only, never raw findings, so the
hallucination surface stays small. If authentication depth was low it is
instructed to say so plainly rather than soften it.

**Extended attack path analysis.** Chains beyond the rules hardcoded in the
correlation stage.

### Safety design

These constraints are deliberate and not configurable away casually.

**Local endpoints only, by default.** Scan output contains the client's
internal addresses, hostnames, patch state and directory structure. Sending
that to a third party processor is very likely outside your engagement
terms. Non-private addresses are refused unless `LLM_ALLOW_EXTERNAL=1` is
set explicitly, and the run warns loudly when it is.

**The model cannot create findings.** Every prompt constrains output to
identifiers supplied in the input, and the script validates the response
against that input before using it. A CVE the model invents is discarded
before it reaches the report.

**The deterministic report comes first.** Sections 1 through 11 are produced
without any model involvement and reproduce identically on a rerun. Model
output is section 11B, separately marked, with a note that it does not
reproduce. An auditor needs a report that regenerates the same way twice.

**Responses are cached by content hash.** A rerun on the same data does not
re-query and does not drift.

| Variable | Default | Meaning |
| --- | --- | --- |
| `LLM_ENDPOINT` | empty | OpenAI compatible base URL, empty disables the layer |
| `LLM_MODEL` | empty | model identifier |
| `LLM_KEY` | empty | bearer token, usually unused locally |
| `LLM_ALLOW_EXTERNAL` | `0` | set to `1` to permit non-private endpoints |
| `LLM_MAX_CALLS` | `60` | hard ceiling on requests per run |
| `LLM_TIMEOUT` | `120` | per request timeout, seconds |

---

## Output

```
kameki-<date>.md         the report
kameki-raw-<date>/       evidence
├── cve-all.txt          every unique CVE, all sources
├── cve-kev.txt          CVEs on the CISA actively exploited list
├── risk-scores.txt      per host risk score
├── attack-paths.txt     correlated attack paths
├── auth-ok.txt          hosts where credentials worked
├── auth-fail.txt        hosts with no authenticated assessment
├── no-response.txt      targets that never responded
├── windows-cves.csv     WES-NG findings per host
├── nvt/                 Greenbone CSV and XML, authenticated host list
├── sysinfo/             raw systeminfo per host
├── nse/                 nmap NSE output per host
├── mods/                exploit module output
├── ad/                  Active Directory findings
├── linux/               Linux inventory per host
├── tls/                 TLS assessment per endpoint
├── nuclei.json          web findings
├── services.xml         full nmap XML
└── ports/map.txt        open ports per host
```

The report opens with the two axes that determine whether anything below it
is trustworthy, then attack paths, actively exploited CVEs, and the highest
risk hosts. Coverage gaps are a section of their own, not a footnote.

---

## kameki-validate.py

Optional companion. Audits a finished report, or compares two.

```bash
# audit a vendor report you were handed
./kameki-validate.py --clone report.pdf -o validation.md

# audit a KameKi run
./kameki-validate.py --kameki kameki-raw-2026-09-23/ -o audit.md

# compare them against the same scope
./kameki-validate.py --clone report.pdf --kameki kameki-raw-2026-09-23/ \
                     --scope targets.txt -o comparison.md
```

Parses Greenbone PDF or CSV exports and KameKi evidence directories.
Reports breadth, depth, detection method breakdown, CVE age distribution,
and in comparison mode the CVE overlap in both directions, including what
KameKi missed that the other tool caught.

The Escalation Summary section produces copy-ready statements of fact, every
number reproducible by rerunning the tool.

---

## Limitations

Stated plainly, because a scanner that oversells itself is the problem this
tool exists to detect.

**WES-NG produces false positives.** It infers missing patches from the
installed hotfix list and does not fully model cumulative update
supersedence. Fully patched Server 2022 hosts can be reported as vulnerable.
Validate every finding against the host's build and UBR before it reaches a
client report. The report carries this warning inline.

**This is not a certified compliance deliverable.** Commercial scanners
carry auditor recognition, certified compliance policies, and a support
contract. Those are institutional properties, not technical ones, and no
script provides them. If a regulated assessment is the end product, that is
a decision for whoever owns the engagement, not for the tool.

**The standalone engine needs remote command execution.** It collects
`systeminfo` over SMB. Where EDR blocks that, use `ENGINE=nvt`, which reads
the registry instead.

**Greenbone still has more per-product depth.** Its NVT feed covers
thousands of specific enterprise products that the standalone engine does
not. That is why KameKi drives Greenbone when it is available rather than
reimplementing detection.

**Some checks are loud.** Remote command execution, exploit modules and
Kerberoasting will light up any competent SOC. Confirm they are in scope and
that the blue team has been notified.

---

## Authorized testing only

This tool authenticates to hosts, executes remote commands, requests
Kerberos service tickets, and probes for exploitable conditions. Run it only
against systems you own or have explicit written authorization to test.

Scope every engagement in writing before you start. Tell the client's
security team the dates. Run `cleanup` before you leave.

---

## Requirements

Linux. Tested on Ubuntu and Debian.

Core: `nmap`, `nxc` (NetExec), `nuclei`, `jq`, `awk`, `wes` (WES-NG), and
either `vulscan` or `vulners` for service CVE mapping.

Optional but recommended: `testssl.sh`, `searchsploit`, `onesixtyone`,
`gvm-cli` with a synced Greenbone backend.

`./kameki.sh install` handles all of it.

---

## License

MIT

## Author

[CyberKareem](https://cyberkareem.com)
