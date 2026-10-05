#!/usr/bin/env python3
"""kameki_msrc.py regression test.

Fixtures are the real shapes taken from Microsoft's own CVRF documents for
2026-Jul, 2026-Aug, 2026-Sep and 2026-Oct, read from the API during
development. No network, no credentials, no Windows host needed.

What it guards against, each of which is a real property of the live data:

  * Base build 26100 is shared by Windows 11 24H2 and Windows Server 2025, and
    in September 2026 they required UBR 9445 and UBR 33438 respectively. Keying
    the lookup on the base build alone and taking the highest revision reports
    every Windows 11 24H2 host as missing a patch that does not exist for it --
    a false positive, in the exact tool built to avoid them.

  * Microsoft names documents YYYY-Mon. Sorted as text, August precedes July,
    so the data window the whole assessment is bounded by is misreported.

  * The current month is published before its Patch Tuesday and contains no
    Windows build data at all -- 2026-Oct was 9,441 bytes against September's
    20,303,321. An empty month must not be allowed to narrow the window
    silently, nor to look like a month that was checked and found clean.

  * A host below the oldest revision in the window is also missing updates
    from before the window, so its CVE count is a floor and must say so.

  * Windows 8.1 and Server 2012 R2 report 6.x builds with no revision to
    compare. They are common in these estates and must be reported as not
    assessable, with the reason, so they still appear in coverage figures.
"""

import io
import json
import os
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import kameki_msrc as M  # noqa: E402


def vuln(cve, remediations, score=7.5, severity="Important",
         impact="Remote Code Execution", exploited=False, pids=("P1",)):
    """One Vulnerability record in Microsoft's shape."""
    exploit_text = ("Publicly Disclosed:No;Exploited:%s;Latest Software "
                    "Release:Exploitation %s"
                    % ("Yes" if exploited else "No",
                       "Detected" if exploited else "Less Likely"))
    return {
        "CVE": cve,
        "ProductStatuses": [{"ProductID": list(pids), "Type": 3}],
        "Threats": [
            {"Description": {"Value": impact}, "ProductID": list(pids), "Type": 0},
            {"Description": {"Value": exploit_text}, "ProductID": list(pids), "Type": 1},
            {"Description": {"Value": severity}, "ProductID": list(pids), "Type": 3},
        ],
        "CVSSScoreSets": [{
            "BaseScore": score, "TemporalScore": score, "EnvironmentalScore": 0,
            "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "ProductID": list(pids),
        }],
        "Remediations": remediations,
    }


def rem(fixed_build, kb, pids, supersedes=None, subtype="Security Update"):
    return {
        "Description": {"Value": kb},
        "URL": "", "ProductID": list(pids), "Type": 2,
        "Date": "0001-01-01T00:00:00", "DateSpecified": False,
        "AffectedFiles": [], "RestartRequired": {"Value": "Yes"},
        "SubType": subtype, "FixedBuild": fixed_build,
        **({"Supercedence": supersedes} if supersedes else {}),
    }


def document(month, products, vulns, version="1.0"):
    return {
        "DocumentTitle": {"Value": "%s Security Updates" % month},
        "DocumentType": {"Value": "Security Update"},
        "DocumentTracking": {
            "Identification": {"ID": {"Value": month},
                               "Alias": {"Value": month}},
            "Status": 2, "Version": version,
            "InitialReleaseDate": "2026-09-08T07:00:00",
            "CurrentReleaseDate": "2026-10-13T07:00:00",
        },
        "ProductTree": {"FullProductName": [
            {"ProductID": pid, "Value": name} for pid, name in products.items()]},
        "Vulnerability": vulns,
    }


# The real product ids and names, and the real revisions, for the two lines
# that share base build 26100.
WIN11_24H2 = {"12345": "Windows 11 Version 24H2 for x64-based Systems"}
SRV2025 = {"12436": "Windows Server 2025",
           "12437": "Windows Server 2025 (Server Core installation)"}
SRV2022 = {"11923": "Windows Server 2022"}

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  PASS  %s" % label)
    else:
        FAIL += 1
        print("  FAIL  %s\n        got  %r\n        want %r" % (label, got, want))


def write(tmp, name, obj):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle)
    return path


def run(argv):
    out = io.StringIO()
    real = sys.stdout
    sys.stdout = out
    code = 0
    try:
        M.main(argv)
    except SystemExit as exc:
        code = exc.code or 0
    finally:
        sys.stdout = real
    try:
        return json.loads(out.getvalue()), code
    except ValueError:
        return {"_raw": out.getvalue()}, code


def main():
    tmp = tempfile.mkdtemp()
    data = os.path.join(tmp, "cvrf")
    os.makedirs(data)
    products = dict(WIN11_24H2, **SRV2025)
    products.update(SRV2022)

    # July: both 26100 lines and Server 2022, at their earliest revisions.
    write(data, "2026-Jul.json", document("2026-Jul", products, [
        vuln("CVE-2026-1001", [rem("10.0.26100.8875", "5100001", list(WIN11_24H2)),
                               rem("10.0.26100.33158", "5100002", list(SRV2025)),
                               rem("10.0.20348.5386", "5100003", list(SRV2022))],
             score=8.1, pids=tuple(products)),
    ]))
    # August: next revisions, one of them actively exploited.
    write(data, "2026-Aug.json", document("2026-Aug", products, [
        vuln("CVE-2026-2001", [rem("10.0.26100.9106", "5110001", list(WIN11_24H2)),
                               rem("10.0.26100.33222", "5110002", list(SRV2025)),
                               rem("10.0.20348.5440", "5110003", list(SRV2022))],
             score=9.8, exploited=True, pids=tuple(products)),
    ]))
    # September: the revisions that make the 26100 collision dangerous.
    write(data, "2026-Sep.json", document("2026-Sep", products, [
        vuln("CVE-2026-3001", [rem("10.0.26100.9445", "5124008", list(WIN11_24H2),
                                   supersedes="5121003"),
                               rem("10.0.26100.33438", "5122871", list(SRV2025),
                                   supersedes="5120233"),
                               rem("10.0.20348.5622", "5122882", list(SRV2022),
                                   supersedes="5120242")],
             score=7.8, severity="Critical", pids=tuple(products)),
    ]))
    # October, published before its Patch Tuesday: no Windows build data.
    write(data, "2026-Oct.json", document("2026-Oct", {}, [
        vuln("CVE-2026-4001", [rem("3.44.0-3", "none", ["99999"])], pids=("99999",)),
    ]))

    db = os.path.join(tmp, "db.json")
    print("compiling Microsoft's documents into a build table")
    res, code = run(["build", "--in", data, "--out", db,
                     "--fetched", "2026-10-05T23:00:00Z"])
    check("exit 0", code, 0)
    check("four documents read", res.get("documents"), 4)
    # Four products, three lines: Server 2025 and its Core edition share one
    # cumulative line, while Windows 11 24H2 and Server 2025 do NOT, despite
    # sharing base build 26100.
    check("three cumulative lines found", res.get("lines"), 3)
    check("and they are keyed by build AND client/server",
          run(["window", "--db", db])[0]["lines"],
          ["20348|server", "26100|client", "26100|server"])

    print("\nthe data window is chronological, not alphabetical")
    # Sorted as text this is Aug, Jul, Oct, Sep -- and the window the whole
    # assessment is bounded by would be reported wrongly.
    check("months in date order", res["window"]["months"],
          ["2026-Jul", "2026-Aug", "2026-Sep", "2026-Oct"])
    check("earliest is July, not August", res["window"]["earliest"], "2026-Jul")
    check("latest is September", res["window"]["latest"], "2026-Sep")

    print("\na month published before its Patch Tuesday is named, not hidden")
    check("October recorded as empty", res["window"]["empty_months"], ["2026-Oct"])
    check("and excluded from the months with data",
          res["window"]["months_with_windows_data"],
          ["2026-Jul", "2026-Aug", "2026-Sep"])

    print("\nbase build 26100 is two separate lines, not one")
    win = run(["assess", "--db", db, "--build", "10.0.26100.9445",
               "--kind", "client", "--host", "WS-01"])[0]
    srv = run(["assess", "--db", db, "--build", "10.0.26100.33438",
               "--kind", "server", "--host", "DC-01"])[0]
    check("Windows 11 24H2 required revision is 9445", win.get("required_ubr"), 9445)
    check("Server 2025 required revision is 33438", srv.get("required_ubr"), 33438)
    # The whole point: at ITS OWN required revision the client is up to date.
    # Taking the highest revision for build 26100 would call it 24,000 behind.
    check("a fully patched 24H2 host is up to date", win.get("up_to_date"), True)
    check("and reports no CVEs", win.get("cve_count"), 0)
    check("a fully patched Server 2025 host is up to date", srv.get("up_to_date"), True)
    check("the two lines name different products",
          sorted(win.get("products", [])) != sorted(srv.get("products", [])), True)

    print("\na host behind by one revision reports exactly that revision's CVEs")
    one = run(["assess", "--db", db, "--build", "10.0.26100.33222",
               "--kind", "server"])[0]
    check("behind by one", one.get("behind_by_levels"), 1)
    check("one CVE", one.get("cve_count"), 1)
    check("the September CVE", [c["cve"] for c in one["findings"]], ["CVE-2026-3001"])
    check("with the KB that fixes it", one["findings"][0]["kb"], "5122871")
    check("not flagged as a floor", one.get("counts_are_a_floor"), False)

    print("\nan actively exploited CVE is surfaced as such")
    two = run(["assess", "--db", db, "--build", "10.0.26100.33158",
               "--kind", "server"])[0]
    check("behind by two", two.get("behind_by_levels"), 2)
    check("Microsoft's exploited flag is carried through",
          two.get("exploited_cves"), ["CVE-2026-2001"])
    check("worst CVSS is the exploited one", two.get("max_cvss"), 9.8)

    print("\nbelow the window, the count is a floor and says so")
    old = run(["assess", "--db", db, "--build", "10.0.20348.1000",
               "--kind", "server"])[0]
    check("assessed", old.get("assessed"), True)
    check("every level missing", old.get("behind_by_levels"), 3)
    check("flagged as a floor", old.get("counts_are_a_floor"), True)
    check("and the reason names the window start",
          "2026-Jul" in (old.get("reason") or ""), True)

    print("\nwhat it refuses to assess, it says so about")
    for build, needle in (("6.3.9600.1", "predates cumulative servicing"),
                          ("6.1.7601.24000", "predates cumulative servicing"),
                          ("not-a-build", "cannot read a Windows build")):
        r, c = run(["assess", "--db", db, "--build", build, "--kind", "server"])
        check("%-16s reported, not crashed" % build, c, 0)
        check("%-16s assessed is false" % build, r.get("assessed"), False)
        check("%-16s gives the reason" % build, needle in (r.get("reason") or ""), True)
        check("%-16s claims no findings" % build, r.get("findings"), [])

    r, _ = run(["assess", "--db", db, "--base", "20348", "--kind", "server"])
    check("a host with no revision collected is not assessed",
          r.get("assessed"), False)
    check("and says the revision was not collected",
          "was not collected" in (r.get("reason") or ""), True)

    print("\na build that exists only on the other line is explained")
    r, _ = run(["assess", "--db", db, "--build", "10.0.20348.5622",
                "--kind", "client"])
    check("not assessed", r.get("assessed"), False)
    check("and the misclassification is named",
          "exists in the data for server" in (r.get("note") or ""), True)

    print("\nprovenance is recorded per document, for PCI 11.3.1.c")
    w, code = run(["window", "--db", db])
    check("exit 0", code, 0)
    prov = {p["month"]: p for p in w["provenance"]}
    check("every month has provenance", sorted(prov), sorted(res["window"]["months"]))
    sep = prov["2026-Sep"]
    for field in ("sha256", "bytes", "source", "fetched", "current_release",
                  "document_version"):
        check("September provenance carries %s" % field, bool(sep.get(field)), True)
    # .get with a default, not sep["sha256"]: when the digest goes missing this
    # must FAIL, and len(None) would crash the suite instead, which proves
    # nothing at all.
    check("the sha256 is a real digest", len(sep.get("sha256") or ""), 64)
    check("the source is the MSRC API",
          sep["source"].startswith("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/"),
          True)

    print("\nan empty input directory and a bad table are refused")
    empty = os.path.join(tmp, "empty")
    os.makedirs(empty)
    r, c = run(["build", "--in", empty, "--out", os.path.join(tmp, "x.json")])
    check("no documents fails", c, 1)
    bad = os.path.join(tmp, "bad.json")
    open(bad, "w").write('{"schema": 999}')
    r, c = run(["assess", "--db", bad, "--build", "10.0.20348.1"])
    check("a table from another version fails", c, 1)
    check("and says so", "different version" in (r.get("error") or ""), True)

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
