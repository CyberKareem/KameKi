#!/usr/bin/env python3
"""Windows patch assessment from Microsoft's own security data.

Compiles MSRC CVRF documents into a build-level lookup table, then judges a
host by comparing the OS build it actually reports against the build Microsoft
says fixes each CVE.

Why this rather than matching version strings against NVD
---------------------------------------------------------
A service-banner or package-version lookup in NVD is not aware of vendor
backports, and NVD's own version ranges are frequently wrong: Nguyen and
Massacci (arXiv:1302.4133) found 134 of 167 verifiable Chrome entries carried
erroneous vulnerable-version data, and by the construction of their measure
every one of those errors is an over-claim -- a false positive. That is the
wrong foundation for a report a client has to act on.

Microsoft states, per CVE, the exact OS build that fixes it. Windows 10,
Windows 11 and Server 2016 and later ship cumulative updates, so a later
cumulative always contains every earlier one. That makes a single comparison

    installed UBR  <  the UBR Microsoft says fixes this CVE

the whole supersedence check. No version ranges, no CPE matching, no
inference. If the host is at or above the fixed build it is not affected, and
the method cannot say otherwise.

What this deliberately will not do
----------------------------------
  * It does not assess a build it has no Microsoft data for. Windows Server
    2012 R2 and earlier are 6.x builds and do not use the cumulative UBR
    scheme at all, so they are reported as not assessed, with the reason,
    rather than guessed at.
  * It does not key on the base build alone. Base build 26100 is shared by
    Windows 11 24H2 and Windows Server 2025, and in September 2026 the two
    required very different revisions -- UBR 9445 against UBR 33438. Taking
    the highest revision for that build would have reported every Windows 11
    24H2 host as missing a patch that does not exist for it. Client and
    server are separate lines.
  * It does not present a count as complete when it cannot be. If a host sits
    below the oldest revision in the compiled window, CVEs from before that
    window also apply, and the result says so instead of implying the figure
    is the whole truth.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys

SCHEMA = 1
# Microsoft writes the fixed build as 10.0.<base>.<revision>; the leading 10.0
# has been constant since Windows 10 and Server 2016.
FIXED_BUILD = re.compile(r"^10\.0\.(\d+)\.(\d+)$")
# Threat records are typed: 0 is the impact, 1 the exploitability assessment,
# 3 the MSRC severity rating.
THREAT_IMPACT, THREAT_EXPLOIT, THREAT_SEVERITY = 0, 1, 3


def emit(obj, code=0):
    json.dump(obj, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()
    sys.exit(code)


def fail(message, code=1, **extra):
    payload = {"ok": False, "error": str(message)}
    payload.update(extra)
    emit(payload, code)


def text_of(node, key="Value"):
    if isinstance(node, dict):
        value = node.get(key)
        return value if isinstance(value, str) else None
    return None


# Microsoft names its documents YYYY-Mon. Sorting those as text puts August
# before July and December before February, which silently misreports the data
# window the whole assessment is bounded by.
MONTH_ORDER = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def month_sort_key(month):
    match = re.match(r"^(\d{4})-([A-Za-z]{3})", month or "")
    if not match:
        return (9999, 99, month or "")
    return (int(match.group(1)), MONTH_ORDER.get(match.group(2).title(), 99), "")


def line_key(base, is_server):
    return "%s|%s" % (base, "server" if is_server else "client")


def classify(product_name):
    """True when this product is a Windows Server edition.

    The only thing separating two cumulative lines that share a base build, so
    it is deliberately simple and based on Microsoft's own product naming.
    """
    return "server" in (product_name or "").lower()


# --------------------------------------------------------------------------
#  build
# --------------------------------------------------------------------------
def collect_cvss(vuln, product_ids):
    """Highest CVSS base score Microsoft published for these products."""
    best, vector = None, None
    for score_set in vuln.get("CVSSScoreSets") or []:
        ids = set(score_set.get("ProductID") or [])
        if product_ids and ids and not (ids & product_ids):
            continue
        raw = score_set.get("BaseScore")
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if best is None or value > best:
            best, vector = value, score_set.get("Vector")
    return best, vector


def collect_threats(vuln, product_ids):
    """Severity, impact and whether Microsoft says it is being exploited."""
    severity = impact = exploit = None
    for threat in vuln.get("Threats") or []:
        ids = set(threat.get("ProductID") or [])
        if product_ids and ids and not (ids & product_ids):
            continue
        value = text_of(threat.get("Description"))
        if not value:
            continue
        kind = threat.get("Type")
        if kind == THREAT_SEVERITY and severity is None:
            severity = value
        elif kind == THREAT_IMPACT and impact is None:
            impact = value
        elif kind == THREAT_EXPLOIT and exploit is None:
            exploit = value
    exploited = bool(exploit and re.search(r"Exploited:\s*Yes", exploit, re.I))
    return severity, impact, exploited


def read_document(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


def document_provenance(path, document, fetched=None):
    body = open(path, "rb").read()
    tracking = document.get("DocumentTracking") or {}
    ident = (tracking.get("Identification") or {}).get("ID") or {}
    return {
        "month": text_of(ident) or os.path.basename(path).rsplit(".", 1)[0],
        "file": os.path.basename(path),
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "document_version": tracking.get("Version"),
        "initial_release": tracking.get("InitialReleaseDate"),
        "current_release": tracking.get("CurrentReleaseDate"),
        "fetched": fetched,
        "source": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/%s"
                  % (text_of(ident) or "?"),
    }


def build(paths, fetched=None):
    lines, provenance, empty = {}, [], []
    for path in paths:
        try:
            document = read_document(path)
        except (OSError, ValueError) as exc:
            return None, "cannot read %s: %s" % (path, exc)
        products = {
            entry.get("ProductID"): entry.get("Value")
            for entry in (document.get("ProductTree") or {}).get("FullProductName", [])
        }
        prov = document_provenance(path, document, fetched)
        provenance.append(prov)

        found = 0
        for vuln in document.get("Vulnerability") or []:
            cve = vuln.get("CVE")
            for rem in vuln.get("Remediations") or []:
                match = FIXED_BUILD.match(rem.get("FixedBuild") or "")
                if not match:
                    continue
                base, revision = match.group(1), int(match.group(2))
                rem_ids = set(rem.get("ProductID") or [])
                kb = text_of(rem.get("Description"))
                severity, impact, exploited = collect_threats(vuln, rem_ids)
                score, vector = collect_cvss(vuln, rem_ids)
                for pid in rem_ids:
                    name = products.get(pid)
                    if not name:
                        continue
                    found += 1
                    key = line_key(base, classify(name))
                    line = lines.setdefault(key, {"base": base,
                                                  "kind": "server" if classify(name) else "client",
                                                  "products": [], "levels": {}})
                    if name not in line["products"]:
                        line["products"].append(name)
                    level = line["levels"].setdefault(str(revision), {
                        "ubr": revision, "kb": kb,
                        "supersedes": rem.get("Supercedence") or None,
                        "month": prov["month"],
                        "released": rem.get("Date") if rem.get("DateSpecified") else
                                    prov.get("initial_release"),
                        "cves": {},
                    })
                    if cve:
                        entry = level["cves"].setdefault(cve, {
                            "cve": cve, "cvss": score, "vector": vector,
                            "severity": severity, "impact": impact,
                            "exploited": exploited,
                        })
                        # The same CVE can appear for several products in one
                        # line; keep the worst score Microsoft gave any of them.
                        if score is not None and (entry["cvss"] is None
                                                  or score > entry["cvss"]):
                            entry["cvss"], entry["vector"] = score, vector
                        entry["exploited"] = entry["exploited"] or exploited
        if not found:
            # A month with no Windows build data is not a reason to narrow the
            # window silently: the current month is routinely published empty
            # before its Patch Tuesday.
            empty.append(prov["month"])

    for line in lines.values():
        levels = sorted(line["levels"].values(), key=lambda l: l["ubr"])
        for level in levels:
            level["cves"] = sorted(level["cves"].values(), key=lambda c: c["cve"])
        line["levels"] = levels
        line["required_ubr"] = levels[-1]["ubr"] if levels else None

    months = sorted({p["month"] for p in provenance}, key=month_sort_key)
    with_data = [m for m in months if m not in empty]
    return {
        "schema": SCHEMA,
        "built": fetched,
        "window": {
            "months": months,
            "months_with_windows_data": with_data,
            "empty_months": sorted(empty, key=month_sort_key),
            "earliest": with_data[0] if with_data else None,
            "latest": with_data[-1] if with_data else None,
        },
        "provenance": provenance,
        "lines": lines,
    }, None


def cmd_build(args):
    paths = sorted(glob.glob(os.path.join(args.indir, "*.json")))
    if not paths:
        fail("no .json CVRF documents in %s" % args.indir)
    table, error = build(paths, args.fetched)
    if error:
        fail(error)
    if not table["lines"]:
        fail("no Windows build data in any document in %s" % args.indir,
             documents=len(paths))
    try:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(table, handle, sort_keys=True)
    except OSError as exc:
        fail("cannot write %s: %s" % (args.out, exc))
    return {
        "ok": True, "path": args.out,
        "documents": len(paths),
        "lines": len(table["lines"]),
        "window": table["window"],
        "cves": len({c["cve"] for l in table["lines"].values()
                     for lv in l["levels"] for c in lv["cves"]}),
    }


# --------------------------------------------------------------------------
#  assess
# --------------------------------------------------------------------------
def load_table(path):
    try:
        with open(path, encoding="utf-8") as handle:
            table = json.load(handle)
    except (OSError, ValueError) as exc:
        fail("cannot read %s: %s" % (path, exc))
    if table.get("schema") != SCHEMA:
        fail("%s was built by a different version of this tool "
             "(schema %r, expected %r)" % (path, table.get("schema"), SCHEMA))
    return table


def assess(table, base, ubr, is_server, host=None):
    key = line_key(base, is_server)
    kind = "server" if is_server else "client"
    out = {"ok": True, "host": host, "base_build": base,
           "installed_ubr": ubr, "kind": kind,
           "window": table.get("window")}
    line = (table.get("lines") or {}).get(key)
    if not line:
        other = (table.get("lines") or {}).get(line_key(base, not is_server))
        out.update({
            "assessed": False,
            "reason": "Microsoft published no fixed build for base build %s "
                      "(%s) in this data window" % (base, kind),
        })
        if other:
            out["note"] = ("base build %s exists in the data for %s, not %s; "
                           "the host was classified from its own reported "
                           "product name" % (base, other["kind"], kind))
        out["findings"] = []
        return out

    levels = line["levels"]
    required = line.get("required_ubr")
    missing = [l for l in levels if l["ubr"] > ubr]
    oldest = levels[0]["ubr"] if levels else None
    # Below the oldest revision in the window means updates from before the
    # window are missing too, so every figure here is a floor, not a total.
    behind_window = bool(oldest is not None and ubr < oldest)

    cves, worst, exploited = {}, None, []
    for level in missing:
        for cve in level["cves"]:
            kept = cves.setdefault(cve["cve"], dict(cve, kb=level["kb"],
                                                    fixed_ubr=level["ubr"]))
            if cve.get("cvss") is not None and (kept.get("cvss") is None
                                                or cve["cvss"] > kept["cvss"]):
                kept["cvss"], kept["vector"] = cve["cvss"], cve["vector"]
            if cve.get("exploited"):
                kept["exploited"] = True
    for cve in cves.values():
        if cve.get("cvss") is not None and (worst is None or cve["cvss"] > worst):
            worst = cve["cvss"]
        if cve.get("exploited"):
            exploited.append(cve["cve"])

    out.update({
        "assessed": True,
        "products": line.get("products", []),
        "required_ubr": required,
        "up_to_date": not missing,
        "behind_by_levels": len(missing),
        "counts_are_a_floor": behind_window,
        "missing_kbs": [l["kb"] for l in missing if l["kb"]],
        "cve_count": len(cves),
        "max_cvss": worst,
        "exploited_cves": sorted(exploited),
        "findings": sorted(cves.values(),
                           key=lambda c: (-(c.get("cvss") or 0), c["cve"])),
    })
    if behind_window:
        out["reason"] = ("installed revision %d is below the oldest revision "
                         "in this data window (%d), so updates released before "
                         "%s are missing as well and are not counted here"
                         % (ubr, oldest, table["window"].get("earliest")))
    return out


# Windows 8.1 / Server 2012 R2 and earlier report 6.x builds and were never
# serviced by cumulative updates with a UBR, so the comparison this module
# performs has no meaning for them. They are common in these estates, so they
# get a specific answer rather than a parse error.
PRE_CUMULATIVE = re.compile(r"^([0-6])\.(\d+)\.(\d+)")


def parse_build(value):
    """Accept 10.0.20348.5622, 20348.5622 or a bare base build.

    Returns (base, ubr, problem). base is None when nothing usable was found.
    """
    text = (value or "").strip()
    match = FIXED_BUILD.match(text)
    if match:
        return match.group(1), int(match.group(2)), None
    match = PRE_CUMULATIVE.match(text)
    if match:
        return None, None, (
            "build %s predates cumulative servicing: Windows 8.1, Server 2012 R2 "
            "and earlier have no update revision to compare, so this method "
            "cannot assess them. Assess these hosts by another means, or treat "
            "them as unsupported if they are past end of life" % text)
    match = re.match(r"^(\d{4,6})\.(\d+)$", text)
    if match:
        return match.group(1), int(match.group(2)), None
    match = re.match(r"^(\d{4,6})$", text)
    if match:
        return match.group(1), None, None
    return None, None, "cannot read a Windows build from %r" % value


def cmd_assess(args):
    table = load_table(args.db)
    base, ubr = args.base, args.ubr
    if args.build:
        base, parsed, problem = parse_build(args.build)
        if base is None:
            # Not an error: a host that cannot be assessed by this method is a
            # legitimate outcome and must be reported as one, so it appears in
            # the coverage figures rather than vanishing from them.
            return {"ok": True, "host": args.host, "kind": args.kind,
                    "reported_build": args.build, "installed_ubr": None,
                    "assessed": False, "findings": [],
                    "reason": problem}
        if parsed is not None:
            ubr = parsed
    if not base:
        return {"ok": False, "error": "no base build given"}
    if ubr is None:
        # Without the revision there is nothing to compare; saying so is the
        # only honest answer, and PCI 11.3.1.2 wants the collection recorded.
        return {"ok": True, "host": args.host, "base_build": base,
                "installed_ubr": None, "assessed": False, "findings": [],
                "reason": "the host's update revision (UBR) was not collected, "
                          "so its patch level cannot be compared"}
    return assess(table, base, ubr, args.kind == "server", args.host)


def cmd_window(args):
    table = load_table(args.db)
    return {"ok": True, "window": table.get("window"),
            "provenance": table.get("provenance"),
            "lines": sorted(table.get("lines", {}))}


# --------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("build", help="compile CVRF documents into a table")
    p.add_argument("--in", dest="indir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--fetched", default=None,
                   help="ISO timestamp recorded as the fetch time")

    p = sub.add_parser("assess", help="judge one host's patch level")
    p.add_argument("--db", required=True)
    p.add_argument("--build", default=None,
                   help="10.0.20348.5622, or 20348.5622")
    p.add_argument("--base", default=None)
    p.add_argument("--ubr", type=int, default=None)
    p.add_argument("--kind", choices=("client", "server"), default="client")
    p.add_argument("--host", default=None)

    p = sub.add_parser("window", help="print the data window and provenance")
    p.add_argument("--db", required=True)
    return parser


HANDLERS = {"build": cmd_build, "assess": cmd_assess, "window": cmd_window}


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        result = HANDLERS[args.command](args)
    except Exception as exc:                       # noqa: BLE001
        fail("%s: %s" % (type(exc).__name__, exc))
    emit(result, 0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
