#!/usr/bin/env python3
"""kameki_gmp.py regression test.

Drives every subcommand against a stubbed gvmd. No Greenbone, no socket, no
network and no root needed.

What it guards against, all of which shipped at least once:

  * gvmd answers on ONE line, so `grep -c '<config id='` returned 1 however
    many configs existed and the operator was told the feed had not imported.
  * the first <name> under a <config> is <owner><name>admin</name>, so
    `grep -A2` read every scan config's name as "admin" and the wanted config
    was never matched.
  * a task that gvmd refused to create left the report id unset, and the next
    line read it.
  * the GMP password was passed in argv, visible in `ps` to every user on the
    host, and had to be scrubbed from shell history afterwards.

The fixtures below are the real shapes: single line, owner and filter noise
included, because that is what broke the shell version.
"""

import io
import json
import os
import sys
import tempfile
from xml.etree import ElementTree

# macOS system python caches bytecode under ~/Library/Caches/com.apple.python,
# outside the source tree, and the staleness check is mtime+size. An edit that
# leaves the file the same size in the same second is invisible to it, so the
# test can silently run the PREVIOUS version of the module. That happened while
# this suite was being written: a one-line change of `==` to `in` is
# byte-for-byte the same length, the cached bytecode was reused, and the mutant
# appeared to pass. Refuse to write or read stale bytecode.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# --------------------------------------------------------------------------
#  fixtures: exactly what gvmd puts on the wire
# --------------------------------------------------------------------------
CONFIGS = (
    '<get_configs_response status="200"><filters id="0"><name>get_configs</name>'
    '</filters><config id="d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663"><owner>'
    '<name>admin</name></owner><name>Base</name></config>'
    '<config id="2d3f051c-55ba-11e3-bf43-406186ea4fc5"><owner><name>admin</name>'
    '</owner><name>Full and fast ultimate</name></config>'
    '<config id="daba56c8-73ec-11df-a475-002264764cea"><owner><name>admin</name>'
    '</owner><name>Full and fast</name><permissions><permission>'
    '<name>Everything</name></permission></permissions></config>'
    '<config id="2dztwpc5-56sa-11e3-aaaa-406186ea4fc5"><owner><name>admin</name>'
    '</owner><name>Host Discovery</name></config>'
    '<config id="8715c877-47a0-438d-98a3-27c7a6ab2196"><owner><name>admin</name>'
    '</owner><name>Discovery</name></config></get_configs_response>'
)
FORMATS = (
    '<get_report_formats_response status="200"><report_format '
    'id="5057e5cc-b825-11e4-9d0e-28d24461215b"><owner><name>admin</name></owner>'
    '<name>Anonymous XML</name></report_format><report_format '
    'id="c1645568-627a-11e3-a660-406186ea4fc5"><owner><name>admin</name></owner>'
    '<name>CSV Results</name></report_format><report_format '
    'id="a994b278-1f62-11e1-96ac-406186ea4fc5"><owner><name>admin</name></owner>'
    '<name>XML</name></report_format></get_report_formats_response>'
)
SCANNERS = (
    '<get_scanners_response status="200"><scanner '
    'id="08b69003-5fc2-4037-a479-93b440211c73"><owner><name>admin</name></owner>'
    '<name>OpenVAS Default</name></scanner></get_scanners_response>'
)


class FakeGmp:
    """Enough of python-gvm's versioned protocol object to drive the client."""

    def __init__(self, behaviour):
        self.b = behaviour
        self.authed = False
        self.calls = []

    def _x(self, s):
        return ElementTree.fromstring(s)

    def authenticate(self, user, password):
        self.calls.append(("authenticate", user))
        if self.b.get("auth_fails"):
            raise RuntimeError("Authentication failed")
        self.authed = True

    def get_version(self):
        return self._x('<get_version_response status="200"><version>22.5'
                       '</version></get_version_response>')

    def get_scan_configs(self, **kw):
        return self._x(CONFIGS)

    def get_report_formats(self, **kw):
        return self._x(FORMATS)

    def get_scanners(self, **kw):
        return self._x(SCANNERS)

    def get_targets(self, **kw):
        return self._x('<get_targets_response status="200"/>')

    def create_credential(self, **kw):
        self.calls.append(("create_credential", kw.get("name"), kw.get("login")))
        return self._x('<create_credential_response status="201" '
                       'id="aaaa1111-2222-3333-4444-555555555555"/>')

    def create_target(self, **kw):
        self.calls.append(("create_target", kw.get("name"), tuple(kw.get("hosts") or ())))
        return self._x('<create_target_response status="201" '
                       'id="bbbb1111-2222-3333-4444-555555555555"/>')

    def create_task(self, **kw):
        self.calls.append(("create_task", kw.get("name")))
        if self.b.get("create_task_fails"):
            raise RuntimeError("Failed to find config")
        return self._x('<create_task_response status="201" '
                       'id="cccc1111-2222-3333-4444-555555555555"/>')

    def start_task(self, task_id):
        if self.b.get("start_returns_no_report"):
            return self._x('<start_task_response status="202"/>')
        return self._x('<start_task_response status="202"><report_id>'
                       'dddd1111-2222-3333-4444-555555555555</report_id>'
                       '</start_task_response>')

    def get_task(self, task_id):
        if self.b.get("task_missing"):
            return self._x('<get_tasks_response status="200"/>')
        polls = len([c for c in self.calls if c[0] == "get_task"])
        # A poll loop with no cap would hang the suite instead of failing it,
        # and a hanging test proves nothing. Refuse to answer forever.
        if polls > self.b.get("max_polls", 50):
            raise RuntimeError("polled %d times without stopping" % polls)
        seq = self.b.get("statuses")
        if seq:
            # Walk the sequence, then hold on the last entry, so a capped poll
            # keeps seeing "Running" instead of running off the end.
            i = min(len([c for c in self.calls if c[0] == "get_task"]), len(seq) - 1)
            self.calls.append(("get_task", i))
            status, progress = seq[i]
        else:
            self.calls.append(("get_task", 0))
            status = self.b.get("status", "Done")
            progress = self.b.get("progress", "100")
        return self._x('<get_tasks_response status="200"><task><status>%s'
                       '</status><progress>%s</progress></task>'
                       '</get_tasks_response>' % (status, progress))

    def get_report(self, **kw):
        import base64
        if self.b.get("report_is_xml"):
            # An XML report format comes back as live elements, not a blob.
            return self._x('<get_reports_response status="200">'
                           '<report id="r1"><report_format id="f1"/>'
                           '<results><result><name>finding</name></result>'
                           '</results></report></get_reports_response>')
        csv = ('IP,Hostname,Port,CVSS,Severity\n'
               '"10.0.0.1","h1","445","7.5","High"\n')
        blob = base64.b64encode(csv.encode()).decode()
        # The real shape: the blob FOLLOWS <report_format/>, so in ElementTree
        # it is that element's tail, not the report's text.
        return self._x('<get_reports_response status="200">'
                       '<report id="r1"><report_format id="f1"/>%s</report>'
                       '</get_reports_response>' % blob)

    def delete_credential(self, cid, **kw):
        self.calls.append(("delete_credential", cid))
        return self._x('<delete_credential_response status="200"/>')


def install_stub(behaviour):
    """Put a fake python-gvm in sys.modules before the client imports it."""
    import types
    gmp_obj = FakeGmp(behaviour)

    conns = types.ModuleType("gvm.connections")

    class UnixSocketConnection:
        def __init__(self, path=None, timeout=None):
            self.path = path

    conns.UnixSocketConnection = UnixSocketConnection

    protos = types.ModuleType("gvm.protocols.gmp")

    class GMP:
        def __init__(self, connection, transform=None):
            pass

        def __enter__(self):
            return gmp_obj

        def __exit__(self, *a):
            return False

    protos.GMP = GMP

    reqs = types.ModuleType("gvm.protocols.gmp.requests.v224")

    class CredentialType:
        USERNAME_PASSWORD = "up"

    # The real enum, names and values both, because kameKi's default alive
    # test is spelled as a VALUE and only the value will match it.
    import enum

    class AliveTest(enum.Enum):
        SCAN_CONFIG_DEFAULT = "Scan Config Default"
        ICMP_PING = "ICMP Ping"
        TCP_ACK_SERVICE_PING = "TCP-ACK Service Ping"
        TCP_SYN_SERVICE_PING = "TCP-SYN Service Ping"
        ARP_PING = "ARP Ping"
        ICMP_AND_TCP_ACK_SERVICE_PING = "ICMP & TCP-ACK Service Ping"
        ICMP_AND_ARP_PING = "ICMP & ARP Ping"
        TCP_ACK_SERVICE_AND_ARP_PING = "TCP-ACK Service & ARP Ping"
        ICMP_TCP_ACK_SERVICE_AND_ARP_PING = "ICMP, TCP-ACK Service & ARP Ping"
        CONSIDER_ALIVE = "Consider Alive"

    reqs.CredentialType = CredentialType
    reqs.AliveTest = AliveTest

    transforms = types.ModuleType("gvm.transforms")
    transforms.EtreeTransform = lambda *a, **k: None
    # The client must ask for the CHECKING transform. With the plain one, gvmd
    # refusing a password comes back as an ordinary element and the client
    # reports success -- which is how a wrong credential got written to disk
    # as verified. Only the checking name is provided here, so asking for the
    # wrong one is an ImportError the test will show.
    transforms.EtreeCheckCommandTransform = lambda *a, **k: None

    base = types.ModuleType("gvm")
    pm = types.ModuleType("gvm.protocols")
    rm = types.ModuleType("gvm.protocols.gmp.requests")
    for name, mod in (("gvm", base), ("gvm.protocols", pm),
                      ("gvm.connections", conns), ("gvm.protocols.gmp", protos),
                      ("gvm.protocols.gmp.requests", rm),
                      ("gvm.protocols.gmp.requests.v224", reqs),
                      ("gvm.transforms", transforms)):
        sys.modules[name] = mod
    return gmp_obj


def run(argv, behaviour=None, files=None):
    """Invoke the client in-process and capture its JSON and exit code."""
    for mod in [m for m in sys.modules if m == "gvm" or m.startswith("gvm.")]:
        del sys.modules[mod]
    for mod in [m for m in sys.modules if m == "kameki_gmp"]:
        del sys.modules[mod]
    gmp_obj = install_stub(behaviour or {})
    import importlib
    importlib.invalidate_caches()
    import kameki_gmp
    importlib.reload(kameki_gmp)
    out, errs = io.StringIO(), io.StringIO()
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, errs
    code = 0
    try:
        kameki_gmp.main(argv)
    except SystemExit as exc:
        code = exc.code or 0
    finally:
        sys.stdout, sys.stderr = real_out, real_err
    text = out.getvalue().strip()
    gmp_obj.stderr = errs.getvalue()
    try:
        return json.loads(text), code, gmp_obj
    except ValueError:
        return {"_raw": text}, code, gmp_obj


PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  PASS  %s" % label)
    else:
        FAIL += 1
        print("  FAIL  %s\n        got  %r\n        want %r" % (label, got, want))


def main():
    tmp = tempfile.mkdtemp()
    sock = os.path.join(tmp, "gvmd.sock")
    open(sock, "w").close()                      # connect() checks it exists
    uf = os.path.join(tmp, "u"); open(uf, "w").write("kameki-admin\n")
    pf = os.path.join(tmp, "p"); open(pf, "w").write("s3cret\n")
    hf = os.path.join(tmp, "hosts"); open(hf, "w").write("10.0.0.1\n10.0.0.2\n\n")
    base = ["--socket", sock, "--user-file", uf, "--pass-file", pf]

    print("the one-line XML that defeated grep is parsed correctly")
    r, c, _ = run(base + ["list", "--kind", "configs"])
    check("five configs, not one", len(r.get("items", [])), 5)
    check("names are the configs', not the owner's",
          [i["name"] for i in r["items"]],
          ["Base", "Full and fast ultimate", "Full and fast", "Host Discovery",
           "Discovery"])
    check("no owner name leaked",
          [i for i in r["items"] if i["name"] == "admin"], [])
    check("exit 0", c, 0)

    print("\nresolving a config by name returns its id")
    r, c, _ = run(base + ["resolve", "--kind", "configs", "--name", "Full and fast"])
    check("id", r.get("id"), "daba56c8-73ec-11df-a475-002264764cea")
    r, c, _ = run(base + ["resolve", "--kind", "configs", "--name", "FULL AND FAST"])
    check("match is case-insensitive", r.get("id"), "daba56c8-73ec-11df-a475-002264764cea")
    r, c, _ = run(base + ["resolve", "--kind", "configs", "--name", "Nope"])
    check("absent config fails", c, 1)
    check("and names what is available", r.get("available"),
          ["Base", "Full and fast ultimate", "Full and fast", "Host Discovery",
           "Discovery"])

    # The feed ships names that contain one another. A substring match returns
    # "Full and fast ultimate" for "Full and fast" -- a far longer scan -- and
    # "Anonymous XML" for "XML", which strips the host addresses.
    r, _, _ = run(base + ["resolve", "--kind", "configs", "--name", "Discovery"])
    check("Discovery is not Host Discovery", r.get("name"), "Discovery")
    r, _, _ = run(base + ["resolve", "--kind", "configs", "--name", "Full and fast"])
    check("Full and fast is not Full and fast ultimate",
          r.get("id"), "daba56c8-73ec-11df-a475-002264764cea")

    print("\nreport formats and scanners")
    r, _, _ = run(base + ["resolve", "--kind", "formats", "--name", "CSV Results"])
    check("CSV Results id", r.get("id"), "c1645568-627a-11e3-a660-406186ea4fc5")
    r, _, _ = run(base + ["resolve", "--kind", "formats", "--name", "XML"])
    check("XML is not Anonymous XML", r.get("id"), "a994b278-1f62-11e1-96ac-406186ea4fc5")
    r, _, _ = run(base + ["resolve", "--kind", "scanners", "--name", "OpenVAS Default"])
    check("scanner id", r.get("id"), "08b69003-5fc2-4037-a479-93b440211c73")

    print("\nthe task lifecycle")
    r, c, g = run(base + ["create-credential", "--name", "c1",
                          "--login-file", uf, "--cred-pass-file", pf])
    check("credential id", r.get("id"), "aaaa1111-2222-3333-4444-555555555555")
    r, c, g = run(base + ["create-target", "--name", "t1", "--hosts-file", hf,
                          "--alive-test", "ICMP Ping"])
    check("target id", r.get("id"), "bbbb1111-2222-3333-4444-555555555555")
    check("blank lines dropped from the host list",
          [c for c in g.calls if c[0] == "create_target"][0][2],
          ("10.0.0.1", "10.0.0.2"))
    r, c, _ = run(base + ["create-task", "--name", "n", "--config", "a",
                          "--target", "b", "--scanner", "c"])
    check("task id", r.get("id"), "cccc1111-2222-3333-4444-555555555555")
    r, c, _ = run(base + ["start-task", "--task", "t"])
    check("report id", r.get("report_id"), "dddd1111-2222-3333-4444-555555555555")
    r, c, _ = run(base + ["task-status", "--task", "t"])
    check("status", (r.get("status"), r.get("progress")), ("Done", 100))

    print("\na refusal is reported as a refusal, not as a crash")
    r, c, _ = run(base + ["create-task", "--name", "n", "--config", "a",
                          "--target", "b", "--scanner", "c"],
                  {"create_task_fails": True})
    check("exit non-zero", c, 1)
    check("ok is false", r.get("ok"), False)
    check("gvmd's own words are kept",
          "Failed to find config" in r.get("error", ""), True)

    r, c, _ = run(base + ["start-task", "--task", "t"],
                  {"start_returns_no_report": True})
    check("a start with no report id fails", c, 1)
    r, c, _ = run(base + ["task-status", "--task", "t"], {"task_missing": True})
    check("a missing task fails", c, 1)
    r, c, _ = run(base + ["check"], {"auth_fails": True})
    check("bad credentials fail", c, 1)
    check("and say so", "authentication failed" in r.get("error", "").lower(), True)

    print("\nthe report is decoded and written, not left base64")
    # gvmd puts the blob AFTER <report_format/>, which is a tail not a text.
    # Reading only .text wrote a zero-byte CSV and the whole NVT stage looked
    # like it had found nothing.
    out = os.path.join(tmp, "r.csv")
    r, c, _ = run(base + ["get-report", "--report", "x", "--format", "y",
                          "--out", out])
    check("exit 0", c, 0)
    body = open(out, encoding="utf-8").read()
    check("decoded to CSV", body.splitlines()[0],
          "IP,Hostname,Port,CVSS,Severity")
    check("not zero bytes", r.get("bytes", 0) > 0, True)
    check("byte count reported", r.get("bytes"), len(body.encode()))

    outx = os.path.join(tmp, "r.xml")
    r, c, _ = run(base + ["get-report", "--report", "x", "--format", "y",
                          "--out", outx], {"report_is_xml": True})
    check("an XML format is written as XML", c, 0)
    xml = open(outx, encoding="utf-8").read()
    check("XML kept as elements", "<result>" in xml, True)

    print("\nthe scan lifecycle runs end to end on one connection")
    csv_out = os.path.join(tmp, "s.csv")
    xml_out = os.path.join(tmp, "s.xml")
    ids_out = os.path.join(tmp, "ids.txt")
    scan = base + ["scan", "--run-name", "r1", "--hosts-file", hf,
                   "--config-name", "Full and fast", "--poll", "0",
                   "--smb-login-file", uf, "--smb-pass-file", pf,
                   "--csv-out", csv_out, "--xml-out", xml_out,
                   "--ids-out", ids_out, "--alive-test", "ICMP Ping"]
    r, c, g = run(scan, {"statuses": [("Requested", "0"), ("Running", "40"),
                                      ("Done", "100")]})
    check("exit 0", c, 0)
    check("status Done", r.get("status"), "Done")
    check("it polled until Done, not once",
          len([x for x in g.calls if x[0] == "get_task"]) >= 3, True)
    check("the right config was used", r.get("config"),
          "daba56c8-73ec-11df-a475-002264764cea")
    check("the openvas scanner was found", r.get("scanner"),
          "08b69003-5fc2-4037-a479-93b440211c73")
    check("host count", r.get("hosts"), 2)
    check("CSV written", r.get("wrote", {}).get("csv", 0) > 0, True)
    check("ids file written", open(ids_out).read().strip(),
          "task=cccc1111-2222-3333-4444-555555555555 "
          "target=bbbb1111-2222-3333-4444-555555555555 "
          "report=dddd1111-2222-3333-4444-555555555555")
    check("progress went to stderr, not stdout", "polling every" in g.stderr, True)

    print("\nthe client's password is removed from gvmd, success or failure")
    check("deleted after a clean run",
          [x for x in g.calls if x[0] == "delete_credential"],
          [("delete_credential", "aaaa1111-2222-3333-4444-555555555555")])

    r, c, g = run(scan, {"create_task_fails": True})
    check("a refused task still exits non-zero", c, 1)
    check("and the credential is STILL deleted",
          [x for x in g.calls if x[0] == "delete_credential"],
          [("delete_credential", "aaaa1111-2222-3333-4444-555555555555")])

    r, c, g = run(scan, {"start_returns_no_report": True})
    check("a task that will not start is reported", r.get("ok"), False)
    check("and the credential is deleted then too",
          len([x for x in g.calls if x[0] == "delete_credential"]), 1)

    r, c, g = run(scan, {"task_missing": True})
    check("a vanished task is reported", c, 1)
    check("with the journalctl hint", "journalctl" in r.get("hint", ""), True)
    check("and the credential is deleted then too",
          len([x for x in g.calls if x[0] == "delete_credential"]), 1)

    print("\nan ssh credential is created and removed only when asked for")
    r, c, g = run(scan, {"statuses": [("Done", "100")]})
    check("no ssh credential by default",
          len([x for x in g.calls if x[0] == "create_credential"]), 1)
    r, c, g = run(scan + ["--ssh-login-file", uf, "--ssh-pass-file", pf],
                  {"statuses": [("Done", "100")]})
    check("two credentials when ssh is on",
          len([x for x in g.calls if x[0] == "create_credential"]), 2)
    check("and both are removed",
          len([x for x in g.calls if x[0] == "delete_credential"]), 2)

    print("\na config the feed did not deliver is named, with what is there")
    r, c, g = run(base + ["scan", "--run-name", "r1", "--hosts-file", hf,
                          "--config-name", "Nonexistent", "--poll", "0",
                          "--smb-login-file", uf, "--smb-pass-file", pf])
    check("exit non-zero", c, 1)
    check("names the missing config",
          "Nonexistent" in r.get("error", ""), True)
    check("lists what gvmd has", "Full and fast" in (r.get("available") or []), True)
    check("gives the feed-sync remedy",
          "greenbone-feed-sync" in r.get("hint", ""), True)
    check("and nothing was created before it failed",
          [x for x in g.calls if x[0] == "create_credential"], [])

    print("\nan empty target list is refused before anything is created")
    empty = os.path.join(tmp, "empty"); open(empty, "w").write("\n\n")
    r, c, g = run(base + ["scan", "--run-name", "r1", "--hosts-file", empty,
                          "--config-name", "Full and fast", "--poll", "0",
                          "--smb-login-file", uf, "--smb-pass-file", pf])
    check("exit non-zero", c, 1)
    check("says the host list is empty", "no hosts" in r.get("error", ""), True)
    check("nothing created", [x for x in g.calls if x[0] == "create_target"], [])

    print("\na scan that never finishes is capped, not left to run for hours")
    r, c, g = run(scan + ["--max-minutes", "-1"],
                  {"statuses": [("Running", "10")], "max_polls": 8})
    check("the cap exports what there is", r.get("ok"), True)
    check("status reported as Running, not Done", r.get("status"), "Running")
    check("and it says so on stderr", "giving up on the poll" in g.stderr, True)
    check("it stopped after one look, not fifty",
          len([x for x in g.calls if x[0] == "get_task"]), 1)

    print("\nthe alive test kameKi actually defaults to is honoured")
    # kameKi's default is ALIVE_TEST="ICMP, TCP-ACK Service & ARP Ping", which
    # is an enum VALUE. Name mangling turns it into ICMP,_TCP_ACK_SERVICE_&...
    # which matches nothing, and gvmd then silently used its own default -- a
    # different set of liveness probes than the operator asked for.
    default_alive = "ICMP, TCP-ACK Service & ARP Ping"
    r, c, g = run(base + ["create-target", "--name", "t", "--hosts-file", hf,
                          "--alive-test", default_alive])
    check("accepted", c, 0)
    r, c, g = run(scan + ["--alive-test", default_alive],
                  {"statuses": [("Done", "100")]})
    check("the scan passes it through", c, 0)
    check("and does not warn about an unknown test",
          "unknown alive test" in g.stderr, False)
    r, c, g = run(scan + ["--alive-test", "ICMP Ping"],
                  {"statuses": [("Done", "100")]})
    check("a plain name still works", "unknown alive test" in g.stderr, False)
    r, c, g = run(scan + ["--alive-test", "Nonsense Ping"],
                  {"statuses": [("Done", "100")]})
    check("a real typo is named rather than silently ignored",
          "unknown alive test" in g.stderr, True)

    print("\nthe client asks for the transform that checks gvmd's status")
    src = open(os.path.join(ROOT, "kameki_gmp.py"), encoding="utf-8").read()
    check("EtreeCheckCommandTransform is used",
          "EtreeCheckCommandTransform()" in src, True)
    check("the non-checking transform is not instantiated",
          "EtreeTransform()" in src.replace("EtreeCheckCommandTransform()", ""),
          False)

    print("\nthe password never reaches argv")
    src = open(os.path.join(ROOT, "kameki_gmp.py"), encoding="utf-8").read()
    check("no --password argument exists", "--password" in src, False)
    check("credentials are read from files", "read_secret" in src, True)

    print("\na missing socket and a missing library are named, not hidden")
    r, c, _ = run(["--socket", os.path.join(tmp, "nope.sock"),
                   "--user-file", uf, "--pass-file", pf, "check"])
    check("missing socket fails", c, 1)
    check("and says which path", "nope.sock" in r.get("error", ""), True)

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
