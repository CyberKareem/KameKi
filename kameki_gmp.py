#!/usr/bin/env python3
"""Greenbone Management Protocol client for kameKi.

Replaces the gvm-cli shell-out and the XML-parsed-with-grep that went with it.
Every subcommand prints one JSON object on stdout and exits non-zero on
failure, so the shell parses results with jq instead of sed and grep.

Three things this fixes that were not fixable in shell:

  * gvmd answers on a single line, so `grep -c` always returned 1 and
    `grep -A2` landed inside <owner><name>admin</name>. Here the response is
    parsed as XML and an object's own child element is read directly.
  * gvm-cli refuses to run as root by design, which forced a runuser wrapper
    that had to guess which account to drop to. python-gvm has no such check:
    it opens the socket as whoever invoked it.
  * the password was passed as a command-line argument, so it was visible in
    `ps` to every user on the box and had to be scrubbed from shell history
    afterwards. Credentials are read from files here and never appear in argv.

Usage is always:  kameki_gmp.py --socket PATH --user-file F --pass-file F CMD
"""

import argparse
import base64
import json
import os
import sys

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_NO_LIBRARY = 3


def emit(obj, code=EXIT_OK):
    json.dump(obj, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()
    sys.exit(code)


def fail(message, code=EXIT_FAIL, **extra):
    payload = {"ok": False, "error": str(message)}
    payload.update(extra)
    emit(payload, code)


def read_secret(path):
    """First line of a file, with no trailing newline. Never from argv."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.readline().strip()
    except OSError as exc:
        fail("cannot read %s: %s" % (path, exc))


def read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        fail("cannot read %s: %s" % (path, exc))


def connect(args):
    """Open an authenticated GMP session, or exit with a readable reason."""
    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols.gmp import GMP
        # EtreeCheckCommandTransform, not EtreeTransform: the plain one hands
        # back an error response as an ordinary element without complaining, so
        # gvmd refusing the password looked exactly like success and the wrong
        # credential was written to disk as verified. This one raises.
        from gvm.transforms import EtreeCheckCommandTransform
    except ImportError as exc:
        fail("python-gvm is not installed: %s. install with: "
             "pipx install gvm-tools   (it depends on python-gvm)" % exc,
             EXIT_NO_LIBRARY)

    if not os.path.exists(args.socket):
        fail("no gvmd socket at %s. is gvmd running?" % args.socket)

    user = read_secret(args.user_file)
    password = read_secret(args.pass_file)
    if not user or not password:
        fail("empty GMP username or password")

    connection = UnixSocketConnection(path=args.socket, timeout=args.timeout)
    session = GMP(connection, transform=EtreeCheckCommandTransform())
    gmp = session.__enter__()
    try:
        gmp.authenticate(user, password)
    except Exception as exc:                       # noqa: BLE001
        try:
            session.__exit__(None, None, None)
        except Exception:                          # noqa: BLE001
            pass
        fail("GMP authentication failed: %s" % exc)
    return session, gmp


def text_of(element, tag):
    """Direct child's text, never a nested one.

    The whole class of bug this module exists to remove came from reaching
    the first matching tag anywhere beneath an element: the first <name>
    under a <config> is <owner><name>, not the config's own name.
    """
    if element is None:
        return None
    child = element.find(tag)
    return child.text if child is not None and child.text else None



def alive_test_for(name):
    """Map a user-written alive test onto the enum, or None.

    The enum's members are keyed by NAME ("ICMP_PING") but kameKi's own
    default is written as a VALUE ("ICMP, TCP-ACK Service & ARP Ping"), which
    no name mangling produces. Matching only on the name silently dropped the
    chosen probe set and let gvmd fall back to its default, quietly changing
    which hosts are judged alive -- so the value is tried first.
    """
    from gvm.protocols.gmp.requests.v224 import AliveTest
    wanted = (name or "").strip().lower()
    if not wanted:
        return None
    for member in AliveTest:
        if member.value.strip().lower() == wanted:
            return member
    key = wanted.upper().replace(" ", "_").replace("-", "_")
    return getattr(AliveTest, key, None)


# --------------------------------------------------------------------------
#  subcommands
# --------------------------------------------------------------------------
KINDS = {
    "configs": ("get_scan_configs", "config"),
    "formats": ("get_report_formats", "report_format"),
    "scanners": ("get_scanners", "scanner"),
    "targets": ("get_targets", "target"),
}


def listing(gmp, kind):
    method, element = KINDS[kind]
    response = getattr(gmp, method)()
    out = []
    for node in response.findall(element):
        out.append({"id": node.get("id"), "name": text_of(node, "name")})
    return out


def cmd_check(gmp, args):
    version = gmp.get_version()
    return {"ok": True, "version": text_of(version, "version")}


def cmd_list(gmp, args):
    return {"ok": True, "kind": args.kind, "items": listing(gmp, args.kind)}


def cmd_resolve(gmp, args):
    wanted = args.name.strip().lower()
    for item in listing(gmp, args.kind):
        if (item["name"] or "").strip().lower() == wanted:
            return {"ok": True, "id": item["id"], "name": item["name"]}
    return {"ok": False, "error": "no %s named %r" % (args.kind, args.name),
            "available": [i["name"] for i in listing(gmp, args.kind)]}


def cmd_create_credential(gmp, args):
    from gvm.protocols.gmp.requests.v224 import CredentialType
    response = gmp.create_credential(
        name=args.name,
        credential_type=CredentialType.USERNAME_PASSWORD,
        login=read_secret(args.login_file),
        password=read_secret(args.cred_pass_file),
        allow_insecure=True,
    )
    return {"ok": True, "id": response.get("id")}


def cmd_create_target(gmp, args):
    from gvm.protocols.gmp.requests.v224 import AliveTest
    alive = None
    if args.alive_test:
        alive = alive_test_for(args.alive_test)
        if alive is None:
            return {"ok": False,
                    "error": "unknown alive test %r" % args.alive_test,
                    "available": [e.value for e in AliveTest]}
    kwargs = {"hosts": read_lines(args.hosts_file)}
    if alive is not None:
        kwargs["alive_test"] = alive
    if args.smb_credential:
        kwargs["smb_credential_id"] = args.smb_credential
    if args.ssh_credential:
        kwargs["ssh_credential_id"] = args.ssh_credential
        kwargs["ssh_credential_port"] = args.ssh_port
    response = gmp.create_target(name=args.name, **kwargs)
    return {"ok": True, "id": response.get("id")}


def cmd_create_task(gmp, args):
    response = gmp.create_task(
        name=args.name,
        config_id=args.config,
        target_id=args.target,
        scanner_id=args.scanner,
    )
    return {"ok": True, "id": response.get("id")}


def cmd_start_task(gmp, args):
    response = gmp.start_task(args.task)
    report = text_of(response, "report_id")
    if not report:
        return {"ok": False, "error": "gvmd started the task but returned no "
                                      "report id"}
    return {"ok": True, "report_id": report}


def cmd_task_status(gmp, args):
    response = gmp.get_task(args.task)
    task = response.find("task")
    if task is None:
        return {"ok": False, "error": "gvmd returned no task %s" % args.task}
    progress = text_of(task, "progress")
    return {"ok": True,
            "status": text_of(task, "status"),
            "progress": int(progress) if (progress or "").lstrip("-").isdigit() else 0}


B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                   "0123456789+/=\n\r \t")


def encoded_payload(node):
    """The base64 blob gvmd attaches to a report, wherever it put it.

    For a non-XML report format the response is

        <report id=".."><report_format id=".."/>UEsDBBQA...</report>

    so the blob is NOT the report element's text -- it follows a child, which
    in ElementTree means it is that child's `tail`. The shell version read it
    with  sed 's|.*</report_format>\(.*\)</report>.*|\1|p'  for exactly this
    reason. Reading only .text here returned an empty report and the CSV was
    silently zero bytes, so every chunk of character data in the subtree is
    considered and the largest base64-looking one wins.
    """
    chunks = [node.text or ""]
    for child in node.iter():
        chunks.append(child.tail or "")
        if child is not node:
            chunks.append(child.text or "")
    best = ""
    for chunk in chunks:
        candidate = chunk.strip()
        if len(candidate) > len(best) and set(candidate) <= B64_ALPHABET:
            best = candidate
    return best


def cmd_get_report(gmp, args):
    """Write the report to a file, decoding base64 when the format is binary."""
    response = gmp.get_report(
        report_id=args.report,
        report_format_id=args.format,
        filter_string=args.filter,
        ignore_pagination=True,
        details=True,
    )
    node = response.find("report")
    if node is None:
        return {"ok": False, "error": "gvmd returned no report %s" % args.report}
    payload = encoded_payload(node)
    data = None
    if payload:
        try:
            data = base64.b64decode(payload, validate=False)
        except Exception:                          # noqa: BLE001
            data = None
    if not data:
        # An XML format arrives as live elements rather than an encoded blob.
        from xml.etree import ElementTree
        data = ElementTree.tostring(node, encoding="utf-8")
    try:
        with open(args.out, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        return {"ok": False, "error": "cannot write %s: %s" % (args.out, exc)}
    return {"ok": True, "path": args.out, "bytes": len(data)}


def cmd_delete_credential(gmp, args):
    gmp.delete_credential(args.id, ultimate=True)
    return {"ok": True, "id": args.id}


# --------------------------------------------------------------------------
#  the whole Stage 3A lifecycle, in one connection
# --------------------------------------------------------------------------
def note(message):
    """Progress to stderr, so stdout stays a single parseable JSON object."""
    sys.stderr.write("%s\n" % message)
    sys.stderr.flush()


def resolve_named(gmp, kind, name, fallback_id, label):
    """Prefer the id gvmd actually holds for this name; fall back to the UUID.

    The stock UUIDs are right on most installs but a partial GVMD data feed
    leaves a different set, and a create_task against an id this gvmd does not
    have fails only after the credential and target already exist.
    """
    items = listing(gmp, kind)
    wanted = (name or "").strip().lower()
    for item in items:
        if (item["name"] or "").strip().lower() == wanted:
            if fallback_id and item["id"] != fallback_id:
                note("    %s %r resolved to %s" % (label, name, item["id"]))
            return item["id"], items
    return None, items


def cmd_scan(gmp, args):
    """Create, run, poll and export a Greenbone task, then clean up.

    Everything the shell did across fifteen gvm-cli invocations -- each one
    re-authenticating, each one parsed with sed -- happens here on one
    connection. Credentials are deleted in a finally block so an aborted scan
    does not leave the client's domain password sitting in gvmd.
    """
    import time

    hosts = read_lines(args.hosts_file)
    if not hosts:
        return {"ok": False, "error": "no hosts in %s" % args.hosts_file}

    version = text_of(gmp.get_version(), "version")
    note("    GMP %s authenticated" % version)

    # Scan config, scanner and report formats, all resolved by name.
    config_id, configs = resolve_named(gmp, "configs", args.config_name,
                                       args.config_id, "scan config")
    if config_id is None:
        if not args.config_id or not any(c["id"] == args.config_id for c in configs):
            return {"ok": False,
                    "error": "scan config %r is not present on this gvmd"
                             % args.config_name,
                    "available": sorted({c["name"] for c in configs if c["name"]}),
                    "hint": "sync the GVMD data feed, then re-run: "
                            "sudo greenbone-feed-sync --type gvmd-data "
                            "&& sudo systemctl restart gvmd"}
        config_id = args.config_id

    scanner_id = args.scanner_id
    for item in listing(gmp, "scanners"):
        if (item["name"] or "").strip().lower().startswith("openvas"):
            scanner_id = item["id"]
            break

    formats = listing(gmp, "formats")
    def format_id(name, fallback):
        for item in formats:
            if (item["name"] or "").strip().lower() == name.strip().lower():
                return item["id"]
        return fallback
    csv_format = format_id("CSV Results", args.csv_format_id)
    xml_format = format_id("XML", args.xml_format_id)

    from gvm.protocols.gmp.requests.v224 import CredentialType

    smb_cred = ssh_cred = task = report = target = None
    try:
        smb_cred = gmp.create_credential(
            name="kameki-smb-%s" % args.run_name,
            credential_type=CredentialType.USERNAME_PASSWORD,
            login=read_secret(args.smb_login_file),
            password=read_secret(args.smb_pass_file),
            allow_insecure=True,
        ).get("id")
        if not smb_cred:
            return {"ok": False, "error": "gvmd refused the SMB credential"}

        if args.ssh_login_file and args.ssh_pass_file:
            ssh_cred = gmp.create_credential(
                name="kameki-ssh-%s" % args.run_name,
                credential_type=CredentialType.USERNAME_PASSWORD,
                login=read_secret(args.ssh_login_file),
                password=read_secret(args.ssh_pass_file),
                allow_insecure=True,
            ).get("id")

        target_kwargs = {"hosts": hosts, "smb_credential_id": smb_cred}
        if ssh_cred:
            target_kwargs["ssh_credential_id"] = ssh_cred
            target_kwargs["ssh_credential_port"] = args.ssh_port
        if args.alive_test:
            alive = alive_test_for(args.alive_test)
            if alive is not None:
                target_kwargs["alive_test"] = alive
            else:
                note("    unknown alive test %r, using the gvmd default"
                     % args.alive_test)
        target = gmp.create_target(
            name="kameki-target-%s" % args.run_name, **target_kwargs).get("id")
        if not target:
            return {"ok": False, "error": "gvmd refused the target"}

        task = gmp.create_task(
            name=args.run_name,
            config_id=config_id,
            target_id=target,
            scanner_id=scanner_id,
            preferences={"max_checks": str(args.max_checks),
                         "max_hosts": str(args.max_hosts)},
        ).get("id")
        if not task:
            return {"ok": False, "error": "gvmd refused the task"}

        report = text_of(gmp.start_task(task), "report_id")
        if not report:
            return {"ok": False, "error": "the task was created but would not "
                                          "start", "task": task}

        if args.ids_out:
            try:
                with open(args.ids_out, "w", encoding="utf-8") as handle:
                    handle.write("task=%s target=%s report=%s\n"
                                 % (task, target, report))
            except OSError:
                pass
        note("    task %s   report %s" % (task, report))
        note("    polling every %ss" % args.poll)

        status, progress, started = "", 0, time.time()
        last = -1
        while True:
            response = gmp.get_task(task)
            node = response.find("task")
            if node is None:
                status = ""
                break
            status = text_of(node, "status") or ""
            raw = text_of(node, "progress") or "0"
            progress = int(raw) if raw.lstrip("-").isdigit() else 0
            if status in ("Done", "Stopped", "Interrupted"):
                break
            if args.max_minutes and (time.time() - started) / 60.0 > args.max_minutes:
                note("    giving up on the poll after %s minutes, exporting "
                     "what the scan has" % args.max_minutes)
                break
            if progress != last:
                note("    %-12s %3s%%   %d min elapsed"
                     % (status, progress, (time.time() - started) / 60))
                last = progress
            time.sleep(args.poll)

        if not status:
            return {"ok": False, "task": task, "report": report,
                    "error": "gvmd returned no status for this task",
                    "hint": "the task may have been removed, or gvmd restarted "
                            "mid-scan. check: journalctl -u gvmd --since "
                            "'1 hour ago'"}

        wrote = {}
        for label, path, fmt in (("csv", args.csv_out, csv_format),
                                 ("xml", args.xml_out, xml_format)):
            if not path:
                continue
            exported = cmd_get_report(gmp, argparse.Namespace(
                report=report, format=fmt, out=path,
                filter=args.filter))
            wrote[label] = exported.get("bytes", 0) if exported.get("ok") else 0
            if not exported.get("ok"):
                note("    the %s export failed: %s"
                     % (label, exported.get("error")))

        return {"ok": True, "status": status, "progress": progress,
                "task": task, "target": target, "report": report,
                "config": config_id, "scanner": scanner_id,
                "hosts": len(hosts), "wrote": wrote}
    finally:
        for cid in (smb_cred, ssh_cred):
            if not cid:
                continue
            try:
                gmp.delete_credential(cid, ultimate=True)
            except Exception as exc:               # noqa: BLE001
                note("    could not remove credential %s from gvmd: %s"
                     % (cid, exc))
        if smb_cred or ssh_cred:
            note("    scan credentials removed from gvmd")


# --------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--socket", default="/run/gvmd/gvmd.sock")
    parser.add_argument("--user-file", required=True)
    parser.add_argument("--pass-file", required=True)
    parser.add_argument("--timeout", type=float, default=600.0)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check")

    p = sub.add_parser("list")
    p.add_argument("--kind", choices=sorted(KINDS), required=True)

    p = sub.add_parser("resolve")
    p.add_argument("--kind", choices=sorted(KINDS), required=True)
    p.add_argument("--name", required=True)

    p = sub.add_parser("create-credential")
    p.add_argument("--name", required=True)
    p.add_argument("--login-file", required=True)
    p.add_argument("--cred-pass-file", required=True)

    p = sub.add_parser("create-target")
    p.add_argument("--name", required=True)
    p.add_argument("--hosts-file", required=True)
    p.add_argument("--alive-test", default=None)
    p.add_argument("--smb-credential", default=None)
    p.add_argument("--ssh-credential", default=None)
    p.add_argument("--ssh-port", type=int, default=22)

    p = sub.add_parser("create-task")
    p.add_argument("--name", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--scanner", required=True)

    p = sub.add_parser("start-task")
    p.add_argument("--task", required=True)

    p = sub.add_parser("task-status")
    p.add_argument("--task", required=True)

    p = sub.add_parser("get-report")
    p.add_argument("--report", required=True)
    p.add_argument("--format", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--filter", default="levels=hmlg rows=-1")

    p = sub.add_parser("delete-credential")
    p.add_argument("--id", required=True)

    p = sub.add_parser("scan")
    p.add_argument("--run-name", required=True)
    p.add_argument("--hosts-file", required=True)
    p.add_argument("--config-name", required=True)
    p.add_argument("--config-id", default="")
    p.add_argument("--scanner-id", default="08b69003-5fc2-4037-a479-93b440211c73")
    p.add_argument("--csv-format-id", default="c1645568-627a-11e3-a660-406186ea4fc5")
    p.add_argument("--xml-format-id", default="a994b278-1f62-11e1-96ac-406186ea4fc5")
    p.add_argument("--alive-test", default=None)
    p.add_argument("--smb-login-file", required=True)
    p.add_argument("--smb-pass-file", required=True)
    p.add_argument("--ssh-login-file", default=None)
    p.add_argument("--ssh-pass-file", default=None)
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--max-checks", type=int, default=5)
    p.add_argument("--max-hosts", type=int, default=20)
    p.add_argument("--poll", type=float, default=30.0)
    p.add_argument("--max-minutes", type=float, default=0.0,
                   help="stop polling and export partial results after this "
                        "long; 0 means wait as long as the scan takes")
    p.add_argument("--csv-out", default=None)
    p.add_argument("--xml-out", default=None)
    p.add_argument("--ids-out", default=None)
    p.add_argument("--filter", default="levels=hmlg rows=-1")
    return parser


HANDLERS = {
    "check": cmd_check,
    "list": cmd_list,
    "resolve": cmd_resolve,
    "create-credential": cmd_create_credential,
    "create-target": cmd_create_target,
    "create-task": cmd_create_task,
    "start-task": cmd_start_task,
    "task-status": cmd_task_status,
    "get-report": cmd_get_report,
    "delete-credential": cmd_delete_credential,
    "scan": cmd_scan,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    session, gmp = connect(args)
    try:
        result = HANDLERS[args.command](gmp, args)
    except Exception as exc:                       # noqa: BLE001
        fail("%s: %s" % (type(exc).__name__, exc))
    finally:
        try:
            session.__exit__(None, None, None)
        except Exception:                          # noqa: BLE001
            pass
    emit(result, EXIT_OK if result.get("ok") else EXIT_FAIL)


if __name__ == "__main__":
    main()
