#!/usr/bin/env python3
"""kameki_gmp.py against a fake gvmd on a real Unix socket.

The stub-based suite (gmp-client.py) replaces the whole `gvm` module, so it
proves the parsing and the control flow but says nothing about whether the
connection code is right. This file uses the REAL python-gvm: a socket, the
version negotiation GMP() does on entry, EtreeTransform, the lot. If
python-gvm changes the shape of GMP() or of UnixSocketConnection, this is what
notices.

Skipped with a clear message when python-gvm is not installed.

    ./tests/gmp-live.py
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

try:
    import gvm  # noqa: F401
except ImportError:
    print("SKIP  python-gvm is not installed, so the live transport is untested")
    print("      install it with: pip3 install python-gvm")
    sys.exit(0)

CONFIGS = (
    '<get_configs_response status="200" status_text="OK">'
    '<config id="d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663"><owner><name>admin</name>'
    '</owner><name>Base</name></config>'
    '<config id="2d3f051c-55ba-11e3-bf43-406186ea4fc5"><owner><name>admin</name>'
    '</owner><name>Full and fast ultimate</name></config>'
    '<config id="daba56c8-73ec-11df-a475-002264764cea"><owner><name>admin</name>'
    '</owner><name>Full and fast</name></config>'
    '</get_configs_response>')


def reply_for(request):
    """The smallest GMP response that keeps python-gvm happy."""
    if "<get_version" in request:
        return ('<get_version_response status="200" status_text="OK">'
                '<version>22.5</version></get_version_response>')
    if "<authenticate" in request:
        if "wrongpass" in request:
            return ('<authenticate_response status="400" '
                    'status_text="Authentication failed"/>')
        return ('<authenticate_response status="200" status_text="OK">'
                '<role>Admin</role></authenticate_response>')
    if "<get_configs" in request:
        return CONFIGS
    return '<generic_response status="200" status_text="OK"/>'


def complete(buf):
    """True once buf holds a whole XML document, the way gvmd frames them."""
    from xml.etree import ElementTree
    try:
        ElementTree.fromstring(buf)
        return True
    except ElementTree.ParseError:
        return False


def serve(path, stop):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(8)
    srv.settimeout(0.4)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=session, args=(conn,), daemon=True).start()
    srv.close()


def session(conn):
    conn.settimeout(10)
    buf = ""
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk.decode("utf-8", "replace")
            while buf.strip() and complete(buf.strip()):
                conn.sendall(reply_for(buf).encode("utf-8"))
                buf = ""
                break
    except (OSError, socket.timeout):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


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
    uf = os.path.join(tmp, "u")
    pf = os.path.join(tmp, "p")
    bad = os.path.join(tmp, "bad")
    open(uf, "w").write("kameki-admin\n")
    open(pf, "w").write("rightpass\n")
    open(bad, "w").write("wrongpass\n")

    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(sock, stop), daemon=True)
    thread.start()
    for _ in range(100):
        if os.path.exists(sock):
            break
        import time
        time.sleep(0.02)

    def run(args, passfile=pf):
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "kameki_gmp.py"),
             "--socket", sock, "--user-file", uf, "--pass-file", passfile,
             "--timeout", "10"] + args,
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        try:
            return json.loads(proc.stdout or "{}"), proc.returncode, proc.stderr
        except ValueError:
            return {"_raw": proc.stdout, "_err": proc.stderr}, proc.returncode, proc.stderr

    try:
        print("the real python-gvm transport, over a real unix socket")
        out, code, _ = run(["check"])
        check("check exits 0", code, 0)
        check("gvmd's version is read", out.get("version"), "22.5")

        out, code, _ = run(["list", "--kind", "configs"])
        check("list exits 0", code, 0)
        check("three configs parsed off the wire",
              [i["name"] for i in out.get("items", [])],
              ["Base", "Full and fast ultimate", "Full and fast"])
        check("the owner's name is not among them",
              "admin" in [i["name"] for i in out.get("items", [])], False)

        out, code, _ = run(["resolve", "--kind", "configs",
                            "--name", "Full and fast"])
        check("resolve returns the exact match, not the longer name",
              out.get("id"), "daba56c8-73ec-11df-a475-002264764cea")

        out, code, _ = run(["check"], passfile=bad)
        check("a refused password exits non-zero", code, 1)
        check("and is reported as an authentication failure",
              "authentication failed" in out.get("error", "").lower(), True)

        out, code, _ = run(["--socket", os.path.join(tmp, "gone.sock"), "check"]
                           if False else ["check"])
        print("\na socket that is not there")
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "kameki_gmp.py"),
             "--socket", os.path.join(tmp, "gone.sock"),
             "--user-file", uf, "--pass-file", pf, "check"],
            capture_output=True, text=True, timeout=60)
        payload = json.loads(proc.stdout or "{}")
        check("exits non-zero", proc.returncode, 1)
        check("names the path", "gone.sock" in payload.get("error", ""), True)
    finally:
        stop.set()
        thread.join(timeout=3)

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
