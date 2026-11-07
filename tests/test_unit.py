"""Fast tests - no container needed.  Run: python3 -m unittest discover -s tests"""
import base64
import os
import ssl
import socket
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cea", "sandbox"))

from cea import dynamic, report, static_scan, trace_parse  # noqa: E402
from cea.target import TargetError, parse_target  # noqa: E402
from cea.util import Finding, clean  # noqa: E402
import sinkhole  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")


class TargetTests(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(parse_target("left-pad").kind, "npm")
        self.assertEqual(parse_target("@scope/pkg@1.2.3").kind, "npm")
        self.assertEqual(parse_target("npm:lodash@4").spec, "lodash@4")
        self.assertEqual(parse_target("pypi:requests==2.32.0").kind, "pypi")
        self.assertEqual(parse_target("requests==2.32.0").kind, "pypi")
        t = parse_target("github:owner/repo#v1")
        self.assertEqual((t.kind, t.spec, t.ref), ("git", "https://github.com/owner/repo", "v1"))
        self.assertEqual(parse_target("owner/repo").kind, "git")
        self.assertEqual(parse_target("https://example.com/install.sh").kind, "url")
        self.assertEqual(parse_target(os.path.join(FIX, "evil-npm")).kind, "dir")
        self.assertEqual(parse_target(os.path.join(FIX, "evil-install.sh")).kind, "script")

    def test_dangerous_git_transports_refused(self):
        for bad in ("ext::sh -c touch% /tmp/pwned", "git@github.com:a/b.git", "git:ext::sh"):
            with self.assertRaises(TargetError, msg=bad):
                parse_target(bad)


class CleanTests(unittest.TestCase):
    def test_strips_terminal_escapes_and_backticks(self):
        out = clean("\x1b[31mred\x1b[0m `rm -rf` ‮evil")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("`", out)
        self.assertNotIn("‮", out)


class TraceTests(unittest.TestCase):
    LOG = [
        '100 execve("/usr/bin/node", ["node", "setup.js"], 0x7ffd /* 9 vars */) = 0\n',
        '100 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f, stack_size=0x9000}, 88) = 101\n',
        '101 execve("/bin/sh", ["/bin/sh", "-c", "curl http://x.invalid"] <unfinished ...>\n',
        '100 openat(AT_FDCWD, "/home/dev/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 23\n',
        '101 <... execve resumed>, 0x5600 /* 9 vars */) = 0\n',
        '101 execve("/usr/local/bin/curl", ["curl"], 0x1 /* 1 vars */) = -1 ENOENT (No such file or directory)\n',
        '100 connect(24, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH (Network is unreachable)\n',
        '100 openat(AT_FDCWD, "/home/dev/.bashrc", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0666) = 25\n',
        '100 openat(AT_FDCWD, "a\\303\\251\\n", O_RDONLY) = 3\n',
    ]

    def test_parse(self):
        ev = trace_parse.parse(self.LOG, step="install")
        argvs = [p["argv"] for p in ev["processes"]]
        self.assertIn(["node", "setup.js"], argvs)
        self.assertIn(["/bin/sh", "-c", "curl http://x.invalid"], argvs)
        sh = [p for p in ev["processes"] if p["pid"] == 101][0]
        self.assertEqual(sh["ppid"], 100)
        self.assertEqual(sh["parent_argv"], ["node", "setup.js"])
        self.assertIn("curl", ev["failed_exec"])
        self.assertEqual(ev["connects"][0]["addr"], "1.2.3.4")
        self.assertEqual(ev["connects"][0]["port"], 443)
        w = [o for o in ev["opens"] if o["write"]]
        self.assertEqual(w[0]["path"], "/home/dev/.bashrc")
        self.assertTrue(any(o["path"] == "aé\n" for o in ev["opens"]))


class SinkholeTests(unittest.TestCase):
    def test_dns_reply(self):
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x04evil\x07example\x00" + b"\x00\x01\x00\x01"
        name, qtype, reply = sinkhole.dns_reply(q)
        self.assertEqual((name, qtype), ("evil.example", 1))
        self.assertEqual(reply[:2], b"\x12\x34")
        self.assertEqual(reply[-4:], socket.inet_aton("127.0.0.1"))

    def test_sni(self):
        ctx = ssl.create_default_context()
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname="exfil.example.org")
        with self.assertRaises(ssl.SSLWantReadError):
            obj.do_handshake()
        self.assertEqual(sinkhole.parse_sni(out.read()), "exfil.example.org")


class LeakTests(unittest.TestCase):
    def test_encoded_forms(self):
        c = dynamic.make_canaries()
        tok = c["GITHUB_TOKEN"]
        blob_b64 = base64.b64encode(('{"x":1,"t":"%s"}' % tok).encode()).decode()
        blob_hex = tok.encode().hex()[:40] + ".dns.example"
        leaks = dynamic.find_leaks(c, [("http", blob_b64), ("dns", blob_hex), ("clean", "nothing here")])
        where = {(n, w) for n, w, _ in leaks}
        self.assertIn(("GITHUB_TOKEN", "http"), where)
        self.assertIn(("GITHUB_TOKEN", "dns"), where)
        self.assertFalse(any(w == "clean" for _, w, _ in leaks))

    def test_honey_paths_consistent(self):
        files = dynamic.honey_files(dynamic.make_canaries())
        self.assertEqual(set(files), set(dynamic.HONEY_RELS))


class StaticTests(unittest.TestCase):
    def test_evil_fixture(self):
        f, stats = static_scan.scan(os.path.join(FIX, "evil-npm"))
        rules = {x.rule for x in f}
        self.assertIn("lifecycle-script", rules)
        self.assertIn("env-dump", rules)
        self.assertIn("persistence", rules)
        self.assertEqual(stats["install_files"], ["scripts/setup.js"])
        self.assertTrue(all(x.context == "install" for x in f if x.file == "scripts/setup.js"))

    def test_benign_fixture(self):
        f, _ = static_scan.scan(os.path.join(FIX, "benign-npm"))
        self.assertFalse([x for x in f if x.severity in ("medium", "high", "critical")])


class VerdictTests(unittest.TestCase):
    def F(self, sev, source="dynamic", rule="x", context="install"):
        return Finding(rule, sev, "t", source, context=context)

    def test_levels(self):
        self.assertEqual(report.verdict([], True, True), "LIKELY_SAFE")
        self.assertEqual(report.verdict([], False, True), "INCOMPLETE")
        self.assertEqual(report.verdict([self.F("critical")], True, True), "MALICIOUS")
        self.assertEqual(report.verdict([self.F("high")], True, True), "UNSAFE")
        self.assertEqual(report.verdict([self.F("high", "static", "sensitive-path", "runtime")], True, True), "REVIEW")
        self.assertEqual(report.verdict([self.F("high", "static", "obfuscator", "runtime")], True, True), "UNSAFE")
        # capabilities alone + clean sandbox run -> safe
        self.assertEqual(report.verdict([self.F("medium", "static", "child-process")], True, True), "LIKELY_SAFE")
        self.assertEqual(report.verdict([self.F("medium", "static", "child-process"), self.F("medium")], True, True), "REVIEW")


if __name__ == "__main__":
    unittest.main()
