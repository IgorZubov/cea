"""Fast tests - no container needed.  Run: python3 -m unittest discover -s tests"""
import base64
import gzip
import io
import json
import os
import tarfile
import tempfile
import types
import zipfile
import ssl
import socket
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cea", "sandbox"))

from cea import cli, dynamic, report, sandbox, static_scan, trace_parse  # noqa: E402
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


# ----------------------------------------------------------------- issue #1: coverage / per-package steps
def _args(**kw):
    a = dict(timeout=100, wait=1, no_import=False, no_bin=False, no_build=False, run=None)
    a.update(kw)
    return types.SimpleNamespace(**a)


def _work(pkg_json, files=()):
    work = tempfile.mkdtemp()
    os.makedirs(os.path.join(work, "src"))
    json.dump(pkg_json, open(os.path.join(work, "src", "package.json"), "w"))
    for f in files:
        path = os.path.join(work, "src", f)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write("console.log(1)\n")
    return work


DEPS = {"install_script_pkgs": [
    {"name": "ffmpeg-static", "version": "5.3.0", "spec": "ffmpeg-static@5.3.0", "path": "node_modules/ffmpeg-static",
     "repo": "eugeneware/ffmpeg-static"},
    {"name": "esbuild", "version": "0.28.1", "spec": "esbuild@0.28.1", "path": "node_modules/esbuild", "repo": "evanw/esbuild"},
    {"name": "--script-shell=/sandbox/app/x", "version": "1.0.0", "spec": "evil@1", "path": "node_modules/x", "repo": None},
]}


class PlanTests(unittest.TestCase):
    def plan(self, pj, files=(), kind="git", stats=DEPS, **kw):
        t = types.SimpleNamespace(kind=kind, spec="x")
        meta = {"kind": kind, "ecosystems": ["npm"], "name": pj.get("name")}
        return cli.build_plan(t, meta, _work(pj, files), _args(**kw), stats)

    def test_one_install_step_per_dependency(self):
        steps, skipped = self.plan({"name": "app", "scripts": {"postinstall": "node x.js"}, "main": "index.js"}, ["index.js"])
        rebuilds = [s for s in steps if s["cmd"][:2] == ["npm", "rebuild"]]
        self.assertEqual([s["cmd"][-1] for s in rebuilds], ["ffmpeg-static@5.3.0", "esbuild@0.28.1", "."])
        self.assertEqual(rebuilds[0]["package"], "ffmpeg-static@5.3.0")
        self.assertEqual(rebuilds[0]["package_repo"], "eugeneware/ffmpeg-static")
        # an option-looking package name never reaches npm's argv
        self.assertFalse(any("--script-shell" in " ".join(s["cmd"]) for s in steps))
        self.assertTrue(any("valid npm name" in why for _, why in skipped))
        # the project's own install hook runs as its own (unattributed) step
        root = [s for s in steps if s["name"] == "project install scripts"][0]
        self.assertEqual(root["cmd"][-1], ".")
        self.assertNotIn("package", root)

    def test_bin_only_package_runs_bin_and_builds_missing_output(self):
        pj = {"name": "yoinks", "bin": {"yoinks": "dist/cli.js"}, "scripts": {"build": "tsup"}}
        steps, skipped = self.plan(pj, stats={})
        names = [s["name"] for s in steps]
        self.assertEqual(names, ["npm run build", "run bin yoinks --help"])
        self.assertEqual(steps[1]["cmd"][-2:], ["/sandbox/app/dist/cli.js", "--help"])
        self.assertTrue(any(w == "import" and "only declares a bin" in why for w, why in skipped))

    def test_missing_output_without_build_script_is_reported(self):
        steps, skipped = self.plan({"name": "t", "bin": "dist/cli.js"}, stats={})
        self.assertTrue(any(w == "build" and "no `build` script" in why for w, why in skipped))
        self.assertEqual(steps[-1]["name"], "run bin t --help")

    def test_bin_flags_and_escapes(self):
        steps, skipped = self.plan({"name": "t", "bin": "cli.js"}, ["cli.js"], stats={}, run="t --version")
        self.assertEqual([s["name"] for s in steps], ["user command"])
        steps, skipped = self.plan({"name": "t", "bin": "../../etc/x"}, stats={})
        self.assertFalse([s for s in steps if s["phase"] == "run"])
        self.assertTrue(any("escapes" in why for _, why in skipped))

    def test_registry_package(self):
        steps, _ = self.plan({"name": "left-pad", "bin": {"lp": "bin/lp.js"}}, ["bin/lp.js"], kind="npm", stats={})
        self.assertEqual([s["name"] for s in steps], ["install scripts: left-pad", "import left-pad", "run bin lp --help"])
        self.assertEqual(steps[-1]["cmd"][-2], "/sandbox/app/node_modules/left-pad/bin/lp.js")


# ------------------------------------------------------- issue #2: attribution / own-binary downloads
def _raw(steps, net):
    raw = tempfile.mkdtemp()
    t = 1000.0
    out = []
    for i, (name, phase, rc) in enumerate(steps):
        out.append({"index": i, "attempt": 0, "name": name, "phase": phase, "cmd": ["x"], "rc": rc,
                    "timed_out": False, "start": t + i * 10, "end": t + i * 10 + 9, "output": "line\nboom", "trace": None})
    json.dump({"steps": out}, open(os.path.join(raw, "steps.json"), "w"))
    with open(os.path.join(raw, "net.jsonl"), "w") as fh:
        for step, ev in net:
            ev = dict(ev, t=t + step * 10 + 1)
            for k in ("raw", "body"):
                ev[k] = base64.b64encode(ev.get(k, "").encode()).decode()
            fh.write(json.dumps(ev) + "\n")
    return raw


def GET(host, path, method="GET", body=""):
    return {"type": "http", "tls": True, "method": method, "host": host, "path": path, "headers": {},
            "raw": f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n", "body": body}


PLAN = [{"name": "install scripts: ffmpeg-static@5.3.0", "phase": "install", "package": "ffmpeg-static@5.3.0",
         "package_path": "node_modules/ffmpeg-static", "package_repo": "eugeneware/ffmpeg-static"},
        {"name": "project lifecycle scripts", "phase": "install"}]
REL = "/eugeneware/ffmpeg-static/releases/download/b6.1.1/ffmpeg-linux-arm64.gz"


class AttributionTests(unittest.TestCase):
    def run_case(self, net, rcs=(0, 0)):
        raw = _raw([(p["name"], p["phase"], rc) for p, rc in zip(PLAN, rcs)], net)
        f, beh = dynamic.analyse(raw, dynamic.make_canaries(), PLAN)
        return f, beh, dynamic.coverage(PLAN, beh, [], True)

    def test_own_release_download_is_attributed_and_downgraded(self):
        f, beh, cov = self.run_case([(0, {"type": "dns", "name": "github.com"}), (0, GET("github.com", REL))])
        dl = [x for x in f if x.rule == "dep-binary-download"][0]
        self.assertEqual((dl.severity, dl.package, dl.file, dl.context),
                         ("low", "ffmpeg-static@5.3.0", "node_modules/ffmpeg-static", "dependency-install"))
        self.assertEqual([x.severity for x in f if x.rule == "dns"], ["info"])
        self.assertEqual(report.verdict(f, True, True, cov), "LIKELY_SAFE")
        self.assertFalse(cov["partial"])

    def test_target_requests_stay_high(self):
        f, _, _ = self.run_case([(1, GET("github.com", REL))])   # same URL, but from the target's own script
        x = [x for x in f if x.rule == "http"][0]
        self.assertEqual((x.severity, x.package, x.context), ("high", "", "install"))

    def test_suspicious_dependency_requests_are_not_downgraded(self):
        cases = {
            "other repo's releases": GET("github.com", "/attacker/tools/releases/download/v1/x.gz"),
            "POST with a body": GET("github.com", REL, method="POST", body="hello"),
            "query string": GET("github.com", REL + "?d=aGVsbG8"),
            "unknown host": GET("evil.example", REL),
        }
        for label, ev in cases.items():
            f, _, cov = self.run_case([(0, {"type": "dns", "name": ev["host"]}), (0, ev)])
            sev = {x.severity for x in f if x.rule in ("http", "dep-artifact-download", "dep-binary-download")}
            self.assertTrue(sev & {"medium", "high"}, label)
            self.assertNotEqual(report.verdict(f, True, True, cov), "LIKELY_SAFE", label)
            self.assertTrue(all(x.package == "ffmpeg-static@5.3.0" for x in f if x.source == "dynamic"), label)

    def test_leaking_download_is_not_downgraded(self):
        c = dynamic.make_canaries()
        raw = _raw([(p["name"], p["phase"], 0) for p in PLAN], [(0, GET("github.com", REL + "/" + c["GITHUB_TOKEN"]))])
        f, _ = dynamic.analyse(raw, c, PLAN)
        self.assertFalse([x for x in f if x.rule == "dep-binary-download"])
        leak = [x for x in f if x.rule == "canary-leak"][0]
        self.assertEqual((leak.severity, leak.package), ("critical", "ffmpeg-static@5.3.0"))
        self.assertEqual(report.verdict(f, True, True), "MALICIOUS")

    def test_failed_step_is_reported_and_marks_partial(self):
        f, beh, cov = self.run_case([], rcs=(1, 0))
        failed = [x for x in f if x.rule == "step-failed"][0]
        self.assertEqual((failed.severity, failed.package, failed.evidence), ("info", "ffmpeg-static@5.3.0", "boom"))
        self.assertTrue(cov["partial"])
        self.assertIn("ffmpeg-static", cov["summary"])
        self.assertEqual([p["status"] for p in cov["planned"]], ["failed", "ok"])
        _, _, cov = self.run_case([], rcs=(1, 1))
        self.assertEqual(report.verdict([], True, True, cov), "INCOMPLETE")   # nothing ran successfully

    def test_known_downloader(self):
        n = {"package": "puppeteer@23.0.0", "method": "GET", "body_bytes": 0, "host": "storage.googleapis.com",
             "path": "/chrome-for-testing-public/131.0/linux64/chrome-linux64.zip", "package_repo": "puppeteer/puppeteer"}
        self.assertEqual(dynamic.classify_download(n, False)[0], "low")
        self.assertEqual(dynamic.classify_download(dict(n, package="leftpad@1.0.0"), False)[0], "medium")


class ScoreTests(unittest.TestCase):
    def test_dependency_capabilities_scored_separately(self):
        dep = [Finding("child-process", "medium", "t", "static", context="dependency-install", package="esbuild@1")] * 11
        own = [Finding("network-code", "low", "t", "static", context="runtime")] * 2
        self.assertEqual(report.score(dep + own, dynamic_ran=True), 2)
        self.assertEqual(report.dependency_score(dep + own), 55)
        # without a clean sandbox run, everything counts
        self.assertEqual(report.score(dep + own, dynamic_ran=False), 57)
        bad = Finding("http", "high", "t", "dynamic", context="dependency-install", package="evil@1")
        self.assertEqual(report.score(dep + own + [bad], dynamic_ran=True), 77)

    def test_static_dep_findings_carry_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            nm = os.path.join(tmp, "node_modules")
            d = os.path.join(nm, "ffmpeg-static")
            os.makedirs(d)
            json.dump({"name": "ffmpeg-static", "version": "5.3.0", "scripts": {"install": "node install.js"},
                       "repository": {"url": "git+https://github.com/eugeneware/ffmpeg-static.git"}},
                      open(os.path.join(d, "package.json"), "w"))
            open(os.path.join(d, "install.js"), "w").write("require('child_process').execSync('x')\n")
            findings = []
            n, specs, pkgs = static_scan.scan_npm_deps(nm, findings)
            self.assertEqual(specs, ["ffmpeg-static@5.3.0"])
            self.assertEqual(pkgs[0]["repo"], "eugeneware/ffmpeg-static")
            self.assertTrue(findings and all(f.package == "ffmpeg-static@5.3.0" for f in findings))

    def test_github_repo_forms(self):
        for v in ("github:a/b", "a/b", "https://github.com/a/b.git", {"url": "git+ssh://git@github.com/a/b.git"},
                  "https://github.com/A/B/tree/main"):
            self.assertEqual(static_scan.github_repo({"repository": v}), "a/b", v)
        self.assertIsNone(static_scan.github_repo({"repository": "https://gitlab.com/a/b"}))


class FakeBodyTests(unittest.TestCase):
    def test_archives_are_valid(self):
        self.assertEqual(gzip.decompress(sinkhole.fake_body(REL)[1]), b"")
        self.assertEqual(tarfile.open(fileobj=io.BytesIO(sinkhole.fake_body("/x.tar.gz?y=1")[1])).getmembers(), [])
        self.assertEqual(zipfile.ZipFile(io.BytesIO(sinkhole.fake_body("/a/b.ZIP")[1])).namelist(), [])
        self.assertEqual(sinkhole.fake_body("/x.json"), ("text/plain", b""))
        r = sinkhole.http_response("HEAD", "/x.zip")
        self.assertTrue(r.endswith(b"\r\n\r\n") and b"Content-Length: 22" in r)


# ------------------------------------------------------------- issue #3: next steps instead of symptoms
MAC_ERR = ("failed to connect to the docker API at unix:///Users/u/.docker/run/docker.sock; check if the path is "
           "correct and if the daemon is running: dial unix /Users/u/.docker/run/docker.sock: connect: no such file or directory")


class HintTests(unittest.TestCase):
    def test_engine_hints(self):
        app = lambda p: p == "/Applications/Docker.app"
        self.assertIn("open -a Docker", sandbox.engine_hint("docker", MAC_ERR, "darwin", exists=app, which=lambda _: None))
        self.assertIn("colima start", sandbox.engine_hint("docker", MAC_ERR, "darwin", exists=lambda _: False,
                                                          which=lambda n: "/x" if n == "colima" else None))
        self.assertIn("systemctl start docker", sandbox.engine_hint("docker", MAC_ERR, "linux",
                                                                     exists=lambda p: p == "/run/systemd/system"))
        self.assertIn("dockerd", sandbox.engine_hint("docker", MAC_ERR, "linux", exists=lambda _: False))
        self.assertIn("podman machine start", sandbox.engine_hint("podman", "Cannot connect to Podman", "darwin"))
        self.assertIn("docker` group", sandbox.engine_hint("docker", "permission denied while trying to connect", "linux"))
        self.assertIsNone(sandbox.engine_hint("docker", "something else entirely", "linux"))

    def test_start_commands(self):
        self.assertEqual(sandbox.start_command("docker", "darwin", exists=lambda p: "OrbStack" in p, which=lambda _: None),
                         ["open", "-a", "OrbStack"])
        self.assertEqual(sandbox.start_command("podman", "darwin"), ["podman", "machine", "start"])
        self.assertEqual(sandbox.start_command("docker", "linux", exists=lambda _: False, which=lambda _: "/x",
                                               is_root=True), ["dockerd"])
        self.assertIsNone(sandbox.start_command("docker", "linux", exists=lambda _: True, is_root=False))

    def test_build_hints(self):
        proxy = ('ERROR: failed to resolve source metadata for docker.io/library/node:22-bookworm-slim: Head '
                 '"https://registry-1.docker.io/v2/library/node/manifests/22-bookworm-slim": Forbidden '
                 '(agent proxy: no rule or network setting allows this host)')
        h = sandbox.build_hint(proxy)
        self.assertIn("registry-1.docker.io", h)
        self.assertIn("cea image import", h)
        self.assertNotIn("rate-limit", h)
        limited = ("unexpected status from HEAD request to https://registry-1.docker.io/v2/library/ubuntu/manifests/24.04: "
                   "429 Too Many Requests")
        self.assertIn("mirror.gcr.io", sandbox.build_hint(limited))
        self.assertIn("no network", sandbox.build_hint("dial tcp: lookup registry-1.docker.io: no such host"))
        # build timings like "#5 0.403" must not look like an HTTP 403
        self.assertIsNone(sandbox.build_hint("#5 0.403 Reading package lists...\nE: Unable to locate package strace"))


if __name__ == "__main__":
    unittest.main()
