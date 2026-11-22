"""cea - ChEck Anything. Run untrusted code in a throw-away sandbox and report
what it does: processes, network, files, secrets."""
import argparse
import io
import json
import os
import shutil
import sys
import tarfile
import time

from . import __version__, dynamic, report, static_scan
from .sandbox import BUILD_NEEDS, REGISTRY_REPO, Engine, SandboxError, image_tag
from .target import TargetError, parse_target
from .util import Finding, clean

NODE_IMPORT = r"""
const t = process.argv[1], w = Number(process.argv[2] || 5);
const { pathToFileURL } = require('url');
let u; try { u = pathToFileURL(require.resolve(t, { paths: [process.cwd()] })).href } catch (e) { u = t }
import(u).then(m => console.log('[cea] imported', t, 'exports:', Object.keys(m).slice(0, 25).join(',')))
  .catch(e => console.log('[cea] import failed:', e && e.message))
  .finally(() => setTimeout(() => process.exit(0), w * 1000));
"""

FAIL_LEVELS = {"review": 1, "unsafe": 2, "malicious": 3}


def log(msg, quiet=False):
    if not quiet:
        print(f"\033[2mcea ▸\033[0m {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ planning
# Runs a declared `bin` the way its shebang asks (no chmod/head helpers: they'd show up as findings).
RUN_BIN = r'''f="$1"; shift
if [ ! -f "$f" ]; then echo "[cea] bin not found (not built?): $f"; exit 127; fi
IFS= read -r first < "$f" || true
case "$first" in
  "#!"*) exec ${first#??} "$f" "$@" ;;
  *) if [ -x "$f" ]; then exec "$f" "$@"; else exec node "$f" "$@"; fi ;;
esac'''
APP = "/sandbox/app"


def _bin_entries(pkg_json):
    b = pkg_json.get("bin")
    name = pkg_json.get("name") if isinstance(pkg_json.get("name"), str) else ""
    name = name.rsplit("/", 1)[-1]
    if isinstance(b, str):
        return [(name or "cli", b)]
    if isinstance(b, dict):
        return [(k, v) for k, v in b.items() if isinstance(v, str)]
    return []


def _safe_rel(path):
    """A package-relative path we are willing to pass to the sandbox (no escapes, no options)."""
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        return None
    p = os.path.normpath(path.strip())
    return None if p in (".", "") or p.startswith(("..", "/", "-")) else p


def build_plan(target, meta, work, args, stats=None):
    """Returns (steps, skipped): skipped = [(what, why)] for the report's coverage section."""
    steps, skipped = [], []
    T = args.timeout
    kind = meta.get("kind", target.kind)
    eco = meta.get("ecosystems") or []
    stats = stats or {}
    pkg_json = {}
    pj_path = os.path.join(work, "src", "package.json")
    if os.path.isfile(pj_path):
        try:
            pkg_json = json.load(open(pj_path, errors="replace"))
        except ValueError:
            pass
        if not isinstance(pkg_json, dict):
            pkg_json = {}

    if "npm" in eco:
        registry = kind in ("npm", "npm-tarball")
        name = meta.get("name") if registry else None
        pkg_dir = f"{APP}/node_modules/{name}" if registry and name else APP
        # One step per package: `npm rebuild` stops at the first failing script, which used to hide
        # every later package's behaviour. Separate steps also let findings name the package.
        for d in stats.get("install_script_pkgs", []):
            nm, ver = d.get("name") or "", d.get("version")
            if not static_scan.NPM_NAME_RE.match(nm):
                skipped.append((f"install scripts of {clean(d.get('spec'), 80)}", "package name is not a valid npm name"))
                continue
            spec = f"{nm}@{ver}" if ver and static_scan.NPM_VERSION_RE.match(ver) else nm
            steps.append({"name": f"install scripts: {d.get('spec')}", "phase": "install", "timeout": T,
                          "package": d.get("spec"), "package_path": d.get("path"), "package_repo": d.get("repo"),
                          "cmd": ["npm", "rebuild", "--foreground-scripts", "--no-audit", "--no-fund", spec]})
        sc = pkg_json.get("scripts") if isinstance(pkg_json.get("scripts"), dict) else {}
        if registry:
            if name and static_scan.NPM_NAME_RE.match(name):
                steps.append({"name": f"install scripts: {name}", "phase": "install", "timeout": T,
                              "cmd": ["npm", "rebuild", "--foreground-scripts", "--no-audit", "--no-fund", name]})
        else:
            # a dev's `npm install` in a clone runs the root's install hooks (and node-gyp for a
            # binding.gyp) - `npm rebuild .` does exactly that for the root only - and then `prepare`
            if any(h in sc for h in ("preinstall", "install", "postinstall")) or \
                    os.path.isfile(os.path.join(work, "src", "binding.gyp")):
                steps.append({"name": "project install scripts", "phase": "install", "timeout": T,
                              "cmd": ["npm", "rebuild", "--foreground-scripts", "--no-audit", "--no-fund", "."]})
            hooks = [h for h in ("preprepare", "prepare", "postprepare") if h in sc]
            if hooks:
                steps.append({"name": "project lifecycle scripts", "phase": "install", "timeout": T,
                              "cmd": ["sh", "-c", "; ".join(f"npm run --if-present {h}" for h in hooks)]})

        # entry points that only exist after a build (dist/ is usually not committed)
        entries = [e for e in (pkg_json.get("main"),) if isinstance(e, str)] + [v for _, v in _bin_entries(pkg_json)]
        src_dir = os.path.join(work, "src")
        missing = [e for e in entries if _safe_rel(e) and not os.path.exists(os.path.join(src_dir, _safe_rel(e)))]
        if missing and not registry:
            if "build" in sc and not args.no_build:
                steps.append({"name": "npm run build", "phase": "build", "timeout": T,
                              "cmd": ["npm", "run", "--if-present", "build"]})
            else:
                why = "--no-build" if "build" in sc else "no `build` script"
                skipped.append(("build", f"{', '.join(missing[:3])} missing in the source and {why}; "
                                         "entry points that need it will fail"))

        if args.no_import:
            skipped.append(("import", "--no-import"))
        elif registry and name:
            steps.append({"name": f"import {name}", "phase": "import", "timeout": T,
                          "cmd": ["node", "-e", NODE_IMPORT, name, str(args.wait)]})
        elif not registry and (pkg_json.get("main") or pkg_json.get("exports")
                               or os.path.isfile(os.path.join(work, "src", "index.js"))):
            steps.append({"name": f"import {APP}", "phase": "import", "timeout": T,
                          "cmd": ["node", "-e", NODE_IMPORT, APP, str(args.wait)]})
        else:
            skipped.append(("import", "package has no main/exports/index.js" +
                            (" (it only declares a bin, which is run instead)" if _bin_entries(pkg_json) else "")))

        bins = _bin_entries(pkg_json)
        if bins and args.run:
            skipped.append((f"run bin `{clean(bins[0][0], 40)} --help`", "--run given"))
        elif bins and args.no_bin:
            skipped.append((f"run bin `{clean(bins[0][0], 40)} --help`", "--no-bin"))
        elif bins:
            cmd_name, rel = bins[0]
            rel = _safe_rel(rel)
            if not rel:
                skipped.append((f"run bin `{clean(cmd_name, 40)}`", "bin path escapes the package"))
            else:
                steps.append({"name": f"run bin {cmd_name} --help", "phase": "run", "timeout": min(T, 60),
                              "cmd": ["sh", "-c", RUN_BIN, "sh", f"{pkg_dir}/{rel}", "--help"]})
                for other, _ in bins[1:4]:
                    skipped.append((f"run bin `{clean(other, 40)}`", "only the first bin is run; use --run for others"))

    if "python" in eco:
        steps.append({"name": "create venv", "phase": "setup", "timeout": 120, "traced": False,
                      "cmd": ["python3", "-m", "venv", "--system-site-packages", "/sandbox/venv"]})
        pip = ["/sandbox/venv/bin/python", "-m", "pip", "install", "--no-index", "--find-links", "/work/dist",
               "--no-build-isolation", "--disable-pip-version-check"]
        what = f"/work/dist/{meta['dist_file']}" if meta.get("dist_file") else APP
        steps.append({"name": "pip install", "phase": "install", "timeout": T,
                      "cmd": pip + [what], "fallback": pip + ["--no-deps", what]})
        if not args.no_import:
            steps.append({"name": "import modules", "phase": "import", "timeout": T,
                          "cmd": ["/sandbox/venv/bin/python", "/cea/py_import.py", str(args.wait)]})
        else:
            skipped.append(("import modules", "--no-import"))

    if kind == "script":
        script = meta.get("script") or os.path.basename(target.spec)
        path = f"{APP}/{script}"
        ext = os.path.splitext(script)[1].lower()
        interp = {".sh": ["bash"], ".bash": ["bash"], ".py": ["python3"], ".js": ["node"], ".mjs": ["node"],
                  ".cjs": ["node"], ".ts": ["node", "--experimental-strip-types"]}.get(ext)
        cmd = (interp + [path]) if interp else ["sh", "-c", 'chmod +x "$1" 2>/dev/null; exec "$1"', "sh", path]
        if not args.run:
            steps.append({"name": f"run {script}", "phase": "run", "timeout": T, "cmd": cmd})

    if args.run:
        steps.append({"name": "user command", "phase": "run", "timeout": T, "cmd": ["sh", "-c", args.run]})
    return steps, skipped


# --------------------------------------------------------------------- check
def prepare_local(target, work):
    for d in ("src", "dist", "fetch"):
        os.makedirs(os.path.join(work, d), exist_ok=True)
    p = target.local_path
    if target.kind == "dir":
        shutil.copytree(p, os.path.join(work, "src"), symlinks=True, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("node_modules", ".git", ".venv", "venv", "__pycache__", "cea-reports"))
    elif target.kind == "npm-tarball":
        shutil.copy(p, os.path.join(work, "fetch", "target.tgz"))
    elif target.kind == "py-dist":
        shutil.copy(p, os.path.join(work, "dist", os.path.basename(p)))
    elif target.kind == "script":
        shutil.copy(p, os.path.join(work, "src", os.path.basename(p)))


def host_extract(path, dest):
    """Static-only mode: unpack an archive as plain data (no links, no escapes)."""
    import zipfile
    root = os.path.realpath(dest)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if os.path.realpath(os.path.join(dest, info.filename)).startswith(root + os.sep):
                    zf.extract(info, dest)
        return
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            parts = m.name.split("/")[1:]
            if not parts or not (m.isfile() or m.isdir()):
                continue
            m.name = "/".join(parts)
            try:
                tf.extract(m, dest, filter="data")
            except Exception:
                pass


def safe_untar(data, dest):
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.isfile() and "/" not in m.name and not m.name.startswith("."):
                try:
                    tf.extract(m, dest, filter="data")
                except Exception:
                    pass


def cmd_check(args):
    t0 = time.time()
    q = args.json
    try:
        target = parse_target(args.target, ecosystem="pypi" if args.pypi else ("npm" if args.npm else None))
    except TargetError as e:
        print(f"cea: {e}", file=sys.stderr)
        return 2
    if args.ref:
        target.ref = args.ref

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.abspath(os.path.join(args.out, f"{target.slug}-{stamp}"))
    work = os.path.join(out_dir, "work")
    raw = os.path.join(out_dir, "raw")
    os.makedirs(work, exist_ok=True)
    os.makedirs(raw, exist_ok=True)
    if hasattr(os, "getuid") and os.getuid() == 0:
        os.chmod(work, 0o777)   # container runs as uid 1000 when we are root
    errors, findings, behaviour, meta = [], [], {}, {"kind": target.kind}
    dynamic_ran, fetch_ok = False, False

    log(f"target {target.display} ({target.kind}) → {out_dir}", q)
    engine = None
    if not args.static_only:
        try:
            engine = Engine(args.engine, args.runtime, verbose=args.verbose)
            engine.ping()
            tag = image_tag()
            if not engine.has_image(tag):
                log(f"building sandbox image {tag} (first run only)...", q)
                engine.build(tag, quiet=q)
        except SandboxError as e:
            errors.append(str(e))
            errors.append("the sandbox is not available: run `cea doctor` for next steps"
                          + ("; `--static-only` gives a reduced, static-only check of a local target meanwhile"
                             if target.local_path else ""))
            engine = None

    # ---- 1. fetch (network on, nothing from the target executes)
    if target.local_path:
        prepare_local(target, work)
    if engine:
        log("fetching target + dependencies (scripts disabled)...", q)
        req = {"mode": "fetch", "kind": target.kind, "spec": target.spec, "ref": target.ref,
               "script": os.path.basename(target.local_path) if target.kind == "script" else None}
        try:
            r = engine.fetch(image_tag(), work, json.dumps(req).encode())
            try:
                meta = json.load(open(os.path.join(work, "meta.json")))
            except (OSError, ValueError):
                meta = {"ok": False, "error": "fetch produced no metadata: " + r.stderr.decode(errors="replace")[-800:]}
            fetch_ok = bool(meta.get("ok"))
            if not fetch_ok:
                errors.append(f"fetch failed: {meta.get('error')}")
            for s in meta.get("skipped_members", [])[:20]:
                findings.append(Finding("archive-escape", "high", "Archive member tries to escape the extraction dir",
                                        "static", evidence=clean(s), context="install"))
        except SandboxError as e:
            errors.append(str(e))
    elif target.local_path:
        fetch_ok = True
        if target.kind == "npm-tarball":
            host_extract(os.path.join(work, "fetch", "target.tgz"), os.path.join(work, "src"))
        elif target.kind == "py-dist":
            host_extract(target.local_path, os.path.join(work, "src"))
    else:
        errors.append("static-only mode needs a local target (remote targets are downloaded inside the sandbox)")

    # ---- 2. static scan (host reads files, never runs them)
    src = os.path.join(work, "src")
    if os.path.isdir(src) and os.listdir(src):
        log("static scan...", q)
        nm = os.path.join(work, "proj", "node_modules")
        # registry/tarball installs don't run `prepare`; a dev's `npm install` in a clone does
        sf, stats = static_scan.scan(src, nm if os.path.isdir(nm) else None, meta.get("ecosystems", []),
                                     registry_pkg=meta.get("kind", target.kind) in ("npm", "npm-tarball"))
        findings += sf
    else:
        stats = {}

    # ---- 3. detonate (no network, honeypot secrets, strace)
    canaries = dynamic.make_canaries()
    steps, skipped = [], []
    if engine and fetch_ok and not args.static_only:
        steps, skipped = build_plan(target, meta, work, args, stats)
        if not steps:
            errors.append("nothing to execute for this target (unknown project type); use --run '<cmd>'")
        else:
            log(f"detonating in sandbox: {', '.join(s['name'] for s in steps)} ...", q)
            req = {"mode": "detonate", "steps": steps, "env": dynamic.honey_env(canaries, ci=args.ci),
                   "honey_files": dynamic.honey_files(canaries)}
            try:
                r = engine.detonate(image_tag(), work, json.dumps(req).encode(),
                                    timeout=args.timeout * (len(steps) + 1) + 120, memory=args.memory, cpus=args.cpus)
                if r.returncode != 0 or not r.stdout:
                    errors.append("detonation failed: " + r.stderr.decode(errors="replace")[-1200:])
                else:
                    safe_untar(r.stdout, raw)
                    df, behaviour = dynamic.analyse(raw, canaries, steps)
                    findings += df
                    dynamic_ran = True
            except SandboxError as e:
                errors.append(str(e))

    # ---- 4. report
    findings = dynamic.dedupe(findings)
    coverage = dynamic.coverage(steps, behaviour, skipped, dynamic_ran)
    v = report.verdict(findings, dynamic_ran, fetch_ok, coverage)
    ctx = {"version": __version__, "checked_at": report.now(), "duration_s": round(time.time() - t0, 1),
           "target": {"display": target.display, "kind": target.kind, "spec": target.spec, "ref": target.ref},
           "meta": {k: meta.get(k) for k in ("name", "version", "commit", "kind", "ecosystems", "dist_file", "sdist_only")},
           "verdict": v, "score": report.score(findings, dynamic_ran),
           "dependency_score": report.dependency_score(findings), "findings": findings, "behaviour": behaviour,
           "coverage": coverage, "static_stats": stats, "dynamic_ran": dynamic_ran, "errors": errors}
    path = report.write(ctx, out_dir)
    if not args.keep_work:
        shutil.rmtree(work, ignore_errors=True)

    counts = {s: sum(1 for f in findings if f.severity == s) for s in report.SEV_ORDER}
    top = [f for f in report._sorted(findings) if f.severity in ("critical", "high", "medium")][:8]
    if args.json:
        print(json.dumps({"verdict": v, "score": ctx["score"], "dependency_score": ctx["dependency_score"],
                          "partial": coverage["partial"], "target": target.display, "report": path,
                          "report_json": os.path.join(out_dir, "report.json"), "counts": counts,
                          "top_findings": [f.to_dict() for f in top], "errors": errors}, indent=1))
    else:
        print()
        print(f"  {report.VERDICTS[v]}")
        if coverage["partial"]:
            print(f"  ⚠️  partial analysis: {coverage['summary']}")
        dep = f" (dependencies: {ctx['dependency_score']})" if ctx["dependency_score"] else ""
        print(f"  score {ctx['score']}/100{dep} · " + ", ".join(f"{counts[s]} {s}" for s in reversed(report.SEV_ORDER) if counts[s]))
        for f in top:
            who = f" {clean(f.package, 60)}" if f.package else ""
            print(f"   {report.SEV_ICON[f.severity]} [{f.source}/{f.context}{who}] {f.title}" + (f": {clean(f.evidence, 100)}" if f.evidence else ""))
        for e in errors:
            print(f"   ! {clean(e, 200)}")
        print(f"\n  report: {path}  ({ctx['duration_s']}s)\n")

    if args.fail_on and report.VERDICT_RANK[v] >= FAIL_LEVELS[args.fail_on]:
        return 1
    return 0 if not errors or dynamic_ran else 3


def cmd_build(args):
    try:
        e = Engine(args.engine, verbose=True)
        e.ping()
        tag = image_tag()
        if args.pull:
            e.pull(tag, args.registry or REGISTRY_REPO)
            print(f"pulled {tag}")
            return 0
        e.build(tag, build_args=args.build_arg or [], network=args.network)
        print(f"built {tag}")
        return 0
    except SandboxError as ex:
        print(f"cea: {ex}", file=sys.stderr)
        return 2


def cmd_image(args):
    try:
        e = Engine(args.engine)
        e.ping()
        tag = image_tag()
        if args.action == "export":
            e.export_image(tag, args.file)
            print(f"exported {tag} -> {args.file}  (load it elsewhere with: cea image import {args.file})")
        else:
            e.import_image(tag, args.file)
            print(f"imported {tag}")
        return 0
    except SandboxError as ex:
        print(f"cea: {ex}", file=sys.stderr)
        return 2


def cmd_doctor(args):
    ok = True
    try:
        e = Engine(args.engine)
        try:
            version = e.ping()
        except SandboxError:
            if not args.start:
                raise
            version = e.start(wait=args.wait)
        print(f"engine      {e.name} {version}")
        tag = image_tag()
        has = e.has_image(tag)
        print(f"image       {tag} " + ("present" if has else
              f"MISSING\n            next: `cea build` ({BUILD_NEEDS}),\n"
              "            or `cea build --pull` (pre-built image), or `cea image import <file>` (offline)"))
        ok &= has
        if has:
            r = e._run(["run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "--user", e.user(), tag, "sh", "-c",
                        "strace -f -qq -e trace=execve -o /dev/null true && echo strace-ok"], timeout=60)
            good = b"strace-ok" in r.stdout
            print(f"strace      {'ok' if good else 'FAILED: ' + r.stderr.decode(errors='replace')[:200]}")
            ok &= good
    except SandboxError as ex:
        print("engine      " + str(ex).replace("\n", "\n            "))
        ok = False
    print("status      " + ("ready" if ok else "not ready"))
    if not ok:
        print("            meanwhile: `cea check --static-only <local dir/file>` runs the static scan only "
              "(no sandbox, much weaker evidence)")
    return 0 if ok else 2


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cea", description="ChEck Anything: sandbox-test a package/repo/script before you trust it.")
    ap.add_argument("--version", action="version", version=f"cea {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    c = sub.add_parser("check", help="analyse a target", description=(
        "Targets: npm:<pkg>[@ver] | pypi:<pkg>[==ver] | github:<owner>/<repo> | https://...git | "
        "https://.../install.sh | ./local/dir | ./pkg.tgz | ./pkg.whl | ./script.sh"))
    c.add_argument("target")
    c.add_argument("--run", help="extra command to run inside the sandbox after install (e.g. 'npx mytool --help')")
    c.add_argument("--out", default=os.environ.get("CEA_REPORTS", "cea-reports"), help="reports directory (default ./cea-reports)")
    c.add_argument("--timeout", type=int, default=180, help="seconds per sandbox step (default 180)")
    c.add_argument("--wait", type=int, default=5, help="seconds to linger after import to catch delayed payloads (default 5)")
    c.add_argument("--ci", action="store_true", help="pretend to be a CI runner (some malware only fires in CI)")
    c.add_argument("--no-import", action="store_true", help="skip the import/require step")
    c.add_argument("--no-bin", action="store_true", help="don't run the package's bin with --help")
    c.add_argument("--no-build", action="store_true", help="don't run `npm run build` when entry points are missing")
    c.add_argument("--static-only", action="store_true", help="no container: static scan of a local target only")
    c.add_argument("--npm", action="store_true", help="treat a bare name as an npm package (default)")
    c.add_argument("--pypi", action="store_true", help="treat a bare name as a PyPI package")
    c.add_argument("--ref", help="git branch/tag to check out")
    c.add_argument("--keep-work", action="store_true", help="keep the fetched (untrusted!) files in <report>/work")
    c.add_argument("--json", action="store_true", help="print a machine-readable summary to stdout")
    c.add_argument("--fail-on", choices=list(FAIL_LEVELS), help="exit 1 if verdict is at least this bad (for CI)")
    c.add_argument("--engine", help="docker | podman (auto)")
    c.add_argument("--runtime", help="OCI runtime, e.g. runsc (gVisor) for stronger isolation")
    c.add_argument("--memory", default="3g")
    c.add_argument("--cpus", default="2")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(func=cmd_check)

    b = sub.add_parser("build", help="build the sandbox image")
    b.add_argument("--build-arg", action="append", help="e.g. NODE_IMAGE=... BASE_IMAGE=...")
    b.add_argument("--network", help="build network (e.g. host)")
    b.add_argument("--pull", action="store_true", help="pull the pre-built image instead of building it")
    b.add_argument("--registry", help=f"image repository for --pull (default {REGISTRY_REPO}, env CEA_IMAGE_REGISTRY)")
    b.add_argument("--engine")
    b.set_defaults(func=cmd_build)

    im = sub.add_parser("image", help="move the sandbox image between machines (offline / blocked registries)")
    im.add_argument("action", choices=["export", "import"])
    im.add_argument("file", help="tar file to write (export) or read (import)")
    im.add_argument("--engine")
    im.set_defaults(func=cmd_image)

    d = sub.add_parser("doctor", help="check that the sandbox works on this machine")
    d.add_argument("--engine")
    d.add_argument("--start", action="store_true", help="start the container engine if it is not running")
    d.add_argument("--wait", type=int, default=90, help="seconds to wait for the engine with --start (default 90)")
    d.set_defaults(func=cmd_doctor)

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
