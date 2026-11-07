#!/usr/bin/env python3
"""CEA in-sandbox agent. Runs ONLY inside the container (never on the host).

Reads one JSON request from stdin.

  mode=fetch     network ON, *no third-party code executes*: download the target
                 and its dependencies (npm --ignore-scripts, wheels only, shallow
                 git clone) into /work.
  mode=detonate  network OFF (+ sinkhole): copy /work into tmpfs, plant honey
                 credentials, run the install / import / run steps under strace.
                 At the end the agent streams a tar of /out to stdout.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile

WORK = "/work"
OUT = "/out"
APP = "/sandbox/app"
HOME = os.environ.get("HOME", "/home/dev")

TRACE_SYSCALLS = ("execve,execveat,clone,clone3,fork,vfork,connect,open,openat,creat,"
                  "unlink,unlinkat,rename,renameat,renameat2,chmod,fchmodat,symlink,symlinkat,ptrace")


def err(*a):
    print("[cea-agent]", *a, file=sys.stderr, flush=True)


def run(cmd, cwd=None, timeout=900, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or b"").decode("utf-8", "replace") + "\n[timeout]"
    except FileNotFoundError as e:
        return 127, str(e)


# ------------------------------------------------------------ safe archives
def safe_extract_tar(path, dest, strip=1):
    skipped = []
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            parts = [p for p in m.name.split("/") if p not in ("", ".")][strip:]
            if not parts:
                continue
            m.name = "/".join(parts)
            if m.islnk():
                m.linkname = "/".join(m.linkname.split("/")[strip:])
            try:
                tf.extract(m, dest, filter="data")
            except Exception as e:  # absolute paths, '..', links escaping dest...
                skipped.append(f"{m.name}: {e}")
    return skipped


def safe_extract_zip(path, dest):
    skipped = []
    root = os.path.realpath(dest)
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(root + os.sep):
                skipped.append(info.filename)
                continue
            zf.extract(info, dest)
    return skipped


def tar_top_has(path, name):
    try:
        with tarfile.open(path) as tf:
            return any(m.name.split("/", 1)[-1] == name and m.name.count("/") == 1 for m in tf.getmembers())
    except Exception:
        return False


# ---------------------------------------------------------------- fetching
def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def sanitize_requirements(lines):
    """Keep plain 'name[extras] <op> version' specs only. Options (-e, -r,
    --index-url...), URLs and paths could trigger builds/code at fetch time."""
    keep = []
    for ln in lines:
        ln = ln.split("#", 1)[0].strip()
        if not ln or ln.startswith("-") or "://" in ln or "@" in ln or ln.startswith((".", "/")):
            continue
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*([<>=!~;].*)?$", ln):
            keep.append(ln)
    return keep


def pip_download(args, meta):
    rc, out = run([sys.executable, "-m", "pip", "download", "--disable-pip-version-check",
                   "--no-cache-dir", "--only-binary=:all:", "--dest", f"{WORK}/dist"] + args)
    meta["log"].append({"cmd": "pip download " + " ".join(args), "rc": rc, "out": out[-3000:]})
    return rc


def fetch_pypi_sdist(name, version, meta):
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=60) as r:
        info = json.load(r)
    files = info.get("urls") or []
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    if not sdists:
        raise RuntimeError(f"no wheel for this platform and no sdist for {name}")
    f = sdists[0]
    dest = f"{WORK}/dist/{os.path.basename(f['filename'])}"
    with urllib.request.urlopen(f["url"], timeout=300) as r, open(dest, "wb") as fh:
        shutil.copyfileobj(r, fh)
    meta["version"] = info["info"]["version"]
    meta["sdist_only"] = True
    return dest


def extract_py_dist(path, meta):
    if path.endswith(".whl") or path.endswith(".zip"):
        meta["skipped_members"] += safe_extract_zip(path, f"{WORK}/src")
    else:
        meta["skipped_members"] += safe_extract_tar(path, f"{WORK}/src", strip=1)


def find_dist_file(name):
    n = norm(name)
    for f in sorted(os.listdir(f"{WORK}/dist")):
        if norm(f).startswith(n + "-"):
            return f"{WORK}/dist/{f}"
    return None


def npm_from_tarball(tgz, meta):
    meta["skipped_members"] += safe_extract_tar(tgz, f"{WORK}/src", strip=1)
    try:
        pj = json.load(open(f"{WORK}/src/package.json"))
    except Exception as e:
        raise RuntimeError(f"tarball has no readable package.json: {e}")
    meta["name"], meta["version"] = pj.get("name"), pj.get("version")
    meta["ecosystems"] = ["npm"]
    os.makedirs(f"{WORK}/proj", exist_ok=True)
    json.dump({"name": "cea-probe", "version": "0.0.0", "private": True,
               "dependencies": {pj["name"]: f"file:{tgz}"}}, open(f"{WORK}/proj/package.json", "w"))
    npm_install(f"{WORK}/proj", meta)


def npm_install(cwd, meta):
    rc, out = run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund",
                   "--loglevel=warn"], cwd=cwd)
    meta["log"].append({"cmd": "npm install --ignore-scripts", "rc": rc, "out": out[-3000:]})
    meta["deps_installed"] = rc == 0


def project_setup(meta):
    """Generic source tree (git clone / local dir): fetch deps without running anything."""
    src, proj = f"{WORK}/src", f"{WORK}/proj"
    shutil.copytree(src, proj, symlinks=True, dirs_exist_ok=True)
    eco = []
    if os.path.isfile(f"{proj}/package.json"):
        eco.append("npm")
        try:
            pj = json.load(open(f"{proj}/package.json"))
            meta.setdefault("name", pj.get("name"))
            meta.setdefault("version", pj.get("version"))
        except Exception:
            pass
        # A project .npmrc may redirect the registry or point npm's `git`/`script-shell` at a repo file.
        for rc_name in (".npmrc", ".yarnrc", ".yarnrc.yml"):
            if os.path.exists(f"{proj}/{rc_name}"):
                os.rename(f"{proj}/{rc_name}", f"{proj}/{rc_name}.cea-quarantined")
                meta["quarantined"].append(rc_name)
        npm_install(proj, meta)
    if any(os.path.exists(f"{proj}/{f}") for f in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")):
        eco.append("python")
        reqs = []
        if os.path.isfile(f"{proj}/requirements.txt"):
            reqs += sanitize_requirements(open(f"{proj}/requirements.txt", errors="replace").read().splitlines())
        if os.path.isfile(f"{proj}/pyproject.toml"):
            try:
                import tomllib
                data = tomllib.load(open(f"{proj}/pyproject.toml", "rb"))
                proj_tbl = data.get("project", {})
                meta.setdefault("name", proj_tbl.get("name"))
                reqs += sanitize_requirements(proj_tbl.get("dependencies", []))
                reqs += sanitize_requirements(data.get("build-system", {}).get("requires", []))
            except Exception as e:
                meta["log"].append({"cmd": "parse pyproject.toml", "rc": 1, "out": str(e)})
        if reqs:
            open("/tmp/cea-reqs.txt", "w").write("\n".join(reqs) + "\n")
            pip_download(["-r", "/tmp/cea-reqs.txt"], meta)
    meta["ecosystems"] = eco


def classify_file(path):
    low = path.lower()
    if low.endswith(".whl"):
        return "py-dist"
    if low.endswith((".tgz", ".tar.gz")):
        if tar_top_has(path, "package.json"):
            return "npm-tarball"
        if tar_top_has(path, "PKG-INFO") or tar_top_has(path, "setup.py") or tar_top_has(path, "pyproject.toml"):
            return "py-dist"
    return "script"


def do_fetch(req):
    kind, spec = req["kind"], req["spec"]
    meta = {"kind": kind, "spec": spec, "log": [], "quarantined": [], "skipped_members": [], "ecosystems": []}
    for d in ("src", "dist", "fetch"):
        os.makedirs(f"{WORK}/{d}", exist_ok=True)
    try:
        if kind == "url":
            name = os.path.basename(spec.split("?")[0].rstrip("/")) or "download"
            dest = f"{WORK}/fetch/{name}"
            req_ = urllib.request.Request(spec, headers={"User-Agent": "cea-fetch/0.1"})
            with urllib.request.urlopen(req_, timeout=300) as r, open(dest, "wb") as fh:
                shutil.copyfileobj(r, fh)
            kind = meta["kind"] = classify_file(dest)
            if kind == "py-dist":
                shutil.move(dest, f"{WORK}/dist/{name}")
            elif kind == "script":
                shutil.copy(dest, f"{WORK}/src/{name}")
                meta["script"] = name
            else:
                os.rename(dest, f"{WORK}/fetch/target.tgz")

        if kind == "npm":
            rc, out = run(["npm", "pack", spec, "--ignore-scripts", "--json",
                           "--pack-destination", f"{WORK}/fetch"], cwd="/tmp")
            meta["log"].append({"cmd": f"npm pack {spec}", "rc": rc, "out": out[-3000:]})
            if rc != 0:
                raise RuntimeError(f"npm pack failed: {out[-800:]}")
            tgz = [f for f in os.listdir(f"{WORK}/fetch") if f.endswith(".tgz")][0]
            os.rename(f"{WORK}/fetch/{tgz}", f"{WORK}/fetch/target.tgz")
            kind = "npm-tarball"
        if kind == "npm-tarball":
            npm_from_tarball(f"{WORK}/fetch/target.tgz", meta)

        elif kind == "pypi":
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([^\s;,]+))?", spec)
            name, version = m.group(1), m.group(2)
            meta["name"] = name
            meta["ecosystems"] = ["python"]
            if pip_download([spec], meta) != 0:
                fetch_pypi_sdist(name, version, meta)
            path = find_dist_file(name)
            if not path:
                raise RuntimeError(f"could not download {spec}")
            meta["dist_file"] = os.path.basename(path)
            extract_py_dist(path, meta)
        elif kind == "py-dist":
            files = os.listdir(f"{WORK}/dist")
            meta["dist_file"] = files[0]
            meta["name"] = re.split(r"-\d", files[0])[0]
            meta["ecosystems"] = ["python"]
            extract_py_dist(f"{WORK}/dist/{files[0]}", meta)
            if files[0].endswith(".whl"):
                pip_download([f"{WORK}/dist/{files[0]}"], meta)  # pulls binary deps

        elif kind == "git":
            cmd = ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
                   "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--no-recurse-submodules"]
            if req.get("ref"):
                cmd += ["--branch", req["ref"]]
            rc, out = run(cmd + ["--", spec, f"{WORK}/src"])
            meta["log"].append({"cmd": "git clone", "rc": rc, "out": out[-3000:]})
            if rc != 0:
                raise RuntimeError(f"git clone failed: {out[-800:]}")
            _, head = run(["git", "-C", f"{WORK}/src", "rev-parse", "HEAD"])
            meta["commit"] = head.strip()
            shutil.rmtree(f"{WORK}/src/.git", ignore_errors=True)
            project_setup(meta)
        elif kind == "dir":
            project_setup(meta)
        elif kind == "script":
            meta.setdefault("script", req.get("script"))
        meta["ok"] = True
    except Exception as e:
        meta["ok"] = False
        meta["error"] = f"{type(e).__name__}: {e}"
    json.dump(meta, open(f"{WORK}/meta.json", "w"), indent=1)
    print(json.dumps({"ok": meta["ok"], "error": meta.get("error")}))


# --------------------------------------------------------------- detonation
def plant_honey(files):
    for rel, content in files.items():
        path = os.path.join(HOME, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        if "/.ssh/" in "/" + rel:
            os.chmod(path, 0o600)


TLS_DIR = "/tmp/.tls"
SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


def start_sinkhole():
    ready = "/tmp/.sinkhole-ready"
    p = subprocess.Popen([sys.executable, "-I", "/cea/sinkhole.py", f"{OUT}/net.jsonl", ready, TLS_DIR],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=open(f"{OUT}/sinkhole.err", "w"))
    for _ in range(50):
        if os.path.exists(ready):
            break
        time.sleep(0.1)
    return p


def tls_trust_env():
    """Make the sandbox CA trusted by curl, node, python, pip, git."""
    ca = f"{TLS_DIR}/ca.pem"
    if not os.path.exists(ca):
        return {}
    bundle = f"{TLS_DIR}/bundle.pem"
    with open(bundle, "w") as out:
        try:
            out.write(open(SYSTEM_BUNDLE).read())
        except OSError:
            pass
        out.write("\n" + open(ca).read())
    return {"SSL_CERT_FILE": bundle, "CURL_CA_BUNDLE": bundle, "REQUESTS_CA_BUNDLE": bundle,
            "NODE_EXTRA_CA_CERTS": ca, "GIT_SSL_CAINFO": bundle, "PIP_CERT": bundle}


def do_detonate(req):
    os.makedirs(OUT, exist_ok=True)
    plant_honey(req.get("honey_files", {}))
    sink = start_sinkhole()

    src = f"{WORK}/proj" if os.path.isdir(f"{WORK}/proj") else f"{WORK}/src"
    if os.path.isdir(src):
        shutil.copytree(src, APP, symlinks=True, dirs_exist_ok=True)
    else:
        os.makedirs(APP, exist_ok=True)

    env = {
        "PATH": f"{APP}/node_modules/.bin:/sandbox/venv/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": HOME, "USER": "dev", "LOGNAME": "dev", "SHELL": "/bin/bash", "LANG": "C.UTF-8",
        "TERM": "xterm-256color", "npm_config_cache": f"{HOME}/.npm",
        "npm_config_update_notifier": "false", "npm_config_audit": "false", "npm_config_fund": "false",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INDEX": "1",
    }
    env.update(tls_trust_env())
    env.update(req.get("env", {}))

    results = []
    for i, step in enumerate(req["steps"]):
        cwd = step.get("cwd", APP)
        timeout = int(step.get("timeout", 120))
        attempts = [step["cmd"]] + ([step["fallback"]] if step.get("fallback") else [])
        for n, cmd in enumerate(attempts):
            trace = f"{OUT}/trace.{i}.{n}.log"
            if step.get("traced", True):
                full = ["timeout", "-k", "5", str(timeout), "strace", "-f", "-qq", "-s", "512",
                        "-e", "signal=none", "-e", f"trace={TRACE_SYSCALLS}", "-o", trace] + cmd
            else:
                full = ["timeout", "-k", "5", str(timeout)] + cmd
            t0 = time.time()
            rc, out = run(full, cwd=cwd, env=env, timeout=timeout + 30)
            results.append({"index": i, "attempt": n, "name": step["name"], "phase": step["phase"],
                            "cmd": cmd, "rc": rc, "timed_out": rc in (124, 137),
                            "start": t0, "end": time.time(), "output": out[-20000:],
                            "trace": os.path.basename(trace) if step.get("traced", True) else None})
            if rc == 0:
                break
    time.sleep(1.0)  # let the sinkhole flush late connections
    sink.terminate()
    json.dump({"steps": results, "finished": time.time()}, open(f"{OUT}/steps.json", "w"), indent=1)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in sorted(os.listdir(OUT)):
            p = os.path.join(OUT, f)
            if os.path.isfile(p) and not os.path.islink(p):
                tf.add(p, arcname=f)
    sys.stdout.buffer.write(buf.getvalue())
    sys.stdout.flush()


def main():
    req = json.loads(sys.stdin.read())
    if req["mode"] == "fetch":
        do_fetch(req)
    elif req["mode"] == "detonate":
        do_detonate(req)
    else:
        err("unknown mode")
        sys.exit(2)


if __name__ == "__main__":
    main()
