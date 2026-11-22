"""Container engine wrapper (Docker or Podman) with hardened defaults."""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

SANDBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
IMAGE_REPO = "cea-sandbox"
# where `cea build --pull` looks for a pre-built image (same content-hash tag as a local build)
REGISTRY_REPO = os.environ.get("CEA_IMAGE_REGISTRY", "ghcr.io/igorzubov/cea-sandbox")
BUILD_NEEDS = ("the build takes ~1 min and needs network access to a container registry (Docker Hub: "
               "node:22-bookworm-slim + ubuntu:24.04) and to Ubuntu apt mirrors")


class SandboxError(RuntimeError):
    pass


def image_hash():
    return hashlib.sha256(open(os.path.join(SANDBOX_DIR, "Dockerfile"), "rb").read()).hexdigest()[:12]


def image_tag():
    """The image every stage runs. CEA_IMAGE overrides it (e.g. an image you pushed to a reachable registry)."""
    return os.environ.get("CEA_IMAGE") or f"{IMAGE_REPO}:{image_hash()}"


def engine_hint(name, err, platform=None, exists=os.path.exists, which=shutil.which):
    """Next step for an engine that is installed but not answering."""
    platform = platform or sys.platform
    low = (err or "").lower()
    if re.search(r"permission denied", low):
        return ("your user may not access the engine socket: add yourself to the `docker` group "
                "(`sudo usermod -aG docker $USER`, then log in again) or use rootless Podman")
    if not re.search(r"no such file|cannot connect|connection refused|daemon running|is the docker daemon|"
                     r"failed to connect|dial unix|socket|machine|not running|unable to connect", low):
        return None
    if name == "podman":
        if platform == "darwin" or platform.startswith("win"):
            return "the Podman machine is not running: `podman machine start` (or `cea doctor --start`)"
        return "start the Podman socket: `systemctl --user start podman.socket`"
    if platform == "darwin":
        for app, label in (("/Applications/Docker.app", "Docker Desktop"), ("/Applications/OrbStack.app", "OrbStack")):
            if exists(app) or exists(os.path.expanduser("~" + app)):
                return f"{label} is installed but not running: `open -a {label.split()[0]}` (or `cea doctor --start`)"
        if which("colima"):
            return "Colima is installed but not running: `colima start` (or `cea doctor --start`)"
        return "no Docker engine is running: start Docker Desktop, OrbStack or Colima"
    if platform.startswith("win"):
        return "Docker Desktop is not running: start it from the Start menu"
    if exists("/run/systemd/system"):
        return "the Docker daemon is not running: `sudo systemctl start docker` (or `cea doctor --start` as root)"
    return "the Docker daemon is not running (no systemd here): start `sudo dockerd` (or `cea doctor --start` as root)"


def start_command(name, platform=None, exists=os.path.exists, which=shutil.which, is_root=None):
    """The command `cea doctor --start` runs, or None if starting needs the user (e.g. sudo)."""
    platform = platform or sys.platform
    is_root = (hasattr(os, "getuid") and os.getuid() == 0) if is_root is None else is_root
    if name == "podman":
        if platform == "darwin" or platform.startswith("win"):
            return ["podman", "machine", "start"]
        return ["systemctl", "--user", "start", "podman.socket"] if exists("/run/systemd/system") else None
    if platform == "darwin":
        for app in ("Docker", "OrbStack"):
            if exists(f"/Applications/{app}.app") or exists(os.path.expanduser(f"~/Applications/{app}.app")):
                return ["open", "-a", app]
        return ["colima", "start"] if which("colima") else None
    if platform.startswith("linux") and is_root:
        if exists("/run/systemd/system"):
            return ["systemctl", "start", "docker"]
        if which("dockerd"):
            return ["dockerd"]   # no init system (containers, WSL without systemd): run it in the background
    return None


def build_hint(output):
    """Turn a failed `docker build` log into a next step."""
    low = (output or "").lower()
    host = None
    m = re.search(r"https?://([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/", output or "", re.I)
    if m:
        host = m.group(1)
    where = f" to {host}" if host else ""
    if re.search(r"toomanyrequests|too many requests|429 too many|rate.?limit", low):
        return ("the registry is rate-limiting you (HTTP 429). Log in (`docker login`) or use a mirror: "
                "cea build --build-arg NODE_IMAGE=mirror.gcr.io/library/node:22-bookworm-slim "
                "--build-arg BASE_IMAGE=mirror.gcr.io/library/ubuntu:24.04")
    if re.search(r"forbidden|proxyconnect|proxy authentication|proxy error|no rule|tunnel|blocked by", low):
        return (f"your network blocks the request{where} (HTTP 403 / proxy refusal), so a mirror on the same "
                "network will likely be blocked too. Options: build on a machine with access and move the image "
                "with `cea image export` / `cea image import`; `cea build --pull` if a registry with the pre-built "
                "image is reachable; point --build-arg NODE_IMAGE=/BASE_IMAGE= at a registry you can reach; or ask "
                "for the registry hosts to be allow-listed. Registry pulls go through the *daemon's* proxy settings "
                "(see README: Proxies)")
    if re.search(r"unauthorized|authentication required|denied: ", low):
        return "the registry wants credentials: `docker login <registry>`, or use another registry with --build-arg"
    if re.search(r"x509|certificate|tls: |ssl", low):
        return ("TLS verification failed: a TLS-intercepting proxy's CA must be trusted by the container engine "
                "(daemon) for pulls; see README: Proxies")
    if re.search(r"no such host|temporary failure in name resolution|could not resolve|i/o timeout|"
                 r"network is unreachable|connection timed out|dial tcp", low):
        return (f"no network connection{where}. {BUILD_NEEDS}. Offline? Use `cea image import <file>` with an "
                "image exported elsewhere (`cea image export`)")
    if re.search(r"no space left", low):
        return "the engine ran out of disk space: `docker system prune` frees unused images/cache"
    return None


def find_engine(preferred=None):
    for name in ([preferred] if preferred else []) + ["docker", "podman"]:
        if name and shutil.which(name):
            return name
    raise SandboxError("no container engine found: install Docker or Podman (or pass --engine)")


def ca_bundle():
    for var in ("CEA_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"):
        p = os.environ.get(var)
        if p and os.path.isfile(p):
            return p
    return None


def proxy_env():
    env = {}
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def proxy_is_local(env):
    return any(h in v for v in env.values() for h in ("127.0.0.1", "localhost", "[::1]"))


class Engine:
    def __init__(self, name=None, runtime=None, verbose=False):
        self.name = find_engine(name)
        self.runtime = runtime
        self.verbose = verbose

    def _run(self, args, input=None, timeout=None, capture=True):
        cmd = [self.name] + args
        if self.verbose:
            print("+", " ".join(cmd), flush=True)
        try:
            return subprocess.run(cmd, input=input, timeout=timeout,
                                  stdout=subprocess.PIPE if capture else None,
                                  stderr=subprocess.PIPE if capture else None)
        except FileNotFoundError:
            raise SandboxError(f"{self.name} not found")

    def ping(self):
        try:
            r = self._run(["info", "--format", "{{.ServerVersion}}"], timeout=30)
        except subprocess.TimeoutExpired:
            raise SandboxError(f"{self.name} did not answer within 30s (still starting?)")
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace").strip()
            hint = engine_hint(self.name, err)
            raise SandboxError(f"{self.name} is installed but not usable: {err[:300]}" + (f"\nNext step: {hint}" if hint else ""))
        return r.stdout.decode().strip()

    def start(self, wait=90):
        """Start the engine (Docker Desktop / OrbStack / Colima / podman machine / systemd) and wait for it."""
        cmd = start_command(self.name)
        if not cmd:
            raise SandboxError("don't know how to start the engine here without sudo: "
                               + (engine_hint(self.name, "not running") or "start it manually"))
        print(f"starting: {' '.join(cmd)}", flush=True)
        try:
            if cmd == ["dockerd"]:
                logf = os.path.join(tempfile.gettempdir(), "cea-dockerd.log")
                subprocess.Popen(cmd, stdout=open(logf, "ab"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                 start_new_session=True)
                print(f"dockerd log: {logf}")
            else:
                subprocess.run(cmd, timeout=300)
        except (OSError, subprocess.SubprocessError) as e:
            raise SandboxError(f"could not run {' '.join(cmd)}: {e}")
        deadline = time.time() + wait
        while True:
            try:
                return self.ping()
            except SandboxError:
                if time.time() > deadline:
                    raise SandboxError(f"{self.name} did not become ready within {wait}s")
                time.sleep(2)

    def has_image(self, tag):
        return self._run(["image", "inspect", tag], timeout=30).returncode == 0

    def build(self, tag, build_args=(), network=None, quiet=False):
        args = ["build", "-t", tag]
        given = {ba.split("=", 1)[0] for ba in build_args}
        # apt inside the build honours http(s)_proxy; Docker treats these build args as predefined
        # (not stored in the image history). Base image pulls use the daemon's own proxy config.
        env = proxy_env()
        for k, v in env.items():
            if k not in given:
                args += ["--build-arg", f"{k}={v}"]
        for ba in build_args:
            args += ["--build-arg", ba]
        if network:
            args += ["--network", network]
        elif env and proxy_is_local(env):
            args += ["--network", "host"]   # a proxy on 127.0.0.1 is only reachable from the host netns
        args.append(SANDBOX_DIR)
        output = self._run_tee(args, timeout=1800, echo=not quiet)
        if output is not None:
            hint = build_hint(output) or "see the output above; " + BUILD_NEEDS
            raise SandboxError("image build failed. " + (output[-1500:] if quiet else "") + f"\nNext step: {hint}")

    def _run_tee(self, args, timeout, echo=True):
        """Run, streaming output to stderr while keeping it for error analysis. None on success."""
        cmd = [self.name] + args
        if self.verbose:
            print("+", " ".join(cmd), flush=True)
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            raise SandboxError(f"{self.name} not found")
        tail, t0 = [], time.time()
        for line in iter(p.stdout.readline, b""):
            if echo:
                sys.stderr.buffer.write(line)
                sys.stderr.flush()
            tail.append(line)
            del tail[:-400]
            if time.time() - t0 > timeout:
                p.kill()
                break
        rc = p.wait()
        return None if rc == 0 else b"".join(tail).decode(errors="replace")

    def pull(self, tag, repo=REGISTRY_REPO):
        """Fetch the pre-built image (same content hash) and tag it as the local sandbox image."""
        remote = f"{repo}:{tag.split(':', 1)[1]}"
        r = self._run(["pull", remote], timeout=1800, capture=False)
        if r.returncode != 0:
            raise SandboxError(f"could not pull {remote}. If no pre-built image exists for this CEA version, "
                               "use `cea build` or `cea image import <file>`")
        r = self._run(["tag", remote, tag], timeout=60)
        if r.returncode != 0:
            raise SandboxError(f"could not tag {remote} as {tag}: {r.stderr.decode(errors='replace')[:300]}")

    def export_image(self, tag, path):
        if not self.has_image(tag):
            raise SandboxError(f"{tag} is not present here: run `cea build` first")
        r = self._run(["save", "-o", path, tag], timeout=1800)
        if r.returncode != 0:
            raise SandboxError(f"export failed: {r.stderr.decode(errors='replace')[:300]}")

    def import_image(self, tag, path):
        r = self._run(["load", "-i", path], timeout=1800)
        if r.returncode != 0:
            raise SandboxError(f"import failed: {r.stderr.decode(errors='replace')[:300]}")
        if not self.has_image(tag):
            loaded = r.stdout.decode(errors="replace").strip()
            raise SandboxError(f"the file was loaded ({loaded[:200]}) but {tag} is still missing: it was exported "
                               "by a different CEA version (the tag is a hash of the sandbox Dockerfile)")

    def user(self):
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000
        if uid == 0:
            uid = gid = 1000
        return f"{uid}:{gid}"

    def hardened(self, name, network, memory="3g", cpus="2", pids=512):
        args = ["run", "--rm", "-i", "--name", name,
                "--network", network,
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--read-only",
                "--pids-limit", str(pids),
                "--memory", memory, "--cpus", cpus,
                "--user", self.user(),
                "--tmpfs", "/tmp:rw,exec,nosuid,size=1g,mode=1777",
                "--tmpfs", "/home/dev:rw,exec,nosuid,size=512m,mode=1777",
                "-e", "HOME=/home/dev",
                "-v", f"{SANDBOX_DIR}:/cea:ro"]
        if self.name == "podman":
            args += ["--userns=keep-id"]
        if self.runtime:
            args += ["--runtime", self.runtime]
        return args

    def run_stage(self, extra_args, image, cmd, stdin_bytes, timeout):
        name = f"cea-{uuid.uuid4().hex[:10]}"
        args = self.hardened(name, extra_args.pop("network"), **extra_args.pop("limits", {}))
        args += extra_args.pop("args", [])
        args += [image] + cmd
        try:
            r = self._run(args, input=stdin_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            self._run(["kill", name], timeout=30)
            raise SandboxError(f"sandbox stage exceeded {timeout}s and was killed")
        return r

    # ------------------------------------------------------------ stages
    def fetch(self, image, work_dir, request_json, timeout=900):
        env = proxy_env()
        network = "host" if (env and proxy_is_local(env)) else "bridge"
        args = ["-v", f"{work_dir}:/work:rw"]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        for k in ("npm_config_registry", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"):
            if os.environ.get(k):
                args += ["-e", f"{k}={os.environ[k]}"]
        ca = ca_bundle()
        if ca:
            args += ["-v", f"{os.path.realpath(ca)}:/etc/cea-ca.crt:ro",
                     "-e", "NODE_EXTRA_CA_CERTS=/etc/cea-ca.crt", "-e", "SSL_CERT_FILE=/etc/cea-ca.crt",
                     "-e", "REQUESTS_CA_BUNDLE=/etc/cea-ca.crt", "-e", "PIP_CERT=/etc/cea-ca.crt",
                     "-e", "GIT_SSL_CAINFO=/etc/cea-ca.crt", "-e", "npm_config_cafile=/etc/cea-ca.crt"]
        args += ["-e", "npm_config_cache=/home/dev/.npm", "-e", "npm_config_update_notifier=false"]
        return self.run_stage({"network": network, "args": args}, image,
                              ["python3", "-I", "/cea/agent.py"], request_json, timeout)

    def detonate(self, image, work_dir, request_json, timeout=1800, memory="3g", cpus="2"):
        tmp = tempfile.mkdtemp(prefix="cea-dns-")
        resolv = os.path.join(tmp, "resolv.conf")
        with open(resolv, "w") as fh:
            fh.write("nameserver 127.0.0.1\noptions timeout:2 attempts:1\n")
        os.chmod(tmp, 0o755)
        os.chmod(resolv, 0o644)
        args = ["-v", f"{work_dir}:/work:ro",
                "-v", f"{resolv}:/etc/resolv.conf:ro",
                "--tmpfs", "/sandbox:rw,exec,size=4g,mode=1777",
                "--tmpfs", "/out:rw,size=512m,mode=1777",
                "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
                "--hostname", "dev-laptop"]
        try:
            return self.run_stage({"network": "none", "args": args, "limits": {"memory": memory, "cpus": cpus}},
                                  image, ["python3", "-I", "/cea/agent.py"], request_json, timeout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
