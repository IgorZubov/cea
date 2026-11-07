"""Container engine wrapper (Docker or Podman) with hardened defaults."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid

SANDBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
IMAGE_REPO = "cea-sandbox"


class SandboxError(RuntimeError):
    pass


def image_tag():
    h = hashlib.sha256(open(os.path.join(SANDBOX_DIR, "Dockerfile"), "rb").read()).hexdigest()[:12]
    return f"{IMAGE_REPO}:{h}"


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
        r = self._run(["info", "--format", "{{.ServerVersion}}"], timeout=30)
        if r.returncode != 0:
            raise SandboxError(f"{self.name} is installed but not usable: {r.stderr.decode(errors='replace').strip()[:300]}")
        return r.stdout.decode().strip()

    def has_image(self, tag):
        return self._run(["image", "inspect", tag], timeout=30).returncode == 0

    def build(self, tag, build_args=(), network=None, quiet=False):
        args = ["build", "-t", tag]
        for ba in build_args:
            args += ["--build-arg", ba]
        if network:
            args += ["--network", network]
        args.append(SANDBOX_DIR)
        r = self._run(args, timeout=1800, capture=quiet)
        if r.returncode != 0:
            msg = r.stderr.decode(errors="replace")[-1500:] if quiet and r.stderr else ""
            raise SandboxError("image build failed. " + msg +
                               "\nHint: if Docker Hub is rate-limited try: cea build --build-arg "
                               "NODE_IMAGE=mirror.gcr.io/library/node:22-bookworm-slim --build-arg "
                               "BASE_IMAGE=mirror.gcr.io/library/ubuntu:24.04")

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
