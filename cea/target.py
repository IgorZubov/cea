"""Parse a user-supplied target spec into something the sandbox can fetch."""
import os
import re
import tarfile
from dataclasses import dataclass, field

GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht")


class TargetError(ValueError):
    pass


@dataclass
class Target:
    kind: str            # npm | pypi | git | url | dir | npm-tarball | py-dist | script
    spec: str            # what the sandbox fetches (package spec / URL / path)
    display: str         # human readable
    ref: str = ""        # git branch/tag
    local_path: str = "" # for local kinds
    extra: dict = field(default_factory=dict)

    @property
    def slug(self):
        s = re.sub(r"[^A-Za-z0-9._-]+", "_", self.display).strip("_")
        return s[:60] or "target"


def _tar_has(path, name):
    try:
        with tarfile.open(path) as tf:
            return any(m.name.count("/") == 1 and m.name.split("/", 1)[1] == name for m in tf.getmembers())
    except Exception:
        return False


def _local(path):
    path = os.path.abspath(os.path.expanduser(path))
    base = os.path.basename(path)
    if os.path.isdir(path):
        return Target("dir", path, base, local_path=path)
    low = base.lower()
    if low.endswith(".whl"):
        return Target("py-dist", path, base, local_path=path)
    if low.endswith((".tgz", ".tar.gz")):
        if _tar_has(path, "package.json"):
            return Target("npm-tarball", path, base, local_path=path)
        return Target("py-dist", path, base, local_path=path)
    return Target("script", path, base, local_path=path)


def _git(url, ref=""):
    if "#" in url and not ref:
        url, ref = url.split("#", 1)
    if not re.match(r"^https?://", url):
        # Only http(s): ext::, file:// and ssh transports can run commands or touch the host.
        raise TargetError(f"only http(s) git URLs are supported, got: {url}")
    disp = re.sub(r"^https?://", "", url).removesuffix(".git") + (f"@{ref}" if ref else "")
    return Target("git", url, disp, ref=ref)


def parse_target(raw, ecosystem=None):
    raw = raw.strip()
    if not raw:
        raise TargetError("empty target")

    prefix, _, rest = raw.partition(":")
    p = prefix.lower()
    if rest and p in ("npm",):
        return Target("npm", rest, f"npm:{rest}")
    if rest and p in ("pypi", "pip", "py"):
        return Target("pypi", rest, f"pypi:{rest}")
    if rest and p in ("github", "gh"):
        return _git(f"https://github.com/{rest}")
    if rest and p == "gitlab":
        return _git(f"https://gitlab.com/{rest}")
    if rest and p in ("git",) and not rest.startswith("//"):
        return _git(rest)
    if rest and p in ("file", "path", "local"):
        return _local(rest)

    if re.match(r"^https?://", raw):
        host = re.sub(r"^https?://", "", raw).split("/")[0].lower()
        if raw.split("#")[0].endswith(".git") or (host in GIT_HOSTS and raw.count("/") <= 5 and "/releases/" not in raw and "/raw/" not in raw):
            return _git(raw)
        return Target("url", raw, raw)
    if re.match(r"^(git@|ssh://|git://|ext::|file://)", raw):
        raise TargetError("only http(s) git URLs are supported (ssh/ext/file transports are refused)")

    if os.path.exists(os.path.expanduser(raw)):
        return _local(raw)

    if ecosystem == "pypi" or re.search(r"(==|~=|>=|<=)", raw):
        return Target("pypi", raw, f"pypi:{raw}")
    if ecosystem == "npm" or raw.startswith("@"):
        return Target("npm", raw, f"npm:{raw}")
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.+)?$", raw):
        return _git(f"https://github.com/{raw}")
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(@[^\s]+)?$", raw):
        return Target("npm", raw, f"npm:{raw}")
    raise TargetError(f"cannot understand target: {raw!r} (try npm:<pkg>, pypi:<pkg>, github:<owner>/<repo>, a URL or a path)")
