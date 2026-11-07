"""Parse `strace -f` logs produced inside the sandbox into behaviour events."""
import re

LINE_RE = re.compile(r"^(\d+)\s+(.*)$")
CALL_RE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?(?:\s+\((.*)\))?\s*$")
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?')


def c_unescape(s):
    out = bytearray()
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
            continue
        nxt = s[i + 1] if i + 1 < len(s) else ""
        simple = {"n": b"\n", "t": b"\t", "r": b"\r", "v": b"\v", "f": b"\f", '"': b'"', "\\": b"\\"}
        if nxt in simple:
            out += simple[nxt]
            i += 2
        elif nxt == "x":
            out.append(int(s[i + 2:i + 4], 16))
            i += 4
        elif nxt.isdigit():
            j = i + 1
            while j < len(s) and j < i + 4 and s[j] in "01234567":
                j += 1
            out.append(int(s[i + 1:j], 8) & 0xFF)
            i = j
        else:
            out += nxt.encode()
            i += 2
    return out.decode("utf-8", "replace")


def strings(args):
    return [c_unescape(m.group(1)) + ("..." if m.group(2) else "") for m in STR_RE.finditer(args)]


def join_unfinished(lines):
    """strace -f splits syscalls interrupted by other processes:
       123 execve("/bin/sh", [...] <unfinished ...>
       123 <... execve resumed>) = 0"""
    pending = {}
    for raw in lines:
        m = LINE_RE.match(raw.rstrip("\n"))
        if not m:
            continue
        pid, rest = int(m.group(1)), m.group(2)
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[: -len("<unfinished ...>")].rstrip()
            continue
        rm = re.match(r"^<\.\.\. (\w+) resumed>(.*)$", rest)
        if rm:
            head = pending.pop(pid, rm.group(1) + "(")
            rest = head + rm.group(2)
        yield pid, rest


def parse_sockaddr(args):
    fam = re.search(r"sa_family=(AF_\w+)", args)
    if not fam:
        return None
    fam = fam.group(1)
    if fam == "AF_INET":
        port = re.search(r"sin_port=htons\((\d+)\)", args)
        addr = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', args)
        return {"family": "inet", "addr": addr.group(1) if addr else "?", "port": int(port.group(1)) if port else 0}
    if fam == "AF_INET6":
        port = re.search(r"sin6_port=htons\((\d+)\)", args)
        addr = re.search(r'inet_pton\(AF_INET6, "([^"]+)"', args)
        return {"family": "inet6", "addr": addr.group(1) if addr else "?", "port": int(port.group(1)) if port else 0}
    if fam == "AF_UNIX":
        path = re.search(r'sun_path=(@?)"([^"]*)"', args)
        return {"family": "unix", "addr": (path.group(1) + path.group(2)) if path else "?", "port": 0}
    return {"family": fam, "addr": "?", "port": 0}


WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")


def parse(lines, step=None):
    """Return dict(processes, connects, opens, mutations)."""
    image = {}         # pid -> argv of the program currently running in it
    parent = {}
    processes, connects, opens, mutations, failed_exec = [], [], [], [], {}
    for pid, rest in join_unfinished(lines):
        cm = CALL_RE.match(rest)
        if not cm:
            continue
        name, args, ret, errno = cm.group(1), cm.group(2), cm.group(3), cm.group(4) or ""
        ok = ret not in ("?",) and not ret.startswith("-")
        if name in ("clone", "clone3", "fork", "vfork"):
            if ok and ret.isdigit():
                child = int(ret)
                parent[child] = pid
                image[child] = image.get(pid)
            continue
        if name in ("execve", "execveat"):
            strs = strings(args)
            path = strs[0] if strs else "?"
            argv = strs[1:] if len(strs) > 1 else [path]
            # execve's argv array ends where the envp pointer begins; strace prints envp as an address.
            if ok:
                ppid = parent.get(pid)
                processes.append({"pid": pid, "ppid": ppid, "path": path, "argv": argv, "step": step,
                                  "parent_argv": image.get(ppid) if ppid else None})
                image[pid] = argv
            else:
                base = path.rsplit("/", 1)[-1]
                failed_exec.setdefault(base, {"count": 0, "errno": errno, "argv": argv, "step": step})
                failed_exec[base]["count"] += 1
            continue
        if name == "connect":
            sa = parse_sockaddr(args)
            if sa:
                sa.update({"pid": pid, "ok": ok or errno == "EINPROGRESS", "errno": errno, "step": step,
                           "by": image.get(pid)})
                connects.append(sa)
            continue
        if name in ("open", "openat", "creat"):
            strs = strings(args)
            if not strs:
                continue
            path = strs[0]
            write = name == "creat" or any(f in args for f in WRITE_FLAGS)
            opens.append({"pid": pid, "path": path, "write": write, "ok": ok, "errno": errno, "step": step,
                          "by": image.get(pid)})
            continue
        if name in ("unlink", "unlinkat", "rename", "renameat", "renameat2", "chmod", "fchmodat",
                    "symlink", "symlinkat", "ptrace"):
            mutations.append({"pid": pid, "call": name, "args": strings(args), "raw": args[:300], "ok": ok,
                              "errno": errno, "step": step, "by": image.get(pid)})
    return {"processes": processes, "connects": connects, "opens": opens, "mutations": mutations,
            "failed_exec": failed_exec}
