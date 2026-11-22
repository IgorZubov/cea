"""Turn raw detonation output (strace logs, sinkhole log, step results) into
behaviour summaries + findings."""
import base64
import binascii
import json
import os
import re
import secrets
import string
import urllib.parse

from . import trace_parse
from .util import Finding, clean

HOME = "/home/dev"
SINK_PORTS = {21, 22, 23, 25, 80, 443, 465, 587, 1337, 2375, 3000, 4444, 5000, 5555, 6667, 8000, 8080, 8443,
              8888, 9000, 9001, 9999}

# ---------------------------------------------------------------- honeypot
def make_canaries():
    r = lambda n, alphabet=string.ascii_letters + string.digits: "".join(secrets.choice(alphabet) for _ in range(n))
    up = string.ascii_uppercase + string.digits
    c = {
        "AWS_ACCESS_KEY_ID": "AKIA" + r(16, up),
        "AWS_SECRET_ACCESS_KEY": r(40),
        "GITHUB_TOKEN": "ghp_" + r(36),
        "NPM_TOKEN": "npm_" + r(36),
        "OPENAI_API_KEY": "sk-proj-" + r(40),
        "ANTHROPIC_API_KEY": "sk-ant-api03-" + r(40),
        "SLACK_TOKEN": "xoxb-" + r(10, string.digits) + "-" + r(24),
        "DATABASE_URL_PASSWORD": "pw" + r(20),
        "SSH_KEY_MARKER": "CEA" + r(30),
        "DOCKER_AUTH": r(32),
        "PYPI_TOKEN": "pypi-" + r(40),
        "WALLET_SEED": " ".join(r(5, string.ascii_lowercase) for _ in range(12)),
        "ENV_FILE_SECRET": "sec_" + r(30),
    }
    return c


def honey_env(c, ci=False):
    env = {
        "AWS_ACCESS_KEY_ID": c["AWS_ACCESS_KEY_ID"],
        "AWS_SECRET_ACCESS_KEY": c["AWS_SECRET_ACCESS_KEY"],
        "GITHUB_TOKEN": c["GITHUB_TOKEN"],
        "GH_TOKEN": c["GITHUB_TOKEN"],
        "NPM_TOKEN": c["NPM_TOKEN"],
        "OPENAI_API_KEY": c["OPENAI_API_KEY"],
        "ANTHROPIC_API_KEY": c["ANTHROPIC_API_KEY"],
        "SLACK_BOT_TOKEN": c["SLACK_TOKEN"],
        "DATABASE_URL": f"postgres://admin:{c['DATABASE_URL_PASSWORD']}@db.internal:5432/prod",
    }
    if ci:
        env.update({"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app",
                    "GITHUB_WORKFLOW": "release", "RUNNER_OS": "Linux"})
    return env


def _ssh_key_body(c):
    body = base64.b64encode((c["SSH_KEY_MARKER"] * 8).encode()).decode()
    return "\n".join(body[i:i + 70] for i in range(0, len(body), 70))


def detection_secrets(c):
    """Canaries + distinctive chunks of honey files (catches e.g. `base64 ~/.ssh/id_rsa | curl`)."""
    d = dict(c)
    d["SSH_PRIVATE_KEY_FILE"] = _ssh_key_body(c).split("\n")[0]
    d["SSH_PRIVATE_KEY_HEADER+BODY"] = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + d["SSH_PRIVATE_KEY_FILE"][:20]
    return d


HONEY_RELS = (".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/known_hosts", ".aws/credentials", ".npmrc", ".pypirc",
              ".git-credentials", ".gitconfig", ".config/gh/hosts.yml", ".docker/config.json", ".kube/config", ".env",
              ".bash_history", ".config/solana/id.json", ".config/Exodus/exodus.wallet/seed.seco",
              ".config/google-chrome/Default/Login Data", ".bashrc", ".profile")


def honey_files(c):
    key_body = _ssh_key_body(c)
    docker_auth = base64.b64encode(f"dev:{c['DOCKER_AUTH']}".encode()).decode()
    return {
        ".ssh/id_rsa": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key_body}\n-----END OPENSSH PRIVATE KEY-----\n",
        ".ssh/id_ed25519": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key_body[:140]}\n-----END OPENSSH PRIVATE KEY-----\n",
        ".ssh/known_hosts": "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        ".aws/credentials": f"[default]\naws_access_key_id = {c['AWS_ACCESS_KEY_ID']}\naws_secret_access_key = {c['AWS_SECRET_ACCESS_KEY']}\n",
        ".npmrc": f"//registry.npmjs.org/:_authToken={c['NPM_TOKEN']}\n",
        ".pypirc": f"[pypi]\nusername = __token__\npassword = {c['PYPI_TOKEN']}\n",
        ".git-credentials": f"https://dev:{c['GITHUB_TOKEN']}@github.com\n",
        ".gitconfig": "[user]\n\tname = Dev\n\temail = dev@example.com\n[credential]\n\thelper = store\n",
        ".config/gh/hosts.yml": f"github.com:\n    oauth_token: {c['GITHUB_TOKEN']}\n    user: dev\n",
        ".docker/config.json": json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": docker_auth}}}),
        ".kube/config": f"apiVersion: v1\nusers:\n- name: admin\n  user:\n    token: {c['DOCKER_AUTH']}\n",
        ".env": f"SECRET_KEY={c['ENV_FILE_SECRET']}\nOPENAI_API_KEY={c['OPENAI_API_KEY']}\n",
        ".bash_history": f"export AWS_SECRET_ACCESS_KEY={c['AWS_SECRET_ACCESS_KEY']}\nssh deploy@prod\n",
        ".config/solana/id.json": json.dumps([ord(ch) for ch in c["WALLET_SEED"][:64]]),
        ".config/Exodus/exodus.wallet/seed.seco": c["WALLET_SEED"],
        ".config/google-chrome/Default/Login Data": f"SQLite format 3\x00 dev {c['ENV_FILE_SECRET']}",
        ".bashrc": "# ~/.bashrc\nexport PS1='$ '\n",
        ".profile": "# ~/.profile\n",
    }


def needles(value):
    """Ways a stolen secret commonly shows up on the wire."""
    v = value.encode()
    out = {value, urllib.parse.quote(value, safe=""), binascii.hexlify(v).decode()}
    for pad in range(3):  # base64 of the value at any alignment inside a bigger blob
        b = base64.b64encode(b"\x00" * pad + v).decode()
        core = b[4 if pad else 0:-4]
        if len(core) >= 12:
            out.add(core)
        out.add(base64.b64encode(v).decode().rstrip("="))
    out.add(base64.b32encode(v).decode().rstrip("=").lower())
    out.add(value[::-1])
    return {n for n in out if len(n) >= 10}


def find_leaks(canaries, blobs):
    """blobs: list of (label, text). Returns [(secret_name, label, matched_form)]."""
    leaks = []
    table = {}
    for name, val in canaries.items():
        ns = needles(val)
        if len(val) >= 24:  # partial leaks (truncated DNS labels, chunked exfil)
            ns |= needles(val[:16]) | needles(val[-16:])
        table[name] = ns
    for label, text in blobs:
        low = text.lower()
        for name, ns in table.items():
            if canaries[name] in text:
                leaks.append((name, label, "plain"))
                continue
            for n in ns:
                if n in text or (n.islower() and n in low):
                    leaks.append((name, label, "plain" if n == canaries[name] else "encoded"))
                    break
    return leaks


# ------------------------------------------------------------- classification
ALLOWED_WRITE = (r"^/sandbox/", r"^/tmp/", r"^/dev/(null|tty|pts/|shm/|stdout|stderr|urandom)",
                 rf"^{HOME}/\.(npm|cache|node-gyp|local/share/virtualenv|config/pip)(/|$)", r"^/proc/(self|thread-self|\d+)/",
                 r"^/out/")
PERSISTENCE = (r"/\.(bashrc|bash_profile|zshrc|profile|zprofile|bash_login)$", r"/\.ssh/authorized_keys",
               r"/\.config/autostart/", r"/\.config/systemd/", r"^/etc/cron", r"/crontab", r"^/etc/(profile|rc\.local|ld\.so\.preload)",
               r"/Library/LaunchAgents/", r"/\.local/bin/", r"/\.(npmrc|gitconfig)$")
SENSITIVE_READ = (r"/\.ssh/", r"/\.aws/", r"/\.npmrc$", r"/\.pypirc$", r"/\.git-credentials$", r"/\.config/gh/",
                  r"/\.docker/config\.json$", r"/\.kube/", r"/\.env$", r"/\.(bash|zsh)_history$", r"^/etc/shadow",
                  r"/\.config/(solana|Exodus|google-chrome|chromium|BraveSoftware)/", r"/\.mozilla/", r"/\.gnupg/",
                  r"/\.netrc$", r"/\.config/gcloud/", r"/\.azure/", r"/Login Data", r"/Local Storage/",
                  r"/\.(bitcoin|ethereum|electrum)/", r"^/proc/(\d+|self)/environ$", r"^/var/run/secrets/")
# legitimate readers: package managers read their own config
BENIGN_READERS = [
    (r"np[mx]-cli\.js|(^|/)np[mx](\s|$)|node_modules/npm/", r"/\.npmrc$"),
    (r"(^|/)pip[0-9.]*$|-m pip|pip install", r"/\.(netrc|pypirc|config/pip)"),
    (r"(^|/)git(\s|$)|git-core/|git-remote-https?", r"/\.(gitconfig|git-credentials|config/git|netrc)"),
]


def _m(patterns, path):
    return any(re.search(p, path) for p in patterns)


def argv_str(argv):
    return " ".join(argv or [])


def is_benign_read(by, path):
    who = argv_str(by)
    return any(re.search(w, who) and re.search(p, path) for w, p in BENIGN_READERS)


SUSPICIOUS_CMD = re.compile(r"(\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bsocat\b|base64\s+-d|/dev/tcp|\bpowershell\b|"
                            r"\bchmod\s+\+x|\bcrontab\b|\bnohup\b|\bsetsid\b|\bssh\b|\bscp\b|python[0-9.]*\s+-c|\bperl\s+-e|"
                            r"node\s+-e|\bsudo\b|\bmkfifo\b|\bxmrig\b)")
BENIGN_EXE = re.compile(r"(^|/)(sh|bash|dash|node|npm|npx|python3?(\.\d+)?|pip3?|timeout|strace|uname|env|cat|"
                        r"git|make|cc|gcc|g\+\+|cmake|node-gyp|ld|as|cc1plus|cc1|collect2|which|ls|mkdir|cp|mv|rm|true)$")


def _plan_info(step_plan, st):
    """Attribution data for a step result, taken from OUR plan (not from the sandbox's steps.json)."""
    i = st.get("index")
    plan = step_plan[i] if isinstance(i, int) and 0 <= i < len(step_plan or []) else {}
    return {"package": plan.get("package") or "", "package_path": plan.get("package_path") or "",
            "package_repo": plan.get("package_repo") or ""}


def ctx_of(item):
    return "dependency-install" if item.get("package") else item["phase"]


def analyse(raw_dir, canaries, step_plan):
    steps = json.load(open(os.path.join(raw_dir, "steps.json")))["steps"]
    for st in steps:
        st.update(_plan_info(step_plan, st))
    findings = []
    behaviour = {"steps": [], "processes": [], "failed_exec": {}, "network": [], "dns": [],
                 "sensitive_reads": [], "writes_outside": [], "mutations": [], "leaks": []}

    for st in steps:
        behaviour["steps"].append({k: st.get(k) for k in ("index", "name", "phase", "cmd", "rc", "timed_out", "attempt",
                                                           "package")} |
                                  {"duration": round(st["end"] - st["start"], 1), "output_tail": clean(st["output"][-600:], 600)})
        if not st.get("trace"):
            continue
        tpath = os.path.join(raw_dir, st["trace"])
        if not os.path.exists(tpath):
            continue
        with open(tpath, errors="replace") as fh:
            ev = trace_parse.parse(fh, step=st["phase"])
        phase = st["phase"]
        pkg = {"package": st["package"], "package_path": st["package_path"]}
        for group in ("processes", "connects", "opens", "mutations"):
            for item in ev[group]:
                item.update(pkg)
        for info in ev["failed_exec"].values():
            info.update(pkg)
        root_exe_seen = False
        for p in ev["processes"]:
            p["phase"] = phase
            if not root_exe_seen:  # the step's own command
                root_exe_seen = True
                p["root"] = True
            behaviour["processes"].append(p)
        ran = {p["path"].rsplit("/", 1)[-1] for p in ev["processes"]}
        for base, info in ev["failed_exec"].items():
            if base in ("ldconfig",) or base in ran or info["errno"] != "ENOENT":
                continue
            behaviour["failed_exec"].setdefault(base, info | {"phase": phase})
        for c in ev["connects"]:
            if c["family"] == "unix":
                if re.search(r"nscd|/dev/log", c["addr"]):
                    continue
                c["phase"] = phase
                behaviour["network"].append(c)
                if re.search(r"docker\.sock|containerd|podman|dbus", c["addr"]):
                    findings.append(F("socket-probe", "high", "Tried to reach a container/system socket",
                                      clean(f"{c['addr']} by {argv_str(c['by'])}"), c))
                continue
            if c["addr"] in ("127.0.0.1", "::1", "::ffff:127.0.0.1") and (c["port"] == 53 or c["port"] in SINK_PORTS):
                continue
            c["phase"] = phase
            behaviour["network"].append(c)
        for o in ev["opens"]:
            path = o["path"]
            if not path.startswith("/"):
                continue
            if _m(SENSITIVE_READ, path) and not o["write"] and not is_benign_read(o["by"], path):
                behaviour["sensitive_reads"].append(o | {"phase": phase})
            if o["write"] and not _m(ALLOWED_WRITE, path):
                behaviour["writes_outside"].append(o | {"phase": phase})
        for mu in ev["mutations"]:
            target = (mu["args"] or [""])[-1] if mu["call"].startswith(("rename", "symlink")) else (mu["args"] or [""])[0]
            if mu["call"] == "ptrace":
                behaviour["mutations"].append(mu | {"phase": phase})
                findings.append(F("ptrace", "high", "Uses ptrace (anti-debugging or process injection)",
                                  clean(mu["raw"]), mu | {"phase": phase}))
                continue
            if target.startswith("/") and not _m(ALLOWED_WRITE, target):
                behaviour["mutations"].append(mu | {"phase": phase, "target": target})

    # ---- network: sinkhole log
    net_events = []
    netlog = os.path.join(raw_dir, "net.jsonl")
    if os.path.exists(netlog):
        for line in open(netlog, errors="replace"):
            try:
                net_events.append(json.loads(line))
            except ValueError:
                pass

    def step_at(t):
        best = None
        for st in steps:
            if st["start"] <= t <= st["end"]:
                return st
            if st["start"] <= t:   # late event: belongs to the most recent step that had started
                best = st
        return best or (steps[0] if steps else {"phase": "?", "package": "", "package_path": "", "package_repo": ""})

    blobs = []
    dns_seen = {}
    for e in net_events:
        st = step_at(e.get("t", 0))
        e["phase"] = st["phase"]
        where = {"package": st.get("package", ""), "package_path": st.get("package_path", ""),
                 "package_repo": st.get("package_repo", ""), "step": st.get("index")}
        if e["type"] == "dns":
            key = (e.get("name", ""), e["phase"], where["step"])
            if key in dns_seen:
                dns_seen[key]["count"] += 1
                continue
            dns_seen[key] = {"name": e.get("name", ""), "phase": e["phase"], "count": 1} | where
            behaviour["dns"].append(dns_seen[key])
            blobs.append((f"DNS query {e.get('name', '')}", e.get("name", "")))
        elif e["type"] in ("http", "tls", "tcp"):
            raw = base64.b64decode(e.get("raw", "")).decode("latin-1")
            body = base64.b64decode(e.get("body", "")).decode("latin-1") if e.get("body") else ""
            item = {"type": e["type"], "port": e.get("port"), "phase": e["phase"]} | where
            if e["type"] == "http":
                item.update(tls=bool(e.get("tls")), method=e.get("method"), host=e.get("host"), path=clean(e.get("path"), 300),
                            body_preview=clean(body, 400), body_bytes=len(body),
                            user_agent=clean(e.get("headers", {}).get("user-agent", ""), 120))
                label = f"{'HTTPS' if e.get('tls') else 'HTTP'} {e.get('method')} {e.get('host')}{e.get('path', '')[:80]}"
            elif e["type"] == "tls":
                item.update(sni=e.get("sni"), intercepted=e.get("intercepted"))
                label = f"TLS to {e.get('sni')}"
            else:
                item.update(bytes=e.get("bytes"), preview=clean(raw, 200))
                label = f"raw TCP :{e.get('port')}"
            item["label"] = label
            behaviour["network"].append(item)
            blobs.append((label, raw + "\n" + body))

    # leaks also show up in argv of spawned processes (e.g. curl -d $NPM_TOKEN)
    for p in behaviour["processes"]:
        blobs.append((f"command line of {p['path']}", argv_str(p["argv"])))
    leaks = find_leaks(detection_secrets(canaries), blobs)
    leaked_labels = {where for _, where, _ in leaks}
    owner = {}   # blob label -> the step item it came from (for attribution)
    for it in behaviour["network"]:
        if it.get("label"):
            owner.setdefault(it["label"], it)
    for d in behaviour["dns"]:
        owner.setdefault(f"DNS query {d['name']}", d)
    for p in behaviour["processes"]:
        owner.setdefault(f"command line of {p['path']}", p)
    seen = set()
    for name, where, form in leaks:
        if (name, where) in seen:
            continue
        seen.add((name, where))
        behaviour["leaks"].append({"secret": name, "where": where, "form": form})
        sev = "critical" if not where.startswith("command line") else "high"
        src = owner.get(where, {})
        findings.append(Finding("canary-leak", sev, f"Honeypot secret {name} was sent out ({form})", "dynamic",
                                file=src.get("package_path") or "", evidence=clean(where, 300), context="exfiltration",
                                package=src.get("package") or ""))

    # ---- findings from behaviour
    # dependency downloads of its own prebuilt binary: classify first, the DNS lookups follow from them
    dl = {}   # (step, host) -> (severity, reason) of the most suspicious request to that host
    for n in behaviour["network"]:
        if n.get("type") == "http":
            n["download"] = classify_download(n, n.get("label") in leaked_labels)
            if n["download"]:
                k = (n.get("step"), (n.get("host") or "").split(":")[0].lower())
                prev = dl.get(k)
                if not prev or SEV_RANK[n["download"][0]] > SEV_RANK[prev[0]]:
                    dl[k] = n["download"]
            else:
                dl[(n.get("step"), (n.get("host") or "").split(":")[0].lower())] = ("high", None)
    for d in behaviour["dns"]:
        if d["name"]:
            sev = "high" if d["phase"] in ("install", "import") else "medium"
            if len(d["name"]) > 60 or re.search(r"[0-9a-f]{20,}|[A-Za-z0-9]{40,}", d["name"]):
                sev = "critical" if d["phase"] in ("install", "import") else "high"
                title = "DNS query that looks like encoded data (DNS exfiltration)"
            else:
                title = f"Network: resolved a hostname during {d['phase']}"
                known = dl.get((d.get("step"), d["name"].lower().rstrip(".")))
                if known and known[1]:
                    sev = "info" if known[0] == "low" else min(sev, known[0], key=SEV_RANK.get)
                    title = f"Network: resolved {d['name']} for the download below"
            findings.append(F("dns", sev, title, clean(d["name"]), d))
    run_sev = lambda phase, sev: "medium" if phase == "run" else sev  # tools/installers you run may use the net
    for n in behaviour["network"]:
        if n.get("type") == "http":
            ev = clean(f"{n['host']}{n['path']} body={n['body_preview'][:160]}")
            if n.get("download"):
                sev, reason = n["download"]
                findings.append(F("dep-binary-download" if sev == "low" else "dep-artifact-download", sev,
                                  f"{n['package']} {reason} (not checksum-verified by CEA)", ev, n))
                continue
            findings.append(F("http", run_sev(n["phase"], "high"), f"{'HTTPS' if n.get('tls') else 'HTTP'} {n['method']} request during {n['phase']}",
                              ev, n))
        elif n.get("type") == "tls":
            findings.append(F("tls", run_sev(n["phase"], "high"), f"HTTPS/TLS connection during {n['phase']}",
                              clean(f"SNI={n['sni']}"), n))
        elif n.get("family") in ("inet", "inet6") and n["addr"] not in ("127.0.0.1", "::1"):
            findings.append(F("direct-ip", "high", "Connection attempt to a hard-coded IP",
                              clean(f"{n['addr']}:{n['port']} by {argv_str(n['by'])}"), n))
    for r in behaviour["sensitive_reads"]:
        honey = r["path"].startswith(HOME + "/")
        findings.append(F("secret-read", "high", "Read a credential/secret file" + (" (honeypot)" if honey else ""),
                          clean(f"{r['path']} by {argv_str(r['by'])[:120]}"), r))
    honey_paths = {f"{HOME}/{rel}" for rel in HONEY_RELS}
    grouped = {}   # ordinary writes outside the project, grouped per directory
    for w in behaviour["writes_outside"] + behaviour["mutations"]:
        if w.get("call") == "ptrace":
            continue
        path = w.get("target") or w.get("path", "")
        who = argv_str(w["by"])[:120]
        persist = _m(PERSISTENCE, path)
        if persist and w["phase"] == "run":
            findings.append(F("persistence", "medium", "Modifies shell profile / autostart (expected only for "
                              "installers - check what it adds)", clean(f"{path} by {who}"), w))
        elif persist:
            findings.append(F("persistence", "critical", "Persistence: modified shell profile/autostart/ssh keys",
                              clean(f"{path} by {who}"), w))
        elif path in honey_paths and w.get("call", "write") != "write":
            findings.append(F("tamper", "high", f"Tampered with a credential file ({w.get('call', 'write')})",
                              clean(f"{path} by {who}"), w))
        else:
            d = "/".join(path.split("/")[:4])
            g = grouped.setdefault((d, w["phase"], w.get("package", "")),
                                   {"n": 0, "example": path, "by": who, "phase": w["phase"],
                                    "package": w.get("package", ""), "package_path": w.get("package_path", "")})
            g["n"] += 1
    for (d, phase, _), g in grouped.items():
        findings.append(F("write-outside", "low" if phase == "run" else "medium",
                          f"Wrote/changed {g['n']} file(s) outside the project under {d}",
                          clean(f"e.g. {g['example']} by {g['by']}"), g))
    for p in behaviour["processes"]:
        cmd = argv_str(p["argv"])
        if p.get("root") or "<pip-setuptools-caller>" in cmd or "pip/_vendor" in cmd:
            continue   # the sandbox's own step command / pip's internal build helpers
        if SUSPICIOUS_CMD.search(cmd):
            findings.append(F("suspicious-exec", "high", f"Ran a suspicious command during {p['phase']}",
                              clean(cmd, 300), p))
        elif p["phase"] == "import" and not BENIGN_EXE.search(p["path"]):
            findings.append(F("import-exec", "medium", "Spawned a program just by being imported", clean(cmd, 300), p))
        elif not BENIGN_EXE.search(p["path"]):
            findings.append(F("exec", "low", f"Executed a program during {p['phase']}", clean(cmd, 300), p))
    for base, info in behaviour["failed_exec"].items():
        if re.match(r"^(curl|wget|nc|ncat|socat|powershell|pwsh|python|perl|ruby|base64|openssl|ssh|scp|bash|xmrig|crontab|sudo)$", base):
            findings.append(F("missing-tool", "medium", f"Tried to run `{base}` (not available in sandbox)",
                              clean(argv_str(info["argv"]), 300), info))
    for st in final_attempts(steps):
        if st["timed_out"]:
            findings.append(F("timeout", "medium", f"Step '{st['name']}' did not finish (hang, daemon, or slow build)",
                              "", st))
        elif step_status(st) == "failed":
            last = [ln for ln in (st.get("output") or "").splitlines() if ln.strip()][-1:] or [""]
            findings.append(F("step-failed", "info",
                              f"Step '{st['name']}' failed (exit {st['rc']}): what it would have done next was not observed",
                              clean(last[0], 200), st))
    return dedupe(findings), behaviour


SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def F(rule, sev, title, evidence, item):
    """A dynamic finding attributed to the step (and dependency) the event came from."""
    return Finding(rule, sev, title, "dynamic", file=item.get("package_path") or "", evidence=evidence,
                   context=ctx_of(item), package=item.get("package") or "")


# Hosts that serve release artifacts. A body-less GET from a dependency's install script to one of these is
# the "download my prebuilt binary" pattern (esbuild, ffmpeg-static, sharp, puppeteer, playwright, ...).
ARTIFACT_HOSTS = re.compile(r"^(github\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com|"
                            r"codeload\.github\.com|registry\.npmjs\.org|registry\.yarnpkg\.com|nodejs\.org|"
                            r"storage\.googleapis\.com|[\w-]+\.github\.io|cdn\.playwright\.dev|"
                            r"playwright(-[\w]+)?\.azureedge\.net|binaries\.prisma\.sh|download\.cypress\.io|"
                            r"downloads\.sentry-cdn\.com|cdn\.npmmirror\.com)$", re.I)
# well-known downloaders whose artifacts don't live in their own repo's releases: package -> host[/path] prefix
KNOWN_DOWNLOADERS = {
    "puppeteer": ("storage.googleapis.com/chrome-for-testing-public/", "googlechromelabs.github.io/"),
    "chromedriver": ("storage.googleapis.com/chrome-for-testing-public/", "googlechromelabs.github.io/"),
    "playwright": ("cdn.playwright.dev/", "playwright.azureedge.net/"),
    "playwright-core": ("cdn.playwright.dev/", "playwright.azureedge.net/"),
    "sharp": ("github.com/lovell/sharp-libvips/releases/download/",),
    "@prisma/engines": ("binaries.prisma.sh/",),
    "prisma": ("binaries.prisma.sh/",),
    "cypress": ("download.cypress.io/",),
    "@sentry/cli": ("downloads.sentry-cdn.com/",),
    "esbuild": ("registry.npmjs.org/@esbuild/",),
}


def _pkg_name(spec):
    return spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec


def classify_download(n, leaked):
    """(severity, reason) when an HTTP request is a dependency fetching a release artifact, else None."""
    if not n.get("package") or leaked or (n.get("method") or "").upper() != "GET" or n.get("body_bytes"):
        return None
    host = (n.get("host") or "").split(":")[0].lower().rstrip(".")
    path = n.get("path") or ""
    if not ARTIFACT_HOSTS.match(host) or re.search(r"[?&#]", path):
        return None   # query strings could carry data; artifact URLs don't need them
    repo = (n.get("package_repo") or "").lower()
    m = re.match(r"^/([\w.-]+)/([\w.-]+)/releases/download/", path)
    if host == "github.com" and m and repo and f"{m.group(1)}/{m.group(2)}".lower() == repo:
        return ("low", "downloads its own prebuilt binary from its GitHub releases")
    for prefix in KNOWN_DOWNLOADERS.get(_pkg_name(n["package"]), ()):
        if f"{host}{path}".startswith(prefix):
            return ("low", f"downloads its prebuilt binary from {prefix.split('/')[0]} (known downloader)")
    return ("medium", f"downloads a release artifact from {host} (not its own repository)")


def final_attempts(steps):
    """The last attempt of each planned step (pip install has a --no-deps fallback)."""
    last = {}
    for st in steps:
        last[st.get("index", id(st))] = st
    return list(last.values())


def step_status(st):
    if st.get("timed_out"):
        return "timeout"
    rc = st.get("rc")
    out = st.get("output") or st.get("output_tail") or ""
    if st["phase"] in ("run", "import"):
        # a CLI exiting non-zero on --help still ran; not being able to start it at all didn't
        if rc in (126, 127) or "[cea] import failed" in out:
            return "failed"
        return "ok"
    return "ok" if rc == 0 else "failed"


def coverage(step_plan, behaviour, skipped, dynamic_ran):
    """What was planned, what actually ran, and what was skipped (and why)."""
    ran = {s.get("index"): s for s in final_attempts((behaviour or {}).get("steps", []))}
    planned = []
    for i, p in enumerate(step_plan or []):
        st = ran.get(i)
        status = step_status(st) if st else "not run"
        planned.append({"name": p["name"], "phase": p["phase"], "package": p.get("package") or "",
                        "status": status, "rc": st.get("rc") if st else None})
    bad = [p for p in planned if p["status"] != "ok"]
    any_ok = any(p["status"] == "ok" for p in planned if p["phase"] != "setup")
    summary = ""
    if bad:
        summary = (f"{len(bad)} of {len(planned)} sandbox step(s) did not complete: "
                   + ", ".join(f"{clean(p['name'], 60)} ({p['status']})" for p in bad[:4])
                   + (" ..." if len(bad) > 4 else ""))
    return {"planned": planned, "skipped": [{"what": w, "why": y} for w, y in (skipped or [])],
            "partial": bool(dynamic_ran and bad), "any_ok": any_ok or not planned, "summary": summary}


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f.rule, f.title, f.evidence, f.context, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
