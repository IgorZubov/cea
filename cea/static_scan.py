"""Static (no-execution) scan of the fetched source. Runs on the host and only
*reads* files as bytes/text - never imports or executes anything."""
import json
import os
import re
import shlex

from .util import Finding, clean

MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 25000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}

JS = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}
PY = {".py", ".pyw"}
SH = {".sh", ".bash", ".zsh", ".command"}
PS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs"}
TEXT = JS | PY | SH | PS | {".json", ".yml", ".yaml", ".toml", ".cfg", ".txt", ".gyp", ".pth", ""}

LIFECYCLE = ("preinstall", "install", "postinstall")
LIFECYCLE_SRC = LIFECYCLE + ("prepare", "preprepare", "postprepare")

# (id, severity, title, regex, languages, escalate-in-install-context)
RULES = [
    # --- remote code / droppers
    ("pipe-to-shell", "high", "Downloads and pipes into a shell",
     r"(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b", "any", False),
    ("powershell-download", "high", "PowerShell download/encoded command",
     r"(?i)(Invoke-WebRequest|IEX\s*\(|Invoke-Expression|DownloadString|-EncodedCommand|-enc\s+[A-Za-z0-9+/=]{20,}|certutil\s+-urlcache)", "any", False),
    ("reverse-shell", "critical", "Reverse-shell pattern",
     r"(/dev/tcp/\d|nc\s+(-\w+\s+)*-e\s|ncat\s.*-e\s|bash\s+-i\s*>&|socat\s+exec:|pty\.spawn\(['\"]/bin/(ba)?sh)", "any", False),
    ("miner", "critical", "Crypto-miner indicators",
     r"(?i)(xmrig|stratum\+tcp://|cryptonight|coinhive|minexmr|nicehash)", "any", False),
    # --- exfil endpoints
    ("exfil-endpoint", "high", "Known exfiltration/webhook endpoint",
     r"(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site|pipedream\.net|requestbin|ngrok\.io|ngrok-free\.app|burpcollaborator|oastify\.com|interact\.sh|oast\.(fun|pro|live|site|online|me)|transfer\.sh|pastebin\.com/raw|paste\.ee|glitch\.me|workers\.dev/|beeceptor\.com|canarytokens)", "any", False),
    ("raw-ip-url", "medium", "URL with a hard-coded IP address",
     r"https?://(?!127\.0\.0\.1|0\.0\.0\.0|localhost)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "any", True),
    # --- credential / secret access
    ("sensitive-path", "high", "References credential / wallet / browser-secret paths",
     r"(?i)(\.ssh[/\\\\](id_|authorized_keys|known_hosts)|\.aws[/\\\\]credentials|\.git-credentials|\.docker[/\\\\]config\.json|\.kube[/\\\\]config|\.config[/\\\\]gh[/\\\\]hosts|\.pypirc|Login Data|Local Storage[/\\\\]leveldb|nkbihfbeogaeaoehlefnkodbefgpgknn|exodus\.wallet|Electrum[/\\\\]wallets|\.bitcoin[/\\\\]wallet|keychain-db|\.gnupg[/\\\\])", "code", True),
    ("netrc", "low", "References ~/.netrc (common in HTTP clients)",
     r"\.netrc\b", "code", True),
    ("npmrc-token", "medium", "Reads npm auth configuration",
     r"(?i)(\.npmrc|_authToken|NPM_TOKEN)", "code", True),
    ("env-dump", "high", "Collects the whole environment",
     r"(JSON\.stringify\(\s*process\.env\s*\)|Object\.(keys|entries|values)\(\s*process\.env\s*\)|\{\s*\.\.\.process\.env\s*\}|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|json\.dumps\(\s*(dict\()?os\.environ)", "code", True),
    ("env-secrets", "medium", "Reads secret-looking environment variables",
     r"(process\.env|os\.environ|getenv)\W{1,4}(\w*(TOKEN|SECRET|PASSWORD|API_?KEY|PRIVATE|CREDENTIAL)\w*)", "code", True),
    ("fingerprint", "low", "Host fingerprinting (hostname/user/network interfaces)",
     r"(os\.(hostname|userInfo|networkInterfaces)\(\)|platform\.node\(\)|getpass\.getuser\(\)|socket\.gethostname\(\))", "code", True),
    # --- execution
    ("child-process", "low", "Spawns processes",
     r"(require\(\s*['\"](node:)?child_process['\"]\s*\)|from\s+['\"](node:)?child_process['\"]|\bexecSync\(|\bspawnSync\(|subprocess\.(Popen|run|call|check_output|check_call)|os\.(system|popen|exec[lv]p?e?)\()", "code", True),
    ("eval", "medium", "Dynamic code evaluation",
     r"(\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*(compile|base64|zlib|marshal|codecs|bytes|requests|urllib|__import__)|vm\.runIn(New|This)?Context)", "code", True),
    ("decode-exec", "high", "Decodes data and executes it",
     r"((eval|exec|Function)\s*\(\s*(atob|Buffer\.from|base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex)|exec\s*\(\s*__import__\(['\"](base64|zlib|marshal)['\"]\))", "code", False),
    ("network-code", "low", "Makes network requests",
     r"(require\(\s*['\"](node:)?(https?|net|dgram|tls)['\"]\s*\)|from\s+['\"](node:)?(https?|net|dgram)['\"]|\bfetch\s*\(\s*['\"`]https?:|axios\.|urllib\.request|requests\.(get|post|put)|http\.client|socket\.socket\(|urlopen\()", "code", True),
    ("dns-lookup", "low", "Performs DNS lookups (possible DNS exfil channel)",
     r"(dns\.(lookup|resolve\w*)\(|socket\.gethostbyname|dns\.resolver)", "code", True),
    # --- persistence
    ("persistence", "high", "Touches shell profiles / autostart / cron / ssh authorized_keys",
     r"(\.bashrc|\.bash_profile|\.zshrc|\.profile\b|crontab\s|/etc/cron|LaunchAgents|\\{1,2}CurrentVersion\\{1,2}Run|\.config/autostart|systemd/user|authorized_keys)", "code", True),
    # --- obfuscation
    ("hex-escapes", "medium", "Heavy hex-escaped strings (obfuscation)",
     r"(\\x[0-9a-fA-F]{2}){40,}", "code", False),
    ("charcode", "medium", "String built from char codes (obfuscation)",
     r"String\.fromCharCode\(\s*(\d+\s*,\s*){15,}|chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)", "code", False),
    ("big-blob", "medium", "Large encoded blob literal",
     r"['\"`][A-Za-z0-9+/]{400,}={0,2}['\"`]", "code", False),
]

SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def read_json(path):
    with open(path, errors="replace") as fh:
        return json.load(fh)


def read_text(path):
    with open(path, errors="replace") as fh:
        return fh.read()


def bump(sev):
    return SEV_ORDER[min(SEV_ORDER.index(sev) + 1, len(SEV_ORDER) - 1)]


def lang_of(path, head):
    ext = os.path.splitext(path)[1].lower()
    if ext in JS:
        return "js"
    if ext in PY:
        return "py"
    if ext in SH or (ext == "" and head.startswith(b"#!") and b"sh" in head[:40]):
        return "sh"
    if ext in PS:
        return "ps"
    if ext == "" and head.startswith(b"#!") and b"python" in head[:40]:
        return "py"
    if ext == "" and head.startswith(b"#!") and b"node" in head[:40]:
        return "js"
    return "text"


BINARY_MAGIC = {b"\x7fELF": "ELF (Linux)", b"MZ": "PE (Windows)", b"\xcf\xfa\xed\xfe": "Mach-O",
                b"\xca\xfe\xba\xbe": "Mach-O universal", b"\xfe\xed\xfa\xce": "Mach-O", b"\xfe\xed\xfa\xcf": "Mach-O"}


def binary_kind(head):
    for magic, name in BINARY_MAGIC.items():
        if head.startswith(magic):
            if magic == b"MZ" and len(head) < 64:
                return None
            return name
    return None


COMPILED = [(rid, sev, title, re.compile(rx), langs, esc) for rid, sev, title, rx, langs, esc in RULES]


def scan_text(rel, text, lang, install_ctx, findings, ctx_label):
    per_rule = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 20000:
            line = line[:20000]
        for rid, sev, title, rx, langs, esc in COMPILED:
            if langs == "code" and lang not in ("js", "py", "sh", "ps"):
                continue
            m = rx.search(line)
            if not m:
                continue
            if per_rule.get(rid, 0) >= 3:  # keep reports short; count the rest
                per_rule[rid] += 1
                continue
            per_rule[rid] = per_rule.get(rid, 0) + 1
            s = bump(sev) if (install_ctx and esc) else sev
            start = max(0, m.start() - 60)
            findings.append(Finding(rid, s, title, "static", file=rel, line=lineno,
                                    evidence=clean(line[start:m.end() + 80]), context=ctx_label))
    for rid, count in per_rule.items():
        if count > 3:
            findings.append(Finding(rid, "info", f"... {count - 3} more '{rid}' matches", "static",
                                    file=rel, context=ctx_label))
    # whole-file heuristics
    if lang == "js":
        ob = len(re.findall(r"\b_0x[0-9a-f]{4,6}\b", text))
        if ob > 20:
            findings.append(Finding("obfuscator", "high", "javascript-obfuscator style identifiers (_0x...)", "static",
                                    file=rel, evidence=f"{ob} obfuscated identifiers", context=ctx_label))
    if lang in ("js", "py"):
        longest = max((len(l) for l in text.splitlines()), default=0)
        if longest > 5000 and not re.search(r"(\.min\.|/dist/|/build/|/vendor/|bundle)", "/" + rel):
            findings.append(Finding("packed", "low", "Very long line - minified/packed code outside a dist folder",
                                    "static", file=rel, evidence=f"longest line {longest} chars", context=ctx_label))


def walk(root):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            count += 1
            if count > MAX_FILES:
                return
            yield os.path.join(dirpath, fn)


def script_files(cmd, base):
    """Files referenced by a lifecycle command (node x.js, python y.py, sh z.sh)."""
    out = set()
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    for t in toks:
        t = t.strip("'\"")
        cand = os.path.normpath(os.path.join(base, t))
        if cand.startswith(base) and os.path.isfile(cand):
            out.add(os.path.relpath(cand, base))
        elif os.path.isfile(cand + ".js"):
            out.add(os.path.relpath(cand + ".js", base))
    return out


def lifecycle_findings(pj, label, base, findings, is_root):
    scripts = pj.get("scripts") or {}
    keys = LIFECYCLE_SRC if is_root else LIFECYCLE
    install_files = set()
    for k in keys:
        cmd = scripts.get(k)
        if not isinstance(cmd, str):
            continue
        sev = "medium"
        if re.search(r"(curl|wget|\|\s*(ba)?sh|base64|eval|node\s+-e|python[0-9.]*\s+-c|powershell|/dev/tcp|nc\s)", cmd):
            sev = "high"
        if is_root and k.startswith(("pre", "post")) and "prepare" in k:
            sev = "low"
        findings.append(Finding("lifecycle-script", sev, f"`{k}` script runs automatically on install", "static",
                                file=f"{label}package.json", evidence=clean(f"{k}: {cmd}"),
                                context="install" if is_root else "dependency-install"))
        install_files |= script_files(cmd, base)
    if not any(k in scripts for k in LIFECYCLE) and os.path.isfile(os.path.join(base, "binding.gyp")):
        findings.append(Finding("native-build", "low", "Has binding.gyp: node-gyp compiles native code on install",
                                "static", file=f"{label}binding.gyp", context="install"))
    for dep_field in ("dependencies", "optionalDependencies"):
        for name, ver in (pj.get(dep_field) or {}).items():
            if isinstance(ver, str) and re.match(r"^(https?:|git(\+\w+)?:|github:|file:|[\w-]+/[\w.-]+(#.*)?$)", ver):
                findings.append(Finding("url-dependency", "medium", "Dependency fetched from a URL/git instead of the registry",
                                        "static", file=f"{label}package.json", evidence=clean(f"{name}: {ver}"),
                                        context="install"))
    return install_files


def scan_npm_deps(node_modules, findings, skip_name=None):
    """Lifecycle scripts of every installed dependency (they run on `npm install`)."""
    deps = 0
    with_scripts = []
    for dirpath, dirnames, filenames in os.walk(node_modules, followlinks=False):
        parent = os.path.basename(os.path.dirname(dirpath))
        grand = os.path.basename(os.path.dirname(os.path.dirname(dirpath)))
        is_pkg = "package.json" in filenames and (parent == "node_modules" or (parent.startswith("@") and grand == "node_modules"))
        if is_pkg:
            try:
                pj = read_json(os.path.join(dirpath, "package.json"))
            except Exception:
                continue
            if skip_name and pj.get("name") == skip_name and os.path.dirname(dirpath) == node_modules.rstrip("/") \
                    or (skip_name and os.path.relpath(dirpath, node_modules) == skip_name):
                continue  # the target itself (already scanned from src/)
            deps += 1
            label = f"node_modules/{os.path.relpath(dirpath, node_modules)}/"
            before = len(findings)
            files = lifecycle_findings(pj, label, dirpath, findings, is_root=False)
            if len(findings) > before:
                with_scripts.append(f"{pj.get('name')}@{pj.get('version')}")
            for rel in files:
                scan_file(os.path.join(dirpath, rel), label + rel, findings, True, "dependency-install")
        dirnames[:] = [d for d in dirnames if d not in (".bin", ".cache")]
    return deps, with_scripts


def scan_file(path, rel, findings, install_ctx, ctx_label, stats=None):
    try:
        if os.path.islink(path):
            target = os.readlink(path)
            if os.path.isabs(target) or ".." in target.split("/"):
                findings.append(Finding("symlink-escape", "high", "Symlink pointing outside the package", "static",
                                        file=rel, evidence=clean(target), context=ctx_label))
            return
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(64)
            bk = binary_kind(head)
            if bk:
                findings.append(Finding("binary", "medium" if not rel.endswith(".node") else "low",
                                        f"Ships a native executable/library ({bk})", "static",
                                        file=rel, evidence=f"{size} bytes", context=ctx_label))
                return
            if size > MAX_FILE:
                if stats is not None:
                    stats["skipped_large"] += 1
                return
            lang = lang_of(path, head)
            if os.path.splitext(path)[1].lower() not in TEXT and lang == "text":
                return
            fh.seek(0)
            data = fh.read()
        if b"\x00" in data[:4096]:
            return
        text = data.decode("utf-8", "replace")
        if stats is not None:
            stats["scanned"] += 1
        if path.endswith(".pth"):
            if re.search(r"(?m)^\s*import\s", text):
                findings.append(Finding("pth-exec", "high", ".pth file executes code on every Python start", "static",
                                        file=rel, evidence=clean(text[:200]), context=ctx_label))
            return
        scan_text(rel, text, lang, install_ctx, findings, ctx_label)
    except OSError:
        return


def scan(src_root, node_modules=None, ecosystems=(), registry_pkg=False):
    findings = []
    stats = {"scanned": 0, "skipped_large": 0, "files": 0, "dependencies": 0, "deps_with_install_scripts": []}
    install_files = set()

    pj_path = os.path.join(src_root, "package.json")
    if os.path.isfile(pj_path):
        try:
            pj = read_json(pj_path)
            install_files |= lifecycle_findings(pj, "", src_root, findings, is_root=not registry_pkg)
            stats["package"] = {"name": pj.get("name"), "version": pj.get("version"),
                                "scripts": {k: v for k, v in (pj.get("scripts") or {}).items() if k in LIFECYCLE_SRC},
                                "bin": pj.get("bin")}
        except Exception as e:
            findings.append(Finding("bad-manifest", "low", "Unparseable package.json", "static", evidence=str(e)))
    for name in ("setup.py",):
        if os.path.isfile(os.path.join(src_root, name)):
            install_files.add(name)
            findings.append(Finding("setup-py", "info", "setup.py is executed when installing from source", "static",
                                    file=name, context="install"))
    for q in (".npmrc", ".yarnrc", ".yarnrc.yml"):
        qp = os.path.join(src_root, q)
        if os.path.isfile(qp) and not os.path.islink(qp):
            content = read_text(qp)[:4000]
            risky = re.search(r"(?im)^\s*(registry|@[\w-]+:registry|script-shell|git|node-options|ignore-scripts|"
                              r"npmRegistryServer|yarnPath|unsafeHttpWhitelist|_authToken|strict-ssl|cafile|ca)\b", content)
            findings.append(Finding("project-npmrc", "medium" if risky else "info",
                                    f"Ships its own {q}" + (" that changes registry/scripts/TLS settings" if risky else ""),
                                    "static", file=q, evidence=clean(content[:200]), context="install"))

    for path in walk(src_root):
        stats["files"] += 1
        rel = os.path.relpath(path, src_root)
        in_install = rel in install_files
        scan_file(path, rel, findings, in_install, "install" if in_install else "runtime", stats)

    if node_modules and os.path.isdir(node_modules):
        stats["dependencies"], stats["deps_with_install_scripts"] = scan_npm_deps(
            node_modules, findings, skip_name=(stats.get("package") or {}).get("name"))

    # file-level combo: decoding + eval in the same file
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, set()).add(f.rule)
    for file, rules in by_file.items():
        if {"big-blob", "eval"} <= rules or {"hex-escapes", "eval"} <= rules:
            findings.append(Finding("blob-eval", "high", "Encoded blob + dynamic evaluation in the same file",
                                    "static", file=file, context="install" if file in install_files else "runtime"))
        if {"sensitive-path", "network-code"} <= rules or {"env-dump", "network-code"} <= rules:
            inst = file in install_files
            findings.append(Finding("collect-and-send", "critical" if inst else "medium",
                                    "Reads secrets AND talks to the network in the same file",
                                    "static", file=file, context="install" if inst else "runtime"))
    stats["install_files"] = sorted(install_files)
    return findings, stats
