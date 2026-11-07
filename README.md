# CEA — ChEck Anything

**Run any npm package, PyPI package, git repo, archive or `curl | sh` installer in a throw-away
sandbox, and get a local report on whether it's safe to use:** what it runs, which network
requests it makes, which files and secrets it touches.

It's built for humans *and* for LLM agents: it ships as a **Claude Code skill/plugin**, has a
`--json` mode, and needs only `python3` + Docker/Podman (no pip dependencies).

```text
$ cea check npm:some-package
cea ▸ fetching target + dependencies (scripts disabled)...
cea ▸ static scan...
cea ▸ detonating in sandbox: npm install scripts (all packages), import some-package ...

  ☠️  MALICIOUS - do not install. Behaviour consistent with credential theft / backdoor.
  score 100/100 · 17 critical, 12 high, 6 medium
   🟥 [dynamic/exfiltration] Honeypot secret NPM_TOKEN was sent out (encoded): DNS query 6e706d5f43...dns.cea-test.invalid
   🟥 [dynamic/exfiltration] Honeypot secret AWS_SECRET_ACCESS_KEY was sent out (encoded): HTTPS POST collector.cea-test.invalid/c
   🟥 [dynamic/install] Persistence: modified shell profile/autostart/ssh keys: /home/dev/.bashrc by node scripts/setup.js
   🟧 [dynamic/install] Read a credential/secret file (honeypot): /home/dev/.ssh/id_rsa by node scripts/setup.js
   ...
  report: ./cea-reports/npm_some-package-20261107-101342/report.md  (10.4s)
```

(Output from the bundled test fixture `tests/fixtures/evil-npm`, which mimics a real npm stealer.)

## Install

```bash
git clone https://github.com/IgorZubov/cea && cd cea && ./install.sh
cea doctor
```

`install.sh` symlinks `cea` into `~/.local/bin` and the skill into `~/.claude/skills/cea`.

**As a Claude Code plugin** (adds the skill and a `/cea:check` command):

```text
/plugin marketplace add IgorZubov/cea
/plugin install cea@cea
```

Then just ask Claude *"is `npm:some-mcp-server` safe to install?"*, or run `/cea:check pypi:requests`.

Requirements: Python 3.10+, and Docker or Podman running. The first check builds the sandbox image
(Ubuntu 24.04 + node 22 + python3 + git + curl + strace, ~125 MB compressed), which takes about a
minute. After that, checks take 5–30 s.

## Usage

```bash
cea check npm:left-pad@1.3.0              # npm registry (a bare name means npm too)
cea check pypi:requests==2.32.3           # PyPI (or: cea check requests==2.32.3)
cea check github:owner/repo#v1.2.0        # any https git URL works too
cea check https://example.com/install.sh  # a script/archive from a URL ("curl | sh" installers)
cea check ./some/dir                      # local project
cea check ./pkg-1.0.0.tgz                 # local npm tarball / .whl / sdist / script

cea check npm:some-cli --run "npx --no-install some-cli --help"   # also run something after install
cea check npm:pkg --ci --wait 30          # look like CI; linger 30 s after import (delayed payloads)
cea check npm:pkg --json                  # summary as JSON on stdout (for agents/scripts)
cea check npm:pkg --fail-on unsafe        # exit 1 if verdict is UNSAFE or worse (CI gate)
cea check ./dir --static-only             # no container: static scan only
```

| Option | Meaning |
|---|---|
| `--run CMD` | extra command run in the sandbox after install (CLI, MCP server, tests...) |
| `--timeout S` | per-step timeout, default 180 |
| `--wait S` | seconds to linger after import, default 5 |
| `--ci` | sets `CI=true`, `GITHUB_ACTIONS=true` ... |
| `--no-import` | don't import/require the package |
| `--out DIR` | reports dir (default `./cea-reports`, or `$CEA_REPORTS`) |
| `--keep-work` | keep the fetched untrusted files in `<report>/work` |
| `--engine docker\|podman` | pick the engine (auto-detected) |
| `--runtime runsc` | use gVisor (or another OCI runtime) for kernel-level isolation |
| `--memory`, `--cpus` | sandbox limits (3g / 2) |

Other commands: `cea doctor` (verify the setup) and `cea build [--build-arg NODE_IMAGE=... --network host]`
(rebuild the image, for example from a registry mirror).

## Verdicts

| Verdict | Meaning |
|---|---|
| ☠️ `MALICIOUS` | planted secrets left the sandbox, persistence, or another critical runtime behaviour |
| 🛑 `UNSAFE` | network calls / secret-file reads / suspicious commands during install or import, obfuscated or dropper code |
| ⚠️ `REVIEW` | nothing clearly malicious, but some behaviour needs a human look |
| ✅ `LIKELY_SAFE` | clean sandbox run, only ordinary capabilities (an install script that behaved, HTTP client code...) |
| ❔ `INCOMPLETE` | analysis couldn't fully run |

Each check writes `report.md` (for humans and LLMs), `report.json` (everything, machine-readable) and
`raw/` (strace logs, sinkhole log, step output) into `cea-reports/<target>-<timestamp>/`.

## How it works

```text
             ┌────────────── host ──────────────┐
 target ───► │ 1. FETCH   container, network ON │  npm install --ignore-scripts, wheel-only pip download,
             │    (nothing from target runs)    │  shallow git clone (no hooks/submodules), .npmrc quarantined
             │                                  │
             │ 2. STATIC  host reads files only │  lifecycle scripts, obfuscation, blob+eval, secret paths,
             │                                  │  exfil endpoints, reverse shells, miners, binaries, .pth ...
             │                                  │
             │ 3. DETONATE  container:          │  --network none, read-only rootfs, --cap-drop ALL,
             │    install → import → --run      │  no-new-privileges, non-root, pids/mem/cpu limits,
             │    all under strace -f           │  target copied into tmpfs, /work mounted read-only
             │    ├─ honeypot secrets           │  fake AWS/GitHub/npm/OpenAI tokens in env, ~/.ssh, ~/.aws,
             │    │                             │  ~/.npmrc, ~/.git-credentials, wallets, browser data...
             │    └─ sinkhole (127.0.0.1)       │  fake DNS answers everything → logs HTTP, intercepts TLS
             │                                  │  with a sandbox-only CA, records raw TCP
             │ 4. REPORT                        │  processes, DNS/HTTP/TLS, secret reads, writes outside the
             └──────────────────────────────────┘  project, leaked canaries (plain/base64/hex/url/base32)
```

What it detects:

- **What runs:** every `execve` with full argv and its parent, during install, import and run.
  Lifecycle scripts of the target *and of every dependency*. Tools it tried to run that aren't there.
- **Network:** every DNS name (including DNS-tunnel exfiltration), HTTP method/host/path/body,
  HTTPS bodies (the sandbox trusts its own throw-away CA), TLS SNI when the client pins certificates,
  direct-IP connection attempts, probes of `docker.sock`.
- **Secrets:** reads of credential files (package managers reading their own config are ignored).
  Exfiltration of planted canary secrets, even when encoded.
- **Files:** writes and renames outside the project/temp/cache dirs, shell-profile/cron/autostart
  persistence, tampering with credential files, `ptrace`.
- **Static:** `curl | sh`, PowerShell droppers, reverse shells, miners, webhook/paste/tunnel exfil
  endpoints, `eval(atob(...))`-style loaders, javascript-obfuscator output, big encoded blobs, env
  dumping, `.pth` auto-exec, symlinks/archive members escaping the package, URL dependencies,
  shipped native binaries.

## Security model & limitations

- The untrusted code runs **only** in the detonation container, which has no network, no capabilities
  and a read-only root, and sees nothing of the host except a read-only copy of the fetched files.
  Results come back as a tarball on stdout, and no writable host directory is shared.
  For stronger isolation use `--runtime runsc` (gVisor) or run CEA in a VM.
- The fetch stage has network access but runs no target code (`--ignore-scripts`, wheels only, no git
  hooks, the project's `.npmrc`/`.yarnrc` is quarantined). If your HTTPS proxy is on `localhost`, fetch
  uses host networking.
- Dynamic analysis observes **one** run. Code gated on dates, real server responses, specific
  OS/CPU, or sandbox detection (e.g. checking `TracerPid`) may stay dormant. A clean result is evidence,
  not proof.
- Only install, import and `--run` are exercised. Code paths that are never called are covered only by
  the static rules, which are heuristics.
- Python sdists can't be resolved offline without executing them. Their dependencies are installed
  only when declared in `pyproject.toml`/`requirements.txt` or available as wheels.
- Report content quoted from the target is sanitised (control chars, ANSI and bidi escapes, backticks)
  and labelled untrusted, so an LLM reading the report doesn't take orders from the package.

## Development

```bash
python3 -m unittest discover -s tests          # fast unit tests, no container
CEA_E2E=1 python3 -m unittest tests.test_e2e   # real sandbox runs against the fixtures
```

`tests/fixtures/` holds harmless imitations of real attacks (npm postinstall stealer, phoning-home
`setup.py`, `curl | sh` key grabber). They only target the reserved `.invalid` TLD.

Layout: `cea/cli.py` (orchestration), `cea/target.py`, `cea/static_scan.py`, `cea/trace_parse.py`,
`cea/dynamic.py` (honeypot + behaviour analysis), `cea/report.py`, `cea/sandbox.py` (engine wrapper),
`cea/sandbox/` (Dockerfile, in-container `agent.py`, `sinkhole.py`, `py_import.py`),
`skills/cea/SKILL.md`, `.claude-plugin/`.

## License

MIT
