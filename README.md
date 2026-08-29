# clean-builder

An offline Node build container that **logs every internet attempt** — point
it at any vite/npm project.

Dependency installs run in a short, fully-logged internet window. Builds and
dev servers run with the network locked down, and anything that *tries* to
leave the container anyway is rejected **and recorded**. An AI analyzer
(OpenRouter) reads the logs and tells you whether anything smells wrong —
supply-chain attacks in npm packages usually reveal themselves exactly there:
a postinstall script phoning home, a "build tool" fetching a binary, a dev
server leaking telemetry.

## Requirements

- **[Incus](https://linuxcontainers.org/incus/)** with a working `images:`
  remote (this is the enforcement engine — see [Why Incus](#future-work-a-docker-backend)).
- **`python3`** on the host (standard library only — nothing to `pip install`).
- Run as a **normal user** with `incus` access — never as root.
- An **OpenRouter API key** only if you use the optional `analyze` step.

## Quick start

```bash
./clean-builder create                 # one-time: network, ACL, container, node toolchain
./clean-builder provision example      # npm install WITH internet — every packet logged
./clean-builder build example          # vite build, NO internet
./clean-builder watch example          # vite dev server, NO internet (q + Enter quits)
./clean-builder analyze                # AI verdict over the logs
```

`example/` is a minimal vite app for smoke-testing; substitute any project
directory that has a `package.json`.

`build` and `watch` accept an optional script name to run a specific
`package.json` script instead of the defaults (`build`, and vite/`dev`
respectively) — useful when a project's full build needs tools the container
doesn't have, or its watcher isn't vite:

```bash
./clean-builder build ../myapp build:assets          # sass + esbuild only
./clean-builder build ../myapp test:contact-worker   # node --test, offline
./clean-builder watch ../myapp watch                 # project's own watcher
```

## Shell shortcut (`cb`)

Typing `./clean-builder` from the repo directory gets old. Drop a small wrapper
into your shell config so you can call it from anywhere as `cb`:

```bash
# ~/.bashrc  (or ~/.zshrc)
export CB_HOME="$HOME/clean-builder"        # where you cloned this repo
cb() { "$CB_HOME/clean-builder" "$@"; }
```

Reload (`source ~/.bashrc`), then drive it from any directory with the project
path as an argument:

```bash
cb create
cb provision ~/code/myapp                   # install deps (online, logged)
cb build     ~/code/myapp                   # offline build
cb build     ~/code/myapp build:assets      # a specific script, offline
cb watch     ~/code/myapp                   # offline dev server
cb analyze   --project myapp
```

The project path is just an argument, so from inside a project you can run
`cb build .` to build the current directory.

## How offline enforcement works

The container **keeps its default route on purpose**. Without a route,
internet attempts die inside the container (ENETUNREACH) before a packet
exists — invisible to any network log. With the route up, every attempt
becomes a real packet at the isolated bridge (`cb0`), where an Incus ACL
decides and logs:

- **Lockdown** (the resting state): only DHCP may leave. Everything else
  hits the network's *logged default-reject*.
- **Provision**: a temporary ACL profile additionally allows DNS to
  1.1.1.1/1.0.0.1 and TCP 80/443 — all logged — and is always restored,
  even on failure.
- `build`/`watch` refuse to start unless the network is actually enforcing:
  the default egress action is `reject`, egress logging is on, and the ACL
  holds exactly one egress rule — the DHCP allow. They also set
  `npm_config_offline` / `COREPACK_ENABLE_NETWORK=0` so honest tools fail
  fast instead of hanging, and clear any leftover `proxy` device (see below)
  before an offline build.
- Private ranges (your host, other containers) are rejected in *every*
  profile.

Package manager is detected per project: `pnpm-lock.yaml` → pnpm (corepack),
`yarn.lock` → yarn (corepack), otherwise npm (`npm ci`; a missing
`package-lock.json` is generated during provision with lifecycle scripts
disabled).

## Logs (`./logs`, host-only — never mounted into the container)

One folder per project, named `<basename>-<8-char path hash>`
(`logs/myapp-3f9c2a1b/`, `logs/example-a41b02cd/`, … — the hash keeps
same-named projects apart, and each folder's `project-path` file records the
full host path; builder-level work like the toolchain install goes to
`logs/builder/`):

| file | contents |
|---|---|
| `install-<stamp>.log` | full install transcript |
| `<script>-<stamp>.log` | offline build/test transcript for that script |
| `egress-<phase>-<stamp>.log` | every packet that left during that phase |
| `net-<phase>-<stamp>.log` | **who** tried to connect: per-process report of every network syscall (strace), naming the exact command behind each attempt |
| `analysis-<stamp>.md` | saved AI verdicts |

Egress lines come from the host kernel log (nftables):

    cb0-egress[-<rule#>] ... SRC=10.23.23.x DST=<ip> PROTO=TCP DPT=<port>

No rule number = the default REJECT fired. **Offline-phase egress files must
be empty and offline-phase net reports must show no remote attempts** — and
when they don't, the net report tells you which process is to blame. Prove
the pipeline works any time with the deliberate offender:

```bash
./clean-builder build example netprobe   # tries to fetch — must come back blocked
```

The probe tries **two** escape routes — by hostname (the DNS path) and by raw
IP (skipping DNS, exercising raw TCP egress) — and exits non-zero if *either*
reaches the network. That makes it a scriptable regression check you can wire
into CI, not just a line to spot in the transcript.

## Output integrity — what did the build *write*?

Blocking the network stops a dependency from phoning home, but a malicious build
can still **inject a backdoor into the output you ship** or tamper with your
source — the build legitimately writes to the project tree, which is on your
host. So after every `build`, clean-builder diffs the project tree
**host-side** (the build can't forge it) and tells you exactly what changed:

- **Layer 1 — writes outside the build output.** A clean build only touches its
  output dirs (`dist/`, `build/`, `.svelte-kit/`, `.vite/`, …). If it writes to
  `src/`, a config file, a lockfile, or into `node_modules/`, that's the
  injection/tampering signature — reported as an **ISSUE**.
- **Layer 2 — suspicious patterns in the output.** The files that changed are
  scanned for high-signal markers that shouldn't appear in a clean bundle:
  `sendBeacon`/`WebSocket`, hardcoded IPs, `eval`/`atob`/`new Function`,
  `document.cookie`/`process.env`/`clipboard` access, and wallet-drainer
  strings. Hits are reported as **REVIEW** (minified bundles can trip these, so
  they need eyes — ideally a diff against a trusted build).

Each build writes a `changeset-<stamp>.md` to its log folder with the verdict
(`✓ CLEAN` / `▲ REVIEW` / `✗ ISSUE`) and the exact files/patterns, and the
terminal prints a one-line verdict. `CB_NO_SCAN=1` skips the diff for very large
repos.

### At-a-glance dashboard

One file shows the latest verdict for every project:

```bash
./clean-builder dashboard      # regenerates and prints logs/STATUS.md
```

```
| project              | last build       | verdict   | unexpected writes | scan hits |
|----------------------|------------------|-----------|-------------------|-----------|
| myapp-3f9c2a1b       | 2026-10-01T02:25 | ✓ clean   | 0                 | 0         |
| othersite-a41b02cd   | 2026-09-30T18:10 | ✗ ISSUE   | 2                 | 0         |
```

`logs/STATUS.md` is rewritten after every build, so a quick glance tells you
which project needs attention. (`✗ ISSUE` = files changed outside the build
output — look first.)

> **Honest limits:** this catches source/`node_modules` tampering, time-bombs,
> and the common exfil/drainer patterns. It does **not** catch a deterministic
> payload written only into `dist/` that matches a baseline you don't have yet,
> and the `node_modules` tripwire is mtime-based (a build could backdate to
> evade it). Treat it as a strong tripwire, not a proof — pin/audit deps and
> diff output against a trusted CI build for the rest.

## AI analysis

`analyze` is an optional triage step. It reads the logs you already have on
disk and asks a model to flag anything that looks like a supply-chain problem —
a postinstall script that phoned home, a "build tool" that fetched a binary, a
dev server leaking telemetry.

```bash
export OPENROUTER_API_KEY=sk-or-...
./clean-builder analyze                        # newest logs across ALL projects
./clean-builder analyze --project myapp        # one project's folder only
./clean-builder analyze --model google/gemini-2.5-flash --last 20
./clean-builder analyze --dry-run              # print the exact prompt, no API call
```

### How it works — and where your data goes

The logs are **already on the host**: `./logs` is host-only, and every file
(transcripts, egress captures, net reports) is written host-side as each phase
runs. So `analyze` never touches the container — there is no "copy the logs out
with `incus`" step, because there is nothing left to copy:

1. It runs on the **host** as a small standard-library Python script
   (`analyze/analyze_logs.py`) — no `incus exec`, no container access.
2. It reads the newest log files straight from `./logs`.
3. It sends them, wrapped in a strict triage rubric, in **one HTTPS request to
   the OpenRouter API** (`https://openrouter.ai`) using your
   `OPENROUTER_API_KEY`.
4. The model returns a JSON verdict, printed and saved to
   `logs/<project>/analysis-<stamp>.md`.

> The *only* time `clean-builder` copies anything out of the container is the
> per-phase `incus file pull` of the `strace` trace — and that happens when the
> phase ends, not during `analyze`. By analysis time, every log is a plain file
> on your host.

### What gets sent

`analyze` uploads the **contents of your log files** — build transcripts
included — to OpenRouter and the model you pick. Point `CB_ANALYZE_MODEL` (or
`--model`) at a provider you are comfortable handing that data to. If build
logs must never leave the machine, skip `analyze` and read the `egress-*` and
`net-*` reports directly; a local-model backend is on the roadmap.

The prompt treats all log content as **untrusted data** — if a transcript tries
to talk the model into a "clean" verdict (`ignore previous instructions…`),
that attempt is itself reported as a finding.

### Output

A strict JSON verdict — `clean` / `suspicious` / `critical`, plus
evidence-quoting findings. Exit code `0` = clean, `1` = findings, `2` = error,
so a nightly `cron` job can gate on it.

## Reaching a local API during watch

Offline means your dev server can't call a backend on another container
either. Instead of opening the network, forward through the host:

```bash
./clean-builder proxy add 8801 10.10.10.170:8801
```

Now `127.0.0.1:8801` *inside* the builder reaches that backend via an Incus
proxy device (host-mediated — the ACL still rejects all private-range
traffic). Point your vite `server.proxy` at `http://127.0.0.1:8801`.

## Security model & limitations

Be clear-eyed about what this does and doesn't promise. It **raises the bar
and creates an audit trail** — a strong, logged offline *default* that catches
the common supply-chain patterns (postinstall phoning home, a "build tool"
fetching a binary, telemetry). It is **not** an airtight sandbox against code
that is actively trying to defeat *it* specifically.

What holds well:

- **Network enforcement** is done by the Incus bridge ACL (a host-side,
  kernel-level default-reject), which container code running as the build user
  cannot change. During `build`, egress to the internet and to private ranges
  is rejected and logged.
- `build` verifies the *enforced* properties (default-reject + logging on)
  before running, not just a rule count, and refuses to run if it cannot read
  the kernel log it depends on for evidence.
- **The log store is out of the build's reach.** `./logs` is host-only —
  never mounted into the container. The `strace` trace is written by root to a
  root-only container directory (the build runs dropped to uid 1000) and pulled
  out per phase, so the build can neither erase nor forge its own attribution,
  and there is no shared writable directory to stage a symlink attack in.
- **Phases are serialized** by a host-side lock, so a `provision` (which opens
  the bridge) can't start mid-`build` and open a window the build could use.
  A second phase waits for the first to finish; `watch` holds the lock for its
  whole session.

Known limitations:

- **strace attribution is still best-effort.** A build can print misleading
  content to its own transcript, and evade the trace itself (io_uring, argv
  spoofing). The trace can no longer be *erased*, but treat the kernel egress
  log as the authoritative signal and the `net-*` report as attribution.
- **`proxy add` opens a host-mediated tunnel that bypasses the bridge ACL**
  and is therefore unlogged. `build` clears proxy devices first, but `watch`
  uses them by design — while a proxy device exists, a `watch` phase has a
  network path the egress log won't show. Remove it (`proxy remove <port>`)
  when you're done.
- **`provision` runs online by design.** Lifecycle scripts execute with the
  network open (logged). The offline guarantee covers `build`/`watch`, not
  dependency installation — review the install egress/transcript.
- **The AI verdict is advisory.** It reads attacker-influenced text; the
  rubric treats logs as untrusted, but trust the raw egress log over the
  model's summary.
- Run this as a **normal user, never root** (the uid mapping would make
  container writes root-owned on the host).

## Other commands & tuning

```bash
./clean-builder status      # container, ACL profile, current project mount
./clean-builder dashboard   # at-a-glance output-integrity status of all projects
./clean-builder logs        # newest files + live kernel entries
./clean-builder lockdown    # force the resting ACL by hand
./clean-builder start       # start the builder by hand
./clean-builder stop        # stop it now (frees memory)
./clean-builder destroy     # remove the container (network/ACL stay)
```

**Idle by default.** Each phase **stops the container when it finishes**, so an
idle builder uses no memory — and any process a build left running is killed
rather than surviving to the next phase (a small security win). `build` runs
once then stops; `provision` starts, installs, and stops; `watch` runs until
you quit, then stops. The toolchain and `node_modules` persist, so the next
phase just restarts the container (~30 s cold start on a slow host). For rapid
back-to-back builds, set `CB_KEEP_RUNNING=1` to leave it up, or `./clean-builder
stop` / `start` by hand.

Tunables (env): `CB_INSTANCE`, `CB_IMAGE`, `CB_NETWORK`, `CB_PORT` (dev
server port, default 5173, must be in the ingress-allowed range 5170-5179),
`CB_CPU`, `CB_MEMORY`, `CB_KEEP_RUNNING` (`1` = don't auto-stop),
`CB_ANALYZE_MODEL`, `CB_APP_URL` (OpenRouter attribution URL). Set these
yourself; `CB_PORT` is validated because it is passed into an in-container
command.

> **Why it stays safe even during provision:** Incus evaluates ACL rules as
> **reject-over-allow, regardless of order**, so the private-range reject always
> wins over the broad `80/443` allow — your host and other containers stay
> unreachable even while the internet window is open.

## Future work: a Docker backend

The CLI is mostly backend-agnostic (exec/mount/proxy map to `docker exec`,
`-v`, published ports or socat). The one piece Docker does not provide is
the heart of this design: **network ACLs with logged rejects**.
`--network none` and `--internal` block traffic but record nothing — the
exact blindness this tool exists to avoid. A `CB_BACKEND=docker` mode would
recreate it with host nftables/iptables rules on the `DOCKER-USER` chain
(LOG + REJECT on the builder's bridge, toggled between lockdown and
provision profiles), at the cost of:

- sudo for every phase switch (Incus needs none),
- global host firewall state instead of a named per-network ACL object,
- Docker Desktop/WSL networking quirks if not on native dockerd.

Estimated at roughly a day of careful work, most of it testing the firewall
toggling. Until then: Incus is the supported backend.

## Tested with

The `analyze` step is model-agnostic — any OpenRouter model works. The triage
rubric is being validated against Claude Opus 4.8, GLM 5.3, OpenAI SOL (~5.6),
and Grok 4.6. Exact model versions are still to be re-verified.

## License

[MIT](LICENSE) © Ivan Popov
