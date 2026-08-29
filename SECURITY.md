# Security Policy

`clean-builder` exists to build **untrusted** Node/npm projects offline while
logging every network attempt. Because its whole purpose is to contain
potentially malicious build code, its own security posture matters. This
document states what it is designed to resist, what it does not claim to stop,
and how to report a vulnerability.

## Threat model

**In scope — what clean-builder is designed to resist:**

- A malicious npm project (package scripts, `node_modules`, postinstall hooks,
  or source) attempting to reach the network during an offline `build`/`watch`.
- That code attempting to reach the host, other containers, or LAN hosts.
- That code attempting to **erase or forge the evidence** (the `strace` trace
  or the per-phase logs) to hide its tracks.
- A concurrent phase racing the single shared network ACL to open a window
  during an offline build.

**Out of scope — what it does not claim to stop:**

- A container escape via a kernel or Incus vulnerability. clean-builder relies
  on Incus/kernel isolation; it is not a hardened sandbox against 0-day escapes.
- The `provision` (dependency install) phase, which runs online **by design**.
  Its network activity is logged, not blocked — review the install logs.
- Exfiltration through a `proxy` device you added for `watch` — a host-mediated
  tunnel that bypasses the bridge ACL by design. Remove it when you are done.
- The build reading secrets that you placed in the mounted project directory.
- Attacks on the model behind the optional `analyze` step. Log content is
  untrusted; the rubric mitigates prompt injection but does not eliminate it,
  and log contents are sent to the OpenRouter model you choose.

## What holds

- **Network enforcement** is a host-side Incus bridge ACL with a logged
  default-reject. Container code (running as the build user, uid 1000) cannot
  change it. `build`/`watch` verify the *enforced* properties before running —
  default-reject on, egress logging on, ACL in lockdown — and refuse to run if
  the network is not locked down or the kernel egress log is unreadable.
- **Evidence integrity.** `./logs` is host-only and never mounted into the
  container. The `strace` trace is written by root to a root-only container
  directory (the build itself runs dropped to uid 1000) and pulled out per
  phase, so a build can neither erase nor forge its own attribution, and there
  is no shared writable directory in which to stage a symlink attack.
- **Serialization.** Phases hold a host-side lock, so the online `provision`
  window cannot start in the middle of an offline `build`.

See the README's "Security model & limitations" section for the full
discussion, including the best-effort nature of `strace` attribution.

## Verifying the offline guarantee yourself

The bundled probe deliberately tries to reach the network during an offline
build — by hostname (the DNS path) and by raw IP (no DNS). Both must be blocked:

```bash
./clean-builder build example netprobe
```

It exits non-zero if either path reaches the network, so you can wire it into
CI as a regression check.

## Reporting a vulnerability

Please report security issues **privately** — do **not** open a public issue
for a vulnerability.

- **Preferred:** use GitHub's private vulnerability reporting on this
  repository — the **Security** tab → **Report a vulnerability**.
  (Enable it under *Settings → Code security and analysis → Private
  vulnerability reporting* if it is not already on.)
- Include the affected version or commit, a description of the issue, and
  ideally a minimal reproduction — for example, a project that demonstrates the
  bypass.

You can expect an acknowledgement of your report. Confirmed issues will be
prioritized; please allow a reasonable window for a fix before public
disclosure.
