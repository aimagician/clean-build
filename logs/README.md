# logs

Everything the builder produces lands here. This folder is **host-only** — it
is deliberately never mounted into the container, so a build cannot tamper with
its own trace or overwrite earlier evidence (traces are written by root inside
the container and pulled out per phase). **One subfolder per project** — named
`<basename>-<8-char path hash>` (e.g. `web-3f9c2a1b`) so two projects that
happen to share a directory name never mix their logs — plus `builder/` for
project-independent work like the toolchain install. Only this README is
tracked.

Inside each project folder:

- `project-path` — the full host path of the project this folder belongs to
- `install-*.log` — install transcript (the only online phase)
- `<script>-*.log` — offline build/test transcripts (`build-assets-*`, …;
  a script literally named `install` or `toolchain` is logged as
  `offline-install`/`offline-toolchain` — those labels are reserved for the
  real online phases)
- `egress-<phase>-*.log` — packets that left the container during that
  phase, from the host kernel log (what left, and where to)
- `net-<phase>-*.log` — per-process network report from strace (**who**
  tried to connect: the exact command behind every attempt and its result)
- `net-<phase>.trace` — raw strace output, kept only if report generation
  failed
- `analysis-*.md` — saved AI verdicts (`./clean-builder analyze`)

Triage rule of thumb: **offline-phase egress files must be empty and
offline-phase net reports must show no remote attempts.** Any remote line in
a build/watch phase is a finding — the net report names the responsible
process. The full rubric lives in the analyzer (`analyze/analyze_logs.py`);
`./clean-builder analyze --project <name>` reviews one project,
plain `analyze` sweeps the newest logs of all of them — cron it for daily
inspection.
