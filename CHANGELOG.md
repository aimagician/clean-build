# Changelog

All notable changes to clean-builder are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-15

First public release.

### Added

- `clean-builder` CLI for offline, fully logged builds of any npm, pnpm or yarn
  project in an Incus container: `create`, `provision`, `build`, `watch`,
  `analyze`, `proxy`, `status`, `dashboard`, `logs`, `lockdown`, `start`,
  `stop` and `destroy`.
- Network enforcement through an Incus bridge ACL with a logged default-reject:
  lockdown (DHCP only) for `build`/`watch`, and a temporary DNS + HTTP(S)
  profile for `provision`, with private ranges rejected in every profile.
- Per-phase egress captures from the host kernel log and per-process `strace`
  attribution reports, kept in a host-only `logs/` folder the build cannot
  reach.
- Output-integrity scan after every build: writes outside the build output are
  flagged as ISSUE, suspicious patterns in the output as REVIEW, with a
  `logs/STATUS.md` dashboard across projects.
- Optional AI triage of the logs through OpenRouter, with a rubric that treats
  log content as untrusted and exit codes a cron job can gate on.
- `example/` vite project and the `netprobe` offline regression check.
- Project infrastructure: CI (ShellCheck, Ruff, unit tests for the `analyze/`
  helpers), security policy, contributing guide, code of conduct, issue and
  pull request templates, CODEOWNERS and Dependabot configuration.

[Unreleased]: https://github.com/aimagician/clean-build/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aimagician/clean-build/releases/tag/v0.1.0
