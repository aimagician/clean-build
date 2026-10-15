# Contributing to clean-builder

Thanks for helping. clean-builder runs untrusted build code, so changes that
touch enforcement get a careful review — but documentation fixes, new
detection patterns, tests and bug reports are just as welcome.

## Ground rules

- **Security issues are reported privately**, never in a public issue or pull
  request — see [SECURITY.md](SECURITY.md).
- **Keep the runtime dependency-free.** The CLI is a single Bash script and the
  helpers in `analyze/` use only the Python standard library (3.9+). Please
  don't add packages to the runtime path.
- **Never weaken the offline guarantee quietly.** If a change touches the ACL
  profiles, `assert_lockdown`, `run_traced`, log handling, the output scan or
  the analyzer rubric, explain in the pull request why the guarantees in
  [SECURITY.md](SECURITY.md) still hold.
- **One concern per pull request** — small, focused changes are the easiest to
  review and to revert.

## Development setup

You need the same things as a user (see the README's
[Requirements](README.md#requirements)): a Linux host with Incus, `python3`,
and a normal, non-root user with Incus access. Fork the repository on GitHub,
then:

```bash
git clone https://github.com/<your-user>/clean-build.git
cd clean-build
./clean-builder create
```

## Before you open a pull request

1. **Run the static checks and unit tests** — the same ones CI runs:

   ```bash
   bash -n clean-builder
   shellcheck --severity=warning clean-builder
   python3 -m py_compile analyze/*.py
   ruff check analyze/ tests/
   python3 -m unittest discover -s tests -v
   ```

   The unit tests cover the `analyze/` helpers and need neither Incus nor
   network access.

2. **Run the offline regression check** if you touched `clean-builder`:

   ```bash
   ./clean-builder provision example
   ./clean-builder build example            # review the output-changeset verdict it prints
   ./clean-builder build example netprobe   # both escape routes must come back "blocked"
   ```

   `netprobe` must end with `both paths blocked — the offline contract held`.
   Its `logs/example-*/egress-netprobe-*.log` records the rejected attempts, and
   the matching `net-netprobe-*.log` should attribute them to
   `node netprobe.mjs`.

3. **Update the docs** — README and SECURITY.md when behavior or guarantees
   change, and add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).

4. **Check the diff for anything private**: secrets, internal hostnames or IP
   addresses, and real log output from your own projects.

## Commits and pull requests

- Write commit subjects in the imperative mood ("Add pnpm store cache to
  provision").
- Link the issue a pull request resolves ("Fixes #12").
- CI must pass. Workflows on pull requests from forks run only after a
  maintainer approves them.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE) that covers this project.
