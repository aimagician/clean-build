## What and why

<!-- What does this change, and why? Link the issue it resolves (e.g. "Fixes #12"). -->

## Security impact

<!-- clean-builder contains untrusted builds, so every change answers this.
     Does it touch the ACL profiles, the lockdown checks, log handling, the
     strace runner, the output scan or the analyzer rubric? If so, explain why
     the guarantees in SECURITY.md still hold. Otherwise write "None". -->

## Checklist

- [ ] CI passes (ShellCheck, Ruff, unit tests, syntax checks)
- [ ] If `clean-builder` changed: `./clean-builder build example netprobe` still reports both paths **blocked**
- [ ] README / SECURITY.md updated if behavior or guarantees changed
- [ ] CHANGELOG.md has an entry under **Unreleased**
- [ ] No secrets, private hostnames or IPs, or personal log output in the diff
