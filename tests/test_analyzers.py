"""Unit tests for the standard-library helpers in analyze/.

No Incus, no network. Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ANALYZE = Path(__file__).resolve().parent.parent / "analyze"


def load(name: str):
    """Import analyze/<name>.py without putting analyze/ on sys.path."""
    spec = importlib.util.spec_from_file_location(name, ANALYZE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analyze_logs = load("analyze_logs")
net_report = load("net_report")

# A trimmed `strace -f -e trace=%net,%process` capture of `npm run netprobe`:
# npm forks, the child execs node, and node tries 1.1.1.1:443 (non-blocking),
# 127.0.0.1:8801 (loopback), an IPv6 resolver, a UDP port-0 source-address
# probe, and a DNS query whose connect() is split across two lines.
TRACE = """\
100 execve("/usr/bin/npm", ["npm", "run", "netprobe"], 0x7ffc8 /* 12 vars */) = 0
100 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f2, stack_size=0x9000}, 88) = 101
101 execve("/usr/bin/node", ["node", "netprobe.mjs"], 0x7ffd1 /* 12 vars */) = 0
101 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 21
101 connect(21, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
101 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 22
101 connect(22, {sa_family=AF_INET, sin_port=htons(8801), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
101 socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 25
101 connect(25, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700:4700::1111", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)
101 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 23
101 connect(23, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("1.1.1.1")}, 16) = 0
101 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 24
101 connect(24, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("1.0.0.1")}, 16 <unfinished ...>
100 exit_group(0) = ?
101 <... connect resumed>) = -1 ECONNREFUSED (Connection refused)
"""

NODE = "node netprobe.mjs"


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.logs = self.dir / "logs"
        self.logs.mkdir()

    def make_log(self, rel: str, text: str, mtime: float = 1_000_000) -> Path:
        path = self.logs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        os.utime(path, (mtime, mtime))
        return path


class NetReportParseTest(TempDirTestCase):
    def parse(self, text: str):
        trace = self.dir / "net-test.trace"
        trace.write_text(text, encoding="utf-8")
        return net_report.parse(trace)

    def test_attributes_each_attempt_to_the_command_that_made_it(self):
        attempts, _ = self.parse(TRACE)
        self.assertIn((NODE, "1.1.1.1", "443", "TCP", "connect", "attempted (non-blocking)"), attempts)
        self.assertIn((NODE, "127.0.0.1", "8801", "TCP", "connect", "ok"), attempts)
        self.assertIn((NODE, "2606:4700:4700::1111", "443", "TCP", "connect", "ENETUNREACH"), attempts)

    def test_completes_a_connect_split_across_unfinished_and_resumed_lines(self):
        attempts, _ = self.parse(TRACE)
        self.assertIn((NODE, "1.0.0.1", "53", "UDP", "connect", "ECONNREFUSED"), attempts)

    def test_udp_port_zero_connects_count_as_probes_not_attempts(self):
        attempts, probes = self.parse(TRACE)
        self.assertEqual(probes, Counter({NODE: 1}))
        self.assertNotIn("0", [port for _, _, port, *_ in attempts])

    def test_forked_child_keeps_the_parent_command_until_it_execs(self):
        trace = (
            '100 execve("/usr/bin/npm", ["npm", "ci"], 0x7ffc /* 9 vars */) = 0\n'
            "100 clone(child_stack=NULL, flags=CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f) = 102\n"
            "102 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 5\n"
            '102 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.20")}, 16) = 0\n'
        )
        attempts, _ = self.parse(trace)
        self.assertEqual(attempts, [("npm ci", "198.51.100.20", "443", "TCP", "connect", "ok")])

    def test_unix_sockets_are_ignored(self):
        trace = '100 connect(3, {sa_family=AF_UNIX, sun_path="/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)\n'
        self.assertEqual(self.parse(trace), ([], Counter()))


class NetReportRenderTest(unittest.TestCase):
    def test_empty_trace_says_the_contract_held(self):
        report = net_report.render([], Counter(), "build")
        self.assertIn("'build'", report)
        self.assertIn("(no network attempts — the contract held)", report)

    def test_remote_processes_are_listed_before_loopback_only_ones(self):
        attempts = [
            ("vite", "127.0.0.1", "5173", "TCP", "connect", "ok"),
            ("node evil.js", "203.0.113.7", "443", "TCP", "connect", "ENETUNREACH"),
        ]
        report = net_report.render(attempts, Counter(), "watch")
        self.assertLess(report.index("node evil.js"), report.index("vite"))
        self.assertIn("→ 127.0.0.1:5173 TCP connect = ok loopback", report)

    def test_v4_mapped_loopback_counts_as_loopback(self):
        self.assertTrue(net_report.is_loopback("::ffff:127.0.0.1"))
        self.assertFalse(net_report.is_loopback("::ffff:1.1.1.1"))


class NetReportCliTest(TempDirTestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, str(ANALYZE / "net_report.py"), *args],
            capture_output=True,
            encoding="utf-8",
            env=env,
            check=False,
        )

    def test_writes_the_report_and_prints_a_one_line_summary(self):
        trace = self.dir / "net-netprobe.trace"
        trace.write_text(TRACE, encoding="utf-8")
        out = self.dir / "net-netprobe.log"
        proc = self.run_cli(str(trace), "--label", "netprobe", "--out", str(out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("3 remote by 1 process(es) to 3 destination(s)", proc.stdout)
        self.assertIn("→ 1.1.1.1:443 TCP connect = attempted (non-blocking)", out.read_text(encoding="utf-8"))

    def test_missing_trace_is_an_error(self):
        proc = self.run_cli(str(self.dir / "nope.trace"), "--out", str(self.dir / "x.log"))
        self.assertEqual(proc.returncode, 2)


class ResolveProjectDirTest(TempDirTestCase):
    def test_rejects_names_that_could_escape_the_logs_folder(self):
        for bad in ("", ".", "..", "../etc", "/etc", ".hidden", "a/b", "a\\b"):
            with self.subTest(project=bad), self.assertRaises(SystemExit):
                analyze_logs.resolve_project_dir(self.logs, bad)

    def test_basename_resolves_to_its_hashed_folder(self):
        folder = self.logs / "myapp-3f9c2a1b"
        folder.mkdir()
        self.assertEqual(analyze_logs.resolve_project_dir(self.logs, "myapp"), folder)
        self.assertEqual(analyze_logs.resolve_project_dir(self.logs, "myapp-3f9c2a1b"), folder)

    def test_ambiguous_basename_is_an_error(self):
        (self.logs / "myapp-11111111").mkdir()
        (self.logs / "myapp-22222222").mkdir()
        with self.assertRaises(SystemExit) as caught:
            analyze_logs.resolve_project_dir(self.logs, "myapp")
        self.assertIn("ambiguous", str(caught.exception))

    def test_suffix_must_be_an_eight_character_hex_hash(self):
        (self.logs / "myapp-backup").mkdir()
        self.assertEqual(analyze_logs.resolve_project_dir(self.logs, "myapp"), self.logs / "myapp")


class CollectLogsTest(TempDirTestCase):
    def names(self, last: int = 10):
        return [name for name, _ in analyze_logs.collect_logs(self.logs, last)]

    def test_takes_the_newest_files_and_returns_them_oldest_first(self):
        self.make_log("app-0123abcd/install-1.log", "one", mtime=1000)
        self.make_log("app-0123abcd/build-2.log", "two", mtime=2000)
        self.make_log("app-0123abcd/egress-build-3.log", "three", mtime=3000)
        self.assertEqual(self.names(last=2), ["app-0123abcd/build-2.log", "app-0123abcd/egress-build-3.log"])

    def test_reads_only_log_files_and_skips_npm_debug_logs(self):
        self.make_log("app-0123abcd/build-1.log", "ok")
        self.make_log("app-0123abcd/2026-01-01T00_00_00_000Z-debug-0.log", "npm internals")
        self.make_log("app-0123abcd/analysis-1.md", "earlier verdict")
        self.make_log("app-0123abcd/project-path", "/home/me/app")
        self.assertEqual(self.names(), ["app-0123abcd/build-1.log"])

    def test_strips_ansi_colour_codes(self):
        self.make_log("app-0123abcd/build-1.log", "\x1b[32m✓ built\x1b[0m in 1s")
        self.assertEqual(analyze_logs.collect_logs(self.logs, 1), [("app-0123abcd/build-1.log", "✓ built in 1s")])

    def test_long_files_are_elided_in_the_middle(self):
        self.make_log("app-0123abcd/build-1.log", "A" * 5 + "B" * 20 + "C" * 5)
        with mock.patch.object(analyze_logs, "MAX_CHARS_PER_FILE", 10):
            ((_, text),) = analyze_logs.collect_logs(self.logs, 1)
        self.assertTrue(text.startswith("AAAAA\n"))
        self.assertTrue(text.endswith("\nCCCCC"))
        self.assertIn("[20 chars elided]", text)

    def test_prompt_budget_drops_the_oldest_files_first(self):
        self.make_log("app-0123abcd/old.log", "o" * 10, mtime=1000)
        self.make_log("app-0123abcd/mid.log", "m" * 10, mtime=2000)
        self.make_log("app-0123abcd/new.log", "n" * 10, mtime=3000)
        stderr = io.StringIO()
        with mock.patch.object(analyze_logs, "MAX_TOTAL_CHARS", 25), redirect_stderr(stderr):
            names = self.names()
        self.assertEqual(names, ["app-0123abcd/mid.log", "app-0123abcd/new.log"])
        self.assertIn("prompt budget full", stderr.getvalue())


class BuildPromptTest(unittest.TestCase):
    def test_labels_each_file_by_kind(self):
        prompt = analyze_logs.build_prompt(
            [
                ("app/install-1.log", "added 1 package"),
                ("app/egress-install-1.log", ""),
                ("app/net-install-1.log", "(no network attempts — the contract held)"),
            ]
        )
        self.assertIn("===== FILE: app/install-1.log (phase transcript) =====\nadded 1 package", prompt)
        self.assertIn("===== FILE: app/egress-install-1.log (egress capture) =====\n(empty)", prompt)
        self.assertIn("===== FILE: app/net-install-1.log (per-process network attempt report) =====", prompt)


class CallOpenRouterTest(unittest.TestCase):
    @staticmethod
    def fake_urlopen(content: str) -> mock.MagicMock:
        body = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(body)
        return mock.MagicMock(return_value=response)

    def test_sends_the_rubric_and_parses_a_fenced_json_verdict(self):
        verdict = {"verdict": "clean", "summary": "nothing left the container", "findings": []}
        urlopen = self.fake_urlopen("```json\n" + json.dumps(verdict) + "\n```")
        with mock.patch.object(analyze_logs.urllib.request, "urlopen", urlopen):
            result = analyze_logs.call_openrouter("test-key", "some/model", "PROMPT")
        self.assertEqual(result, verdict)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, analyze_logs.API_URL)
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "some/model")
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual(payload["messages"][0], {"role": "system", "content": analyze_logs.RUBRIC})
        self.assertEqual(payload["messages"][1], {"role": "user", "content": "PROMPT"})

    def test_attribution_url_follows_cb_app_url(self):
        urlopen = self.fake_urlopen('{"verdict": "clean"}')
        with mock.patch.dict(os.environ, {"CB_APP_URL": "https://example.org/my-fork"}), mock.patch.object(
            analyze_logs.urllib.request, "urlopen", urlopen
        ):
            analyze_logs.call_openrouter("test-key", "some/model", "PROMPT")
        self.assertEqual(urlopen.call_args.args[0].get_header("Http-referer"), "https://example.org/my-fork")


class RenderReportTest(unittest.TestCase):
    def test_lists_findings_with_severity_and_evidence(self):
        report = analyze_logs.render_report(
            {
                "verdict": "critical",
                "summary": "A packet left during an offline build.",
                "findings": [
                    {
                        "severity": "critical",
                        "file": "app/egress-build-1.log",
                        "evidence": "cb0-egress SRC=10.23.23.5 DST=203.0.113.7 PROTO=TCP DPT=443",
                        "explanation": "offline phases must not send packets",
                    }
                ],
            },
            "some/model",
            ["app/egress-build-1.log"],
        )
        self.assertIn("VERDICT: CRITICAL", report)
        self.assertIn("✗ [critical] app/egress-build-1.log", report)
        self.assertIn("    evidence: cb0-egress SRC=10.23.23.5", report)


class AnalyzeCliTest(TempDirTestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, str(ANALYZE / "analyze_logs.py"), *args],
            capture_output=True,
            encoding="utf-8",
            env=env,
            check=False,
        )

    def test_dry_run_prints_the_prompt_without_calling_the_api(self):
        self.make_log("app-0123abcd/install-1.log", "added 1 package")
        proc = self.run_cli("--logs", str(self.logs), "--project", "app", "--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("----- system prompt -----", proc.stdout)
        self.assertIn("===== FILE: install-1.log (phase transcript) =====", proc.stdout)

    def test_missing_api_key_is_a_configuration_error(self):
        self.make_log("app-0123abcd/install-1.log", "added 1 package")
        proc = self.run_cli("--logs", str(self.logs))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("OPENROUTER_API_KEY", proc.stderr)

    def test_nothing_to_analyze_exits_cleanly(self):
        proc = self.run_cli("--logs", str(self.logs))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("nothing to analyze", proc.stdout)

    def test_missing_logs_folder_is_an_error(self):
        proc = self.run_cli("--logs", str(self.dir / "missing"))
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
