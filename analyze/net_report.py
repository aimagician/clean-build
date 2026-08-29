#!/usr/bin/env python3
"""Turn a clean-builder strace network trace into a per-process report.

The builder wraps every phase in `strace -f -e trace=%net,%process`, so each
network syscall carries the PID that made it and the trace also records every
exec/fork — enough to name the exact command behind every connection attempt,
which the kernel ACL log alone cannot do.

    net_report.py <trace-file> --label build --out net-build-<stamp>.log

Prints a one-line summary to stdout, writes the full report to --out.
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# argv is matched as a run of quoted strings (escape-aware), not `.*?]` —
# a literal ] inside an argument must not truncate the capture
EXEC_RE = re.compile(r'^(\d+)\s+execve(?:at)?\("([^"]*)",\s*\[((?:\s*"(?:[^"\\]|\\.)*",?)*)')
FORK_RE = re.compile(r"^(\d+)\s+(?:clone3?|fork|vfork)\(.*\)\s*=\s*(\d+)")
# strace -f splits busy clone/socket calls into <unfinished ...> + resumed lines
FORK_RESUMED_RE = re.compile(r"^(\d+)\s+<\.\.\.\s+(?:clone3?|fork|vfork)\s+resumed>.*\)\s*=\s*(\d+)")
SOCKET_RE = re.compile(r"^(\d+)\s+socket\((AF_INET6?),\s*([A-Z0-9_|]+),.*\)\s*=\s*(\d+)")
SOCKET_UNFINISHED_RE = re.compile(r"^(\d+)\s+socket\((AF_INET6?),\s*([A-Z0-9_|]+),.*<unfinished")
SOCKET_RESUMED_RE = re.compile(r"^(\d+)\s+<\.\.\.\s+socket\s+resumed>.*\)\s*=\s*(\d+)")
NET_RE = re.compile(r"^(\d+)\s+(connect|sendto|sendmsg|sendmmsg)\((\d+),\s*(.*)$")
RESUMED_RE = re.compile(r"^(\d+)\s+<\.\.\.\s+(connect|sendto|sendmsg|sendmmsg)\s+resumed>(.*)$")
ADDR4_RE = re.compile(r'sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)')
ADDR6_RE = re.compile(r'sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),.*?inet_pton\(AF_INET6,\s*"([^"]+)"')
# anchored to end of line so a `) = 0` inside a printed payload can't match
RESULT_RE = re.compile(r"\)\s*=\s*(-?\d+|\?)(?:\s+([A-Z][A-Z0-9]+))?(?:\s+\([^)]*\))?\s*$")
ARGV_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

MAX_CMD_CHARS = 140


def is_loopback(ip: str) -> bool:
    ip = ip.removeprefix("::ffff:")  # v4-mapped addresses (Node dual-stack)
    return ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::")


def outcome_of(text: str) -> str:
    res = RESULT_RE.search(text)
    if not res or res.group(1) == "?":
        return "?"
    if int(res.group(1)) >= 0:
        return "ok"
    if res.group(2) == "EINPROGRESS":
        return "attempted (non-blocking)"
    return res.group(2) or "failed"


def parse(trace_path: Path):
    """Return (attempts, probes): attempts are (cmd, ip, port, proto, syscall,
    outcome) tuples; probes counts UDP port-0 connects per command (kernel
    source-address selection — no packet is ever sent for those)."""
    cmds: dict[str, str] = {}                    # pid -> command line
    socks: dict[tuple[str, str], str] = {}       # (pid, fd) -> TCP/UDP
    socks_any: dict[str, str] = {}               # fd -> last known proto (threads share fd tables)
    pending: dict[tuple[str, str], tuple] = {}   # (pid, syscall) -> (ip, port, proto)
    pending_socket: dict[str, str] = {}          # pid -> proto of an unfinished socket()
    attempts: list[tuple] = []
    probes: Counter = Counter()

    def adopt(parent: str, child: str):
        cmds.setdefault(child, cmds.get(parent, "?"))
        for (spid, fd), proto in list(socks.items()):
            if spid == parent:
                socks.setdefault((child, fd), proto)

    def cmd_of(pid: str) -> str:
        cmd = cmds.get(pid, f"?(pid {pid})")
        return cmd if len(cmd) <= MAX_CMD_CHARS else cmd[: MAX_CMD_CHARS - 1] + "…"

    def emit(pid: str, syscall: str, ip: str, port: str, proto: str, outcome: str):
        if port == "0" and proto != "TCP":
            probes[cmd_of(pid)] += 1
        else:
            attempts.append((cmd_of(pid), ip, port, proto, syscall, outcome))

    with trace_path.open(errors="replace") as fh:
        for line in fh:
            m = EXEC_RE.match(line)
            if m:
                pid, path, argv_raw = m.groups()
                argv = ARGV_ITEM_RE.findall(argv_raw)
                cmds[pid] = " ".join(argv) if argv else path
                continue

            m = FORK_RE.match(line) or FORK_RESUMED_RE.match(line)
            if m:
                adopt(*m.groups())
                continue

            m = SOCKET_RE.match(line)
            if m:
                pid, _family, sock_type, fd = m.groups()
                proto = "TCP" if "SOCK_STREAM" in sock_type else "UDP"
                socks[(pid, fd)] = proto
                socks_any[fd] = proto
                continue

            m = SOCKET_UNFINISHED_RE.match(line)
            if m:
                pid, _family, sock_type = m.groups()
                pending_socket[pid] = "TCP" if "SOCK_STREAM" in sock_type else "UDP"
                continue

            m = SOCKET_RESUMED_RE.match(line)
            if m:
                pid, fd = m.groups()
                proto = pending_socket.pop(pid, None)
                if proto:
                    socks[(pid, fd)] = proto
                    socks_any[fd] = proto
                continue

            m = RESUMED_RE.match(line)
            if m:
                pid, syscall, rest = m.groups()
                held = pending.pop((pid, syscall), None)
                if held:
                    emit(pid, syscall, *held, outcome_of(rest))
                continue

            m = NET_RE.match(line)
            if m:
                pid, syscall, fd, rest = m.groups()
                addr = ADDR4_RE.search(rest) or ADDR6_RE.search(rest)
                if not addr:
                    continue  # AF_UNIX, netlink, or a connected-socket send
                port, ip = addr.groups()
                proto = socks.get((pid, fd)) or socks_any.get(fd, "?")
                if "<unfinished" in rest:
                    pending[(pid, syscall)] = (ip, port, proto)
                else:
                    emit(pid, syscall, ip, port, proto, outcome_of(rest))

    # anything still pending never got a resumed line — report it as unknown
    for (pid, syscall), held in pending.items():
        emit(pid, syscall, *held, "?")
    return attempts, probes


def render(attempts, probes, label: str) -> str:
    lines = [
        f"# Network attempts during '{label}' — per process (strace) — {datetime.now():%Y-%m-%d %H:%M:%S}",
        "# Offline phases must show no non-loopback attempts. ENETUNREACH/blocked",
        "# results mean the lockdown stopped the packet; 'ok'/'attempted' during an",
        "# offline phase means a packet reached the bridge — check the egress log.",
        "",
    ]
    if not attempts and not probes:
        lines.append("(no network attempts — the contract held)")
        return "\n".join(lines) + "\n"

    grouped: dict[str, Counter] = {}
    for cmd, ip, port, proto, syscall, outcome in attempts:
        tag = " loopback" if is_loopback(ip) else ""
        grouped.setdefault(cmd, Counter())[f"→ {ip}:{port} {proto} {syscall} = {outcome}{tag}"] += 1
    for cmd in probes:
        grouped.setdefault(cmd, Counter())

    def loopback_only(item):  # processes that touched remote destinations sort first
        return all("loopback" in dest for dest in item[1]) if item[1] else True

    for cmd, dests in sorted(grouped.items(), key=loopback_only):
        lines.append(cmd)
        for dest, n in dests.most_common():
            lines.append(f"    {dest}" + (f"   ×{n}" if n > 1 else ""))
        if probes.get(cmd):
            lines.append(
                f"    ({probes[cmd]} UDP port-0 connects — kernel source-address probes, no packets sent)"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--label", default="phase")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if not args.trace.is_file():
        print(f"error: no such trace: {args.trace}", file=sys.stderr)
        return 2

    attempts, probes = parse(args.trace)
    args.out.write_text(render(attempts, probes, args.label))

    remote = [a for a in attempts if not is_loopback(a[1])]
    if not attempts and not probes:
        print("▶ net attempts: none")
    elif not attempts:
        print("▶ net attempts: none (only source-address probes)")
    else:
        shown = remote or attempts
        procs = len({a[0] for a in shown})
        dests = len({(a[1], a[2]) for a in shown})
        kind = "remote" if remote else "loopback-only"
        print(f"▶ net attempts: {len(shown)} {kind} by {procs} process(es) to {dests} destination(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
