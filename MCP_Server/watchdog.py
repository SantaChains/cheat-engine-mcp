#!/usr/bin/env python3
"""Bridge watchdog: monitor the Cheat Engine MCP bridge from OUTSIDE the CE process.

The bridge lives inside CE's main thread, so when CE dies (crash, exit) or the
main thread blocks on a modal dialog, every MCP call fails from the outside with
no way to distinguish the causes. This supervisor closes that gap: it polls the
bridge's TCP port and reports/acts on three states:

  UP        bridge answers ping
  BLOCKED   port accepts TCP but ping times out -> CE main thread busy
            (modal dialog / inputQuery / long command)
  DOWN      nothing listening -> CE or the bridge script is gone

Usage:
  python watchdog.py                       # monitor and print state changes
  python watchdog.py --interval 5          # poll every 5 s (default 3)
  python watchdog.py --restart-ce          # relaunch CE on prolonged DOWN
  python watchdog.py --ce-path "C:\\Program Files\\Cheat Engine 7.5\\cheatengine-x86_64.exe" \
                    --table "game.CT"      # table passed as CLI arg to CE

Exit codes: 0 = still UP at shutdown (Ctrl+C), 1 = DOWN for --give-up seconds.
"""

import argparse
import json
import socket
import struct
import subprocess
import sys
import time

def probe(host, port, timeout=2.0):
    """Return 'UP' | 'BLOCKED' | 'DOWN'."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except OSError:
        return "DOWN"
    try:
        ping = json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {},
                           "id": 0}, separators=(",", ":")).encode("utf-8")
        sock.settimeout(timeout)
        sock.sendall(struct.pack("<I", len(ping)) + ping)
        hdr = _recv_exact(sock, 4, timeout)
        if hdr is None:
            return "BLOCKED"
        body_len = struct.unpack("<I", hdr)[0]
        if _recv_exact(sock, body_len, timeout) is None:
            return "BLOCKED"
        return "UP"
    except (OSError, struct.error):
        return "BLOCKED"
    finally:
        sock.close()

def _recv_exact(sock, n, timeout):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf

def main():
    ap = argparse.ArgumentParser(description="Cheat Engine MCP bridge watchdog")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=17171)
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--restart-ce", action="store_true",
                    help="relaunch CE after DOWN persists for --down-budget seconds")
    ap.add_argument("--ce-path", default=r"C:\Program Files\Cheat Engine 7.5\cheatengine-x86_64-SPOOFER.exe",
                    help="path to the CE executable used with --restart-ce")
    ap.add_argument("--table", default=None, help="table file passed to CE on relaunch")
    ap.add_argument("--down-budget", type=float, default=30.0,
                    help="seconds of continuous DOWN before --restart-ce fires")
    args = ap.parse_args()

    state = None
    down_started = None
    try:
        while True:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            current = probe(args.host, args.port)

            if current != state:
                state = current
                print(f"[{now}] state -> {current}", flush=True)

            # The DOWN budget must measure the CURRENT episode only: without
            # this reset, a stale down_started from a previous DOWN period
            # (DOWN -> UP -> DOWN) would fire --restart-ce immediately.
            if current == "DOWN":
                if down_started is None:
                    down_started = time.time()
            else:
                down_started = None

            if (current == "DOWN" and args.restart_ce and down_started
                    and time.time() - down_started >= args.down_budget):
                cmd = [args.ce_path]
                if args.table:
                    cmd.append(args.table)
                print(f"[{now}] DOWN for {args.down_budget:g}s -> relaunching CE", flush=True)
                try:
                    subprocess.Popen(cmd)
                except OSError as exc:
                    print(f"[{now}] relaunch failed: {exc}", flush=True)
                down_started = None

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("watchdog stopped", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    main()
