#!/usr/bin/env python3
"""
TCP test harness for the Cheat Engine MCP bridge (v15, native TCP transport).

This replaces the original ``test_mcp.py``, which still spoke the pre-v15 Named
Pipe protocol and asserted ``EXPECTED_VERSION_PREFIX = "12."`` — it could not
run against the current bridge at all.

Two modes
---------

    python test_bridge.py                # live mode: probe a running bridge
    python test_bridge.py --self-test    # no CE required: stub server + client contract

Live mode talks to a real Cheat Engine (bridge script loaded) over TCP. It is
read-only by default: it never writes target memory, never attaches a process
and never injects anything. Pass ``--allow-write`` to also exercise
write/read-back round trips (only against an attached process).

Self-test mode starts an in-process stub that speaks the exact wire format, then
asserts the Python client's contract: UTF-8 fidelity, timeout semantics (no
retry), connection-failure reporting, JSON-RPC error unwrapping and the
oversized-request guard. It needs no Cheat Engine and no MCP SDK side effects.

Exit code is 0 when every executed check passed.
"""

import argparse
import importlib.util
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 17171
PORT_SCAN_RANGE = 10


# --------------------------------------------------------------------------
# tiny result recorder
# --------------------------------------------------------------------------

class Checker:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.failures = []

    def check(self, name, cond, detail=""):
        if cond:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            self.failures.append((name, detail))
            print(f"  FAIL  {name}   {detail}")
        return bool(cond)

    def skip(self, name, why=""):
        self.skipped += 1
        print(f"  SKIP  {name}   {why}")

    def section(self, title):
        print(f"\n== {title} ==")

    def summary(self):
        print(f"\n{self.passed} passed, {self.failed} failed, {self.skipped} skipped")
        for name, detail in self.failures:
            print(f"  - {name}: {detail}")
        return 0 if self.failed == 0 else 1


# --------------------------------------------------------------------------
# raw wire helpers (used by live mode; independent of the MCP server module)
# --------------------------------------------------------------------------

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf.extend(chunk)
    return bytes(buf)


def wire_call(sock, method, params=None, timeout=30.0):
    """One length-prefixed JSON-RPC exchange. Returns the envelope dict."""
    req = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1},
                     ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sock.settimeout(timeout)
    sock.sendall(struct.pack("<I", len(req)) + req)
    n = struct.unpack("<I", recv_exact(sock, 4))[0]
    body = recv_exact(sock, n)
    return json.loads(body.decode("utf-8", errors="replace"))


def wire_result(sock, method, params=None, timeout=30.0):
    """Like wire_call but returns just the `result` object."""
    env = wire_call(sock, method, params, timeout)
    if "error" in env:
        return env["error"]
    return env.get("result", env)


def results_to_text(res):
    """Normalise a result (str/bytes/indent) to a printable string."""
    if isinstance(res, str):
        return res
    return json.dumps(res, indent=2, ensure_ascii=False)


def find_bridge(host, base_port, scan=PORT_SCAN_RANGE):
    """Return (sock, port) for the first port that answers a CE bridge ping."""
    for offset in range(scan):
        port = base_port + offset
        try:
            sock = socket.create_connection((host, port), timeout=1.0)
        except OSError:
            continue
        try:
            res = wire_result(sock, "ping", timeout=5.0)
            if isinstance(res, dict) and res.get("success"):
                return sock, port
        except Exception:
            pass
        sock.close()
    return None, None


# --------------------------------------------------------------------------
# live mode
# --------------------------------------------------------------------------

def run_live(host, base_port, allow_write):
    c = Checker()
    print(f"Connecting to a CE bridge on {host}:{base_port}..{base_port + PORT_SCAN_RANGE - 1} ...")

    sock, port = find_bridge(host, base_port)
    if not sock:
        print("\nNo CE bridge found. Checklist:")
        print("  1. Cheat Engine is running.")
        print("  2. ce_mcp_bridge.lua was executed in CE (File -> Execute Script).")
        print("  3. CE's console shows: [MCP] Bridge v15.1.0 started on port 17171")
        print("  4. Nothing else owns the port:  netstat -an | findstr 17171")
        print(f"  5. If CE is remote, pass --host/--base-port.")
        return 2

    print(f"Connected on port {port}.\n")

    # ---------------------------------------------------------------- identity
    c.section("identity")
    ping = wire_result(sock, "ping")
    c.check("ping succeeds", isinstance(ping, dict) and ping.get("success") is True, results_to_text(ping))
    c.check("version is 15.x", str(ping.get("version", "")).startswith("15."), ping.get("version"))
    status = wire_result(sock, "status")
    ok_status = isinstance(status, dict) and status.get("success") is True
    c.check("status command exists", ok_status, results_to_text(status))
    if ok_status:
        attached = status.get("process_attached")
        print(f"        version={status.get('version')} port={status.get('port')} "
              f"methods={status.get('method_count')} arch={status.get('target_arch')} "
              f"attached={attached}")
        c.check("status reports method_count > 150", (status.get("method_count") or 0) > 150,
                status.get("method_count"))
        c.check("status reports native DLL state", isinstance(status.get("native"), dict),
                status.get("native"))
    else:
        attached = None

    # ------------------------------------------------------------- dispatcher
    c.section("dispatcher introspection")
    methods = wire_result(sock, "list_methods", {"limit": 10000})
    implemented = isinstance(methods, dict) and methods.get("success") is True
    c.check("list_methods exists", implemented, results_to_text(methods))
    if implemented:
        names = set(methods.get("methods") or [])
        for required in ("ping", "batch", "status", "read_memory", "aob_scan",
                        "set_breakpoint", "evaluate_lua"):
            c.check(f"dispatcher exposes '{required}'", required in names)
        if ok_status:
            c.check("list_methods total == status.method_count",
                    methods.get("total") == status.get("method_count"),
                    f"{methods.get('total')} vs {status.get('method_count')}")

    # -------------------------------------------------------------------- batch
    c.section("batch execution")
    b = wire_result(sock, "batch", {"calls": [{"method": "ping"}, {"method": "status"}]})
    c.check("batch of two succeeds", isinstance(b, dict) and b.get("success") is True,
            results_to_text(b))
    if isinstance(b, dict) and b.get("results"):
        c.check("batch reports succeeded=2", b.get("succeeded") == 2, b.get("succeeded"))
        c.check("batch entries keep index+method",
                b["results"][0].get("index") == 1 and b["results"][0].get("method") == "ping")
    bfail = wire_result(sock, "batch", {"calls": [{"method": "definitely_not_a_method"}]})
    c.check("batch surfaces unknown method", isinstance(bfail, dict) and bfail.get("failed") == 1,
            results_to_text(bfail))
    c.check("batch error_code is METHOD_NOT_FOUND",
            isinstance(bfail, dict) and bfail.get("results", [{}])[0].get("error_code") == "METHOD_NOT_FOUND",
            results_to_text(bfail))

    # ---------------------------------------------------------- UTF-8 fidelity
    c.section("UTF-8 round trip (the pre-15.1 parse-error bug)")
    probe = "中文-Ω-測試"
    u = wire_result(sock, "batch", {"calls": [{"method": probe}]})
    echoed = ""
    if isinstance(u, dict) and u.get("results"):
        echoed = str(u["results"][0].get("method") or "")
    c.check("non-ASCII method name survives both directions", echoed == probe,
            f"sent {probe!r}, got {echoed!r} "
            "(a mismatch means the backslash-u decode bug is back)")

    # -------------------------------------------------------------- read paths
    c.section("read-only commands")
    pid_res = wire_result(sock, "get_opened_process_id")
    pid = pid_res.get("process_id") if isinstance(pid_res, dict) else None
    c.check("get_opened_process_id responds", isinstance(pid_res, dict), results_to_text(pid_res))

    info = wire_result(sock, "get_process_info")
    c.check("get_process_info responds", isinstance(info, dict), results_to_text(info))

    if pid:
        print(f"        attached process id = {pid}")
        mods = wire_result(sock, "enum_modules", {"limit": 10})
        ok_mods = isinstance(mods, dict) and mods.get("success") is True
        c.check("enum_modules responds", ok_mods, results_to_text(mods))
        if ok_mods:
            entries = mods.get("modules") or []
            c.check("module list is not empty", len(entries) > 0, "0 modules returned")
            addrs = [m.get("address") for m in entries]
            c.check("module list has no duplicate addresses", len(addrs) == len(set(addrs)),
                    f"{len(addrs) - len(set(addrs))} duplicates "
                    f"(the pre-15.1 double-scan bug)")
            mod_count = mods.get("returned")
            c.check("returned matches page length",
                    mod_count == len(entries), f"{mod_count} vs {len(entries)}")
            base = entries[0].get("address")
            if base:
                c.section("memory read at main module base")
                rm = wire_result(sock, "read_memory", {"address": base, "size": 64})
                c.check("read_memory succeeds", isinstance(rm, dict) and rm.get("success") is True,
                        results_to_text(rm))
                if isinstance(rm, dict) and rm.get("success"):
                    c.check("MZ header present at module base",
                            str(rm.get("data", "")).startswith("4D 5A"),
                            rm.get("data", "")[:32])
                    c.check("bytes array omitted by default", "bytes" not in rm,
                            "read_memory returned the redundant 'bytes' payload")
                rm2 = wire_result(sock, "read_memory",
                                  {"address": base, "size": 64, "include_bytes": True})
                c.check("include_bytes opt-in works",
                        isinstance(rm2, dict) and isinstance(rm2.get("bytes"), list),
                        results_to_text(rm2))
                di = wire_result(sock, "disassemble", {"address": base, "count": 5})
                c.check("disassemble succeeds at module base",
                        isinstance(di, dict) and di.get("success") is True, results_to_text(di))

        if allow_write:
            c.section("write round trip (--allow-write)")
            scratch = wire_result(sock, "allocate_memory", {"size": 64})
            if isinstance(scratch, dict) and scratch.get("success"):
                addr = scratch.get("address")
                w = wire_result(sock, "write_integer", {"address": addr, "value": 0x12345678, "type": "dword"})
                c.check("write_integer succeeds", w.get("success") is True, results_to_text(w))
                r = wire_result(sock, "read_integer", {"address": addr, "type": "dword"})
                c.check("read-back matches", r.get("value") == 0x12345678, results_to_text(r))
                wire_result(sock, "free_memory", {"address": addr})
            else:
                c.skip("write round trip", "allocate_memory failed: " + results_to_text(scratch))
    else:
        c.skip("module/memory probes", "no process attached in Cheat Engine")
        if allow_write:
            c.skip("write round trip", "no process attached")

    # ------------------------------------------------------------- bad input
    c.section("error handling")
    bad = wire_result(sock, "read_memory", {"address": "not-an-address", "size": 4})
    c.check("bad address returns success=false", bad.get("success") is False, results_to_text(bad))
    c.check("bad address carries an error_code", bool(bad.get("error_code")), results_to_text(bad))
    unknown = wire_call(sock, "no_such_command")
    c.check("unknown method returns a JSON-RPC error",
            isinstance(unknown, dict) and "error" in unknown, results_to_text(unknown))
    c.check("unknown method carries METHOD_NOT_FOUND",
            (unknown.get("error", {}).get("data") or {}).get("error_code") == "METHOD_NOT_FOUND"
            if isinstance(unknown, dict) else False, results_to_text(unknown))

    sock.close()
    return c.summary()


# --------------------------------------------------------------------------
# self-test mode: stub bridge + real client module
# --------------------------------------------------------------------------

class StubBridge:
    """Minimal server speaking the DLL's wire format, for client contract tests."""

    def __init__(self, slow_seconds=2.0):
        self.slow_seconds = slow_seconds
        self.port = None
        self.counts = {}
        self.raw_payloads = []
        self._lock = threading.Lock()
        self._srv = None
        self._running = False
        self._threads = []

    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        return self.port

    def stop(self):
        self._running = False
        try:
            self._srv.close()
        except OSError:
            pass

    def count(self, method):
        with self._lock:
            return self.counts.get(method, 0)

    def reset(self):
        with self._lock:
            self.counts.clear()
            self.raw_payloads.clear()

    def last_raw(self):
        with self._lock:
            return self.raw_payloads[-1] if self.raw_payloads else b""

    def _accept_loop(self):
        while self._running:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _serve(self, conn):
        try:
            while self._running:
                raw = recv_exact(conn, 4)
                n = struct.unpack("<I", raw)[0]
                body = recv_exact(conn, n)
                with self._lock:
                    self.raw_payloads.append(body)
                req = json.loads(body.decode("utf-8"))
                method = req.get("method")
                params = req.get("params") or {}
                with self._lock:
                    self.counts[method] = self.counts.get(method, 0) + 1
                conn.sendall(self._frame(self._dispatch(method, params, req.get("id"))))
        except (OSError, ConnectionError, json.JSONDecodeError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _frame(payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return struct.pack("<I", len(body)) + body

    def _dispatch(self, method, params, req_id):
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id,
                    "result": {"success": True, "version": "15.1.0-stub", "process_id": 0}}
        if method == "echo":
            return {"jsonrpc": "2.0", "id": req_id,
                    "result": {"success": True, "echo": params}}
        if method == "rpc_error":
            return {"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32601,
                "message": "Method not found: rpc_error",
                "data": {"error_code": "METHOD_NOT_FOUND", "method": "rpc_error"},
            }}
        if method == "__slow":
            time.sleep(self.slow_seconds)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"success": True, "slept": True}}
        if method == "__crashed":
            return {"jsonrpc": "2.0", "id": req_id,
                    "result": {"success": False, "error": "Invalid address: nonsense",
                               "error_code": "INVALID_ADDRESS"}}
        return {"jsonrpc": "2.0", "id": req_id,
                "result": {"success": False, "error": f"Method not found: {method}",
                           "error_code": "METHOD_NOT_FOUND"}}


def _load_client_module(host, port, timeout_seconds):
    os.environ["CE_HOST"] = host
    os.environ["CE_PORT"] = str(port)
    os.environ["CE_PORT_RANGE"] = "1"
    os.environ["CE_MCP_RETRIES"] = "1"
    os.environ["CE_MCP_RETRY_DELAY"] = "0.05"
    os.environ["CE_MCP_TIMEOUT"] = str(timeout_seconds)

    spec = importlib.util.spec_from_file_location("mcp_cheatengine_test",
                                                  HERE / "mcp_cheatengine.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_self_test():
    c = Checker()
    print("Self-test: stub bridge + real client (no Cheat Engine involved)\n")

    stub = StubBridge(slow_seconds=2.0)
    port = stub.start()

    try:
        ce = _load_client_module("127.0.0.1", port, timeout_seconds=10.0)
    except Exception as exc:
        print(f"Could not import mcp_cheatengine.py: {type(exc).__name__}: {exc}")
        print("Run this with the project venv: MCP_Server/.venv/Scripts/python.exe test_bridge.py --self-test")
        stub.stop()
        return 2

    # ------------------------------------------------------------- basic path
    c.section("client <-> stub basics")
    r = ce.call("ping")
    c.check("call() returns the flat result", isinstance(r, dict) and r.get("success") is True,
            results_to_text(r))
    c.check("version visible through call()", str(r.get("version", "")).startswith("15.1"),
            r.get("version"))

    # --------------------------------------------------------------- UTF-8
    c.section("UTF-8 request encoding")
    stub.reset()
    sample = {"text": "中文-Ω-測試", "path": r"C:\用户\游戏\表.ct"}
    r = ce.call("echo", sample)
    c.check("echo succeeds", isinstance(r, dict) and r.get("success") is True, results_to_text(r))
    c.check("echo payload identical", r.get("echo") == sample, results_to_text(r))
    raw = stub.last_raw()
    c.check("wire payload carries raw UTF-8 (no \\u escapes)", b"\\u4e2d" not in raw.lower(),
            raw[:120])
    c.check("wire payload contains the UTF-8 bytes",
            "中文".encode("utf-8") in raw, raw[:120])

    # ------------------------------------------------------- error unwrapping
    c.section("JSON-RPC error unwrapping")
    r = ce.call("rpc_error")
    c.check("error envelope -> success=false", r.get("success") is False, results_to_text(r))
    c.check("error_code pulled from error.data", r.get("error_code") == "METHOD_NOT_FOUND",
            results_to_text(r))
    r = ce.call("__crashed")
    c.check("result-level error_code preserved", r.get("error_code") == "INVALID_ADDRESS",
            results_to_text(r))

    # --------------------------------------------------------------- timeout
    c.section("timeout semantics (must NOT retry)")
    ce.ce_client.max_retries = 3          # make any retry obvious
    ce.ce_client.timeout_seconds = 0.4
    stub.reset()
    t0 = time.time()
    r = ce.call("__slow")
    elapsed = time.time() - t0
    c.check("timeout reported as error_code TIMEOUT", r.get("error_code") == "TIMEOUT",
            results_to_text(r))
    c.check("call() did not raise", isinstance(r, dict))
    c.check("no retry after a timeout", stub.count("__slow") == 1,
            f"server saw the command {stub.count('__slow')} times")
    c.check("timeout honoured promptly (< 2s)", elapsed < 2.0, f"{elapsed:.2f}s")
    ce.ce_client.timeout_seconds = 10.0
    ce.ce_client.max_retries = 1
    time.sleep(2.1)   # let the stub finish sleeping so it can serve again

    # ----------------------------------------------------- connection failure
    c.section("connection failure reporting")
    dead = ce.TCPBridgeClient("127.0.0.1", 1)     # nothing listens on port 1
    dead.timeout_seconds = 1.0
    dead.max_retries = 0
    try:
        dead.send_command("ping")
        c.check("dead endpoint raises", False, "no exception raised")
    except ConnectionError as exc:
        c.check("dead endpoint raises ConnectionError", True)
    payload = ce.error_payload(ConnectionError("boom"), "ping")
    c.check("error_payload maps ConnectionError -> BRIDGE_UNAVAILABLE",
            payload.get("error_code") == "BRIDGE_UNAVAILABLE", results_to_text(payload))
    payload = ce.error_payload(TimeoutError("slow"), "scan_all")
    c.check("error_payload maps TimeoutError -> TIMEOUT", payload.get("error_code") == "TIMEOUT")
    c.check("error_payload records the method", payload.get("method") == "scan_all")

    # ------------------------------------------------------- oversized request
    c.section("oversized request guard")
    r = ce.call("big", {"blob": "A" * (ce.MAX_REQUEST_SIZE_BYTES + 1024)})
    c.check("oversized request -> CLIENT_ERROR (never raises)", r.get("error_code") == "CLIENT_ERROR",
            results_to_text(r))
    c.check("oversized request explains the limit", "limit" in str(r.get("error", "")).lower(),
            r.get("error"))
    c.check("stub never received the oversized command", stub.count("big") == 0,
            stub.count("big"))

    # ------------------------------------------------------------ formatting
    c.section("result formatting helpers")
    c.check("format_result(None) is an error object",
            json.loads(ce.format_result(None)).get("success") is False)
    c.check("format_result keeps non-ASCII raw",
            "中文" in ce.format_result({"v": "中文"}), ce.format_result({"v": "中文"}))
    odd = json.loads(ce.format_result({"o": object()}))
    c.check("format_result tolerates non-serialisable values",
            "object" in str(odd.get("o")), results_to_text(odd))
    c.check("format_result never raises on a circular structure",
            isinstance(ce.format_result({"self": None}), str))
    circ = {}
    circ["me"] = circ
    c.check("circular payload becomes an error object, not an exception",
            json.loads(ce.format_result(circ)).get("error_code") == "INTERNAL_ERROR")
    c.check("new tools registered",
            all(hasattr(ce, n) for n in ("bridge_status", "list_bridge_methods", "batch_call")))

    # ------------------------------------------------------------ alias check
    c.section("JSON-RPC alias / unknown method")
    r = ce.call("definitely_not_a_method")
    c.check("unknown method -> METHOD_NOT_FOUND",
            r.get("error_code") == "METHOD_NOT_FOUND", results_to_text(r))

    stub.stop()
    return c.summary()


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="CE MCP bridge TCP test harness")
    ap.add_argument("--host", default=DEFAULT_HOST, help="bridge host (default 127.0.0.1)")
    ap.add_argument("--base-port", type=int, default=DEFAULT_PORT, help="first port to probe")
    ap.add_argument("--self-test", action="store_true",
                    help="run the offline client-contract test (no Cheat Engine needed)")
    ap.add_argument("--allow-write", action="store_true",
                    help="live mode: also exercise allocate/write/read-back round trips")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()
    return run_live(args.host, args.base_port, args.allow_write)


if __name__ == "__main__":
    sys.exit(main())
