#!/usr/bin/env python3
"""JSON-RPC probe for the CE MCP TCP bridge.

Verifies the *wire contract* end to end — framing, envelope shapes, UTF-8
transport, and connection edge behaviour — independent of the MCP tool layer.

Modes:
    python probe_bridge.py --self-test          # offline: in-process stub
    python probe_bridge.py                      # live: probe 127.0.0.1:17171
    python probe_bridge.py --host H --port P    # live: remote bridge
    python probe_bridge.py --large 524288       # raise the CJK payload size

The probe is strictly read-only: the only command it dispatches with logic is
`evaluate_lua` on pure expressions (string building, arithmetic) and `status`.

Authoritative frame facts (from NativeBridge/ce_mcp_tcp.c, do not guess):
  * request/response framing: 4-byte little-endian length prefix + UTF-8 body
  * len <= 0 or len > 4 MiB  -> DLL drops the connection (no response)
  * truncated body           -> DLL drops the connection
  * strict lock-step: one request, one response (120 s Lua budget); on Lua
    timeout the DLL answers {"error":"timeout waiting for command handler"}
    -- note this DLL-level error is NOT the documented flat envelope
  * TCP_NODELAY + SO_KEEPALIVE are set on the accepted socket
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 17171
MAX_CMD_SIZE = 4 * 1024 * 1024  # mirrors MAX_CMD_SIZE in ce_mcp_tcp.c


# ---------------------------------------------------------------------------
# framing helpers
# ---------------------------------------------------------------------------

def send_frame(sock: socket.socket, body: bytes) -> None:
    sock.sendall(struct.pack("<I", len(body)) + body)


def recv_exact(sock: socket.socket, n: int, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket, timeout: float = 10.0) -> bytes | None:
    """Return the raw body of the next frame, or None on disconnect."""
    hdr = recv_exact(sock, 4, timeout)
    if len(hdr) < 4:
        return None
    (length,) = struct.unpack("<I", hdr)
    if length == 0 or length > MAX_CMD_SIZE:
        return None
    body = recv_exact(sock, length, timeout)
    if len(body) < length:
        return None
    return body


def connect(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


# ---------------------------------------------------------------------------
# probe harness
# ---------------------------------------------------------------------------

class Probe:
    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        self.results: list[tuple[str, str, str]] = []  # (name, status, detail)

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.results.append((name, "PASS" if ok else "FAIL", detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

    def _connect(self) -> socket.socket:
        return connect(self.host, self.port)

    def _rpc(self, sock: socket.socket, method: str | None = None, params: dict | None = None,
             _id=None, raw_body: bytes | None = None, extra: dict | None = None,
             drop_jsonrpc: bool = False) -> dict:
        if raw_body is None:
            req: dict = {}
            if not drop_jsonrpc:
                req["jsonrpc"] = "2.0"
            if _id is not None:
                req["id"] = _id
            if method is not None:
                req["method"] = method
            if params is not None:
                req["params"] = params
            if extra:
                req.update(extra)
            raw_body = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        send_frame(sock, raw_body)
        body = recv_frame(sock, timeout=15.0)
        if body is None:
            return {"__disconnect__": True}
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"__undecodable__": body[:64]}


# ---------------------------------------------------------------------------
# the matrix (read-only experiments)
# ---------------------------------------------------------------------------

def matrix(p: Probe, large_bytes: int) -> None:
    print(f"\n=== JSON-RPC frame matrix vs {p.host}:{p.port} ===")

    # T1 baseline + envelope shape
    sock = p._connect()
    r = p._rpc(sock, "status", {}, _id=1)
    p.record("T1 baseline status + jsonrpc envelope",
             r.get("jsonrpc") == "2.0" and r.get("id") == 1
             and isinstance(r.get("result"), dict) and r["result"].get("success") is True,
             f"keys={sorted(r)[:6]}")

    # T2 id echo variants
    r = p._rpc(sock, "status", {}, _id="string-id")
    p.record("T2a string id echoed", r.get("id") == "string-id", f"id={r.get('id')!r}")
    r = p._rpc(sock, "status", {}, _id=None)  # id omitted entirely
    p.record("T2b missing id tolerated", "__disconnect__" not in r, f"keys={sorted(r)[:6]}")

    # T3 extra / missing envelope fields (dispatcher is method-name based)
    r = p._rpc(sock, "status", {}, _id=7, extra={"x_extra": "ignored"}, drop_jsonrpc=True)
    p.record("T3 no-jsonrpc + extra fields tolerated", r.get("result", {}).get("success") is True)

    # T4 unknown method -> JSON-RPC -32601 with data.error_code
    r = p._rpc(sock, "definitely_not_a_method", {}, _id=9)
    err = r.get("error") or {}
    p.record("T4 unknown method -> -32601 METHOD_NOT_FOUND",
             err.get("code") == -32601 and (err.get("data") or {}).get("error_code") == "METHOD_NOT_FOUND",
             f"error={err}")

    # T5 invalid JSON body -> -32700 PARSE_ERROR
    r = p._rpc(sock, raw_body=b"{not json at all")
    err = r.get("error") or {}
    p.record("T5 invalid JSON -> -32700 PARSE_ERROR",
             err.get("code") == -32700 and (err.get("data") or {}).get("error_code") == "PARSE_ERROR",
             f"error={err}")

    # T6 trailing newline inside the body (leniency of the Lua codec)
    body = json.dumps({"jsonrpc": "2.0", "id": 11, "method": "status", "params": {}}).encode() + b"\n"
    r = p._rpc(sock, raw_body=body)
    p.record("T6 trailing newline in body tolerated", r.get("result", {}).get("success") is True)

    # T7 CJK round trip over the wire (UTF-8 fidelity, raw bytes both ways)
    payload = "中文往返测试：绀碧の焦点 ✅"
    r = p._rpc(sock, "evaluate_lua",
               {"code": f'return "{payload}"'}, _id=13)
    got = r.get("result", {})
    p.record("T7 CJK round trip", got.get("success") is True and got.get("result") == payload,
             f"got={got.get('result', got.get('error'))!r:.80}")

    # T8 large CJK payload (throughput + integrity)
    big = "中文" * (large_bytes // 6)  # 6 bytes per char in UTF-8
    r = p._rpc(sock, "evaluate_lua", {"code": f'return ("中文"):rep({large_bytes // 6})'}, _id=14)
    got = r.get("result", {})
    p.record(f"T8 large CJK payload ({large_bytes} bytes)",
             got.get("success") is True and got.get("result") == big,
             f"len={len(got.get('result', ''))}")

    # T9 pipelining: two frames back-to-back, responses in order
    send_frame(sock, json.dumps({"jsonrpc": "2.0", "id": 21, "method": "status", "params": {}}).encode())
    send_frame(sock, json.dumps({"jsonrpc": "2.0", "id": 22, "method": "status", "params": {}}).encode())
    r1, r2 = json.loads(recv_frame(sock)), json.loads(recv_frame(sock))
    p.record("T9 pipelined frames answered in order",
             r1.get("id") == 21 and r2.get("id") == 22, f"ids={r1.get('id')},{r2.get('id')}")
    sock.close()

    # T10 zero-length frame -> DLL drops the connection
    sock = p._connect()
    send_frame(sock, b"")
    body = recv_frame(sock, timeout=5.0)
    p.record("T10 zero-length frame disconnects (per ce_mcp_tcp.c)", body is None)
    sock.close()

    # T11 oversized declared length (> 4 MiB header) -> disconnect
    sock = p._connect()
    sock.sendall(struct.pack("<I", MAX_CMD_SIZE + 1))
    body = recv_frame(sock, timeout=5.0)
    p.record("T11 oversized length header disconnects", body is None)
    sock.close()

    # T12 truncated frame (declare 1000, deliver 100, close) -> disconnect
    sock = p._connect()
    sock.sendall(struct.pack("<I", 1000) + b"x" * 100)
    sock.shutdown(socket.SHUT_WR)
    body = recv_frame(sock, timeout=5.0)
    p.record("T12 truncated frame disconnects", body is None)
    sock.close()

    # T13 bridge recovers after abusive connections (fresh connect works)
    try:
        sock = p._connect()
        r = p._rpc(sock, "status", {}, _id=41)
        p.record("T13 bridge healthy after abusive connections",
                 r.get("result", {}).get("success") is True)
        sock.close()
    except OSError as exc:
        p.record("T13 bridge healthy after abusive connections", False, str(exc))


# ---------------------------------------------------------------------------
# offline stub (validates the probe's own frame logic without CE)
# ---------------------------------------------------------------------------

def _stub_server(sock: socket.socket) -> None:
    """Mirror ce_mcp_tcp.c semantics: lock-step, guards, disconnect on abuse."""
    try:
        while True:
            hdr = recv_exact(sock, 4, timeout=10.0)
            if len(hdr) < 4:
                return
            (length,) = struct.unpack("<I", hdr)
            if length == 0 or length > MAX_CMD_SIZE:
                return                      # DLL behaviour: drop connection
            body = recv_exact(sock, length, timeout=10.0)
            if len(body) < length:
                return                      # truncated -> drop
            try:
                req = json.loads(body.decode("utf-8"))
                method = req.get("method")
                _id = req.get("id")
                if method == "status":
                    resp = {"jsonrpc": "2.0", "result": {"success": True, "stub": True}, "id": _id}
                elif method == "evaluate_lua":
                    resp = {"jsonrpc": "2.0",
                            "result": {"success": True, "result": "中文往返测试：绀碧の焦点 ✅"}, "id": _id}
                else:
                    resp = {"jsonrpc": "2.0", "id": _id,
                            "error": {"code": -32601, "message": "Method not found",
                                      "data": {"error_code": "METHOD_NOT_FOUND"}}}
                out = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            except (UnicodeDecodeError, json.JSONDecodeError):
                out = json.dumps({"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": "Parse error",
                                            "data": {"error_code": "PARSE_ERROR"}}}).encode("utf-8")
            send_frame(sock, out)
    except (OSError, ValueError):
        return


def self_test(large_bytes: int) -> int:
    print("=== probe self-test (in-process stub, no CE) ===")
    server = socket.socket()
    server.bind((DEFAULT_HOST, 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=_serve_once, args=(server,), daemon=True).start()

    p = Probe(DEFAULT_HOST, port)
    # The stub serves exactly one connection; run the non-destructive half.
    sock = p._connect()
    r = p._rpc(sock, "status", {}, _id=1)
    p.record("S1 baseline envelope", r.get("result", {}).get("success") is True)
    r = p._rpc(sock, "nope", {}, _id=2)
    p.record("S2 unknown method shape", (r.get("error") or {}).get("code") == -32601)
    r = p._rpc(sock, raw_body=b"{bad")
    p.record("S3 parse error shape", (r.get("error") or {}).get("code") == -32700)
    r = p._rpc(sock, "evaluate_lua", {"code": "return 1"}, _id=3)
    p.record("S4 CJK over wire", r.get("result", {}).get("result") == "中文往返测试：绀碧の焦点 ✅")
    sock.close()
    server.close()

    failed = sum(1 for _, s, _ in p.results if s == "FAIL")
    print(f"\nself-test: {len(p.results) - failed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def _serve_once(server: socket.socket) -> None:
    sock, _ = server.accept()
    _stub_server(sock)
    sock.close()


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="JSON-RPC probe for the CE MCP TCP bridge")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--self-test", action="store_true", help="offline stub mode, no CE")
    ap.add_argument("--large", type=int, default=131072,
                    help="CJK payload size in bytes for T8 (default 131072)")
    args = ap.parse_args()

    if args.self_test:
        return self_test(args.large)

    p = Probe(args.host, args.port)
    try:
        matrix(p, args.large)
    except OSError as exc:
        print(f"\nCannot reach bridge at {args.host}:{args.port} — {exc}")
        print("Checklist: 1) CE running  2) ce_mcp_bridge.lua executed "
              "(look for '[MCP] Bridge v15.2.0 started on port ...')  3) correct --host/--port")
        return 2

    failed = [(n, d) for n, s, d in p.results if s == "FAIL"]
    print(f"\n===== {len(p.results) - len(failed)} passed, {len(failed)} failed =====")
    if failed:
        for n, d in failed:
            print(f"  FAIL {n}: {d}")
        return 1
    print("Wire contract verified: framing, envelope shapes, UTF-8, edge guards all conform.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
