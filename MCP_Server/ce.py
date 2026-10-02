"""Minimal CLI client for the Cheat Engine MCP TCP bridge. Stdlib only.

No MCP protocol involved -- just the same 4-byte length prefix + JSON-RPC
framing that mcp_cheatengine.py uses.

    python ce.py ping
    python ce.py read_memory '{"address":"0x140001000","size":4}'
    python ce.py                                # no args -> self-check (ping)
"""
import json
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = 17171


def _recv(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CE bridge closed the connection")
        buf += chunk
    return buf


def send_command(method, params=None, host=HOST, port=PORT, timeout=30):
    """Send one JSON-RPC request, return its `result` dict."""
    req = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}
    ).encode("utf-8")
    with socket.create_connection((host, port), timeout) as sock:
        sock.sendall(struct.pack("<I", len(req)) + req)
        n = struct.unpack("<I", _recv(sock, 4))[0]
        resp = json.loads(_recv(sock, n))
    if "error" in resp:
        raise RuntimeError(resp["error"])
    return resp["result"]


if __name__ == "__main__":
    if len(sys.argv) < 2:  # self-check
        r = send_command("ping")
        assert r.get("success") is True, r
        print("self-check OK:", r.get("message"))
        sys.exit(0)

    params = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    print(json.dumps(send_command(sys.argv[1], params), indent=2, ensure_ascii=False))
