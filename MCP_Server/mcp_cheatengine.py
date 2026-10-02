import sys
import os

# ============================================================================
# CRITICAL: WINDOWS LINE ENDING FIX FOR MCP (MONKEY-PATCH)
# The MCP SDK's stdio_server uses TextIOWrapper without newline='\n', causing
# Windows to output CRLF (\r\n) instead of LF (\n). This causes the error:
# "invalid trailing data at the end of stream"
# We MUST patch the MCP SDK BEFORE importing FastMCP.
# ============================================================================

if sys.platform == "win32":
    import msvcrt
    from io import TextIOWrapper
    from contextlib import asynccontextmanager

    # Set binary mode on the underlying handles so the MCP transport does not
    # translate LF -> CRLF. Guarded: when the server is imported for tooling
    # (or launched with redirected/closed stdio) these handles may not exist,
    # and an unguarded setmode() would abort the process at import time.
    def _force_binary(stream):
        try:
            if stream is not None and hasattr(stream, "fileno"):
                msvcrt.setmode(stream.fileno(), os.O_BINARY)
        except (ValueError, OSError, AttributeError):
            pass

    _force_binary(sys.stdin)
    _force_binary(sys.stdout)

    # Monkey-patch the MCP SDK's stdio_server to use newline='\n'
    import mcp.server.stdio as mcp_stdio
    import anyio
    import anyio.lowlevel
    import mcp.types as types
    from mcp.shared.message import SessionMessage
    
    @asynccontextmanager
    async def _patched_stdio_server(
        stdin: "anyio.AsyncFile[str] | None" = None,
        stdout: "anyio.AsyncFile[str] | None" = None,
    ):
        """Patched stdio_server with proper Windows newline handling."""
        if not stdin:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdin = anyio.wrap_file(TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline='\n'))
        if not stdout:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdout = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline='\n'))

        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

        async def stdin_reader():
            try:
                async with read_stream_writer:
                    async for line in stdin:
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await read_stream_writer.send(exc)
                            continue
                        session_message = SessionMessage(message)
                        await read_stream_writer.send(session_message)
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async def stdout_writer():
            try:
                async with write_stream_reader:
                    async for session_message in write_stream_reader:
                        json = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                        await stdout.write(json + "\n")
                        await stdout.flush()
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            yield read_stream, write_stream
    
    # Apply the monkey-patch
    mcp_stdio.stdio_server = _patched_stdio_server

# ============================================================================
# STDOUT PROTECTION FOR MCP
# MCP uses stdout for JSON-RPC. ANY stray output corrupts it.
# ============================================================================

# Save original stdout for MCP to use
_mcp_stdout = sys.stdout

# Redirect stdout to stderr so any accidental prints go to logs, not MCP stream
sys.stdout = sys.stderr

# Now safe to import libraries that might print during import
import json
import struct
import time
import math
import itertools
import threading
import traceback
import socket as _socket

try:
    # SDK dual-version compatibility: mcp 2.x renamed FastMCP to MCPServer
    # (mcp.server.mcpserver); 1.x keeps FastMCP (mcp.server.fastmcp). Both
    # expose the same decorator/add_tool/run surface this module uses, and
    # both import stdio_server into their server module namespace, so the
    # Windows CRLF patch below can be applied to whichever one is present.
    try:
        from mcp.server.mcpserver import MCPServer as _ServerClass  # mcp >= 2
        _MCP_SERVER_MODULE = "mcp.server.mcpserver.server"
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as _ServerClass  # noqa: F401
        _MCP_SERVER_MODULE = "mcp.server.fastmcp.server"

    if sys.platform == "win32":
        import importlib as _importlib
        fastmcp_server = _importlib.import_module(_MCP_SERVER_MODULE)
        fastmcp_server.stdio_server = _patched_stdio_server

except ImportError as e:
    print(f"[MCP CE] Import Error: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

# Restore stdout for MCP usage after imports are complete
sys.stdout = _mcp_stdout

# Debug helper - always goes to stderr, never corrupts MCP
def debug_log(msg):
    print(f"[MCP CE] {msg}", file=sys.stderr, flush=True)

# Helper to format results as proper JSON strings for MCP tools
def format_result(result):
    """Format a CE Bridge result as a JSON string for AI consumption.

    Never raises: an unexpected payload type is reported as an error object so
    the tool call still returns something the agent can read.
    """
    if result is None:
        return json.dumps({"success": False, "error": "Empty result from bridge",
                           "error_code": "INTERNAL_ERROR"}, ensure_ascii=False)
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, indent=None, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as exc:
        return json.dumps({"success": False, "error_code": "INTERNAL_ERROR",
                           "error": f"Result not JSON-serialisable: {exc}"}, ensure_ascii=False)

# ============================================================================
# CONFIGURATION
# ============================================================================

MCP_SERVER_NAME = "cheatengine"

# The native DLL frames with a 32-bit length prefix and refuses to read a
# command larger than MAX_CMD_SIZE (4 MiB). Guarding here turns "the bridge
# silently dropped the connection" into an actionable message.
MAX_RESPONSE_SIZE_BYTES = 32 * 1024 * 1024
MAX_REQUEST_SIZE_BYTES = 4 * 1024 * 1024

# Host/endpoint configuration. TCP is the only transport: the Lua bridge has
# shipped a native TCP server (4-byte LE length prefix + JSON-RPC) since v15.
CE_HOST = os.environ.get("CE_HOST", "127.0.0.1")
CE_PORT = int(os.environ.get("CE_PORT", "17171"))

# Optional shared-token authentication (design borrowed from
# tonytranrp/cheat-engine-mcp, implemented at the Lua dispatch layer — no DLL
# change). Set CE_MCP_AUTH_TOKEN to the same value on both sides; when set,
# every request carries params._auth and the Lua bridge rejects anything else
# with AUTH_REQUIRED before the handler runs. Unset on both sides = open
# loopback access (the default).
CE_AUTH_TOKEN = os.environ.get("CE_MCP_AUTH_TOKEN") or None

# How many extra attempts after the first failure. Only ever applied to
# *connection* failures — never to timeouts (see send_command).
CE_MAX_RETRIES = int(os.environ.get("CE_MCP_RETRIES", "2"))
# Timeout for the identity handshake that distinguishes "CE bridge" from
# "some other service happens to own this port".
CE_PROBE_TIMEOUT = float(os.environ.get("CE_MCP_PROBE_TIMEOUT", "3.0"))
# Seconds to wait between connection retries.
CE_RETRY_DELAY = float(os.environ.get("CE_MCP_RETRY_DELAY", "0.3"))


def _parse_timeout_seconds(raw_value):
    """Parse CE_MCP_TIMEOUT seconds; <=0 disables timeout."""
    if raw_value is None:
        return 90.0
    try:
        timeout = float(raw_value)
    except (TypeError, ValueError):
        return 30.0
    if not math.isfinite(timeout):
        return 30.0
    if timeout <= 0:
        return None
    return timeout


# Per-command wall-clock budget. Must stay BELOW the DLL's own 120 s
# wait, otherwise the DLL reports the timeout and the Python side keeps waiting.
CE_MCP_TIMEOUT_SECONDS = _parse_timeout_seconds(os.environ.get("CE_MCP_TIMEOUT"))

_REQUEST_COUNTER = itertools.count(1)


# ============================================================================
# ERROR HELPERS
# ============================================================================

def error_payload(exc, method=None):
    """Convert any exception into the bridge's documented error shape."""
    if isinstance(exc, TimeoutError):
        code = "TIMEOUT"
    elif isinstance(exc, ConnectionError):
        code = "BRIDGE_UNAVAILABLE"
    else:
        code = "CLIENT_ERROR"
    payload = {"success": False, "error": str(exc), "error_code": code}
    if method:
        payload["method"] = method
    return payload


# ============================================================================
# SHARED BRIDGE CLIENT (framing, timeout, retry, error unwrapping)
# ============================================================================

class BaseBridgeClient:
    """Transport-agnostic half of the bridge client.

    Subclasses supply connect/close/is_open/_exchange_once; everything else
    (locking, timeouts, retry policy, JSON-RPC unwrapping) lives here so TCP
    and Named Pipe cannot drift apart.
    """

    #: extra attempts after the first failure (connection errors only)
    max_retries = CE_MAX_RETRIES

    def __init__(self):
        self.timeout_seconds = CE_MCP_TIMEOUT_SECONDS
        self._io_lock = threading.Lock()        # exactly one in-flight request
        self._conn_lock = threading.RLock()     # guards connect()/close()
        self._last_error = None

    # ---- transport hooks ---------------------------------------------------
    def connect(self) -> bool:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def is_open(self) -> bool:
        raise NotImplementedError

    def _exchange_once(self, req_json: bytes) -> dict:
        raise NotImplementedError

    # ---- framing -----------------------------------------------------------
    def _exchange_with_timeout(self, req_json, method):
        """Send one request and read one reply, honouring CE_MCP_TIMEOUT."""
        timeout = self.timeout_seconds
        if timeout is None:
            return self._exchange_once(req_json)

        box = {}

        def _worker():
            try:
                box["r"] = self._exchange_once(req_json)
            except Exception as exc:  # propagated to the caller below
                box["e"] = exc

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            # The reply may still arrive later; a late frame would desynchronise
            # the length-prefixed stream, so the connection is not reusable.
            self.close()
            raise TimeoutError(
                f"'{method}' timed out after {timeout:g}s (raise CE_MCP_TIMEOUT for long scans). "
                "The command may still be running inside Cheat Engine. "
                + self._diagnose_after_timeout()
            )
        if "e" in box:
            raise box["e"]
        return box["r"]

    @staticmethod
    def _unwrap(response, method):
        """Turn a JSON-RPC envelope into the bridge's flat result dict."""
        if not isinstance(response, dict):
            return {"success": False, "method": method, "error_code": "INTERNAL_ERROR",
                    "error": "Malformed response from CE bridge"}

        if "error" in response:
            err = response["error"]
            code = None
            if isinstance(err, dict):
                data = err.get("data")
                if isinstance(data, dict):
                    code = data.get("error_code")
                msg = err.get("message") or json.dumps(err, ensure_ascii=False)
            else:
                msg = str(err)
            return {"success": False, "method": method,
                    "error": msg, "error_code": code or "RPC_ERROR"}

        result = response.get("result", response)
        if isinstance(result, dict):
            return result
        return {"success": False, "method": method, "error_code": "INTERNAL_ERROR",
                "error": f"Unexpected result payload: {type(result).__name__}"}

    # ---- request path ------------------------------------------------------
    def _build_request(self, method, params):
        params = dict(params or {})
        if CE_AUTH_TOKEN is not None:
            params.setdefault("_auth", CE_AUTH_TOKEN)
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": next(_REQUEST_COUNTER),
        }
        # ensure_ascii=False is REQUIRED: the Lua side must receive raw UTF-8.
        # With the json.dumps() default (ensure_ascii=True) every non-ASCII
        # character became a \uXXXX escape, which the bridge's decoder rejected
        # as a parse error — so write_string("中文"), evaluate_lua with CJK,
        # non-ASCII file paths, speak_text etc. all failed.
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def send_command(self, method, params=None, retries=None):
        """Raises on failure. Tool bodies should call call() instead."""
        attempts = self.max_retries if retries is None else max(0, int(retries))
        last_error = None

        for attempt in range(attempts + 1):
            with self._conn_lock:
                if not self.is_open() and not self.connect():
                    last_error = ConnectionError(
                        f"Cannot connect to the CE bridge. Ensure ce_mcp_bridge.lua is "
                        f"running in Cheat Engine ({self.describe_endpoint()})."
                    )
                    if attempt < attempts:
                        time.sleep(CE_RETRY_DELAY)
                        continue
                    raise last_error

            req_json = self._build_request(method, params)
            if len(req_json) > MAX_REQUEST_SIZE_BYTES:
                raise ValueError(
                    f"Request for '{method}' is {len(req_json)} bytes, over the "
                    f"{MAX_REQUEST_SIZE_BYTES} byte bridge limit. Split it into "
                    f"smaller writes (e.g. chunked write_memory / write_region_to_file)."
                )

            try:
                with self._io_lock:
                    response = self._exchange_with_timeout(req_json, method)
                return self._unwrap(response, method)
            except TimeoutError:
                # NEVER retry a timeout. The command may have already executed
                # (write_memory, auto_assemble, inject_dll, execute_code...),
                # so a retry would apply the side effect a second time.
                raise
            except (ConnectionError, OSError) as exc:
                last_error = exc
                with self._conn_lock:
                    self.close()
                if attempt < attempts:
                    time.sleep(CE_RETRY_DELAY)
                    continue

        raise last_error or ConnectionError("Unknown communication error")

    def describe_endpoint(self) -> str:
        return self.__class__.__name__

    def _diagnose_after_timeout(self) -> str:
        """Subclasses may probe the endpoint to explain a timeout. Best-effort:
        never raises, never adds more than ~4s."""
        return ""


# ============================================================================
# TCP CLIENT (default — local and remote, stdlib only)
# ============================================================================

CE_PORT_SCAN_RANGE = int(os.environ.get("CE_PORT_RANGE", "10"))


class TCPBridgeClient(BaseBridgeClient):
    """TCP client for the native CE MCP bridge.

    The DLL binds the first free port in [CE_PORT, CE_PORT+N) and the client
    mirrors that scan, verifying each candidate with a ping so an unrelated
    service squatting on the port is not mistaken for a bridge.
    """

    def __init__(self, host=CE_HOST, port=CE_PORT):
        super().__init__()
        self.host = host
        self.base_port = port
        self.port = port
        self.sock = None

    def describe_endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def _diagnose_after_timeout(self) -> str:
        """Discriminate the three timeout causes the caller cannot see otherwise:
        CE gone (no listener) vs CE main thread blocked (modal dialog / long
        command — the Lua timer cannot fire while blocked) vs budget too small
        (a fresh ping answers). Diagnosis text is appended to the TimeoutError."""
        diagnosis = "Diagnosis: "
        sock = None
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((self.host, self.port))
            sock.settimeout(2.0)
            ping = json.dumps({"jsonrpc": "2.0", "method": "ping",
                               "params": {}, "id": 0},
                              ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            sock.sendall(struct.pack("<I", len(ping)) + ping)
            hdr = self._recv_from(sock, 4)
            body_len = struct.unpack("<I", hdr)[0]
            if body_len > 1024 * 1024:
                diagnosis += "bridge replied with an oversized frame (unexpected)."
                return diagnosis
            self._recv_from(sock, body_len)
            diagnosis += ("a fresh ping answers — the original command simply "
                          "exceeded its budget; raise CE_MCP_TIMEOUT for "
                          "long-running work")
            return diagnosis
        except _socket.timeout:
            diagnosis += ("the port accepts TCP but ping got no reply — CE's main "
                          "thread is likely BLOCKED (modal dialog, inputQuery, or a "
                          "long command). The DLL fast path still works while "
                          "blocked: call dialog_enum to see open dialogs and "
                          "dialog_dismiss to close one remotely, or wait.")
            return diagnosis
        except (ConnectionError, OSError):
            diagnosis += (f"no listener on {self.host}:{self.port} — Cheat Engine or "
                          "the bridge script is down (crash, exit, or reload in progress).")
            return diagnosis
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def is_open(self) -> bool:
        return self.sock is not None

    # ---- connection --------------------------------------------------------
    def _try_connect(self, port):
        """Open a TCP connection to one port. Returns a socket or None."""
        sock = None
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)
            sock.settimeout(0.5)
            sock.connect((self.host, port))
            sock.settimeout(None)
            return sock
        except (_socket.error, OSError):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            return None

    def _is_ce_bridge(self, sock):
        """Send a ping to confirm the peer really is a CE MCP bridge."""
        try:
            ping_req = json.dumps(
                {"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 0},
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            payload = struct.pack('<I', len(ping_req)) + ping_req
            sock.settimeout(CE_PROBE_TIMEOUT)
            sock.sendall(payload)

            hdr = self._recv_from(sock, 4)
            resp_len = struct.unpack('<I', hdr)[0]
            if resp_len > 1024 * 1024:
                return False
            body = self._recv_from(sock, resp_len)
            resp = json.loads(body.decode('utf-8', errors='replace'))
            sock.settimeout(None)
            return bool(resp.get('result', {}).get('success', False))
        except Exception:
            return False

    @staticmethod
    def _recv_from(sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("CE bridge closed the connection.")
            buf.extend(chunk)
        return bytes(buf)

    def connect(self) -> bool:
        # 1) the configured / last known port
        sock = self._try_connect(self.port)
        if sock and self._is_ce_bridge(sock):
            self.sock = sock
            debug_log(f"TCP connected to {self.host}:{self.port}")
            return True
        if sock:
            try:
                sock.close()
            except Exception:
                pass

        # 2) scan the DLL's port range
        for offset in range(CE_PORT_SCAN_RANGE):
            port = self.base_port + offset
            if port == self.port:
                continue
            sock = self._try_connect(port)
            if sock and self._is_ce_bridge(sock):
                self.port = port
                self.sock = sock
                debug_log(f"TCP found CE bridge at {self.host}:{port}")
                return True
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        debug_log(
            f"TCP scan failed: no CE bridge on {self.host}:"
            f"{self.base_port}-{self.base_port + CE_PORT_SCAN_RANGE - 1}"
        )
        return False

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(_socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # ---- I/O ---------------------------------------------------------------
    def _exchange_once(self, req_json: bytes) -> dict:
        payload = struct.pack('<I', len(req_json)) + req_json
        self.sock.sendall(payload)

        resp_len = struct.unpack('<I', self._recv_from(self.sock, 4))[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ConnectionError(f"Response too large: {resp_len} bytes")

        body = self._recv_from(self.sock, resp_len)
        return _decode_json_body(body)


# ============================================================================
# RESPONSE DECODING
# ============================================================================

def _decode_json_body(body: bytes) -> dict:
    """Parse a JSON-RPC body, tolerating invalid UTF-8 from the target process.

    Handlers such as read_clipboard / evaluate_lua can legitimately return
    bytes that are not valid UTF-8. Decoding strictly crashed the whole tool
    call with a UnicodeDecodeError that no except-clause caught.
    """
    try:
        text = body.decode('utf-8')
    except UnicodeDecodeError:
        text = body.decode('utf-8', errors='replace')
        debug_log("Bridge response contained invalid UTF-8; replaced bad bytes.")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConnectionError(f"Invalid JSON from CE bridge: {exc}") from exc


# ============================================================================
# CLIENT FACTORY
# ============================================================================

def _create_client():
    debug_log(f"Transport: TCP ({CE_HOST}:{CE_PORT})")
    return TCPBridgeClient(CE_HOST, CE_PORT)


ce_client = _create_client()


def call(method, params=None, retries=None):
    """Invoke a bridge command and NEVER raise.

    Every MCP tool goes through this so a dead bridge, a timeout or a bad
    payload comes back as {success:false, error_code:...} that the agent can act
    on, instead of an exception that surfaces as an opaque tool failure.
    """
    try:
        return ce_client.send_command(method, params, retries=retries)
    except Exception as exc:  # noqa: BLE001 - deliberately total
        debug_log(f"call('{method}') failed: {type(exc).__name__}: {exc}")
        return error_payload(exc, method)

# ============================================================================
# MCP SERVER — v15.1 (native TCP transport)
# ============================================================================

mcp = _ServerClass(MCP_SERVER_NAME)

# ============================================================================
# UNIT-32 — LAYERED / PROGRESSIVE TOOL LOADING
# ============================================================================
# 243 tools with full JSON schemas in a single tools/list costs the client
# tens of thousands of tokens of context on every session start. Tools are
# therefore *recorded* while the module body executes (mcp.tool is swapped
# for a recorder below) and only registered selectively:
#
#   CE_MCP_TOOLS=all                      (default) register everything
#   CE_MCP_TOOLS=core                     only the always-on core set
#   CE_MCP_TOOLS=core,memory,debug,...    core plus named categories
#   CE_MCP_TOOLS=minimal                  alias for "core"
#
# "core" is always included so the agent can always: check bridge health,
# read/write memory, evaluate Lua, recover from modal dialogs and load more
# tool categories via the always-registered ce_tools_manage tool.
#
# Startup registration is done by _register_startup_tools() at the bottom of
# this module; ce_tools_manage(action="enable", ...) extends the surface at
# runtime and best-effort sends notifications/tools/list_changed.
# ============================================================================

_TOOL_SPECS = []  # function objects in definition order; FastMCP derives the
                  # tool name and description from __name__ / __doc__


def _record_tool(*_args, **_kwargs):
    """Drop-in stand-in for FastMCP.tool() during the module body: record the
    function for selective registration instead of registering immediately."""
    def decorator(fn):
        _TOOL_SPECS.append(fn)
        return fn
    return decorator


mcp.tool = _record_tool  # instance attribute shadows the class method until
                         # startup registration completes, then it is removed

# --- BRIDGE INTROSPECTION & BATCHING ---

@mcp.tool()
def bridge_status() -> str:
    """Health/diagnostics snapshot of the bridge (prefer this over ping()).

    Returns JSON with: success, version, transport, port, native (DLL status:
    listening/connected/running/port), process_id, process_attached,
    target_arch, uptime_seconds, method_count, resources (live breakpoints,
    DBVM watches, persistent scans), stats (commands/errors/batches handled)
    and last_method / last_error / last_error_code.

    Use it first when something looks wrong: process_attached=false means CE has
    no target open, and last_error_code tells you how the previous call failed.
    """
    return format_result(call("status"))

@mcp.tool()
def list_bridge_methods(prefix: str = "", offset: int = 0, limit: int = 500) -> str:
    """List every command the bridge dispatcher accepts (self-discovery).

    Args:
        prefix: Optional name filter, e.g. "dbk", "persistent_scan", "aob_".
        offset: Start index for pagination.
        limit: Maximum names to return (default 500, max 10000).

    Returns JSON with: success, total, offset, limit, returned, methods.
    """
    params = {"offset": offset, "limit": limit}
    if prefix:
        params["prefix"] = prefix
    return format_result(call("list_methods", params))

@mcp.tool()
def batch_call(calls: list, stop_on_error: bool = True) -> str:
    """Run several bridge commands in ONE round trip (max 64 per batch).

    Each entry is {"method": "<name>", "params": {...}}. Use this whenever you
    are about to issue several independent commands — reading a handful of
    addresses, probing several modules, applying a multi-step patch — because
    it removes one MCP + socket round trip per command (each currently costs
    ~1-15 ms plus client overhead, and they are serialised server-side anyway).

    Args:
        calls: List of {"method", "params"} objects. Nesting "batch" inside a
            batch is rejected.
        stop_on_error: When True (default) stop at the first failure; when False
            run every entry and report all failures.

    Returns JSON with: success (True only if every sub-command succeeded),
    requested, executed, succeeded, failed, stopped_early, and
    results: [{index, method, success, error_code, ...}] where each entry is the
    normal single-command result.
    """
    return format_result(call("batch", {"calls": calls, "stop_on_error": stop_on_error}))

@mcp.tool()
def get_audit_log(offset: int = 0, limit: int = 100, clear: bool = False) -> str:
    """Read the bridge's audit trail of mutating commands (newest first).

    Every write-class command (write_*, set_*, execute_*, auto_assemble,
    load/save_table, symbol registration, process attach, ...) is recorded
    with a timestamp, success flag, error_code and a compact params summary
    (long values like scripts are summarized as <NB> byte counts). Read-only
    probes are not recorded. The ring keeps the newest 200 entries and is
    reset when the Lua script reloads.

    Args:
        offset: Skip this many of the newest entries (0 = most recent).
        limit: Maximum entries to return (default 100, max 200).
        clear: Empty the audit log after reading.

    Returns JSON with: success, total, offset, limit, returned, entries
    (each {time, method, success, error_code, params}), cleared.
    """
    return format_result(call("get_audit_log", {"offset": offset, "limit": limit,
                                                "clear": clear}))

@mcp.tool()
def list_apis(filter: str = "", offset: int = 0, limit: int = 200) -> str:
    """Enumerate the global Lua functions available inside the Cheat Engine VM.

    Self-introspection for the celua surface: instead of guessing whether an
    API exists (getMemoryRecordByID vs al.getMemoryRecord confusion), query
    the actual VM. Returns plain-name matches; qualify with record tables or
    method calls as documented in celua.txt.

    Args:
        filter: Case-insensitive substring filter on function names
            (e.g. "memory" -> getMemoryRecord*, memory_record_*).
        offset: Pagination start (0-based, alphabetical order).
        limit: Max names per page (default 200, max 2000).

    Returns JSON with: success, total, offset, limit, returned, apis (sorted names).
    """
    return format_result(call("list_apis", {"filter": filter, "offset": offset,
                                            "limit": limit}))

@mcp.tool()
def table_state() -> str:
    """Report the loaded table's path, on-disk size/hash and in-memory record count.

    Answers "is the CE in-memory table in sync with the file on disk" before a
    save_table would risk overwriting newer disk edits. The hash is FNV-1a 32-bit
    over the file contents: capture it before editing, compare after.

    Returns JSON with: success, table_path (absent when no table loaded / CE < 7.4),
    disk_size, disk_fnv1a, disk_exists, memory_records, note.
    """
    return format_result(call("table_state", {}))

@mcp.tool()
def patch_memory_record_script(id: int, find: str, replace: str = "",
                               all: bool = False) -> str:
    """Uniqueness-guarded find/replace inside a memoryrecord's AA/Lua script.

    Hot-fix table scripts without re-sending the whole text. The previous
    script text is pushed onto an undo ring (5 deep per record) before the
    write, so mistakes are reversible with undo_memory_record_script_patch.

    Args:
        id: Memoryrecord ID.
        find: Literal text to locate (plain match, no regex).
        replace: Replacement text ("" deletes the match).
        all: Replace every occurrence. Without it, a multi-match find is
            rejected with AMBIGUOUS_MATCH so accidental broad edits fail safe.

    Returns JSON with: success, replaced, old_length, new_length.
    Error codes: NO_MATCH, AMBIGUOUS_MATCH, NO_SCRIPT, INVALID_PARAMS.
    """
    return format_result(call("patch_memory_record_script",
                              {"id": id, "find": find, "replace": replace, "all": all}))

@mcp.tool()
def undo_memory_record_script_patch(id: int) -> str:
    """Restore the previous script text of a memoryrecord from the undo ring.

    Pops the newest patch made by patch_memory_record_script for this record
    (ring depth 5). Returns JSON with: success, restored_length,
    remaining_history. Error code NO_HISTORY when nothing to undo.
    """
    return format_result(call("undo_memory_record_script_patch", {"id": id}))

# --- DLL FAST PATH (answered by the DLL's server thread, not by CE Lua) -----
#
# The dll_* methods below are intercepted inside ce_mcp_tcp.dll BEFORE the
# command queue: CE's main thread never runs them. They work — instantly —
# even while a modal dialog blocks CE's main thread and every other tool
# times out. Use dll_status to distinguish "Lua busy" from "Lua frozen".

@mcp.tool()
def dll_status() -> str:
    """DLL-side health report, answered by the DLL's own thread (always works).

    Unlike `status` (which runs on CE's main thread and dies with it), this
    reports the transport layer from inside the DLL: frame/byte counters,
    last method, and poll_age_ms — the time since CE's main thread last
    serviced the bridge. A large poll_age_ms with lua_responsive=false means
    the main thread is blocked or busy; call dialog_enum to check for a modal.

    Returns JSON with: success, component, version, uptime_ms, frames_rx,
    frames_tx, bytes_rx, bytes_tx, last_method, poll_age_ms, lua_responsive.
    """
    return format_result(call("dll_status", {}))

@mcp.tool()
def dialog_enum() -> str:
    """List top-level windows of the Cheat Engine process (DLL fast path).

    Runs inside the DLL's server thread, so it answers even when CE's main
    thread is blocked by a modal dialog — the exact situation where every
    Lua-backed tool times out. A modal is usually an enabled dialog whose
    parent window is disabled. TMainForm and TApplication are listed but
    protected from dismissal.

    Returns JSON with: success, count, dialogs (each {index, hwnd, class,
    title, enabled}).
    """
    return format_result(call("dll_enum_dialogs", {}))

@mcp.tool()
def dialog_dismiss(index: int = None, hwnd: int = None, title: str = None,
                   force: bool = False) -> str:
    """Close a Cheat Engine window remotely (DLL fast path, works while blocked).

    Posts WM_CLOSE to the target window. Identify the target by index/hwnd
    from dialog_enum, or by case-insensitive title substring. Safety rails:
    windows of class TMainForm or TApplication are refused unless force=true
    (closing them can kill CE); only windows of the CE process are eligible.

    Args:
        index: Dialog index from dialog_enum (0-based).
        hwnd: Window handle from dialog_enum.
        title: Case-insensitive substring of the window title.
        force: Allow closing protected classes (TMainForm/TApplication).

    Returns JSON with: success, posted, hwnd, class.
    Error codes: INVALID_PARAMS, INVALID_TARGET, NOT_FOUND, PROTECTED_WINDOW.
    """
    params = {}
    if index is not None: params["index"] = index
    if hwnd is not None: params["hwnd"] = hwnd
    if title is not None: params["title"] = title
    if force: params["force"] = True
    return format_result(call("dll_dismiss_dialog", params))

@mcp.tool()
def wait_until(method: str, params: dict = None, path: str = "success",
               expected=None, timeout: float = 30.0, interval: float = 1.0) -> str:
    """Poll a bridge command until a field in its result reaches a value.

    Replaces blind external sleep-retry loops: instead of "sleep 5, try again",
    make one call that polls the bridge at `interval` until the condition holds
    or `timeout` expires. Typical uses: wait for a persistent scan to finish
    (wait_until("persistent_scan_get_results", {...}, "success", True)),
    wait for a memoryrecord to apply, wait for a process to be attached
    (wait_until("status", {}, "process_attached", True)).

    Args:
        method: Bridge command to invoke each round (must succeed at the RPC
            level; RPC errors are retried like any other non-match).
        params: Parameters dict passed through to the command.
        path: Dot path into the result dict, e.g. "success",
            "process_attached", "records.0.enabled" (numeric segments index lists).
        expected: Value to wait for. Comparison is `value == expected`, or
            `str(value) == expected` when expected is a string.
        timeout: Total budget in seconds (default 30, min 0.1).
        interval: Seconds between rounds (default 1.0, min 0.05). The first
            probe runs immediately.

    Returns JSON with: success (condition met), satisfied, attempts, elapsed,
    last_value (value observed at `path` on the final round, when present),
    last_result (full final result).
    """
    import time as _time
    if not method or not isinstance(method, str):
        return json.dumps({"success": False, "error": "method required",
                           "error_code": "INVALID_PARAMS"}, ensure_ascii=False)
    timeout = max(0.1, float(timeout))
    interval = max(0.05, float(interval))
    deadline = _time.monotonic() + timeout
    attempts, last_value, last_result = 0, None, None
    segments = [seg for seg in str(path).split(".") if seg]

    def _walk(obj):
        cur = obj
        for seg in segments:
            if isinstance(cur, dict) and seg in cur:
                cur = cur[seg]
            elif isinstance(cur, list):
                try:
                    cur = cur[int(seg)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return cur

    def _matches(value):
        if value == expected:
            return True
        return isinstance(expected, str) and str(value) == expected

    while True:
        attempts += 1
        last_result = call(method, params)
        last_value = _walk(last_result)
        if _matches(last_value):
            return json.dumps({"success": True, "satisfied": True, "attempts": attempts,
                               "elapsed": round(timeout - (deadline - _time.monotonic()), 3),
                               "last_value": last_value, "last_result": last_result},
                              ensure_ascii=False, default=str)
        if _time.monotonic() >= deadline:
            return json.dumps({"success": False, "satisfied": False, "attempts": attempts,
                               "elapsed": timeout, "last_value": last_value,
                               "last_result": last_result,
                               "error": f"condition '{path}' == {expected!r} not met "
                                        f"within {timeout:g}s", "error_code": "TIMEOUT"},
                              ensure_ascii=False, default=str)
        _time.sleep(interval)

# --- PROCESS & MODULES ---

@mcp.tool()
def get_process_info() -> str:
    """Get current process ID, name, modules count and architecture."""
    return format_result(call("get_process_info"))

@mcp.tool()
def enum_modules(offset: int = 0, limit: int = 100) -> str:
    """List all loaded modules (DLLs) with their base addresses and sizes.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum modules to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, modules.
    """
    return format_result(call("enum_modules", {"offset": offset, "limit": limit}))

@mcp.tool()
def get_thread_list(offset: int = 0, limit: int = 100) -> str:
    """Get list of threads in the attached process.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum threads to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, threads.
    """
    return format_result(call("get_thread_list", {"offset": offset, "limit": limit}))

@mcp.tool()
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name (e.g., 'Engine.GameEngine') to an address."""
    return format_result(call("get_symbol_address", {"symbol": symbol}))

@mcp.tool()
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Get symbolic name and module info for an address (Reverse of get_symbol_address)."""
    return format_result(call("get_address_info", {
        "address": address, 
        "include_modules": include_modules, 
        "include_symbols": include_symbols,
        "include_sections": include_sections
    }))

@mcp.tool()
def get_rtti_classname(address: str) -> str:
    """Try to identify the class name of an object at address using Run-Time Type Information."""
    return format_result(call("get_rtti_classname", {"address": address}))

# --- MEMORY READING ---

@mcp.tool()
def read_memory(address: str, size: int = 256, include_bytes: bool = False) -> str:
    """Read raw bytes from memory.

    Args:
        address: Address to read (hex string or symbol).
        size: Number of bytes to read (1 .. 1048576, default 256).
        include_bytes: Also return a "bytes" array. It carries exactly the same
            information as "data" (space-separated hex) but as a JSON list, i.e.
            roughly 4x the wire size — leave it off unless a caller really needs
            to index individual bytes.

    Returns JSON with: success, address, size, data, and optionally bytes.
    """
    return format_result(call("read_memory", {"address": address, "size": size,
                                              "include_bytes": include_bytes}))

@mcp.tool()
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number from memory. Types: byte, word, dword, qword, float, double."""
    return format_result(call("read_integer", {"address": address, "type": type}))

@mcp.tool()
def read_string(address: str, max_length: int = 256, wide: bool = False, encoding: str = "utf8") -> str:
    """Read a string from memory.

    Args:
        address: Memory address to read from.
        max_length: Maximum number of bytes to read.
        wide: Legacy flag — when True, overrides encoding to 'utf16le' for backward compat.
        encoding: One of 'ascii', 'utf8' (default), 'utf16le', or 'raw'.
                  'ascii': strip non-printable bytes.
                  'utf8': preserve valid UTF-8 multi-byte sequences.
                  'utf16le': read as wide (UTF-16 LE) string.
                  'raw': return bytes as a hex string (e.g. '48 65 6C 6C 6F').

    Returns JSON with: success, address, value, encoding, wide, length, raw_length.
    """
    # Backward compat: wide=True maps to utf16le unless caller also set encoding explicitly
    resolved_encoding = "utf16le" if wide else encoding
    return format_result(call("read_string", {"address": address, "max_length": max_length, "wide": wide, "encoding": resolved_encoding}))

@mcp.tool()
def read_pointer(address: str, offsets: list[int] = None) -> str:
    """Read a pointer chain. Returns the final address and value."""
    # Bridge supports 'read_pointer' for single dereference or 'read_pointer_chain' for multiple
    if offsets:
        return format_result(call("read_pointer_chain", {"base": address, "offsets": offsets}))
    else:
        return format_result(call("read_pointer_chain", {"base": address, "offsets": [0]}))

@mcp.tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return analysis of every step."""
    return format_result(call("read_pointer_chain", {"base": base, "offsets": offsets}))

@mcp.tool()
def checksum_memory(address: str, size: int) -> str:
    """Calculate MD5 checksum of a memory region to detect changes."""
    return format_result(call("checksum_memory", {"address": address, "size": size}))

# --- SCANNING ---

@mcp.tool()
def scan_all(value: str, type: str = "exact", protection: str = "+W-C") -> str:
    """Unified Memory Scanner. Types: exact, string, array. Protection: +W-C (Writable, Not Copy-on-Write)."""
    return format_result(call("scan_all", {"value": value, "type": type, "protection": protection}))

@mcp.tool()
def get_scan_results(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Get results from the last 'scan_all' operation.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum results to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, results.
    """
    return format_result(call("get_scan_results", {"offset": offset, "limit": limit, "max": max}))

@mcp.tool()
def next_scan(value: str, scan_type: str = "exact") -> str:
    """Next scan to filter results. Types: exact, increased, decreased, changed, unchanged, bigger, smaller."""
    return format_result(call("next_scan", {"value": value, "scan_type": scan_type}))

@mcp.tool()
def write_integer(address: str, value: int, type: str = "dword") -> str:
    """Write a number to memory. Types: byte, word, dword, qword, float, double."""
    return format_result(call("write_integer", {"address": address, "value": value, "type": type}))

@mcp.tool()
def write_memory(address: str, bytes: list[int]) -> str:
    """Write raw bytes to memory."""
    return format_result(call("write_memory", {"address": address, "bytes": bytes}))

@mcp.tool()
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string to memory (ASCII or Wide/UTF-16)."""
    return format_result(call("write_string", {"address": address, "value": value, "wide": wide}))


@mcp.tool()
def aob_scan(pattern: str, protection: str = "+X", limit: int = 100) -> str:
    """Scan for an Array of Bytes (AOB) pattern. Example: '48 89 5C 24'."""
    return format_result(call("aob_scan", {"pattern": pattern, "protection": protection, "limit": limit}))

@mcp.tool()
def search_string(string: str, wide: bool = False, limit: int = 100) -> str:
    """Quickly search for a text string in memory."""
    return format_result(call("search_string", {"string": string, "wide": wide, "limit": limit}))

@mcp.tool()
def generate_signature(address: str) -> str:
    """Generate a unique AOB signature that can find this specific address again."""
    return format_result(call("generate_signature", {"address": address}))

@mcp.tool()
def get_memory_regions(max: int = 100) -> str:
    """Get list of valid memory regions nearby common bases."""
    return format_result(call("get_memory_regions", {"max": max}))

@mcp.tool()
def enum_memory_regions_full(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Enumerate ALL memory regions in the process (Native EnumMemoryRegions).

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum regions to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, regions.
    """
    return format_result(call("enum_memory_regions_full", {"offset": offset, "limit": limit, "max": max}))

# --- ANALYSIS & DISASSEMBLY ---

@mcp.tool()
def disassemble(address: str, count: int = 20, offset: int = 0, limit: int = 100) -> str:
    """Disassemble instructions starting at an address.

    Args:
        address: Target address (hex string or symbol).
        count: Number of instructions to generate (default 20).
        offset: Start index within the generated list for pagination (default 0).
        limit: Maximum instructions to return (default 100, max 10000).

    Returns JSON with: success, start_address, total, offset, limit, returned, instructions.
    """
    return format_result(call("disassemble", {"address": address, "count": count, "offset": offset, "limit": limit}))

@mcp.tool()
def get_instruction_info(address: str) -> str:
    """Get detailed info about a single instruction (size, bytes, opcode)."""
    return format_result(call("get_instruction_info", {"address": address}))

@mcp.tool()
def find_function_boundaries(address: str, max_search: int = 4096) -> str:
    """Attempt to find the start and end of a function containing the address."""
    return format_result(call("find_function_boundaries", {"address": address, "max_search": max_search}))

@mcp.tool()
def analyze_function(address: str) -> str:
    """Analyze a function to find all CALL instructions output (calls made by this function)."""
    return format_result(call("analyze_function", {"address": address}))

@mcp.tool()
def find_references(address: str, offset: int = 0, limit: int = 50) -> str:
    """Find instructions that access (reference) this address.

    Args:
        address: Target address to find references to.
        offset: Start index for pagination (default 0).
        limit: Maximum references to return (default 50, max 10000).

    Returns JSON with: success, target, total, offset, limit, returned, references, arch.
    """
    return format_result(call("find_references", {"address": address, "offset": offset, "limit": limit}))

@mcp.tool()
def find_call_references(function_address: str, offset: int = 0, limit: int = 100) -> str:
    """Find all locations that CALL this function.

    Args:
        function_address: Address of the function to find callers of.
        offset: Start index for pagination (default 0).
        limit: Maximum callers to return (default 100, max 10000).

    Returns JSON with: success, function_address, total, offset, limit, returned, callers.
    """
    return format_result(call("find_call_references", {"address": function_address, "offset": offset, "limit": limit}))

@mcp.tool()
def dissect_structure(address: str, size: int = 256) -> str:
    """Use CE's auto-guess feature to interpret memory at address as a structure."""
    return format_result(call("dissect_structure", {"address": address, "size": size}))

# --- DEBUGGING & BREAKPOINTS ---

@mcp.tool()
def set_breakpoint(address: str, id: str = None, capture_registers: bool = True, capture_stack: bool = False, stack_depth: int = 16) -> str:
    """Set a hardware execution breakpoint. Non-breaking/Logging only."""
    return format_result(call("set_breakpoint", {
        "address": address, 
        "id": id,
        "capture_registers": capture_registers,
        "capture_stack": capture_stack,
        "stack_depth": stack_depth
    }))

@mcp.tool()
def set_data_breakpoint(address: str, id: str = None, access_type: str = "w", size: int = 4) -> str:
    """Set a hardware data breakpoint (watchpoint). Types: 'r' (read), 'w' (write), 'rw' (access)."""
    return format_result(call("set_data_breakpoint", {
        "address": address, 
        "id": id,
        "access_type": access_type,
        "size": size
    }))

@mcp.tool()
def remove_breakpoint(id: str) -> str:
    """Remove a breakpoint by its ID."""
    return format_result(call("remove_breakpoint", {"id": id}))

@mcp.tool()
def list_breakpoints() -> str:
    """List all active breakpoints."""
    return format_result(call("list_breakpoints"))

@mcp.tool()
def clear_all_breakpoints() -> str:
    """Remove ALL breakpoints."""
    return format_result(call("clear_all_breakpoints"))

@mcp.tool()
def get_breakpoint_hits(id: str = None, clear: bool = False, offset: int = 0, limit: int = 100) -> str:
    """Get hits for a specific breakpoint ID (or all if None). Set clear=True to flush buffer.

    Args:
        id: Breakpoint ID to query, or None for all breakpoints.
        clear: If True, flush the hit buffer after reading (default False).
        offset: Start index for pagination (default 0).
        limit: Maximum hits to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, hits.
    """
    return format_result(call("get_breakpoint_hits", {"id": id, "clear": clear, "offset": offset, "limit": limit}))

# --- DBVM / HYPERVISOR TOOLS (Ring -1) ---

@mcp.tool()
def get_physical_address(address: str) -> str:
    """Translate Virtual Address to Physical Address (requires DBVM)."""
    return format_result(call("get_physical_address", {"address": address}))

@mcp.tool()
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start invisible DBVM hypervisor watch. Modes: 'w' (writes), 'r' (reads), 'x' (execute)."""
    return format_result(call("start_dbvm_watch", {"address": address, "mode": mode, "max_entries": max_entries}))

@mcp.tool()
def stop_dbvm_watch(address: str) -> str:
    """Stop DBVM watch and return results."""
    return format_result(call("stop_dbvm_watch", {"address": address}))

@mcp.tool()
def poll_dbvm_watch(address: str, max_results: int = 1000, clear: bool = True) -> str:
    """Poll DBVM watch logs WITHOUT stopping. Returns register state at each execution hit.

    Args:
        address: Virtual address of the active watch.
        max_results: Maximum hits to return.
        clear: Consume (clear) the DLL-side watch log after reading. Defaults to
            True so successive polls return each hit once; pass False to keep
            re-reading the whole accumulated log.
    """
    return format_result(call("poll_dbvm_watch", {
        "address": address,
        "max_results": max_results,
        "clear": clear,
    }))

# --- KERNEL MODE / DBVM EXTENSIONS (Unit 21) ---

@mcp.tool()
def dbk_get_cr0() -> str:
    """Read Control Register 0 (CR0) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr0 as a hex string.
    """
    return format_result(call("dbk_get_cr0"))

@mcp.tool()
def dbk_get_cr3() -> str:
    """Read Control Register 3 (CR3 — page-table base) via DBK or DBVM.

    Works when either the DBK kernel driver or the DBVM hypervisor is loaded.
    Returns cr3 as a hex string.
    """
    return format_result(call("dbk_get_cr3"))

@mcp.tool()
def dbk_get_cr4() -> str:
    """Read Control Register 4 (CR4) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr4 as a hex string.
    """
    return format_result(call("dbk_get_cr4"))

@mcp.tool()
def read_process_memory_cr3(cr3: str, address: str, size: int) -> str:
    """Read virtual memory using an explicit CR3 page-table base via DBK/DBVM.

    Bypasses the standard OS memory-translation path, making it effective for
    processes that hide memory from normal reads (e.g. anti-cheat analysis).

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) identifying the target page table.
        address: Virtual address to read from (hex string or symbol name).
        size: Number of bytes to read.
    """
    return format_result(call(
        "read_process_memory_cr3",
        {"cr3": cr3, "address": address, "size": size}
    ))

@mcp.tool()
def write_process_memory_cr3(cr3: str, address: str, bytes: list) -> str:
    """Write to virtual memory using an explicit CR3 page-table base via DBK/DBVM.

    Bypasses the standard OS memory-translation path.

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) identifying the target page table.
        address: Virtual address to write to (hex string or symbol name).
        bytes: List of integer byte values to write.
    """
    return format_result(call(
        "write_process_memory_cr3",
        {"cr3": cr3, "address": address, "bytes": bytes}
    ))

@mcp.tool()
def map_memory(address: str, size: int) -> str:
    """Map a kernel/physical address range into the CE usermode context via DBK.

    Returns a mapped_address that can be used for ordinary memory reads/writes.
    Call unmap_memory() with the same mapped_address when finished.

    Requires: DBK kernel driver loaded; a process must be attached.

    Args:
        address: Source address to map (hex string or symbol name).
        size: Number of bytes to map.
    """
    return format_result(call(
        "map_memory",
        {"address": address, "size": size}
    ))

@mcp.tool()
def unmap_memory(mapped_address: str, size: int = 0) -> str:
    """Release a memory mapping created by map_memory().

    The size parameter is accepted for API compatibility but unused internally;
    the MDL handle captured during map_memory() is used to release the mapping.

    Requires: DBK kernel driver loaded; a process must be attached.

    Args:
        mapped_address: The mapped address returned by a prior map_memory() call.
        size: Unused; kept for API symmetry with map_memory().
    """
    return format_result(call(
        "unmap_memory",
        {"mapped_address": mapped_address, "size": size}
    ))

@mcp.tool()
def dbk_writes_ignore_write_protection(enable: bool) -> str:
    """Toggle whether DBK memory writes bypass copy-on-write (CoW) protection.

    When enabled, writes go directly to the underlying physical page instead of
    triggering a page fault and creating a process-private copy. Useful when
    patching shared read-only pages across all processes simultaneously.

    Requires: DBK kernel driver loaded.

    Args:
        enable: True to bypass CoW; False to restore normal CoW behaviour.
    """
    return format_result(call(
        "dbk_writes_ignore_write_protection",
        {"enable": enable}
    ))

@mcp.tool()
def get_physical_address_cr3(cr3: str, virtual_address: str) -> str:
    """Translate a virtual address to its physical address using an explicit CR3.

    Unlike get_physical_address (which uses the currently attached process's CR3),
    this function lets you walk any process's page table — useful for cross-process
    physical memory analysis.

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) of the target process's page table.
        virtual_address: Virtual address to translate (hex string or symbol name).
    """
    return format_result(call(
        "get_physical_address_cr3",
        {"cr3": cr3, "virtual_address": virtual_address}
    ))

# --- SCRIPTING & CONTROL ---

@mcp.tool()
def evaluate_lua(code: str) -> str:
    """Execute arbitrary Lua code in Cheat Engine and return the result.

    Any print() output during execution is captured and returned in
    "printed" (list of lines) instead of leaking into the CE console. Table
    return values are serialized to JSON; CE userdata falls back to a shallow
    dump. Prefer dedicated tools (memory/table/scan) over raw Lua when one
    exists — they validate inputs and never risk corrupting CE state.
    """
    return format_result(call("evaluate_lua", {"code": code}))

@mcp.tool()
def auto_assemble(script: str) -> str:
    """Run an AutoAssembler script (injection, code caves, etc)."""
    return format_result(call("auto_assemble", {"script": script}))

@mcp.tool()
def assemble_instruction(
    line: str,
    address: str = None,
    preference: int = 0,
    skip_range_check: bool = False,
) -> str:
    """Assemble a single x86/x64 instruction into bytes.

    Requires an attached process when an address is given (the address is used to
    resolve relative operands such as JMP targets).

    Returns {success, bytes: [int], size: int}.
    preference: 0=none, 1=short, 2=long, 3=far.
    """
    params: dict = {"line": line, "preference": preference, "skip_range_check": skip_range_check}
    if address is not None:
        params["address"] = address
    return format_result(call("assemble_instruction", params))


@mcp.tool()
def auto_assemble_check(
    script: str,
    enable: bool = True,
    target_self: bool = False,
) -> str:
    """Validate an Auto Assembler script for syntax errors without executing it.

    Returns {success, valid: bool, errors: [str]}.
    enable: True checks the [Enable] section; False checks [Disable].
    target_self: if True, validates against CE's own process instead of the target.
    """
    return format_result(call("auto_assemble_check", {
        "script": script,
        "enable": enable,
        "target_self": target_self,
    }))


@mcp.tool()
def compile_c_code(
    source: str,
    address: str = None,
    target_self: bool = False,
    kernelmode: bool = False,
) -> str:
    """Compile C source code using CE's built-in TCC compiler.

    Does not require an attached process unless an address is provided.
    Returns {success, symbols: {name: address}, errors: [str]}.
    If TCC is unavailable: {success=false, error="TCC compiler not available",
    error_code="CE_API_UNAVAILABLE"}.
    """
    params: dict = {"source": source, "target_self": target_self, "kernelmode": kernelmode}
    if address is not None:
        params["address"] = address
    return format_result(call("compile_c_code", params))


@mcp.tool()
def compile_cs_code(
    source: str,
    references: list = None,
    core_assembly: str = None,
) -> str:
    """Compile C# source code using CE's .NET compiler (requires .NET 4+).

    Returns {success, assembly_handle: str} where assembly_handle is the path to
    the generated assembly. On .NET runtime absent:
    {success=false, error_code="CE_API_UNAVAILABLE"}.
    """
    params: dict = {"source": source, "references": references or []}
    if core_assembly is not None:
        params["core_assembly"] = core_assembly
    return format_result(call("compile_cs_code", params))


@mcp.tool()
def generate_api_hook_script(
    address: str,
    target_address: str,
    code_to_execute: str = "",
) -> str:
    """Generate an Auto Assembler script that hooks a function and redirects it.

    Requires an attached process. address is the function to hook;
    target_address is where execution should jump after the hook.
    code_to_execute is optional extra AA code inserted into the generated script.
    Returns {success, script: str}.
    """
    return format_result(call("generate_api_hook_script", {
        "address": address,
        "target_address": target_address,
        "code_to_execute": code_to_execute,
    }))


@mcp.tool()
def generate_code_injection_script(address: str) -> str:
    """Generate a boilerplate code-injection Auto Assembler script for an address.

    Requires an attached process.
    Returns {success, script: str} — the script can be used as a starting point
    for patching code at that location.
    """
    return format_result(call("generate_code_injection_script", {
        "address": address,
    }))


@mcp.tool()
def ping() -> str:
    """Check connectivity and get version info."""
    return format_result(call("ping"))

# --- DEBUG OUTPUT & MULTIMEDIA (Unit 23) ---

@mcp.tool()
def output_debug_string(message: str) -> str:
    """Post a message to the Windows debugger via OutputDebugString (readable with tools like DebugView)."""
    return format_result(call("output_debug_string", {"message": message}))

@mcp.tool()
def speak_text(text: str, english_only: bool = False) -> str:
    """Speak text via Windows SAPI text-to-speech. Set english_only=True to force the English voice."""
    return format_result(call("speak_text", {"text": text, "english_only": english_only}))

@mcp.tool()
def play_sound(filename: str) -> str:
    """Play a WAV sound file by filename. Path must not contain '..' directory traversal."""
    return format_result(call("play_sound", {"filename": filename}))

@mcp.tool()
def beep() -> str:
    """Play a simple system beep sound."""
    return format_result(call("beep", {}))

@mcp.tool()
def set_progress_state(state: str) -> str:
    """Set the Cheat Engine taskbar progress state. Valid states: none, normal, paused, error, indeterminate."""
    return format_result(call("set_progress_state", {"state": state}))

@mcp.tool()
def set_progress_value(current: int, max: int) -> str:
    """Set the Cheat Engine taskbar progress bar position. Provide current value and maximum value."""
    return format_result(call("set_progress_value", {"current": current, "max": max}))
# --- THREADING & SYNCHRONIZATION (Unit-22) ---

@mcp.tool()
def create_thread(code: str, arg: str = "") -> str:
    """Execute Lua code in a new CE thread.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process,
    carrying the same risk as evaluate_lua. Only use with trusted code.

    Returns {success, thread_id}.
    """
    return format_result(call("create_thread", {"code": code, "arg": arg}))

@mcp.tool()
def get_global_variable(name: str) -> str:
    """Read a global variable from CE's main Lua state.

    Useful for reading values set by scripts running in other threads.
    Returns {success, value} where value is stringified via tostring().
    """
    return format_result(call("get_global_variable", {"name": name}))

@mcp.tool()
def set_global_variable(name: str, value: str) -> str:
    """Write a global variable in CE's main Lua state.

    Useful for passing values to scripts running in other threads.
    Returns {success}.
    """
    return format_result(call("set_global_variable", {"name": name, "value": value}))

@mcp.tool()
def queue_to_main_thread(code: str) -> str:
    """Queue Lua code to run on CE's main thread without waiting for its result.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    on the main thread, carrying the same risk as evaluate_lua. Only use with
    trusted code.

    Returns {success}.
    """
    return format_result(call("queue_to_main_thread", {"code": code}))

@mcp.tool()
def check_synchronize() -> str:
    """Process queued main-thread calls (checkSynchronize).

    Call this from an infinite loop in the main thread when using threading
    and synchronize calls. Returns {success}.
    """
    return format_result(call("check_synchronize"))

@mcp.tool()
def in_main_thread() -> str:
    """Check whether the current code is running in CE's main thread.

    Returns {success, is_main_thread}.
    """
    return format_result(call("in_main_thread"))
# >>> BEGIN UNIT-20b Shell Execution <<<
def _check_shell_gate():
    if os.environ.get("CE_MCP_ALLOW_SHELL") != "1":
        return json.dumps({
            "success": False,
            "error": "Shell execution disabled. Set environment variable CE_MCP_ALLOW_SHELL=1 to enable.",
            "error_code": "PERMISSION_DENIED"
        })
    return None

@mcp.tool()
def run_command(command: str, args: str = "") -> str:
    """Execute a shell command in the host OS. SECURITY: Arbitrary code execution.

    REQUIRES environment variable CE_MCP_ALLOW_SHELL=1 at server startup.
    By default, this tool returns a PERMISSION_DENIED error.

    Args:
        command: Command path or name (e.g. "notepad.exe", "cmd.exe").
        args: Arguments string.

    Returns JSON with: success, output, exit_code.
    """
    blocked = _check_shell_gate()
    if blocked:
        return blocked
    return format_result(call("run_command", {"command": command, "args": args}))

@mcp.tool()
def shell_execute(command: str, args: str = "", verb: str = "open", working_dir: str = "", showcommand: int = None) -> str:
    """Invoke Windows ShellExecute. SECURITY: Arbitrary code execution.

    REQUIRES environment variable CE_MCP_ALLOW_SHELL=1 at server startup.

    Args:
        command: Command or file to execute.
        args: Arguments string.
        verb: ShellExecute verb. CE currently supports "open" only.
        working_dir: Working directory (empty for current).
        showcommand: Optional Win32 show command integer.

    Returns JSON with: success.
    """
    blocked = _check_shell_gate()
    if blocked:
        return blocked
    params = {
        "command": command,
        "args": args,
        "verb": verb,
        "working_dir": working_dir,
    }
    if showcommand is not None:
        params["showcommand"] = showcommand
    return format_result(call("shell_execute", params))
# >>> END UNIT-20b <<<
# >>> BEGIN UNIT-20a File IO Clipboard <<<

@mcp.tool()
def file_exists(filename: str) -> str:
    """Check whether a file exists at the given path. Returns {success, exists: bool}."""
    return format_result(call("file_exists", {"filename": filename}))

@mcp.tool()
def delete_file(filename: str) -> str:
    """Delete a file at the given path. Returns {success}.

    WARNING: This is a destructive operation. The file will be permanently deleted
    from disk. Path traversal sequences ('..') are blocked by the bridge. Use with
    extreme caution — there is no undo.
    """
    return format_result(call("delete_file", {"filename": filename}))

@mcp.tool()
def get_file_list(path: str) -> str:
    """List files in the given directory path. Returns {success, count, files: [str]}."""
    return format_result(call("get_file_list", {"path": path}))

@mcp.tool()
def get_directory_list(path: str) -> str:
    """List subdirectories in the given directory path. Returns {success, count, directories: [str]}."""
    return format_result(call("get_directory_list", {"path": path}))

@mcp.tool()
def get_temp_folder() -> str:
    """Return the path to the system temp folder. Returns {success, path: str}."""
    return format_result(call("get_temp_folder"))

@mcp.tool()
def get_file_version(filename: str) -> str:
    """Get the version info of a file (major, minor, release, build). Returns {success, major, minor, release, build, version_string}."""
    return format_result(call("get_file_version", {"filename": filename}))

@mcp.tool()
def read_clipboard() -> str:
    """Read text from the system clipboard. Returns {success, text: str}."""
    return format_result(call("read_clipboard"))

@mcp.tool()
def write_clipboard(text: str) -> str:
    """Write text to the system clipboard. Returns {success}."""
    return format_result(call("write_clipboard", {"text": text}))

# >>> END UNIT-20a <<<
# >>> BEGIN UNIT-19 Structure Management <<<

@mcp.tool()
def create_structure(name: str) -> str:
    """Create a new empty CE structure definition and add it to the global list.

    Args:
        name: The name for the new structure.

    Returns JSON with: success, structure_id.
    """
    return format_result(call("create_structure", {"name": name}))


@mcp.tool()
def get_structure_by_name(name: str) -> str:
    """Find a CE structure by name in the global structure list.

    Args:
        name: The structure name to search for.

    Returns JSON with: success, structure_id, name, element_count, size.
    """
    return format_result(call("get_structure_by_name", {"name": name}))


@mcp.tool()
def add_element_to_structure(structure_id: int, name: str, offset: int, type: str) -> str:
    """Add a new element to an existing CE structure.

    Args:
        structure_id: The structure ID returned by create_structure or get_structure_by_name.
        name: The element name.
        offset: The byte offset of the element within the structure.
        type: The variable type. Accepted values: byte, word, dword, qword,
              float, single, double, string, aob, bytearray, pointer.

    Returns JSON with: success, element_index.
    """
    return format_result(call("add_element_to_structure", {
        "structure_id": structure_id,
        "name": name,
        "offset": offset,
        "type": type,
    }))


@mcp.tool()
def get_structure_elements(structure_id: int) -> str:
    """Get all elements of a CE structure.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, structure_id, elements (list of {name, offset, type, size}).
    """
    return format_result(call("get_structure_elements", {"structure_id": structure_id}))


@mcp.tool()
def export_structure_to_xml(structure_id: int) -> str:
    """Export a CE structure definition as XML.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, xml (XML string representation of the structure).
    """
    return format_result(call("export_structure_to_xml", {"structure_id": structure_id}))


@mcp.tool()
def delete_structure(structure_id: int) -> str:
    """Delete a CE structure from the global list and free it.

    Args:
        structure_id: The structure ID to delete.

    Returns JSON with: success.
    """
    return format_result(call("delete_structure", {"structure_id": structure_id}))

# >>> END UNIT-19 <<<
# >>> BEGIN UNIT-18 Cheat Table Records <<<

@mcp.tool()
def load_table(filename: str, merge: bool = False) -> str:
    """Load a Cheat Engine table (.ct) file into the current session.

    Args:
        filename: Path to the .ct or .cetrainer file to load.
        merge: If True, merge with the current table instead of replacing it.

    Returns JSON with: success.
    """
    return format_result(call("load_table", {"filename": filename, "merge": merge}))

@mcp.tool()
def save_table(filename: str, protect: bool = False) -> str:
    """Save the current cheat table to a file.

    Args:
        filename: Destination path for the .ct or .cetrainer file.
        protect: If True and the filename has a .cetrainer extension, protect it from normal reading.

    Returns JSON with: success.
    """
    return format_result(call("save_table", {"filename": filename, "protect": protect}))

@mcp.tool()
def get_address_list(offset: int = 0, limit: int = 100) -> str:
    """List memory records in the current cheat table's address list.

    Args:
        offset: Zero-based index of the first record to return.
        limit: Maximum number of records to return (default 100).

    Returns JSON with: success, total, offset, limit, returned, records (list of
    {id, description, address, type, value, offsets, enabled}).
    """
    return format_result(call("get_address_list", {"offset": offset, "limit": limit}))

@mcp.tool()
def get_memory_record(id: int = None, description: str = None) -> str:
    """Retrieve a single memory record by ID or description.

    Args:
        id: Unique numeric ID of the memory record.
        description: Description string of the memory record (used when id is not provided).

    Returns JSON with: success, record ({id, description, address, type, value, offsets, enabled}).
    """
    params = {}
    if id is not None:
        params["id"] = id
    if description is not None:
        params["description"] = description
    return format_result(call("get_memory_record", params))

@mcp.tool()
def create_memory_record(description: str, address: str, var_type: str = "dword") -> str:
    """Create a new memory record in the cheat table address list.

    Args:
        description: Human-readable label for the new entry.
        address: Address string (hex, symbol, or pointer expression) to watch.
        var_type: Variable type — byte, word, dword, qword, float, double, string, bytearray (default: dword).

    Returns JSON with: success, id, record ({id, description, address, type, value, offsets, enabled}).
    """
    return format_result(call("create_memory_record", {
        "description": description,
        "address": address,
        "type": var_type,
    }))

@mcp.tool()
def delete_memory_record(id: int) -> str:
    """Delete a memory record from the cheat table address list by ID.

    Args:
        id: Unique numeric ID of the memory record to delete.

    Returns JSON with: success.
    """
    return format_result(call("delete_memory_record", {"id": id}))

@mcp.tool()
def get_memory_record_value(id: int) -> str:
    """Read the current value of a memory record as a string.

    Args:
        id: Unique numeric ID of the memory record.

    Returns JSON with: success, value (string representation of the current value).
    """
    return format_result(call("get_memory_record_value", {"id": id}))

@mcp.tool()
def set_memory_record_value(id: int, value: str) -> str:
    """Write a value to a memory record (and therefore to the target process memory).

    Args:
        id: Unique numeric ID of the memory record to update.
        value: New value as a string (e.g. "100", "3.14", "FF AA BB").

    Returns JSON with: success.
    """
    return format_result(call("set_memory_record_value", {"id": id, "value": value}))

@mcp.tool()
def set_memory_record_active(id: int, active: bool) -> str:
    """Activate (freeze) or deactivate (unfreeze) a cheat table memory record.

    This is the equivalent of ticking the checkbox next to a table entry in the
    CE UI (`mr.Active = true`). For Auto Assembler script records, activation
    runs the script.

    Args:
        id: Unique numeric ID of the memory record.
        active: True to activate/freeze, False to deactivate/unfreeze.

    Returns JSON with: success, requested, applied (read-back of the real
    state), record, and warning if the state did not stick (e.g. the record's
    script failed to enable).
    """
    return format_result(call("set_memory_record_active", {"id": id, "active": active}))

@mcp.tool()
def set_memory_record_address(id: int, address: str, offsets: list = None) -> str:
    """Retarget a memory record to a new address, optionally making it a pointer.

    Args:
        id: Unique numeric ID of the memory record.
        address: Interpretable address string (hex, symbol, or pointer expression).
        offsets: Optional array of pointer offsets (numbers or offset strings like "+10").
                 When provided, the record becomes a pointer with these offsets.

    Returns JSON with: success, record.
    """
    params: dict = {"id": id, "address": address}
    if offsets is not None:
        params["offsets"] = offsets
    return format_result(call("set_memory_record_address", params))

@mcp.tool()
def set_memory_record_type(id: int, var_type: str, size: int = None, unicode: bool = None,
                           startbit: int = None, bit_size: int = None) -> str:
    """Change the variable type of a memory record.

    Args:
        id: Unique numeric ID of the memory record.
        var_type: byte, word, dword, qword, float, double, string, bytearray,
                  binary, or autoassembler (script record).
        size: For string: character count. For bytearray: byte count.
        unicode: For string records: True for UTF-16, False for ASCII.
        startbit: For binary records: first bit to read from.
        bit_size: For binary records: number of bits.

    Returns JSON with: success, record, warnings (sub-config that did not apply).
    """
    params: dict = {"id": id, "type": var_type}
    if size is not None:
        params["size"] = size
    if unicode is not None:
        params["unicode"] = unicode
    if startbit is not None:
        params["startbit"] = startbit
    if bit_size is not None:
        params["bit_size"] = bit_size
    return format_result(call("set_memory_record_type", params))

@mcp.tool()
def set_memory_record_description(id: int, description: str) -> str:
    """Rename a memory record (the label shown in the CE table).

    Args:
        id: Unique numeric ID of the memory record.
        description: New description text (non-empty).

    Returns JSON with: success, record.
    """
    return format_result(call("set_memory_record_description", {"id": id, "description": description}))

@mcp.tool()
def set_memory_record_script(id: int, script: str) -> str:
    """Set the Auto Assembler script text of a memory record.

    Storing the script does not execute it — activate the record afterwards
    with set_memory_record_active(id, true) to run it.

    Args:
        id: Unique numeric ID of an autoassembler-type memory record.
        script: Full AA script text, including [enable]/[disable] sections.

    Returns JSON with: success, note, record.
    """
    return format_result(call("set_memory_record_script", {"id": id, "script": script}))

@mcp.tool()
def set_memory_record_offsets(id: int, offsets: list) -> str:
    """Replace the pointer offsets of a memory record (without changing its base address).

    Args:
        id: Unique numeric ID of the memory record.
        offsets: Array of pointer offsets (numbers, or interpretable strings like "+10",
                 "[base]+4"). Max 32 entries. The record becomes a multi-level pointer.

    Returns JSON with: success, record.
    """
    return format_result(call("set_memory_record_offsets", {"id": id, "offsets": offsets}))

@mcp.tool()
def get_memory_record_children(id: int, recursive: bool = False, offset: int = 0, limit: int = 100) -> str:
    """List the child records nested under a memory record (group header).

    Args:
        id: Unique numeric ID of the parent memory record.
        recursive: If True, walk nested groups up to max_depth levels.
        offset: Zero-based index of the first child to return.
        limit: Maximum number of children to return (default 100).

    Returns JSON with: success, total, offset, limit, returned, children.
    """
    return format_result(call("get_memory_record_children", {
        "id": id, "recursive": recursive, "offset": offset, "limit": limit,
    }))

@mcp.tool()
def get_memory_record_current_address(id: int) -> str:
    """Resolve a memory record's final address (symbol/pointer expression applied).

    Useful before follow-up read/write calls: a record pointing at
    "[base]+offset" is resolved to a concrete hex address.

    Args:
        id: Unique numeric ID of the memory record.

    Returns JSON with: success, address (hex string), address_integer.
    """
    return format_result(call("get_memory_record_current_address", {"id": id}))

@mcp.tool()
def append_memory_record(id: int, parent_id: int) -> str:
    """Nest an existing memory record under a group-header record.

    Args:
        id: Unique numeric ID of the record to move.
        parent_id: Unique numeric ID of the group header to nest it under.

    Returns JSON with: success, record.
    """
    return format_result(call("append_memory_record", {"id": id, "parent_id": parent_id}))

# >>> END UNIT-18 <<<
# --- INPUT AUTOMATION (Unit-17) — system-wide, no process guard required ---

@mcp.tool()
def get_pixel(x: int, y: int) -> str:
    """Get the colour of a screen pixel at (x, y). Returns r, g, b channels and the raw COLORREF integer."""
    return format_result(call("get_pixel", {"x": x, "y": y}))

@mcp.tool()
def get_mouse_pos() -> str:
    """Get the current mouse cursor position. Returns x and y screen coordinates."""
    return format_result(call("get_mouse_pos"))

@mcp.tool()
def set_mouse_pos(x: int, y: int) -> str:
    """Move the mouse cursor to screen position (x, y)."""
    return format_result(call("set_mouse_pos", {"x": x, "y": y}))

@mcp.tool()
def is_key_pressed(vk: int) -> str:
    """Check whether a key is currently held down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space, 0x01 for left mouse button).
    Returns pressed: bool."""
    return format_result(call("is_key_pressed", {"vk": vk}))

@mcp.tool()
def key_down(vk: int) -> str:
    """Simulate pressing a key down (does NOT release it automatically).
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(call("key_down", {"vk": vk}))

@mcp.tool()
def key_up(vk: int) -> str:
    """Release a key that was pressed with key_down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(call("key_up", {"vk": vk}))

@mcp.tool()
def do_key_press(vk: int) -> str:
    """Simulate a full key press (down + up) for the given key.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(call("do_key_press", {"vk": vk}))

@mcp.tool()
def get_screen_info() -> str:
    """Get the primary screen dimensions and DPI. Returns width, height (pixels) and dpi."""
    return format_result(call("get_screen_info"))
# --- WINDOW / GUI TOOLS (Unit-16) ---

@mcp.tool()
def find_window(title: str = None, class_name: str = None) -> str:
    """Find a top-level window by title and/or class name (system-wide, no process required).

    At least one of title or class_name must be provided.
    Returns {success, handle} on success or {success=false, error_code="NOT_FOUND"} when
    no matching window exists.
    """
    params = {}
    if title is not None:
        params["title"] = title
    if class_name is not None:
        params["class_name"] = class_name
    return format_result(call("find_window", params))

@mcp.tool()
def get_window_caption(handle: str) -> str:
    """Return the caption (title bar text) of a window given its handle (hex string)."""
    return format_result(call("get_window_caption", {"handle": handle}))

@mcp.tool()
def get_window_class_name(handle: str) -> str:
    """Return the window class name of a window given its handle (hex string)."""
    return format_result(call("get_window_class_name", {"handle": handle}))

@mcp.tool()
def get_window_process_id(handle: str) -> str:
    """Return the process ID that owns a window given its handle (hex string)."""
    return format_result(call("get_window_process_id", {"handle": handle}))

@mcp.tool()
def send_window_message(handle: str, msg: int, wparam: int = 0, lparam: int = 0) -> str:
    """Send a Windows message (WM_*) to a window.

    handle  -- hex window handle string
    msg     -- message ID (e.g. 0x000F for WM_PAINT)
    wparam  -- WPARAM value (default 0)
    lparam  -- LPARAM value (default 0)

    Returns {success, result} where result is the integer return value of SendMessage.
    """
    return format_result(call("send_window_message", {
        "handle": handle,
        "msg": msg,
        "wparam": wparam,
        "lparam": lparam,
    }))

@mcp.tool()
def show_message(message: str) -> str:
    """Show a modal message dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user dismisses the dialog by
    clicking OK.  Do not invoke from automation that expects a timely response.

    Returns {success} after the user closes the dialog.
    """
    return format_result(call("show_message", {"message": message}))

@mcp.tool()
def input_query(caption: str, prompt: str, default: str = "") -> str:
    """Show a modal text-input dialog in Cheat Engine and return what the user typed.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user submits or cancels the dialog.
    Do not invoke from automation that expects a timely response.

    Returns {success, value, cancelled}.  If cancelled is true, value is an empty string.
    """
    return format_result(call("input_query", {
        "caption": caption,
        "prompt": prompt,
        "default": default,
    }))

@mcp.tool()
def show_selection_list(caption: str, prompt: str, options: list) -> str:
    """Show a modal list-selection dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user picks an item or cancels.
    Do not invoke from automation that expects a timely response.

    options -- list of strings to display
    Returns {success, selected_index, selected_value, cancelled}.
    selected_index is -1 and cancelled is true when the user dismisses without selecting.
    """
    return format_result(call("show_selection_list", {
        "caption": caption,
        "prompt": prompt,
        "options": options,
    }))

# --- UNIT 15: ADVANCED SCANNING ---

@mcp.tool()
def aob_scan_unique(pattern: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern that must match exactly once. Returns {success, address} or error with count.
    Use this when you expect a signature to be unique in the process."""
    return format_result(call("aob_scan_unique", {"pattern": pattern, "protection": protection}))

@mcp.tool()
def aob_scan_module(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern restricted to a specific module's memory range.
    Returns {success, count, addresses: [str]}."""
    return format_result(call("aob_scan_module", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@mcp.tool()
def aob_scan_module_unique(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern in a specific module that must match exactly once.
    Returns {success, address} or error with count."""
    return format_result(call("aob_scan_module_unique", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@mcp.tool()
def pointer_rescan(value: str, previous_results_file: str = None) -> str:
    """Re-scan an existing pointer scan for a new value. Requires a prior pointer scan in CE.
    Returns {success, result_count}. Run a Pointer Scanner scan in CE first."""
    params = {"value": value}
    if previous_results_file:
        params["previous_results_file"] = previous_results_file
    return format_result(call("pointer_rescan", params))

@mcp.tool()
def create_persistent_scan(name: str) -> str:
    """Create a named, stateful memory scan session. Use the name with persistent_scan_* tools.
    Returns {success, scan_name}."""
    return format_result(call("create_persistent_scan", {"name": name}))

@mcp.tool()
def persistent_scan_first_scan(name: str, value: str, type: str = "dword", scan_option: str = "exact") -> str:
    """Run the first scan on a named persistent scan session.
    Types: byte, word, dword, qword, float, double, string.
    Scan options: exact, unknown, between, bigger, smaller.
    Returns {success, scan_name, count}."""
    return format_result(call("persistent_scan_first_scan", {
        "name": name,
        "value": value,
        "type": type,
        "scan_option": scan_option
    }))

@mcp.tool()
def persistent_scan_next_scan(name: str, value: str = None, scan_option: str = "exact") -> str:
    """Narrow down results with a next scan on a named persistent scan session.
    Scan options: exact, increased, decreased, changed, unchanged, bigger, smaller.
    Returns {success, scan_name, count}."""
    params = {"name": name, "scan_option": scan_option}
    if value is not None:
        params["value"] = value
    return format_result(call("persistent_scan_next_scan", params))

@mcp.tool()
def persistent_scan_get_results(name: str, offset: int = 0, limit: int = 100) -> str:
    """Get paginated results from a named persistent scan session.
    Returns {success, total, offset, limit, results: [{address, value}]}."""
    return format_result(call("persistent_scan_get_results", {
        "name": name,
        "offset": offset,
        "limit": limit
    }))

@mcp.tool()
def persistent_scan_destroy(name: str) -> str:
    """Destroy a named persistent scan session and free its memory.
    Returns {success, scan_name, destroyed}."""
    return format_result(call("persistent_scan_destroy", {"name": name}))
# --- MEMORY OPERATIONS (Unit 14) ---

@mcp.tool()
def copy_memory(source: str, size: int, dest: str = None, method: int = 0) -> str:
    """Copy memory between addresses. Methods: 0=target→target, 1=target→CE, 2=CE→target, 3=CE→CE. Returns dest_address allocated by CE if dest is None."""
    return format_result(call("copy_memory", {
        "source": source, "size": size, "dest": dest, "method": method
    }))

@mcp.tool()
def compare_memory(addr1: str, addr2: str, size: int, method: int = 0) -> str:
    """Compare two memory regions. Methods: 0=target/target, 1=addr1=target addr2=CE, 2=both CE. Returns equal flag and first_diff byte index (-1 if equal)."""
    return format_result(call("compare_memory", {
        "addr1": addr1, "addr2": addr2, "size": size, "method": method
    }))

@mcp.tool()
def write_region_to_file(address: str, size: int, filename: str) -> str:
    """Write a memory region to a file. Filename must be an absolute path and must not contain '..' components."""
    return format_result(call("write_region_to_file", {
        "address": address, "size": size, "filename": filename
    }))

@mcp.tool()
def read_region_from_file(filename: str, destination: str) -> str:
    """Read a file into memory at the given destination address. Filename must be an absolute path and must not contain '..' components."""
    return format_result(call("read_region_from_file", {
        "filename": filename, "destination": destination
    }))

@mcp.tool()
def md5_memory(address: str, size: int) -> str:
    """Calculate the MD5 hash of a memory region. Returns the hash as a hex string."""
    return format_result(call("md5_memory", {
        "address": address, "size": size
    }))

@mcp.tool()
def md5_file(filename: str) -> str:
    """Calculate the MD5 hash of a file on the CE host. Filename must not contain '..' components."""
    return format_result(call("md5_file", {"filename": filename}))

@mcp.tool()
def create_section(size: int) -> str:
    """Create a Windows section (shared memory) of the given size. Returns a handle as a hex string."""
    return format_result(call("create_section", {"size": size}))

@mcp.tool()
def map_view_of_section(handle: str, address: str = None, size: int = 0) -> str:
    """Map a section into the target process. 'handle' is from create_section. 'address' is optional preferred base. Returns mapped_address."""
    return format_result(call("map_view_of_section", {
        "handle": handle, "address": address, "size": size
    }))

# >>> BEGIN UNIT-12 Symbol Management <<<
@mcp.tool()
def register_symbol(name: str, address: str, do_not_save: bool = False) -> str:
    """Register a user-defined symbol with a given name and address.

    Args:
        name: Symbol name to register.
        address: Address to bind to the symbol (hex string or decimal).
        do_not_save: If True, this symbol is not persisted when the CE table is saved.

    Returns JSON with: success, name, address.
    """
    return format_result(call("register_symbol", {
        "name": name, "address": address, "do_not_save": do_not_save
    }))

@mcp.tool()
def unregister_symbol(name: str) -> str:
    """Remove a previously registered user-defined symbol.

    Args:
        name: Symbol name to unregister.

    Returns JSON with: success.
    """
    return format_result(call("unregister_symbol", {"name": name}))

@mcp.tool()
def enum_registered_symbols() -> str:
    """List all user-registered symbols.

    Returns JSON with: success, count, symbols (list of {name, address, module}).
    """
    return format_result(call("enum_registered_symbols"))

@mcp.tool()
def delete_all_registered_symbols() -> str:
    """Delete every user-registered symbol (both AA and Lua).

    Returns JSON with: success, deleted_count.
    """
    return format_result(call("delete_all_registered_symbols"))

@mcp.tool()
def enable_windows_symbols() -> str:
    """Trigger download and load of Windows PDB symbol files.

    Note: The actual PDB download and indexing is asynchronous; this call returns
    immediately once the process has been initiated by Cheat Engine.

    Returns JSON with: success.
    """
    return format_result(call("enable_windows_symbols"))

@mcp.tool()
def enable_kernel_symbols() -> str:
    """Enable kernel-mode symbol resolution (requires DBK driver).

    Returns JSON with: success.
    On failure returns error_code DBK_NOT_LOADED if the kernel driver is absent.
    """
    return format_result(call("enable_kernel_symbols"))

@mcp.tool()
def get_symbol_info(name: str) -> str:
    """Retrieve detailed information about a known symbol.

    Requires an attached process.

    Args:
        name: Symbol or export name to look up.

    Returns JSON with: success, name, address, module, size.
    Returns error_code NOT_FOUND if the symbol is unknown.
    """
    return format_result(call("get_symbol_info", {"name": name}))

@mcp.tool()
def get_module_size(module_name: str) -> str:
    """Get the in-memory size of a loaded module.

    Requires an attached process.

    Args:
        module_name: Module filename (e.g. 'kernel32.dll').

    Returns JSON with: success, size.
    """
    return format_result(call("get_module_size", {"module_name": module_name}))

@mcp.tool()
def load_new_symbols() -> str:
    """Scan for newly loaded modules and import their symbols.

    Returns JSON with: success.
    """
    return format_result(call("load_new_symbols"))

@mcp.tool()
def reinitialize_symbol_handler() -> str:
    """Perform a full reset and reload of the Cheat Engine symbol handler.

    Returns JSON with: success.
    """
    return format_result(call("reinitialize_symbol_handler"))
# >>> END UNIT-12 <<<
# --- UNIT-11: DEBUG CONTEXT + PER-THREAD BREAKPOINTS ---

@mcp.tool()
def debug_get_context(extra_regs: bool = False) -> str:
    """Get the current thread's CPU register context. Set extra_regs=True to include XMM0-15 and FP0-7."""
    return format_result(call("debug_get_context", {"extra_regs": extra_regs}))

@mcp.tool()
def debug_set_context(registers: dict) -> str:
    """Set CPU register values in the paused thread. Pass a dict like {\"RAX\": \"0x1234\", \"RIP\": \"0x140001000\"}."""
    return format_result(call("debug_set_context", {"registers": registers}))

@mcp.tool()
def debug_get_xmm_pointer(xmm_nr: int = 0) -> str:
    """Return the CE-local memory address of an XMM register (0-15) for the currently broken thread."""
    return format_result(call("debug_get_xmm_pointer", {"xmm_nr": xmm_nr}))

@mcp.tool()
def debug_set_last_branch_recording(enable: bool) -> str:
    """Enable or disable Intel LBR (Last Branch Recording). Requires kernel-mode debugger."""
    return format_result(call("debug_set_last_branch_recording", {"enable": enable}))

@mcp.tool()
def debug_get_last_branch_record(index: int) -> str:
    """Get the from/to addresses of a Last Branch Record entry at the given index."""
    return format_result(call("debug_get_last_branch_record", {"index": index}))

@mcp.tool()
def debug_set_breakpoint_for_thread(thread_id: int, address: str, size: int = 1, trigger: str = "execute") -> str:
    """Set a breakpoint that fires only on a specific thread. trigger: execute|write|read|access."""
    return format_result(call("debug_set_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
        "size": size,
        "trigger": trigger,
    }))

@mcp.tool()
def debug_remove_breakpoint_for_thread(thread_id: int, address: str) -> str:
    """Remove a per-thread breakpoint at the given address for the given thread."""
    return format_result(call("debug_remove_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
    }))

# --- DEBUGGER CONTROL (Unit 10) ---

@mcp.tool()
def debug_process(interface: int = 0) -> str:
    """Start the CE debugger for the currently opened process.

    interface: CE debugger interface enum.
      0 = default, 1 = Windows native, 2 = VEH debugger,
      3 = kernel debugger (DBK), 4 = DBVM.
    Requires a process to be attached. Returns {success, interface_used, interface_name}.
    """
    return format_result(call("debug_process", {"interface": interface}))

@mcp.tool()
def debug_is_debugging() -> str:
    """Check whether the CE debugger has been started.

    Always safe to call; no process guard. Returns {success, is_debugging: bool}.
    """
    return format_result(call("debug_is_debugging"))

@mcp.tool()
def debug_get_current_debugger_interface() -> str:
    """Return the active debugger interface used by CE.

    Returns {success, interface: int | null, interface_name: str}.
    interface_name values: 'windows_native', 'veh', 'kernel', 'mac_native', 'gdb', 'none'.
    """
    return format_result(call("debug_get_current_debugger_interface"))

@mcp.tool()
def debug_break_thread(thread_id: int) -> str:
    """Break a specific thread by its thread ID.

    The thread may not stop instantly — it must be scheduled to run first.
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(call("debug_break_thread", {"thread_id": thread_id}))

@mcp.tool()
def debug_continue(method: str = "run") -> str:
    """Continue execution from a breakpoint.

    method: one of 'run' (co_run), 'step_into' (co_stepinto), 'step_over' (co_stepover).
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(call("debug_continue", {"method": method}))

@mcp.tool()
def debug_detach() -> str:
    """Detach the debugger from the target process if possible.

    Returns {success, detached: bool}. Safe to call when no debugger is active.
    """
    return format_result(call("debug_detach"))

@mcp.tool()
def pause_process() -> str:
    """Pause (freeze) the currently opened process using CE's global pause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(call("pause_process"))

@mcp.tool()
def unpause_process() -> str:
    """Resume (unfreeze) the currently opened process using CE's global unpause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(call("unpause_process"))
# --- CODE INJECTION & EXECUTION ---

@mcp.tool()
def inject_dll(filepath: str, skip_symbol_reload: bool = False) -> str:
    """Inject a DLL into the currently attached target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    Args:
        filepath: Absolute path to the DLL or dylib to inject.
        skip_symbol_reload: If True, skips waiting for symbol reload after injection.

    Returns:
        JSON with {success}.
    """
    return format_result(call("inject_dll", {
        "filepath": filepath,
        "skip_symbol_reload": skip_symbol_reload,
    }))

@mcp.tool()
def inject_dotnet_dll(
    filepath: str,
    class_name: str,
    method_name: str,
    param: str = "",
    timeout: int = -1,
) -> str:
    """Inject a .NET DLL and invoke a static method in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    The method must be declared as: public static int MethodName(string parameters).

    Args:
        filepath: Absolute path to the managed (.NET) DLL.
        class_name: Fully-qualified class name (e.g. 'MyNamespace.MyClass').
        method_name: Name of the static method to call.
        param: String parameter passed to the method.
        timeout: Milliseconds to wait for return (-1 = wait indefinitely).

    Returns:
        JSON with {success, result} where result is the integer return value.
    """
    return format_result(call("inject_dotnet_dll", {
        "filepath":    filepath,
        "class_name":  class_name,
        "method_name": method_name,
        "param":       param,
        "timeout":     timeout,
    }))

@mcp.tool()
def execute_code(address: str, param: int = 0, timeout: int = -1) -> str:
    """Call a stdcall function with one argument at the given address in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    Args:
        address: Address (hex string or symbol) of the function to call.
        param: Integer argument passed as the single parameter.
        timeout: Milliseconds to wait (-1 = indefinitely).

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(call("execute_code", {
        "address": address,
        "param":   param,
        "timeout": timeout,
    }))

@mcp.tool()
def execute_code_ex(
    call_method: int,
    timeout: int,
    address: str,
    args: list = None,
) -> str:
    """Call a function with an explicit calling convention and multiple arguments.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    call_method values:
        0 = stdcall
        1 = cdecl
        2 = thiscall
        3 = fastcall

    Args:
        call_method: Integer calling convention identifier.
        timeout: Milliseconds to wait (-1 = indefinitely, 0 = fire-and-forget).
        address: Address (hex string or symbol) of the function to call.
        args: List of arguments. Each element can be a raw value (CE guesses type)
              or a dict with keys 'type' and 'value'.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(call("execute_code_ex", {
        "call_method": call_method,
        "timeout":     timeout,
        "address":     address,
        "args":        args or [],
    }))

@mcp.tool()
def execute_method(
    address: str,
    instance: str,
    args: list = None,
    call_method: int = 0,
    timeout: int = -1,
) -> str:
    """Call a C++ instance method with an implicit 'this' pointer in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    The instance pointer is placed into the register selected by call_method (ECX by default
    for thiscall). If instance is None the call behaves like execute_code_ex.

    Args:
        address: Address (hex string or symbol) of the method to call.
        instance: Address of the object instance ('this' pointer).
        args: List of additional arguments passed after 'this'.
        call_method: Calling convention (0=stdcall, 1=cdecl, 2=thiscall, 3=fastcall).
        timeout: Milliseconds to wait (-1 = indefinitely).

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(call("execute_method", {
        "address":     address,
        "instance":    instance,
        "args":        args or [],
        "call_method": call_method,
        "timeout":     timeout,
    }))

@mcp.tool()
def execute_code_local(address: str, param: int = 0) -> str:
    """Call a stdcall function inside Cheat Engine's own process (NOT the target).

    Security warning: Executes arbitrary code in the CE process. Use with caution.

    Useful for calling CE internal helpers or code loaded into CE itself.

    Args:
        address: Address within CE's memory space to call.
        param: Integer argument passed as the single parameter.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(call("execute_code_local", {
        "address": address,
        "param":   param,
    }))

@mcp.tool()
def execute_code_local_ex(
    address: str,
    args: list = None,
    call_method: int = 0,
) -> str:
    """Call a function inside Cheat Engine's own process with explicit calling convention.

    Security warning: Executes arbitrary code in the CE process. Use with caution.

    call_method values:
        0 = stdcall
        1 = cdecl
        2 = thiscall
        3 = fastcall

    Args:
        address: Address within CE's memory space to call.
        args: List of arguments passed to the function.
        call_method: Integer calling convention identifier.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(call("execute_code_local_ex", {
        "address":     address,
        "args":        args or [],
        "call_method": call_method,
    }))

# >>> BEGIN UNIT-08 Memory Allocation <<<

@mcp.tool()
def allocate_memory(size: int, base_address: str = None, protection: str = "rwx") -> str:
    """Allocate memory in the target process.

    Args:
        size: Number of bytes to allocate.
        base_address: Preferred base address as hex string (e.g. "0x140000000"). Optional.
        protection: Access flags — "r" (read-only), "rw" (read-write),
                    "rx" (read-execute), "rwx" (read-write-execute, default).

    Returns JSON with: success, address.
    """
    params = {"size": size, "protection": protection}
    if base_address is not None:
        params["base_address"] = base_address
    return format_result(call("allocate_memory", params))

@mcp.tool()
def free_memory(address: str, size: int = 0) -> str:
    """Free memory previously allocated in the target process.

    Args:
        address: Address of the region to free as hex string.
        size: Size of the region in bytes. Use 0 to let the OS determine it (default).

    Returns JSON with: success.
    """
    return format_result(call("free_memory", {"address": address, "size": size}))

@mcp.tool()
def allocate_shared_memory(name: str, size: int) -> str:
    """Create and map a shared memory region in the target process.

    The region is allocated with non-executable protection by default.

    Args:
        name: Unique name for the shared memory object.
        size: Size in bytes. Defaults to 4096 if the region does not yet exist.

    Returns JSON with: success, address.
    """
    return format_result(call("allocate_shared_memory", {"name": name, "size": size}))

@mcp.tool()
def get_memory_protection(address: str) -> str:
    """Query the protection flags of a memory page in the target process.

    Args:
        address: Address to query as hex string.

    Returns JSON with: success, read (bool), write (bool), execute (bool), raw (PAGE_* name).
    """
    return format_result(call("get_memory_protection", {"address": address}))

@mcp.tool()
def set_memory_protection(address: str, size: int, read: bool = True, write: bool = True, execute: bool = True) -> str:
    """Change the protection flags of a memory region in the target process.

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region to protect.
        read: Allow read access (default True).
        write: Allow write access (default True).
        execute: Allow execute access (default True).

    Returns JSON with: success.
    """
    return format_result(call("set_memory_protection", {
        "address": address, "size": size, "read": read, "write": write, "execute": execute
    }))

@mcp.tool()
def full_access(address: str, size: int) -> str:
    """Grant full read-write-execute access to a memory region (convenience wrapper).

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region.

    Returns JSON with: success.
    """
    return format_result(call("full_access", {"address": address, "size": size}))

@mcp.tool()
def allocate_kernel_memory(size: int) -> str:
    """Allocate non-paged kernel memory via the DBK driver.

    Requires the Cheat Engine kernel driver (DBK) to be loaded.

    Args:
        size: Number of bytes to allocate.

    Returns JSON with: success, address.
    Error codes: DBK_NOT_LOADED if the kernel driver is not active.
    """
    return format_result(call("allocate_kernel_memory", {"size": size}))

# >>> END UNIT-08 <<<
# >>> BEGIN UNIT-07 Process Lifecycle <<<

@mcp.tool()
def open_process(process_id_or_name: str) -> str:
    """Open a process by PID or name and attach Cheat Engine to it.

    Args:
        process_id_or_name: Numeric PID as string (e.g. "12345") or process name (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id, process_name}.
    """
    return format_result(call("open_process", {"process_id_or_name": process_id_or_name}))

@mcp.tool()
def get_process_list() -> str:
    """Get the list of running processes on the system.

    Returns:
        JSON with {success, count, processes: [{pid: int, name: str}, ...]}.
    """
    return format_result(call("get_process_list"))

@mcp.tool()
def get_processid_from_name(name: str) -> str:
    """Look up the PID of a process by its executable name.

    Args:
        name: Process name to search for (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id} or {success=false, error, error_code="NOT_FOUND"}.
    """
    return format_result(call("get_processid_from_name", {"name": name}))

@mcp.tool()
def get_foreground_process() -> str:
    """Get the PID and window handle of the process currently in the foreground.

    Returns:
        JSON with {success, process_id, window_handle}.
    """
    return format_result(call("get_foreground_process"))

@mcp.tool()
def create_process(path: str, args: str = "", debug: bool = False, break_on_entry: bool = False) -> str:
    """Create and optionally debug a new process.

    Args:
        path: Full path to the executable.
        args: Command-line arguments string (default empty).
        debug: Attach Windows debugger if True.
        break_on_entry: Break on entry point if True (requires debug=True).

    Returns:
        JSON with {success, process_id}.
    """
    return format_result(call("create_process", {
        "path": path,
        "args": args,
        "debug": debug,
        "break_on_entry": break_on_entry,
    }))

@mcp.tool()
def get_opened_process_id() -> str:
    """Get the PID of the process currently attached to Cheat Engine.

    Returns:
        JSON with {success, process_id} or {success=false, error_code="NO_PROCESS"}.
    """
    return format_result(call("get_opened_process_id"))

@mcp.tool()
def get_opened_process_handle() -> str:
    """Get the OS handle of the process currently attached to Cheat Engine as a hex string.

    Returns:
        JSON with {success, handle} where handle is a hex string.
    """
    return format_result(call("get_opened_process_handle"))

# >>> END UNIT-07 <<<

# >>> BEGIN UNIT-24 Signature Tooling <<<

@mcp.tool()
def aob_scan_region(pattern: str, start: str, size: int = 0, end_address: str = "",
                    protection: str = "+X", unique: bool = False, limit: int = 100) -> str:
    """AOB scan restricted to an address range [start, start+size) or [start, end_address).
    Supports {token} placeholders (see set_signature_tokens).
    unique=True uses a bounded mem-scan and returns the first hit only (faster).
    Returns {success, total, returned, addresses:[str]} or {success, address}."""
    p = {"pattern": pattern, "start": start, "protection": protection, "limit": limit}
    if end_address:
        p["end"] = end_address
    if size:
        p["size"] = size
    if unique:
        p["unique"] = True
    return format_result(call("aob_scan_region", p))

@mcp.tool()
def diagnose_scan_failure(pattern: str, module_name: str = "", protection: str = "+X") -> str:
    """Explain why an AOB pattern does not match: compares the pattern against the
    module's file ON DISK vs LIVE MEMORY, and lists non-system (mod-like) modules.
    Verdicts: matches-in-memory | exists-on-disk-but-patched-at-runtime (=mod conflict)
    | not-found-anywhere (=wrong signature for this build).
    Returns {success, in_memory_count, on_disk:{...}, non_system_modules:[...], verdict, hint}."""
    p = {"pattern": pattern, "protection": protection}
    if module_name:
        p["module_name"] = module_name
    return format_result(call("diagnose_scan_failure", p))

@mcp.tool()
def set_signature_tokens(tokens: dict, version: str = "") -> str:
    """Teach {token} values used inside AOB patterns / Auto-Assembler scripts.
    tokens maps token -> bytes, e.g. {"s1.2": "55 9B 56 01"}.
    version defaults to the running game's FileVersion; use "*" for a version-independent rule.
    Stored in MCP_Server/sig_tokens.txt so it survives restarts.
    Returns {success, version, tokens_set:[str], file}."""
    p = {"tokens": tokens}
    if version:
        p["version"] = version
    return format_result(call("set_signature_tokens", p))

@mcp.tool()
def get_signature_tokens() -> str:
    """Report the signature-token table: running game version, known versions,
    which tokens are active for this version, and the raw table.
    Returns {success, game_version, file, versions:[str], active_tokens:[str], raw}."""
    return format_result(call("get_signature_tokens"))

# >>> END UNIT-24 <<<

# >>> BEGIN UNIT-31 CE API gap coverage (v15.5.0) <<<
# Thin typed tools over the CE Lua APIs added in Lua UNIT-31: speedhack,
# disassembly context, structure auto-guess, hotkeys, custom value types,
# code-dissection database, .NET inspection, table files, AA command
# extensions, HTTP, DBK/DBVM kernel interfaces. See DEV_GUIDE section 13.

@mcp.tool()
def set_speed(speed: float) -> str:
    """Set the game speed via the CE speedhack (1.0 = normal, 0.5 = half, 2.0 = double).

    Args:
        speed: Positive multiplier (e.g. 0.1..10).

    Returns {success, speed}."""
    return format_result(call("set_speed", {"speed": speed}))

@mcp.tool()
def get_speed() -> str:
    """Read the currently set speedhack multiplier.

    Returns {success, speed}."""
    return format_result(call("get_speed"))

@mcp.tool()
def get_previous_opcode(address: str) -> str:
    """Get the address of the opcode preceding the given address (best-effort estimate).

    Args:
        address: Address (hex string like "0x401000" or number).

    Returns {success, address, previous}."""
    return format_result(call("get_previous_opcode", {"address": address}))

@mcp.tool()
def get_last_disassemble_data() -> str:
    """Read CE's LastDisassembleData table (fields of the most recent disassembly).

    Returns {success, data}."""
    return format_result(call("get_last_disassemble_data"))

@mcp.tool()
def auto_guess_structure(name: str, base_address: str, offset: int = 0, size: int = 0) -> str:
    """Auto-guess structure layout from memory at an address (CE structure dissect autoGuess).

    Args:
        name: Structure name; created if it does not exist.
        base_address: Address to guess from (hex string or number).
        offset: Offset into the structure to start guessing (default 0).
        size: Size in bytes to guess (0 = CE default heuristics).

    Returns {success, name, base_address, elements}."""
    return format_result(call("auto_guess_structure",
                              {"name": name, "base_address": base_address,
                               "offset": offset, "size": size}))

@mcp.tool()
def create_hotkey(keys: list, action_lua: str, delay: int = 0) -> str:
    """Create a CE hotkey (max 5 keys) that runs Lua code when pressed.

    The action runs inside CE on every hotkey activation. Use list/remove to
    manage; the bridge keeps the hotkey object alive until remove_hotkey.

    Args:
        keys: Key codes array, e.g. [112, 113] for F1+F2 (VK codes or CE key names).
        action_lua: Lua source to execute when the hotkey fires.
        delay: Minimum ms between activations (0 = global delay).

    Returns {success, id, keys}."""
    return format_result(call("create_hotkey",
                              {"keys": keys, "action_lua": action_lua, "delay": delay}))

@mcp.tool()
def list_hotkeys() -> str:
    """List bridge-managed hotkeys created via create_hotkey.

    Returns {success, hotkeys:[{id}]}."""
    return format_result(call("list_hotkeys"))

@mcp.tool()
def remove_hotkey(id: str) -> str:
    """Destroy a hotkey created via create_hotkey.

    Args:
        id: Hotkey id returned by create_hotkey (e.g. "hk_1").

    Returns {success, id}."""
    return format_result(call("remove_hotkey", {"id": id}))

@mcp.tool()
def register_custom_type(name: str, byte_count: int, bytes_to_value_lua: str,
                         value_to_bytes_lua: str, is_float: bool = False) -> str:
    """Register a custom value type from Lua converter functions (for encrypted/encoded values).

    The converters receive raw bytes and must return the decoded value and vice
    versa, e.g. bytes_to_value_lua="return (b1 ~ 0x5A) + b2*256" (CE Lua bitops).
    After registration the type can be used in read_custom/write_custom and in
    memory records.

    Args:
        name: Unique type name.
        byte_count: 1..8 bytes per value.
        bytes_to_value_lua: Lua source "function(b1,b2,...)" body returning a number.
        value_to_bytes_lua: Lua source returning a byte table for a value.
        is_float: True if the user-side value is a float.

    Returns {success, name, byte_count}."""
    return format_result(call("register_custom_type",
                              {"name": name, "byte_count": byte_count,
                               "bytes_to_value_lua": bytes_to_value_lua,
                               "value_to_bytes_lua": value_to_bytes_lua,
                               "is_float": is_float}))

@mcp.tool()
def register_custom_type_aa(name: str, script: str) -> str:
    """Register a custom value type from an Auto Assembler script with ConvertRoutine/ConvertBackRoutine.

    Args:
        name: Type name to associate (informational).
        script: AA script allocating ConvertRoutine and ConvertBackRoutine.

    Returns {success, name}."""
    return format_result(call("register_custom_type_aa", {"name": name, "script": script}))

@mcp.tool()
def get_custom_type(name: str) -> str:
    """Check a custom type exists and get registration info.

    Args:
        name: Type name.

    Returns {success, name, registered_byte_count, uses_float}."""
    return format_result(call("get_custom_type", {"name": name}))

@mcp.tool()
def read_custom(address: str, type_name: str, byte_count: int = 0) -> str:
    """Read bytes at an address and decode them with a registered custom type.

    Args:
        address: Address (hex string or number).
        type_name: Registered custom type name.
        byte_count: Required only if the type was registered via register_custom_type_aa.

    Returns {success, address, type_name, value}."""
    return format_result(call("read_custom",
                              {"address": address, "type_name": type_name,
                               "byte_count": byte_count or None}))

@mcp.tool()
def write_custom(address: str, type_name: str, value, byte_count: int = 0) -> str:
    """Encode a value with a registered custom type and write the bytes.

    Args:
        address: Address (hex string or number).
        type_name: Registered custom type name.
        value: Value to encode and write.
        byte_count: Only needed for AA-registered types.

    Returns {success, address, wrote}."""
    return format_result(call("write_custom",
                              {"address": address, "type_name": type_name,
                               "value": value, "byte_count": byte_count or None}))

@mcp.tool()
def dissect_code_start(module: str = "", base: str = "", size: int = 0) -> str:
    """Dissect code to populate CE's code-reference database (DissectCode).

    Provide either a module name or base+size. After this, dissect_code_references /
    dissect_code_strings / dissect_code_functions query the cached database -
    far faster than AOB-based find_references.

    Args:
        module: Module name to dissect (e.g. "game.exe"); takes priority.
        base: Base address if dissecting a raw range.
        size: Range size in bytes.

    Returns {success, scope}."""
    return format_result(call("dissect_code_start",
                              {"module": module or None,
                               "base": base or None, "size": size}))

@mcp.tool()
def dissect_code_references(address: str, offset: int = 0, limit: int = 50) -> str:
    """Find code that references an address using the dissected database.

    Args:
        address: Target address (hex string or number).
        offset: Pagination offset.
        limit: Max entries.

    Returns {success, references:[{from, type}], total}."""
    return format_result(call("dissect_code_references",
                              {"address": address, "offset": offset, "limit": limit}))

@mcp.tool()
def dissect_code_strings(offset: int = 0, limit: int = 100) -> str:
    """List strings found by code dissection with their addresses.

    Returns {success, strings:[{address, string}], total}."""
    return format_result(call("dissect_code_strings", {"offset": offset, "limit": limit}))

@mcp.tool()
def dissect_code_functions(offset: int = 0, limit: int = 100) -> str:
    """List functions found by code dissection with their addresses.

    Returns {success, functions:[{address}], total}."""
    return format_result(call("dissect_code_functions", {"offset": offset, "limit": limit}))

@mcp.tool()
def dissect_code_manage(action: str, filename: str = "") -> str:
    """Save / load / clear the code dissection database.

    Args:
        action: "save" | "load" | "clear".
        filename: Database file (required for save/load).

    Returns {success, action}."""
    return format_result(call("dissect_code_manage", {"action": action, "filename": filename}))

@mcp.tool()
def dotnet_status() -> str:
    """Check whether the .NET data collector is attached to the target process.

    Returns {success, attached}."""
    return format_result(call("dotnet_status"))

@mcp.tool()
def dotnet_enum_domains() -> str:
    """Enumerate .NET application domains: [{DomainHandle, Name}].

    Returns {success, domains}."""
    return format_result(call("dotnet_enum_domains"))

@mcp.tool()
def dotnet_enum_modules(domain_handle: int) -> str:
    """Enumerate .NET modules in a domain: [{ModuleHandle, BaseAddress, Name}].

    Args:
        domain_handle: From dotnet_enum_domains.

    Returns {success, modules}."""
    return format_result(call("dotnet_enum_modules", {"domain_handle": domain_handle}))

@mcp.tool()
def dotnet_enum_types(module_handle: int) -> str:
    """Enumerate .NET classes (TypeDefs) in a module: [{TypeDefToken, Name, Flags, Extends}].

    Args:
        module_handle: From dotnet_enum_modules.

    Returns {success, typedefs}."""
    return format_result(call("dotnet_enum_types", {"module_handle": module_handle}))

@mcp.tool()
def dotnet_type_details(domain_handle: int, typedef_token: int) -> str:
    """Full details of a .NET class: fields (offsets/types/names), methods, parent.

    Args:
        domain_handle: From dotnet_enum_domains.
        typedef_token: From dotnet_enum_types.

    Returns {success, fields, methods, parent}."""
    return format_result(call("dotnet_type_details",
                              {"domain_handle": domain_handle, "typedef_token": typedef_token}))

@mcp.tool()
def dotnet_method_params(domain_handle: int, method_token: int) -> str:
    """Parameter list of a .NET method: [{Name, CType}].

    Args:
        domain_handle: From dotnet_enum_domains.
        method_token: MethodDefToken from dotnet_type_details methods.

    Returns {success, parameters}."""
    return format_result(call("dotnet_method_params",
                              {"domain_handle": domain_handle, "method_token": method_token}))

@mcp.tool()
def dotnet_address_info(address: str) -> str:
    """Inspect a .NET object at an address: class name, fields with offsets.

    Args:
        address: Object address (hex string or number).

    Returns {success, data}."""
    return format_result(call("dotnet_address_info", {"address": address}))

@mcp.tool()
def dotnet_enum_objects(type_name: str = "") -> str:
    """Enumerate live .NET objects, optionally filtered by type name.

    Args:
        type_name: Optional full type name filter; empty = all objects.

    Returns {success, objects}."""
    return format_result(call("dotnet_enum_objects",
                              {"type_name": type_name or None}))

@mcp.tool()
def table_file_create(name: str, source_path: str = "") -> str:
    """Embed a file into the cheat table (CT), optionally reading from disk.

    Args:
        name: Name inside the table.
        source_path: File to read; empty creates a blank embedded file.

    Returns {success, name}."""
    return format_result(call("table_file_create",
                              {"name": name, "source_path": source_path or None}))

@mcp.tool()
def table_file_find(name: str) -> str:
    """Check whether an embedded table file exists.

    Args:
        name: Embedded file name.

    Returns {success, name}."""
    return format_result(call("table_file_find", {"name": name}))

@mcp.tool()
def table_file_export(name: str, dest_path: str) -> str:
    """Export an embedded table file to disk.

    Args:
        name: Embedded file name.
        dest_path: Destination path on disk.

    Returns {success, name, dest}."""
    return format_result(call("table_file_export", {"name": name, "dest_path": dest_path}))

@mcp.tool()
def table_file_delete(name: str) -> str:
    """Delete an embedded table file.

    Args:
        name: Embedded file name.

    Returns {success, name}."""
    return format_result(call("table_file_delete", {"name": name}))

@mcp.tool()
def register_aa_command(command: str, lua_code: str) -> str:
    """Register a custom Auto Assembler command implemented in Lua.

    The function receives (parameters, syntaxcheckonly) and returns the string
    that replaces the command during assembly.

    Args:
        command: New AA command name.
        lua_code: Lua source of the handler.

    Returns {success, command}."""
    return format_result(call("register_aa_command", {"command": command, "lua_code": lua_code}))

@mcp.tool()
def unregister_aa_command(command: str) -> str:
    """Remove a previously registered custom Auto Assembler command.

    Args:
        command: Command name.

    Returns {success, command}."""
    return format_result(call("unregister_aa_command", {"command": command}))

@mcp.tool()
def http_get(url: str, header: str = "", max_len: int = 65536) -> str:
    """HTTP GET from inside CE (getInternet). Useful for fetching resources.

    Args:
        url: Target URL.
        header: Optional extra header for this request.
        max_len: Truncate body to this many bytes.

    Returns {success, body, length, truncated}."""
    return format_result(call("http_get",
                              {"url": url, "header": header or None,
                               "max_len": max_len}))

@mcp.tool()
def http_post(url: str, data: str) -> str:
    """HTTP POST urlencoded data from inside CE (getInternet).

    Args:
        url: Target URL.
        data: URL-encoded payload.

    Returns {success, response}."""
    return format_result(call("http_post", {"url": url, "data": data}))

@mcp.tool()
def dbk_initialize() -> str:
    """Load the DBK kernel driver. Required before kernelmode switches and MSR access.

    Returns {success, loaded}."""
    return format_result(call("dbk_initialize"))

@mcp.tool()
def dbk_use_kernelmode(mode: str) -> str:
    """Switch a Windows API pointer to the DBK kernelmode implementation.

    Args:
        mode: "openprocess" | "memoryaccess" | "queryregions".

    Returns {success, mode}."""
    return format_result(call("dbk_use_kernelmode", {"mode": mode}))

@mcp.tool()
def dbk_read_msr(msr: int) -> str:
    """Read a model-specific register via the DBK driver (requires dbk_initialize).

    Args:
        msr: MSR index.

    Returns {success, msr, value}."""
    return format_result(call("dbk_read_msr", {"msr": msr}))

@mcp.tool()
def dbk_write_msr(msr: int, value) -> str:
    """Write a model-specific register via the DBK driver. DANGEROUS: can destabilise the OS.

    Args:
        msr: MSR index.
        value: Value to write.

    Returns {success, msr}."""
    return format_result(call("dbk_write_msr", {"msr": msr, "value": value}))

@mcp.tool()
def dbvm_initialize(offloados: bool = False, reason: str = "") -> str:
    """Initialise the DBVM hypervisor (requires DBK driver; offloados boots the OS under DBVM).

    Args:
        offloados: True to offload the running OS onto DBVM (very invasive).
        reason: Optional reason string logged by CE.

    Returns {success}."""
    return format_result(call("dbvm_initialize",
                              {"offloados": offloados, "reason": reason or None}))

@mcp.tool()
def dbvm_read_msr(msr: int) -> str:
    """Read an MSR through DBVM (requires dbvm_initialize).

    Args:
        msr: MSR index.

    Returns {success, msr, value}."""
    return format_result(call("dbvm_read_msr", {"msr": msr}))

@mcp.tool()
def dbvm_write_msr(msr: int, value) -> str:
    """Write an MSR through DBVM. DANGEROUS: affects the whole system.

    Args:
        msr: MSR index.
        value: Value to write.

    Returns {success, msr}."""
    return format_result(call("dbvm_write_msr", {"msr": msr, "value": value}))

@mcp.tool()
def dbvm_cloak_activate(physical_base: int, virtual_base: int = 0) -> str:
    """Activate DBVM cloaking on a 4KB page: the game reads what it expects while CE executes the truth.

    Args:
        physical_base: Page-aligned physical address.
        virtual_base: Optional virtual address.

    Returns {success, physical_base}."""
    return format_result(call("dbvm_cloak_activate",
                              {"physical_base": physical_base,
                               "virtual_base": virtual_base or None}))

@mcp.tool()
def dbvm_cloak_deactivate(physical_base: int) -> str:
    """Deactivate DBVM cloaking on a page and restore the real memory contents.

    Args:
        physical_base: Cloaked page's physical address.

    Returns {success, physical_base}."""
    return format_result(call("dbvm_cloak_deactivate", {"physical_base": physical_base}))

@mcp.tool()
def dbvm_cloak_read(physical_base: int) -> str:
    """Read the 4096 bytes the CPU actually executes on a cloaked page (preview: first 64).

    Args:
        physical_base: Cloaked page's physical address.

    Returns {success, size, preview}."""
    return format_result(call("dbvm_cloak_read", {"physical_base": physical_base}))

@mcp.tool()
def dbvm_cloak_write(physical_base: int, bytes: list) -> str:
    """Write the real bytes executed by the CPU on a cloaked page (1..4096 byte array).

    Args:
        physical_base: Cloaked page's physical address.
        bytes: Array of byte values.

    Returns {success, wrote}."""
    return format_result(call("dbvm_cloak_write",
                              {"physical_base": physical_base, "bytes": bytes}))

# >>> END UNIT-31 <<<

# ============================================================================
# UNIT-32 (continued) — category catalog, profile selection, dynamic loading
# ============================================================================

# tool name -> category. "core" is always registered regardless of profile.
_TOOL_CATEGORIES = {
    # --- core: always on (health, memory IO basics, Lua escape hatch,
    #     modal-dialog recovery, this manager) ---
    "bridge_status": "core", "ping": "core", "dll_status": "core",
    "list_bridge_methods": "core", "batch_call": "core", "get_audit_log": "core",
    "list_apis": "core", "table_state": "core", "evaluate_lua": "core",
    "get_process_info": "core", "open_process": "core", "wait_until": "core",
    "dialog_enum": "core", "dialog_dismiss": "core",

    # --- memory ---
    "read_memory": "memory", "read_integer": "memory", "read_string": "memory",
    "read_pointer": "memory", "read_pointer_chain": "memory",
    "checksum_memory": "memory", "write_integer": "memory",
    "write_memory": "memory", "write_string": "memory", "copy_memory": "memory",
    "compare_memory": "memory", "md5_memory": "memory",
    "create_section": "memory", "map_view_of_section": "memory",
    "allocate_memory": "memory", "free_memory": "memory",
    "allocate_shared_memory": "memory", "get_memory_protection": "memory",
    "set_memory_protection": "memory", "full_access": "memory",

    # --- scanning (one-shot, persistent sessions, AOB, signatures) ---
    "scan_all": "scan", "next_scan": "scan", "get_scan_results": "scan",
    "aob_scan": "scan", "aob_scan_unique": "scan", "aob_scan_module": "scan",
    "aob_scan_module_unique": "scan", "aob_scan_region": "scan",
    "search_string": "scan", "diagnose_scan_failure": "scan",
    "set_signature_tokens": "scan", "get_signature_tokens": "scan",
    "pointer_rescan": "scan", "generate_signature": "scan",
    "get_memory_regions": "scan", "enum_memory_regions_full": "scan",
    "create_persistent_scan": "scan", "persistent_scan_first_scan": "scan",
    "persistent_scan_next_scan": "scan", "persistent_scan_get_results": "scan",
    "persistent_scan_destroy": "scan",

    # --- disassembly & static code analysis ---
    "disassemble": "disasm", "get_instruction_info": "disasm",
    "find_function_boundaries": "disasm", "analyze_function": "disasm",
    "find_references": "disasm", "find_call_references": "disasm",
    "assemble_instruction": "disasm", "get_previous_opcode": "disasm",
    "get_last_disassemble_data": "disasm",

    # --- debugger & watchpoints ---
    "set_breakpoint": "debug", "set_data_breakpoint": "debug",
    "remove_breakpoint": "debug", "list_breakpoints": "debug",
    "clear_all_breakpoints": "debug", "get_breakpoint_hits": "debug",
    "debug_get_context": "debug", "debug_set_context": "debug",
    "debug_get_xmm_pointer": "debug", "debug_set_last_branch_recording": "debug",
    "debug_get_last_branch_record": "debug",
    "debug_set_breakpoint_for_thread": "debug",
    "debug_remove_breakpoint_for_thread": "debug", "debug_process": "debug",
    "debug_is_debugging": "debug",
    "debug_get_current_debugger_interface": "debug",
    "debug_break_thread": "debug", "debug_continue": "debug",
    "debug_detach": "debug", "start_dbvm_watch": "debug",
    "stop_dbvm_watch": "debug", "poll_dbvm_watch": "debug",

    # --- process & thread control ---
    "enum_modules": "process", "get_thread_list": "process",
    "create_thread": "process", "queue_to_main_thread": "process",
    "check_synchronize": "process", "in_main_thread": "process",
    "pause_process": "process", "unpause_process": "process",
    "get_process_list": "process", "get_processid_from_name": "process",
    "get_foreground_process": "process", "create_process": "process",
    "get_opened_process_id": "process", "get_opened_process_handle": "process",
    "set_speed": "process", "get_speed": "process",

    # --- symbols & address resolution ---
    "get_symbol_address": "symbols", "get_address_info": "symbols",
    "get_rtti_classname": "symbols", "get_physical_address": "symbols",
    "register_symbol": "symbols", "unregister_symbol": "symbols",
    "enum_registered_symbols": "symbols",
    "delete_all_registered_symbols": "symbols",
    "enable_windows_symbols": "symbols", "enable_kernel_symbols": "symbols",
    "get_symbol_info": "symbols", "get_module_size": "symbols",
    "load_new_symbols": "symbols", "reinitialize_symbol_handler": "symbols",

    # --- structures (dissected / auto-guessed) ---
    "dissect_structure": "structures", "create_structure": "structures",
    "get_structure_by_name": "structures",
    "add_element_to_structure": "structures",
    "get_structure_elements": "structures", "export_structure_to_xml": "structures",
    "delete_structure": "structures", "auto_guess_structure": "structures",

    # --- cheat table & memory records ---
    "patch_memory_record_script": "table",
    "undo_memory_record_script_patch": "table",
    "load_table": "table", "save_table": "table", "get_address_list": "table",
    "get_memory_record": "table", "create_memory_record": "table",
    "delete_memory_record": "table", "get_memory_record_value": "table",
    "set_memory_record_value": "table", "set_memory_record_active": "table",
    "set_memory_record_address": "table", "set_memory_record_type": "table",
    "set_memory_record_description": "table", "set_memory_record_script": "table",
    "set_memory_record_offsets": "table", "get_memory_record_children": "table",
    "get_memory_record_current_address": "table",
    "append_memory_record": "table", "table_file_create": "table",
    "table_file_find": "table", "table_file_export": "table",
    "table_file_delete": "table",

    # --- Auto Assembler, code generation & injection ---
    "auto_assemble": "aa", "auto_assemble_check": "aa",
    "compile_c_code": "aa", "compile_cs_code": "aa",
    "generate_api_hook_script": "aa", "generate_code_injection_script": "aa",
    "register_aa_command": "aa", "unregister_aa_command": "aa",

    # --- native code execution & DLL injection ---
    "output_debug_string": "exec", "inject_dll": "exec",
    "inject_dotnet_dll": "exec", "execute_code": "exec",
    "execute_code_ex": "exec", "execute_method": "exec",
    "execute_code_local": "exec", "execute_code_local_ex": "exec",

    # --- .NET inspection ---
    "dotnet_status": "dotnet", "dotnet_enum_domains": "dotnet",
    "dotnet_enum_modules": "dotnet", "dotnet_enum_types": "dotnet",
    "dotnet_type_details": "dotnet", "dotnet_method_params": "dotnet",
    "dotnet_address_info": "dotnet", "dotnet_enum_objects": "dotnet",

    # --- code dissect library ---
    "dissect_code_start": "dissect", "dissect_code_references": "dissect",
    "dissect_code_strings": "dissect", "dissect_code_functions": "dissect",
    "dissect_code_manage": "dissect",

    # --- hotkeys & custom value types ---
    "create_hotkey": "custom", "list_hotkeys": "custom",
    "remove_hotkey": "custom", "register_custom_type": "custom",
    "register_custom_type_aa": "custom", "get_custom_type": "custom",
    "read_custom": "custom", "write_custom": "custom",

    # --- UI inspection, keyboard/mouse input ---
    "get_pixel": "ui_input", "get_mouse_pos": "ui_input",
    "set_mouse_pos": "ui_input", "is_key_pressed": "ui_input",
    "key_down": "ui_input", "key_up": "ui_input", "do_key_press": "ui_input",
    "get_screen_info": "ui_input", "find_window": "ui_input",
    "get_window_caption": "ui_input", "get_window_class_name": "ui_input",
    "get_window_process_id": "ui_input", "send_window_message": "ui_input",

    # --- OS/CE side effects: dialogs, files, clipboard, sound, shell ---
    "speak_text": "system", "play_sound": "system", "beep": "system",
    "set_progress_state": "system", "set_progress_value": "system",
    "get_global_variable": "system", "set_global_variable": "system",
    "run_command": "system", "shell_execute": "system",
    "file_exists": "system", "delete_file": "system",
    "get_file_list": "system", "get_directory_list": "system",
    "get_temp_folder": "system", "get_file_version": "system",
    "read_clipboard": "system", "write_clipboard": "system",
    "show_message": "system", "input_query": "system",
    "show_selection_list": "system", "write_region_to_file": "system",
    "read_region_from_file": "system", "md5_file": "system",

    # --- kernel mode (DBK) & DBVM hypervisor ---
    "dbk_get_cr0": "kernel", "dbk_get_cr3": "kernel", "dbk_get_cr4": "kernel",
    "read_process_memory_cr3": "kernel", "write_process_memory_cr3": "kernel",
    "map_memory": "kernel", "unmap_memory": "kernel",
    "dbk_writes_ignore_write_protection": "kernel",
    "get_physical_address_cr3": "kernel", "allocate_kernel_memory": "kernel",
    "dbk_initialize": "kernel", "dbk_use_kernelmode": "kernel",
    "dbk_read_msr": "kernel", "dbk_write_msr": "kernel",
    "dbvm_initialize": "kernel", "dbvm_read_msr": "kernel",
    "dbvm_write_msr": "kernel", "dbvm_cloak_activate": "kernel",
    "dbvm_cloak_deactivate": "kernel", "dbvm_cloak_read": "kernel",
    "dbvm_cloak_write": "kernel",

    # --- network ---
    "http_get": "net", "http_post": "net",
}

_TOOL_CATEGORY_ORDER = [
    "core", "memory", "scan", "disasm", "debug", "process", "symbols",
    "structures", "table", "aa", "exec", "dotnet", "dissect", "custom",
    "ui_input", "system", "kernel", "net",
]

# ce_tools_manage is registered directly (not via the recorder) and is
# therefore always present, even with CE_MCP_TOOLS=core.
_registered_tool_names = {"ce_tools_manage"}
_register_lock = threading.Lock()


def _resolve_profile(raw_value):
    """Parse a CE_MCP_TOOLS value into an ordered, validated category list."""
    raw = (raw_value or "all").strip()
    if raw.lower() in ("all", "*", ""):
        return list(_TOOL_CATEGORY_ORDER)
    cats = []
    for part in raw.replace(";", ",").split(","):
        cat = part.strip().lower()
        if not cat:
            continue
        if cat == "minimal":
            cat = "core"
        if cat not in _TOOL_CATEGORIES_ORDER_SET:
            raise ValueError(
                f"unknown CE_MCP_TOOLS category '{cat}' (valid: all/minimal or "
                f"{', '.join(_TOOL_CATEGORY_ORDER)})")
        if cat not in cats:
            cats.append(cat)
    if "core" not in cats:
        cats.insert(0, "core")
    return cats


_TOOL_CATEGORIES_ORDER_SET = set(_TOOL_CATEGORY_ORDER)


def _uncategorized_tool_names():
    return sorted(fn.__name__ for fn in _TOOL_SPECS
                  if fn.__name__ not in _TOOL_CATEGORIES)


def _register_tool_fn(fn):
    mcp.add_tool(fn)
    _registered_tool_names.add(fn.__name__)


def _notify_tool_list_changed():
    """Best-effort notifications/tools/list_changed to the connected client.

    Returns (sent: bool, detail: str). Never raises: clients that do not
    support the notification simply need to re-list or reconnect to see the
    new tools, and the ce_tools_manage response carries that hint.
    """
    session = None
    try:
        ctx = mcp.get_context()  # FastMCP 1.x
        session = getattr(ctx, "session", None)
    except Exception:
        session = None
    if session is None:
        try:  # mcp 2.x: read the lowlevel server's request contextvar
            from mcp.server.lowlevel import server as _ll_server
            rc = _ll_server.request_context.get(None)
            session = getattr(rc, "session", None)
        except Exception:
            session = None
    if session is None or not hasattr(session, "send_tool_list_changed"):
        return False, ("no client session available; refresh the tool list "
                       "(re-list tools or reconnect) to see the new tools")
    try:
        import anyio
        anyio.from_thread.run(session.send_tool_list_changed)
        return True, "notifications/tools/list_changed sent"
    except Exception as exc:  # noqa: BLE001 - notification is best-effort
        return False, f"list_changed notification skipped ({exc}); refresh the tool list manually"


def _enable_categories(categories, notify=True):
    """Register every recorded tool of the given categories. Idempotent.

    Returns (added: list[str], notified: bool, notify_detail: str).
    """
    added = []
    with _register_lock:
        for cat in categories:
            for fn in _TOOL_SPECS:
                name = fn.__name__
                if _TOOL_CATEGORIES.get(name) == cat and name not in _registered_tool_names:
                    _register_tool_fn(fn)
                    added.append(name)
    if notify and added:
        notified, detail = _notify_tool_list_changed()
    else:
        notified, detail = False, "no notification needed"
    return added, notified, detail


def ce_tools_manage(action: str = "list", categories=None) -> str:
    """Inspect and progressively load the Cheat Engine toolset (243 tools in 18 categories).

    Only "core" tools are guaranteed registered at start (profile comes from
    the CE_MCP_TOOLS environment variable). If a tool you need is not in your
    tool list, load its category here.

    Args:
        action: "list" (default) - show every category, its tools and which
                are already enabled. "enabled" - names of registered tools.
                "enable" - register the given categories now (idempotent).
        categories: For "enable" only: one category name or a list, e.g.
                "debug" or ["memory", "debug"]. Valid categories: core,
                memory, scan, disasm, debug, process, symbols, structures,
                table, aa, exec, dotnet, dissect, custom, ui_input, system,
                kernel, net.

    Returns JSON. After "enable", refresh your tool list if the new tools do
    not appear immediately (a list_changed notification is sent when the
    client supports it).
    """
    action = (action or "list").strip().lower()
    if action == "enabled":
        return format_result({
            "success": True, "action": "enabled",
            "count": len(_registered_tool_names),
            "tools": sorted(_registered_tool_names),
            "total_available": len(_TOOL_SPECS) + 1,
        })
    if action == "enable":
        if isinstance(categories, str):
            categories = [categories]
        if not isinstance(categories, list) or not categories:
            return format_result({
                "success": False, "action": "enable",
                "error": "provide a category name or a list of category names",
                "valid_categories": _TOOL_CATEGORY_ORDER,
            })
        try:
            cats = _resolve_profile(",".join(str(c) for c in categories))
        except ValueError as exc:
            return format_result({
                "success": False, "action": "enable", "error": str(exc),
                "valid_categories": _TOOL_CATEGORY_ORDER,
            })
        cats = [c for c in cats if c != "core"] or cats
        added, notified, detail = _enable_categories(cats, notify=True)
        return format_result({
            "success": True, "action": "enable",
            "requested_categories": cats,
            "added": added, "added_count": len(added),
            "registered_total": len(_registered_tool_names),
            "list_changed_sent": notified, "list_changed_detail": detail,
        })
    if action == "list":
        catalog = {}
        for cat in _TOOL_CATEGORY_ORDER:
            names = sorted(n for n, c in _TOOL_CATEGORIES.items() if c == cat)
            if cat == "core":
                names = sorted(set(names) | {"ce_tools_manage"})
            catalog[cat] = {
                "count": len(names),
                "enabled": all(n in _registered_tool_names for n in names),
                "tools": names,
            }
        return format_result({
            "success": True, "action": "list",
            "registered_total": len(_registered_tool_names),
            "total_available": len(_TOOL_SPECS) + 1,
            "profile_hint": ('set CE_MCP_TOOLS (e.g. "core,memory,debug") '
                             'or call this tool with action="enable"'),
            "categories": catalog,
        })
    return format_result({
        "success": False, "error": f"unknown action '{action}'",
        "valid_actions": ["list", "enabled", "enable"],
    })


mcp.add_tool(ce_tools_manage)


def _register_startup_tools():
    """Register the tool profile selected by CE_MCP_TOOLS (default: all)."""
    uncategorized = _uncategorized_tool_names()
    if uncategorized:
        debug_log(f"WARNING: tools missing from _TOOL_CATEGORIES, registering "
                  f"them anyway: {', '.join(uncategorized)}")
    raw = os.environ.get("CE_MCP_TOOLS", "all")
    cats = _resolve_profile(raw)  # ValueError here is a hard config error
    added, _, _ = _enable_categories(cats, notify=False)
    if uncategorized:  # never let a catalog miss hide tools from the agent
        for fn in _TOOL_SPECS:
            if fn.__name__ in uncategorized and fn.__name__ not in _registered_tool_names:
                _register_tool_fn(fn)
                added.append(fn.__name__)
    try:
        del mcp.tool  # restore the real FastMCP.tool for any late registrations
    except AttributeError:
        pass
    debug_log(f"Tool profile '{raw}': {len(_registered_tool_names)}/"
              f"{len(_TOOL_SPECS) + 1} tools registered "
              f"(categories: {', '.join(cats)}; SDK: {_MCP_SERVER_MODULE})")


_register_startup_tools()


if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v12/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
