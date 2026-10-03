# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.
`CLAUDE.md` is a byte-identical copy — **update both** when you change this file.

## What this project is

A three-tier bridge that lets AI agents (via MCP) drive Cheat Engine to inspect and manipulate a
running Windows process. See `README.md` for user-facing docs.

- Wire protocol version: `v99` (length-prefixed JSON-RPC over TCP)
- Bridge script version: **`15.8.1`** (`VERSION` in `ce_mcp_bridge.lua`)
- Surface: **253 dispatcher methods** in Lua, **249 registered MCP tools** in Python (248 recorded tools plus the
  always-present `ce_tools_manage` progressive-loading meta tool; the difference is
  aliases such as `read_bytes` → `read_memory`, and `batch` which is a transport-level primitive)

> ### ⚠️ The transport changed in v15 — older docs are wrong
> v12 and earlier used a **Windows Named Pipe** (`\\.\pipe\CE_MCP_Bridge_v99`) with a Lua worker
> thread (`PipeWorker`) and `thread.synchronize`. **None of that exists any more.** v15 uses a
> native C DLL (`ce_mcp_tcp_x64.dll` / `ce_mcp_tcp_x86.dll`) that owns a Winsock thread, and the
> Lua side drains it from CE's main thread with a 1 ms timer. `AI_Context/AI_Guide_MCP_Server_Implementation.md`
> still describes the pipe era and is **historical only** (the obsolete `test_mcp.py` has been
> removed; git history retains it).

## Commands

```bash
# Python deps: the MCP SDK is the only dependency (TCP transport is stdlib-only)
pip install -r MCP_Server/requirements.txt

# ---- tests (see "Testing" below for details) ----
lua MCP_Server/test_bridge_lua.lua                                  # offline Lua unit tests, no CE
python MCP_Server/test_bridge.py --self-test                        # offline Python client contract
python MCP_Server/probe_bridge.py --self-test                       # offline wire-probe self-check
python MCP_Server/test_bridge.py                                    # live smoke test (needs CE running)
python MCP_Server/probe_bridge.py                                   # live frame-format matrix (read-only)
python MCP_Server/test_bridge.py --allow-write                      # + allocate/write/read-back
```

Loading the Lua side in Cheat Engine: `File -> Execute Script -> open MCP_Server/ce_mcp_bridge.lua
-> Execute`. Some CE builds expose this through `Table -> Show Cheat Table Lua Script`; in that case
execute `dofile([[C:\path\to\cheatengine-mcp-bridge\MCP_Server\ce_mcp_bridge.lua]])` instead of
pasting the full bridge. Success log:

```
[MCP] Bridge v15.8.0 started on port 17171 (native TCP, 1ms poll)
```

Re-executing the script auto-calls `StopMCPBridge` / `cleanupZombieState` first, so reloading is safe.

The MCP server is normally spawned by the AI client over stdio, but can be launched directly with
`python MCP_Server/mcp_cheatengine.py` for debugging (it blocks waiting for stdio JSON-RPC).

## Architecture

Three processes, two IPC layers:

```
AI client ──(MCP / JSON-RPC over stdio)──▶ mcp_cheatengine.py
                                                  │
                                                  ▼ (4-byte LE length prefix + UTF-8 JSON-RPC)
                                        127.0.0.1:17171..17180  (TCP, native DLL)
                                                  │
                                                  ▼
                                     ce_mcp_tcp_{x64,x86}.dll  (own Winsock thread)
                                                  │  1 ms main-thread poll
                                                  ▼
                                          ce_mcp_bridge.lua (inside Cheat Engine)
                                                  │
                                                  ▼ (CE Lua API / DBVM)
                                            Target process memory
```

### Native bridge — `NativeBridge/ce_mcp_tcp.c` (prebuilt into `MCP_Server/*.dll`)

Statically links the CRT (`/MT`), so no VC runtime is required. It resolves the Lua C API at load
time (`lua_pushstring`, `lua_pcallk`, …) and registers five globals inside CE:

| Lua global | Purpose |
|---|---|
| `mcp_tcp_start(port, bind)` | bind `port`, scanning up to 10 ports; returns `{ok, port}` |
| `mcp_tcp_poll()` | non-blocking: returns the next pending command string, or `nil` |
| `mcp_tcp_respond(str)` | hands one response back to the socket thread |
| `mcp_tcp_stop()` | tear down |
| `mcp_tcp_status()` | `{listening, connected, port, running}` |

The socket thread accepts **one** client at a time and waits up to 120 s for a response. Frame sizes
are capped: 4 MiB for a command (`MAX_CMD_SIZE`) and — separately — 32 MiB client-side for
responses. Rebuild with `NativeBridge/build.bat` (MSVC) if you change the C source; the prebuilt
DLLs are otherwise authoritative. **Lua/Python-only changes never require a rebuild** — the DLL is
just the TCP transport and its five `mcp_tcp_*` globals.

### Lua side — `MCP_Server/ce_mcp_bridge.lua`

One self-contained script with its own pure-Lua JSON codec, loaded inside Cheat Engine.

- **Main-thread execution.** `NativePollLoop` is driven by `createTimer(nil, false)`, which fires on
  CE's **main thread** — the only place CE Lua APIs may be called. It runs `executeCommand` inline.
  Do **not** reintroduce `createThread`/`synchronize` here: an earlier revision hopped
  main → worker → main for every command (a thread creation plus a message-pump round trip per
  call) for no benefit. `workerBusy` remains only as a re-entrancy guard, because blocking handlers
  (`show_message`, `auto_assemble`) can pump CE's message loop and re-enter the timer.
- **Command dispatcher** (`commandHandlers`): a plain table mapping JSON-RPC method name → `cmd_*`
  function. Several methods have aliases (`read_memory`/`read_bytes`,
  `find_what_writes_safe` → `cmd_start_dbvm_watch`, `status`/`bridge_status`, …).
- **Error envelope** (`executeCommand` → `finalizeResult` → `safeEncode`):
  - parse failure / unknown method → JSON-RPC `error` object with `error.data.error_code`
  - a handler that *throws* → a normal `result` with `{success:false, error_code:"INTERNAL_ERROR"}`,
    so one crashing command can never take down a `batch` or the transport
  - a handler that returns `{success:false}` **without** an `error_code` gets one inferred from the
    message by `inferErrorCode()` — this is what gives every failure a machine-readable code
  - `safeEncode` guarantees a response is always produced, even for circular/exotic tables
- **Codec contract** (`encode_table`/`decode`): nesting depth is capped at **200 on both sides** —
  a pathological payload fails with the deterministic message `JSON nesting depth exceeded 200`
  instead of a C `stack overflow` attributed to a random recursion line (a field-reported
  "response encoding failed … line 553" was exactly this). Table classification: dense sequential
  `[1..n]` → JSON array, **everything else → object** (mixed tables fall through to object
  encoding with `"1"`,`"2"`… keys so no key is ever silently dropped; sparse arrays keep their
  items as `"3"`… objects). Empty table → `[]`. Circular tables still error and are caught by
  `safeEncode` → `INTERNAL_ERROR`.
- **Resource caps (all params are clamped at the handler, not the caller)**: breakpoint hit
  history keeps the newest **500** per breakpoint (`recordBPHit`); `captureStack` depth ≤ **128**;
  scan/search `limit` ≤ **10000**; `get_memory_record_children` walks ≤ **5000** nodes (reports
  `truncated: true`); dissect size ≤ **64 KiB**; memory-MD5 size ≤ **16 MiB**; DBVM log poll ≤
  **100000** rows; kernel paths reject oversize outright (`read_process_memory_cr3` ≤ **4 MiB**
  because the byte-array JSON inflates ~5x, `map_memory` ≤ **16 MiB**). New handlers **must**
  clamp every caller-controlled `limit`/`size`/`depth` the same way — an unclamped value freezes
  CE for the duration of the loop and can exhaust memory.
- **Zombie cleanup** (`cleanupZombieState`): `StartMCPBridge` always calls `StopMCPBridge` first,
  which tears down hardware breakpoints, DBVM watches, scan objects, persistent scans **and kernel
  `mapMemory` MDL handles**. This is load-bearing — reloading the script while a HW breakpoint or
  kernel mapping is live otherwise leaks DR slots / kernel memory and can freeze the target. Any new
  long-lived resource you add **must** get a teardown entry here.
  Note `mappedMemoryMDL` is declared near the top of the file precisely so this function can see the
  same local.
- **Universal 32/64-bit handling** (`getArchInfo`, `captureRegisters`, `captureStack`): always branch
  on `targetIs64Bit()` and use `readPointer()` instead of `readInteger()`/`readQword()` when you mean
  "pointer-sized". Hardcoding register names or pointer size silently breaks on the other
  architecture. `captureStack` returns a dense 1-based array of `{offset, value}` — it must not use
  index 0, because the JSON encoder treats `[1]` presence as "this is an array" and would drop the
  first slot.
- **Memory record manipulation (UNIT-26).** The write side of cheat-table entries:
  `set_memory_record_active` (the `mr.Active = true` freeze path — always read the state back and
  warn when it did not stick, because a failing AA script leaves `Active=false` without throwing),
  `set_memory_record_address` (optional pointer offsets in one call), `set_memory_record_type`
  (with `String.Size`/`Aob.Size`/`Binary.*` sub-config applied *after* the type switch),
  `set_memory_record_description`, `set_memory_record_script`, `set_memory_record_offsets`,
  `get_memory_record_children` (recursive walk), `get_memory_record_current_address`,
  `append_memory_record`. These need no attached process, so there is no process guard.
- **`evaluate_lua` captures `print()`** into `result.printed` and serializes table returns as JSON
  (`serializeLuaValue`), so inspection snippets come back parseable instead of `"table: 0x..."`.
- **`MCP_Bridge` console handle** (end of file): `MCP_Bridge.call(method, params)` runs any command
  from CE's own Lua console with no socket. Set `MCP_BRIDGE_NO_AUTOSTART = true` before `dofile()`
  to load the script without binding a port (used by `test_bridge_lua.lua`).

### Python side — `MCP_Server/mcp_cheatengine.py`

Thin `FastMCP` wrapper plus a hardened transport client.

- `BaseBridgeClient` owns locking, timeouts, the retry policy and JSON-RPC unwrapping;
  `TCPBridgeClient` only implements connect/close/`_exchange_once` (the legacy pywin32
  `PipeBridgeClient` was removed in v15.2.1).
- **`call(method, params)`** wraps `ce_client.send_command` and **never raises**: a dead bridge, a
  timeout or an oversized payload comes back as `{success:false, error_code:...}` instead of an
  exception that surfaces as an opaque MCP tool failure. **Every tool body must use `call(...)`.**
- **`ensure_ascii=False` is mandatory** in `_build_request`. With the `json.dumps` default
  (`ensure_ascii=True`) every non-ASCII character is emitted as a `\uXXXX` escape; the Lua decoder
  used to call `string.char(codepoint)`, which raises for any codepoint > 0xFF — so any CJK payload
  (`write_string`, `evaluate_lua`, non-ASCII paths, `speak_text`) failed with a bare "Parse error".
  Both ends are now correct: Python sends raw UTF-8, and the Lua `unescapeJsonString` decodes
  `\uXXXX` (including surrogate pairs) to real UTF-8 bytes.
- **Never retry a timeout.** `send_command` retries connection failures only. A timed-out command
  may already have executed inside CE (`write_memory`, `auto_assemble`, `inject_dll`, `execute_code`),
  and replaying it would apply the side effect twice. A timeout closes the socket, because a late
  frame would desynchronise the length-prefixed stream.
- **Windows stdio pitfalls (top of file, before any other imports)** — do not move this block:
  - The MCP SDK's `stdio_server` wraps stdio with `TextIOWrapper` without `newline='\n'`, so on
    Windows it emits `\r\n` and the transport rejects with "invalid trailing data." The file
    monkey-patches `mcp.server.stdio.stdio_server` **and** `mcp.server.fastmcp.server.stdio_server`
    (FastMCP captures a reference at import time, so patching only the first module is a silent
    no-op).
  - `sys.stdout` is redirected to `sys.stderr` around third-party imports so stray prints can't
    corrupt the JSON-RPC stream. Anything diagnostic must go through `debug_log()` (stderr only).
    A single stray `print()` on stdout will break the protocol.
  - The `msvcrt.setmode` calls are wrapped in `_force_binary()` — importing the module for tooling
    must not abort when stdio is redirected or absent.

### Adding a new MCP tool

Two files are the source of truth — there is no codegen, so you must edit both:

1. In `ce_mcp_bridge.lua`: write `function cmd_foo(params) ... return { success = true, ... } end`
   and register it in the `commandHandlers` table inside the appropriate unit sub-block (see
   **Section markers** below). Command handlers are intentionally global, not top-level locals:
   Cheat Engine can fail to compile the chunk once it exceeds 200 local variables. The handler name
   must match the snake_case verb-first convention (`cmd_<name>`).
2. In `mcp_cheatengine.py`: add
   `@mcp.tool() def foo(...): return format_result(call("foo", {...}))`.
   Use `call`, not `ce_client.send_command`.
3. Follow the **Conventions** section below.
4. Reload the Lua script in CE; the Python server reconnects automatically.

For a purely additive unit you can avoid touching the big table: define the handler and then append
`commandHandlers.foo = cmd_foo` after the table (see UNIT-25).

## Environment & safety constraints

- **Windows only.** TCP via stdlib — the only transport (pipe client removed in v15.2.1).
- **Cheat Engine prerequisite**: CE → Settings → Extra → **disable "Query memory region routines"**.
  With it enabled, memory scans on DBVM-protected pages trigger `CLOCK_WATCHDOG_TIMEOUT` BSODs. This
  is a hard requirement documented in both `README.md` and the AI guide; don't weaken it without
  testing.
- **Ports**: the DLL binds `0.0.0.0` starting at `17171` and steps up to 10 ports. `TCP_BASE_PORT`
  and `TCP_BIND` in the Lua file are authoritative; the Python side mirrors the range
  (`CE_PORT`/`CE_PORT_RANGE`) and verifies each candidate with a `ping` so a foreign service on the
  port is not mistaken for a bridge. There is **no authentication or encryption** — never expose
  these ports to an untrusted network.
- **Codex config:** use TOML, not JSON. Add `[mcp_servers.cheatengine]`, `command = "python"`, and
  `args = ['C:\path\to\MCP_Server\mcp_cheatengine.py']`. Use TOML single-quoted strings for Windows
  paths so backslashes are literal, then restart Codex and verify with the `ping` tool.
- **Anti-cheat safety** (per `AI_Context/AI_Guide_MCP_Server_Implementation.md`): prefer hardware
  DR0–DR3 breakpoints over software (`0xCC`) breakpoints, and prefer DBVM watches for truly invisible
  tracing. `cmd_set_breakpoint` / `cmd_set_data_breakpoint` already pass `bpmDebugRegister`; keep new
  debugging tools on that path. Only four hardware slots exist — `serverState.hw_bp_slots` tracks them.
- **Env vars**

  | Var | Default | Meaning |
  |---|---|---|
  | `CE_MCP_TIMEOUT` | `90` | Per-command seconds (`<=0` disables). Must stay below the DLL's 120 s wait. |
  | `CE_MCP_RETRIES` | `2` | Extra attempts, connection failures only |
  | `CE_MCP_RETRY_DELAY` | `0.3` | Seconds between connection retries |
  | `CE_MCP_PROBE_TIMEOUT` | `3.0` | Timeout for the "is this really a CE bridge?" ping |
  | `CE_PORT_RANGE` | `10` | Ports to scan |
  | `CE_HOST` / `CE_PORT` | `127.0.0.1` / `17171` | Bridge endpoint |
  | `CE_MCP_ALLOW_SHELL` | *(unset)* | `1` enables `run_command` / `shell_execute` |
  | `CE_MCP_BIND` | *(unset)* | DLL v3.3.0+: bind address for the bridge listener. Default is `127.0.0.1` (loopback only); set e.g. `0.0.0.0` **before CE starts** to opt into remote debugging on a trusted LAN |

## Conventions

### Return shape
- **Success:** `{ success: true, <fields> }`
- **Error:** `{ success: false, error: "<human msg>", error_code: "<UPPER_SNAKE>" }`
- **Error code enum:** `NO_PROCESS`, `INVALID_ADDRESS`, `INVALID_PARAMS`, `CE_API_UNAVAILABLE`,
  `DBVM_NOT_LOADED`, `DBK_NOT_LOADED`, `PERMISSION_DENIED`, `NOT_FOUND`, `OUT_OF_RESOURCES`,
  `INTERNAL_ERROR`. Since v15.1 these are also inferred centrally when a handler omits one, so a
  missing `error_code` is a *documentation* bug, not an untraceable one. Prefer setting it explicitly.

### Addresses
Output: hex string via `toHex()` — `"0x" + uppercase hex`, **no zero padding** (so `"0x1000"` and
`"0x140001000"` have the same shape). Input: accept string or integer.

### Naming
Python tool name == Lua dispatcher key == `cmd_<name>` minus the `cmd_` prefix. Snake_case, verb-first.

### Section markers for contributions
New handlers are appended with unit markers (`-- >>> BEGIN UNIT-NN <Title> <<<`) to keep parallel
contributions mergeable. New dispatcher entries go inside the `commandHandlers` table in unit
sub-blocks, or via `commandHandlers.foo = cmd_foo` after it (UNIT-25 style).

### Pagination
List-returning commands (scan results, memory regions, modules, threads, disassembly, references, BP
hits, methods) support `offset` / `limit` params with a standard
`{ total, offset, limit, returned, <key>: [...] }` return shape. `max` is a deprecated alias for
`limit`. Use `paginate(params, items, defaultLimit)`.

### Batch
`batch({calls:[{method,params}], stop_on_error})` runs up to 64 commands in one round trip and
returns `{success, requested, executed, succeeded, failed, stopped_early, results:[{index,method,…}]}`.
Prefer it over N separate tool calls — with the 1 ms poll and one-command-at-a-time server, round
trips dominate latency.

## Testing

| File | Needs CE? | Purpose |
|---|---|---|
| `MCP_Server/test_bridge_lua.lua` | **no** (any Lua 5.3+) | Unit tests for the JSON codec, `toHex`, `paginate`, error inference, `batch`, `status`, memory-record manipulation (stubbed AddressList), `evaluate_lua`, UTF-8/CJK matrix, guard paths. Loads the bridge with `MCP_BRIDGE_NO_AUTOSTART` and stubs the CE API. |
| `MCP_Server/test_bridge.py --self-test` | **no** | Client-contract tests against an in-process stub bridge: UTF-8 fidelity, timeout-without-retry, connection errors, JSON-RPC unwrapping, oversized-request guard. |
| `MCP_Server/probe_bridge.py --self-test` | **no** | Validates the probe's own framing/reconnect logic against an in-process stub that mirrors `ce_mcp_tcp.c` semantics. |
| `MCP_Server/test_bridge.py` | yes | Live read-only smoke test: identity, dispatcher parity, batch, UTF-8 round trip, module list (duplicate detection), memory read, error paths. |
| `MCP_Server/probe_bridge.py` | yes | Live read-only **frame-format matrix** (13 experiments): envelope shapes, id echo, unknown-method/-32700 shapes, trailing-newline leniency, CJK + large-payload round trips, pipelining, zero-length/oversized/truncated-frame disconnects, post-abuse recovery. |

### Wire facts every client must know (from `ce_mcp_tcp.c` + `executeCommand`)

- **Dispatch, not MCP handshake.** `method` is looked up directly in `commandHandlers[method]`;
  there is no `initialize`/`tools/list` handshake on this socket. The envelope is JSON-RPC
  2.0-*shaped* (`jsonrpc`/`id` echoed), but `method` is a plain bridge command name.
- **Two response shapes.** Success and command-level failures come back as
  `{jsonrpc, result: {success, error_code, ...}, id}`; transport-level failures come back as a
  JSON-RPC `error` object: parse error `-32700` with `data.error_code = "PARSE_ERROR"`, unknown
  method `-32601` with `"METHOD_NOT_FOUND"`. The Python `_unwrap()` normalises both.
- **DLL fast path (v3.3.0).** Methods with the `dll_` prefix (`dll_ping`, `dll_status`, `dll_enum_dialogs`, `dll_dismiss_dialog`) are parsed, executed and answered inside the DLL server thread, BEFORE the Lua queue. They work even while CE's main thread is blocked by a modal dialog - which is when every Lua-backed command times out. `dll_status.poll_age_ms` measures time since the main thread last serviced the bridge.
- **DLL-level timeout drops the connection (v3.3.0).** If Lua exceeds the 120 s budget, the DLL answers
  `{"error":"timeout waiting for command handler"}` — *not* JSON-RPC-shaped (no `code`; `_unwrap`
  degrades it to `error_code: "RPC_ERROR"`) — and then **closes the connection**. Keeping it open
  would let a late Lua response pair with the *next* command (stale-response crossover); teardown is
  the industry-standard resync. The client's next call hits `ConnectionError` and reconnects.
- **Bind address (v3.3.0).** Default `127.0.0.1`; `CE_MCP_BIND` env override (checked in both the
  Lua start log and the DLL). Binding `0.0.0.0` by default was the one MCP-security checklist
  violation; loopback-only fixes it (DNS-rebinding/local-process attacks target exactly that).
- **Framing family.** 4-byte LE length prefix is the same family as gRPC's 5-byte prefix — the
  correct choice for raw TCP (NDJSON/MCP-stdio would forbid raw newlines; LSP headers add parsing
  overhead). Guard: `len <= 0 || len > 4 MiB` → the DLL **drops the connection**; so do truncated
  bodies. Lock-step: one request → one response; pipelined frames are buffered by TCP and answered
  in order.

The obsolete `test_mcp.py` (pre-v15 Named Pipe protocol, expected version `12.x`) has been
**removed**; git history retains it.

The self-test mode can run under any Python with the `mcp` SDK installed; the project venv
(`MCP_Server/.venv/Scripts/python.exe`) is the safe choice.

`lua` must be ≥ 5.3 (the bridge uses `&`, `>>`, `<<`). Lua 5.5 additionally rejects assigning to a
loop control variable, so avoid `for k in ... do k = ...` patterns — `luac -p ce_mcp_bridge.lua` on
5.5 is a useful extra syntax gate.

## Reference material in `AI_Context/`

- `MCP_Bridge_Command_Reference.md` — per-command reference with request/response examples. Consult
  this when working on a specific tool instead of grepping the Lua file.
- `AI_Guide_MCP_Server_Implementation.md` — architecture and safety notes. **Written for the v11.4.0
  Named Pipe design; the safety guidance (BSOD setting, DBVM, hardware breakpoints) still applies,
  the architecture sections do not.**
- `CE_LUA_Documentation.md` — Cheat Engine 7.6 Lua API reference (~229 KB). Offline source of truth
  when a CE function's behaviour is unclear.
- `BATCH_WORKER_BRIEFING.md` — task specifications from the v12 parallel overhaul. Historical.
- `plugins/` — CE native plugin SDK headers and Lua headers. **Not used** at runtime.
