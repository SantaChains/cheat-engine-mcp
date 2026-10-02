**[English](README.md) | [中文](README_CN.md)**

# Cheat Engine MCP Bridge — TCP Enhanced Edition

[![Version](https://img.shields.io/badge/version-15.4.1-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org) [![Transport](https://img.shields.io/badge/transport-Native%20TCP%20DLL-orange.svg)](#) [![Tools](https://img.shields.io/badge/tools-198-brightgreen.svg)](#available-tools)

> Based on [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge) that replaces Windows Named Pipe with a native C TCP bridge, enabling **remote CE control**, **zero pywin32 dependency**, and **multi-instance support**.

[Demo Video](https://github.com/user-attachments/assets/a184a006-f569-4b55-858a-ed80a7139035)

---

## This Project vs Original — Key Differences

### Architecture

```
ORIGINAL (v12.0.0)                         THIS PROJECT (v15.4.1)
AI Client                                  AI Client
  │ stdio JSON-RPC                           │ stdio JSON-RPC
  ▼                                          ▼
mcp_cheatengine.py                         mcp_cheatengine.py
  │ Named Pipe (pywin32)                     │ TCP socket (stdlib only)
  ▼                                          ▼
\\.\pipe\CE_MCP_Bridge_v99                 ce_mcp_tcp.dll (native C)
  │ Worker thread (Lua pipe I/O)             │ Winsock2 + select()
  ▼                                          ▼
ce_mcp_bridge.lua → Target Process         ce_mcp_bridge.lua → Target Process
```

### Pros & Cons Comparison

| | Original (v12.0.0) | This Project (v15.4.1) |
|---|---|---|
| **Transport** | Named Pipe | Native TCP (C DLL) |
| **Remote CE** | Requires `ce_tcp_relay.py` relay script | Built-in via `CE_HOST` env var |
| **Python deps** | `mcp` + `pywin32` | `mcp` only |
| **Multi-instance** | Not supported | Port auto-increment (17171–17181) |
| **Timeout** | 30s | 90s, 3x retry + auto-reconnect |
| **Debug console** | None | Dedicated DLL diagnostic window |
| **Lua code** | ~6700 lines (FFI/Winsock/Pipe) | ~6600 lines (FFI removed; +batch/self-inspection) |
| **CRT dependency** | None | Static `/MT` — no VC runtime needed |

| | Original Advantages | This Project Advantages |
|---|---|---|
| **Simplicity** | Zero DLL, pip install only | N/A |
| **Local security** | Named Pipe is local-only by design | N/A |
| **Remote debugging** | N/A | Native TCP, no relay scripts |
| **Cross-platform server** | N/A | TCP stdlib works anywhere |
| **Stability** | N/A | No FFI crashes, no PEB-walk failures |
| **Multi-CE** | N/A | Auto port discovery |

> **Security**: TCP has **no auth/encryption**. Only expose on trusted networks. Never open port 17171 to the internet.

### Project Structure Comparison

```
ORIGINAL                                   THIS FORK
────────                                   ─────────
MCP_Server/                                MCP_Server/
├── mcp_cheatengine.py  (pywin32 pipe)     ├── mcp_cheatengine.py   (TCP stdlib, 198 tools)
├── ce_mcp_bridge.lua   (~6700 lines)      ├── ce_mcp_bridge.lua    (~6600 lines)
├── ce_tcp_relay.py     (TCP relay)        ├── ce_mcp_tcp_x64.dll   ← NEW: native DLL
├── test_mcp.py                            ├── ce_mcp_tcp_x86.dll   ← NEW: native DLL
└── requirements.txt    (mcp + pywin32)    ├── test_bridge_lua.lua  ← NEW: offline Lua tests
                                           ├── test_bridge.py       ← NEW: client contract/smoke
                                           └── requirements.txt     (mcp only)
AI_Context/             (docs)
                                           NativeBridge/            ← NEW: DLL source
                                           ├── ce_mcp_tcp.c         (770 lines C)
                                           ├── build.bat
                                           └── bin/{x64,x86}/

                                           AI_Context/              (docs)
```

Key structural differences:
- **Removed**: `ce_tcp_relay.py` — no longer needed, TCP is native
- **Removed**: `pywin32` from requirements — TCP uses Python stdlib
- **Added**: `NativeBridge/` — compiled C DLL source and build system
- **Added**: Pre-built DLLs in `MCP_Server/` for easy deployment
- **Added**: Offline + live test harnesses (`test_bridge_lua.lua`, `test_bridge.py`)
- **Reworked**: Lua bridge — dead FFI/pipe code removed, then `batch`, `status`/`list_methods`
  self-inspection and central error-code inference added back on top

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/HollyZoe/cheatengine-mcp-tcp-bridge.git
cd cheatengine-mcp-tcp-bridge
```

### 2. Install Python Dependencies

**Prerequisites**: Python 3.10+ ([download](https://python.org/downloads/))

The MCP server requires the `mcp` Python package (Model Context Protocol SDK). This is **not a built-in module** — you must install it manually:

```bash
pip install -r MCP_Server/requirements.txt
```

Or install directly:
```bash
pip install mcp
```

> If you have multiple Python versions, use `python -m pip install mcp` to ensure it installs to the correct environment.

**Verify the installation succeeded**:
```bash
python -c "from mcp.server.fastmcp import FastMCP; print('OK')"
```

If you see `ModuleNotFoundError: No module named 'mcp'`, the install failed — check:
- You're using the same `python` that Cursor/your AI client will use
- Try `python -m pip install mcp` instead of just `pip install mcp`
- On Windows, pip may warn scripts are not on PATH — this is fine, Cursor spawns the server via the `python` command directly

> **Note**: TCP transport requires **no** `pywin32`. The legacy Named Pipe transport (and its `pywin32` dependency) was removed in v15.2.1.

### 3. Place DLL

Copy `ce_mcp_tcp_x64.dll` (or `_x86.dll` for 32-bit CE) into your **Cheat Engine directory**:

```
C:\CE 7.5\cheatengine-x86_64.exe
C:\CE 7.5\ce_mcp_tcp_x64.dll    ← here
```

DLL source: `MCP_Server/` or `NativeBridge/bin/`.

### 4. Load in Cheat Engine

1. Attach CE to your target process
2. `File` → `Execute Script` → open `MCP_Server/ce_mcp_bridge.lua` → `Execute`

Or via Lua console:
```lua
dofile([[C:\path\to\MCP_Server\ce_mcp_bridge.lua]])
```

Expected output:
```
[MCP] CE x64 - loading ce_mcp_tcp_x64.dll
[MCP] DLL loaded OK from: C:\CE 7.5\ce_mcp_tcp_x64.dll
[MCP] Bridge v15.4.1 started on 127.0.0.1:17171 (native TCP, 1ms poll)
```

### 5. Configure AI Client

<details>
<summary><b>Cursor IDE</b></summary>

`.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "cheatengine": {
      "command": "python",
      "args": ["C:/path/to/MCP_Server/mcp_cheatengine.py"],
      "env": { "CE_HOST": "127.0.0.1", "CE_PORT": "17171" }
    }
  }
}
```
</details>

<details>
<summary><b>Claude Desktop</b></summary>

`%APPDATA%\Claude\claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "cheatengine": {
      "command": "python",
      "args": ["C:/path/to/MCP_Server/mcp_cheatengine.py"],
      "env": { "CE_HOST": "127.0.0.1", "CE_PORT": "17171" }
    }
  }
}
```
</details>

<details>
<summary><b>Codex CLI</b></summary>

`~/.codex/config.toml`:
```toml
[mcp_servers.cheatengine]
command = "python"
args = ['C:\path\to\MCP_Server\mcp_cheatengine.py']
```
</details>

<details>
<summary><b>Remote CE</b></summary>

```json
{ "env": { "CE_HOST": "192.168.1.100", "CE_PORT": "17171" } }
```

Firewall on CE machine:
```powershell
netsh advfirewall firewall add rule name="CE MCP" dir=in action=allow protocol=TCP localport=17171
```
</details>

### 6. Verify

Ask the AI: *"Ping Cheat Engine"*

```json
{"success": true, "version": "15.4.1", "message": "CE MCP Bridge v15.4.1 alive"}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CE_HOST` | `127.0.0.1` | CE machine IP (remote debugging) |
| `CE_PORT` | `17171` | TCP port (auto-increments if busy) |
| `CE_PORT_RANGE` | `10` | Ports to scan from base |
| `CE_MCP_TIMEOUT` | `90` | Per-tool timeout (seconds). Keep below the DLL's 120 s wait; `<=0` disables |
| `CE_MCP_RETRIES` | `2` | Extra attempts — **connection failures only**, never timeouts |
| `CE_MCP_RETRY_DELAY` | `0.3` | Seconds between connection retries |
| `CE_MCP_PROBE_TIMEOUT` | `3.0` | Timeout for the "is this really a CE bridge?" liveness ping |
| `CE_MCP_ALLOW_SHELL` | *(unset)* | `1` to enable `run_command`/`shell_execute` |
| `CE_MCP_BIND` | *(unset)* | DLL v3.3.0+: listener bind address, default `127.0.0.1` (loopback only). Set e.g. `0.0.0.0` before CE starts to opt into remote debugging |

> A timed-out command is **never** retried: it may already have executed inside CE
> (`write_memory`, `auto_assemble`, `inject_dll`, `execute_code`), so replaying it would apply the
> side effect twice. A timeout closes the socket instead.

---

## Available Tools (198 MCP tools / 203 dispatcher methods)

The Python side exposes **198** `@mcp.tool()` functions; the Lua dispatcher resolves **203** methods
(the difference is aliases such as `read_bytes` → `read_memory`, `status` → `bridge_status`).

| Category | Examples |
|----------|----------|
| **Memory Read/Write** | `read_memory`, `write_memory`, `read_integer`, `write_string`, `read_pointer_chain` |
| **Scanning** | `scan_all`, `next_scan`, `aob_scan`, `aob_scan_module`, `search_string` |
| **Disassembly & Analysis** | `disassemble`, `analyze_function`, `find_function_boundaries`, `find_references`, `find_call_references` |
| **Code Injection** | `auto_assemble`, `inject_dll`, `execute_code`, `compile_c_code` |
| **Breakpoints & Debug** | `set_breakpoint`, `set_data_breakpoint`, `start_dbvm_watch`, `get_breakpoint_hits` |
| **Process & Modules** | `open_process`, `get_process_list`, `enum_modules`, `get_symbol_address` |
| **Structures** | `create_structure`, `dissect_structure`, `add_element_to_structure`, `get_rtti_classname` |
| **Memory Management** | `allocate_memory`, `free_memory`, `get_memory_protection`, `get_memory_regions` |
| **Cheat Table** | `load_table`, `save_table`, `create_memory_record`, `set_memory_record_active`, `set_memory_record_address`, `set_memory_record_script`, `get_memory_record_children` |
| **GUI & Input** | `find_window`, `is_key_pressed`, `get_pixel`, `show_message`, `speak_text` |
| **File & System** | `file_exists`, `md5_file`, `get_file_list`, `evaluate_lua` |
| **Kernel (DBK/DBVM)** | `dbk_get_cr3`, `get_physical_address`, `read_process_memory_cr3` |
| **Bridge control** | `batch_call`, `bridge_status`, `list_bridge_methods` |

> **Batch is the fast path.** With a 1 ms main-thread poll and one command in flight at a time,
> round trips dominate latency. `batch_call(calls=[{method, params}, ...])` runs up to **64** commands
> in a single round trip and returns a per-item result array.

Full reference: [`AI_Context/MCP_Bridge_Command_Reference.md`](AI_Context/MCP_Bridge_Command_Reference.md)

---

## Testing

Two harnesses run **without Cheat Engine** and are the fastest way to validate a change.
For the full developer reference (architecture, wire protocol, concurrency model, build,
extension guide) see **[DEV_GUIDE.md](DEV_GUIDE.md)**.

```bash
lua MCP_Server/test_bridge_lua.lua            # offline Lua unit tests (any Lua 5.3+), no CE
python MCP_Server/test_bridge.py --self-test  # offline Python client contract, no CE
python MCP_Server/probe_bridge.py --self-test # offline wire-probe self-check, no CE
```

With CE running and the bridge loaded, a read-only smoke test:

```bash
python MCP_Server/test_bridge.py              # identity, dispatcher parity, batch, UTF-8, memory read
python MCP_Server/test_bridge.py --allow-write  # + allocate / write / read-back
```

| File | Needs CE? | Purpose |
|------|-----------|---------|
| `test_bridge_lua.lua` | no | JSON codec, `toHex`, `paginate`, error inference, `batch`, `status`, memory-record manipulation (stubbed AddressList), `evaluate_lua`, UTF-8/CJK matrix, guard paths |
| `test_bridge.py --self-test` | no | UTF-8 fidelity, timeout-without-retry, connection errors, JSON-RPC unwrapping, oversized-request guard |
| `probe_bridge.py --self-test` | no | Probe framing/reconnect logic vs an in-process stub mirroring `ce_mcp_tcp.c` |
| `test_bridge.py` | yes | Live read-only smoke test |
| `probe_bridge.py` | yes | Live read-only **frame matrix** (13 experiments): envelope shapes, id echo, `-32601`/`-32700` paths, trailing-newline leniency, CJK + large payloads, pipelining, abusive-frame disconnects, post-abuse recovery |

The obsolete `test_mcp.py` (pre-v15 Named Pipe protocol) has been removed; git history retains it.

Current status: **130/0** Lua unit assertions, **27/0** Python contract assertions, **4/0** probe self-test.

### Historical manual results (pre-v15 surface, target: Notepad.exe on Windows 10)

| Result | Count |
|--------|-------|
| Passed | **110+** |
| Fixed during testing | **3** (get_memory_protection, get_memory_regions, debug_get_current_debugger_interface) |
| CE environment limitation | **5** (compile_c_code, compile_cs_code, load_new_symbols, pointer_rescan, inject_dotnet_dll) |
| Requires kernel driver | **~20** (skipped — needs signed driver/DBVM) |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named 'mcp'` | Run `python -m pip install mcp` (see [Install](#2-install-python-dependencies)) |
| DLL not found | Copy `ce_mcp_tcp_x64.dll` to CE directory |
| Cannot connect | Check `netstat -an \| findstr 17171`, verify CE_HOST/CE_PORT |
| `error_code: BRIDGE_UNAVAILABLE` | Bridge DLL not listening, or your Lua script is still the pre-v15 pipe build |
| `error_code: TIMEOUT` | Raise `CE_MCP_TIMEOUT`; the command is **not** retried by design |
| Non-ASCII / CJK `write_string` fails | Pre-15.1 bug — reload the current `ce_mcp_bridge.lua` in CE |
| "too many local variables" | Use `dofile(...)` instead of pasting the script |
| Timeout on heavy ops | Increase `CE_MCP_TIMEOUT` |
| CE UI freezes | Normal — handlers run on main thread for API safety |
| Many small calls are slow | Use `batch_call` to collapse them into one round trip |

---

## Critical: BSOD Prevention

> **Disable** CE → Settings → Extra → **"Query memory region routines"**. Memory scans on DBVM pages trigger `CLOCK_WATCHDOG_TIMEOUT` BSODs with it enabled.

---

## Credits

Derived from [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge) by [@miscusi-peek](https://github.com/miscusi-peek). Contributors: [@libangli218](https://github.com/libangli218), [@lauralex](https://github.com/lauralex), [@iamtyroon](https://github.com/iamtyroon).

## Disclaimer

For educational and research purposes only. Do not use for malicious hacking, cheating in multiplayer games, or violating Terms of Service.
