**[English](README.md) | [中文](README_CN.md)**

# Cheat Engine MCP Bridge — Native TCP Edition

[![Version](https://img.shields.io/badge/version-15.4.1-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org) [![Transport](https://img.shields.io/badge/transport-Native%20TCP%20DLL-orange.svg)](#) [![Tools](https://img.shields.io/badge/tools-198-brightgreen.svg)](#available-tools)

Let your AI assistant (Claude, Cursor, Codex, any MCP client) drive **Cheat Engine** directly:
read and write process memory, scan for values, disassemble functions, set breakpoints,
inject code, and manipulate cheat tables — **198 MCP tools** backed by a native C TCP bridge
inside Cheat Engine.

> Based on [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge),
> rebuilt on a native C TCP transport — remote CE control, zero pywin32 dependency,
> multi-instance support. See [Credits](#credits).

---

## Features

- **198 MCP tools** covering memory, scanning, disassembly, breakpoints, injection, cheat tables, kernel paths
- **Native C transport** — a small DLL owns a Winsock thread; no `pywin32`, no FFI crashes, static `/MT` CRT (no VC runtime needed)
- **Remote debugging built-in** — point `CE_HOST` at another machine, no relay scripts
- **Multi-instance** — auto port discovery (17171–17180), one MCP server can map to one of several CE instances
- **`batch_call`** — up to 64 commands in a single round trip (the latency fast path)
- **Machine-readable errors** — every failure carries an `error_code`; timeouts are never blindly retried
- **Fastpath bypass** — `dll_status` / `dialog_enum` / `dialog_dismiss` answer even while CE's main thread is frozen by a modal dialog
- **Hidden-by-default debug console** — zero UI interference; set `CE_MCP_DEBUG_CONSOLE=1` to see DLL diagnostics
- **Tested offline** — 163 Lua unit assertions, 27 Python contract assertions, 4 probe checks; no CE needed to run the suite

### Architecture

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

---

## Setup

### 1. Clone

```bash
git clone https://github.com/SantaChains/cheat-engine-mcp.git
cd cheat-engine-mcp
```

### 2. Install Python Dependencies

**Prerequisites**: Python 3.10+ ([download](https://python.org/downloads/))

```bash
pip install -r MCP_Server/requirements.txt
```

Verify:
```bash
python -c "from mcp.server.fastmcp import FastMCP; print('OK')"
```

If you see `ModuleNotFoundError: No module named 'mcp'`, try `python -m pip install mcp` and make sure it installs into the same interpreter your AI client spawns.

> TCP transport requires **no** `pywin32`.

### 3. Place the DLL

Copy the DLL matching your Cheat Engine build into the **CE directory**:

```
C:\CE 7.5\cheatengine-x86_64.exe
C:\CE 7.5\ce_mcp_tcp_x64.dll    ← here (use _x86.dll for 32-bit CE)
```

Prebuilt DLLs ship in `MCP_Server/` (also in `NativeBridge/bin/`).

### 4. Load in Cheat Engine

1. Attach CE to your target process
2. `File` → `Execute Script` → open `MCP_Server/ce_mcp_bridge.lua` → `Execute`

Or via the Lua console:
```lua
dofile([[C:\path\to\MCP_Server\ce_mcp_bridge.lua]])
```

Expected output:
```
[MCP] CE x64 - loading ce_mcp_tcp_x64.dll
[MCP] DLL loaded OK from: C:\CE 7.5\ce_mcp_tcp_x64.dll
[MCP] Bridge v15.4.1 started on 127.0.0.1:17171 (native TCP, 1ms poll)
```

No window will pop up — the DLL debug console is hidden by default (`CE_MCP_DEBUG_CONSOLE=1` shows it without stealing focus).

### 5. Configure Your AI Client

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
<summary><b>Remote CE (another machine)</b></summary>

```json
{ "env": { "CE_HOST": "192.168.1.100", "CE_PORT": "17171" } }
```

Firewall on the CE machine:
```powershell
netsh advfirewall firewall add rule name="CE MCP" dir=in action=allow protocol=TCP localport=17171
```

By default the DLL binds to `127.0.0.1` only. For remote access set `CE_MCP_BIND=0.0.0.0` in the CE machine's environment before starting CE.
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
| `CE_MCP_BIND` | `127.0.0.1` | DLL listener bind address; set `0.0.0.0` before CE starts for remote debugging |
| `CE_MCP_DEBUG_CONSOLE` | *(unset)* | `1` to show the DLL debug console (never steals focus) |

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
| **Bridge control** | `batch_call`, `bridge_status`, `list_bridge_methods`, `dll_status`, `dialog_enum`, `dialog_dismiss` |

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

Current status: **163/0** Lua unit assertions, **27/0** Python contract assertions, **4/0** probe self-test.

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
| CE UI freezes | Normal — handlers run on main thread for API safety |
| Many small calls are slow | Use `batch_call` to collapse them into one round trip |
| CE frozen by a modal dialog | Use `dialog_enum` + `dialog_dismiss` — they answer even while the main thread is blocked |

---

## Critical: BSOD Prevention

> **Disable** CE → Settings → Extra → **"Query memory region routines"**. Memory scans on DBVM pages trigger `CLOCK_WATCHDOG_TIMEOUT` BSODs with it enabled.

---

## Credits

This project is a deep rework derived from
[miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge)
by [@miscusi-peek](https://github.com/miscusi-peek) — the Lua bridge foundation, MCP server design
and original tool set all trace back to it. Contributors of the original:
[@libangli218](https://github.com/libangli218), [@lauralex](https://github.com/lauralex),
[@iamtyroon](https://github.com/iamtyroon).

This edition replaces the Named Pipe transport with a native C TCP DLL and extends the surface
to 198 tools. Licensed under the same terms — see [LICENSE](LICENSE).

## Disclaimer

For educational and research purposes only. Do not use for malicious hacking, cheating in multiplayer games, or violating Terms of Service.
