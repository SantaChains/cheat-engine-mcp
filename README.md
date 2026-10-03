**[English](README.md) | [中文](README_CN.md)**

# Cheat Engine MCP Bridge — Native TCP Edition

[![Version](https://img.shields.io/badge/version-15.8.1-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org) [![Transport](https://img.shields.io/badge/transport-Native%20TCP%20DLL-orange.svg)](#) [![Tools](https://img.shields.io/badge/tools-249-brightgreen.svg)](#available-tools)

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

Copy the DLL matching your Cheat Engine build into CE's **plugin directory** (recommended — the
standard location for CE native components):

```
C:\Program Files\Cheat Engine\cheatengine-x86_64.exe
C:\Program Files\Cheat Engine\plugins\ce_mcp_tcp_x64.dll    ← here (use _x86.dll for 32-bit CE)
```

The CE root directory (`C:\Program Files\Cheat Engine\ce_mcp_tcp_x64.dll`) also works if you
prefer — the bridge searches both, plugins first is *not* required; root is kept for backward
compatibility.

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
[MCP] DLL loaded OK from: C:\Program Files\Cheat Engine\plugins\ce_mcp_tcp_x64.dll
[MCP] Bridge v15.8.1 started on 127.0.0.1:17171 (native TCP, 1ms poll)
```

No window will pop up — the DLL debug console is hidden by default (`CE_MCP_DEBUG_CONSOLE=1` shows it without stealing focus).

### 5. Configure Your AI Client

The server is a standard **MCP stdio** server built on the official MCP Python SDK — it follows the
current MCP spec and works with **any** client that supports stdio MCP servers. The generic config
shape is always the same `mcpServers` JSON object (Codex CLI is the one TOML outlier below):
Cursor, Windsurf, Cline, Claude Desktop, Claude Code, Gemini CLI, Trae, Qoder, CodeBuddy and other
IDEs / terminal AI CLIs all accept it.

<details>
<summary><b>Claude Code CLI (recommended way)</b></summary>

```bash
claude mcp add cheatengine -- python "C:/path/to/MCP_Server/mcp_cheatengine.py"
```

Or project-scoped `.mcp.json` (same `mcpServers` JSON shape as below).
</details>

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
<summary><b>Gemini CLI</b></summary>

`~/.gemini/settings.json`:
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
<summary><b>Trae / Qoder / CodeBuddy (Chinese IDEs)</b></summary>

All use the same `mcpServers` JSON format:

- **Trae**: `~/.trae/mcp.json` (or MCP panel → Add manually → stdio)
- **Qoder**: MCP panel → stdio server, command `python`, args as above
- **CodeBuddy**: `~/.codebuddy/mcp.json` (same shape as Cursor)
</details>

<details>
<summary><b>Windsurf / Cline / other JSON clients</b></summary>

Same `mcpServers` JSON as Cursor — only the config file location differs
(`~/.codeium/windsurf/mcp_config.json`, VS Code `settings.json` / Cline panel, etc.).
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
{"success": true, "version": "15.8.1", "message": "CE MCP Bridge v15.8.0 alive"}
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
| `CE_MCP_TOOLS` | `all` | **Tool loading profile**: `all` / `core` (alias `minimal`) / `core,memory,debug,...` — see [Progressive Tool Loading](#progressive-tool-loading) |
| `CE_MCP_AUTH_TOKEN` | *(unset)* | Shared token auth: set on both sides so every request carries `params._auth` and the bridge rejects the rest with `AUTH_REQUIRED` |

> A command that **may already have executed** is **never** retried. That covers a timed-out
> command and any failure after the request frame was fully delivered — `write_memory`,
> `auto_assemble`, `inject_dll` or `execute_code` may have run, and replaying would apply the
> side effect twice. Only failures where the frame was never delivered (connect / send failure)
> are retried. A timeout closes the socket instead.

---

## Progressive Tool Loading

249 tools with full JSON schemas in one `tools/list` costs a client a lot of context on every
session start. The server therefore loads tools in **layers**:

- `CE_MCP_TOOLS=all` *(default)* — everything, exactly as before.
- `CE_MCP_TOOLS=core` (alias `minimal`) — only 15 always-on tools: bridge health
  (`bridge_status`, `ping`, `dll_status`), memory IO basics, `evaluate_lua`, batch/audit
  introspection, modal-dialog recovery (`dialog_enum`/`dialog_dismiss`) and `ce_tools_manage`.
- `CE_MCP_TOOLS=core,memory,debug` — core plus any of the 18 categories below.

At runtime the always-registered **`ce_tools_manage`** tool extends the surface without a restart:

```json
{"name": "ce_tools_manage", "arguments": {"action": "list"}}
{"name": "ce_tools_manage", "arguments": {"action": "enable", "categories": ["memory", "debug"]}}
```

`enable` is idempotent and sends `notifications/tools/list_changed` when the client supports it
(otherwise: re-list tools or reconnect). Categories: `core`, `memory`, `scan`, `disasm`, `debug`,
`process`, `symbols`, `structures`, `table`, `aa`, `exec`, `dotnet`, `dissect`, `custom`,
`ui_input`, `system`, `kernel`, `net`.

---

## Available Tools (249 registered tools / 253 dispatcher methods)

The Python side records **248** `@mcp.tool()` functions plus the `ce_tools_manage` meta tool
(**249** registered by default); the Lua dispatcher resolves **253** methods
(the difference is aliases such as `read_bytes` → `read_memory`, `status` → `bridge_status`).

| Category | Tools | Examples |
|----------|-------|----------|
| **core** (always on) | 16 | `bridge_status`, `ping`, `ct_preflight`, `evaluate_lua`, `batch_call`, `dialog_enum`, `ce_tools_manage` |
| **memory** | 22 | `read_memory`, `write_memory`, `read_pointer_chain`, `validate_pointer_chain`, `inject_preview`, `allocate_memory` |
| **scan** | 22 | `scan_all`, `aob_scan`, `aob_scan_unique`, `aob_health_scan`, `pointer_rescan`, `persistent_scan_*`, `generate_signature` |
| **disasm** | 9 | `disassemble`, `analyze_function`, `find_references`, `get_previous_opcode` |
| **debug** | 22 | `set_breakpoint`, `debug_get_context`, `debug_continue`, `start_dbvm_watch` |
| **process** | 16 | `open_process`*(core)*, `get_process_list`, `pause_process`, `set_speed`, `queue_to_main_thread` |
| **symbols** | 14 | `get_symbol_address`, `get_symbol_info`, `register_symbol`, `reinitialize_symbol_handler` |
| **structures** | 8 | `create_structure`, `dissect_structure`, `auto_guess_structure`, `export_structure_to_xml` |
| **table** | 24 | `load_table`, `save_table`, `create_memory_record`, `ct_memory_records_health`, `table_file_*` |
| **aa** | 8 | `auto_assemble`, `compile_c_code`, `generate_code_injection_script`, `register_aa_command` |
| **exec** | 8 | `execute_code`, `execute_code_ex`, `inject_dll`, `inject_dotnet_dll` |
| **dotnet** | 8 | `dotnet_status`, `dotnet_enum_types`, `dotnet_type_details`, `dotnet_enum_objects` |
| **dissect** | 5 | `dissect_code_start`, `dissect_code_references`, `dissect_code_strings`, `dissect_code_functions` |
| **custom** | 8 | `create_hotkey`, `register_custom_type`, `read_custom`, `write_custom` |
| **ui_input** | 13 | `find_window`, `is_key_pressed`, `do_key_press`, `get_mouse_pos`, `send_window_message` |
| **system** | 23 | `file_exists`, `get_file_list`, `read_clipboard`, `show_message`, `md5_file`, `write_region_to_file` |
| **kernel** | 21 | `dbk_initialize`, `read_process_memory_cr3`, `dbvm_initialize`, `dbvm_cloak_*` |
| **net** | 2 | `http_get`, `http_post` |

> **Batch is the fast path.** With a 1 ms main-thread poll and one command in flight at a time,
> round trips dominate latency. `batch_call(calls=[{method, params}, ...])` runs up to **64** commands
> in a single round trip and returns a per-item result array.

### Recommended Workflows

**Pointer tracing**

```json
// 1. Find what accesses the address (get a register value like RBX from the context)
{"name": "find_what_accesses_or_debug_get_context", "arguments": {"address": "0x255D5E758"}}
// 2. Value-scan for that pointer target, then narrow down
{"name": "create_persistent_scan", ...} // first scan → persistent_scan_next_scan → ... → game.exe+offset
// Or go straight to pointer rescan once you have a candidate base
{"name": "pointer_rescan", "arguments": {...}}
```

**Function analysis**

```json
// 1. Boundaries + disassembly
{"name": "find_function_boundaries", "arguments": {"address": "0x14587EDB0"}}
{"name": "analyze_function", "arguments": {"address": "0x14587EDB0"}}
// 2. Step through execution
{"name": "set_breakpoint", "arguments": {"address": "0x14587EDB0"}}
{"name": "debug_get_context", "arguments": {}}
// 3. Signature for game updates
{"name": "generate_signature", "arguments": {"address": "0x14587EDB0"}}
```

**Cheat table pipeline**

```json
{"name": "load_table", "arguments": {"path": "C:/tables/game.CT"}}
{"name": "get_address_list", "arguments": {}}
{"name": "set_memory_record_active", "arguments": {"id": 12, "active": true}}
```

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

Current status: **221/0** Lua unit assertions, **38/0** Python contract assertions, **4/0** probe self-test.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named 'mcp'` | Run `python -m pip install mcp` (see [Install](#2-install-python-dependencies)) |
| DLL not found | Copy `ce_mcp_tcp_x64.dll` into CE's `plugins\` folder (or the CE root directory) |
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
