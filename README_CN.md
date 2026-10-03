**[English](README.md) | [中文](README_CN.md)**

# Cheat Engine MCP Bridge — 原生 TCP 版

[![Version](https://img.shields.io/badge/version-15.8.2-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org) [![Transport](https://img.shields.io/badge/transport-原生%20TCP%20DLL-orange.svg)](#) [![Tools](https://img.shields.io/badge/工具-249-brightgreen.svg)](#可用工具)

让你的 AI 助手（Claude、Cursor、Codex、任何 MCP 客户端）直接驱动 **Cheat Engine**：
读写进程内存、扫描数值、反汇编函数、下断点、注入代码、操作 CT 表——**198 个 MCP 工具**，
由运行在 Cheat Engine 内部的原生 C TCP 桥支撑。

> 始于 [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge)
> 的深度重构衍生版，重建为原生 C TCP 传输——支持远程 CE 控制、零 pywin32 依赖、多实例并行。
> 见[致谢](#致谢)。

---

## 特性

- **198 个 MCP 工具**：内存、扫描、反汇编、断点、注入、CT 表、内核路径全覆盖
- **原生 C 传输**：小型 DLL 独占 Winsock 线程；无 `pywin32`、无 FFI 崩溃、静态 `/MT` CRT（无需 VC 运行时）
- **远程调试内置**：`CE_HOST` 指向另一台机器即可，无需中继脚本
- **多实例**：端口自动发现（17171–17180），一个 MCP 服务端可对应多个 CE 实例之一
- **`batch_call`**：单次往返最多打包 64 条命令（延迟优化快路径）
- **机器可读错误**：每个失败都带 `error_code`；超时绝不盲目重试
- **快速通道旁路**：`dll_status` / `dialog_enum` / `dialog_dismiss` 在 CE 主线程被模态框冻结时仍能应答
- **调试控制台默认隐藏**：零 UI 干扰；设 `CE_MCP_DEBUG_CONSOLE=1` 可查看 DLL 诊断日志
- **离线测试**：163 条 Lua 单元断言、27 条 Python 契约断言、4 条探针自检；无需运行 CE 即可跑完

### 架构

```
AI 客户端 ──(MCP / JSON-RPC over stdio)──▶ mcp_cheatengine.py
                                              │
                                              ▼ (4 字节 LE 长度前缀 + UTF-8 JSON-RPC)
                                    127.0.0.1:17171..17180  (TCP, 原生 DLL)
                                              │
                                              ▼
                                 ce_mcp_tcp_{x64,x86}.dll  (独立 Winsock 线程)
                                              │  1ms 主线程轮询
                                              ▼
                                      ce_mcp_bridge.lua (CE 内部)
                                              │
                                              ▼ (CE Lua API / DBVM)
                                        目标进程内存
```

---

## 安装使用

### 1. 克隆仓库

```bash
git clone https://github.com/SantaChains/cheat-engine-mcp.git
cd cheat-engine-mcp
```

### 2. 安装 Python 依赖

**前置要求**：Python 3.10+（[下载](https://python.org/downloads/)）

```bash
pip install -r MCP_Server/requirements.txt
```

验证：
```bash
python -c "from mcp.server.fastmcp import FastMCP; print('OK')"
```

若出现 `ModuleNotFoundError: No module named 'mcp'`，改用 `python -m pip install mcp`，并确认安装到 AI 客户端将启动的同一个解释器。

> TCP 传输**不需要** `pywin32`。

### 3. 放置 DLL

把与你 CE 位数匹配的 DLL 复制到 CE 的**插件目录**（推荐——CE 原生组件的标准位置）：

```
C:\Program Files\Cheat Engine\cheatengine-x86_64.exe
C:\Program Files\Cheat Engine\plugins\ce_mcp_tcp_x64.dll    ← 放这里（32 位 CE 用 _x86.dll）
```

放在 CE 根目录（`C:\Program Files\Cheat Engine\ce_mcp_tcp_x64.dll`）也可以——桥会同时搜索两处，保留根目录只为向后兼容。

预构建 DLL 位于 `MCP_Server/`（也在 `NativeBridge/bin/`）。

### 4. 在 Cheat Engine 中加载

1. CE 附加到目标进程
2. `File` → `Execute Script` → 打开 `MCP_Server/ce_mcp_bridge.lua` → `Execute`

或通过 Lua 控制台：
```lua
dofile([[C:\path\to\MCP_Server\ce_mcp_bridge.lua]])
```

预期输出：
```
[MCP] CE x64 - loading ce_mcp_tcp_x64.dll
[MCP] DLL loaded OK from: C:\Program Files\Cheat Engine\plugins\ce_mcp_tcp_x64.dll
[MCP] Bridge v15.8.2 started on 127.0.0.1:17171 (native TCP, 1ms poll)
```

不会弹出任何窗口——DLL 调试控制台默认隐藏（`CE_MCP_DEBUG_CONSOLE=1` 可显示，且不抢焦点）。

### 5. 配置 AI 客户端

服务端是基于官方 MCP Python SDK 的标准 **MCP stdio** 服务器，遵循 MCP 最新规范，**任何**支持 stdio MCP 的客户端都能接入。通用配置都是同一个 `mcpServers` JSON 结构（唯独 Codex CLI 用 TOML）：Cursor、Windsurf、Cline、Claude Desktop、Claude Code、Gemini CLI、Trae、Qoder、CodeBuddy 等国内外 IDE / 终端 AI CLI 均适用。

<details>
<summary><b>Claude Code CLI（推荐方式）</b></summary>

```bash
claude mcp add cheatengine -- python "C:/path/to/MCP_Server/mcp_cheatengine.py"
```

或项目级 `.mcp.json`（与下方相同的 `mcpServers` JSON 结构）。
</details>

<details>
<summary><b>Cursor IDE</b></summary>

`.cursor/mcp.json`：
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

`%APPDATA%\Claude\claude_desktop_config.json`：
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

`~/.codex/config.toml`：
```toml
[mcp_servers.cheatengine]
command = "python"
args = ['C:\path\to\MCP_Server\mcp_cheatengine.py']
```
</details>

<details>
<summary><b>Gemini CLI</b></summary>

`~/.gemini/settings.json`：
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
<summary><b>Trae / Qoder / CodeBuddy（国产 IDE）</b></summary>

均使用相同的 `mcpServers` JSON 格式：

- **Trae**：`~/.trae/mcp.json`（或在 MCP 面板 → 手动添加 → stdio 类型）
- **Qoder**：MCP 面板 → stdio 服务器，command 填 `python`，args 同上
- **CodeBuddy**：`~/.codebuddy/mcp.json`（与 Cursor 同结构）
</details>

<details>
<summary><b>Windsurf / Cline / 其他 JSON 客户端</b></summary>

与 Cursor 相同的 `mcpServers` JSON——只是配置文件位置不同
（Windsurf 为 `~/.codeium/windsurf/mcp_config.json`，VS Code 为 `settings.json` / Cline 面板等）。
</details>

<details>
<summary><b>远程 CE（另一台机器）</b></summary>

```json
{ "env": { "CE_HOST": "192.168.1.100", "CE_PORT": "17171" } }
```

CE 机器的防火墙：
```powershell
netsh advfirewall firewall add rule name="CE MCP" dir=in action=allow protocol=TCP localport=17171
```

DLL 默认只绑定 `127.0.0.1`。远程访问需在 CE 机器启动前设置环境变量 `CE_MCP_BIND=0.0.0.0`。
</details>

### 6. 验证

问 AI：*"Ping 一下 Cheat Engine"*

```json
{"success": true, "version": "15.8.2", "message": "CE MCP Bridge v15.8.0 alive"}
```

---

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `CE_HOST` | `127.0.0.1` | CE 机器 IP（远程调试） |
| `CE_PORT` | `17171` | TCP 端口（被占用时自动递增） |
| `CE_PORT_RANGE` | `10` | 从起始端口扫描的数量 |
| `CE_MCP_TIMEOUT` | `90` | 单工具超时（秒）。应低于 DLL 的 120 秒等待；`<=0` 关闭 |
| `CE_MCP_RETRIES` | `2` | 额外重试次数——**仅限连接失败**，绝不重试超时 |
| `CE_MCP_RETRY_DELAY` | `0.3` | 连接重试间隔（秒） |
| `CE_MCP_PROBE_TIMEOUT` | `3.0` | 「这真是 CE 桥吗」存活探测超时 |
| `CE_MCP_ALLOW_SHELL` | *(未设置)* | 设 `1` 启用 `run_command`/`shell_execute` |
| `CE_MCP_BIND` | `127.0.0.1` | DLL 监听绑定地址；远程调试需在 CE 启动前设 `0.0.0.0` |
| `CE_MCP_DEBUG_CONSOLE` | *(未设置)* | 设 `1` 显示 DLL 调试控制台（不抢焦点） |
| `CE_MCP_TOOLS` | `all` | **工具加载剖面**：`all` / `core`（别名 `minimal`）/ `core,memory,debug,...`——见[分层渐进式工具加载](#分层渐进式工具加载) |
| `CE_MCP_AUTH_TOKEN` | *(未设置)* | 共享令牌认证：两端设同值后，每个请求自动携带 `params._auth`，其余被桥以 `AUTH_REQUIRED` 拒绝 |

> **可能已执行过的命令绝不重试**。涵盖超时的命令与「请求帧已完整送达后」的任何失败——
> `write_memory`、`auto_assemble`、`inject_dll`、`execute_code` 可能已经生效，重放会把副作用
> 应用两次。只有帧未送达的失败（连接/发送失败）才允许重试。超时直接断开 socket。

---

## 分层渐进式工具加载

249 个工具连同完整 JSON Schema 放进一次 `tools/list`，每次会话启动都会消耗客户端大量上下文。
服务端因此按**层**加载工具：

- `CE_MCP_TOOLS=all` *（默认）*——全量注册，与旧版行为一致。
- `CE_MCP_TOOLS=core`（别名 `minimal`）——仅 16 个常驻工具：桥健康（`bridge_status`、`ping`、
  `dll_status`）、内存 IO 基础、`evaluate_lua`、batch/审计内省、模态框解困
  （`dialog_enum`/`dialog_dismiss`）以及 `ce_tools_manage`。
- `CE_MCP_TOOLS=core,memory,debug`——core 加上 18 个类别中任意若干。

运行时通过常驻的 **`ce_tools_manage`** 工具扩展工具面，无需重启：

```json
{"name": "ce_tools_manage", "arguments": {"action": "list"}}
{"name": "ce_tools_manage", "arguments": {"action": "enable", "categories": ["memory", "debug"]}}
```

`enable` 幂等；客户端支持时会收到 `notifications/tools/list_changed` 通知
（否则重新拉取工具列表或重连即可）。类别：`core`、`memory`、`scan`、`disasm`、`debug`、
`process`、`symbols`、`structures`、`table`、`aa`、`exec`、`dotnet`、`dissect`、`custom`、
`ui_input`、`system`、`kernel`、`net`。

---

## 可用工具（249 个注册工具 / 253 个调度方法）

Python 侧记录 **248** 个 `@mcp.tool()` 函数，外加 `ce_tools_manage` 元工具
（默认共 **249** 个注册）；Lua 调度器解析 **253** 个方法
（差值是别名，如 `read_bytes` → `read_memory`、`status` → `bridge_status`）。

| 类别 | 数量 | 示例 |
|------|------|------|
| **core**（常驻） | 16 | `bridge_status`, `ping`, `ct_preflight`, `evaluate_lua`, `batch_call`, `dialog_enum`, `ce_tools_manage` |
| **memory** | 22 | `read_memory`, `write_memory`, `read_pointer_chain`, `validate_pointer_chain`, `inject_preview`, `allocate_memory` |
| **scan** | 22 | `scan_all`, `aob_scan`, `aob_scan_unique`, `aob_health_scan`, `pointer_rescan`, `persistent_scan_*`, `generate_signature` |
| **disasm** | 9 | `disassemble`, `analyze_function`, `find_references`, `get_previous_opcode` |
| **debug** | 22 | `set_breakpoint`, `debug_get_context`, `debug_continue`, `start_dbvm_watch` |
| **process** | 16 | `get_process_list`, `pause_process`, `set_speed`, `queue_to_main_thread` |
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

> **batch 是快路径。** 1ms 主线程轮询 + 同时只有一条命令在途，往返延迟占主导。
> `batch_call(calls=[{method, params}, ...])` 单次往返跑最多 **64** 条命令，逐项返回结果数组。

### 推荐工作流

**指针追踪**

```json
// 1. 查谁访问该地址（从上下文拿寄存器值，如 RBX）
{"name": "set_breakpoint", "arguments": {"address": "0x255D5E758"}}
{"name": "debug_get_context", "arguments": {}}
// 2. 用该值做持久化扫描逐轮过滤，直到 game.exe+offset
{"name": "create_persistent_scan", ...}   // first_scan → next_scan → ...
// 或已有候选基址时直接指针重扫
{"name": "pointer_rescan", "arguments": {}}
```

**函数分析**

```json
{"name": "find_function_boundaries", "arguments": {"address": "0x14587EDB0"}}
{"name": "analyze_function", "arguments": {"address": "0x14587EDB0"}}
{"name": "generate_signature", "arguments": {"address": "0x14587EDB0"}}  // 游戏更新后的特征码
```

**CT 表流水线**

```json
{"name": "load_table", "arguments": {"path": "C:/tables/game.CT"}}
{"name": "get_address_list", "arguments": {}}
{"name": "set_memory_record_active", "arguments": {"id": 12, "active": true}}
```

完整参考：[`AI_Context/MCP_Bridge_Command_Reference.md`](AI_Context/MCP_Bridge_Command_Reference.md)

---

## 测试

两套测试**无需运行 Cheat Engine**，是验证改动的最快方式。
完整开发者参考（架构、线协议、并发模型、构建、扩展指南）见 **[DEV_GUIDE.md](DEV_GUIDE.md)**。

```bash
lua MCP_Server/test_bridge_lua.lua            # 离线 Lua 单元测试（任意 Lua 5.3+），无需 CE
python MCP_Server/test_bridge.py --self-test  # 离线 Python 客户端契约，无需 CE
python MCP_Server/probe_bridge.py --self-test # 离线线格式探针自检，无需 CE
```

CE 运行且桥已加载时的只读冒烟测试：

```bash
python MCP_Server/test_bridge.py              # 身份、调度 parity、batch、UTF-8、内存读
python MCP_Server/test_bridge.py --allow-write  # + 分配 / 写入 / 读回
```

当前状态：**221/0** Lua 单元断言、**38/0** Python 契约断言、**4/0** 探针自检。

---

## 故障排查

| 问题 | 解决 |
|------|------|
| `No module named 'mcp'` | 运行 `python -m pip install mcp`（见[安装](#2-安装-python-依赖)） |
| DLL 未找到 | 把 `ce_mcp_tcp_x64.dll` 复制到 CE 目录 |
| 无法连接 | 检查 `netstat -an \| findstr 17171`，核对 CE_HOST/CE_PORT |
| `error_code: BRIDGE_UNAVAILABLE` | 桥 DLL 未监听，或你的 Lua 脚本还是 v15 前的管道版 |
| `error_code: TIMEOUT` | 调大 `CE_MCP_TIMEOUT`；该命令按设计**不会**重试 |
| 非ASCII/中文 `write_string` 失败 | 15.1 前的 bug——在 CE 里重新加载当前版 `ce_mcp_bridge.lua` |
| "too many local variables" | 改用 `dofile(...)` 而不是粘贴整段脚本 |
| CE 界面卡住 | 正常——handler 在主线程执行以保证 API 安全 |
| 大量小命令很慢 | 用 `batch_call` 合并为一次往返 |
| CE 被模态框冻结 | 用 `dialog_enum` + `dialog_dismiss`——主线程阻塞时它们仍能应答 |

---

## 关键：防蓝屏

> **关闭** CE → 设置 → 额外 → **「查询内存区域例程」（Query memory region routines）**。开启状态下对 DBVM 页面做内存扫描会触发 `CLOCK_WATCHDOG_TIMEOUT` 蓝屏。

---

## 致谢

本项目是基于 [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge)
（作者 [@miscusi-peek](https://github.com/miscusi-peek)）的深度重构衍生版——Lua 桥基础、MCP 服务端
设计与原始工具集均源自该项目。原作者贡献者：[@libangli218](https://github.com/libangli218)、
[@lauralex](https://github.com/lauralex)、[@iamtyroon](https://github.com/iamtyroon)。

本版本以原生 C TCP DLL 取代命名管道传输，并将工具面扩展到 198 个。许可遵循相同条款——
见 [LICENSE](LICENSE)。

## 免责声明

仅供学习与研究用途。不得用于恶意破解、多人游戏作弊或违反服务条款的行为。
