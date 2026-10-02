**[English](README.md) | [中文](README_CN.md)**

# Cheat Engine MCP Bridge — 原生 TCP 版

[![Version](https://img.shields.io/badge/version-15.4.1-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org) [![Transport](https://img.shields.io/badge/transport-原生%20TCP%20DLL-orange.svg)](#) [![Tools](https://img.shields.io/badge/工具-198-brightgreen.svg)](#可用工具)

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

把与你 CE 位数匹配的 DLL 复制到 **CE 目录**：

```
C:\CE 7.5\cheatengine-x86_64.exe
C:\CE 7.5\ce_mcp_tcp_x64.dll    ← 放这里（32 位 CE 用 _x86.dll）
```

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
[MCP] DLL loaded OK from: C:\CE 7.5\ce_mcp_tcp_x64.dll
[MCP] Bridge v15.4.1 started on 127.0.0.1:17171 (native TCP, 1ms poll)
```

不会弹出任何窗口——DLL 调试控制台默认隐藏（`CE_MCP_DEBUG_CONSOLE=1` 可显示，且不抢焦点）。

### 5. 配置 AI 客户端

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
{"success": true, "version": "15.4.1", "message": "CE MCP Bridge v15.4.1 alive"}
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

> 超时的命令**绝不重试**：它可能已在 CE 内执行过（`write_memory`、`auto_assemble`、`inject_dll`、
> `execute_code`），重放会把副作用应用两次。超时直接断开 socket。

---

## 可用工具（198 个 MCP 工具 / 203 个调度方法）

Python 侧暴露 **198** 个 `@mcp.tool()` 函数；Lua 调度器解析 **203** 个方法
（差值是别名，如 `read_bytes` → `read_memory`、`status` → `bridge_status`）。

| 类别 | 示例 |
|------|------|
| **内存读写** | `read_memory`, `write_memory`, `read_integer`, `write_string`, `read_pointer_chain` |
| **扫描** | `scan_all`, `next_scan`, `aob_scan`, `aob_scan_module`, `search_string` |
| **反汇编与分析** | `disassemble`, `analyze_function`, `find_function_boundaries`, `find_references`, `find_call_references` |
| **代码注入** | `auto_assemble`, `inject_dll`, `execute_code`, `compile_c_code` |
| **断点与调试** | `set_breakpoint`, `set_data_breakpoint`, `start_dbvm_watch`, `get_breakpoint_hits` |
| **进程与模块** | `open_process`, `get_process_list`, `enum_modules`, `get_symbol_address` |
| **结构体** | `create_structure`, `dissect_structure`, `add_element_to_structure`, `get_rtti_classname` |
| **内存管理** | `allocate_memory`, `free_memory`, `get_memory_protection`, `get_memory_regions` |
| **CT 表** | `load_table`, `save_table`, `create_memory_record`, `set_memory_record_active`, `set_memory_record_address`, `set_memory_record_script`, `get_memory_record_children` |
| **GUI 与输入** | `find_window`, `is_key_pressed`, `get_pixel`, `show_message`, `speak_text` |
| **文件与系统** | `file_exists`, `md5_file`, `get_file_list`, `evaluate_lua` |
| **内核（DBK/DBVM）** | `dbk_get_cr3`, `get_physical_address`, `read_process_memory_cr3` |
| **桥控制** | `batch_call`, `bridge_status`, `list_bridge_methods`, `dll_status`, `dialog_enum`, `dialog_dismiss` |

> **batch 是快路径。** 1ms 主线程轮询 + 同时只有一条命令在途，往返延迟占主导。
> `batch_call(calls=[{method, params}, ...])` 单次往返跑最多 **64** 条命令，逐项返回结果数组。

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

当前状态：**163/0** Lua 单元断言、**27/0** Python 契约断言、**4/0** 探针自检。

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
