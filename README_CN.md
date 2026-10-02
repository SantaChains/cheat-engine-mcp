**[English](README.md) | [中文](README_CN.md)**

# Cheat Engine MCP Bridge — TCP 增强版

[![Version](https://img.shields.io/badge/version-15.4.1-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org) [![Transport](https://img.shields.io/badge/transport-原生%20TCP%20DLL-orange.svg)](#) [![Tools](https://img.shields.io/badge/工具-198-brightgreen.svg)](#可用工具)

> 始于 [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge) 的深度重构衍生版。用原生 C TCP 桥接替代命名管道，支持**远程 CE 控制**、**零 pywin32 依赖**和**多实例并行**。

[演示视频](https://github.com/user-attachments/assets/a184a006-f569-4b55-858a-ed80a7139035)

---

## 本项目 vs 原版 — 核心差异

### 架构对比

```
原版 (v12.0.0)                              本项目 (v15.4.1)
AI 客户端                                    AI 客户端
  │ stdio JSON-RPC                            │ stdio JSON-RPC
  ▼                                           ▼
mcp_cheatengine.py                          mcp_cheatengine.py
  │ 命名管道 (需 pywin32)                      │ TCP 套接字 (仅 stdlib)
  ▼                                           ▼
\\.\pipe\CE_MCP_Bridge_v99                  ce_mcp_tcp.dll (原生 C)
  │ Worker 线程 (Lua 管道 I/O)                 │ Winsock2 + select()
  ▼                                           ▼
ce_mcp_bridge.lua → 目标进程                 ce_mcp_bridge.lua → 目标进程
```

### 优缺点对比

| | 原版 (v12.0.0) | 本项目 (v15.4.1) |
|---|---|---|
| **传输方式** | 命名管道 | 原生 TCP (C DLL) |
| **远程 CE** | 需要 `ce_tcp_relay.py` 中继脚本 | 内置，`CE_HOST` 环境变量 |
| **Python 依赖** | `mcp` + `pywin32` | 仅 `mcp` |
| **多实例** | 不支持 | 端口自动递增 (17171–17181) |
| **超时** | 30 秒 | 90 秒，3 次重试 + 自动重连 |
| **调试控制台** | 无 | 独立 DLL 诊断窗口 |
| **Lua 代码** | ~6700 行 (含 FFI/Winsock/Pipe) | ~6600 行（移除 FFI，新增 batch/自省） |
| **CRT 依赖** | 无 | 静态 `/MT` 链接，无需 VC 运行库 |

| | 原版优势 | 本项目优势 |
|---|---|---|
| **简洁性** | 无 DLL，pip install 即可 | — |
| **本地安全** | 命名管道天然仅限本机 | — |
| **远程调试** | — | 原生 TCP，无需中继脚本 |
| **跨平台服务端** | — | TCP stdlib 跨平台可用 |
| **稳定性** | — | 无 FFI 崩溃、无 PEB 遍历失败 |
| **多实例** | — | 自动端口发现 |

> **安全提示**：TCP **无身份验证和加密**。仅在可信网络中使用。绝不将端口 17171 暴露到公网。

### 项目结构对比

```
原版                                        本项目
────                                       ────
MCP_Server/                                MCP_Server/
├── mcp_cheatengine.py  (pywin32 管道)      ├── mcp_cheatengine.py    (TCP stdlib, 198 工具)
├── ce_mcp_bridge.lua   (~6700 行)          ├── ce_mcp_bridge.lua     (~6600 行)
├── ce_tcp_relay.py     (TCP 中继)          ├── ce_mcp_tcp_x64.dll    ← 新增：原生 DLL
├── test_mcp.py                            ├── ce_mcp_tcp_x86.dll    ← 新增：原生 DLL
└── requirements.txt    (mcp + pywin32)    ├── test_bridge_lua.lua   ← 新增：离线 Lua 测试
                                           ├── test_bridge.py        ← 新增：客户端契约/冒烟
                                           └── requirements.txt      (仅 mcp)
AI_Context/             (文档)
                                           NativeBridge/             ← 新增：DLL 源码
                                           ├── ce_mcp_tcp.c          (770 行 C 代码)
                                           ├── build.bat
                                           └── bin/{x64,x86}/

                                           AI_Context/               (文档)
```

关键结构差异：
- **移除**：`ce_tcp_relay.py` — TCP 已原生支持，无需中继
- **移除**：requirements 中的 `pywin32` — TCP 使用 Python 标准库
- **新增**：`NativeBridge/` — 编译的 C DLL 源码和构建系统
- **新增**：`MCP_Server/` 中的预编译 DLL，方便部署
- **新增**：离线 + 在线测试工具（`test_bridge_lua.lua`、`test_bridge.py`）
- **重构**：Lua 桥接 — 移除废弃 FFI/管道代码，并新增 `batch`、`status`/`list_methods`
  自省能力与集中式错误码推断

---

## 安装配置

### 1. 克隆仓库

```bash
git clone https://github.com/HollyZoe/cheatengine-mcp-tcp-bridge.git
cd cheatengine-mcp-tcp-bridge
```

### 2. 安装 Python 依赖

**前置要求**：Python 3.10+（[下载](https://python.org/downloads/)）

MCP 服务器需要 `mcp` Python 包（Model Context Protocol SDK）。这**不是 Python 内置模块**，必须手动安装：

```bash
pip install -r MCP_Server/requirements.txt
```

或直接安装：
```bash
pip install mcp
```

> 如果你有多个 Python 版本，使用 `python -m pip install mcp` 确保安装到正确的环境。

**验证安装是否成功**：
```bash
python -c "from mcp.server.fastmcp import FastMCP; print('OK')"
```

如果出现 `ModuleNotFoundError: No module named 'mcp'`，说明安装失败，检查：
- 你使用的 `python` 是否与 Cursor/AI 客户端使用的是同一个
- 尝试 `python -m pip install mcp` 而非 `pip install mcp`
- Windows 上 pip 可能提示脚本不在 PATH 中 — 这没关系，Cursor 直接通过 `python` 命令启动服务器

> **注意**：TCP 传输模式**不需要** `pywin32`。旧版命名管道传输及其 `pywin32` 依赖已在 v15.2.1 移除。

### 3. 放置 DLL

将 `ce_mcp_tcp_x64.dll`（32 位 CE 用 `_x86.dll`）复制到 **CE 可执行文件目录**：

```
C:\CE 7.5\cheatengine-x86_64.exe
C:\CE 7.5\ce_mcp_tcp_x64.dll    ← 放这里
```

DLL 来源：`MCP_Server/` 或 `NativeBridge/bin/`

### 4. 在 CE 中加载

1. 将 CE 附加到目标进程
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
<summary><b>远程 CE</b></summary>

```json
{ "env": { "CE_HOST": "192.168.1.100", "CE_PORT": "17171" } }
```

CE 机器防火墙：
```powershell
netsh advfirewall firewall add rule name="CE MCP" dir=in action=allow protocol=TCP localport=17171
```
</details>

### 6. 验证

对 AI 说：*"Ping 一下 Cheat Engine"*

```json
{"success": true, "version": "15.4.1", "message": "CE MCP Bridge v15.4.1 alive"}
```

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CE_HOST` | `127.0.0.1` | CE 机器 IP（远程调试） |
| `CE_PORT` | `17171` | TCP 端口（占用时自动递增） |
| `CE_PORT_RANGE` | `10` | 从基础端口扫描的范围 |
| `CE_MCP_TIMEOUT` | `90` | 每个工具超时（秒）。需低于 DLL 的 120 秒等待；`<=0` 表示禁用 |
| `CE_MCP_RETRIES` | `2` | 额外重试次数 — **仅连接失败**，绝不重试超时 |
| `CE_MCP_RETRY_DELAY` | `0.3` | 连接重试间隔（秒） |
| `CE_MCP_PROBE_TIMEOUT` | `3.0` | "对方是否真是 CE 桥接"的存活探测超时 |
| `CE_MCP_ALLOW_SHELL` | *(未设置)* | 设为 `1` 启用 `run_command`/`shell_execute` |
| `CE_MCP_BIND` | *(未设置)* | DLL v3.3.0+：监听绑定地址，默认 `127.0.0.1`（仅回环）。需远程调试时在启动 CE 前设为 `0.0.0.0` |

> 超时的命令**绝不重试**：它可能已在 CE 内执行完毕（`write_memory`、`auto_assemble`、
> `inject_dll`、`execute_code`），重放会导致副作用执行两次。超时后改为关闭套接字。

---

## 可用工具（198 个 MCP 工具 / 203 个调度方法）

Python 侧暴露 **198** 个 `@mcp.tool()` 函数；Lua 调度器解析 **203** 个方法
（差额为别名，如 `read_bytes` → `read_memory`、`status` → `bridge_status`）。

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
| **作弊表** | `load_table`, `save_table`, `create_memory_record`, `set_memory_record_active`, `set_memory_record_address`, `set_memory_record_script`, `get_memory_record_children` |
| **GUI 与输入** | `find_window`, `is_key_pressed`, `get_pixel`, `show_message`, `speak_text` |
| **文件与系统** | `file_exists`, `md5_file`, `get_file_list`, `evaluate_lua` |
| **内核 (DBK/DBVM)** | `dbk_get_cr3`, `get_physical_address`, `read_process_memory_cr3` |
| **桥接控制** | `batch_call`, `bridge_status`, `list_bridge_methods` |

> **批处理是快车道。** 主线程 1ms 轮询、同一时刻只跑一条命令，往返开销才是延迟大头。
> `batch_call(calls=[{method, params}, ...])` 可在一次往返中执行最多 **64** 条命令，并返回逐项结果数组。

完整参考：[`AI_Context/MCP_Bridge_Command_Reference.md`](AI_Context/MCP_Bridge_Command_Reference.md)

---

## 测试

两套测试工具**无需运行 Cheat Engine** 即可执行，是验证改动最快的方式。完整开发者参考（架构、线协议、并发模型、构建、扩展指南）见 **[DEV_GUIDE.md](DEV_GUIDE.md)**：

```bash
lua MCP_Server/test_bridge_lua.lua            # 离线 Lua 单元测试（任意 Lua 5.3+），无需 CE
python MCP_Server/test_bridge.py --self-test  # 离线 Python 客户端契约测试，无需 CE
python MCP_Server/probe_bridge.py --self-test # 离线线级探针自检，无需 CE
```

CE 运行且桥接已加载后，可做只读冒烟测试：

```bash
python MCP_Server/test_bridge.py              # 身份、调度一致性、batch、UTF-8、内存读取
python MCP_Server/test_bridge.py --allow-write  # 追加 allocate / write / 回读
```

| 文件 | 需要 CE？ | 用途 |
|------|-----------|------|
| `test_bridge_lua.lua` | 否 | JSON 编解码、`toHex`、`paginate`、错误码推断、`batch`、`status`、记忆条目操作（stub AddressList）、`evaluate_lua`、UTF-8/CJK 矩阵、守卫路径 |
| `test_bridge.py --self-test` | 否 | UTF-8 保真、超时不重试、连接错误、JSON-RPC 解包、超长请求守卫 |
| `probe_bridge.py --self-test` | 否 | 探针自身的帧处理/重连逻辑（对照模拟 `ce_mcp_tcp.c` 语义的进程内 stub） |
| `test_bridge.py` | 是 | 在线只读冒烟测试 |
| `probe_bridge.py` | 是 | 在线只读**帧格式矩阵**（13 项实验）：信封形状、id 回显、`-32601`/`-32700` 路径、尾换行容忍、CJK 与大载荷往返、管线化、恶意帧断连、滥用后恢复 |

废弃的 `test_mcp.py`（v15 之前命名管道协议）已删除；git 历史中仍可找回。

当前状态：Lua 单元断言 **130/0**，Python 契约断言 **27/0**，探针自检 **4/0**。

### 历史人工测试结果（v15 之前的接口，目标：Windows 10 上的 Notepad.exe）

| 结果 | 数量 |
|------|------|
| 通过 | **110+** |
| 测试中修复 | **3** (get_memory_protection, get_memory_regions, debug_get_current_debugger_interface) |
| CE 环境限制 | **5** (compile_c_code, compile_cs_code, load_new_symbols, pointer_rescan, inject_dotnet_dll) |
| 需要内核驱动 | **约 20**（已跳过 — 需签名驱动/DBVM） |

---

## 故障排除

| 问题 | 解决方案 |
|------|---------|
| `No module named 'mcp'` | 运行 `python -m pip install mcp`（参见[安装步骤](#2-安装-python-依赖)） |
| DLL 未找到 | 将 `ce_mcp_tcp_x64.dll` 复制到 CE 目录 |
| 无法连接 | 检查 `netstat -an \| findstr 17171`，确认 CE_HOST/CE_PORT |
| `error_code: BRIDGE_UNAVAILABLE` | 桥接 DLL 未监听，或 Lua 脚本仍是 v15 之前的管道版本 |
| `error_code: TIMEOUT` | 增大 `CE_MCP_TIMEOUT`；该命令按设计**不会**重试 |
| 非 ASCII / 中文 `write_string` 失败 | v15.1 之前的缺陷 — 在 CE 中重新加载当前 `ce_mcp_bridge.lua` |
| "too many local variables" | 用 `dofile(...)` 替代粘贴脚本 |
| 高负载操作超时 | 增大 `CE_MCP_TIMEOUT` |
| CE UI 卡顿 | 正常现象 — 处理器在主线程运行以保证 API 安全 |
| 大量小调用很慢 | 用 `batch_call` 合并为一次往返 |

---

## 重要：防止蓝屏

> **必须禁用** CE → Settings → Extra → **"Query memory region routines"**。启用时扫描 DBVM 保护页面会触发 `CLOCK_WATCHDOG_TIMEOUT` 蓝屏。

---

## 致谢

基于 [miscusi-peek/cheatengine-mcp-bridge](https://github.com/miscusi-peek/cheatengine-mcp-bridge) 的深度重构衍生版，原作者 [@miscusi-peek](https://github.com/miscusi-peek)。贡献者：[@libangli218](https://github.com/libangli218)、[@lauralex](https://github.com/lauralex)、[@iamtyroon](https://github.com/iamtyroon)。

## 免责声明

仅用于教育和研究目的。请勿用于恶意攻击、多人游戏作弊或违反服务条款。
