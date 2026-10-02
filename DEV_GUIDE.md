# DEV_GUIDE — cheatengine-mcp-tcp-bridge 开发者指南

> 面向维护者与二次开发者。版本基线：Lua bridge **v15.6.0** / Native DLL **v3.3.4**。
> 所有数字（上限、端口、超时）均为代码中的真实常量，非建议值。

---

## 1. 系统架构

```
┌─────────────────────────────────────────────────────────────────────┐
│ AI Host (Claude / 任意 MCP 客户端)                                    │
└──────────────┬──────────────────────────────────────────────────────┘
               │ MCP: JSON-RPC 2.0 over stdio
┌──────────────▼──────────────────────────────────────────────────────┐
│ mcp_cheatengine.py — FastMCP Server，195 个 @mcp.tool()              │
│  · 薄包装层：每个 tool = 参数校验(docstring 契约) → call() → format_result │
│  · call() 永不抛异常：异常归一为 {success:false, error_code}           │
│  · Windows CRLF monkey-patch（必须在 import FastMCP 前打）             │
└──────────────┬──────────────────────────────────────────────────────┘
               │ TCP: 4B LE 长度前缀 + UTF-8 JSON-RPC 2.0（见 §2）
┌──────────────▼──────────────────────────────────────────────────────┐
│ ce_mcp_tcp_{x64,x86}.dll v3.3.0 — 导出 luaopen_ce_mcp_tcp（Lua C 扩展）│
│  · Winsock2 / 静态 CRT(/MT)，无外部依赖                                │
│  · 每 client 一条 socket 线程（接收 + 组帧 + 派发排队）                  │
│  · 对 Lua 暴露 5 个 C 函数（见 §4）                                    │
└──────────────┬──────────────────────────────────────────────────────┘
               │ 进程内 C 函数调用（非 socket，同属 CE 进程）
┌──────────────▼──────────────────────────────────────────────────────┐
│ ce_mcp_bridge.lua v15.6.0 — 运行在 CE 主线程                          │
│  · 1ms CreateTimer 轮询 mcp_tcp_poll()，每 tick drain 一条待处理命令     │
│  · executeCommand() → commandHandlers[method] 直查（无 MCP 握手层）    │
│  · 194 个 cmd_* handler + 203 个注册方法名（含别名）               │
└──────────────┬──────────────────────────────────────────────────────┘
               │ CE Lua API（readMemory / AOBScan / debugger / DBVM …）
┌──────────────▼──────────────────────────────────────────────────────┐
│ 目标进程内存 / CE 表 / 内核接口                                        │
└─────────────────────────────────────────────────────────────────────┘
```

**核心设计不变量**

| 不变量 | 原因 |
|---|---|
| 所有 CE Lua API 调用都在 CE 主线程执行 | CE Lua 解释器非线程安全；DLL 只做字节搬运 |
| 每 tick 只 drain 一条命令 | 单命令长耗时（如全内存扫描）不会饿死 CE GUI |
| `method` 即命令名，直查哈希表 | 无 MCP handshake / initialize 层；信封只是 JSON-RPC 形状 |
| 请求-响应严格锁步（lock-step） | 长度前缀流式协议下，迟到帧会导致后续响应错位（desync） |

---

## 2. 线协议规范（Wire Protocol）

### 2.1 帧格式（Framing）

```
┌──────────────┬─────────────────────────────┐
│ u32 LE nBytes│ UTF-8 JSON body（nBytes 字节）│
└──────────────┴─────────────────────────────┘
```

- 长度前缀 **4 字节小端**，不含自身 4 字节。与 gRPC 的 5B 前缀同族（gRPC 多 1B 压缩标志）。
- 客户端请求体上限 **4 MiB**（`MAX_REQUEST_SIZE_BYTES`，对齐 DLL 的 `MAX_CMD_SIZE`）。
- DLL 侧 `len == 0` 或 `len > 4 MiB` → **立即断连**（无法重新同步，长度前缀流没有重同步机制）。
- 响应体客户端上限 **32 MiB**（`MAX_RESPONSE_SIZE_BYTES`）。
- 无压缩、无心跳；连接复用，可管线化发送但响应仍逐条返回。

### 2.2 信封三形态（Envelope Semantics）

**① 正常路径**（Lua 层产生）：
```json
→ {"jsonrpc":"2.0","method":"ping","params":{},"id":7}
← {"jsonrpc":"2.0","id":7,"result":{"success":true,"message":"..."}}
```
`id` 原样回显；`result` 恒为扁平对象，`success` 布尔字段是业务级状态。

**② 解析/路由错误**（DLL 层产生）：
```json
← {"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}
← {"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"method not found"}}
```

**③ DLL 超时**（v3.2.0 语义）：
```json
← {"error":"timeout: no response from Lua within 120 s"}
```
发出该帧后 **DLL 主动断连**——防止 Lua 迟到 121s 的真实响应串扰（cross-talk）到下一条命令。

### 2.3 客户端超时契约（防双重执行）

`BaseBridgeClient._exchange_with_timeout`（默认 90s，`CE_MCP_TIMEOUT`）超时后 **必须 `close()`**，且 **TimeoutError 永不重试**：
- 命令可能已在 CE 内生效（`write_memory` / `auto_assemble` / `inject_dll`）；
- 重试 = 二次副作用；
- 不 close = 迟到帧污染连接。
重试策略（`CE_MAX_RETRIES=2`）只作用于连接建立失败，延迟 `CE_MCP_RETRY_DELAY=0.3s`。

超时后 `TCPBridgeClient._diagnose_after_timeout()` 会做一次 best-effort 探测（≤3.5s）并区分三种成因，追加到 TimeoutError 消息：
- 端口拒绝连接 → CE/桥已死（崩溃、退出或重载中）；
- TCP 可连但 ping 无响应 → CE 主线程被阻塞（模态框 / inputQuery / 长命令）——Lua 定时器在主线程阻塞期间根本不会触发，桥无法应答；
- 新 ping 正常应答 → 原命令只是超预算，应调大 `CE_MCP_TIMEOUT`。

---

## 3. Lua 侧编解码契约（Codec Contract）

手写 JSON 编解码器（CE 沙箱无 cjson），位于 `ce_mcp_bridge.lua` 的 `json` 模块。

| 规则 | 行为 |
|---|---|
| 编码深度护栏 | `ENCODE_MAX_DEPTH = 200`，超出报确定性错误 `"nesting depth exceeded 200"`（根因：无护栏时栈溢出位置随机，错误行号不可信） |
| 解码深度护栏 | `DECODE_MAX_DEPTH = 200`，同上 |
| 数组判定 | 稠密 `[1..n]`（`n==0 or next(t,n)==nil`）→ JSON array；其余 → JSON object |
| 混合表 | `{[1]="a", extra="b"}` → object（`{"1":"a","extra":"b"}`），**零丢失** |
| 稀疏数组 | `{[1]="a",[3]="c"}` → object，洞项保留 |
| 空表 | → `[]` |
| 循环引用 | 编码报错（`circular`），由 pcall 兜底 |
| int64 | 原样输出十进制（Lua 5.3 整数子类型），不做 float 舍入 |
| UTF-8 | 双向原样透传；解码支持 `\uXXXX`（含 BMP）、代理对合成 4 字节序列 |
| 非法 UTF-8 | 客户端 `_decode_json_body` 用 `errors='replace'` 降级，不让单个坏字节炸掉整个工具调用 |

**分页钳制**（v15.2.1）：所有 offset/limit 入口统一走 `clampPaging(params, defaultLimit, maxLimit)`：
- `limit` 下界 1、上界 `maxLimit or 10000`；`max` 是 `limit` 的向后兼容别名；
- `offset` 下界 0；
- 非数值参数（如字符串 `"abc"`）回落默认值，**不允许 mid-handler 抛错**；
- 0 基 CE 集合（FoundList / addresslist）用 `clampPaging` 手动索引；1 基 Lua 表用 `paginate(params, items, defaultLimit)` 切片。

---

## 4. 并发与线程模型

### 4.1 DLL（ce_mcp_tcp.c）

```
socket 线程（每 client 一条）          CE 主线程
─────────────────────────           ─────────────
recv → 组帧 → 入队 → SetEvent   →    1ms timer → mcp_tcp_poll() 取一条
                                     → Lua handler 执行
mcp_tcp_respond(result)  ←──────────  （写回持 CS）
（CS 保护共享状态；事件驱动唤醒）
```

关键修复（v3.2.0，均为并发缺陷）：
1. **超时串扰**：处理器超时后发错误帧并断连，socket 线程不再把迟到响应写给下一条命令。
2. **malloc 失败路径**：`mcp_tcp_respond` 分配失败返回 `ok:0` 并 `SetEvent` 唤醒，不悬挂主线程。
3. **stop UB**：`mcp_tcp_stop` 等待线程退出至多 10s；线程未退出则**跳过** `DeleteCriticalSection`（删除仍被持有的 CS 是未定义行为）。

### 4.2 Python 客户端锁序

`_io_lock`（串行化在途请求）→ `_conn_lock`（保护 connect/close，RLock）。全代码库锁序一致，无死锁环。

### 4.3 超时层级（必须满足的偏序）

```
CE_MCP_TIMEOUT (客户端 90s，默认) < DLL 处理器等待 (120s)
```
反过来会导致：DLL 已报超时断连，Python 还在等 → 客户端挂死 90s 才报错。

---

## 5. 错误码字典

**Lua handler 产生**（`result.error_code`）：

| 错误码 | 语义 |
|---|---|
| `INVALID_PARAMS` | 参数缺失/类型错误/预校验失败（**零副作用**保证：先验后改） |
| `INVALID_ADDRESS` | 地址解析失败（非十六进制、未映射） |
| `NOT_FOUND` | 目标资源不存在（memoryrecord / breakpoint / symbol） |
| `NO_PROCESS` | 未附加进程但有进程前置的操作 |
| `METHOD_NOT_FOUND` | 注册表无此方法名 |
| `PARSE_ERROR` | 请求体 JSON 解析失败 |
| `CE_API_ERROR` | CE Lua API 调用返回失败（pcall 捕获） |
| `CE_API_UNAVAILABLE` | 依赖的 CE 全局函数不存在（版本差异） |
| `DBK_NOT_LOADED` | DBK 内核驱动未加载 |
| `PERMISSION_DENIED` | 内核操作权限不足 |
| `OUT_OF_RESOURCES` | 硬件断点槽耗尽等资源分配失败 |
| `SCAN_ERROR` | 扫描引擎错误 |
| `UNKNOWN_SIG_TOKEN` | sig_tokens.txt 中缺少 pattern 占位 token |
| `PARTIAL_FAILURE` | 批量/多点操作部分成功 |
| `INTERNAL_ERROR` | 未预期异常（pcall 兜底），message 含原始错误 |
| `SCRIPT_TOO_LARGE` | AA 脚本超过 64 KiB 门禁（装配级校验大脚本会冻结主线程） |
| `NO_MATCH` | script patch：find 文本不在 Script 中 |
| `AMBIGUOUS_MATCH` | script patch：find 多处命中且未传 all=true（fail-safe） |
| `NO_SCRIPT` | 目标 memoryrecord 无可读 Script |
| `NO_HISTORY` | script undo：该条目撤销环为空 |
| `PROTECTED_WINDOW` | dll_dismiss_dialog：目标类为 TMainForm/TApplication（需 force=true） |
| `INVALID_TARGET` | dll_dismiss_dialog：hwnd 不属于本进程 / index 越界 |
| `UNKNOWN_METHOD` | dll_ 前缀方法未注册于快速通道 |

**Python 客户端产生**：

| 错误码 | 语义 |
|---|---|
| `TIMEOUT` | `CE_MCP_TIMEOUT` 到期，连接已关闭，命令状态未知（可能已执行） |
| `BRIDGE_UNAVAILABLE` | 连接失败/端口扫描未命中（重试后） |
| `RPC_ERROR` | 服务端 error 帧（code 取 data.error_code） |
| `CLIENT_ERROR` | 其余本地异常 |
| `INTERNAL_ERROR` | 响应载荷形状异常 |

---

## 6. 资源上限表（Resource Caps）

所有调用方可控的 limit/size/depth 必须在 handler 内钳制（防恶意/失误参数耗尽资源）：

| 资源 | 常量 | 值 |
|---|---|---|
| JSON 编码深度 | `ENCODE_MAX_DEPTH` | 200 |
| JSON 解码深度 | `DECODE_MAX_DEPTH` | 200 |
| batch 子命令数 | `BATCH_MAX_CALLS` | 64 |
| 断点命中历史 | `MAX_HITS_PER_BREAKPOINT` | 500 / 断点（环形淘汰最旧） |
| 子树遍历节点预算 | `MAX_CHILD_NODES` | 5000（超出 `truncated=true`） |
| children 分页上限 | clampPaging maxLimit | 1000 |
| 分页通用上限 | clampPaging 默认 maxLimit | 10000 |
| read_memory 单次 | — | 1 MiB |
| execute_code 写入 | — | 64 KiB |
| 栈捕获深度 | captureStack | min(depth, 128) |
| CR3 物理内存读 | — | 4 MiB |
| map_memory | — | 16 MiB |
| 枚举窗口数 | `MAX_DIALOGS` | 64，超出截断 |
| Lua 活性阈值 | `LUA_RESPONSIVE_THRESHOLD_MS` | 5000 ms，poll_age 超此值即 lua_responsive=false |
| AA 脚本体量 | `AA_MAX_SCRIPT_SIZE` | 64 KiB，超限拒绝（`SCRIPT_TOO_LARGE`） |
| evaluate print 捕获 | `MAX_PRINTED_LINES` | 200 行，超出 `printed_truncated=true` |
| 审计环形缓冲 | `MAX_AUDIT_ENTRIES` | 200 条，淘汰最旧 |
| 磁盘表 FNV 哈希 | `FNV_MAX_HASH_BYTES` | 32 MiB，超出 `hash_truncated=true`（纯 Lua 逐字节哈希跑在主线程，防大表冻结 UI） |
| 请求体（客户端→DLL） | `MAX_CMD_SIZE` | 4 MiB，超限断连 |
| 响应体（客户端校验） | `MAX_RESPONSE_SIZE_BYTES` | 32 MiB |

---

### 6.1 审计轨（v15.3.0）

**外部看门狗**（`MCP_Server/watchdog.py`，进程外监控，与桥解耦）：轮询探针区分三态——`UP`（ping 应答）/`BLOCKED`（TCP 通但 ping 超时 → 主线程被模态框/长命令阻塞）/`DOWN`（无监听 → CE 已死）；`--restart-ce` 在 DOWN 持续 `--down-budget` 秒后自动拉起 CE（可带 `--table` 载表）。退出码 1 = DOWN 持续至放弃，供外部编排。

`executeCommand` 与 `cmd_batch` 在结果落定后统一过 `auditLogEntry`：凡方法名命中 `AUDIT_MUTATING_PREFIXES`（write_/set_/create_/delete_/execute_/inject_/load_table/save_table/register_/auto_assemble/compile_/map_memory/... 共 27 个前缀）即写入 `serverState.auditLog`（时间戳、方法、success、error_code、紧凑参数摘要——长值折叠为 `<NB>` 字节数，脚本永不入账）。
读取走 `get_audit_log`（offset/limit 分页，newest first，`clear=true` 读后清空）。只读探针不入账。审计随脚本重载清零；需要持久化就在会话结束前 `get_audit_log` 落盘。

## 6.2 DLL 快速通道（v3.3.0，C 层旁路）

CE 在主线程执行一切 Lua；模态框（messageDialog/inputQuery）冻结主线程时，Lua 定时器停摆、队列无人 drain、所有排队命令从外部看全是超时。DLL 的 TCP 工作线程独立于主线程——因此 `dll_` 前缀方法在**收帧后、入队前**被工作线程拦截并就地应答（解析参数、执行、回帧，全程不碰 Lua 队列）：

- `dll_ping`：恒可用健康探针；
- `dll_status`：帧/字节计数、last_method、`poll_age_ms`（主线程上次调 mcp_tcp_poll 距今毫秒数，Lua 定时器每 1ms 打一次心跳——poll_age 大即主线程被阻塞或正跑长命令，lua_responsive 按阈值 5s 判定）；
- `dll_enum_dialogs`：EnumWindowsW 枚举本进程可见顶层窗口（UTF-16→UTF-8 标题，排除调试控制台），模态检测；
- `dll_dismiss_dialog`：按 index/hwnd/标题子串定位并 PostMessageW(WM_CLOSE)；TMainForm/TApplication 类保护（force=true 覆盖）；仅限本进程窗口。hwnd 解析用 64 位整数（`_atoi64`），按「截断 32 位 + 符号扩展」重建 HWND——USER 句柄是符号扩展的 32 位值，纯 32 位 `atoi` 在高位句柄上会 UB 溢出。

v3.3.1 修复：① hwnd 64 位往返（见上）；② `mcp_tcp_stop` 从 Lua 线程关闭 client_sock 后，服务器线程断连路径不再二次 `closesocket` 同一句柄（句柄复用风险 → 仅当槽内仍是该句柄才关闭）。
v3.3.2 修复：③ DllMain 加载器锁纪律——`AllocConsole` 从 DLL_PROCESS_ATTACH 延迟到首次 `dbg_log`（MS DLL Best Practices：DllMain 应最小化，懒初始化零成本合规）；④ x86 构建加 `/guard:cf`（CFG，Control Flow Guard）——MSVC 默认只给 ASLR/DEP，CFG 需显式开启；三模式 build.bat 均已显式化加固标志（MinGW：`-Wl,--dynamicbase --nxcompat --high-entropy-va`，版本无关）。详见 dev.md Part II §C2/§C6。

v3.3.3 修复（输入解析 UB 收尾）：① `json_extract_int` 改用 `strtol`（atoi 越界输入是 UB，恶意客户端发超大数字可触发）；② `json_extract_i64` 改用 `_strtoi64`（越界时钳位到 LLONG_MIN/MAX 并置 ERANGE，`_atoi64` 同为 UB）；③ `strcpy(dl->buf,"[")` → 直接赋值 `dl->buf[0]='['`（字面风格收敛）。

v3.3.4 修复（调试控制台抢前台）：`AllocConsole` 创建的 conhost 窗口会抢占前台焦点，阻塞与 CE 主窗口的交互（用户实测报告）。现默认 `ShowWindow(SW_HIDE)` 隐藏控制台——`WriteConsoleA` 对隐藏窗口照常缓冲写入，日志文本不丢失；设环境变量 `CE_MCP_DEBUG_CONSOLE=1` 可在加载时以 `SW_SHOWNOACTIVATE`（不夺焦）显示。运行时验证注意：控制台隐藏后日志仍在缓冲中，attach 该 conhost 或设环境变量重启可见。

约束：连接是 lock-step 单事务——若前一条 Lua 命令还在等 120s 预算，下一条帧（含 dll_*）要等它结束；客户端超时断开后重连，dll_* 即可用。dll_* 走与传统命令相同的 4B LE 帧 + JSON-RPC 信封（id 回显）。Python 侧对应 `dll_status`/`dialog_enum`/`dialog_dismiss` 三个 MCP 工具。

## 7. 配置（环境变量）

| 变量 | 默认 | 语义 |
|---|---|---|
| `CE_HOST` | `127.0.0.1` | 桥地址 |
| `CE_PORT` | `17171` | 基准端口（DLL 绑定第一个空闲端口） |
| `CE_PORT_RANGE` | `10` | 客户端向上扫描的端口数（ping 探测防误连） |
| `CE_MCP_TIMEOUT` | `90` | 客户端单命令秒数；`<=0` 禁用超时（危险：DLL 120s 仍会断） |
| `CE_MCP_RETRIES` | `2` | 连接失败重试次数（**不含**超时） |
| `CE_MCP_RETRY_DELAY` | `0.3` | 重试间隔秒 |
| `CE_MCP_PROBE_TIMEOUT` | `3.0` | ping 身份握手超时秒 |
| `CE_MCP_BIND` | `127.0.0.1` | DLL 监听地址；`0.0.0.0` 才能远程调试（自担风险） |

---

## 8. 构建指南（Native DLL）

**x64 首选 MinGW**（一条命令、零环境变量、产物 28KB vs MSVC /MT 154KB；依赖仅系统自带 UCRT，
无 libgcc/libwinpthread 拖挂）。**x86 只能 MSVC**（本机无 i686 MinGW 工具链）。

```bat
cd NativeBridge
build.bat          REM x64 Release via MinGW gcc → bin\x64\ce_mcp_tcp_x64.dll
build.bat msvc     REM x64 Release via MSVC /MT（静态 CRT，备用）
build.bat x86      REM x86 Release via MSVC（MinGW 无 i686 目标）
```

MinGW 等价单命令（Git Bash 直跑，已实测 gcc 16.2.0 x86_64-ucrt-posix-seh）：

```bash
gcc -shared -O2 -s -static \
  -D WIN32 -D NDEBUG -D _WINDOWS -D _USRDLL \
  -D _CRT_SECURE_NO_WARNINGS -D _WINSOCK_DEPRECATED_NO_WARNINGS \
  ce_mcp_tcp.c -o bin/x64/ce_mcp_tcp_x64.dll -lws2_32 -luser32 -lkernel32
```

MSVC 路线（VS Build Tools，静态 CRT `/MT`）：

```bash
export INCLUDE="<MSVC include (Windows 盘符格式!) >;<SDK ucrt/shared/um/winrt>"
export LIB="<MSVC lib/x64>;<SDK ucrt/x64>;<SDK um/x64>"
MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 \
  "cl.exe全路径" /nologo /O2 /LD /W3 /MT /D WIN32 /D NDEBUG /D _WINDOWS /D _USRDLL \
  /D _CRT_SECURE_NO_WARNINGS /D _WINSOCK_DEPRECATED_NO_WARNINGS \
  ce_mcp_tcp.c ws2_32.lib kernel32.lib user32.lib \
  /Fe:bin/x64/ce_mcp_tcp_x64.dll /Fo:bin/x64/ /link /DLL /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF
```

MSVC 沙箱坑（实测）：INCLUDE/LIB 里的 MSVC 路径必须是 Windows 盘符格式（`D:/...`），
写成 MSYS 的 `/d/...` 会报 `excpt.h` 找不到；且本沙箱曾出现 cl.exe 静默失败（无输出无产物），
每次构建后必须核对产物 mtime。

MinGW 产物验收：`objdump -p <dll> | grep "DLL Name"` —— 只允许 KERNEL32/WS2_32/api-ms-win-crt-*；
出现 libgcc / libwinpthread 即漏了 `-static`。

产物校验（缺一不可）：
1. PE machine：x64 = `0x8664`，x86 = `0x014C`；
2. `MCP_Server/` 与 `NativeBridge/bin/<arch>/` 两份副本 md5 一致；
3. 源码 mtime 早于产物 mtime（防忘了重编）。

**DLL 与 Lua 的耦合面**只有 5 个 C 函数签名 + 线协议，无 ABI 耦合——改 Lua/Python 不需要重编 DLL。

部署：DLL 放到 CE 的 `plugins\` 目录（标准插件路径，v15.4.2 起桥会自动搜索 `<CE目录>\plugins\`）或 CE 根目录——两处都会被 `tryLoadNativeDLL` 按序尝试；CE 执行该 Lua 即自动启动（`MCP_BRIDGE_NO_AUTOSTART=true` 可只加载不启动，供控制台调试）。

---

## 9. 测试体系

| 套件 | 命令 | 覆盖 | 当前 |
|---|---|---|---|
| Lua 单测 | `lua MCP_Server/test_bridge_lua.lua` | 纯 Lua 核心：编解码矩阵、分页钳制、batch 执行器、UNIT-26 memoryrecord mock、UTF-8/CJK、深度/循环/稀疏表回归 | 139/0 |
| Python 契约 | `.venv/Scripts/python.exe test_bridge.py --self-test` | TCP 客户端契约：组帧、UTF-8 保真、超时语义（不重试）、失步防护、端口扫描、错误解包（in-process stub server，无需 CE） | 27/0 |
| 线协议探针 | `python probe_bridge.py --self-test` | 信封三形态、id 回显、坏 JSON、CJK 过线（镜像 DLL 语义的 stub）；`--host` 模式可打真桥做 13 项帧矩阵实验 | 4/0 |
| 语法门 | `luac -p ce_mcp_bridge.lua` + `py_compile` | 加载期正确性 | OK |

**新增回归的固定套路**：
- Lua mock CE 对象时注意调用约定——handler 用**点号**调 CE 集合方法（`fl.getAddress(i)`），mock 函数签名不带 self；
- 中文用例必须走文件（`lua -e` 传中文在 GBK 控制台产生假阴性）；
- 断言跨层契约时以线协议为准，不信内部返回形状（`MCP_Bridge.call` 返回的是编码后的 JSON 字符串）。

---

## 10. 扩展指南：端到端新增一条命令

以假设的 `get_heap_ranges` 为例，五步，缺一不可：

1. **Lua handler**（`ce_mcp_bridge.lua`）：
   ```lua
   function cmd_get_heap_ranges(params)
       local limit = clampPaging(params, 100)          -- ① 分页/尺寸钳制
       local pid = params.pid or getOpenedProcessID()  -- ② 参数兜底
       if not pid or pid == 0 then
           return { success = false, error = "No process", error_code = "NO_PROCESS" }
       end
       local ok, res = pcall(function() return enumHeapRanges() end)  -- ③ pcall 包裹 CE API
       if not ok then
           return { success = false, error = tostring(res), error_code = "CE_API_ERROR" }
       end
       return { success = true, ... }                  -- ④ 扁平 result + success
   end
   ```
2. **注册**：`commandHandlers.get_heap_ranges = cmd_get_heap_ranges`（别名直接再赋值一行）。
3. **Python 工具**（`mcp_cheatengine.py`）：`@mcp.tool()` + 单行 body `return format_result(call("get_heap_ranges", {...}))`。docstring 是给 AI 的唯一文档——写清参数、边界、返回字段，附使用示例。
4. **测试**：`test_bridge_lua.lua` 加 handler 级用例（正常/缺参/NOT_FOUND 三件套），必要时 mock CE API。
5. **文档**：README 工具计数、本指南错误码/caps 表若有新增同步更新。

**约束**：handler 内不得调用会阻塞的 CE API 之外的任何阻塞原语（主线程）；所有外发数据必须过 `json.encode`（深度/循环由护栏兜底）；写操作预校验失败必须零副作用。

---

## 11. 发布清单（Release Checklist）

- [ ] `luac -p ce_mcp_bridge.lua`、`py_compile *.py` 通过
- [ ] Lua 139 / Python 27 / Probe 4 全绿
- [ ] 若改了 `ce_mcp_tcp.c`：双架构重编 + PE 校验 + 双副本 md5 一致
- [ ] `VERSION`（Lua）/ badge（README ×2）同步 bump
- [ ] 部署侧：DLL 覆盖到 CE 目录 → CE 里重载 `ce_mcp_bridge.lua` → 控制台见 `[MCP] Bridge v15.4.2 started on 127.0.0.1:17171`
- [ ] 烟测：`python ce.py ping` → `bridge_status` 检查 `process_attached` / `native.listening`
- [ ] 无未跟踪的草稿/备份文件混入版本库

## 12. 已知约束（硅事实，勿对抗）

- CE Lua 沙箱无 cjson/luasocket/FFI——JSON 编解码器手写是**唯一解**，不是 NIH；
- 本构建 AutoHotkey/CE 侧存在不可捕获的致命错误族（参考用户级记忆），Lua 侧同理：凡 pcall 能包的都包；
- `PAGE_GUARD` 类断点方案全面劣于 DBK 调试寄存器方案（DR0-DR3 四槽是硬件上限）；
- 开启 CE "Query memory region routines" 时对 DBVM 保护页扫描可触发 BSOD——发布文档必须保留此警告。

## 13. CE API 覆盖缺口与路线图（v15.4.2 审计 → v15.5.0 落地，依据官方 celua.txt 全集）

核心工作流（内存/扫描/调试/AA/符号/表/记录/结构/文件/系统，14 域）自 v15.4 起完整覆盖。
v15.5.0 新增 **45 个 handler / 45 个工具**（UNIT-31），把审计出的缺口全部按「零新依赖、薄适配、
pcall + 存在性检查降级」原则落地；回调型 API（custom type 转换器、热键动作、AA 命令）以 Lua 源码
串经 `load()` 编译，与 evaluate_lua 同级安全语义，并纳入审计前缀。

### v15.5.0 已落地（按域）

| 域 | 新增 handler |
|---|---|
| 变速 | `set_speed` / `get_speed`（speedhack_setSpeed/getSpeed） |
| 反汇编上下文 | `get_previous_opcode` / `get_last_disassemble_data` |
| 结构猜测 | `auto_guess_structure`（structure.autoGuess） |
| 热键 | `create_hotkey` / `list_hotkeys` / `remove_hotkey`（桥持对象保活） |
| 自定义类型 | `register_custom_type` / `register_custom_type_aa` / `get_custom_type` / `read_custom` / `write_custom`（桥记录 byte_count） |
| 代码解剖库 | `dissect_code_start` / `_references` / `_strings` / `_functions` / `_manage`（save/load/clear） |
| .NET 检查 | `dotnet_status` / `enum_domains` / `enum_modules` / `enum_types` / `type_details` / `method_params` / `address_info` / `enum_objects` |
| 表文件 | `table_file_create` / `find` / `export` / `delete`（createTableFile/findTableFile） |
| AA 扩展 | `register_aa_command` / `unregister_aa_command` |
| 网络 | `http_get` / `http_post`（getInternet） |
| DBK 内核 | `dbk_initialize` / `dbk_use_kernelmode`（三开关合一）/ `dbk_read_msr` / `dbk_write_msr` |
| DBVM | `dbvm_initialize` / `dbvm_read_msr` / `dbvm_write_msr` / `dbvm_cloak_activate` / `_deactivate` / `_read`（4096B 预览前 64）/ `_write` |

### 刻意不实现（架构理由，非遗漏）

- **`dbvm_traceonbp_*`×5 / `dbvm_bp_*`×5**：需要阻塞式事件等待，与 1ms 单线程轮询模型不兼容；
  `dbvm_watch` 四件套已覆盖轮询监视模式。
- **`dbvm_speedhack_setSpeed`**：修改全系统 TSC（影响时钟），对 AI 工具过于危险；`evaluate_lua` 可达。
- **AA Prologue/Template/registerAssembler/setAssemblerMode/registerSymbolLookupCallback**：
  深度 AA 内部扩展点，AI 消费场景不需要；`registerAutoAssemblerCommand`（最常用）已暴露。
- **`getSettings`**：官方 celua.txt 无此全局函数（此前审计为提取噪声误报），不作承诺。

### 非 gap（明确不做，理由如下）

- **指针扫描首扫**：CE Lua 本身无此 API（GUI 专属），桥无法覆盖；`pointer_rescan` 已是 Lua 侧极限
- **mono_\* 函数族**：仅 mono 附加后动态存在，`evaluate_lua` 可直接调用
- **LCL GUI 全家桶 / d3dhook / LuaPipe / sleep 类**：headless 设计刻意不暴露（GUI 构建与阻塞调用走 `evaluate_lua` 逃生舱）
- **`unregisterCustomType`**：官方 API 不存在（自定义类型注册后不可注销），`get_custom_type` 可查询避免重名

---

## 14. 分层渐进式工具加载与共享令牌认证（v15.6.0，UNIT-32）

### 背景（竞品对照结论）

对照 tonytranrp/cheat-engine-mcp（Node + 命名管道 + Lua，127 工具）与其衍生讨论后，采纳两点、
舍弃两点：

- **采纳①**：共享令牌认证（其 `CE_MCP_AUTH_TOKEN` 走管道层）——本桥在 **Lua dispatch 单点**
  （`executeCommand`）实现，零 DLL 变更；batch 天然被覆盖（batch 是 executeCommand 的一个 handler
  内循环，外层门禁先行）。
- **采纳②**：面向 AI 的「推荐工作流」文档（指针追踪 / 函数分析 / CT 表流水线）。
- **舍弃①**：其 CE-MCP-Plugin 纯 C 文本协议（外连 8888、无帧、无 JSON）——架构劣于本桥的
  4B LE + JSON + DLL 旁路，无可吸收项。
- **舍弃②**：DLL 层认证 / 自定义管道名——本桥默认 loopback + 端口扫描 + ping 身份识别已覆盖
  同等威胁面；Lua 层令牌补足「本地恶意进程」这一剩余缺口。

### 分层加载设计（Python，mcp_cheatengine.py）

- **记录器模式**：`mcp.tool` 在模块体执行期间被实例属性 `_record_tool` 遮蔽——243 个
  `@mcp.tool()` 装饰器**零改动**，只记录 `(fn)` 到 `_TOOL_SPECS`，不注册。启动注册完成后
  `del mcp.tool` 恢复真身。
- **类别目录**：`_TOOL_CATEGORIES`（243 项全覆盖，18 类 + core 常驻），启动时未归类工具
  兜底注册并打 stderr 警告（绝不静默吞工具）。
- **剖面**：`CE_MCP_TOOLS=all|minimal|core|core,<cat>...`；未知类别 fail-fast（SystemExit）。
- **运行时扩展**：常驻 `ce_tools_manage(action=list|enabled|enable)`；`enable` 幂等（集合去重），
  best-effort 发 `notifications/tools/list_changed`（1.x 走 `mcp.get_context().session`，
  2.x 走 lowlevel `request_context` contextvar；拿不到会话则返回「请重列/重连」提示）。
- **SDK 双版本 shim**：mcp 2.x 把 FastMCP 改名 MCPServer（`mcp.server.mcpserver`）；导入时
  优先 2.x、回退 1.x。Windows CRLF 补丁同时挂到两版的 server 模块命名空间（2.x 的 stdio 仍用
  TextIOWrapper 且不带 `newline='\n'`，隐患仍在）。requirements 钉 `mcp>=1.0.0,<3`。

### Lua 侧认证门禁

`resolveAuthToken()` 在加载时读 `CE_MCP_AUTH_TOKEN`（getEnvironmentVariable → os.getenv 回退）。
`executeCommand` 在 handler 查找前校验 `params._auth`，失败返回 `AUTH_REQUIRED`（JSON-RPC
error envelope）；通过后 `params._auth = nil` 剥离——handler 与审计日志均不见令牌。两端都未设置
= 原有开放 loopback 行为，向后兼容。

### 测试增量

- Lua：+6（缺 token / 错 token / 对 token / batch 过门 / 审计不泄 token / 复载还原开放态）；
  测试用函数作用域封装——主 chunk 已逼近 Lua 200 局部变量上限，`do..end` 不够、须独立 function。
- Python：+11（243 记录数、目录全覆盖、core/minimal/未知剖面、244 注册面、list/enabled 一致性、
  enable 幂等、token 注入/未设不注入）。
