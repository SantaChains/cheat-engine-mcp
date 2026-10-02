# dev.md — cheatengine-mcp-tcp-bridge 技术原理、业界对照与选型推荐

> Part I：基于 v15.2.0 代码实态 + 2026-10-02 检索（Lua/Python/协议/安全/调试器层）。
> **Part II（C 与 DLL 层深查）：基于 v15.4.1 / DLL v3.3.2 代码实态 + 2026-10-03 检索。**
> 每项技术按「项目现状 → 业界/学术对照 → 结论与推荐」结构分析。
> 结论分三级：**推荐保持**（当前即最优）/ **建议改进**（有明确更优解）/ **可选升级**（收益与成本并存）。

---

## 0. 架构总览

```
AI 客户端 (Claude 等)
   │  MCP / JSON-RPC over stdio
   ▼
MCP_Server/mcp_cheatengine.py   (Python, FastMCP, 189 工具, call() 永不抛出)
   │  TCP: 4B LE 长度前缀 + UTF-8 JSON, 锁步一问一答, 端口扫描 17171-17180
   ▼
MCP_Server/ce_mcp_tcp_{x64,x86}.dll   (C, Winsock2, select(), /MT 静态 CRT)
   │  DLL 通过运行时解析 Lua C API 注册 mcp_tcp_start/poll/respond/stop/status
   ▼
MCP_Server/ce_mcp_bridge.lua    (纯 Lua, 1ms 定时器主线程轮询, 198 调度方法)
   │  CE Lua API
   ▼
Cheat Engine (读内存 / 扫描 / 断点 DR0-DR3 / DBVM Ring-1 / DBK 内核驱动)
   ▼
目标进程
```

核心设计约束：**CE Lua API 只能在主线程调用**。这决定了后续几乎所有架构选择。

---

## 1. 帧协议：4 字节 LE 长度前缀

**项目现状**：DLL 层实现 `4 字节小端长度前缀 + UTF-8 JSON 体`，超限（>4MB）/零长/截断帧直接断连，锁步一问一答，`TCP_NODELAY + SO_KEEPALIVE`。

**业界对照**（TCP 上的三大帧协议家族）：

| 方案 | 代表协议 | 优点 | 缺点 |
|---|---|---|---|
| 长度前缀 | **gRPC**（5B：1 压缩标志 + 4B 大端长度）、WebSocket | O(1) 定界、体可含任意字节、零解析开销 | 长度字段损坏后流失步，需断连恢复 |
| Content-Length 头 | LSP / DAP（`Content-Length: N\r\n\r\n`） | 线上可读，socat 直接观察调试友好 | 头解析开销、实现更复杂 |
| 分隔符（NDJSON） | MCP stdio、JSONL | 极简、可 grep | 体中不得出现真实换行（依赖 JSON 转义保证） |

关键工程共识（GopherTrunk 帧协议教程 / bhekani Length-Prefixed Framing）：
- 「如果必须自建帧协议，就选长度前缀，**必须限定长度上限**（无上限的长度字段是攻击面），并在首字节发出前确定失步恢复策略」。
- 业界失步恢复的标准答案就是**杀连接重连**——gRPC 与 WebSocket 实现均如此。本桥 DLL 对坏帧直接断连，正是这一惯例。
- gRPC 5B 前缀与本桥 4B 前缀同族，仅多一个压缩标志字节；本桥无压缩需求，4B 是最简正确形态。

**结论：推荐保持。** 与 gRPC 同族的选型，4MB 上限、坏帧断连、NODELAY/KEEPALIVE 全部符合最佳实践。唯一可选增强：响应体支持 `grpc-message` 式的独立错误通道（见 §3）。

---

## 2. JSON 编解码：纯 Lua 手写编解码器

**项目现状**：约 500 行手写 JSON 编解码器，含：`utf8Encode` + `\uXXXX` 代理对、64 位整数精确往返（`math.type` 分支）、深度护栏 200（encode/decode 双侧）、混合表回落对象编码零丢失、循环引用检测 + `safeEncode` 兜底。

**业界对照**（2026 年 Lua JSON 库格局，wjson 基准数据）：

| 库 | 实现 | Lua 5.5 PUC | 特点 |
|---|---|---|---|
| rxi/json.lua | 纯 Lua ~400 行 | ✅ | 最普及，但**无 UTF-8 校验、64 位精度丢失** |
| lunajson | 纯 Lua | ✅ | PUC Lua 5.4/5.5 上最快纯 Lua 方案，SAX 模式 |
| wjson | 纯 Lua 单文件 | ✅ | RFC 8259 严格校验、过 JSONTestSuite、UTF-8 验证；LuaJIT 上最快 |
| lua-cjson | C 扩展 | 需重编译 | 吞吐最高，但 CE 内嵌 Lua 加载 C 模块不可行 |
| dkjson | 纯 Lua | ✅ | 可配置性强，较慢 |

**为什么必须自研而不能直接用现成库**：
1. CE 的 Lua 是宿主内嵌环境，无 `luarocks`，引入第三方单文件库虽可行但**契约风险不可控**（工具描述声称的行为必须与真实行为一致）。
2. 本桥的两个硬需求——**64 位整数无损**（地址值！）与**深度护栏**——rxi 都没有，wjson 有但无法保证在 CE 5.5 宿主下行为可审计。
3. 手写方案的错误路径已被 130 项单元测试 + 13 项线上帧实验双重锁定，这比「引入更快但行为黑盒的库」更符合本项目的可靠性目标。

**结论：推荐保持自研。** 可选升级：把 `JSONTestSuite` 全套用例移植进 `test_bridge_lua.lua`（wjson 的合规性验证法），预计半天工作量，能把「理论正确」升级为「标准套件验证正确」。性能上纯 Lua 编解码对本桥不是瓶颈（锁步 RPC 每秒命令数 << 解析吞吐），不必换库。

---

## 3. 线级信封：JSON-RPC 2.0 双形状 + 第三形状

**项目现状**：
- 正常/命令级失败：`{jsonrpc:"2.0", id, result:{success, error_code, ...}}`
- 解析错误/未知方法：JSON-RPC `error` 对象（`-32700` / `-32601`）
- DLL 层 120s 超时：`{"error":"timeout waiting for command handler"}`（非 JSON-RPC 形状）
- `method` 直接查 `commandHandlers[method]`，**无 MCP 握手**（initialize/tools/list 不存在）

**业界对照**：
- JSON-RPC 2.0 规范本身允许两种响应形状并存（result XOR error），本桥用法合法。
- MCP 官方 transport 就是 JSON-RPC over stdio/streamable-HTTP，带完整握手；本桥在 MCP 服务器（Python 层）与 Lua 桥之间用「JSON-RPC 形状 + 纯命令名分发」是**私有内层协议**，不需要握手——这是合理的分层：握手语义属于外层 MCP，内层只做命令分发。
- gRPC 的对照做法：状态走独立 trailers 通道（`grpc-status`/`grpc-message`），错误与数据彻底分离。

**结论：推荐保持，建议一项小改进**——把 DLL 超时响应统一为 JSON-RPC error 形状（`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"timeout..."}}`），消除第三形状。改动点在 `ce_mcp_tcp.c` 一处字符串，需重编译 DLL；不急则维持现状（Python `_unwrap` 已正确降级）。

---

## 4. MCP 服务器层：FastMCP + 189 工具

**项目现状**：`@mcp.tool()` 装饰器 + docstring 自动生成描述；统一 `call()` 永不抛出；`format_result` 永不抛出；错误信封 `{success, error, error_code}`。

**业界对照**（FastMCP 官方实践 / MCPize / Cloudurable 指南）：

| 最佳实践 | 本项目 | 评价 |
|---|---|---|
| 工具聚焦：一个工具做一件事 | 189 个细粒度工具按域分类 | ✅ 超额符合 |
| 分页 + `total/offset/returned` 元数据 | `paginate()` 强制约定 | ✅ |
| 错误信息可操作、不暴露内部异常 | 错误码枚举 + 中性错误文本 | ✅ |
| 类型提示 + Pydantic 入参前置验证 | 参数验证主要在 Lua 层 | ⚠️ 部分符合 |
| async-first，避免阻塞事件循环 | 全同步（stdio 单客户端场景） | ⚠️ 场景可接受 |
| `ctx.info()/ctx.error()` 进度上报 | 未使用 Context | 可选升级 |
| in-memory 测试（FastMCP Client 直连） | 自研 stub 进程内测试 | ✅ 等效实现 |

**同步阻塞的合理性**：FastMCP 指南强调 async 是为并发工具调用；本桥底层是**锁步单通道**（一次一条命令），并发无意义，同步反而消除了事件循环复杂度。这不是缺陷。

**结论：推荐保持。** 可选升级：`run_command`/`evaluate_lua` 等高危工具接入 MCP Context 上报（`ctx.warning("dangerous op")`），让 AI 客户端在人机审批 UI 里看到风险提示。

---

## 5. 安全模型：绑定地址、认证与危险工具门控

**项目现状**：
- DLL `TCP_BIND = "0.0.0.0"`（全接口监听！）
- 无任何认证
- `run_command`/`shell_execute` 由 `CE_MCP_ALLOW_SHELL` 环境变量门控（默认关）
- Python 端连接 `127.0.0.1`（但远机调试场景支持 `CE_HOST`）

**业界对照**（2026 年 MCP 安全检查清单，Safeguard/Panther/wraith.sh 共识）：

> **"Bind local servers to 127.0.0.1, never 0.0.0.0."** —— 这是 2025 年多起本地 MCP 服务器 DNS rebinding 漏洞集群的直接根因。Streamable-HTTP 服务器必须校验 Origin；本地 TCP 服务器必须只绑回环。

- 最小权限：工具应有最窄能力面；高危操作（删除、shell、任意执行）必须有人类审批门。
- 本地不等于安全边界：「Do not rely on localhost as a security boundary」——同机任意进程都能连上一个无认证的 17171 端口。
- 资源预算：无上限的工具调用 = 远程 DoS 向量（本桥已在 Lua 层全面钳制，见 AGENTS.md Resource caps）。

**结论：建议改进（优先级最高的一项）。**
1. **`TCP_BIND` 默认改 `127.0.0.1`**，需要远机调试时用环境变量显式开启——一行改动 + 文档说明，收益极大。
2. 可选：加共享 token 握手（首帧 `{"auth": "..."}` 或自定义头），防同机其他进程误连/恶意连。当前单用户桌面场景风险低，非必须。
3. `CE_MCP_ALLOW_SHELL` 门控模式正确，建议文档中把它升格为「审批门」概念并补充 `evaluate_lua` 的等价风险说明（它本来就是任意代码执行，比 shell 更强）。

---

## 6. 调试与内存检查技术栈

### 6.1 硬件断点（DR0–DR3 + DR7）

**项目现状**：`debug_setBreakpoint(..., bpmDebugRegister, ...)`，4 槽位管理（`hw_bp_slots`），命中后必调 `debug_continueFromBreakpoint`。

**业界/学术对照**：
- Intel SDM Vol.3 Ch.17：DR0–DR3 地址寄存器 + DR7 控制寄存器，**硬件上限恒为 4**，无例外（GOTO 2025 debugger internals 演讲原文："four hardware breakpoints total, no exceptions"）。
- 看雪 2026 论证（CE VEH Debugger vs PAGE_GUARD）：CE 的 VEH 调试器核心就是 DR 寄存器，字节级精度、CPU 硬件比对、持久有效；PAGE_GUARD 页级粒度、一次性触发、有竞态窗口和误触发风暴，仅适合单线程粗粒度监控。
- 本桥的 4 槽位显式管理 + 命中即续跑，是对该硬件约束的正确工程化。

**结论：推荐保持。** 4 槽是硅约束，任何工具（Frida/x64dbg/WinDbg）同限。软件 INT3 断点（`bpmInt3`）作为补充已在桥内可用，二者互补正确。

### 6.2 DBVM（Ring -1 hypervisor 监视）

**项目现状**：`dbvm_watch_writes/reads/executes` + 日志拉取/清理，隐藏内存写入监视。

**业界对照**：
- DBVM 是 CE 自带的 Type-1 hypervisor（Intel VT-x），用 EPT 在硬件层捕获内存访问——比内核驱动更隐蔽、比 PAGE_GUARD 更精确。
- 对照项目：HyperHide（hypervisor 反调试，EPT 操作）、TitanHide（内核态隐藏调试器）。逆向社区共识：**EPT 级监视是隐蔽性与精确性的天花板**，DBVM 让 CE 用户免开发即可用。
- 前置条件明确：必须禁用 "Query memory region routines"（防 `CLOCK_WATCHDOG_TIMEOUT` 蓝屏），本桥文档已固化此要求。

**结论：推荐保持。** 这是本桥相对「Frida + 自写脚本」路线的核心差异化能力。

### 6.3 合规边界（非技术但必须声明）

多人在反作弊（VAC/EAC/BattlEye/Vanguard）环境下使用任何此类工具都会封号，且 Frida/CE 本身是反作弊扫描目标。本桥定位：**单机游戏修改与安全研究**。文档中的定位声明应保留。

---

## 7. 主线程执行模型：1ms 定时器轮询

**项目现状**：`createTimer(nil, false)` 主线程 1ms 轮询 `mcp_tcp_poll()`，命令在主线程 `executeCommand`，`workerBusy` 防重入；`runOnMainThread` 仅在非主线程定时器分发的 CE 版本上降级到 `synchronize`。

**业界对照**：
- 单线程亲和（thread affinity）是 GUI 框架的通用铁律（Win32 消息循环、macOS Main Dispatch Queue、Android Main Looper）：**UI/宿主 API 只在拥有它们的线程调用**。
- 跨线程调度反模式：worker 线程执行 → `synchronize` 回主线程合并结果（本桥 v14 及更早的做法），每命令付出两次线程切换 + 合并竞态。
- 1ms 轮询在空闲时的 CPU 代价（select 一次、约 0.1% 单核）远低于线程往返的每命令延迟（数百 µs–ms 级）+ 复杂度成本。

**结论：推荐保持。** 这是本项目性价比最高的一次架构修正。可选微优化：空闲期把定时器间隔从 1ms 放宽到 5–10ms、收到首字节后再收紧（自适应轮询），空闲 CPU 再降一个量级；收益有限，非必须。

---

## 8. 可靠性语义：锁步 + 超时不重试 + 资源钳制

**项目现状**：
- 客户端超时后**关闭连接**（防迟到响应污染下一命令——锁步协议的头号隐患）
- 重试只发生在**连接失败**；**超时绝不重试**（超时命令可能已在 CE 内产生副作用）
- `call()` 永不抛出，统一错误信封；Lua 层 10+ 处 limit/size/depth 钳制；断点命中历史 500 条环形淘汰

**业界对照**：
- gRPC 重试语义：仅幂等操作默认自动重试（`UNAVAILABLE`），非幂等需显式 `RetryInfo` —— 本桥「超时不重试」与 gRPC 默认策略一致且更保守（正确，因为写内存天然非幂等）。
- deadline 传播：gRPC 的 `grpc-timeout` 随请求传播；本桥用固定 `CE_MCP_TIMEOUT`，单客户端场景够用。
- 资源预算 = 2026 MCP 安全共识的 "Cap expensive operations... so a runaway agent hits a wall instead of a bill"，本桥的 Resource caps 段已制度化。

**结论：推荐保持。** 这套语义组合（锁步 + 超时断连 + 非幂等不重试 + 全面钳制）是教科书级的正确。

---

## 9. 批处理与内省

**项目现状**：`batch`（≤64 条、禁嵌套、`stop_on_error`）一次往返；`status`/`bridge_status`/`list_methods` 自省；`evaluate_lua` 万能逃生口。

**业界对照**：
- 单命令一次往返是锁步 RPC 的固有延迟瓶颈；批处理是 gRPC client streaming / HTTP pipelining 的同型解法。64 上限 + 禁嵌套 + 逐条错误结果，与 GitHub/GitLab 批量 API 的设计同构。
- `list_methods` 自省对应 MCP `tools/list`（外层已有）+ LSP `completionItem/resolve` 式的能力发现；双端（外层 MCP / 内层桥）各有一套发现机制，分层正确。
- `evaluate_lua` 作为 escape hatch：等价于 LSP 的自定义扩展命令或调试器的 expression evaluation——成熟工具都留这样一个「协议覆盖不到时的万能通道」，但必须与资源钳制配套（本桥 evaluate 结果受深度护栏 200 约束）。

**结论：推荐保持。** 可选升级：`batch` 结果里回显每条的 `id` 已支持；再加一条 `elapsed_ms` 汇总统计即可支撑后续性能回归基线。

---

## 10. 测试策略：stub 离线测试 + 正式探针

**项目现状**：
- `test_bridge_lua.lua`：130 断言，CE API 全 stub，无需 CE（含 UTF-8/CJK 矩阵、深度护栏、混合表、batch、断点钳制）
- `test_bridge.py --self-test`：进程内 stub 桥按线级契约逐字节镜像 DLL 语义（27 断言）
- `probe_bridge.py`：13 项帧矩阵实验的正式 JSON-RPC 探针（含死端口检查清单）

**业界对照**：
- FastMCP 官方推荐 in-memory testing（Client 直连 server 实例，无子进程无网络）——本桥 stub 桥是同一思想的等价实现。
- wjson 用 JSONTestSuite 验证合规性；MCP Inspector 是交互式调试器——probe_bridge.py 定位于二者之间（自动化协议验证）。
- 契约测试（contract testing）原则：**客户端测试必须针对线级契约而非实现**——stub 桥镜像的是 DLL 帧语义（含坏帧断连行为），而非 mock 返回值，这是正确的做法。

**结论：推荐保持。** 可选升级：JSONTestSuite 移植（与 §2 同一工作项）+ CI 化（GitHub Actions 跑三个离线测试，live 测试标注 needs-CE）。

---

## 11. 总对比矩阵

| # | 技术点 | 项目选型 | 业界/学术基准 | 结论 |
|---|---|---|---|---|
| 1 | 帧协议 | 4B LE 长度前缀 + 4MB 守卫 + 坏帧断连 | gRPC 同族（5B）；失步杀连接是标准恢复策略 | **推荐保持** |
| 2 | JSON 编解码 | 自研纯 Lua（深度护栏/64 位/UTF-8） | wjson/lunajson 更快但契约不可控；rxi 有精度缺陷 | **推荐保持** + 移植 JSONTestSuite |
| 3 | 线级信封 | JSON-RPC 2.0 双形状 + DLL 超时第三形状 | JSON-RPC 规范允许双形状；gRPC 错误走独立通道 | **保持**；小改：统一超时形状 |
| 4 | MCP 层 | FastMCP 同步 + 189 细粒度工具 + 分页 + 错误码 | 官方最佳实践大半符合；async 与 Pydantic 为可选 | **推荐保持** |
| 5 | 安全 | 绑 0.0.0.0、无认证、shell 门控 | **127.0.0.1 强制**、最小权限、审批门 | **⚠️ 建议改进**（绑回环） |
| 6a | 硬件断点 | DR0–DR3 + 4 槽管理 + 命中即续跑 | Intel SDM 硬性 4 槽；CE VEH 即 DR 方案 | **推荐保持** |
| 6b | DBVM | Ring -1 EPT 级监视 | HyperHide/TitanHide 同类中 CE 开箱即用 | **推荐保持** |
| 7 | 执行模型 | 主线程 1ms 定时器轮询 | 单线程亲和铁律；消灭线程往返 | **推荐保持** + 可选自适应间隔 |
| 8 | 可靠性语义 | 锁步 + 超时断连不重试 + 全面钳制 | gRPC 幂等重试原则；MCP 资源预算共识 | **推荐保持** |
| 9 | 批处理/自省 | batch ≤64 + list_methods + evaluate_lua | 批量 API 同构；escape hatch 惯例 | **推荐保持** |
| 10 | 测试 | stub 离线 + 契约级 stub + 帧探针 | in-memory testing / contract testing 思想 | **推荐保持** + CI 化 |

---

## 12. 推荐路线

### 短期（建议尽快，收益/成本比最高）
1. **✅ 已完成（2026-10-02，DLL v3.2.0）**：`TCP_BIND` 默认改 `127.0.0.1`，`CE_MCP_BIND` 环境变量显式开启远机监听（DLL 与 Lua 双侧读取）；同时修了超时断连、respond OOM、stop 线程活性检查三个并发缺陷。
2. README/dev.md 固化「危险工具审批门」说明：`run_command`/`shell_execute`/`evaluate_lua`/`write_memory`/`auto_assemble` 属同一风险级。

### 中期（可选，提升合规性与性能基线）
3. 移植 JSONTestSuite 到 `test_bridge_lua.lua`，编解码合规性从「自证」升级为「标准套件验证」。
4. `batch` 响应加 `elapsed_ms`；Lua 空闲轮询间隔自适应（1ms 忙 / 5ms 闲）。
5. DLL 超时响应统一为 JSON-RPC error 形状（需重编译 DLL）。

### 不建议做
- **换用 lua-cjson/wjson 等第三方 JSON 库**：CE 宿主环境契约不可控，自研方案已有 130 项测试锁定，换库收益（解析吞吐）对本桥无意义。
- **改造为 async MCP 工具**：锁步底层决定了并发无收益，徒增复杂度。
- **追求突破 4 个硬件断点**：硅约束，PAGE_GUARD 替代方案精度与稳定性全面劣于 DR 方案（见看雪论证），现有 int3/DBVM 组合已覆盖其余场景。

---

## 附：主要参考来源

- MCP 官方 / FastMCP 实践：mcpize.com《MCP Server Python: Production-Ready Servers with FastMCP》、cloudurable.com FastMCP Guide
- MCP 安全：safeguard.sh《Securing MCP Servers: A Practical Checklist》（127.0.0.1 绑定、tool pinning）、panther.com《How to Secure an MCP Server》（审批门/最小权限）、wraith.sh《MCP Security: The Attack Surface》
- 帧协议：gophertrunk.org《Message framing》（三家族 + 失步恢复）、bhekani.com《Length-Prefixed Framing》、kreya.app《gRPC deep dive》（5B 前缀）
- Lua JSON：winterstream/wjson（基准 + JSONTestSuite 方法论）、vurvdev/qjson（编码性能基准）
- 调试器架构：Intel SDM Vol.3 Ch.17（Debug Registers）、GOTO 2025 Sy Brand《What Really Happens When You Hit a Breakpoint》、看雪 2026《深度理解 VEH-CheatEngine vs VEH-PAGE_GUARD》、b0ldfrev《调试原理》
- 逆向工具格局：2026 RE Tools Deep Dive（CE/Frida/x64dbg 定位与反作弊对抗现状）

---

---

# Part II — C 与 DLL 层深查（2026-10-03）

> 对象：`NativeBridge/ce_mcp_tcp.c`（1222 行，DLL v3.3.2）+ 双工具链构建体系。
> 检索范围：modern C（C23）、Win32/DLL 官方最佳实践、Winsock I/O 模型、Windows 同步原语、
> 嵌入式 C JSON 库、二进制安全加固、Lua C API 宿主链接模式。
> Part I 的 §1-§5（协议/安全）结论不变；本部分只覆盖 C 层独有的技术决策。

## C1. Lua C API 链接模式：运行时符号解析（宿主静态链接场景的唯一解）

**项目现状**：四阶段解析——① 按 10 个已知名称（lua54/53.dll 等）GetModuleHandle/LoadLibrary → ② 主 exe 导出 → ③ Toolhelp32 全模块快照扫描（任何导出 lua_pushstring 的模块）→ ④ 扫描 CE 目录 lua*.dll 文件 + PE 导出表诊断。17 个函数指针；即使部分缺失（getglobal/pcallk/error/isnumber），核心 12 个齐即判可用（优雅降级）。

**业界对照**：
- lua-users《Easy Manual Library Load》：宿主静态链接 Lua 时，LoadLibrary + GetProcAddress 手动解析是**标准做法**——DLL 与宿主必须共享**同一** Lua VM 实例（同一 lua_State、同一分配器），静态链一份 lua54.dll 进自己反而会得到两个独立 VM/堆，必崩。
- StackGuides 经典问答（"call Lua functions without custom .lib"）：宿主（如游戏）静态链 Lua 后，第三方 C 模块**没有正规链接途径**，只能依赖宿主导出符号——"the developers made it essentially impossible for users to write their own C modules without hacking the binary"。
- 同型项目：**SQLite loadable extensions** 与 **Redis Modules** 同为「C 扩展注入宿主」范式——都要求扩展通过宿主传入/可解析的 API 指针工作，绝不自带一份宿主库。

**结论：推荐保持。** 四阶段降级顺序比一般开源扩展更健壮（全模块快照兜底是超出惯例的防御）。luaopen_ce_mcp_tcp 入口符合 Lua require/loadlib 模块约定（CSDN/博客园对照：入口签名 `int luaopen_xxx(lua_State*)`、返回压栈值个数，均正确）。

## C2. DllMain 与加载器锁纪律（v3.3.2 修复）

**项目现状**：`DLL_PROCESS_ATTACH` 原本调用 `dbg_init()` → AllocConsole + freopen(stdout)——在加载器锁（loader lock）下调用。v3.3.2 已改为延迟初始化：DllMain 只设 `g_self_module` + dbg_log（走既有 `if (!g_console) dbg_init()` 懒路径，首次实际发生在 luaopen 解析 Lua API 时，此时 LoadLibrary 已释放加载器锁）；DETACH 仅 running=0 + closesocket + SetEvent（kernel32 安全集），FreeConsole 加 g_console 守卫。

**业界对照**（Microsoft Learn《Dynamic-Link Library Best Practices》，权威级）：
- "DllMain is called while the loader-lock is held... The ideal DllMain would be just an empty stub"；明令禁止：LoadLibrary、线程同步、CoInitializeEx、注册表、**User32/Gdi32 调用**、"Call CreateThread — can work but is risky"。
- PVS-Studio V718 即为此设诊断；Raymond Chen 多次论证：DllMain 期间创建的线程要等所有 DLL_THREAD_ATTACH 处理完才能跑，同步即死锁。
- 本 DLL 的 TCP 服务线程在 `mcp_tcp_start`（Lua 调用，加载器锁已释放）中创建——符合规范；AllocConsole 虽属 kernel32，但内部涉控制台驱动初始化，MS 文档精神是"能推迟就推迟"，懒初始化是零成本合规。

**结论：推荐保持（本轮已修）。** 遗留可选项：DllMain 内 dbg_log 的 WriteConsoleA 仍在锁下（WriteConsole 本身属安全集，实测 CE 加载路径无问题）；追求绝对纯净可在 ATTACH 完全静默、首条日志延迟到 luaopen——收益趋零，不建议再动。

## C3. Winsock I/O 模型：select + 锁步单客户端

**项目现状**：accept 循环 select(1s 超时) 监听单连接；recv 用 select(200ms) 分片 + `g_bridge.running` 检查实现可中断阻塞；TCP_NODELAY + SO_KEEPALIVE；单客户端锁步一问一答。

**业界对照**（Winsock 五大 I/O 模型共识，Windows 核心编程 / CSDN 工业级对比 / cnblogs 模型表）：

| 模型 | 复杂度 | 并发能力 | 适用场景 |
|---|---|---|---|
| 阻塞+多线程 | 低 | 低 | 小工具 |
| **select** | 中 | 低（FD_SETSIZE 限制） | **简单客户端/小服务** |
| WSAEventSelect | 中高 | 中 | 事件驱动、中型服务 |
| Overlapped I/O | 高 | 高 | 高性能服务器 |
| IOCP | 最高 | 极高 | 工业级高并发 |

- 业界共识原话："如果性能啥的都不需要考虑，那简洁的 Select 模式值得被考虑"；"IOCP 的线程调度优化…不要盲目创建线程"——IOCP 的全部复杂度只为高并发买单，本桥**单客户端、每命令一次往返**，C10K 问题域之外。

**结论：推荐保持。** select 的两个已知缺陷（fd_set 每次重置、64 上限）在本桥连接数=1 的前提下不存在。若未来真要多客户端，正确升级位是 WSAEventSelect 而非 IOCP（复杂度阶梯）。

## C4. 线程同步原语组合：CS + SRWLOCK + Interlocked + Event 各就各位

**项目现状**：命令/响应队列用 `CRITICAL_SECTION`（可重入、配合 manual-reset Event 握手）；v3.3.0 fastpath 的 `g_last_method` 用 `SRWLOCK_INIT` 静态初始化（读多写少：每帧写一次、dll_status 读）；帧/字节计数器用 `InterlockedExchangeAdd`；`g_last_lua_poll_tick` 心跳用 `InterlockedExchange`。

**业界对照**（Microsoft Learn《About Synchronization》官方选型表 + MSDN Magazine SRW 基准）：
- 官方选型表：SRW = "现代新代码的默认选择，最小内存足迹（指针大小）"；CS = "需要可重入/递归加锁时"；Interlocked = 无锁计数标准；Event = "用于『发生了什么』通知，而不是保护数据"——本桥四者用法逐条吻合。
- MSDN Magazine 基准：无争用时 SRW ≈ CS；争用时 SRW 显著更快（4 写者场景约 CS 一半耗时）；静态初始化 SRWLOCK 免 Initialize/Delete 生命周期管理（v3.3.0 正是为此弃用 g_bridge.cs 守护 last_method——避免 stop 后 use-after-delete）。
- 常见错误对照："对进程内同步使用 Mutex"是官方点名的反模式——本桥未犯。

**结论：推荐保持。** 这是教科书级的原语选型，无需改动。

## C5. C 层 JSON 处理：手写字段提取器 vs 引库

**项目现状**：fastpath 只需从 4 种固定形状请求中提取 5 类字段，手写约 100 行（`json_extract_string/int/i64/bool/id` + `json_escape` 序列化），全程栈缓冲 + 信封一次 malloc；id 要求 **verbatim 回显**（引号/转义序列原样复制）。

**业界对照**（嵌入式 C JSON 选型框架，cJSON/jsmn/mu_json 对比资料）：
- cJSON：树形模型、动态分配、全功能——RAM/碎片风险使其不适合"固定字段提取"场景（tsight.io《cJSON 内存地雷》：链表逐项 malloc，长寿命进程碎片化）。
- jsmn：零分配 token 化，"仅提取少数字段、协议固定"正是其最佳用例；但需自行遍历 token，且不处理字符串生成。
- 本桥场景命中 jsmn 类用例（固定形状、少字段），但有三项引库成本：① 双工具链编译与静态 CRT 兼容；② **verbatim id 回显**——cJSON/mu_json 重序列化会规范化转义（`\uXXXX`→UTF-8 等），改变线上字节形状，破坏 id 严格回显契约；③ 审计面扩大。100 行手写代码已被 Lua/Python 契约测试矩阵间接锁定。

**结论：推荐保持手写。** 若未来 dll_ 方法需要嵌套对象参数，再评估 jsmn 移植（届时仅解析侧，id 回显路径仍手写）。

## C6. 二进制安全加固：PE DllCharacteristics 实证（v3.3.2 新增 CFG）

**项目现状**（dumpbin 实测）：

| 构建 | 工具链 | 修复前 | 修复后 |
|---|---|---|---|
| x64 | MinGW gcc 16.2 | `0x0160` HIGH_ENTROPY_VA + DYNAMIC_BASE + NX_COMPAT | 同左（build.bat 已显式化 `-Wl,--dynamicbase --nxcompat --high-entropy-va`） |
| x86 | MSVC /MT | `0x0140` DYNAMIC_BASE + NX_COMPAT（link.exe 默认） | `0x4140` **+ GUARD_CF**（`/guard:cf` + `/link /GUARD:CF`） |

**业界对照**：
- MinGW 历史：binutils bug 19011 记载其默认曾是 "terrible... security implications"，binutils 2.36 起才为 MinGW 目标默认开 dynamicbase/nxcompat；`--high-entropy-va` 默认化更晚（binutils 2.39 尚无）——**显式传参是版本无关的正确姿势**（Krita 等大型项目的 CMake 加固补丁即此做法）。
- MSVC：/DYNAMICBASE /NXCOMPAT 自 VS2008/2012 起是 link.exe 默认（裸命令行同样生效，本轮已实证）；**CFG 不在默认集**，需显式 `/guard:cf`——MS SRD《Software Defense》系列将其列为内存破坏利用缓解的标准层。
- 硬约束：MinGW 无法生成 Windows CFG（`-fcf-protection` 是 Intel CET，机制不同）；x86 无 i686 MinGW 工具链，CFG 只有 MSVC 路径能提供。

**方法论教训（本轮实证）**：初判"x86 完全无加固"来自自制 PE 解析器把 PE32 的 DllCharacteristics 偏移读错 2 字节（读到 Subsystem=0x0002）——用 dumpbin 交叉验证后证伪，并进一步用旧参数重构建确认 MSVC 默认已有 ASLR/DEP。**手写二进制解析必须与权威工具（dumpbin/objdump）对照校准**。

**结论：推荐保持。** x64 的 CFG 缺失是工具链硬约束，接受；/MT 静态 CRT 消除目标机 VC redist 依赖（CE 环境无保障），正确。

## C7. 时间源：GetTickCount 回绕语义（正确使用了"例外条款"）

**项目现状**：心跳 `poll_age_ms` 与 recv 超时用 `GetTickCount` + DWORD 减法 + `(LONG)` 截断比较；`uptime_ms` 以 `%lu` 打印（49.7 天回绕后显示错误，仅诊断展示）。

**业界对照**：
- MS 文档原文给出两条正路："To avoid this problem, use GetTickCount64. Otherwise, check for an overflow condition"；GetTickCount64 为 ULONGLONG（约 5.8 亿年不回绕），Vista+ 可用。
- Stack Overflow 经典结论（Jon Skeet）：**无符号 DWORD 减法在回绕下结果正确**（模 2^32 运算），前提仅两条：不中途转换为其他类型、单次耗时 <49.7 天。
- 本桥两条前提均满足：`(DWORD)(now - last)` 全程无符号；心跳间隔阈值 5s。唯一不严格处是 `(LONG)` cast——差值 <2^31 时语义不变，心跳场景恒成立。

**结论：推荐保持。** 可选升级：整体迁 `GetTickCount64` 消除 uptime 49.7 天显示回绕——收益极低（CE 会话极少超 49 天），列为可选不动。

## C8. HWND 32/64 位句柄安全（v3.3.1 修复）

**项目现状**：`dll_enum_dialogs` 以 `(unsigned long)(uintptr_t)hwnd` 打印；`dll_dismiss_dialog` 以 `_atoi64` 解析 + 「截断 uint32 → 符号扩展」重建 HWND；`IsWindow` + 本进程 PID 双重校验兜底。

**业界对照**：
- MS《Interprocess Communication Between 32-bit and 64-bit Applications》："USER and GDI handles are **sign extended** 32-bit values"——64 位句柄的高 32 位是符号扩展，非零填充。
- `atoi` 在 >INT_MAX 输入上是未定义行为（C 标准 7.22.1）；截断 uint32 后再符号扩展对两种打印形式均无损往返。
- 兜底校验（IsWindow + PID）保证了即使解析出错也只会得到安全的 INVALID_TARGET 拒绝，而非误关窗口。

**结论：推荐保持（已修）。** 可选项：enum 输出改 `%lld` 打印 `(intptr_t)hwnd` 使往返显式无损——但会破坏 Python 工具透传的旧缓存句柄形状，收益不抵迁移成本，不做。

## C9. 双工具链策略：MinGW（x64 默认）+ MSVC /MT（x86）

**项目现状**：x64 = MinGW `-shared -O2 -s -static`（35,840B，仅依赖 KERNEL32/WS2_32/api-ms-win-crt-*）；x86 = MSVC `/MT`（137,216B，CRT 静态 + CFG 表）；build.bat 三模式（mingw 默认/msvc/x86）。

**业界对照**：
- `-static` 成功前提（winpthreads/libgcc 可静态）：本机 ucrt 运行时 + `-s` 剥离，产物接近 MSVC /MT 体积的 1/4——单二进制 Windows 工具的主流做法之一（另一主流即 /MT）。
- /MT 与 /MD 的取舍：目标机（CE 用户的任意 Windows）无 VC redist 保障，静态 CRT 是分发安全解；代价是体积与安全更新不随系统 CRT 走（对本桥无威胁面——它不解析不可信输入到 CRT 字符串函数之外）。
- 工具链差异已文档化：`#pragma comment` 仅 MSVC 生效（MinGW 良性告警）、C 源须纯 ASCII（C4819）、MSYS 路径转换需 `MSYS2_ARG_CONV_EXCL='*'`。

**结论：推荐保持。** x86 无 i686 MinGW，双工具链是环境约束下的最优解；若未来装上 i686 MinGW 可评估统一，但 CFG 将丢失（x86 侧），不建议。

## C10. dll_* fastpath：控制面/数据面分离模式

**项目现状**：`dll_` 前缀方法在 TCP 线程收帧后、入队前拦截就地应答（不碰 Lua 队列）；`poll_age_ms` 心跳把「Lua 忙」与「Lua 冻结」区分开——数据面（CE 主线程）完全冻结时控制面（健康/自省/窗口管理）仍可达。

**业界对照**：
- 控制面/数据面分离是网络工程的根骨模式：**gRPC Health Checking Protocol**（独立于业务方法的标准健康服务，服务挂死时健康检查通道语义仍在）、TCP keepalive（传输层带外活性）、服务器带外管理（iDRAC/iLO，主机死机时管理面可达）。
- 本桥对「控制面能力面」的定义精确：ping（活性）、status（计数+心跳）、enum/dismiss（模态框检测与解除）——恰是数据面冻结时排障所需的最小集，且 dismiss 带类名保护 + force 语义（带外通道的权限必须更严，符合最小权限）。

**结论：推荐保持。** 可选扩展（均需安全审视）：`dll_force_disconnect`（客户端失步时主动断开恢复）——锁步协议下 client 超时自断已覆盖，暂无需求。

## Part II 总对比矩阵

| # | 技术点 | 项目选型 | 业界/学术基准 | 结论 |
|---|---|---|---|---|
| C1 | Lua C API 链接 | 四阶段运行时符号解析 + 优雅降级 | 宿主静态链接场景唯一正解（lua-users/SQLite/Redis Modules 同型） | **推荐保持** |
| C2 | DllMain 纪律 | v3.3.2 起 AllocConsole 延迟初始化 | MS DLL Best Practices："ideal DllMain = empty stub" | **推荐保持**（本轮已修） |
| C3 | Winsock 模型 | select + 锁步单客户端 | 五模型阶梯：select 正是单连接小服务的正确位 | **推荐保持** |
| C4 | 同步原语 | CS(队列) + SRWLOCK(读多写少) + Interlocked(计数) | MS 官方选型表逐条吻合；SRW 争用性能为 CS 约 2x | **推荐保持** |
| C5 | C 层 JSON | ~100 行手写字段提取 + verbatim id 回显 | cJSON 树形过重；jsmn 型用例但引库破坏 id 回显契约 | **推荐保持** |
| C6 | 二进制加固 | x64: ASLR+DEP+HEASLR；x86: +CFG（v3.3.2） | MinGW 2.36+ 默认与 MSVC 默认+显式 CFG；手写 PE 解析需 dumpbin 校准 | **推荐保持**（本轮已修） |
| C7 | 时间源 | GetTickCount + DWORD 模运算 | MS 例外条款：无符号减法回绕安全，前提满足 | **推荐保持** + 可选 GetTickCount64 |
| C8 | HWND 安全 | _atoi64 + 截断符号扩展重建 + 双重校验 | USER 句柄符号扩展 32 位；atoi 溢出是 UB | **推荐保持**（已修） |
| C9 | 双工具链 | MinGW x64（小体积）/ MSVC /MT x86（CFG） | 单二进制分发两主流做法；环境约束最优 | **推荐保持** |
| C10 | fastpath 模式 | 控制面/数据面分离 + poll_age 心跳 | gRPC Health Checking / 带外管理同型 | **推荐保持** |

## Part II 推荐路线

**已完成（2026-10-03，DLL v3.3.1→v3.3.2）**：
1. hwnd 64 位解析（_atoi64 + 截断符号扩展）；双重 closesocket 竞态修复。
2. DllMain 加载器锁纪律：AllocConsole 延迟到首次 dbg_log。
3. x86 构建 `/guard:cf`（CFG）+ 全模式显式 ASLR/DEP 标志；build.bat 固化。

**可选（低优先级）**：
4. GetTickCount64 迁移（消 uptime 49.7 天显示回绕）。
5. enum 输出 `%lld` 化（无损往返显式化）——需同步 Python 侧语义，收益低。

**不建议做**：
- 引入 cJSON/jsmn 到 C 层（破坏 id verbatim 回显、扩大审计面，fastpath 字段太简单用不上）。
- x64 追求 CFG（MinGW 无 Windows CFG 生成能力，硬约束）。
- select → IOCP/WSAEventSelect（单客户端锁步下纯复杂度税）。

## 附 II：Part II 参考来源

- Microsoft Learn：《Dynamic-Link Library Best Practices》（loader lock 禁令清单）、《About Synchronization》（原语选型表）、《Interprocess Communication Between 32-bit and 64-bit Applications》（句柄符号扩展）、GetTickCount/GetTickCount64 API 文档
- MSDN Magazine《Concurrency: Slim Reader/Writer Locks》（SRW vs CS 基准）；MS SRD《Software Defense》系列（CFG 等缓解层次）
- binutils：sourceware bug 19011（MinGW 链接器默认加固史）、2025-04 ld/PE 补丁（默认 DLL characteristics 限定 MinGW）、ld 文档（--dynamicbase/--nxcompat/--high-entropy-va）
- Lua 宿主链接：lua-users.org《Easy Manual Library Load》、StackGuides "call Lua functions from Lua C module without custom .lib"、msys.ch《Lua Integration Guide》（5.4 C API 惯例）
- Winsock 模型：《Windows 核心编程》五模型体系、tsight.io《C Winsock 编程深水区》、cnblogs《Windows Socket I/O 模型》对照表
- C 层 JSON：cJSON/jsmn/mu_json 嵌入式选型对比（hqwc.cn、CSDN STM32 实战、tsight.io cJSON 内存分析）
- C23：ISO/IEC 9899:2024 要点（nullptr/[[nodiscard]]/constexpr 采纳矩阵）
