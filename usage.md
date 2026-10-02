# 《艾尔登法环》CT 汉化项目文档

## 一、项目概述

- **版本**：法环 CT-v4.25.2（基于 zeroblox、SilverCelty 团队的个人汉化）
- **支持**：艾尔登法环 DLC 及 1.17
- **原始作者**：Hexinton 团队（[Nexus Mods - Elden Ring Mod 48](https://www.nexusmods.com/eldenring/mods/48)）
- **初始汉化**：SilverCelty 团队（[Nexus Mods - Elden Ring Mod 74](https://www.nexusmods.com/eldenring/mods/74)）
- **基于版本**：zeroblox 汉化（[Nexus Mods - Elden Ring Mod 8153](https://www.nexusmods.com/eldenring/mods/8153)）
- **致谢名单**：SilverCelty、少年歌行、zchsg、Eric-Vito、Rawlins、MMP、Zeroblox

## 二、参考与致谢

### 修改基础及教程
- [Elden Ring Mod 48 - Hexinton 原始 CT 表](https://www.nexusmods.com/eldenring/mods/48)
- [Elden Ring Mod 74 - SilverCelty 初始汉化](https://www.nexusmods.com/eldenring/mods/74)
- [Bilibili 视频教程 - CT 表修改基础](https://www.bilibili.com/video/BV1Dy4y1F72k/)

### 相关工具参考
- [FLiNG Trainer - 艾尔登法环 DLC 修改器](https://flingtrainer.com/trainer/elden-ring-shadow-of-the-erdtree-trainer-1768067282/)
- [GitHub - EldenRingTool](https://github.com/kh0nsu/EldenRingTool) **内附 TSV**
- [Github - CT TGA](https://github.com/The-Grand-Archives/Elden-Ring-CT-TGA)

### Cheat Engine
- [Cheat Engine 官网](https://www.cheatengine.org/)
- [GitHub - Cheat Engine MCP TCP 桥](https://github.com/HollyZoe/cheatengine-mcp-tcp-bridge)
- [看雪论坛 - CT  MCP 教程](https://bbs.kanxue.com/thread-291832-1.htm)

### 翻译工具及索引资料
- [GitHub - docutranslate 翻译工具](https://github.com/xunbu/docutranslate)
- [GitHub - SoulsModTranslator 魂系模组翻译工具](https://github.com/hhhxiao/SoulsModTranslator)
- [Google 表格 - 索引资料](https://docs.google.com/spreadsheets/u/3/d/e/2PACX-1vQ0LUsF2rBNa55jMq8KNVYFeyxnV_TinvJ9-xh6nzeWhp3OOnPYu_yNCslI2yorP7hFl47Bel4YE82G/pubhtml#)

### 其他
- [GitHub - ctterm](https://github.com/SantaChains/ctterm)
- [GitHub - soul_game_src](https://github.com/SantaChains/soul_game_src)

## 三、自述（使用说明与修改内容）

使用 AI。推荐使用前先存档，且使用前关闭小蓝熊。

### 1. CT 表（Hexinton-v8.0.4.CT）

- **致命修复**：改名启动时表根本点不开。  
  表对“把 `eldenring.exe` 改名成 `start_protected_game.exe`”的兼容只注册了符号，但 `getModuleSize("eldenring.exe")` 返回 `nil` → `[Enable]` → `GetParamBasePtr()` 里 `exebase + exesize` 抛错 → 整个 enable 中止。  
  改为 `getModuleSize("eldenring.exe") or getModuleSize("start_protected_game.exe")`（2 处）。  
  ※ 离线（改名 / 绕 EAC）启动必须修这条，否则表就是点不开。

- **清掉 193 条会让游戏卡死的 DLC 编号**。  
  Choose Grace 里 5/6/7 位的数字（如 `680000:Gravesite Plain`）是“区域×100+序号”的显示标签，不是 warp id。传进去会把 `FieldArea` 打成 `area=0` → 游戏卡死。  
  它们和真实事件 flag 的换算：`flag = 70000 + floor(v/100) + v%100`。

- **新增永久解锁**：`★ Unlock ALL DLC Graces - PERMANENT`。  
  位置：`[Enable] > [Scripts] > [Progression]`（勾选 `[Enable]` 后才显示）。  
  内置 111 条 flag（105 个 DLC 赐福 + 6 个 DLC 地图），写入游戏 flag 状态 → 进存档 → 重开仍在。  
  ※ 表原有的 Unlock/Restore（Before Closing CE）系列是临时的，关 CE 前要还原。

- **补入 32 条实测可用的 DLC 传送点**。  
  Choose Grace，按大区归组；V=已核对落点，~=已解析。

- **其他**：
  - `[Player Status]` 字段偏移过期：`LastGrace +0xB30 → +0xB60`，`TargetGrace +0xB3C → +0xB6C`
  - 失效签名 2 条：`dhitboxhook`（40 48 是双 REX 前缀，非法）、`VfxDebugConstructor`（前导脏字节）→ 用作者注释里的原始汇编当内容锚点重建，已验证唯一
  - 删除 `WorldTalkMan`（全表仅 2 处定义、零引用；删后启动少一行报错）

### 2. MCP 桥（MCP_Server/）

- **新增“签名工具”4 个工具**（桥 4 个 + Python 4 个；工具数 173 → 177）：
  - `set_signature_tokens` / `get_signature_tokens`：签名里写 `{token}`，按游戏 `FileVersion` 从 `sig_tokens.txt` 取值。已接入 `aob_scan` / `aob_scan_module` / `auto_assemble` / `auto_assemble_check`。  
    ※ 以后游戏更新只需改一行 token，不必重写整条签名 —— 这是本表最大的维护痛点。
  - `diagnose_scan_failure`：扫不到时自动三分 —— 内存命中 / 磁盘有而内存没有（= 被 mod 覆盖）/ 磁盘也没有（= 签名写错），并列出疑似 mod 模块
  - `aob_scan_region`：限定地址区间扫描，避免区域外误命中

- **合并重复定义**：`requireProcess`（4 份、3 种签名）、`sanitizeFilename`（2 份、实现不同）各留 1 份。  
  ※ 第 4 份 `requireProcess` 只回布尔、不带错误表，会让其后用 `ok,err` 惯用法的命令返回 `null`。

### 3. 环境上的坑（实测结论）

- **程序化 `loadTable` 会丢记录**：同一张表只装入 10,385 条（原 12,902），连未改动的原始备份也一样 → 必须用 CE 界面 `File → Open` 打开表。
- **CE 里在跑的 bridge 可能不是最新那份**：重载后新功能可用，过一阵又变 `Method not found` → 从补丁文件重新执行，别用 CE 编辑器里的旧文本。
- **mod 与表功能确实会冲突**：`mods/` 下的 `DisableRuneLoss` / `NoStatsRequirement` / `SummonAnywhere` / `RideAnywhere` / `UnlockTheFps` 会顶掉表里对应的 5 条 AOB（同一处代码被 hook 两遍）→ 二选一。

### 4. DLC 传送点编码规律（排查所得）

- `warpId = <世界/地图><gridX 两位><gridZ 两位><2950 + 序号>`
  - 本体大地图前缀 `10`；DLC 大地图前缀 `20`
  - 迷宫用 8 位 `<area><sub><2950 + 序号>`
  - 大地图：每块瓦片的锚点赐福 = 该瓦片上的 `idx 2950`
  - 迷宫：整张图内自 `2950` 起递增（塔之镇 `n=0..3`，石棺大洞 `n=0..4`）
  - `sub` = 同一 `area` 下的子地图号（塔之镇 `20/00`，艾尼尔·伊利姆 `20/01`），必须从游戏读
  - 例：墓地平原 tile(46,40) → `2046402950`；塔之镇第二点 → `20002951`
  ※ 规律只用于解读 / 验证，id 仍需在赐福上休息后从 `GameMan+0xB60` 实采。

## 四、版本信息

**法环 CT-v4.25.2_基于 zeroblox、SilverCelty 团队的个人汉化**  
支持艾尔登法环 DLC 及 1.17

- 原始作者：Hexinton 团队（[Nexus Mods](https://www.nexusmods.com/eldenring/mods/48)）
- 初始汉化：SilverCelty 团队（[Nexus Mods](https://www.nexusmods.com/eldenring/mods/74)）
- 基于版本：zeroblox 汉化（[Nexus Mods](https://www.nexusmods.com/eldenring/mods/8153)）

**致谢名单**：SilverCelty、少年歌行、zchsg、Eric-Vito、Rawlins、MMP、Zeroblox

**更新内容**：4.25.2

