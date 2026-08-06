# ctn — Chat Talk Nonsense · 项目规划书 / Project Planning

> 版本 / Version: `1.0.0`
> 创建日期 / Created: 2026-08-06
> 状态 / Status: 已确认，进入实现阶段 / Confirmed, entering implementation

---

## 1. 项目定位 / Positioning

**中文**
`ctn`（Chat Talk Nonsense）是一款**本地优先**的开发者辅助桌面工具，以**单文件**形态交付。它把日常开发中四件高频但零散的事情收进一个窗口：语法体检、安全体检、文件比对、提示词打磨。核心原则是——**断网也能干活**，联网只是锦上添花。

**English**
`ctn` (Chat Talk Nonsense) is a **local-first** developer utility delivered as a **single file**. It consolidates four high-frequency yet scattered daily tasks into one window: syntax checking, security auditing, file diffing, and prompt refinement. The guiding principle is simple — **it works offline**; the network is a bonus, never a dependency.

---

## 2. 技术选型（已确认）/ Tech Stack (Confirmed)

| 维度 / Dimension | 选型 / Choice | 理由 / Rationale |
|---|---|---|
| 语言 / Language | Python 3.8+ | 跨平台，标准库丰富 / Cross-platform, rich stdlib |
| GUI 框架 / GUI | Tkinter + ttk（标准库）| 零第三方依赖，真正单文件 / Zero deps, truly single-file |
| 交付形态 / Delivery | 单个 `ctn.py`；可选 PyInstaller `--onefile` 打成独立 exe | 双形态，源码可审计 / Dual form, auditable source |
| 语法引擎 / Syntax | Python `ast` + `tokenize` 深度检查；其余语言内置通用规则引擎 | 真实编译级错误 + 广覆盖 / Real compiler-level errors + broad coverage |
| 云端 API / Cloud API | **纯自定义**（URL / Headers / Body 模板 / 响应路径全部用户可配）| 不锁死厂商，任何兼容服务都能接 / Vendor-agnostic |
| 密钥存储 / Secrets | 机器绑定 PBKDF2-HMAC-SHA256 派生 + **AES-256-GCM** | 无需记密码；配置被拷走也解不开 / No password needed; useless if copied |
| 网络层 / Network | `urllib.request`（标准库）| 无 `requests` 依赖 / No `requests` dependency |

> **零第三方依赖硬约束**：AES-256-GCM 采用内置的纯 Python 实现（含 S-box 运行时生成、密钥扩展、GHASH、CTR）。若运行环境恰好装有 `cryptography`，自动切换到原生实现以提升性能。
>
> **Zero-dependency hard constraint**: AES-256-GCM ships as a built-in pure-Python implementation (runtime S-box generation, key expansion, GHASH, CTR). If `cryptography` happens to be installed, it transparently switches to the native backend for speed.

---

## 3. 架构设计 / Architecture

```
ctn.py  (single file)
├─ [L0] Crypto Layer      纯 Python AES-256-GCM + PBKDF2 + 机器指纹
├─ [L1] Config Store      JSON 持久化 · 敏感字段加密 · 原子写入
├─ [L2] i18n Engine       ZH/EN 双语字典 · 运行时热切换 · 观察者刷新
├─ [L3] Theme Engine      Light/Dark 双主题 · ttk.Style 全量重绘
├─ [L4] Analysis Engines
│    ├─ SyntaxEngine      ast/tokenize + 多语言规则引擎
│    ├─ SecurityEngine    5 类风险 · 正则+启发式 · 分级告警
│    ├─ DiffEngine        difflib · 行级/词级 · 报告导出
│    └─ CloudClient       自定义 API 调用 · 占位符渲染 · 响应提取
└─ [L5] GUI Layer         侧边栏导航 · 5 个功能页 · 后台线程 + 队列回传
```

**关键设计约定 / Key conventions**

- 所有耗时操作（云端请求、大文件扫描）走 `threading.Thread`，通过 `queue.Queue` + `after()` 回主线程，界面永不卡死。
- 引擎层与 GUI 层零耦合，引擎均返回结构化 `Finding` 对象，便于后续做 CLI 或单测。
- 所有面向用户的字符串统一走 `T(key)`，杜绝硬编码文案。

---

## 4. 功能模块拆解 / Module Breakdown

### 4.1 语法筛查 / Syntax Check

| 项 | 说明 |
|---|---|
| 本地模式 / Local | **Python**：`compile()` + `ast.parse()` 捕获真实 `SyntaxError`（含真实行号、列号、错误文本、`^` 指示符）；`tokenize` 补充缩进不一致、Tab/Space 混用、行尾空白、超长行。<br>**JS/TS/JSON/YAML/HTML/XML/CSS/SQL/C/C++/Java/Go**：内置规则引擎，检测括号/引号未闭合与错配（带栈式配对追踪，精确定位到"哪一行的哪个括号没关"）、JSON 结构合法性（`json.loads` 真实报错）、YAML 缩进与制表符、HTML 标签未闭合、控制字符、编码异常。 |
| 云端模式 / Cloud | 把源码 + 语言类型塞进用户自定义的请求模板，交给 LLM 做语义级审查（逻辑漏洞、API 误用、可读性），结果与本地结果**分区展示**，不混淆。 |
| 输出 / Output | 表格：`级别 / 行 / 列 / 规则ID / 描述`，双击跳转源码定位，颜色分级（Error 红 / Warning 橙 / Info 蓝）。 |

### 4.2 安全性筛查 / Security Scan

纯本地，五大类，共 40+ 条规则：

1. **敏感信息泄露 / Secret Leakage** — AWS AK/SK、GitHub Token (`ghp_`/`gho_`)、OpenAI `sk-`、Slack、Google API Key、私钥 PEM 块、JWT、硬编码密码/口令、数据库连接串、手机号、身份证号、邮箱。
2. **SQL 注入 / SQL Injection** — 字符串拼接建 SQL（`+` / `%` / f-string / `.format()`）、`execute()` 传入变量拼接、ORM `raw()` 滥用。
3. **恶意/危险代码 / Malicious & Dangerous** — `eval` / `exec` / `compile` 动态执行、`pickle.loads` 反序列化、`os.system` / `subprocess(shell=True)` 命令注入、`__import__` 动态导入、反弹 shell 特征、Base64 大块编码载荷、`document.write` / `innerHTML` XSS 面。
4. **加密与随机性 / Crypto Weakness** — MD5/SHA1 用于口令、`random` 用于安全场景、`ssl` 校验关闭 (`verify=False`)、硬编码 IV/盐、DES/RC4。
5. **路径与文件 / Path & File** — 路径穿越 `../`、`os.path.join` 拼接用户输入、临时文件不安全创建、通配删除。

每条命中输出：**风险等级（严重/高/中/低）+ 行号 + 命中片段（密钥自动脱敏为 `sk-****abcd`）+ 修复建议**。

### 4.3 文件对比 / File Diff

- 左右双栏同步滚动，行号栏独立。
- `difflib.SequenceMatcher` 做行级 opcodes；对 `replace` 块再做**词级细粒度高亮**，精确到"这一行改了哪个词"。
- 统计条：新增 / 删除 / 修改 / 未变 行数，相似度百分比。
- **云端对比**：从配置的 URL 拉取远端文本（`GET`，支持自定义 Header），与本地文件比对，实现"本地 ↔ 云端"双向比较。
- 导出报告：`HTML`（带配色、可直接发人）/ `Markdown` / 统一 `unified diff` 补丁格式。

### 4.4 Agent 提示词优化 / Prompt Optimizer

- 用户在设置页完成 **纯自定义 API** 配置后可用。
- 内置 5 种优化目标（可选）：结构化重写 / 角色与约束强化 / 减少歧义 / 压缩 Token / 生成 Few-shot 示例。
- 界面：上方原始提示词，下方优化结果，中间为"优化目标 + 温度 + 附加要求"控制条。
- 支持一键复制、保存为 `.md`、以及**优化前后 Token 粗估对比**。
- 无网络或未配置时，给出明确的双语引导，而不是干巴巴报错。

### 4.5 设置 / Settings

- **通用**：语言（中文 / English）、主题（浅色 / 深色 / 跟随系统）、字号。
- **云端 API（纯自定义）**：
  - Endpoint URL
  - HTTP Method
  - Headers（JSON，支持 `{api_key}` 占位符）
  - Request Body 模板（JSON，支持 `{prompt}` `{system}` `{model}` `{temperature}` 占位符）
  - Response 提取路径（点号路径，如 `choices.0.message.content`）
  - Timeout / 代理
- **密钥管理**：输入即加密落盘，界面永远只显示掩码；提供"连接测试"按钮。
- **导入 / 导出配置**：导出时可选择是否剥离密钥。

---

## 5. 安全存储方案 / Secret Storage Design

```
机器指纹 = SHA256( 用户名 ∥ 主机名 ∥ 平台 ∥ MAC地址 ∥ 固定盐 )
主密钥   = PBKDF2-HMAC-SHA256( 机器指纹, 随机盐16B, 200000 轮 ) → 32B
密文     = AES-256-GCM( 主密钥, 随机 nonce 12B, 明文 )
落盘格式 = base64( salt ∥ nonce ∥ tag ∥ ciphertext )
```

- 密钥从不明文落盘、从不打印日志、从不出现在导出报告中。
- 配置文件被复制到其他机器 → 机器指纹变化 → 派生密钥不同 → GCM 认证失败 → 拒绝解密并提示重新录入。
- 配置目录：`%APPDATA%\ctn\`（Windows）/ `~/.config/ctn/`（Linux）/ `~/Library/Application Support/ctn/`（macOS）。

---

## 6. 双语与主题 / i18n & Theming

- **双语**：单一 `LANG` 字典，`{key: {"zh": ..., "en": ...}}`。切换语言时遍历已注册控件的 `i18n_key` 属性即时刷新，**无需重启**。覆盖范围包括菜单、按钮、标签、占位符、状态栏、错误提示、导出报告标题、消息框。
- **主题**：两套完整调色板（背景 / 面板 / 边框 / 前景 / 次级前景 / 强调色 / 四级告警色 / diff 三色）。切换时统一重配 `ttk.Style` 与所有 `Text` 组件 tag，包括滚动条与选中态。

---

## 7. 交付物清单 / Deliverables

| 文件 / File | 说明 / Description |
|---|---|
| `ctn.py` | 单文件主程序，零第三方依赖 / Single-file app, zero third-party deps |
| `README.md` | 中英双语说明文档 / Bilingual documentation |
| `index.html` | 商业风格产品展示页（双语 + 深浅色）/ Commercial landing page |
| `build.bat` / `build.sh` | PyInstaller 单 exe 打包脚本（CLI 英文输出）/ Packaging scripts |
| `Planning/Planning.md` | 本文档 / This document |

---

## 8. 实施步骤 / Implementation Steps

1. ✅ 确认技术细节 / Confirm tech details
2. ⬜ 交付本规划书 / Deliver this plan
3. ⬜ 加密层 + 配置层 + i18n + 主题引擎
4. ⬜ 语法引擎 + 安全引擎
5. ⬜ 对比引擎 + 云端客户端 + 提示词优化
6. ⬜ GUI 五页装配
7. ⬜ 自测（语法编译 / 加密往返 / 引擎断言 / GUI 启动）
8. ⬜ README + 展示页 + 打包脚本

---

## 9. 验收标准 / Acceptance Criteria

- [ ] 拔掉网线，语法筛查、安全筛查、本地对比三大功能完全可用。
- [ ] 中英切换即时生效，界面无任何残留未翻译文本。
- [ ] 深浅色切换后，所有区域（含代码区、diff 区、表格）配色一致无死角。
- [ ] 语法错误报告的行号 / 列号与真实位置一致（Python 用真实 `SyntaxError`）。
- [ ] 密钥写入后，配置文件中不含任何明文密钥片段。
- [ ] 配置文件跨机器复制后无法解密，且给出友好双语提示。
- [ ] `python -m py_compile ctn.py` 通过；程序可正常启动并渲染。

---

_Planning by ctn project · 2026-08-06_
