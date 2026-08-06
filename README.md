# ctn · Chat Talk Nonsense

> 一个本地优先、单文件、双语 GUI 工作台：语法 / 安全 / 对比 / 提示词优化。
> A local-first, single-file, bilingual GUI workbench: syntax · security · diff · prompt.

ctn 是一个完全本地运行的中英双语开发者工具,核心功能是给你的代码做体检——把有问题的代码喂进来,告诉你在哪里、有多严重、为什么。所有本地引擎都不联网也能用,云端能力作为可选扩展。

---

## English

### What it does

ctn bundles four frequently-used code review tools into one window:

1. **Syntax check** — finds unmatched brackets, unterminated strings, bad indentation, banned keywords, and style issues across Python / JS / TS / Java / C / C++ / Go / Rust / SQL / shell / PHP / Lua. Switches between **local** (offline) and **cloud** (your own OpenAI-compatible endpoint) modes.
2. **Security scan** — 40+ rules covering leaked secrets, suspicious SQL concatenation, dangerous calls (`eval`, `exec`, `os.system`, `subprocess.shell=True`), weak crypto, unsafe paths, plus Shannon-entropy detection for unknown keys. Hits are colour-graded and auto-masked.
3. **Multi-file diff** — side-by-side compare of two local files **or** two cloud URLs, with row-level + word-level highlighting. Export the result as HTML, Markdown or a unified patch.
4. **Agent prompt optimizer** — paste any prompt, pick optimisation goals (structured rewrite, role, ambiguity, token budget, few-shot), and ctn will re-write it via the custom API you configured in Settings.

Everything else is plumbing: bilingual labels, light / dark theme, machine-bound AES-256-GCM key vault, atomic config writes, async workers, headless CLI.

### Highlights

| Pillar             | What you actually get                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------- |
| **Local-first**    | All four engines run offline. The cloud button is opt-in.                                   |
| **Bilingual**      | Every label, message, button, hint, error, tooltip is shown in zh / en. Hot-swap at runtime.|
| **Themes**         | Light + dark, full token palette, Windows-11 accent bar auto-disabled.                      |
| **Single file**    | `ctn.py` — ~2 000 lines, zero third-party deps. Optional `cryptography` for AES-GCM.        |
| **Encrypted vault**| API keys never touch disk in plain text. PBKDF2-HMAC-SHA256 binds the key to this machine.   |
| **Portable build** | `python ctn.py` or `pyinstaller --onefile ctn.py` → a single `ctn.exe`.                    |

### Quick start

```bash
# run directly (Python 3.8+)
python ctn.py

# one-file build (Nuitka — see "Building a binary" below)
build.bat            # Windows
./build.sh           # macOS / Linux
# → dist/ctn.exe

# CLI (English output only)
python ctn.py --check path/to/file.py
python ctn.py --scan  path/to/file.py --severity high
python ctn.py --diff  a.py b.py --format html --out report.html
python ctn.py --selftest
python ctn.py --version
python ctn.py --help
```

### Settings worth opening first

| Section        | What to fill                                                                                       |
| -------------- | -------------------------------------------------------------------------------------------------- |
| **API**        | Endpoint URL, method, model, key, response-path template (e.g. `choices.0.message.content`).       |
| **Headers**    | JSON for `Authorization: Bearer ...` etc. Tokens are never logged.                                 |
| **Body**       | JSON template. Use `{{prompt}}` `{{system}}` `{{temperature}}` `{{model}}` placeholders.           |
| **Vault**      | Shows backend (pure-Python or `cryptography`), key fingerprint, masked preview of stored secret.   |

### Building a binary

`build.bat` / `build.sh` default to **Nuitka**, not PyInstaller. That is a deliberate choice.

PyInstaller's one-file bootloader is a long-standing antivirus false positive — Windows Defender typically reports it as `Trojan:Win32/Wacatac` and quarantines the exe within seconds of it being written. This was reproduced on the build machine: the 12.5 MB `ctn.exe` appeared, then vanished 3 seconds later. `--onedir` and `--noupx` did not help, because the bootloader binary itself is what gets matched.

Nuitka compiles the Python source down to C and links an ordinary native binary, so there is no shared bootloader signature to trip over.

```bash
build.bat                 # Nuitka (recommended)
build.bat pyinstaller     # PyInstaller, if you prefer it and have an AV exclusion
```

On a clean machine Nuitka will offer to download the MinGW64 toolchain. The build scripts set `NUITKA_CACHE_DIR=E:\SDK\Nuitka\cache` so the toolchain lands off the system drive; override that variable if you want it elsewhere.

If you *do* want to stay on PyInstaller, add a Defender exclusion for the output folder first:

```powershell
Add-MpPreference -ExclusionPath "E:\PC\ctn-tool\dist"
```

Note that this only helps on *your* machine — anyone you send the PyInstaller build to will hit the same false positive.

### Project layout

```
ctn-tool/
├── ctn.py              ← everything (engine, GUI, CLI, tests, vault, i18n, themes)
├── README.md           ← you are here
├── index.html          ← public product landing page (bilingual)
├── build.bat           ← Windows: build ctn.exe (Nuitka by default)
├── build.sh            ← POSIX : build ctn   (Nuitka by default)
├── Planning/Planning.md← design notes, decisions, acceptance criteria
└── dist/ctn.exe        ← build output
```

### Privacy

ctn never sends your code anywhere unless you press the **Cloud** button and have an API configured. Even then, only the active buffer is sent — file system, clipboard, and config never leave the machine.

---

## 中文

### 它能做什么

ctn 把四件开发者常做的事合并到一个窗口里:

1. **语法筛查** — 检测括号不匹配、字符串未闭合、缩进错误、禁用关键字、风格问题,覆盖 Python / JS / TS / Java / C / C++ / Go / Rust / SQL / shell / PHP / Lua。支持 **本地**(完全离线)和 **云端**(你自己配置的 OpenAI 兼容端点)两种模式。
2. **安全筛查** — 40+ 条规则,涵盖密钥泄露、可疑 SQL 拼接、危险调用(`eval` / `exec` / `os.system` / `subprocess.shell=True`)、弱加密、不安全路径,加上针对未知密钥的 Shannon 熵检测。命中按严重度着色,密钥自动脱敏。
3. **多文件对比** — 左右两侧分别支持本地文件或云端 URL,行级 + 词级差异高亮,导出 HTML / Markdown / unified patch 三种格式。
4. **Agent 提示词优化** — 粘贴任意提示词,选择优化目标(结构化改写 / 角色 / 消歧 / token 预算 / few-shot),ctn 通过你在「设置」里配置的 API 帮你改写。

其余都是底座:中英双语标签、浅色 / 深色主题、机器绑定 AES-256-GCM 密钥保险箱、原子化配置写入、后台异步执行、纯命令行模式。

### 卖点一览

| 卖点             | 实际拿到的东西                                                                          |
| ---------------- | --------------------------------------------------------------------------------------- |
| **本地优先**     | 四个引擎全部离线可用,云端按钮是可选的。                                                |
| **中英双语**     | 全部标签、提示、按钮、说明、错误、tooltip 都有 zh / en 两种,运行期热切换。             |
| **双主题**       | 浅色 + 深色,完整 token 调色板,Windows 11 标题栏强调色自动禁用。                       |
| **单文件**       | `ctn.py` 一个文件,~2000 行,零第三方依赖。可选 `cryptography` 加速 AES-GCM。           |
| **加密保险箱**   | API 密钥永不以明文落盘,PBKDF2-HMAC-SHA256 把密钥绑定到当前机器。                       |
| **便携打包**     | `python ctn.py` 直接跑,或用 `build.bat` 编译成单个原生 `ctn.exe`。                     |

### 快速开始

```bash
# 直接运行 (Python 3.8+)
python ctn.py

# 单文件打包 (Nuitka,详见下方「编译成可执行文件」)
build.bat            # Windows
./build.sh           # macOS / Linux
# → dist/ctn.exe

# CLI (输出全部英文)
python ctn.py --check path/to/file.py
python ctn.py --scan  path/to/file.py --severity high
python ctn.py --diff  a.py b.py --format html --out report.html
python ctn.py --selftest
python ctn.py --version
python ctn.py --help
```

### 第一次打开「设置」建议填的东西

| 分区        | 填什么                                                                            |
| ----------- | --------------------------------------------------------------------------------- |
| **API**     | 端点 URL、HTTP 方法、模型名、密钥、响应路径模板(如 `choices.0.message.content`)。 |
| **Headers** | `Authorization: Bearer ...` 等 JSON。令牌永不写日志。                             |
| **Body**    | JSON 模板。占位符支持 `{{prompt}}` `{{system}}` `{{temperature}}` `{{model}}`。   |
| **Vault**   | 显示后端(纯 Python 或 `cryptography`)、密钥指纹、已存密钥的脱敏预览。            |

### 编译成可执行文件

`build.bat` / `build.sh` 默认走 **Nuitka**,不是 PyInstaller。这是刻意选的。

PyInstaller 的 onefile 引导程序是个由来已久的杀软误报源——Windows Defender 通常把它判成 `Trojan:Win32/Wacatac`,exe 刚写到磁盘几秒内就被隔离。这个问题在本项目的构建机上被复现了:12.5 MB 的 `ctn.exe` 生成成功,3 秒后消失。换 `--onedir`、加 `--noupx` 都没用,因为被匹配的是引导程序二进制本身。

Nuitka 把 Python 源码编译成 C 再链接成普通原生二进制,不存在共用的引导程序特征码,自然也就没这个问题。

```bash
build.bat                 # Nuitka (推荐)
build.bat pyinstaller     # 如果你坚持用 PyInstaller 且已加杀软排除项
```

干净机器上 Nuitka 会提示下载 MinGW64 工具链。构建脚本已设 `NUITKA_CACHE_DIR=E:\SDK\Nuitka\cache`,工具链会落在非系统盘;想换位置改这个环境变量即可。

如果你**确实**想继续用 PyInstaller,先给输出目录加 Defender 排除:

```powershell
Add-MpPreference -ExclusionPath "E:\PC\ctn-tool\dist"
```

注意这只对**你自己这台机器**有效——把 PyInstaller 版本发给别人,对方一样会中招。

### 项目结构

```
ctn-tool/
├── ctn.py              ← 全部代码(引擎、GUI、CLI、自检、保险箱、双语、主题)
├── README.md           ← 本文件
├── index.html          ← 公开的产品落地页(中英双语)
├── build.bat           ← Windows: 打包 ctn.exe (默认 Nuitka)
├── build.sh            ← POSIX : 打包 ctn   (默认 Nuitka)
├── Planning/Planning.md← 设计笔记、决策记录、验收标准
└── dist/ctn.exe        ← 构建产物
```

### 隐私

ctn 永远不会把你的代码发到任何地方——除非你主动点 **云端** 按钮并配置好 API。即便如此,发出的也只是当前编辑框内容,不会扫文件系统、不会读剪贴板、不会上传配置文件。

---

## License

MIT.
