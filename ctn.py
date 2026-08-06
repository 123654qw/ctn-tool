#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ctn - Chat Talk Nonsense
========================
A local-first, single-file, bilingual (ZH / EN) developer toolkit.

Features
--------
1. Syntax Check      - local (offline) + cloud (LLM) modes
2. Security Scan     - fully local, 5 risk categories, 40+ rules
3. File Diff         - local <-> local and local <-> cloud, exportable reports
4. Prompt Optimizer  - fully user-configurable API endpoint
5. Settings          - machine-bound AES-256-GCM encrypted secret storage

Zero third-party dependencies. Python 3.8+. Tkinter only.

CLI (English output only):
    python ctn.py --help
    python ctn.py --version
    python ctn.py --check <file>
    python ctn.py --scan <file>
    python ctn.py --diff <fileA> <fileB>

License: MIT
"""

from __future__ import annotations

import ast
import base64
import binascii
import difflib
import getpass
import hashlib
import hmac
import io
import json
import keyword as _kw
import math
import os
import platform
import queue
import re
import socket
import ssl
import sys
import threading
import time
import tokenize
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ETree
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

APP_NAME = "ctn"
APP_FULL = "Chat Talk Nonsense"
APP_VERSION = "1.0.0"
APP_BUILD = "2026.08.06"


# =============================================================================
# SECTION 0 - Pure-Python AES-256-GCM  (no third-party dependency)
# =============================================================================

def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _build_sbox() -> List[int]:
    """Generate the AES S-box at runtime (no hard-coded 256-byte table)."""
    sbox = [0] * 256
    p, q = 1, 1
    while True:
        # p = p * 3 in GF(2^8)
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        # q = q / 3 in GF(2^8)
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q = (q ^ 0x09) & 0xFF
        value = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (value ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
         0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(byte: int) -> int:
    byte <<= 1
    if byte & 0x100:
        byte = (byte ^ 0x1B) & 0xFF
    return byte & 0xFF


class AES256:
    """Minimal AES-256 block cipher (encryption direction only, enough for GCM)."""

    ROUNDS = 14

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES256 requires a 32-byte key")
        self._round_keys = self._expand_key(key)

    @staticmethod
    def _expand_key(key: bytes) -> List[int]:
        nk, nr = 8, AES256.ROUNDS
        words: List[List[int]] = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // nk - 1]
            elif i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            prev = words[i - nk]
            words.append([prev[j] ^ temp[j] for j in range(4)])
        flat: List[int] = []
        for word in words:
            flat.extend(word)
        return flat

    def encrypt_block(self, block: bytes) -> bytes:
        rk = self._round_keys
        state = [block[i] ^ rk[i] for i in range(16)]
        for rnd in range(1, self.ROUNDS):
            state = [_SBOX[b] for b in state]
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            off = rnd * 16
            state = [state[i] ^ rk[off + i] for i in range(16)]
        state = [_SBOX[b] for b in state]
        state = self._shift_rows(state)
        off = self.ROUNDS * 16
        return bytes(state[i] ^ rk[off + i] for i in range(16))

    @staticmethod
    def _shift_rows(state: List[int]) -> List[int]:
        out = [0] * 16
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
        return out

    @staticmethod
    def _mix_columns(state: List[int]) -> List[int]:
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = state[4 * c:4 * c + 4]
            out[4 * c + 0] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            out[4 * c + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            out[4 * c + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            out[4 * c + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
        return out


_GCM_R = 0xE1000000000000000000000000000000


def _gf_mul(x: int, y: int) -> int:
    """Multiplication in GF(2^128) using the GCM bit-reflected convention."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_R
        else:
            v >>= 1
    return z


class AESGCM:
    """AES-256-GCM AEAD built on the pure-Python block cipher above."""

    def __init__(self, key: bytes):
        self._aes = AES256(key)
        self._h = int.from_bytes(self._aes.encrypt_block(b"\x00" * 16), "big")

    def _ghash(self, data: bytes) -> int:
        y = 0
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16].ljust(16, b"\x00")
            y = _gf_mul(y ^ int.from_bytes(chunk, "big"), self._h)
        return y

    def _ctr(self, counter_block: bytes, data: bytes) -> bytes:
        out = bytearray()
        counter = int.from_bytes(counter_block, "big")
        for i in range(0, len(data), 16):
            counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
            stream = self._aes.encrypt_block(counter.to_bytes(16, "big"))
            chunk = data[i:i + 16]
            out.extend(bytes(a ^ b for a, b in zip(chunk, stream)))
        return bytes(out)

    def _tag(self, j0: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        padded = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
        padded += ciphertext + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
        padded += (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
        s = self._ghash(padded)
        e = int.from_bytes(self._aes.encrypt_block(j0), "big")
        return (s ^ e).to_bytes(16, "big")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        j0 = nonce + b"\x00\x00\x00\x01"
        ciphertext = self._ctr(j0, plaintext)
        return ciphertext, self._tag(j0, aad, ciphertext)

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        j0 = nonce + b"\x00\x00\x00\x01"
        expected = self._tag(j0, aad, ciphertext)
        if not hmac.compare_digest(expected, tag):
            raise ValueError("GCM authentication failed")
        return self._ctr(j0, ciphertext)


# Optional fast path: use the `cryptography` package when it happens to exist.
_NATIVE_GCM = None
try:  # pragma: no cover - environment dependent
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _NativeAESGCM  # type: ignore
    _NATIVE_GCM = _NativeAESGCM
except Exception:  # pragma: no cover
    _NATIVE_GCM = None


# =============================================================================
# SECTION 1 - Machine-bound secret vault
# =============================================================================

_VAULT_SALT_TAG = b"ctn-vault-v1"
_PBKDF2_ROUNDS = 200_000


def machine_fingerprint() -> bytes:
    """Stable per-machine identifier. Never leaves this process."""
    parts = []
    try:
        parts.append(getpass.getuser())
    except Exception:
        parts.append("unknown-user")
    try:
        parts.append(socket.gethostname())
    except Exception:
        parts.append("unknown-host")
    parts.append(platform.system())
    parts.append(platform.machine())
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        parts.append("0")
    raw = "\x1f".join(parts).encode("utf-8", "replace") + _VAULT_SALT_TAG
    return hashlib.sha256(raw).digest()


class SecretVault:
    """AES-256-GCM sealed strings, keyed by a machine-bound derived key."""

    PREFIX = "ctnenc:v1:"

    def __init__(self) -> None:
        self._fingerprint = machine_fingerprint()
        self._cache: Dict[bytes, bytes] = {}

    def _derive(self, salt: bytes) -> bytes:
        if salt in self._cache:
            return self._cache[salt]
        key = hashlib.pbkdf2_hmac("sha256", self._fingerprint, salt, _PBKDF2_ROUNDS, dklen=32)
        self._cache[salt] = key
        return key

    def seal(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive(salt)
        data = plaintext.encode("utf-8")
        if _NATIVE_GCM is not None:
            blob = _NATIVE_GCM(key).encrypt(nonce, data, _VAULT_SALT_TAG)
            ciphertext, tag = blob[:-16], blob[-16:]
        else:
            ciphertext, tag = AESGCM(key).encrypt(nonce, data, _VAULT_SALT_TAG)
        payload = salt + nonce + tag + ciphertext
        return self.PREFIX + base64.b64encode(payload).decode("ascii")

    def open(self, sealed: str) -> str:
        if not sealed:
            return ""
        if not sealed.startswith(self.PREFIX):
            # Legacy / plain value - hand it back untouched so nothing is lost.
            return sealed
        try:
            payload = base64.b64decode(sealed[len(self.PREFIX):].encode("ascii"))
        except (binascii.Error, ValueError) as exc:
            raise VaultError("corrupted payload") from exc
        if len(payload) < 44:
            raise VaultError("payload too short")
        salt, nonce, tag, ciphertext = payload[:16], payload[16:28], payload[28:44], payload[44:]
        key = self._derive(salt)
        try:
            if _NATIVE_GCM is not None:
                data = _NATIVE_GCM(key).decrypt(nonce, ciphertext + tag, _VAULT_SALT_TAG)
            else:
                data = AESGCM(key).decrypt(nonce, ciphertext, tag, _VAULT_SALT_TAG)
        except Exception as exc:
            raise VaultError("authentication failed") from exc
        return data.decode("utf-8", "replace")

    def self_test(self) -> bool:
        probe = "ctn-self-test-" + base64.b16encode(os.urandom(6)).decode()
        try:
            return self.open(self.seal(probe)) == probe
        except Exception:
            return False


class VaultError(Exception):
    """Raised when a sealed secret cannot be opened on this machine."""


VAULT = SecretVault()


def mask_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * 8}{value[-keep:]}"


# =============================================================================
# SECTION 2 - Configuration store
# =============================================================================

def config_dir() -> str:
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, APP_NAME)
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/" + APP_NAME)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, APP_NAME)


CONFIG_PATH = os.path.join(config_dir(), "config.json")

DEFAULT_BODY_TEMPLATE = (
    '{\n'
    '  "model": "{model}",\n'
    '  "messages": [\n'
    '    {"role": "system", "content": "{system}"},\n'
    '    {"role": "user", "content": "{prompt}"}\n'
    '  ],\n'
    '  "temperature": {temperature}\n'
    '}'
)

DEFAULT_HEADERS_TEMPLATE = (
    '{\n'
    '  "Content-Type": "application/json",\n'
    '  "Authorization": "Bearer {api_key}"\n'
    '}'
)

DEFAULTS: Dict[str, Any] = {
    "language": "zh",
    "theme": "light",
    "font_size": 10,
    "api_url": "",
    "api_method": "POST",
    "api_headers": DEFAULT_HEADERS_TEMPLATE,
    "api_body": DEFAULT_BODY_TEMPLATE,
    "api_response_path": "choices.0.message.content",
    "api_model": "",
    "api_key": "",          # stored sealed
    "api_timeout": 60,
    "api_proxy": "",
    "diff_remote_url": "",
    "diff_remote_headers": "{}",
    "scan_max_bytes": 4 * 1024 * 1024,
}

SECRET_FIELDS = ("api_key",)


class ConfigStore:
    def __init__(self, path: str = CONFIG_PATH) -> None:
        self.path = path
        self.data: Dict[str, Any] = dict(DEFAULTS)
        self.vault_ok = True
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            return
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        for key, default in DEFAULTS.items():
            if key not in raw:
                continue
            value = raw[key]
            if key in SECRET_FIELDS and isinstance(value, str):
                try:
                    value = VAULT.open(value)
                except VaultError:
                    value = ""
                    self.vault_ok = False
            if isinstance(default, int) and not isinstance(default, bool):
                try:
                    value = int(value)
                except Exception:
                    value = default
            self.data[key] = value

    def save(self) -> Tuple[bool, str]:
        payload: Dict[str, Any] = {}
        for key, value in self.data.items():
            if key in SECRET_FIELDS and isinstance(value, str) and value:
                payload[key] = VAULT.seal(value)
            else:
                payload[key] = value
        payload["_meta"] = {
            "app": APP_NAME,
            "version": APP_VERSION,
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
            try:
                if not sys.platform.startswith("win"):
                    os.chmod(self.path, 0o600)
            except Exception:
                pass
            return True, self.path
        except Exception as exc:
            return False, str(exc)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def export_to(self, path: str, strip_secrets: bool = True) -> Tuple[bool, str]:
        payload = dict(self.data)
        if strip_secrets:
            for key in SECRET_FIELDS:
                payload[key] = ""
        else:
            for key in SECRET_FIELDS:
                if payload.get(key):
                    payload[key] = VAULT.seal(payload[key])
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            return True, path
        except Exception as exc:
            return False, str(exc)

    def import_from(self, path: str) -> Tuple[bool, str]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                return False, "not a JSON object"
            for key in DEFAULTS:
                if key in raw:
                    value = raw[key]
                    if key in SECRET_FIELDS and isinstance(value, str) and value:
                        try:
                            value = VAULT.open(value)
                        except VaultError:
                            value = ""
                    self.data[key] = value
            return True, path
        except Exception as exc:
            return False, str(exc)


# =============================================================================
# SECTION 3 - Bilingual string table
# =============================================================================

LANG: Dict[str, Tuple[str, str]] = {
    # ---- shell -------------------------------------------------------------
    "app.title": ("ctn · 开发者工具箱", "ctn · Developer Toolkit"),
    "app.tagline": ("本地优先 · 断网可用", "Local-first · Works offline"),
    "nav.syntax": ("语法筛查", "Syntax"),
    "nav.security": ("安全筛查", "Security"),
    "nav.diff": ("文件对比", "Diff"),
    "nav.prompt": ("提示词优化", "Prompt"),
    "nav.settings": ("设置", "Settings"),
    "nav.syntax.sub": ("本地 / 云端", "Local / Cloud"),
    "nav.security.sub": ("纯本地扫描", "Fully offline"),
    "nav.diff.sub": ("本地 / 云端", "Local / Cloud"),
    "nav.prompt.sub": ("自定义 API", "Custom API"),
    "nav.settings.sub": ("配置与密钥", "Config & keys"),
    "side.theme.light": ("浅色", "Light"),
    "side.theme.dark": ("深色", "Dark"),
    "side.offline": ("离线就绪", "Offline ready"),

    # ---- shared ------------------------------------------------------------
    "common.open": ("打开文件", "Open File"),
    "common.run": ("开始检查", "Run Check"),
    "common.clear": ("清空", "Clear"),
    "common.copy": ("复制", "Copy"),
    "common.save": ("保存", "Save"),
    "common.browse": ("浏览…", "Browse…"),
    "common.ready": ("就绪", "Ready"),
    "common.running": ("正在处理…", "Working…"),
    "common.error": ("错误", "Error"),
    "common.warning": ("警告", "Warning"),
    "common.info": ("提示", "Notice"),
    "common.success": ("成功", "Success"),
    "common.language": ("语言", "Language"),
    "common.file": ("文件", "File"),
    "common.paste_hint": ("在此粘贴代码，或点击「打开文件」载入",
                          "Paste code here, or click \"Open File\" to load"),
    "common.elapsed": ("耗时 {0} ms", "took {0} ms"),
    "common.lines": ("{0} 行", "{0} lines"),
    "common.copied": ("已复制到剪贴板", "Copied to clipboard"),
    "common.saved": ("已保存至 {0}", "Saved to {0}"),
    "common.no_input": ("没有可处理的内容", "Nothing to process"),
    "common.read_fail": ("读取文件失败：{0}", "Failed to read file: {0}"),
    "common.filter": ("筛选", "Filter"),
    "common.all": ("全部", "All"),
    "common.detail": ("详情", "Detail"),
    "common.suggestion": ("修复建议", "Suggested fix"),
    "common.select_row": ("选中一行以查看详情", "Select a row to see details"),

    # ---- severity ----------------------------------------------------------
    "sev.critical": ("严重", "Critical"),
    "sev.high": ("高危", "High"),
    "sev.medium": ("中危", "Medium"),
    "sev.low": ("低危", "Low"),
    "sev.error": ("错误", "Error"),
    "sev.warning": ("警告", "Warning"),
    "sev.info": ("提示", "Info"),

    # ---- syntax ------------------------------------------------------------
    "syntax.head": ("语法筛查", "Syntax Check"),
    "syntax.desc": ("本地引擎离线可用；云端模式交给你配置的模型做语义级审查。",
                    "The local engine runs offline; cloud mode sends the code to your configured model for semantic review."),
    "syntax.language": ("语言", "Language"),
    "syntax.auto": ("自动识别", "Auto-detect"),
    "syntax.mode.local": ("本地", "Local"),
    "syntax.mode.cloud": ("云端", "Cloud"),
    "syntax.col.sev": ("级别", "Level"),
    "syntax.col.line": ("行", "Line"),
    "syntax.col.col": ("列", "Col"),
    "syntax.col.rule": ("规则", "Rule"),
    "syntax.col.msg": ("说明", "Message"),
    "syntax.clean": ("未发现语法问题 ✓", "No syntax issues found ✓"),
    "syntax.summary": ("{0} 个错误 · {1} 个警告 · {2} 条提示",
                       "{0} errors · {1} warnings · {2} notices"),
    "syntax.cloud.tab": ("云端语义审查", "Cloud Semantic Review"),
    "syntax.cloud.prompt_sys": (
        "你是一名严谨的代码审查员。只输出问题清单，每条包含：行号、严重程度、问题、修复建议。不要复述代码。",
        "You are a rigorous code reviewer. Output only a list of findings; each has line number, severity, issue, and fix. Do not restate the code."),
    "syntax.detected": ("识别为 {0}", "Detected as {0}"),

    # ---- security ----------------------------------------------------------
    "sec.head": ("安全性筛查", "Security Scan"),
    "sec.desc": ("完全本地执行，不上传任何代码。命中的密钥会自动脱敏显示。",
                 "Runs entirely on your machine. Nothing is uploaded. Matched secrets are masked in the report."),
    "sec.col.sev": ("风险", "Risk"),
    "sec.col.line": ("行", "Line"),
    "sec.col.cat": ("类别", "Category"),
    "sec.col.rule": ("规则", "Rule"),
    "sec.col.msg": ("说明", "Finding"),
    "sec.clean": ("未发现安全风险 ✓", "No security risks found ✓"),
    "sec.summary": ("严重 {0} · 高危 {1} · 中危 {2} · 低危 {3}",
                    "Critical {0} · High {1} · Medium {2} · Low {3}"),
    "sec.cat.secret": ("敏感信息", "Secrets"),
    "sec.cat.sqli": ("SQL 注入", "SQL Injection"),
    "sec.cat.danger": ("危险代码", "Dangerous Code"),
    "sec.cat.crypto": ("加密弱点", "Weak Crypto"),
    "sec.cat.path": ("路径与文件", "Path & File"),
    "sec.snippet": ("命中片段", "Matched snippet"),
    "sec.export": ("导出报告", "Export Report"),

    # ---- diff --------------------------------------------------------------
    "diff.head": ("多文件对比", "File Diff"),
    "diff.desc": ("左右两侧可分别来自本地文件或云端地址，支持导出对比报告。",
                  "Either side can come from a local file or a remote URL. Reports are exportable."),
    "diff.left": ("左侧 (A)", "Left (A)"),
    "diff.right": ("右侧 (B)", "Right (B)"),
    "diff.src.local": ("本地", "Local"),
    "diff.src.cloud": ("云端", "Cloud"),
    "diff.url": ("URL", "URL"),
    "diff.fetch": ("拉取", "Fetch"),
    "diff.compare": ("开始对比", "Compare"),
    "diff.added": ("新增 {0}", "+{0} added"),
    "diff.removed": ("删除 {0}", "-{0} removed"),
    "diff.changed": ("修改 {0}", "~{0} changed"),
    "diff.same": ("未变 {0}", "={0} unchanged"),
    "diff.similarity": ("相似度 {0}%", "Similarity {0}%"),
    "diff.identical": ("两侧内容完全一致 ✓", "Both sides are identical ✓"),
    "diff.need_both": ("请先为两侧都提供内容", "Please provide content for both sides"),
    "diff.export.html": ("导出 HTML", "Export HTML"),
    "diff.export.md": ("导出 Markdown", "Export Markdown"),
    "diff.export.patch": ("导出补丁", "Export Patch"),
    "diff.fetching": ("正在拉取远端内容…", "Fetching remote content…"),
    "diff.fetched": ("已拉取 {0} 字节", "Fetched {0} bytes"),
    "diff.report.title": ("ctn 对比报告", "ctn Diff Report"),
    "diff.report.generated": ("生成时间", "Generated"),

    # ---- prompt ------------------------------------------------------------
    "prompt.head": ("Agent 提示词优化", "Agent Prompt Optimizer"),
    "prompt.desc": ("使用你在设置页配置的自定义 API 对提示词进行分析、改写与优化。",
                    "Uses the custom API you configured in Settings to analyse and rewrite your prompt."),
    "prompt.original": ("原始提示词", "Original prompt"),
    "prompt.result": ("优化结果", "Optimized result"),
    "prompt.goal": ("优化目标", "Goal"),
    "prompt.goal.structure": ("结构化重写", "Structured rewrite"),
    "prompt.goal.role": ("角色与约束强化", "Role & constraints"),
    "prompt.goal.clarity": ("消除歧义", "Remove ambiguity"),
    "prompt.goal.compact": ("压缩 Token", "Compress tokens"),
    "prompt.goal.fewshot": ("补充 Few-shot 示例", "Add few-shot examples"),
    "prompt.temperature": ("温度", "Temperature"),
    "prompt.extra": ("附加要求（可选）", "Extra requirements (optional)"),
    "prompt.run": ("优化提示词", "Optimize"),
    "prompt.tokens": ("原始 ≈{0} tokens → 优化后 ≈{1} tokens", "Before ≈{0} tokens → After ≈{1} tokens"),
    "prompt.need_cfg": ("尚未配置 API。请到「设置 → 云端 API」填写接口地址与请求模板。",
                        "No API configured yet. Go to Settings → Cloud API and fill in the endpoint and templates."),
    "prompt.working": ("模型正在思考…", "The model is thinking…"),

    # ---- settings ----------------------------------------------------------
    "set.head": ("设置", "Settings"),
    "set.general": ("通用", "General"),
    "set.api": ("云端 API（完全自定义）", "Cloud API (fully custom)"),
    "set.vault": ("密钥与安全", "Secrets & Security"),
    "set.data": ("配置数据", "Configuration Data"),
    "set.lang": ("界面语言", "Interface language"),
    "set.theme": ("外观主题", "Appearance"),
    "set.font": ("代码字号", "Code font size"),
    "set.api.url": ("接口地址 URL", "Endpoint URL"),
    "set.api.method": ("请求方法", "HTTP method"),
    "set.api.model": ("模型标识", "Model identifier"),
    "set.api.headers": ("请求头模板 (JSON)", "Headers template (JSON)"),
    "set.api.body": ("请求体模板 (JSON)", "Request body template (JSON)"),
    "set.api.path": ("响应提取路径", "Response extraction path"),
    "set.api.key": ("API 密钥", "API key"),
    "set.api.timeout": ("超时（秒）", "Timeout (seconds)"),
    "set.api.proxy": ("代理地址（可选）", "Proxy (optional)"),
    "set.api.placeholders": (
        "可用占位符：{api_key} {model} {prompt} {system} {temperature}；模板中的占位符会自动做 JSON 转义。",
        "Placeholders: {api_key} {model} {prompt} {system} {temperature}. Values are JSON-escaped automatically."),
    "set.api.path_hint": ("点号路径，例如 choices.0.message.content；留空表示返回整个响应文本。",
                          "Dotted path, e.g. choices.0.message.content. Leave empty to return the raw response."),
    "set.test": ("测试连接", "Test connection"),
    "set.test.ok": ("连接成功，模型已返回内容。", "Connected. The model returned content."),
    "set.test.fail": ("连接失败：{0}", "Connection failed: {0}"),
    "set.save": ("保存设置", "Save settings"),
    "set.saved": ("设置已保存", "Settings saved"),
    "set.reset": ("恢复默认", "Restore defaults"),
    "set.reset.confirm": ("确定要恢复所有默认设置吗？此操作会清除已保存的 API 配置。",
                          "Restore all defaults? This clears your saved API configuration."),
    "set.export": ("导出配置", "Export config"),
    "set.import": ("导入配置", "Import config"),
    "set.export.strip": ("导出时剥离密钥", "Strip secrets on export"),
    "set.vault.ok": ("加密自检通过 · AES-256-GCM · 机器绑定密钥",
                     "Vault self-test passed · AES-256-GCM · machine-bound key"),
    "set.vault.fail": ("加密自检未通过，密钥将不会被保存。",
                       "Vault self-test failed; secrets will not be stored."),
    "set.vault.locked": ("检测到无法解密的密钥：配置文件可能来自其他机器，请重新录入 API 密钥。",
                         "Found a secret that cannot be decrypted: the config likely came from another machine. Please re-enter your API key."),
    "set.vault.backend": ("加密后端：{0}", "Crypto backend: {0}"),
    "set.vault.stored": ("当前已保存：{0}", "Currently stored: {0}"),
    "set.vault.empty": ("（未设置）", "(not set)"),
    "set.path": ("配置文件位置", "Config file location"),
    "set.about": ("关于", "About"),
    "set.about.text": (
        "ctn — Chat Talk Nonsense，一个本地优先的单文件开发者工具箱。\n"
        "语法筛查、安全筛查、文件对比三大功能完全离线可用，不会向任何服务器发送你的代码。",
        "ctn — Chat Talk Nonsense, a local-first single-file developer toolkit.\n"
        "Syntax check, security scan and file diff work fully offline; your code never leaves your machine."),

    # ---- network -----------------------------------------------------------
    "net.no_url": ("尚未配置接口地址", "Endpoint URL is not configured"),
    "net.bad_headers": ("请求头模板不是合法 JSON：{0}", "Headers template is not valid JSON: {0}"),
    "net.bad_body": ("请求体模板不是合法 JSON：{0}", "Body template is not valid JSON: {0}"),
    "net.http_error": ("HTTP {0}：{1}", "HTTP {0}: {1}"),
    "net.timeout": ("请求超时", "Request timed out"),
    "net.unreachable": ("无法连接到服务器：{0}", "Cannot reach the server: {0}"),
    "net.bad_path": ("响应中找不到路径 {0}", "Path {0} not found in the response"),
    "net.empty": ("服务器返回了空内容", "The server returned an empty response"),
}


class I18n:
    def __init__(self, lang: str = "zh") -> None:
        self.lang = lang if lang in ("zh", "en") else "zh"
        self._listeners: List[Callable[[], None]] = []

    def set_lang(self, lang: str) -> None:
        if lang not in ("zh", "en") or lang == self.lang:
            return
        self.lang = lang
        for fn in list(self._listeners):
            try:
                fn()
            except Exception:
                pass

    def on_change(self, fn: Callable[[], None]) -> None:
        self._listeners.append(fn)

    def t(self, key: str, *args: Any) -> str:
        pair = LANG.get(key)
        if pair is None:
            return key
        text = pair[0] if self.lang == "zh" else pair[1]
        if args:
            try:
                return text.format(*args)
            except Exception:
                return text
        return text

    def pick(self, zh: str, en: str) -> str:
        return zh if self.lang == "zh" else en


I18N = I18n()
T = I18N.t
P = I18N.pick


# =============================================================================
# SECTION 4 - Theme palettes
# =============================================================================

THEMES: Dict[str, Dict[str, str]] = {
    "light": {
        "bg": "#eef0f4",
        "panel": "#ffffff",
        "panel_alt": "#f7f8fa",
        "sidebar": "#1b1f27",
        "sidebar_fg": "#c9ced8",
        "sidebar_active": "#2a3140",
        "sidebar_active_fg": "#ffffff",
        "border": "#d8dce3",
        "fg": "#1b1f27",
        "fg_dim": "#6a7280",
        "accent": "#2f6bff",
        "accent_fg": "#ffffff",
        "accent_soft": "#e4ecff",
        "code_bg": "#ffffff",
        "code_fg": "#1b1f27",
        "gutter_bg": "#f2f4f7",
        "gutter_fg": "#a3aab5",
        "select": "#cfe0ff",
        "critical": "#b3123a",
        "high": "#d93025",
        "medium": "#c77700",
        "low": "#2f6bff",
        "ok": "#12805c",
        "diff_add": "#e3f7e8",
        "diff_del": "#fdeaec",
        "diff_chg": "#fff6d9",
        "diff_add_word": "#a9e8bb",
        "diff_del_word": "#f7bcc3",
        "row_alt": "#fafbfc",
    },
    "dark": {
        "bg": "#14171d",
        "panel": "#1c2027",
        "panel_alt": "#22262f",
        "sidebar": "#0f1216",
        "sidebar_fg": "#8c94a1",
        "sidebar_active": "#232935",
        "sidebar_active_fg": "#ffffff",
        "border": "#2e343f",
        "fg": "#e4e7ec",
        "fg_dim": "#8c94a1",
        "accent": "#5b8cff",
        "accent_fg": "#0f1216",
        "accent_soft": "#1e2a45",
        "code_bg": "#181c22",
        "code_fg": "#dfe3e9",
        "gutter_bg": "#161a20",
        "gutter_fg": "#5b6472",
        "select": "#2b3d63",
        "critical": "#ff5f7a",
        "high": "#ff7a66",
        "medium": "#e8a33d",
        "low": "#6fa4ff",
        "ok": "#3ecf8e",
        "diff_add": "#12291c",
        "diff_del": "#2e1619",
        "diff_chg": "#2f2a12",
        "diff_add_word": "#1d5334",
        "diff_del_word": "#5f2229",
        "row_alt": "#1f242c",
    },
}


class ThemeManager:
    def __init__(self, name: str = "light") -> None:
        self.name = name if name in THEMES else "light"
        self._listeners: List[Callable[[], None]] = []

    @property
    def c(self) -> Dict[str, str]:
        return THEMES[self.name]

    def set(self, name: str) -> None:
        if name not in THEMES or name == self.name:
            return
        self.name = name
        for fn in list(self._listeners):
            try:
                fn()
            except Exception:
                pass

    def toggle(self) -> None:
        self.set("dark" if self.name == "light" else "light")

    def on_change(self, fn: Callable[[], None]) -> None:
        self._listeners.append(fn)


THEME = ThemeManager()


def ui_font() -> str:
    if sys.platform.startswith("win"):
        return "Microsoft YaHei UI"
    if sys.platform == "darwin":
        return "PingFang SC"
    return "Noto Sans CJK SC"


def code_font() -> str:
    if sys.platform.startswith("win"):
        return "Consolas"
    if sys.platform == "darwin":
        return "Menlo"
    return "DejaVu Sans Mono"


# =============================================================================
# SECTION 5 - Shared analysis primitives
# =============================================================================

SEV_ORDER = {"critical": 0, "error": 1, "high": 1, "warning": 2,
             "medium": 2, "info": 3, "low": 3}


@dataclass
class Finding:
    severity: str
    line: int
    col: int
    rule: str
    zh: str
    en: str
    snippet: str = ""
    fix_zh: str = ""
    fix_en: str = ""
    category: str = ""

    @property
    def message(self) -> str:
        return P(self.zh, self.en)

    @property
    def fix(self) -> str:
        return P(self.fix_zh, self.fix_en)

    def sort_key(self) -> Tuple[int, int, int]:
        return (SEV_ORDER.get(self.severity, 9), self.line, self.col)


EXT_MAP: Dict[str, str] = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".json": "json", ".jsonc": "json",
    ".yaml": "yaml", ".yml": "yaml",
    ".html": "html", ".htm": "html", ".vue": "html",
    ".xml": "xml", ".svg": "xml", ".xsd": "xml",
    ".css": "css", ".scss": "css", ".less": "css",
    ".sql": "sql",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".java": "java", ".cs": "csharp", ".go": "go", ".rs": "rust",
    ".php": "php", ".rb": "ruby", ".swift": "swift", ".kt": "kotlin",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".toml": "toml",
    ".md": "markdown", ".txt": "text", ".log": "text", ".env": "ini",
}

SUPPORTED_LANGS: List[str] = [
    "python", "javascript", "typescript", "json", "yaml", "html", "xml",
    "css", "sql", "c", "cpp", "java", "csharp", "go", "rust", "php",
    "ruby", "shell", "ini", "toml", "markdown", "text",
]


def detect_language(text: str, filename: str = "") -> str:
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in EXT_MAP:
            return EXT_MAP[ext]
        base = os.path.basename(filename).lower()
        if base in ("dockerfile", "makefile"):
            return "text"
    head = text[:4000]
    stripped = head.strip()
    if stripped.startswith("#!"):
        first = stripped.splitlines()[0]
        if "python" in first:
            return "python"
        if "node" in first:
            return "javascript"
        if "sh" in first or "bash" in first:
            return "shell"
    if stripped[:1] in "{[":
        try:
            json.loads(text)
            return "json"
        except Exception:
            pass
    if stripped.startswith("<?xml"):
        return "xml"
    if re.search(r"<!DOCTYPE\s+html|<html[\s>]", head, re.I):
        return "html"
    score = {
        "python": len(re.findall(r"^\s*(def |class |import |from .+ import |elif |print\()", head, re.M)),
        "javascript": len(re.findall(r"(function\s|=>|const |let |var |console\.log|require\()", head)),
        "sql": len(re.findall(r"\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE|JOIN)\b", head, re.I)),
        "css": len(re.findall(r"[.#][\w-]+\s*\{[^}]*:", head)),
        "yaml": len(re.findall(r"^[ \t]*[\w.-]+:\s*(\S.*)?$", head, re.M)) if ":" in head else 0,
        "c": len(re.findall(r"#include\s*<|printf\(|int\s+main\s*\(", head)),
    }
    best = max(score, key=lambda k: score[k])
    return best if score[best] >= 2 else "text"


@dataclass
class ScanProfile:
    line_comments: Tuple[str, ...] = ()
    block_comments: Tuple[Tuple[str, str], ...] = ()
    strings: Tuple[str, ...] = ()
    triple_strings: Tuple[str, ...] = ()
    escape: bool = True
    brackets: bool = True


PROFILES: Dict[str, ScanProfile] = {
    "python": ScanProfile(("#",), (), ("'", '"'), ('"""', "'''")),
    "javascript": ScanProfile(("//",), (("/*", "*/"),), ("'", '"', "`")),
    "typescript": ScanProfile(("//",), (("/*", "*/"),), ("'", '"', "`")),
    "json": ScanProfile((), (), ('"',)),
    "css": ScanProfile((), (("/*", "*/"),), ("'", '"')),
    "sql": ScanProfile(("--",), (("/*", "*/"),), ("'", '"')),
    "c": ScanProfile(("//",), (("/*", "*/"),), ("'", '"')),
    "cpp": ScanProfile(("//",), (("/*", "*/"),), ("'", '"')),
    "java": ScanProfile(("//",), (("/*", "*/"),), ("'", '"')),
    "csharp": ScanProfile(("//",), (("/*", "*/"),), ("'", '"')),
    "go": ScanProfile(("//",), (("/*", "*/"),), ("'", '"', "`")),
    "rust": ScanProfile(("//",), (("/*", "*/"),), ("'", '"')),
    "php": ScanProfile(("//", "#"), (("/*", "*/"),), ("'", '"')),
    "ruby": ScanProfile(("#",), (), ("'", '"')),
    "shell": ScanProfile(("#",), (), ("'", '"')),
    "yaml": ScanProfile(("#",), (), ("'", '"'), brackets=True),
    "ini": ScanProfile((";", "#"), (), ("'", '"'), brackets=False),
    "toml": ScanProfile(("#",), (), ("'", '"')),
    "html": ScanProfile((), (("<!--", "-->"),), ('"', "'"), brackets=False),
    "xml": ScanProfile((), (("<!--", "-->"),), ('"', "'"), brackets=False),
    "markdown": ScanProfile((), (), (), brackets=False),
    "text": ScanProfile((), (), (), brackets=False),
}

BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}
OPEN_BRACKETS = "([{"


@dataclass
class ScanState:
    """Result of the generic lexical sweep: findings plus two masked views.

    code_only - comments blanked, string literals preserved (offsets unchanged)
    stripped  - comments AND string bodies blanked (offsets unchanged)
    """
    findings: List[Finding] = field(default_factory=list)
    code_only: str = ""
    stripped: str = ""


def lexical_scan(text: str, lang: str) -> ScanState:
    """Language-aware sweep: bracket pairing, string/comment termination, masking."""
    profile = PROFILES.get(lang, PROFILES["text"])
    state = ScanState()
    out_nc = list(text)
    out_bare = list(text)
    n = len(text)
    i = 0
    line, col = 1, 1
    stack: List[Tuple[str, int, int]] = []

    def blank(start: int, end: int, comments: bool = True) -> None:
        for k in range(start, min(end, n)):
            if text[k] in "\r\n":
                continue
            out_bare[k] = " "
            if comments:
                out_nc[k] = " "

    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            col = 1
            i += 1
            continue

        # --- line comments ---
        matched = False
        for token in profile.line_comments:
            if text.startswith(token, i):
                end = text.find("\n", i)
                end = n if end == -1 else end
                blank(i, end)
                col += end - i
                i = end
                matched = True
                break
        if matched:
            continue

        # --- block comments ---
        for opener, closer in profile.block_comments:
            if text.startswith(opener, i):
                end = text.find(closer, i + len(opener))
                if end == -1:
                    state.findings.append(Finding(
                        "error", line, col, "LEX001",
                        f"块注释 {opener} 从未使用 {closer} 闭合",
                        f"Block comment {opener} is never closed with {closer}",
                        fix_zh=f"在文件结束前补上 {closer}",
                        fix_en=f"Add the matching {closer} before end of file"))
                    blank(i, n)
                    i = n
                else:
                    end += len(closer)
                    blank(i, end)
                    for k in range(i, end):
                        if text[k] == "\n":
                            line += 1
                            col = 1
                        else:
                            col += 1
                    i = end
                matched = True
                break
        if matched:
            continue

        # --- triple-quoted strings ---
        for delim in profile.triple_strings:
            if text.startswith(delim, i):
                end = text.find(delim, i + len(delim))
                if end == -1:
                    state.findings.append(Finding(
                        "error", line, col, "LEX002",
                        f"三引号字符串 {delim} 未闭合",
                        f"Triple-quoted string {delim} is not terminated",
                        fix_zh=f"补上收尾的 {delim}",
                        fix_en=f"Add the closing {delim}"))
                    blank(i, n)
                    i = n
                else:
                    end += len(delim)
                    blank(i + len(delim), end - len(delim), comments=False)
                    for k in range(i, end):
                        if text[k] == "\n":
                            line += 1
                            col = 1
                        else:
                            col += 1
                    i = end
                matched = True
                break
        if matched:
            continue

        # --- single-line strings ---
        if ch in profile.strings:
            start_line, start_col = line, col
            j = i + 1
            terminated = False
            while j < n:
                cj = text[j]
                if profile.escape and cj == "\\":
                    j += 2
                    continue
                if cj == "\n" and ch != "`":
                    break
                if cj == ch:
                    terminated = True
                    break
                j += 1
            if not terminated:
                state.findings.append(Finding(
                    "error", start_line, start_col, "LEX003",
                    f"字符串起始于此处但没有闭合的 {ch}",
                    f"String starts here but the closing {ch} is missing",
                    snippet=text[i:min(i + 40, n)].split("\n")[0],
                    fix_zh="补上收尾引号，或检查是否有多余的转义反斜杠",
                    fix_en="Add the closing quote, or check for a stray escape backslash"))
                stop = text.find("\n", i)
                stop = n if stop == -1 else stop
                blank(i, stop, comments=False)
                col += stop - i
                i = stop
                continue
            blank(i + 1, j, comments=False)
            for k in range(i, j + 1):
                if text[k] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
            i = j + 1
            continue

        # --- brackets ---
        if profile.brackets:
            if ch in OPEN_BRACKETS:
                stack.append((ch, line, col))
            elif ch in BRACKET_PAIRS:
                want = BRACKET_PAIRS[ch]
                if not stack:
                    state.findings.append(Finding(
                        "error", line, col, "LEX004",
                        f"多余的右括号 '{ch}'，找不到与之配对的 '{want}'",
                        f"Unexpected closing bracket '{ch}' with no matching '{want}'",
                        fix_zh="删除这个括号，或补上前面缺失的左括号",
                        fix_en="Remove it, or add the missing opening bracket earlier"))
                elif stack[-1][0] != want:
                    got, gl, gc = stack.pop()
                    state.findings.append(Finding(
                        "error", line, col, "LEX005",
                        f"括号错配：第 {gl} 行第 {gc} 列的 '{got}' 被 '{ch}' 关闭",
                        f"Bracket mismatch: '{got}' opened at line {gl}, col {gc} is closed by '{ch}'",
                        fix_zh="检查括号嵌套顺序是否写反",
                        fix_en="Check the nesting order of your brackets"))
                else:
                    stack.pop()
        col += 1
        i += 1

    for got, gl, gc in stack:
        closer = {"(": ")", "[": "]", "{": "}"}[got]
        state.findings.append(Finding(
            "error", gl, gc, "LEX006",
            f"左括号 '{got}' 从未闭合（缺少 '{closer}'）",
            f"Opening bracket '{got}' is never closed (missing '{closer}')",
            fix_zh=f"在合适位置补上 '{closer}'",
            fix_en=f"Add the matching '{closer}'"))

    state.code_only = "".join(out_nc)
    state.stripped = "".join(out_bare)
    return state


# =============================================================================
# SECTION 6 - Syntax engine
# =============================================================================

_PY_MSG_RULES: List[Tuple[str, str]] = [
    (r"^invalid syntax\. Perhaps you forgot a comma\?$", "无效语法：这里可能少了一个逗号"),
    (r"^invalid syntax$", "无效的语法"),
    (r"^'(.+)' was never closed$", "括号 '{0}' 从未闭合"),
    (r"^closing parenthesis '(.+)' does not match opening parenthesis '(.+)'.*$",
     "右括号 '{0}' 与左括号 '{1}' 不匹配"),
    (r"^unmatched '(.+)'$", "多余的 '{0}'，找不到配对的左括号"),
    (r"^unexpected EOF while parsing$", "解析时遇到意外的文件结尾，可能有语句块未写完"),
    (r"^EOL while scanning string literal$", "字符串未闭合就到了行尾"),
    (r"^unterminated string literal \(detected at line (\d+)\)$", "第 {0} 行的字符串未闭合"),
    (r"^unterminated triple-quoted string literal \(detected at line (\d+)\)$",
     "第 {0} 行的三引号字符串未闭合"),
    (r"^EOF in multi-line statement$", "多行语句在结束前就到了文件末尾"),
    (r"^expected ':'$", "此处缺少冒号 ':'"),
    (r"^expected an indented block.*$", "此处需要一个缩进的代码块"),
    (r"^unexpected indent$", "意外的缩进，这一行不该缩进"),
    (r"^unexpected unindent$", "意外的反缩进"),
    (r"^unindent does not match any outer indentation level$", "反缩进层级与任何外层缩进都对不上"),
    (r"^inconsistent use of tabs and spaces in indentation$", "缩进中混用了 Tab 与空格"),
    (r"^invalid character '(.+)' \(U\+(\w+)\)$", "非法字符 '{0}'（U+{1}），常见于误用中文全角符号"),
    (r"^invalid non-printable character U\+(\w+)$", "存在不可打印字符 U+{0}"),
    (r"^cannot assign to (.+)$", "不能对 {0} 赋值"),
    (r"^leading zeros in decimal integer literals are not permitted.*$", "十进制整数不允许有前导零"),
    (r"^Missing parentheses in call to '(.+)'.*$", "调用 '{0}' 时缺少括号（这是 Python 2 的写法）"),
    (r"^duplicate argument '(.+)' in function definition$", "函数定义中参数 '{0}' 重复"),
    (r"^positional argument follows keyword argument.*$", "位置参数不能写在关键字参数后面"),
    (r"^'(return|yield|break|continue|await)' outside .*$", "'{0}' 出现在不允许使用它的位置"),
    (r"^f-string: (.+)$", "f-string 错误：{0}"),
    (r"^too many statically nested blocks$", "静态嵌套的代码块层级过深"),
]
_PY_MSG_COMPILED = [(re.compile(p), z) for p, z in _PY_MSG_RULES]


def translate_py_error(msg: str) -> str:
    for rx, zh in _PY_MSG_COMPILED:
        m = rx.match(msg)
        if m:
            try:
                return zh.format(*m.groups())
            except Exception:
                return zh
    return f"语法错误：{msg}"


FULLWIDTH_PUNCT = {
    "，": ",", "。": ".", "；": ";", "：": ":", "（": "(", "）": ")",
    "【": "[", "】": "]", "｛": "{", "｝": "}", "“": '"', "”": '"',
    "‘": "'", "’": "'", "！": "!", "？": "?", "、": ",", "《": "<",
    "》": ">", "％": "%", "＋": "+", "－": "-", "＝": "=", "＊": "*",
    "／": "/", "＼": "\\", "｜": "|", "＆": "&", "＃": "#", "＠": "@",
}

PY_BUILTIN_NAMES = {
    "list", "dict", "set", "str", "int", "float", "bool", "tuple", "type",
    "id", "input", "print", "len", "max", "min", "sum", "map", "filter",
    "range", "object", "bytes", "next", "iter", "hash", "dir", "vars",
    "file", "format", "open", "compile", "eval", "exec", "all", "any",
}


class SyntaxEngine:
    """Offline syntax analysis. Real errors, real line numbers."""

    MAX_LINE = 120

    def analyse(self, text: str, lang: str) -> List[Finding]:
        findings: List[Finding] = []
        if not text.strip():
            return findings

        findings.extend(self._encoding_checks(text))

        if lang == "python":
            findings.extend(self._python(text))
        elif lang == "json":
            findings.extend(self._json(text))
        elif lang in ("html", "xml"):
            findings.extend(self._markup(text, lang))
        elif lang == "yaml":
            findings.extend(self._yaml(text))
        else:
            findings.extend(lexical_scan(text, lang).findings)
            if lang == "css":
                findings.extend(self._css(text))
            elif lang == "sql":
                findings.extend(self._sql(text))
            elif lang in ("javascript", "typescript"):
                findings.extend(self._javascript(text))

        findings.extend(self._style(text, lang))
        findings.sort(key=lambda f: f.sort_key())
        return findings

    # -- generic -------------------------------------------------------------
    @staticmethod
    def _encoding_checks(text: str) -> List[Finding]:
        out: List[Finding] = []
        if text.startswith("\ufeff"):
            out.append(Finding("warning", 1, 1, "ENC001",
                               "文件以 UTF-8 BOM 开头，部分解释器会因此报错",
                               "File starts with a UTF-8 BOM, which breaks some interpreters",
                               fix_zh="用无 BOM 的 UTF-8 重新保存",
                               fix_en="Re-save the file as UTF-8 without BOM"))
        for idx, raw in enumerate(text.splitlines(), 1):
            for ch in raw:
                if ch in ("\t",):
                    continue
                cat = unicodedata.category(ch)
                if cat == "Cc" or cat == "Cf":
                    out.append(Finding("error", idx, raw.index(ch) + 1, "ENC002",
                                       f"第 {idx} 行含有不可见控制字符 U+{ord(ch):04X}",
                                       f"Line {idx} contains invisible control character U+{ord(ch):04X}",
                                       fix_zh="删除该字符后重新保存",
                                       fix_en="Delete the character and save again"))
                    break
        if "\r\n" in text and re.search(r"(?<!\r)\n", text):
            out.append(Finding("info", 1, 1, "ENC003",
                               "文件中混用了 CRLF 与 LF 换行符",
                               "The file mixes CRLF and LF line endings",
                               fix_zh="统一为一种换行符（建议 LF）",
                               fix_en="Normalise to a single style (LF recommended)"))
        return out

    def _style(self, text: str, lang: str) -> List[Finding]:
        out: List[Finding] = []
        lines = text.splitlines()
        indent_styles = set()
        for idx, raw in enumerate(lines, 1):
            if len(raw) > self.MAX_LINE:
                out.append(Finding("info", idx, self.MAX_LINE + 1, "STY001",
                                   f"第 {idx} 行过长（{len(raw)} 字符，建议不超过 {self.MAX_LINE}）",
                                   f"Line {idx} is long ({len(raw)} chars, recommended max {self.MAX_LINE})",
                                   fix_zh="拆分为多行以提升可读性",
                                   fix_en="Split it across multiple lines"))
            if raw != raw.rstrip() and raw.strip():
                out.append(Finding("info", idx, len(raw.rstrip()) + 1, "STY002",
                                   f"第 {idx} 行行尾有多余空白",
                                   f"Line {idx} has trailing whitespace",
                                   fix_zh="删除行尾空白字符",
                                   fix_en="Strip the trailing whitespace"))
            lead = raw[:len(raw) - len(raw.lstrip())]
            if lead:
                if "\t" in lead and " " in lead:
                    out.append(Finding("warning", idx, 1, "STY003",
                                       f"第 {idx} 行缩进混用了 Tab 与空格",
                                       f"Line {idx} mixes tabs and spaces in its indentation",
                                       fix_zh="统一使用空格或 Tab 之一",
                                       fix_en="Use either tabs or spaces consistently"))
                indent_styles.add("tab" if lead[0] == "\t" else "space")
        if len(indent_styles) > 1:
            out.append(Finding("info", 1, 1, "STY004",
                               "文件中同时存在 Tab 缩进与空格缩进的行",
                               "The file contains both tab-indented and space-indented lines",
                               fix_zh="全文统一缩进风格",
                               fix_en="Unify the indentation style across the file"))
        if text and not text.endswith("\n"):
            out.append(Finding("info", max(1, len(lines)), 1, "STY005",
                               "文件末尾缺少换行符",
                               "File does not end with a newline",
                               fix_zh="在文件末尾补一个换行",
                               fix_en="Add a trailing newline"))
        if lang not in ("markdown", "text"):
            masked = lexical_scan(text, lang).stripped if lang in PROFILES else text
            for idx, raw in enumerate(masked.splitlines(), 1):
                for pos, ch in enumerate(raw, 1):
                    if ch in FULLWIDTH_PUNCT:
                        out.append(Finding("error", idx, pos, "STY006",
                                           f"第 {idx} 行使用了全角符号 '{ch}'，应为半角 '{FULLWIDTH_PUNCT[ch]}'",
                                           f"Line {idx} uses full-width '{ch}'; it should be ASCII '{FULLWIDTH_PUNCT[ch]}'",
                                           fix_zh=f"把 '{ch}' 换成 '{FULLWIDTH_PUNCT[ch]}'",
                                           fix_en=f"Replace '{ch}' with '{FULLWIDTH_PUNCT[ch]}'"))
                        break
        return out

    # -- python --------------------------------------------------------------
    def _python(self, text: str) -> List[Finding]:
        out: List[Finding] = []
        src = text.replace("\r\n", "\n").replace("\r", "\n")
        tree: Optional[ast.AST] = None
        try:
            tree = compile(src, "<ctn>", "exec", ast.PyCF_ONLY_AST)
        except SyntaxError as exc:
            line = exc.lineno or 1
            col = exc.offset or 1
            raw_msg = exc.msg or "syntax error"
            snippet = (exc.text or "").rstrip("\n")
            out.append(Finding("error", line, col, "PY000",
                               translate_py_error(raw_msg),
                               f"Syntax error: {raw_msg}",
                               snippet=snippet,
                               fix_zh="按报错位置检查该行及其上一行",
                               fix_en="Inspect the reported line and the one before it"))
            return out
        except ValueError as exc:
            out.append(Finding("error", 1, 1, "PY001", f"源码无法编译：{exc}",
                               f"Source cannot be compiled: {exc}"))
            return out

        try:
            list(tokenize.generate_tokens(io.StringIO(src).readline))
        except tokenize.TokenError as exc:
            out.append(Finding("warning", 1, 1, "PY002",
                               f"词法分析未完成：{exc.args[0]}",
                               f"Tokenizer stopped early: {exc.args[0]}"))
        except IndentationError as exc:
            out.append(Finding("error", exc.lineno or 1, exc.offset or 1, "PY003",
                               translate_py_error(exc.msg or ""),
                               f"Indentation error: {exc.msg}"))

        if tree is not None:
            out.extend(self._python_ast(tree, src))
        return out

    def _python_ast(self, tree: ast.AST, src: str) -> List[Finding]:
        out: List[Finding] = []
        lines = src.splitlines()

        def snip(node: ast.AST) -> str:
            ln = getattr(node, "lineno", 0)
            return lines[ln - 1].strip() if 0 < ln <= len(lines) else ""

        imported: Dict[str, Tuple[int, int]] = {}
        used: set = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imported[name] = (node.lineno, node.col_offset + 1)
            elif isinstance(node, ast.ImportFrom):
                if node.module == "__future__":
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        out.append(Finding("warning", node.lineno, node.col_offset + 1, "PY010",
                                           "使用了通配导入 `from ... import *`，会污染命名空间",
                                           "Wildcard import `from ... import *` pollutes the namespace",
                                           snippet=snip(node),
                                           fix_zh="显式列出需要导入的名字",
                                           fix_en="List the names you actually need"))
                        continue
                    name = alias.asname or alias.name
                    imported[name] = (node.lineno, node.col_offset + 1)
            elif isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                base = node
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    used.add(base.id)

            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    out.append(Finding("warning", node.lineno, node.col_offset + 1, "PY011",
                                       "裸 except 会吞掉 KeyboardInterrupt 等所有异常",
                                       "A bare `except` swallows every exception, including KeyboardInterrupt",
                                       snippet=snip(node),
                                       fix_zh="改成 `except Exception:` 或捕获具体异常类型",
                                       fix_en="Use `except Exception:` or catch a specific type"))
                body = node.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    out.append(Finding("warning", body[0].lineno, body[0].col_offset + 1, "PY012",
                                       "异常被静默吞掉（except 块只有 pass）",
                                       "Exception is silently swallowed (the except block only contains `pass`)",
                                       fix_zh="至少记录日志，或注释说明为什么可以忽略",
                                       fix_en="Log it, or add a comment explaining why it is safe to ignore"))

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        out.append(Finding("warning", default.lineno, default.col_offset + 1, "PY013",
                                           f"函数 `{node.name}` 使用了可变对象作为默认参数，会在多次调用间共享",
                                           f"Function `{node.name}` uses a mutable default argument shared across calls",
                                           snippet=snip(default),
                                           fix_zh="改成 None，并在函数体内初始化",
                                           fix_en="Use None and initialise inside the function body"))
                if node.name in PY_BUILTIN_NAMES:
                    out.append(Finding("info", node.lineno, node.col_offset + 1, "PY014",
                                       f"函数名 `{node.name}` 覆盖了同名内置函数",
                                       f"Function name `{node.name}` shadows a builtin",
                                       fix_zh="换一个不冲突的名字",
                                       fix_en="Pick a non-conflicting name"))

            if isinstance(node, ast.Compare):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comparator, ast.Constant) \
                            and comparator.value is None:
                        out.append(Finding("warning", node.lineno, node.col_offset + 1, "PY015",
                                           "与 None 比较应使用 `is` / `is not` 而不是 `==` / `!=`",
                                           "Compare with None using `is` / `is not`, not `==` / `!=`",
                                           snippet=snip(node),
                                           fix_zh="改写为 `x is None` 或 `x is not None`",
                                           fix_en="Rewrite as `x is None` or `x is not None`"))

            if isinstance(node, ast.Assert) and isinstance(node.test, ast.Tuple) and node.test.elts:
                out.append(Finding("error", node.lineno, node.col_offset + 1, "PY016",
                                   "assert 后面跟了元组，条件将永远为真",
                                   "`assert` on a tuple is always true",
                                   snippet=snip(node),
                                   fix_zh="去掉多余的括号",
                                   fix_en="Remove the extra parentheses"))

            if isinstance(node, ast.Dict):
                seen: Dict[Any, int] = {}
                for key in node.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, (str, int, float, bool)):
                        if key.value in seen:
                            out.append(Finding("warning", key.lineno, key.col_offset + 1, "PY017",
                                               f"字典中键 {key.value!r} 重复，后者会覆盖前者",
                                               f"Duplicate dict key {key.value!r}; the later one wins",
                                               fix_zh="删除重复的键",
                                               fix_en="Remove the duplicate key"))
                        else:
                            seen[key.value] = key.lineno

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                body = getattr(node, "body", [])
                for idx, stmt in enumerate(body[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        nxt = body[idx + 1]
                        out.append(Finding("warning", nxt.lineno, nxt.col_offset + 1, "PY018",
                                           "这一行永远不会被执行（前面已经 return/raise/break）",
                                           "Unreachable code: the previous statement always exits",
                                           snippet=snip(nxt),
                                           fix_zh="删除死代码，或调整控制流",
                                           fix_en="Delete the dead code or fix the control flow"))
                        break

        for name, (ln, col) in imported.items():
            if name not in used and name != "_":
                out.append(Finding("info", ln, col, "PY019",
                                   f"导入的 `{name}` 在文件中未被使用",
                                   f"Imported name `{name}` is never used",
                                   fix_zh="删除无用的导入",
                                   fix_en="Remove the unused import"))
        return out

    # -- json ----------------------------------------------------------------
    @staticmethod
    def _json(text: str) -> List[Finding]:
        out: List[Finding] = []
        try:
            json.loads(text)
            return out
        except json.JSONDecodeError as exc:
            out.append(Finding("error", exc.lineno, exc.colno, "JSON001",
                               f"JSON 解析失败：{exc.msg}（第 {exc.lineno} 行第 {exc.colno} 列）",
                               f"JSON parse error: {exc.msg} (line {exc.lineno}, column {exc.colno})",
                               snippet=text.splitlines()[exc.lineno - 1].strip()
                               if 0 < exc.lineno <= len(text.splitlines()) else "",
                               fix_zh="常见原因：多余的逗号、使用了单引号、键没有加双引号、注释未被允许",
                               fix_en="Common causes: trailing comma, single quotes, unquoted keys, comments"))
        except Exception as exc:
            out.append(Finding("error", 1, 1, "JSON002", f"JSON 无法解析：{exc}",
                               f"JSON cannot be parsed: {exc}"))
        if re.search(r",\s*[}\]]", text):
            m = re.search(r",\s*[}\]]", text)
            ln = text[:m.start()].count("\n") + 1
            out.append(Finding("error", ln, 1, "JSON003",
                               "存在多余的尾随逗号，标准 JSON 不允许",
                               "Trailing comma found; standard JSON does not allow it",
                               fix_zh="删除该逗号",
                               fix_en="Remove that comma"))
        return out

    # -- markup --------------------------------------------------------------
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                 "link", "meta", "param", "source", "track", "wbr", "!doctype"}

    def _markup(self, text: str, lang: str) -> List[Finding]:
        out: List[Finding] = list(lexical_scan(text, lang).findings)
        if lang == "xml":
            try:
                ETree.fromstring(text)
            except ETree.ParseError as exc:
                ln, col = getattr(exc, "position", (1, 1))
                out.append(Finding("error", ln, col + 1, "XML001",
                                   f"XML 解析失败：{exc.msg if hasattr(exc, 'msg') else exc}",
                                   f"XML parse error: {exc}",
                                   fix_zh="检查标签闭合与实体转义",
                                   fix_en="Check tag closure and entity escaping"))
                return out
        stack: List[Tuple[str, int]] = []
        for match in re.finditer(r"<\s*(/?)\s*([A-Za-z!][\w:.-]*)([^>]*?)(/?)\s*>", text):
            closing, name, attrs, self_close = match.groups()
            line = text[:match.start()].count("\n") + 1
            low = name.lower()
            if low.startswith("!"):
                continue
            if self_close == "/" or (lang == "html" and low in self.VOID_TAGS):
                continue
            if closing:
                if not stack:
                    out.append(Finding("error", line, 1, "TAG001",
                                       f"第 {line} 行的 </{name}> 没有对应的开始标签",
                                       f"Closing tag </{name}> at line {line} has no matching opening tag",
                                       fix_zh="删除该闭合标签或补上开始标签",
                                       fix_en="Remove it or add the opening tag"))
                elif stack[-1][0] != low:
                    open_name, open_line = stack.pop()
                    out.append(Finding("error", line, 1, "TAG002",
                                       f"标签交叉：第 {open_line} 行的 <{open_name}> 被 </{name}> 关闭",
                                       f"Tag mismatch: <{open_name}> opened at line {open_line} closed by </{name}>",
                                       fix_zh="检查标签嵌套顺序",
                                       fix_en="Check the nesting order"))
                else:
                    stack.pop()
            else:
                stack.append((low, line))
        for name, line in stack:
            out.append(Finding("error", line, 1, "TAG003",
                               f"第 {line} 行的 <{name}> 从未闭合",
                               f"<{name}> opened at line {line} is never closed",
                               fix_zh=f"补上 </{name}>",
                               fix_en=f"Add the matching </{name}>"))
        if lang == "html" and not re.search(r"<html[\s>]", text, re.I) and "<body" in text.lower():
            out.append(Finding("info", 1, 1, "TAG004",
                               "文档包含 <body> 但缺少 <html> 根元素",
                               "Document has <body> but no <html> root element",
                               fix_zh="补全 HTML 文档结构",
                               fix_en="Complete the HTML document structure"))
        return out

    # -- yaml ----------------------------------------------------------------
    @staticmethod
    def _yaml(text: str) -> List[Finding]:
        out: List[Finding] = []
        indents: List[Tuple[int, int]] = []
        seen_keys: Dict[Tuple[int, str], int] = {}
        for idx, raw in enumerate(text.splitlines(), 1):
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            lead = raw[:len(raw) - len(raw.lstrip())]
            if "\t" in lead:
                out.append(Finding("error", idx, lead.index("\t") + 1, "YAML001",
                                   f"第 {idx} 行缩进使用了 Tab，YAML 规范禁止用 Tab 缩进",
                                   f"Line {idx} indents with a tab; YAML forbids tabs for indentation",
                                   fix_zh="改用空格缩进",
                                   fix_en="Use spaces instead"))
            depth = len(lead)
            indents.append((idx, depth))
            body = raw.strip()
            m = re.match(r"^-?\s*([\w.\-\"']+)\s*:(.*)$", body)
            if m:
                key, rest = m.group(1), m.group(2)
                if rest and not rest.startswith(" ") and not rest.startswith("\t"):
                    out.append(Finding("error", idx, len(lead) + len(key) + 2, "YAML002",
                                       f"第 {idx} 行冒号后缺少空格（`key: value` 中间必须有空格）",
                                       f"Line {idx}: a space is required after the colon (`key: value`)",
                                       fix_zh="在冒号后补一个空格",
                                       fix_en="Add a space after the colon"))
                sig = (depth, key)
                if sig in seen_keys:
                    out.append(Finding("warning", idx, len(lead) + 1, "YAML003",
                                       f"键 `{key}` 在同一层级重复（首次出现在第 {seen_keys[sig]} 行）",
                                       f"Duplicate key `{key}` at the same level (first seen on line {seen_keys[sig]})",
                                       fix_zh="重命名或删除重复项",
                                       fix_en="Rename or remove the duplicate"))
                else:
                    seen_keys[sig] = idx
            if body.count('"') % 2 or body.count("'") % 2:
                if not re.search(r"#.*['\"]", body):
                    out.append(Finding("warning", idx, 1, "YAML004",
                                       f"第 {idx} 行引号数量为奇数，可能有未闭合的字符串",
                                       f"Line {idx} has an odd number of quotes; a string may be unterminated",
                                       fix_zh="检查引号是否成对",
                                       fix_en="Check that quotes are balanced"))
        widths = sorted({d for _, d in indents if d > 0})
        if widths:
            unit = widths[0]
            if unit and any(d % unit for _, d in indents if d):
                bad = next(i for i, d in indents if d and d % unit)
                out.append(Finding("warning", bad, 1, "YAML005",
                                   f"缩进宽度不一致（基准为 {unit} 空格）",
                                   f"Inconsistent indentation width (base unit is {unit} spaces)",
                                   fix_zh="统一每级缩进的空格数",
                                   fix_en="Use a consistent number of spaces per level"))
        return out

    # -- css / sql / js ------------------------------------------------------
    @staticmethod
    def _css(text: str) -> List[Finding]:
        out: List[Finding] = []
        for block in re.finditer(r"\{([^{}]*)\}", text):
            body = block.group(1)
            start_line = text[:block.start()].count("\n") + 1
            for offset, decl in enumerate(body.split("\n")):
                stripped = decl.strip()
                if not stripped or stripped.startswith("/*"):
                    continue
                if ":" in stripped and not stripped.endswith((";", "{", "}", ",")):
                    nxt = body.split("\n")[offset + 1].strip() if offset + 1 < len(body.split("\n")) else ""
                    if nxt and not nxt.startswith("}"):
                        out.append(Finding("warning", start_line + offset, len(decl) + 1, "CSS001",
                                           f"第 {start_line + offset} 行的声明可能缺少分号",
                                           f"Declaration on line {start_line + offset} may be missing a semicolon",
                                           snippet=stripped,
                                           fix_zh="在声明末尾补上 `;`",
                                           fix_en="Append `;` to the declaration"))
        return out

    @staticmethod
    def _sql(text: str) -> List[Finding]:
        out: List[Finding] = []
        upper = text.upper()
        for kw, need in (("SELECT", "FROM"), ("INSERT INTO", "VALUES"), ("UPDATE", "SET")):
            if kw in upper and need not in upper:
                ln = upper[:upper.index(kw)].count("\n") + 1
                out.append(Finding("warning", ln, 1, "SQL001",
                                   f"语句使用了 {kw} 但没有找到 {need} 子句",
                                   f"Statement uses {kw} but no {need} clause was found",
                                   fix_zh="补全 SQL 语句结构",
                                   fix_en="Complete the SQL statement"))
        if re.search(r"\b(DELETE\s+FROM|UPDATE)\b", upper) and not re.search(r"\bWHERE\b", upper):
            ln = upper[:re.search(r"\b(DELETE\s+FROM|UPDATE)\b", upper).start()].count("\n") + 1
            out.append(Finding("error", ln, 1, "SQL002",
                               "DELETE / UPDATE 语句没有 WHERE 条件，将影响整张表",
                               "DELETE / UPDATE without a WHERE clause affects the whole table",
                               fix_zh="补上 WHERE 条件，或确认这就是你想要的",
                               fix_en="Add a WHERE clause, or confirm this is intentional"))
        return out

    @staticmethod
    def _javascript(text: str) -> List[Finding]:
        out: List[Finding] = []
        masked = lexical_scan(text, "javascript").stripped
        for idx, raw in enumerate(masked.splitlines(), 1):
            stripped = raw.strip()
            if re.match(r"^(if|for|while|switch|catch)\s*\(", stripped) and stripped.endswith(";"):
                out.append(Finding("warning", idx, len(raw), "JS001",
                                   f"第 {idx} 行控制语句后紧跟分号，循环体/条件体会变成空语句",
                                   f"Line {idx}: a semicolon right after the control statement creates an empty body",
                                   fix_zh="删除多余的分号",
                                   fix_en="Remove the stray semicolon"))
            if re.search(r"[^=!<>]=[^=]", stripped) and re.match(r"^(if|while)\s*\(", stripped):
                out.append(Finding("warning", idx, 1, "JS002",
                                   f"第 {idx} 行条件判断里出现了单个 `=`，可能想写 `==` 或 `===`",
                                   f"Line {idx}: a single `=` inside a condition; did you mean `==` or `===`?",
                                   fix_zh="改成比较运算符",
                                   fix_en="Use a comparison operator"))
            if re.search(r"\bvar\s+\w+", stripped):
                out.append(Finding("info", idx, raw.index("var") + 1, "JS003",
                                   f"第 {idx} 行使用了 `var`，建议改用 `let` / `const`",
                                   f"Line {idx} uses `var`; prefer `let` / `const`",
                                   fix_zh="改用块级作用域声明",
                                   fix_en="Switch to block-scoped declarations"))
            if re.search(r"[^=!<>]==[^=]", stripped):
                out.append(Finding("info", idx, 1, "JS004",
                                   f"第 {idx} 行使用了宽松相等 `==`，建议改用 `===`",
                                   f"Line {idx} uses loose equality `==`; prefer `===`",
                                   fix_zh="改成严格相等以避免隐式转换",
                                   fix_en="Use strict equality to avoid coercion"))
        return out


# =============================================================================
# SECTION 7 - Security engine
# =============================================================================

@dataclass
class SecRule:
    rid: str
    category: str
    severity: str
    pattern: "re.Pattern[str]"
    zh: str
    en: str
    fix_zh: str
    fix_en: str
    mask: bool = False
    scope: str = "raw"        # raw = including comments, code = comments stripped
    langs: Tuple[str, ...] = ()


def _rx(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, flags)


SECURITY_RULES: List[SecRule] = [
    # ---------- Secrets ----------
    SecRule("SEC-S01", "secret", "critical",
            _rx(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
            "疑似 AWS Access Key ID 硬编码在源码中",
            "Hard-coded AWS Access Key ID found in source",
            "立即吊销该凭证，改用环境变量或 IAM 角色",
            "Revoke it immediately; use environment variables or IAM roles", mask=True),
    SecRule("SEC-S02", "secret", "critical",
            _rx(r"(?i)aws(.{0,20})?(secret|private)[_\-\s]*(access)?[_\-\s]*key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
            "疑似 AWS Secret Access Key 明文出现",
            "AWS Secret Access Key appears in plaintext",
            "立即轮换密钥并从版本历史中清除",
            "Rotate the key and purge it from version history", mask=True),
    SecRule("SEC-S03", "secret", "critical",
            _rx(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
            "疑似 GitHub Personal Access Token",
            "GitHub personal access token detected",
            "到 GitHub 设置中撤销该 token",
            "Revoke the token in your GitHub settings", mask=True),
    SecRule("SEC-S04", "secret", "critical",
            _rx(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
            "疑似 OpenAI 风格 API 密钥（sk- 前缀）",
            "OpenAI-style API key detected (sk- prefix)",
            "撤销密钥，改从环境变量或加密配置读取",
            "Revoke it and read the key from an env var or encrypted config", mask=True),
    SecRule("SEC-S05", "secret", "critical",
            _rx(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
            "疑似 Slack Token",
            "Slack token detected",
            "在 Slack 应用管理中撤销",
            "Revoke it in your Slack app settings", mask=True),
    SecRule("SEC-S06", "secret", "critical",
            _rx(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            "疑似 Google API Key",
            "Google API key detected",
            "在 GCP 控制台限制或删除该密钥",
            "Restrict or delete the key in the GCP console", mask=True),
    SecRule("SEC-S07", "secret", "critical",
            _rx(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            "源码中内嵌了私钥 PEM 块",
            "A private key PEM block is embedded in the source",
            "把私钥移到受保护的密钥库，并重新生成密钥对",
            "Move it to a protected key store and regenerate the key pair"),
    SecRule("SEC-S08", "secret", "high",
            _rx(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
            "疑似硬编码的 JWT",
            "Hard-coded JWT detected",
            "JWT 应在运行时获取，不应写死在代码里",
            "JWTs should be obtained at runtime, not embedded", mask=True),
    SecRule("SEC-S09", "secret", "high",
            _rx(r"(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key)\b\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
            "变量名暗示这是凭证，但值被硬编码在代码里",
            "A credential-looking variable is assigned a hard-coded value",
            "改为从环境变量、密钥管理服务或加密配置读取",
            "Read it from an env var, a secret manager, or encrypted config", mask=True),
    SecRule("SEC-S10", "secret", "high",
            _rx(r"(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s'\"<>]*:[^\s'\"<>@]+@[^\s'\"<>]+"),
            "数据库连接串中包含明文账号密码",
            "Database connection string contains plaintext credentials",
            "把连接串拆成组件，密码走密钥管理",
            "Split the DSN and load the password from a secret manager", mask=True),
    SecRule("SEC-S11", "secret", "medium",
            _rx(r"(?i)\bslack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{20,}"),
            "疑似 Slack Webhook 地址",
            "Slack webhook URL detected",
            "撤销并重建 Webhook",
            "Revoke and recreate the webhook", mask=True),
    SecRule("SEC-S12", "secret", "low",
            _rx(r"\b1[3-9]\d{9}\b"),
            "疑似中国大陆手机号明文出现",
            "A Chinese mobile number appears in plaintext",
            "确认是否为测试数据，生产代码应做脱敏",
            "Confirm it is test data; production code should mask it", mask=True),
    SecRule("SEC-S13", "secret", "medium",
            _rx(r"\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
            "疑似身份证号明文出现",
            "A national ID number appears in plaintext",
            "个人敏感信息不得硬编码，必须脱敏或加密",
            "Personal data must never be hard-coded; mask or encrypt it", mask=True),

    # ---------- SQL injection ----------
    SecRule("SEC-Q01", "sqli", "critical",
            _rx(r"(?i)(execute|executemany|query|cursor\.execute)\s*\(\s*f?['\"].*?(SELECT|INSERT|UPDATE|DELETE).*?\{"),
            "使用 f-string 拼接 SQL 后直接执行，存在注入风险",
            "SQL built with an f-string is executed directly - injection risk",
            "改用参数化查询：execute(sql, (params,))",
            "Use parameterised queries: execute(sql, (params,))", scope="code"),
    SecRule("SEC-Q02", "sqli", "critical",
            _rx(r"(?i)['\"]\s*(SELECT|INSERT INTO|UPDATE|DELETE FROM)[^'\"]*['\"]\s*(\+|%)\s*\w+"),
            "SQL 语句通过字符串拼接构造，存在注入风险",
            "SQL statement is built by string concatenation - injection risk",
            "改用占位符绑定参数，不要拼接用户输入",
            "Bind parameters with placeholders instead of concatenating input", scope="code"),
    SecRule("SEC-Q03", "sqli", "high",
            _rx(r"(?i)['\"]\s*(SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*\.\s*format\s*\("),
            "SQL 语句使用 .format() 注入变量",
            "SQL statement uses .format() to inject variables",
            "改用数据库驱动提供的参数绑定",
            "Use the driver's parameter binding instead", scope="code"),
    SecRule("SEC-Q04", "sqli", "high",
            _rx(r"(?i)\.raw\s*\(\s*f?['\"].*?%s?.*?['\"]\s*%|\.extra\s*\(\s*where\s*=" ),
            "ORM 原生 SQL 接口中拼接了变量",
            "Raw ORM SQL interface receives concatenated variables",
            "尽量使用 ORM 查询表达式，必须用原生 SQL 时传参数列表",
            "Prefer ORM expressions; pass a parameter list when raw SQL is unavoidable", scope="code"),
    SecRule("SEC-Q05", "sqli", "medium",
            _rx(r"(?i)(WHERE|AND|OR)\s+\w+\s*=\s*['\"]?\s*\+\s*\w+"),
            "WHERE 条件由字符串拼接而成",
            "WHERE clause is assembled through concatenation",
            "使用参数化查询",
            "Use a parameterised query", scope="code"),

    # ---------- Dangerous code ----------
    SecRule("SEC-D01", "danger", "critical",
            _rx(r"(?<![\w.])eval\s*\("),
            "调用 eval() 动态执行代码，若参数可控将导致任意代码执行",
            "eval() executes dynamic code; attacker-controlled input means RCE",
            "改用 json.loads / ast.literal_eval 等安全替代",
            "Use json.loads or ast.literal_eval instead", scope="code"),
    SecRule("SEC-D02", "danger", "critical",
            _rx(r"(?<![\w.])exec\s*\("),
            "调用 exec() 动态执行代码块",
            "exec() executes a dynamic code block",
            "重构逻辑以避免动态执行",
            "Refactor so dynamic execution is not needed", scope="code"),
    SecRule("SEC-D03", "danger", "critical",
            _rx(r"subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
            "subprocess 使用 shell=True，拼接用户输入会导致命令注入",
            "subprocess with shell=True allows command injection",
            "改为传入参数列表，并保持 shell=False",
            "Pass an argument list and keep shell=False", scope="code"),
    SecRule("SEC-D04", "danger", "high",
            _rx(r"os\.(system|popen|spawn\w*)\s*\("),
            "使用 os.system / os.popen 直接执行系统命令",
            "os.system / os.popen executes a shell command directly",
            "改用 subprocess 并传参数列表",
            "Use subprocess with an argument list"),
    SecRule("SEC-D05", "danger", "critical",
            _rx(r"pickle\.(loads?|Unpickler)\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"),
            "反序列化不可信数据可导致任意代码执行",
            "Deserialising untrusted data can lead to arbitrary code execution",
            "改用 json，或 yaml.safe_load",
            "Use json, or yaml.safe_load"),
    SecRule("SEC-D06", "danger", "high",
            _rx(r"__import__\s*\(|importlib\.import_module\s*\(\s*[^'\"]"),
            "动态导入模块，模块名可控时存在风险",
            "Dynamic module import; risky when the module name is user-controlled",
            "对模块名做白名单校验",
            "Validate the module name against an allow-list", scope="code"),
    SecRule("SEC-D07", "danger", "critical",
            _rx(r"socket\.socket\([^)]*\)[\s\S]{0,200}?(dup2|/bin/sh|/bin/bash)"),
            "检测到疑似反弹 Shell 的代码特征",
            "Code pattern resembling a reverse shell was detected",
            "确认这段代码的来源，非预期请立即删除",
            "Verify the origin of this code; delete it if unexpected", scope="code"),
    SecRule("SEC-D08", "danger", "medium",
            _rx(r"base64\.b64decode\s*\(\s*['\"][A-Za-z0-9+/=]{120,}['\"]"),
            "存在超长 Base64 编码载荷并被解码，可能是被混淆的恶意代码",
            "A very long Base64 payload is decoded - possibly obfuscated malicious code",
            "解码检查其内容后再决定是否保留",
            "Decode and inspect the payload before keeping it"),
    SecRule("SEC-D09", "danger", "high",
            _rx(r"\.innerHTML\s*=(?!\s*['\"]{2})|document\.write\s*\("),
            "直接写入 innerHTML / document.write 会带来 XSS 风险",
            "Writing to innerHTML / document.write introduces XSS risk",
            "改用 textContent，或对内容做转义",
            "Use textContent, or escape the content", scope="code"),
    SecRule("SEC-D10", "danger", "high",
            _rx(r"(?i)dangerouslySetInnerHTML|v-html\s*="),
            "框架层面绕过了 XSS 防护",
            "Framework-level XSS protection is being bypassed",
            "确保内容已经过白名单净化",
            "Ensure the content is sanitised against an allow-list", scope="code"),
    SecRule("SEC-D11", "danger", "medium",
            _rx(r"(?i)new\s+Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]"),
            "以字符串形式构造并执行代码，等同 eval",
            "Building code from a string is equivalent to eval",
            "改为传入函数引用",
            "Pass a function reference instead", scope="code"),

    # ---------- Weak crypto ----------
    SecRule("SEC-C01", "crypto", "high",
            _rx(r"(?i)hashlib\.(md5|sha1)\s*\(|CryptoJS\.(MD5|SHA1)\s*\(|MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-?1)['\"]"),
            "使用 MD5 / SHA-1，这两个算法已不适合安全场景",
            "MD5 / SHA-1 are no longer suitable for security purposes",
            "口令请用 bcrypt / scrypt / argon2；摘要请用 SHA-256 及以上",
            "Use bcrypt / scrypt / argon2 for passwords, SHA-256+ for digests", scope="code"),
    SecRule("SEC-C02", "crypto", "high",
            _rx(r"(?i)(verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|rejectUnauthorized\s*:\s*false|_create_unverified_context)"),
            "关闭了 TLS 证书校验，等于放弃了中间人防护",
            "TLS certificate verification is disabled - no MITM protection",
            "保持证书校验开启；自签证书请配置 CA 包",
            "Keep verification on; configure a CA bundle for self-signed certs", scope="code"),
    SecRule("SEC-C03", "crypto", "medium",
            _rx(r"(?<![\w.])random\.(random|randint|choice|randrange|sample)\s*\("),
            "使用普通伪随机数，不适合生成令牌或密钥",
            "Standard pseudo-random numbers are unsuitable for tokens or keys",
            "改用 secrets 模块或 os.urandom",
            "Use the secrets module or os.urandom", scope="code"),
    SecRule("SEC-C04", "crypto", "high",
            _rx(r"(?i)\b(DES|RC4|ECB)\b\s*(mode|MODE_ECB|\()|MODE_ECB"),
            "使用了已被淘汰的加密算法或 ECB 模式",
            "An obsolete cipher or ECB mode is being used",
            "改用 AES-GCM 或 ChaCha20-Poly1305",
            "Switch to AES-GCM or ChaCha20-Poly1305", scope="code"),
    SecRule("SEC-C05", "crypto", "medium",
            _rx(r"(?i)\b(iv|nonce|salt)\s*=\s*['\"][^'\"]{4,}['\"]"),
            "硬编码的 IV / Nonce / Salt 会削弱加密强度",
            "A hard-coded IV / nonce / salt weakens the encryption",
            "每次加密都应生成新的随机值",
            "Generate a fresh random value for every operation", scope="code"),

    # ---------- Path & file ----------
    SecRule("SEC-P01", "path", "high",
            _rx(r"open\s*\(\s*[^)]*\+\s*\w+|open\s*\(\s*f['\"][^'\"]*\{"),
            "文件路径由变量拼接而成，可能被路径穿越利用",
            "File path is concatenated from variables - path traversal risk",
            "使用 os.path.abspath + 前缀校验限制访问范围",
            "Use os.path.abspath plus a prefix check to constrain access", scope="code"),
    SecRule("SEC-P02", "path", "high",
            _rx(r"\.\./\.\./|\.\.\\\.\.\\"),
            "代码中出现连续的上级目录引用",
            "Repeated parent-directory references appear in the code",
            "确认这是预期行为，避免用户输入进入路径",
            "Confirm this is intended and keep user input out of paths"),
    SecRule("SEC-P03", "path", "medium",
            _rx(r"(?i)(shutil\.rmtree|os\.removedirs|rm\s+-rf|del\s+/s\s+/q)"),
            "存在递归删除操作，误用会造成不可逆的数据损失",
            "A recursive delete is present; misuse causes irreversible data loss",
            "删除前校验目标路径，并提供确认或回收站机制",
            "Validate the target path and add a confirmation or trash step"),
    SecRule("SEC-P04", "path", "medium",
            _rx(r"tempfile\.mktemp\s*\(|/tmp/[\w.\-]+['\"]"),
            "使用了不安全的临时文件创建方式，存在竞态风险",
            "Insecure temporary file creation - race condition risk",
            "改用 tempfile.mkstemp 或 NamedTemporaryFile",
            "Use tempfile.mkstemp or NamedTemporaryFile", scope="code"),
    SecRule("SEC-P05", "path", "low",
            _rx(r"os\.chmod\s*\([^)]*0o?777|chmod\s+777"),
            "把文件权限设置为 777，任何用户都可读写执行",
            "Setting permissions to 777 grants everyone read/write/execute",
            "收紧为最小必要权限，例如 0o600 或 0o644",
            "Tighten to the minimum required, e.g. 0o600 or 0o644"),
]

SEC_CATEGORY_KEYS = {
    "secret": "sec.cat.secret",
    "sqli": "sec.cat.sqli",
    "danger": "sec.cat.danger",
    "crypto": "sec.cat.crypto",
    "path": "sec.cat.path",
}

_ENTROPY_VAR = re.compile(
    r"(?i)\b(\w*(?:key|token|secret|passwd|password|credential|auth|signature)\w*)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class SecurityEngine:
    """Fully offline security audit."""

    def scan(self, text: str, lang: str) -> List[Finding]:
        if not text.strip():
            return []
        findings: List[Finding] = []
        code_only = lexical_scan(text, lang).code_only if lang in PROFILES else text
        raw_lines = text.splitlines()

        for rule in SECURITY_RULES:
            if rule.langs and lang not in rule.langs:
                continue
            haystack = code_only if rule.scope == "code" else text
            for match in rule.pattern.finditer(haystack):
                line = haystack[:match.start()].count("\n") + 1
                col = match.start() - (haystack.rfind("\n", 0, match.start()) + 1) + 1
                raw = raw_lines[line - 1] if 0 < line <= len(raw_lines) else ""
                snippet = match.group(0).strip()
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."
                if rule.mask:
                    snippet = self._mask_snippet(snippet)
                findings.append(Finding(
                    rule.severity, line, col, rule.rid,
                    rule.zh, rule.en,
                    snippet=snippet or raw.strip(),
                    fix_zh=rule.fix_zh, fix_en=rule.fix_en,
                    category=rule.category))

        findings.extend(self._entropy_pass(code_only))
        findings = self._dedupe(findings)
        findings.sort(key=lambda f: f.sort_key())
        return findings

    @staticmethod
    def _mask_snippet(snippet: str) -> str:
        def repl(m: "re.Match[str]") -> str:
            return mask_secret(m.group(0))
        return re.sub(r"[A-Za-z0-9_\-+/=]{12,}", repl, snippet)

    @staticmethod
    def _entropy_pass(text: str) -> List[Finding]:
        out: List[Finding] = []
        for match in _ENTROPY_VAR.finditer(text):
            name, value = match.group(1), match.group(2)
            entropy = shannon_entropy(value)
            if entropy < 3.6:
                continue
            if re.fullmatch(r"[A-Za-z_]+", value):
                continue
            line = text[:match.start()].count("\n") + 1
            out.append(Finding(
                "high", line, 1, "SEC-E01",
                f"变量 `{name}` 的值具有高信息熵（{entropy:.2f}），疑似真实凭证",
                f"Value of `{name}` has high entropy ({entropy:.2f}) - looks like a real credential",
                snippet=f"{name} = {mask_secret(value)}",
                fix_zh="从环境变量或密钥管理服务读取，不要写进源码",
                fix_en="Load it from an environment variable or a secret manager",
                category="secret"))
        return out

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        seen = set()
        out = []
        for f in findings:
            sig = (f.rule, f.line, f.snippet)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(f)
        return out


# =============================================================================
# SECTION 8 - Diff engine
# =============================================================================

@dataclass
class DiffRow:
    tag: str
    lno_a: Optional[int]
    lno_b: Optional[int]
    text_a: str
    text_b: str
    spans_a: List[Tuple[int, int]] = field(default_factory=list)
    spans_b: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class DiffResult:
    rows: List[DiffRow]
    added: int
    removed: int
    changed: int
    same: int
    similarity: float
    name_a: str = "A"
    name_b: str = "B"
    lines_a: List[str] = field(default_factory=list)
    lines_b: List[str] = field(default_factory=list)

    @property
    def identical(self) -> bool:
        return self.added == 0 and self.removed == 0 and self.changed == 0


_WORD_RE = re.compile(r"\w+|\s+|[^\w\s]")


class DiffEngine:
    def compare(self, text_a: str, text_b: str,
                name_a: str = "A", name_b: str = "B",
                ignore_ws: bool = False, ignore_case: bool = False) -> DiffResult:
        lines_a = text_a.replace("\r\n", "\n").split("\n")
        lines_b = text_b.replace("\r\n", "\n").split("\n")

        def norm(seq: List[str]) -> List[str]:
            out = seq
            if ignore_ws:
                out = [re.sub(r"\s+", " ", s).strip() for s in out]
            if ignore_case:
                out = [s.lower() for s in out]
            return out

        matcher = difflib.SequenceMatcher(None, norm(lines_a), norm(lines_b), autojunk=False)
        rows: List[DiffRow] = []
        added = removed = changed = same = 0

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for off in range(i2 - i1):
                    rows.append(DiffRow("equal", i1 + off + 1, j1 + off + 1,
                                        lines_a[i1 + off], lines_b[j1 + off]))
                same += i2 - i1
            elif tag == "replace":
                span = max(i2 - i1, j2 - j1)
                for off in range(span):
                    ia = i1 + off
                    jb = j1 + off
                    has_a = ia < i2
                    has_b = jb < j2
                    if has_a and has_b:
                        sa, sb = self._word_spans(lines_a[ia], lines_b[jb])
                        rows.append(DiffRow("replace", ia + 1, jb + 1,
                                            lines_a[ia], lines_b[jb], sa, sb))
                        changed += 1
                    elif has_a:
                        rows.append(DiffRow("delete", ia + 1, None, lines_a[ia], ""))
                        removed += 1
                    else:
                        rows.append(DiffRow("insert", None, jb + 1, "", lines_b[jb]))
                        added += 1
            elif tag == "delete":
                for off in range(i2 - i1):
                    rows.append(DiffRow("delete", i1 + off + 1, None, lines_a[i1 + off], ""))
                removed += i2 - i1
            elif tag == "insert":
                for off in range(j2 - j1):
                    rows.append(DiffRow("insert", None, j1 + off + 1, "", lines_b[j1 + off]))
                added += j2 - j1

        return DiffResult(rows, added, removed, changed, same,
                          round(matcher.ratio() * 100, 2), name_a, name_b,
                          lines_a, lines_b)

    @staticmethod
    def _word_spans(a: str, b: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
        toks_a = _WORD_RE.findall(a)
        toks_b = _WORD_RE.findall(b)
        pos_a: List[int] = []
        acc = 0
        for tok in toks_a:
            pos_a.append(acc)
            acc += len(tok)
        pos_b: List[int] = []
        acc = 0
        for tok in toks_b:
            pos_b.append(acc)
            acc += len(tok)
        sm = difflib.SequenceMatcher(None, toks_a, toks_b, autojunk=False)
        spans_a: List[Tuple[int, int]] = []
        spans_b: List[Tuple[int, int]] = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            if i2 > i1:
                start = pos_a[i1]
                end = pos_a[i2 - 1] + len(toks_a[i2 - 1])
                spans_a.append((start, end))
            if j2 > j1:
                start = pos_b[j1]
                end = pos_b[j2 - 1] + len(toks_b[j2 - 1])
                spans_b.append((start, end))
        return spans_a, spans_b

    # -- exports -------------------------------------------------------------
    @staticmethod
    def to_unified(result: DiffResult) -> str:
        return "\n".join(difflib.unified_diff(
            result.lines_a, result.lines_b,
            fromfile=result.name_a, tofile=result.name_b, lineterm=""))

    @staticmethod
    def to_markdown(result: DiffResult, lang: str = "zh") -> str:
        zh = lang == "zh"
        head = [
            f"# {'ctn 对比报告' if zh else 'ctn Diff Report'}",
            "",
            f"- **{'左侧' if zh else 'Left'} (A)**: `{result.name_a}`",
            f"- **{'右侧' if zh else 'Right'} (B)**: `{result.name_b}`",
            f"- **{'生成时间' if zh else 'Generated'}**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **{'相似度' if zh else 'Similarity'}**: {result.similarity}%",
            f"- **{'统计' if zh else 'Stats'}**: +{result.added} / -{result.removed} / ~{result.changed} / ={result.same}",
            "",
            "```diff",
        ]
        body = []
        for row in result.rows:
            if row.tag == "equal":
                continue
            if row.tag in ("delete", "replace") and row.text_a:
                body.append(f"-{row.lno_a or ''}\t{row.text_a}")
            if row.tag in ("insert", "replace") and row.text_b:
                body.append(f"+{row.lno_b or ''}\t{row.text_b}")
        if not body:
            body.append("  " + ("两侧内容完全一致" if zh else "Both sides are identical"))
        return "\n".join(head + body + ["```", ""])

    @staticmethod
    def to_html(result: DiffResult, lang: str = "zh") -> str:
        zh = lang == "zh"
        def esc(s: str) -> str:
            return (s.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))

        rows_html = []
        for row in result.rows:
            cls = row.tag
            rows_html.append(
                "<tr class='{cls}'>"
                "<td class='ln'>{la}</td><td class='src'>{ta}</td>"
                "<td class='ln'>{lb}</td><td class='src'>{tb}</td></tr>".format(
                    cls=cls,
                    la=row.lno_a or "", lb=row.lno_b or "",
                    ta=esc(row.text_a) or "&nbsp;", tb=esc(row.text_b) or "&nbsp;"))

        title = "ctn 对比报告 / ctn Diff Report"
        return f"""<!DOCTYPE html>
<html lang="{'zh-CN' if zh else 'en'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#f6f7f9;--panel:#fff;--fg:#1b1f27;--dim:#6a7280;--bd:#e2e5ea;
--add:#e3f7e8;--del:#fdeaec;--chg:#fff6d9;--ln:#f2f4f7;--lnfg:#a3aab5}}
@media(prefers-color-scheme:dark){{:root{{--bg:#14171d;--panel:#1c2027;--fg:#e4e7ec;--dim:#8c94a1;
--bd:#2e343f;--add:#12291c;--del:#2e1619;--chg:#2f2a12;--ln:#161a20;--lnfg:#5b6472}}}}
*{{box-sizing:border-box}}
body{{margin:0;padding:32px;background:var(--bg);color:var(--fg);
font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei UI",sans-serif}}
.wrap{{max-width:1400px;margin:0 auto}}
h1{{font-size:22px;letter-spacing:-.02em;margin:0 0 4px}}
.sub{{color:var(--dim);font-size:13px;margin-bottom:20px}}
.meta{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px}}
.chip{{background:var(--panel);border:1px solid var(--bd);border-radius:999px;
padding:5px 14px;font-size:12px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--bd);border-radius:10px;overflow:hidden;
font:12.5px/1.7 {code_font()!r},"SF Mono",Menlo,monospace}}
td{{padding:2px 10px;vertical-align:top;white-space:pre-wrap;word-break:break-word}}
td.ln{{width:52px;text-align:right;background:var(--ln);color:var(--lnfg);
user-select:none;border-right:1px solid var(--bd)}}
td.src{{width:calc(50% - 52px)}}
tr.insert td:nth-child(3),tr.insert td:nth-child(4){{background:var(--add)}}
tr.delete td:nth-child(1),tr.delete td:nth-child(2){{background:var(--del)}}
tr.replace td:nth-child(2){{background:var(--del)}}
tr.replace td:nth-child(4){{background:var(--add)}}
footer{{margin-top:20px;color:var(--dim);font-size:12px}}
</style>
</head>
<body><div class="wrap">
<h1>{title}</h1>
<div class="sub">Generated by {APP_NAME} v{APP_VERSION} · {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
<div class="meta">
<span class="chip">A · {esc(result.name_a)}</span>
<span class="chip">B · {esc(result.name_b)}</span>
<span class="chip">{'相似度' if zh else 'Similarity'} {result.similarity}%</span>
<span class="chip">+{result.added}</span>
<span class="chip">-{result.removed}</span>
<span class="chip">~{result.changed}</span>
<span class="chip">={result.same}</span>
</div>
<table>{''.join(rows_html)}</table>
<footer>ctn — Chat Talk Nonsense · local-first developer toolkit</footer>
</div></body></html>"""


# =============================================================================
# SECTION 9 - Cloud client (fully user-defined endpoint)
# =============================================================================

class CloudError(Exception):
    def __init__(self, zh: str, en: str) -> None:
        super().__init__(en)
        self.zh = zh
        self.en = en

    @property
    def localized(self) -> str:
        return P(self.zh, self.en)


def _json_escape(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=False)[1:-1]


def render_template(template: str, values: Dict[str, Any]) -> str:
    out = template
    for key, value in values.items():
        token = "{" + key + "}"
        if token in out:
            out = out.replace(token, _json_escape(value))
    return out


def extract_path(payload: Any, path: str) -> Optional[str]:
    if not path:
        return json.dumps(payload, ensure_ascii=False, indent=2) if not isinstance(payload, str) else payload
    node = payload
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(node, dict):
            if part not in node:
                return None
            node = node[part]
        else:
            return None
    if isinstance(node, (dict, list)):
        return json.dumps(node, ensure_ascii=False, indent=2)
    return str(node)


class CloudClient:
    def __init__(self, cfg: ConfigStore) -> None:
        self.cfg = cfg

    def configured(self) -> bool:
        return bool(str(self.cfg.get("api_url", "")).strip())

    def _opener(self) -> urllib.request.OpenerDirector:
        handlers: List[Any] = []
        proxy = str(self.cfg.get("api_proxy", "")).strip()
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        ctx = ssl.create_default_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        return urllib.request.build_opener(*handlers)

    def chat(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        url = str(self.cfg.get("api_url", "")).strip()
        if not url:
            raise CloudError(*LANG["net.no_url"])

        values = {
            "api_key": self.cfg.get("api_key", ""),
            "model": self.cfg.get("api_model", ""),
            "prompt": prompt,
            "system": system,
            "temperature": temperature,
        }

        try:
            headers = json.loads(render_template(str(self.cfg.get("api_headers", "{}")), values) or "{}")
            if not isinstance(headers, dict):
                raise ValueError("headers template must be a JSON object")
            headers = {str(k): str(v) for k, v in headers.items()}
        except Exception as exc:
            raise CloudError(LANG["net.bad_headers"][0].format(exc),
                             LANG["net.bad_headers"][1].format(exc))

        body_text = render_template(str(self.cfg.get("api_body", "{}")), values)
        try:
            json.loads(body_text)
        except Exception as exc:
            raise CloudError(LANG["net.bad_body"][0].format(exc),
                             LANG["net.bad_body"][1].format(exc))

        method = str(self.cfg.get("api_method", "POST")).upper() or "POST"
        timeout = int(self.cfg.get("api_timeout", 60) or 60)
        headers.setdefault("User-Agent", f"{APP_NAME}/{APP_VERSION}")

        request = urllib.request.Request(
            url, data=body_text.encode("utf-8"), headers=headers, method=method)
        try:
            with self._opener().open(request, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                pass
            raise CloudError(LANG["net.http_error"][0].format(exc.code, detail or exc.reason),
                             LANG["net.http_error"][1].format(exc.code, detail or exc.reason))
        except socket.timeout:
            raise CloudError(*LANG["net.timeout"])
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise CloudError(LANG["net.unreachable"][0].format(reason),
                             LANG["net.unreachable"][1].format(reason))
        except Exception as exc:
            raise CloudError(LANG["net.unreachable"][0].format(exc),
                             LANG["net.unreachable"][1].format(exc))

        path = str(self.cfg.get("api_response_path", "")).strip()
        try:
            payload = json.loads(raw)
        except Exception:
            return raw
        content = extract_path(payload, path)
        if content is None:
            raise CloudError(LANG["net.bad_path"][0].format(path),
                             LANG["net.bad_path"][1].format(path))
        if not content.strip():
            raise CloudError(*LANG["net.empty"])
        return content

    def fetch_text(self, url: str, headers_json: str = "{}", timeout: int = 30) -> str:
        url = url.strip()
        if not url:
            raise CloudError(*LANG["net.no_url"])
        try:
            headers = json.loads(headers_json or "{}")
            headers = {str(k): str(v) for k, v in headers.items()}
        except Exception as exc:
            raise CloudError(LANG["net.bad_headers"][0].format(exc),
                             LANG["net.bad_headers"][1].format(exc))
        headers.setdefault("User-Agent", f"{APP_NAME}/{APP_VERSION}")
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._opener().open(request, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raise CloudError(LANG["net.http_error"][0].format(exc.code, exc.reason),
                             LANG["net.http_error"][1].format(exc.code, exc.reason))
        except Exception as exc:
            raise CloudError(LANG["net.unreachable"][0].format(exc),
                             LANG["net.unreachable"][1].format(exc))


PROMPT_GOALS: List[Tuple[str, str, str]] = [
    ("structure", "prompt.goal.structure",
     "Restructure the prompt into clearly separated sections: Role, Task, Context, Constraints, Output format."),
    ("role", "prompt.goal.role",
     "Strengthen the role definition and make all constraints explicit and testable."),
    ("clarity", "prompt.goal.clarity",
     "Eliminate ambiguity: replace vague wording with precise, measurable instructions."),
    ("compact", "prompt.goal.compact",
     "Compress the prompt to the minimum token count while preserving every requirement."),
    ("fewshot", "prompt.goal.fewshot",
     "Add two concise few-shot examples that demonstrate the expected input and output."),
]

PROMPT_SYSTEM_ZH = (
    "你是一名资深的 Prompt 工程师。用户会给你一段提示词，你需要输出优化后的版本。\n"
    "输出格式严格如下：\n"
    "## 优化后的提示词\n<这里给出可以直接复制使用的完整提示词>\n\n"
    "## 改动说明\n<用要点列出你做了哪些改动，每条一行，说明为什么>\n\n"
    "## 风险提醒\n<如果原提示词存在歧义、越权或安全隐患，在这里指出；没有则写「无」>\n"
    "不要输出除上述三节以外的任何内容。"
)

PROMPT_SYSTEM_EN = (
    "You are a senior prompt engineer. The user gives you a prompt; you return an improved version.\n"
    "Use exactly this output format:\n"
    "## Optimized Prompt\n<the full, ready-to-copy prompt>\n\n"
    "## What Changed\n<bullet points, one change per line, with the reason>\n\n"
    "## Risks\n<ambiguity, over-reach or safety concerns in the original; write \"None\" if there are none>\n"
    "Do not output anything outside those three sections."
)


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    cjk = len(re.findall(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]", text))
    rest = len(text) - cjk
    return int(cjk + max(0, rest) / 3.6) + 1


def build_prompt_request(original: str, goals: Sequence[str], extra: str, lang: str) -> Tuple[str, str]:
    goal_map = {g[0]: g[2] for g in PROMPT_GOALS}
    selected = [goal_map[g] for g in goals if g in goal_map]
    system = PROMPT_SYSTEM_ZH if lang == "zh" else PROMPT_SYSTEM_EN
    parts: List[str] = []
    if selected:
        parts.append(("优化目标 / Goals:\n" if lang == "zh" else "Goals:\n")
                     + "\n".join(f"- {s}" for s in selected))
    if extra.strip():
        parts.append(("附加要求 / Extra requirements:\n" if lang == "zh" else "Extra requirements:\n")
                     + extra.strip())
    parts.append(("待优化的原始提示词：\n" if lang == "zh" else "Original prompt to optimize:\n")
                 + "-----\n" + original.strip() + "\n-----")
    if lang == "zh":
        parts.append("请用中文回答。")
    else:
        parts.append("Answer in English.")
    return system, "\n\n".join(parts)


# =============================================================================
# SECTION 10 - GUI
# =============================================================================

try:  # GUI is optional: the CLI works without Tk.
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except Exception:  # pragma: no cover
    tk = None  # type: ignore
    ttk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore
    TK_AVAILABLE = False


ROLE_PROPS: Dict[str, Callable[[Dict[str, str]], Dict[str, Any]]] = {
    "root":       lambda c: {"bg": c["bg"]},
    "panel":      lambda c: {"bg": c["bg"]},
    "card":       lambda c: {"bg": c["panel"]},
    "card_alt":   lambda c: {"bg": c["panel_alt"]},
    "sidebar":    lambda c: {"bg": c["sidebar"]},
    "title":      lambda c: {"bg": c["bg"], "fg": c["fg"]},
    "title_card": lambda c: {"bg": c["panel"], "fg": c["fg"]},
    "muted":      lambda c: {"bg": c["bg"], "fg": c["fg_dim"]},
    "muted_card": lambda c: {"bg": c["panel"], "fg": c["fg_dim"]},
    "label":      lambda c: {"bg": c["panel"], "fg": c["fg"]},
    "label_bg":   lambda c: {"bg": c["bg"], "fg": c["fg"]},
    "sep":        lambda c: {"bg": c["border"]},
    "accentbar":  lambda c: {"bg": c["accent"]},
}


class UIKit:
    """Central widget registry so a theme switch repaints everything."""

    def __init__(self) -> None:
        self.items: List[Tuple[Any, str]] = []

    def reg(self, widget: Any, role: str) -> Any:
        self.items.append((widget, role))
        return widget

    def apply(self) -> None:
        colors = THEME.c
        alive: List[Tuple[Any, str]] = []
        for widget, role in self.items:
            try:
                if not widget.winfo_exists():
                    continue
            except Exception:
                continue
            alive.append((widget, role))
            fn = ROLE_PROPS.get(role)
            if fn is None:
                continue
            try:
                widget.configure(**fn(colors))
            except Exception:
                pass
        self.items = alive


class AsyncRunner:
    def __init__(self, root: Any) -> None:
        self.root = root
        self.q: "queue.Queue[Tuple[Callable[[bool, Any], None], bool, Any]]" = queue.Queue()
        self.root.after(60, self._poll)

    def submit(self, fn: Callable[[], Any], callback: Callable[[bool, Any], None]) -> None:
        def worker() -> None:
            try:
                self.q.put((callback, True, fn()))
            except Exception as exc:  # noqa: BLE001
                self.q.put((callback, False, exc))
        threading.Thread(target=worker, daemon=True).start()

    def _poll(self) -> None:
        while True:
            try:
                callback, ok, payload = self.q.get_nowait()
            except queue.Empty:
                break
            try:
                callback(ok, payload)
            except Exception:
                traceback.print_exc()
        self.root.after(60, self._poll)


def make_button(kit: UIKit, parent: Any, text: str, command: Callable[[], None],
                primary: bool = False, width: int = 0) -> Any:
    btn = tk.Button(parent, text=text, command=command, relief="flat", bd=0,
                    padx=14, pady=6, cursor="hand2",
                    font=(ui_font(), 9), highlightthickness=0,
                    activeforeground=THEME.c["fg"])
    if width:
        btn.configure(width=width)
    btn._ctn_primary = primary  # type: ignore[attr-defined]
    kit.items.append((btn, "__button__"))
    return btn


def paint_buttons(kit: UIKit) -> None:
    colors = THEME.c
    for widget, role in kit.items:
        if role != "__button__":
            continue
        try:
            if not widget.winfo_exists():
                continue
            primary = getattr(widget, "_ctn_primary", False)
            if primary:
                widget.configure(bg=colors["accent"], fg=colors["accent_fg"],
                                 activebackground=colors["accent"],
                                 activeforeground=colors["accent_fg"],
                                 disabledforeground=colors["fg_dim"])
            else:
                widget.configure(bg=colors["panel_alt"], fg=colors["fg"],
                                 activebackground=colors["accent_soft"],
                                 activeforeground=colors["fg"],
                                 disabledforeground=colors["fg_dim"])
        except Exception:
            pass


class CodeEditor:
    """Text area with a synced line-number gutter."""

    def __init__(self, app: "CtnApp", parent: Any, height: int = 14,
                 readonly: bool = False, wrap: str = "none", gutter_width: int = 5) -> None:
        self.app = app
        self.readonly = readonly
        self._custom_gutter: Optional[List[str]] = None
        self.frame = tk.Frame(parent, bd=1, relief="flat", highlightthickness=1)
        self.gutter = tk.Text(self.frame, width=gutter_width, padx=6, bd=0,
                              highlightthickness=0, state="disabled", takefocus=0,
                              wrap="none", cursor="arrow", height=height)
        self.text = tk.Text(self.frame, bd=0, highlightthickness=0, wrap=wrap,
                            undo=True, padx=10, pady=6, height=height)
        self.vsb = ttk.Scrollbar(self.frame, orient="vertical", command=self._yview)
        self.hsb = ttk.Scrollbar(self.frame, orient="horizontal", command=self.text.xview)
        self.gutter.grid(row=0, column=0, sticky="ns")
        self.text.grid(row=0, column=1, sticky="nsew")
        self.vsb.grid(row=0, column=2, sticky="ns")
        self.hsb.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.frame.rowconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)
        self.text.configure(yscrollcommand=self._on_yscroll, xscrollcommand=self.hsb.set)
        self.text.bind("<<Modified>>", self._on_modified)
        self.link: Optional["CodeEditor"] = None
        self.refresh_gutter()

    # -- scrolling -----------------------------------------------------------
    def _yview(self, *args: Any) -> None:
        self.text.yview(*args)
        self.gutter.yview(*args)
        if self.link is not None:
            self.link.text.yview(*args)
            self.link.gutter.yview(*args)

    def _on_yscroll(self, first: str, last: str) -> None:
        self.vsb.set(first, last)
        try:
            self.gutter.yview_moveto(first)
            if self.link is not None:
                self.link.text.yview_moveto(first)
                self.link.gutter.yview_moveto(first)
                self.link.vsb.set(first, last)
        except Exception:
            pass

    def _on_modified(self, _event: Any = None) -> None:
        if self.text.edit_modified():
            self.refresh_gutter()
            self.text.edit_modified(False)

    # -- content -------------------------------------------------------------
    def get(self) -> str:
        return self.text.get("1.0", "end-1c")

    def set(self, content: str) -> None:
        state = self.text.cget("state")
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.edit_modified(False)
        if self.readonly:
            self.text.configure(state="disabled")
        else:
            self.text.configure(state=state)
        self._custom_gutter = None
        self.refresh_gutter()

    def set_gutter(self, labels: List[str]) -> None:
        self._custom_gutter = labels
        self.refresh_gutter()

    def refresh_gutter(self) -> None:
        if self._custom_gutter is not None:
            body = "\n".join(self._custom_gutter)
        else:
            count = int(self.text.index("end-1c").split(".")[0])
            body = "\n".join(str(i) for i in range(1, count + 1))
        self.gutter.configure(state="normal")
        self.gutter.delete("1.0", "end")
        self.gutter.insert("1.0", body)
        self.gutter.tag_configure("r", justify="right")
        self.gutter.tag_add("r", "1.0", "end")
        self.gutter.configure(state="disabled")
        try:
            self.gutter.yview_moveto(self.text.yview()[0])
        except Exception:
            pass

    def goto(self, line: int, col: int = 1) -> None:
        try:
            self.text.tag_remove("ctn_hl", "1.0", "end")
            index = f"{max(1, line)}.0"
            self.text.see(index)
            self.text.tag_add("ctn_hl", index, f"{max(1, line)}.end")
            self.text.tag_configure("ctn_hl", background=THEME.c["accent_soft"])
            if not self.readonly:
                self.text.mark_set("insert", f"{max(1, line)}.{max(0, col - 1)}")
                self.text.focus_set()
        except Exception:
            pass

    def apply_theme(self, size: int) -> None:
        colors = THEME.c
        font = (code_font(), size)
        self.frame.configure(bg=colors["border"], highlightbackground=colors["border"],
                             highlightcolor=colors["border"])
        self.text.configure(bg=colors["code_bg"], fg=colors["code_fg"], font=font,
                            insertbackground=colors["fg"],
                            selectbackground=colors["select"],
                            selectforeground=colors["fg"])
        self.gutter.configure(bg=colors["gutter_bg"], fg=colors["gutter_fg"], font=font)
        self.text.tag_configure("ctn_hl", background=colors["accent_soft"])
        for tag, key in (("add", "diff_add"), ("del", "diff_del"), ("chg", "diff_chg")):
            self.text.tag_configure(tag, background=colors[key])
        self.text.tag_configure("addw", background=colors["diff_add_word"])
        self.text.tag_configure("delw", background=colors["diff_del_word"])
        self.text.tag_configure("dim", foreground=colors["fg_dim"])


class Page:
    """Base page: owns a frame plus text/theme refresh hooks."""

    def __init__(self, app: "CtnApp") -> None:
        self.app = app
        self.kit = app.kit
        self.frame = tk.Frame(app.content)
        self.kit.reg(self.frame, "panel")
        self.editors: List[CodeEditor] = []

    def header(self, title_key: str, desc_key: str) -> Any:
        box = tk.Frame(self.frame)
        self.kit.reg(box, "panel")
        title = tk.Label(box, text="", anchor="w", font=(ui_font(), 15, "bold"))
        desc = tk.Label(box, text="", anchor="w", justify="left", font=(ui_font(), 9))
        self.kit.reg(title, "title")
        self.kit.reg(desc, "muted")
        title.pack(fill="x")
        desc.pack(fill="x", pady=(3, 0))
        self._h_title, self._h_title_key = title, title_key
        self._h_desc, self._h_desc_key = desc, desc_key
        return box

    def card(self, parent: Any, **pack: Any) -> Any:
        frame = tk.Frame(parent, bd=0, highlightthickness=1)
        self.kit.reg(frame, "card")
        self.app.bordered.append(frame)
        return frame

    def apply_texts(self) -> None:
        if hasattr(self, "_h_title"):
            self._h_title.configure(text=T(self._h_title_key))
            self._h_desc.configure(text=T(self._h_desc_key))

    def apply_theme(self) -> None:
        for editor in self.editors:
            editor.apply_theme(self.app.code_size)

    def on_show(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# Syntax page
# --------------------------------------------------------------------------- #
class SyntaxPage(Page):
    def __init__(self, app: "CtnApp") -> None:
        super().__init__(app)
        self.findings: List[Finding] = []
        self.current_path = ""
        self.mode = tk.StringVar(value="local")
        self.lang_var = tk.StringVar(value="auto")

        self.header("syntax.head", "syntax.desc").pack(fill="x", padx=24, pady=(20, 12))

        bar = self.card(self.frame)
        bar.pack(fill="x", padx=24)
        inner = tk.Frame(bar)
        self.kit.reg(inner, "card")
        inner.pack(fill="x", padx=14, pady=12)

        self.btn_open = make_button(self.kit, inner, "", self.open_file)
        self.btn_open.pack(side="left")

        self.lbl_lang = tk.Label(inner, text="", font=(ui_font(), 9))
        self.kit.reg(self.lbl_lang, "muted_card")
        self.lbl_lang.pack(side="left", padx=(16, 6))
        self.cmb_lang = ttk.Combobox(inner, textvariable=self.lang_var, width=13,
                                     state="readonly", values=["auto"] + SUPPORTED_LANGS)
        self.cmb_lang.pack(side="left")

        self.rb_local = tk.Radiobutton(inner, text="", variable=self.mode, value="local",
                                       font=(ui_font(), 9), bd=0, highlightthickness=0,
                                       cursor="hand2")
        self.rb_cloud = tk.Radiobutton(inner, text="", variable=self.mode, value="cloud",
                                       font=(ui_font(), 9), bd=0, highlightthickness=0,
                                       cursor="hand2")
        self.rb_local.pack(side="left", padx=(18, 4))
        self.rb_cloud.pack(side="left", padx=(0, 4))
        self.app.radios.extend([self.rb_local, self.rb_cloud])

        self.btn_clear = make_button(self.kit, inner, "", self.clear)
        self.btn_clear.pack(side="right")
        self.btn_run = make_button(self.kit, inner, "", self.run, primary=True)
        self.btn_run.pack(side="right", padx=(0, 8))

        self.lbl_file = tk.Label(inner, text="", font=(ui_font(), 8))
        self.kit.reg(self.lbl_file, "muted_card")
        self.lbl_file.pack(side="right", padx=12)

        paned = tk.PanedWindow(self.frame, orient="vertical", sashwidth=6, bd=0,
                               sashrelief="flat", opaqueresize=True)
        self.paned = paned
        paned.pack(fill="both", expand=True, padx=24, pady=(12, 18))

        self.editor = CodeEditor(app, paned, height=14)
        self.editors.append(self.editor)
        paned.add(self.editor.frame, minsize=140, stretch="always")

        self.nb = ttk.Notebook(paned)
        paned.add(self.nb, minsize=150, stretch="always")

        tree_holder = tk.Frame(self.nb)
        self.kit.reg(tree_holder, "card")
        self.tree = ttk.Treeview(tree_holder, columns=("sev", "line", "col", "rule", "msg"),
                                 show="headings", selectmode="browse")
        for col, width, anchor in (("sev", 70, "center"), ("line", 60, "e"),
                                   ("col", 50, "e"), ("rule", 80, "center"),
                                   ("msg", 640, "w")):
            self.tree.column(col, width=width, anchor=anchor,
                             stretch=(col == "msg"))
        vsb = ttk.Scrollbar(tree_holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.nb.add(tree_holder, text="local")

        self.cloud_box = CodeEditor(app, self.nb, height=8, readonly=True,
                                    wrap="word", gutter_width=3)
        self.editors.append(self.cloud_box)
        self.nb.add(self.cloud_box.frame, text="cloud")

        self.summary = tk.Label(self.frame, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.summary, "muted")
        self.summary.pack(fill="x", padx=24, pady=(0, 10))

    # -- actions -------------------------------------------------------------
    def open_file(self) -> None:
        path = filedialog.askopenfilename(
            title=T("common.open"),
            filetypes=[("All supported", "*.py *.js *.ts *.jsx *.tsx *.json *.yaml *.yml "
                                         "*.html *.htm *.xml *.css *.sql *.c *.h *.cpp *.java "
                                         "*.go *.rs *.php *.rb *.sh *.ini *.toml *.md *.txt"),
                       ("All files", "*.*")])
        if not path:
            return
        content = self.app.read_text_file(path)
        if content is None:
            return
        self.current_path = path
        self.editor.set(content)
        self.lbl_file.configure(text=os.path.basename(path))
        detected = detect_language(content, path)
        self.lang_var.set(detected)
        self.app.status(T("syntax.detected", detected))

    def clear(self) -> None:
        self.editor.set("")
        self.cloud_box.set("")
        self.tree.delete(*self.tree.get_children())
        self.findings = []
        self.current_path = ""
        self.lbl_file.configure(text="")
        self.summary.configure(text="")
        self.app.status(T("common.ready"))

    def run(self) -> None:
        source = self.editor.get()
        if not source.strip():
            self.app.status(T("common.no_input"), "warn")
            return
        lang = self.lang_var.get()
        if lang == "auto":
            lang = detect_language(source, self.current_path)
            self.lang_var.set(lang)
        self.app.status(T("common.running"))
        self.btn_run.configure(state="disabled")
        started = time.time()

        def work() -> List[Finding]:
            return SyntaxEngine().analyse(source, lang)

        def done(ok: bool, payload: Any) -> None:
            self.btn_run.configure(state="normal")
            if not ok:
                self.app.status(f"{T('common.error')}: {payload}", "error")
                return
            self.findings = payload
            self._render(payload)
            ms = int((time.time() - started) * 1000)
            self.app.status(f"{T('syntax.detected', lang)} · {T('common.elapsed', ms)}", "ok")

        self.app.runner.submit(work, done)

        if self.mode.get() == "cloud":
            self._run_cloud(source, lang)

    def _run_cloud(self, source: str, lang: str) -> None:
        if not self.app.cloud.configured():
            self.cloud_box.set(T("prompt.need_cfg"))
            self.nb.select(1)
            return
        self.cloud_box.set(T("prompt.working"))
        self.nb.select(1)
        system = T("syntax.cloud.prompt_sys")
        prompt = (f"Language: {lang}\n"
                  f"Review the following source code and report concrete problems.\n"
                  f"Answer in {'Chinese' if I18N.lang == 'zh' else 'English'}.\n"
                  f"-----\n{source}\n-----")

        def work() -> str:
            return self.app.cloud.chat(prompt, system, 0.2)

        def done(ok: bool, payload: Any) -> None:
            if ok:
                self.cloud_box.set(str(payload))
                self.app.status(T("common.ready"), "ok")
            else:
                msg = payload.localized if isinstance(payload, CloudError) else str(payload)
                self.cloud_box.set(msg)
                self.app.status(msg, "error")

        self.app.runner.submit(work, done)

    def _render(self, findings: List[Finding]) -> None:
        self.tree.delete(*self.tree.get_children())
        errors = sum(1 for f in findings if f.severity == "error")
        warns = sum(1 for f in findings if f.severity == "warning")
        infos = sum(1 for f in findings if f.severity == "info")
        for idx, f in enumerate(findings):
            self.tree.insert("", "end", iid=str(idx),
                             values=(T(f"sev.{f.severity}"), f.line, f.col, f.rule, f.message),
                             tags=(f.severity, "odd" if idx % 2 else "even"))
        if findings:
            self.summary.configure(text=T("syntax.summary", errors, warns, infos))
        else:
            self.summary.configure(text=T("syntax.clean"))

    def _on_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            finding = self.findings[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.editor.goto(finding.line, finding.col)
        detail = finding.message
        if finding.fix:
            detail += f"  |  {T('common.suggestion')}: {finding.fix}"
        self.app.status(detail)

    def apply_texts(self) -> None:
        super().apply_texts()
        self.btn_open.configure(text=T("common.open"))
        self.btn_run.configure(text=T("common.run"))
        self.btn_clear.configure(text=T("common.clear"))
        self.lbl_lang.configure(text=T("syntax.language"))
        self.rb_local.configure(text=T("syntax.mode.local"))
        self.rb_cloud.configure(text=T("syntax.mode.cloud"))
        for col, key in (("sev", "syntax.col.sev"), ("line", "syntax.col.line"),
                         ("col", "syntax.col.col"), ("rule", "syntax.col.rule"),
                         ("msg", "syntax.col.msg")):
            self.tree.heading(col, text=T(key))
        self.nb.tab(0, text=T("nav.syntax"))
        self.nb.tab(1, text=T("syntax.cloud.tab"))
        if self.findings or self.summary.cget("text"):
            self._render(self.findings)

    def apply_theme(self) -> None:
        super().apply_theme()
        self.paned.configure(bg=THEME.c["bg"])
        self.app.style_tree(self.tree)


# --------------------------------------------------------------------------- #
# Security page
# --------------------------------------------------------------------------- #
class SecurityPage(Page):
    def __init__(self, app: "CtnApp") -> None:
        super().__init__(app)
        self.findings: List[Finding] = []
        self.current_path = ""
        self.filter_var = tk.StringVar(value="all")

        self.header("sec.head", "sec.desc").pack(fill="x", padx=24, pady=(20, 12))

        bar = self.card(self.frame)
        bar.pack(fill="x", padx=24)
        inner = tk.Frame(bar)
        self.kit.reg(inner, "card")
        inner.pack(fill="x", padx=14, pady=12)

        self.btn_open = make_button(self.kit, inner, "", self.open_file)
        self.btn_open.pack(side="left")
        self.lbl_filter = tk.Label(inner, text="", font=(ui_font(), 9))
        self.kit.reg(self.lbl_filter, "muted_card")
        self.lbl_filter.pack(side="left", padx=(16, 6))
        self.cmb_filter = ttk.Combobox(inner, textvariable=self.filter_var, width=12,
                                       state="readonly",
                                       values=["all", "critical", "high", "medium", "low"])
        self.cmb_filter.pack(side="left")
        self.cmb_filter.bind("<<ComboboxSelected>>", lambda e: self._render(self.findings))

        self.btn_export = make_button(self.kit, inner, "", self.export)
        self.btn_export.pack(side="right")
        self.btn_run = make_button(self.kit, inner, "", self.run, primary=True)
        self.btn_run.pack(side="right", padx=(0, 8))
        self.lbl_file = tk.Label(inner, text="", font=(ui_font(), 8))
        self.kit.reg(self.lbl_file, "muted_card")
        self.lbl_file.pack(side="right", padx=12)

        paned = tk.PanedWindow(self.frame, orient="vertical", sashwidth=6, bd=0,
                               sashrelief="flat")
        self.paned = paned
        paned.pack(fill="both", expand=True, padx=24, pady=(12, 18))

        self.editor = CodeEditor(app, paned, height=12)
        self.editors.append(self.editor)
        paned.add(self.editor.frame, minsize=120, stretch="always")

        lower = tk.Frame(paned)
        self.kit.reg(lower, "panel")
        paned.add(lower, minsize=170, stretch="always")

        tree_holder = tk.Frame(lower, highlightthickness=1)
        self.kit.reg(tree_holder, "card")
        self.app.bordered.append(tree_holder)
        tree_holder.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_holder, columns=("sev", "line", "cat", "rule", "msg"),
                                 show="headings", selectmode="browse")
        for col, width, anchor in (("sev", 70, "center"), ("line", 60, "e"),
                                   ("cat", 110, "center"), ("rule", 90, "center"),
                                   ("msg", 620, "w")):
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "msg"))
        vsb = ttk.Scrollbar(tree_holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.detail = CodeEditor(app, lower, height=5, readonly=True, wrap="word",
                                 gutter_width=2)
        self.editors.append(self.detail)
        self.detail.frame.pack(fill="x", pady=(10, 0))

        self.summary = tk.Label(self.frame, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.summary, "muted")
        self.summary.pack(fill="x", padx=24, pady=(0, 10))

    def open_file(self) -> None:
        path = filedialog.askopenfilename(title=T("common.open"),
                                          filetypes=[("All files", "*.*")])
        if not path:
            return
        content = self.app.read_text_file(path)
        if content is None:
            return
        self.current_path = path
        self.editor.set(content)
        self.lbl_file.configure(text=os.path.basename(path))

    def run(self) -> None:
        source = self.editor.get()
        if not source.strip():
            self.app.status(T("common.no_input"), "warn")
            return
        lang = detect_language(source, self.current_path)
        self.app.status(T("common.running"))
        self.btn_run.configure(state="disabled")
        started = time.time()

        def work() -> List[Finding]:
            return SecurityEngine().scan(source, lang)

        def done(ok: bool, payload: Any) -> None:
            self.btn_run.configure(state="normal")
            if not ok:
                self.app.status(f"{T('common.error')}: {payload}", "error")
                return
            self.findings = payload
            self._render(payload)
            ms = int((time.time() - started) * 1000)
            self.app.status(T("common.elapsed", ms), "ok")

        self.app.runner.submit(work, done)

    def _visible(self) -> List[Finding]:
        flt = self.filter_var.get()
        if flt == "all":
            return self.findings
        return [f for f in self.findings if f.severity == flt]

    def _render(self, findings: List[Finding]) -> None:
        self.findings = findings
        self.tree.delete(*self.tree.get_children())
        rows = self._visible()
        for f in rows:
            idx = self.findings.index(f)
            cat = T(SEC_CATEGORY_KEYS.get(f.category, "common.info"))
            self.tree.insert("", "end", iid=str(idx),
                             values=(T(f"sev.{f.severity}"), f.line, cat, f.rule, f.message),
                             tags=(f.severity,))
        counts = {k: sum(1 for f in findings if f.severity == k)
                  for k in ("critical", "high", "medium", "low")}
        if findings:
            self.summary.configure(text=T("sec.summary", counts["critical"], counts["high"],
                                          counts["medium"], counts["low"]))
        else:
            self.summary.configure(text=T("sec.clean"))
            self.detail.set("")

    def _on_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            f = self.findings[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.editor.goto(f.line, f.col)
        body = [f"[{T('sev.' + f.severity)}] {f.rule} · {T(SEC_CATEGORY_KEYS.get(f.category, 'common.info'))}",
                f"{T('sec.col.line')}: {f.line}",
                f"{f.message}"]
        if f.snippet:
            body.append(f"{T('sec.snippet')}: {f.snippet}")
        if f.fix:
            body.append(f"{T('common.suggestion')}: {f.fix}")
        self.detail.set("\n".join(body))

    def export(self) -> None:
        if not self.findings:
            self.app.status(T("common.no_input"), "warn")
            return
        path = filedialog.asksaveasfilename(defaultextension=".md",
                                            filetypes=[("Markdown", "*.md"), ("Text", "*.txt")],
                                            initialfile="ctn-security-report.md")
        if not path:
            return
        zh = I18N.lang == "zh"
        lines = [f"# {'ctn 安全扫描报告' if zh else 'ctn Security Report'}", "",
                 f"- {'文件' if zh else 'File'}: `{self.current_path or '(inline)'}`",
                 f"- {'生成时间' if zh else 'Generated'}: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                 f"- {'命中总数' if zh else 'Total findings'}: {len(self.findings)}", "",
                 f"| {'风险' if zh else 'Risk'} | {'行' if zh else 'Line'} | "
                 f"{'规则' if zh else 'Rule'} | {'说明' if zh else 'Finding'} | "
                 f"{'修复建议' if zh else 'Fix'} |",
                 "|---|---|---|---|---|"]
        for f in self.findings:
            msg = (f.zh if zh else f.en).replace("|", "\\|")
            fix = (f.fix_zh if zh else f.fix_en).replace("|", "\\|")
            lines.append(f"| {T('sev.' + f.severity)} | {f.line} | {f.rule} | {msg} | {fix} |")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            self.app.status(T("common.saved", path), "ok")
        except Exception as exc:
            self.app.status(str(exc), "error")

    def apply_texts(self) -> None:
        super().apply_texts()
        self.btn_open.configure(text=T("common.open"))
        self.btn_run.configure(text=T("common.run"))
        self.btn_export.configure(text=T("sec.export"))
        self.lbl_filter.configure(text=T("common.filter"))
        for col, key in (("sev", "sec.col.sev"), ("line", "sec.col.line"),
                         ("cat", "sec.col.cat"), ("rule", "sec.col.rule"),
                         ("msg", "sec.col.msg")):
            self.tree.heading(col, text=T(key))
        if self.findings:
            self._render(self.findings)

    def apply_theme(self) -> None:
        super().apply_theme()
        self.paned.configure(bg=THEME.c["bg"])
        self.app.style_tree(self.tree)


# --------------------------------------------------------------------------- #
# Diff page
# --------------------------------------------------------------------------- #
class DiffPage(Page):
    def __init__(self, app: "CtnApp") -> None:
        super().__init__(app)
        self.result: Optional[DiffResult] = None
        self.src_a = tk.StringVar(value="local")
        self.src_b = tk.StringVar(value="local")
        self.path_a = tk.StringVar()
        self.path_b = tk.StringVar()
        self.ignore_ws = tk.BooleanVar(value=False)
        self.ignore_case = tk.BooleanVar(value=False)

        self.header("diff.head", "diff.desc").pack(fill="x", padx=24, pady=(20, 12))

        bar = self.card(self.frame)
        bar.pack(fill="x", padx=24)
        inner = tk.Frame(bar)
        self.kit.reg(inner, "card")
        inner.pack(fill="x", padx=14, pady=12)
        inner.columnconfigure(3, weight=1)

        self.row_a = self._source_row(inner, 0, "diff.left", self.src_a, self.path_a, "a")
        self.row_b = self._source_row(inner, 1, "diff.right", self.src_b, self.path_b, "b")

        opts = tk.Frame(inner)
        self.kit.reg(opts, "card")
        opts.grid(row=2, column=0, columnspan=6, sticky="ew", pady=(10, 0))
        self.chk_ws = tk.Checkbutton(opts, text="", variable=self.ignore_ws,
                                     font=(ui_font(), 9), bd=0, highlightthickness=0,
                                     cursor="hand2")
        self.chk_case = tk.Checkbutton(opts, text="", variable=self.ignore_case,
                                       font=(ui_font(), 9), bd=0, highlightthickness=0,
                                       cursor="hand2")
        self.chk_ws.pack(side="left")
        self.chk_case.pack(side="left", padx=(12, 0))
        self.app.checks.extend([self.chk_ws, self.chk_case])

        self.btn_patch = make_button(self.kit, opts, "", lambda: self.export("patch"))
        self.btn_md = make_button(self.kit, opts, "", lambda: self.export("md"))
        self.btn_html = make_button(self.kit, opts, "", lambda: self.export("html"))
        self.btn_cmp = make_button(self.kit, opts, "", self.compare, primary=True)
        self.btn_cmp.pack(side="right")
        self.btn_html.pack(side="right", padx=(0, 8))
        self.btn_md.pack(side="right", padx=(0, 8))
        self.btn_patch.pack(side="right", padx=(0, 8))

        body = tk.Frame(self.frame)
        self.kit.reg(body, "panel")
        body.pack(fill="both", expand=True, padx=24, pady=(12, 6))
        body.columnconfigure(0, weight=1, uniform="d")
        body.columnconfigure(1, weight=1, uniform="d")
        body.rowconfigure(0, weight=1)

        self.left = CodeEditor(app, body, height=18, gutter_width=5)
        self.right = CodeEditor(app, body, height=18, gutter_width=5)
        self.editors.extend([self.left, self.right])
        self.left.link = self.right
        self.right.link = self.left
        self.left.frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.right.frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        self.stats = tk.Label(self.frame, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.stats, "muted")
        self.stats.pack(fill="x", padx=24, pady=(0, 12))

    def _source_row(self, parent: Any, row: int, label_key: str,
                    src_var: Any, path_var: Any, side: str) -> Dict[str, Any]:
        label = tk.Label(parent, text="", width=10, anchor="w", font=(ui_font(), 9, "bold"))
        self.kit.reg(label, "label")
        label.grid(row=row, column=0, sticky="w", pady=3)
        rb_local = tk.Radiobutton(parent, text="", variable=src_var, value="local",
                                  font=(ui_font(), 9), bd=0, highlightthickness=0,
                                  cursor="hand2")
        rb_cloud = tk.Radiobutton(parent, text="", variable=src_var, value="cloud",
                                  font=(ui_font(), 9), bd=0, highlightthickness=0,
                                  cursor="hand2")
        rb_local.grid(row=row, column=1, sticky="w")
        rb_cloud.grid(row=row, column=2, sticky="w", padx=(4, 10))
        self.app.radios.extend([rb_local, rb_cloud])
        entry = tk.Entry(parent, textvariable=path_var, bd=0, highlightthickness=1,
                         font=(ui_font(), 9))
        entry.grid(row=row, column=3, sticky="ew", padx=(0, 8), ipady=4)
        self.app.entries.append(entry)
        btn_browse = make_button(self.kit, parent, "", lambda: self._browse(side))
        btn_browse.grid(row=row, column=4, padx=(0, 6))
        btn_load = make_button(self.kit, parent, "", lambda: self._load(side))
        btn_load.grid(row=row, column=5)
        return {"label": label, "rb_local": rb_local, "rb_cloud": rb_cloud,
                "entry": entry, "browse": btn_browse, "load": btn_load}

    def _browse(self, side: str) -> None:
        path = filedialog.askopenfilename(title=T("common.open"))
        if not path:
            return
        (self.path_a if side == "a" else self.path_b).set(path)
        (self.src_a if side == "a" else self.src_b).set("local")
        self._load(side)

    def _load(self, side: str) -> None:
        target = self.left if side == "a" else self.right
        source = (self.src_a if side == "a" else self.src_b).get()
        value = (self.path_a if side == "a" else self.path_b).get().strip()
        if not value:
            self.app.status(T("common.no_input"), "warn")
            return
        if source == "local":
            content = self.app.read_text_file(value)
            if content is None:
                return
            target.set(content)
            self.app.status(T("common.lines", content.count("\n") + 1), "ok")
            return
        self.app.status(T("diff.fetching"))
        headers = str(self.app.cfg.get("diff_remote_headers", "{}"))

        def work() -> str:
            return self.app.cloud.fetch_text(value, headers, 30)

        def done(ok: bool, payload: Any) -> None:
            if ok:
                target.set(str(payload))
                self.app.status(T("diff.fetched", len(str(payload))), "ok")
            else:
                msg = payload.localized if isinstance(payload, CloudError) else str(payload)
                self.app.status(msg, "error")

        self.app.runner.submit(work, done)

    def compare(self) -> None:
        text_a = self.left.get()
        text_b = self.right.get()
        if not text_a.strip() or not text_b.strip():
            self.app.status(T("diff.need_both"), "warn")
            return
        name_a = os.path.basename(self.path_a.get()) or "A"
        name_b = os.path.basename(self.path_b.get()) or "B"
        result = DiffEngine().compare(text_a, text_b, name_a, name_b,
                                      self.ignore_ws.get(), self.ignore_case.get())
        self.result = result
        self._render(result)

    def _render(self, result: DiffResult) -> None:
        for editor, key in ((self.left, "a"), (self.right, "b")):
            editor.text.configure(state="normal")
            editor.text.delete("1.0", "end")
        gut_a: List[str] = []
        gut_b: List[str] = []
        for idx, row in enumerate(result.rows, 1):
            gut_a.append(str(row.lno_a) if row.lno_a else "·")
            gut_b.append(str(row.lno_b) if row.lno_b else "·")
            self.left.text.insert("end", row.text_a + "\n")
            self.right.text.insert("end", row.text_b + "\n")
            tag = {"insert": "add", "delete": "del", "replace": "chg"}.get(row.tag)
            if tag:
                if row.tag in ("delete", "replace"):
                    self.left.text.tag_add("del" if row.tag == "delete" else "chg",
                                           f"{idx}.0", f"{idx}.end+1c")
                if row.tag in ("insert", "replace"):
                    self.right.text.tag_add("add" if row.tag == "insert" else "chg",
                                            f"{idx}.0", f"{idx}.end+1c")
            for start, end in row.spans_a:
                self.left.text.tag_add("delw", f"{idx}.{start}", f"{idx}.{end}")
            for start, end in row.spans_b:
                self.right.text.tag_add("addw", f"{idx}.{start}", f"{idx}.{end}")
        self.left.set_gutter(gut_a)
        self.right.set_gutter(gut_b)
        self.left.text.edit_modified(False)
        self.right.text.edit_modified(False)
        if result.identical:
            self.stats.configure(text=T("diff.identical"))
        else:
            self.stats.configure(text="   ".join([
                T("diff.added", result.added), T("diff.removed", result.removed),
                T("diff.changed", result.changed), T("diff.same", result.same),
                T("diff.similarity", result.similarity)]))
        self.app.status(T("diff.similarity", result.similarity), "ok")

    def export(self, kind: str) -> None:
        if self.result is None:
            self.app.status(T("common.no_input"), "warn")
            return
        ext = {"html": ".html", "md": ".md", "patch": ".diff"}[kind]
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=f"ctn-diff-report{ext}",
            filetypes=[(kind.upper(), "*" + ext), ("All files", "*.*")])
        if not path:
            return
        engine = DiffEngine()
        if kind == "html":
            body = engine.to_html(self.result, I18N.lang)
        elif kind == "md":
            body = engine.to_markdown(self.result, I18N.lang)
        else:
            body = engine.to_unified(self.result)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            self.app.status(T("common.saved", path), "ok")
        except Exception as exc:
            self.app.status(str(exc), "error")

    def apply_texts(self) -> None:
        super().apply_texts()
        for row, key in ((self.row_a, "diff.left"), (self.row_b, "diff.right")):
            row["label"].configure(text=T(key))
            row["rb_local"].configure(text=T("diff.src.local"))
            row["rb_cloud"].configure(text=T("diff.src.cloud"))
            row["browse"].configure(text=T("common.browse"))
            row["load"].configure(text=T("diff.fetch"))
        self.chk_ws.configure(text=P("忽略空白差异", "Ignore whitespace"))
        self.chk_case.configure(text=P("忽略大小写", "Ignore case"))
        self.btn_cmp.configure(text=T("diff.compare"))
        self.btn_html.configure(text=T("diff.export.html"))
        self.btn_md.configure(text=T("diff.export.md"))
        self.btn_patch.configure(text=T("diff.export.patch"))
        if self.result is not None:
            self._render(self.result)


# --------------------------------------------------------------------------- #
# Prompt page
# --------------------------------------------------------------------------- #
class PromptPage(Page):
    def __init__(self, app: "CtnApp") -> None:
        super().__init__(app)
        self.goal_vars: Dict[str, Any] = {}
        self.temp = tk.DoubleVar(value=0.4)

        self.header("prompt.head", "prompt.desc").pack(fill="x", padx=24, pady=(20, 12))

        bar = self.card(self.frame)
        bar.pack(fill="x", padx=24)
        inner = tk.Frame(bar)
        self.kit.reg(inner, "card")
        inner.pack(fill="x", padx=14, pady=12)

        self.lbl_goal = tk.Label(inner, text="", font=(ui_font(), 9, "bold"))
        self.kit.reg(self.lbl_goal, "label")
        self.lbl_goal.pack(side="left")
        self.goal_checks: List[Tuple[Any, str]] = []
        for gid, key, _desc in PROMPT_GOALS:
            var = tk.BooleanVar(value=(gid in ("structure", "clarity")))
            chk = tk.Checkbutton(inner, text="", variable=var, font=(ui_font(), 9),
                                 bd=0, highlightthickness=0, cursor="hand2")
            chk.pack(side="left", padx=(10, 0))
            self.goal_vars[gid] = var
            self.goal_checks.append((chk, key))
            self.app.checks.append(chk)

        row2 = tk.Frame(bar)
        self.kit.reg(row2, "card")
        row2.pack(fill="x", padx=14, pady=(0, 12))
        self.lbl_temp = tk.Label(row2, text="", font=(ui_font(), 9))
        self.kit.reg(self.lbl_temp, "muted_card")
        self.lbl_temp.pack(side="left")
        self.spn_temp = ttk.Spinbox(row2, from_=0.0, to=2.0, increment=0.1, width=6,
                                    textvariable=self.temp)
        self.spn_temp.pack(side="left", padx=(8, 18))
        self.lbl_extra = tk.Label(row2, text="", font=(ui_font(), 9))
        self.kit.reg(self.lbl_extra, "muted_card")
        self.lbl_extra.pack(side="left")
        self.ent_extra = tk.Entry(row2, bd=0, highlightthickness=1, font=(ui_font(), 9))
        self.ent_extra.pack(side="left", fill="x", expand=True, padx=(8, 12), ipady=4)
        self.app.entries.append(self.ent_extra)
        self.btn_run = make_button(self.kit, row2, "", self.run, primary=True)
        self.btn_run.pack(side="right")

        body = tk.Frame(self.frame)
        self.kit.reg(body, "panel")
        body.pack(fill="both", expand=True, padx=24, pady=(12, 6))
        body.columnconfigure(0, weight=1, uniform="p")
        body.columnconfigure(1, weight=1, uniform="p")
        body.rowconfigure(1, weight=1)

        self.lbl_orig = tk.Label(body, text="", anchor="w", font=(ui_font(), 9, "bold"))
        self.lbl_res = tk.Label(body, text="", anchor="w", font=(ui_font(), 9, "bold"))
        self.kit.reg(self.lbl_orig, "title")
        self.kit.reg(self.lbl_res, "title")
        self.lbl_orig.grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.lbl_res.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=(0, 6))

        self.original = CodeEditor(app, body, height=16, wrap="word", gutter_width=3)
        self.result = CodeEditor(app, body, height=16, readonly=True, wrap="word",
                                 gutter_width=3)
        self.editors.extend([self.original, self.result])
        self.original.frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        self.result.frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0))

        foot = tk.Frame(self.frame)
        self.kit.reg(foot, "panel")
        foot.pack(fill="x", padx=24, pady=(4, 12))
        self.lbl_tokens = tk.Label(foot, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.lbl_tokens, "muted")
        self.lbl_tokens.pack(side="left")
        self.btn_save = make_button(self.kit, foot, "", self.save)
        self.btn_copy = make_button(self.kit, foot, "", self.copy)
        self.btn_save.pack(side="right")
        self.btn_copy.pack(side="right", padx=(0, 8))

    def run(self) -> None:
        original = self.original.get().strip()
        if not original:
            self.app.status(T("common.no_input"), "warn")
            return
        if not self.app.cloud.configured():
            self.result.set(T("prompt.need_cfg"))
            self.app.status(T("prompt.need_cfg"), "warn")
            return
        goals = [gid for gid, var in self.goal_vars.items() if var.get()]
        extra = self.ent_extra.get()
        system, prompt = build_prompt_request(original, goals, extra, I18N.lang)
        temperature = float(self.temp.get() or 0.4)
        self.result.set(T("prompt.working"))
        self.btn_run.configure(state="disabled")
        self.app.status(T("prompt.working"))

        def work() -> str:
            return self.app.cloud.chat(prompt, system, temperature)

        def done(ok: bool, payload: Any) -> None:
            self.btn_run.configure(state="normal")
            if ok:
                text = str(payload)
                self.result.set(text)
                self.lbl_tokens.configure(
                    text=T("prompt.tokens", estimate_tokens(original), estimate_tokens(text)))
                self.app.status(T("common.ready"), "ok")
            else:
                msg = payload.localized if isinstance(payload, CloudError) else str(payload)
                self.result.set(msg)
                self.app.status(msg, "error")

        self.app.runner.submit(work, done)

    def copy(self) -> None:
        text = self.result.get()
        if not text.strip():
            self.app.status(T("common.no_input"), "warn")
            return
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        self.app.status(T("common.copied"), "ok")

    def save(self) -> None:
        text = self.result.get()
        if not text.strip():
            self.app.status(T("common.no_input"), "warn")
            return
        path = filedialog.asksaveasfilename(defaultextension=".md",
                                            initialfile="ctn-prompt.md",
                                            filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.app.status(T("common.saved", path), "ok")
        except Exception as exc:
            self.app.status(str(exc), "error")

    def apply_texts(self) -> None:
        super().apply_texts()
        self.lbl_goal.configure(text=T("prompt.goal"))
        for chk, key in self.goal_checks:
            chk.configure(text=T(key))
        self.lbl_temp.configure(text=T("prompt.temperature"))
        self.lbl_extra.configure(text=T("prompt.extra"))
        self.lbl_orig.configure(text=T("prompt.original"))
        self.lbl_res.configure(text=T("prompt.result"))
        self.btn_run.configure(text=T("prompt.run"))
        self.btn_copy.configure(text=T("common.copy"))
        self.btn_save.configure(text=T("common.save"))


# --------------------------------------------------------------------------- #
# Settings page
# --------------------------------------------------------------------------- #
class SettingsPage(Page):
    def __init__(self, app: "CtnApp") -> None:
        super().__init__(app)
        self.reveal = tk.BooleanVar(value=False)
        self.strip_secrets = tk.BooleanVar(value=True)
        self._section_labels: List[Tuple[Any, str]] = []
        self._field_labels: List[Tuple[Any, str]] = []

        self.header("set.head", "set.about.text").pack(fill="x", padx=24, pady=(20, 12))

        outer = tk.Frame(self.frame)
        self.kit.reg(outer, "panel")
        outer.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        self.canvas = tk.Canvas(outer, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.inner = tk.Frame(self.canvas)
        self.kit.reg(self.inner, "panel")
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw", tags="inner")
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfigure("inner", width=e.width))
        self.canvas.bind_all("<MouseWheel>", self._wheel)

        self.vars: Dict[str, Any] = {}
        self._build_general()
        self._build_api()
        self._build_vault()
        self._build_data()
        self.load_from_config()

    def _wheel(self, event: Any) -> None:
        try:
            if self.app.current_page is not self:
                return
            self.canvas.yview_scroll(int(-event.delta / 120), "units")
        except Exception:
            pass

    def _section(self, key: str) -> Any:
        holder = tk.Frame(self.inner, highlightthickness=1)
        self.kit.reg(holder, "card")
        self.app.bordered.append(holder)
        holder.pack(fill="x", pady=(0, 14))
        title = tk.Label(holder, text="", anchor="w", font=(ui_font(), 11, "bold"))
        self.kit.reg(title, "title_card")
        title.pack(fill="x", padx=16, pady=(12, 2))
        self._section_labels.append((title, key))
        body = tk.Frame(holder)
        self.kit.reg(body, "card")
        body.pack(fill="x", padx=16, pady=(6, 14))
        body.columnconfigure(1, weight=1)
        return body

    def _field(self, parent: Any, row: int, key: str) -> Any:
        label = tk.Label(parent, text="", anchor="w", width=18, font=(ui_font(), 9))
        self.kit.reg(label, "label")
        label.grid(row=row, column=0, sticky="w", pady=5)
        self._field_labels.append((label, key))
        return label

    def _entry(self, parent: Any, row: int, name: str, show: str = "") -> Any:
        var = tk.StringVar()
        self.vars[name] = var
        entry = tk.Entry(parent, textvariable=var, bd=0, highlightthickness=1,
                         font=(ui_font(), 9))
        if show:
            entry.configure(show=show)
        entry.grid(row=row, column=1, sticky="ew", pady=5, ipady=4)
        self.app.entries.append(entry)
        return entry

    def _hint(self, parent: Any, row: int, key: str) -> Any:
        label = tk.Label(parent, text="", anchor="w", justify="left",
                         font=(ui_font(), 8), wraplength=760)
        self.kit.reg(label, "muted_card")
        label.grid(row=row, column=1, sticky="ew", pady=(0, 6))
        self._field_labels.append((label, key))
        return label

    # -- sections ------------------------------------------------------------
    def _build_general(self) -> None:
        body = self._section("set.general")
        self._field(body, 0, "set.lang")
        self.cmb_lang = ttk.Combobox(body, width=18, state="readonly",
                                     values=["中文 (Chinese)", "English"])
        self.cmb_lang.grid(row=0, column=1, sticky="w", pady=5)
        self.cmb_lang.bind("<<ComboboxSelected>>", self._on_lang)

        self._field(body, 1, "set.theme")
        self.cmb_theme = ttk.Combobox(body, width=18, state="readonly",
                                      values=[T("side.theme.light"), T("side.theme.dark")])
        self.cmb_theme.grid(row=1, column=1, sticky="w", pady=5)
        self.cmb_theme.bind("<<ComboboxSelected>>", self._on_theme)

        self._field(body, 2, "set.font")
        self.spn_font = ttk.Spinbox(body, from_=8, to=18, width=6, command=self._on_font)
        self.spn_font.grid(row=2, column=1, sticky="w", pady=5)

    def _build_api(self) -> None:
        body = self._section("set.api")
        self._field(body, 0, "set.api.url")
        self._entry(body, 0, "api_url")
        self._field(body, 1, "set.api.method")
        self.cmb_method = ttk.Combobox(body, width=10, state="readonly",
                                       values=["POST", "GET", "PUT"])
        self.cmb_method.grid(row=1, column=1, sticky="w", pady=5)
        self._field(body, 2, "set.api.model")
        self._entry(body, 2, "api_model")
        self._field(body, 3, "set.api.key")
        key_row = tk.Frame(body)
        self.kit.reg(key_row, "card")
        key_row.grid(row=3, column=1, sticky="ew", pady=5)
        key_row.columnconfigure(0, weight=1)
        var = tk.StringVar()
        self.vars["api_key"] = var
        self.ent_key = tk.Entry(key_row, textvariable=var, bd=0, highlightthickness=1,
                                show="*", font=(ui_font(), 9))
        self.ent_key.grid(row=0, column=0, sticky="ew", ipady=4)
        self.app.entries.append(self.ent_key)
        self.chk_reveal = tk.Checkbutton(key_row, text="", variable=self.reveal,
                                         command=self._toggle_reveal, font=(ui_font(), 9),
                                         bd=0, highlightthickness=0, cursor="hand2")
        self.chk_reveal.grid(row=0, column=1, padx=(8, 0))
        self.app.checks.append(self.chk_reveal)

        self._field(body, 4, "set.api.headers")
        self.txt_headers = tk.Text(body, height=4, bd=0, highlightthickness=1, wrap="none",
                                   padx=8, pady=6)
        self.txt_headers.grid(row=4, column=1, sticky="ew", pady=5)
        self.app.plain_texts.append(self.txt_headers)

        self._field(body, 5, "set.api.body")
        self.txt_body = tk.Text(body, height=9, bd=0, highlightthickness=1, wrap="none",
                                padx=8, pady=6)
        self.txt_body.grid(row=5, column=1, sticky="ew", pady=5)
        self.app.plain_texts.append(self.txt_body)
        self._hint(body, 6, "set.api.placeholders")

        self._field(body, 7, "set.api.path")
        self._entry(body, 7, "api_response_path")
        self._hint(body, 8, "set.api.path_hint")

        self._field(body, 9, "set.api.timeout")
        self._entry(body, 9, "api_timeout")
        self._field(body, 10, "set.api.proxy")
        self._entry(body, 10, "api_proxy")

        actions = tk.Frame(body)
        self.kit.reg(actions, "card")
        actions.grid(row=11, column=1, sticky="ew", pady=(10, 0))
        self.btn_save = make_button(self.kit, actions, "", self.save, primary=True)
        self.btn_test = make_button(self.kit, actions, "", self.test_connection)
        self.btn_save.pack(side="left")
        self.btn_test.pack(side="left", padx=(8, 0))

    def _build_vault(self) -> None:
        body = self._section("set.vault")
        self.lbl_vault = tk.Label(body, text="", anchor="w", justify="left",
                                  font=(ui_font(), 9), wraplength=820)
        self.kit.reg(self.lbl_vault, "label")
        self.lbl_vault.grid(row=0, column=0, columnspan=2, sticky="ew", pady=2)
        self.lbl_backend = tk.Label(body, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.lbl_backend, "muted_card")
        self.lbl_backend.grid(row=1, column=0, columnspan=2, sticky="ew", pady=2)
        self.lbl_stored = tk.Label(body, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.lbl_stored, "muted_card")
        self.lbl_stored.grid(row=2, column=0, columnspan=2, sticky="ew", pady=2)

    def _build_data(self) -> None:
        body = self._section("set.data")
        self.lbl_path = tk.Label(body, text="", anchor="w", font=(ui_font(), 8),
                                 wraplength=820, justify="left")
        self.kit.reg(self.lbl_path, "muted_card")
        self.lbl_path.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        actions = tk.Frame(body)
        self.kit.reg(actions, "card")
        actions.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.chk_strip = tk.Checkbutton(actions, text="", variable=self.strip_secrets,
                                        font=(ui_font(), 9), bd=0, highlightthickness=0,
                                        cursor="hand2")
        self.chk_strip.pack(side="left", padx=(0, 12))
        self.app.checks.append(self.chk_strip)
        self.btn_export = make_button(self.kit, actions, "", self.export_cfg)
        self.btn_import = make_button(self.kit, actions, "", self.import_cfg)
        self.btn_reset = make_button(self.kit, actions, "", self.reset_cfg)
        self.btn_export.pack(side="left")
        self.btn_import.pack(side="left", padx=(8, 0))
        self.btn_reset.pack(side="right")

    # -- behaviour -----------------------------------------------------------
    def _toggle_reveal(self) -> None:
        self.ent_key.configure(show="" if self.reveal.get() else "*")

    def _on_lang(self, _event: Any = None) -> None:
        lang = "zh" if self.cmb_lang.current() == 0 else "en"
        self.app.cfg.set("language", lang)
        self.app.set_language(lang)

    def _on_theme(self, _event: Any = None) -> None:
        name = "light" if self.cmb_theme.current() == 0 else "dark"
        self.app.cfg.set("theme", name)
        THEME.set(name)

    def _on_font(self) -> None:
        try:
            size = int(self.spn_font.get())
        except Exception:
            return
        self.app.code_size = max(8, min(18, size))
        self.app.cfg.set("font_size", self.app.code_size)
        self.app.apply_theme()

    @staticmethod
    def _select(combo: Any, index: int) -> None:
        """Select a combobox entry defensively (values may not be populated yet)."""
        values = list(combo.cget("values") or ())
        if not values:
            return
        try:
            combo.current(max(0, min(index, len(values) - 1)))
        except Exception:
            combo.set(values[max(0, min(index, len(values) - 1))])

    def load_from_config(self) -> None:
        cfg = self.app.cfg
        self._select(self.cmb_lang, 0 if cfg.get("language") == "zh" else 1)
        self._select(self.cmb_theme, 0 if cfg.get("theme") == "light" else 1)
        self.spn_font.set(int(cfg.get("font_size", 10)))
        self.cmb_method.set(str(cfg.get("api_method", "POST")))
        for name in ("api_url", "api_model", "api_key", "api_response_path",
                     "api_timeout", "api_proxy"):
            self.vars[name].set(str(cfg.get(name, "")))
        self.txt_headers.delete("1.0", "end")
        self.txt_headers.insert("1.0", str(cfg.get("api_headers", "")))
        self.txt_body.delete("1.0", "end")
        self.txt_body.insert("1.0", str(cfg.get("api_body", "")))
        self._refresh_vault()

    def _refresh_vault(self) -> None:
        ok = VAULT.self_test()
        self.lbl_vault.configure(text=T("set.vault.ok") if ok else T("set.vault.fail"),
                                 fg=THEME.c["ok"] if ok else THEME.c["high"])
        backend = "cryptography (native)" if _NATIVE_GCM is not None else "pure-python AES-256-GCM"
        self.lbl_backend.configure(text=T("set.vault.backend", backend))
        key = str(self.app.cfg.get("api_key", ""))
        self.lbl_stored.configure(
            text=T("set.vault.stored", mask_secret(key) if key else T("set.vault.empty")))

    def save(self) -> None:
        cfg = self.app.cfg
        for name in ("api_url", "api_model", "api_key", "api_response_path", "api_proxy"):
            cfg.set(name, self.vars[name].get().strip())
        try:
            cfg.set("api_timeout", int(self.vars["api_timeout"].get() or 60))
        except Exception:
            cfg.set("api_timeout", 60)
        cfg.set("api_method", self.cmb_method.get() or "POST")
        cfg.set("api_headers", self.txt_headers.get("1.0", "end-1c"))
        cfg.set("api_body", self.txt_body.get("1.0", "end-1c"))
        ok, info = cfg.save()
        self._refresh_vault()
        if ok:
            self.app.status(f"{T('set.saved')} · {info}", "ok")
        else:
            self.app.status(f"{T('common.error')}: {info}", "error")

    def test_connection(self) -> None:
        self.save()
        if not self.app.cloud.configured():
            self.app.status(T("net.no_url"), "warn")
            return
        self.app.status(T("common.running"))
        self.btn_test.configure(state="disabled")

        def work() -> str:
            return self.app.cloud.chat("Reply with exactly: OK", "You are a connectivity probe.", 0.0)

        def done(ok: bool, payload: Any) -> None:
            self.btn_test.configure(state="normal")
            if ok:
                self.app.status(f"{T('set.test.ok')} → {str(payload).strip()[:80]}", "ok")
            else:
                msg = payload.localized if isinstance(payload, CloudError) else str(payload)
                self.app.status(T("set.test.fail", msg), "error")

        self.app.runner.submit(work, done)

    def export_cfg(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            initialfile="ctn-config.json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        ok, info = self.app.cfg.export_to(path, self.strip_secrets.get())
        self.app.status(T("common.saved", info) if ok else f"{T('common.error')}: {info}",
                        "ok" if ok else "error")

    def import_cfg(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        ok, info = self.app.cfg.import_from(path)
        if ok:
            self.load_from_config()
            self.app.set_language(str(self.app.cfg.get("language", "zh")))
            THEME.set(str(self.app.cfg.get("theme", "light")))
            self.app.status(T("common.saved", info), "ok")
        else:
            self.app.status(f"{T('common.error')}: {info}", "error")

    def reset_cfg(self) -> None:
        if not messagebox.askyesno(APP_NAME, T("set.reset.confirm")):
            return
        self.app.cfg.data = dict(DEFAULTS)
        self.app.cfg.save()
        self.load_from_config()
        self.app.set_language(str(DEFAULTS["language"]))
        THEME.set(str(DEFAULTS["theme"]))
        self.app.status(T("set.saved"), "ok")

    def apply_texts(self) -> None:
        super().apply_texts()
        for label, key in self._section_labels:
            label.configure(text=T(key))
        for label, key in self._field_labels:
            label.configure(text=T(key))
        self.cmb_theme.configure(values=[T("side.theme.light"), T("side.theme.dark")])
        self.cmb_theme.current(0 if THEME.name == "light" else 1)
        self.chk_reveal.configure(text=P("显示", "Show"))
        self.chk_strip.configure(text=T("set.export.strip"))
        self.btn_save.configure(text=T("set.save"))
        self.btn_test.configure(text=T("set.test"))
        self.btn_export.configure(text=T("set.export"))
        self.btn_import.configure(text=T("set.import"))
        self.btn_reset.configure(text=T("set.reset"))
        self.lbl_path.configure(text=f"{T('set.path')}: {CONFIG_PATH}")
        self._refresh_vault()

    def apply_theme(self) -> None:
        super().apply_theme()
        colors = THEME.c
        self.canvas.configure(bg=colors["bg"])
        for widget in (self.txt_headers, self.txt_body):
            widget.configure(bg=colors["code_bg"], fg=colors["code_fg"],
                             insertbackground=colors["fg"],
                             font=(code_font(), self.app.code_size),
                             highlightbackground=colors["border"],
                             highlightcolor=colors["accent"],
                             selectbackground=colors["select"])
        self._refresh_vault()


# --------------------------------------------------------------------------- #
# Main application shell
# --------------------------------------------------------------------------- #
class NavItem:
    def __init__(self, app: "CtnApp", parent: Any, key: str, sub_key: str,
                 icon: str, command: Callable[[], None]) -> None:
        self.app = app
        self.key = key
        self.sub_key = sub_key
        self.active = False
        self.frame = tk.Frame(parent, cursor="hand2")
        self.bar = tk.Frame(self.frame, width=3)
        self.bar.pack(side="left", fill="y")
        body = tk.Frame(self.frame)
        body.pack(side="left", fill="both", expand=True, padx=(9, 10), pady=8)
        self.icon = tk.Label(body, text=icon, font=(ui_font(), 11))
        self.icon.pack(side="left", padx=(0, 9))
        texts = tk.Frame(body)
        texts.pack(side="left", fill="x", expand=True)
        self.title = tk.Label(texts, text="", anchor="w", font=(ui_font(), 10))
        self.sub = tk.Label(texts, text="", anchor="w", font=(ui_font(), 7))
        self.title.pack(fill="x")
        self.sub.pack(fill="x")
        self._body = body
        self._texts = texts
        for widget in (self.frame, body, texts, self.icon, self.title, self.sub):
            widget.bind("<Button-1>", lambda e: command())
            widget.bind("<Enter>", self._enter)
            widget.bind("<Leave>", self._leave)

    def _enter(self, _e: Any = None) -> None:
        if not self.active:
            self._paint(hover=True)

    def _leave(self, _e: Any = None) -> None:
        if not self.active:
            self._paint(hover=False)

    def set_active(self, active: bool) -> None:
        self.active = active
        self._paint()

    def _paint(self, hover: bool = False) -> None:
        colors = THEME.c
        if self.active:
            bg, fg = colors["sidebar_active"], colors["sidebar_active_fg"]
            self.bar.configure(bg=colors["accent"])
        else:
            bg = colors["sidebar_active"] if hover else colors["sidebar"]
            fg = colors["sidebar_fg"]
            self.bar.configure(bg=bg)
        for widget in (self.frame, self._body, self._texts):
            widget.configure(bg=bg)
        self.icon.configure(bg=bg, fg=colors["accent"] if self.active else fg)
        self.title.configure(bg=bg, fg=fg)
        self.sub.configure(bg=bg, fg=colors["fg_dim"] if not self.active else colors["sidebar_fg"])

    def apply_texts(self) -> None:
        self.title.configure(text=T(self.key))
        self.sub.configure(text=T(self.sub_key))


class CtnApp:
    def __init__(self) -> None:
        self.cfg = ConfigStore()
        I18N.lang = str(self.cfg.get("language", "zh"))
        THEME.name = str(self.cfg.get("theme", "light"))
        self.code_size = int(self.cfg.get("font_size", 10))
        self.cloud = CloudClient(self.cfg)
        self.kit = UIKit()
        self.bordered: List[Any] = []
        self.entries: List[Any] = []
        self.checks: List[Any] = []
        self.radios: List[Any] = []
        self.plain_texts: List[Any] = []

        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} · {APP_FULL} v{APP_VERSION}")
        self.root.geometry("1280x820")
        self.root.minsize(1080, 700)
        self.runner = AsyncRunner(self.root)
        self.style = ttk.Style(self.root)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Disable Windows 11 title-bar accent override so the dark theme title
        # bar stays neutral (attribute 19 = DWMWA_USE_IMMERSIVE_DARK_MODE_TITLE_BAR).
        if sys.platform.startswith("win"):
            try:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    ctypes.windll.user32.GetParent(self.root.winfo_id()),
                    19,
                    ctypes.byref(ctypes.c_int(1)),
                    ctypes.sizeof(ctypes.c_int))
            except Exception:
                pass

        self.kit.reg(self.root, "root")
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content()
        self._build_statusbar()

        self.pages: Dict[str, Page] = {
            "syntax": SyntaxPage(self),
            "security": SecurityPage(self),
            "diff": DiffPage(self),
            "prompt": PromptPage(self),
            "settings": SettingsPage(self),
        }
        for page in self.pages.values():
            page.frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.current_page: Optional[Page] = None

        I18N.on_change(self.apply_texts)
        THEME.on_change(self.apply_theme)
        self.apply_theme()
        self.apply_texts()
        self.show("syntax")
        if not self.cfg.vault_ok:
            self.status(T("set.vault.locked"), "warn")
        else:
            self.status(T("common.ready"))
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- construction --------------------------------------------------------
    def _build_sidebar(self) -> None:
        self.sidebar = tk.Frame(self.root, width=214)
        self.sidebar.grid(row=0, column=0, sticky="nsw", rowspan=2)
        self.sidebar.grid_propagate(False)
        self.kit.reg(self.sidebar, "sidebar")

        brand = tk.Frame(self.sidebar)
        brand.pack(fill="x", pady=(22, 6), padx=18)
        self.kit.reg(brand, "sidebar")
        self.brand_mark = tk.Label(brand, text="ctn", font=(ui_font(), 21, "bold"), anchor="w")
        self.brand_mark.pack(fill="x")
        self.brand_sub = tk.Label(brand, text=APP_FULL, font=(ui_font(), 8), anchor="w")
        self.brand_sub.pack(fill="x")
        self.brand_tag = tk.Label(brand, text="", font=(ui_font(), 7), anchor="w")
        self.brand_tag.pack(fill="x", pady=(6, 0))

        sep = tk.Frame(self.sidebar, height=1)
        sep.pack(fill="x", padx=18, pady=(14, 10))
        self.kit.reg(sep, "sep")

        nav_box = tk.Frame(self.sidebar)
        nav_box.pack(fill="x")
        self.kit.reg(nav_box, "sidebar")
        specs = [("syntax", "nav.syntax", "nav.syntax.sub", "\u25c6"),
                 ("security", "nav.security", "nav.security.sub", "\u26a0"),
                 ("diff", "nav.diff", "nav.diff.sub", "\u21c4"),
                 ("prompt", "nav.prompt", "nav.prompt.sub", "\u270e"),
                 ("settings", "nav.settings", "nav.settings.sub", "\u2699")]
        self.nav: Dict[str, NavItem] = {}
        for pid, key, sub, icon in specs:
            item = NavItem(self, nav_box, key, sub, icon, lambda p=pid: self.show(p))
            item.frame.pack(fill="x")
            self.nav[pid] = item

        bottom = tk.Frame(self.sidebar)
        bottom.pack(side="bottom", fill="x", padx=14, pady=16)
        self.kit.reg(bottom, "sidebar")
        self.btn_theme = tk.Button(bottom, text="", command=self.toggle_theme, relief="flat",
                                   bd=0, cursor="hand2", font=(ui_font(), 9), pady=5,
                                   highlightthickness=0)
        self.btn_lang = tk.Button(bottom, text="", command=self.toggle_language, relief="flat",
                                  bd=0, cursor="hand2", font=(ui_font(), 9), pady=5,
                                  highlightthickness=0)
        self.btn_theme.pack(fill="x")
        self.btn_lang.pack(fill="x", pady=(6, 0))
        self.lbl_version = tk.Label(bottom, text=f"v{APP_VERSION} · {APP_BUILD}",
                                    font=(ui_font(), 7))
        self.lbl_version.pack(fill="x", pady=(10, 0))

    def _build_content(self) -> None:
        self.content = tk.Frame(self.root)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.kit.reg(self.content, "panel")

    def _build_statusbar(self) -> None:
        self.statusbar = tk.Frame(self.root, height=30)
        self.statusbar.grid(row=1, column=1, sticky="ew")
        self.kit.reg(self.statusbar, "card")
        self.status_dot = tk.Label(self.statusbar, text="\u25cf", font=(ui_font(), 9))
        self.status_dot.pack(side="left", padx=(20, 6), pady=5)
        self.status_text = tk.Label(self.statusbar, text="", anchor="w", font=(ui_font(), 9))
        self.kit.reg(self.status_text, "muted_card")
        self.status_text.pack(side="left", fill="x", expand=True)
        self.status_right = tk.Label(self.statusbar, text="", anchor="e", font=(ui_font(), 8))
        self.kit.reg(self.status_right, "muted_card")
        self.status_right.pack(side="right", padx=20)

    # -- helpers -------------------------------------------------------------
    def style_tree(self, tree: Any) -> None:
        colors = THEME.c
        rowheight = max(22, self.code_size * 2 + 4)
        self.style.configure("Treeview", background=colors["panel"],
                             fieldbackground=colors["panel"], foreground=colors["fg"],
                             bordercolor=colors["border"], borderwidth=0,
                             rowheight=rowheight, font=(ui_font(), 9))
        self.style.configure("Treeview.Heading", background=colors["panel_alt"],
                             foreground=colors["fg_dim"], relief="flat",
                             font=(ui_font(), 9, "bold"), padding=(6, 6))
        self.style.map("Treeview.Heading", background=[("active", colors["accent_soft"])])
        self.style.map("Treeview",
                       background=[("selected", colors["accent_soft"])],
                       foreground=[("selected", colors["fg"])])
        for sev, key in (("critical", "critical"), ("high", "high"), ("error", "high"),
                         ("medium", "medium"), ("warning", "medium"),
                         ("low", "low"), ("info", "low")):
            tree.tag_configure(sev, foreground=colors[key])

    def read_text_file(self, path: str) -> Optional[str]:
        try:
            limit = int(self.cfg.get("scan_max_bytes", 4 * 1024 * 1024))
            if os.path.getsize(path) > limit:
                self.status(P(f"文件超过 {limit // 1024 // 1024} MB，已拒绝载入",
                              f"File exceeds {limit // 1024 // 1024} MB and was not loaded"), "warn")
                return None
            with open(path, "rb") as fh:
                raw = fh.read()
            for encoding in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
                try:
                    return raw.decode(encoding)
                except UnicodeDecodeError:
                    continue
            return raw.decode("utf-8", "replace")
        except Exception as exc:
            self.status(T("common.read_fail", exc), "error")
            return None

    def status(self, message: str, kind: str = "info") -> None:
        colors = THEME.c
        palette = {"info": colors["fg_dim"], "ok": colors["ok"],
                   "warn": colors["medium"], "error": colors["high"]}
        self.status_dot.configure(fg=palette.get(kind, colors["fg_dim"]),
                                  bg=colors["panel"])
        self.status_text.configure(text=message.replace("\n", " ")[:400])

    def show(self, page_id: str) -> None:
        page = self.pages[page_id]
        page.frame.lift()
        self.current_page = page
        for pid, item in self.nav.items():
            item.set_active(pid == page_id)
        page.on_show()

    def toggle_theme(self) -> None:
        THEME.toggle()
        self.cfg.set("theme", THEME.name)

    def toggle_language(self) -> None:
        new_lang = "en" if I18N.lang == "zh" else "zh"
        self.cfg.set("language", new_lang)
        self.set_language(new_lang)

    def set_language(self, lang: str) -> None:
        I18N.set_lang(lang)
        if hasattr(self, "pages") and "settings" in self.pages:
            settings = self.pages["settings"]
            if isinstance(settings, SettingsPage):
                settings.cmb_lang.current(0 if lang == "zh" else 1)
        # Re-render the current page so stale translated labels (statusbar, badges,
        # tree headers, etc.) get refreshed to the new language.
        if getattr(self, "current_page", None) is not None:
            try:
                self.current_page.apply_texts()
            except Exception:
                pass
        if hasattr(self, "status_text"):
            try:
                self.status(self.status_text.cget("text") or T("common.ready"))
            except Exception:
                pass

    # -- refresh -------------------------------------------------------------
    def apply_texts(self) -> None:
        self.brand_tag.configure(text=T("app.tagline"))
        for item in self.nav.values():
            item.apply_texts()
        self.btn_theme.configure(
            text=("\u25d0  " + T("side.theme.dark")) if THEME.name == "light"
            else ("\u25d1  " + T("side.theme.light")))
        self.btn_lang.configure(text="\u6587  " + ("English" if I18N.lang == "zh" else "中文"))
        self.status_right.configure(text=T("side.offline"))
        for page in getattr(self, "pages", {}).values():
            page.apply_texts()

    def apply_theme(self) -> None:
        colors = THEME.c
        self.kit.apply()
        paint_buttons(self.kit)
        self.root.configure(bg=colors["bg"])
        self.sidebar.configure(bg=colors["sidebar"])
        for widget in (self.brand_mark, self.brand_sub, self.brand_tag, self.lbl_version):
            widget.configure(bg=colors["sidebar"])
        self.brand_mark.configure(fg=colors["accent"])
        self.brand_sub.configure(fg=colors["sidebar_fg"])
        self.brand_tag.configure(fg=colors["fg_dim"])
        self.lbl_version.configure(fg=colors["fg_dim"])
        for btn in (self.btn_theme, self.btn_lang):
            btn.configure(bg=colors["sidebar_active"], fg=colors["sidebar_fg"],
                          activebackground=colors["accent"],
                          activeforeground=colors["accent_fg"])
        for item in self.nav.values():
            item._paint()

        for frame in self.bordered:
            try:
                frame.configure(highlightbackground=colors["border"],
                                highlightcolor=colors["border"])
            except Exception:
                pass
        for entry in self.entries:
            try:
                entry.configure(bg=colors["panel_alt"], fg=colors["fg"],
                                insertbackground=colors["fg"],
                                highlightbackground=colors["border"],
                                highlightcolor=colors["accent"],
                                disabledbackground=colors["panel_alt"],
                                selectbackground=colors["select"])
            except Exception:
                pass
        for widget in self.checks + self.radios:
            try:
                widget.configure(bg=colors["panel"], fg=colors["fg"],
                                 activebackground=colors["panel"],
                                 activeforeground=colors["accent"],
                                 selectcolor=colors["panel_alt"])
            except Exception:
                pass

        self.style.configure("TScrollbar", background=colors["panel_alt"],
                             troughcolor=colors["bg"], bordercolor=colors["bg"],
                             arrowcolor=colors["fg_dim"], relief="flat")
        self.style.map("TScrollbar", background=[("active", colors["accent_soft"])])
        self.style.configure("TCombobox", fieldbackground=colors["panel_alt"],
                             background=colors["panel_alt"], foreground=colors["fg"],
                             arrowcolor=colors["fg_dim"], bordercolor=colors["border"],
                             lightcolor=colors["border"], darkcolor=colors["border"],
                             padding=5)
        self.style.map("TCombobox",
                       fieldbackground=[("readonly", colors["panel_alt"])],
                       foreground=[("readonly", colors["fg"])],
                       selectbackground=[("readonly", colors["panel_alt"])],
                       selectforeground=[("readonly", colors["fg"])])
        self.root.option_add("*TCombobox*Listbox.background", colors["panel"])
        self.root.option_add("*TCombobox*Listbox.foreground", colors["fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", colors["accent"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", colors["accent_fg"])
        self.style.configure("TSpinbox", fieldbackground=colors["panel_alt"],
                             background=colors["panel_alt"], foreground=colors["fg"],
                             arrowcolor=colors["fg_dim"], bordercolor=colors["border"],
                             padding=4)
        self.style.configure("TNotebook", background=colors["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", background=colors["panel_alt"],
                             foreground=colors["fg_dim"], padding=(16, 7),
                             font=(ui_font(), 9), borderwidth=0)
        self.style.map("TNotebook.Tab",
                       background=[("selected", colors["panel"])],
                       foreground=[("selected", colors["fg"])])

        for widget in self.plain_texts:
            try:
                widget.configure(bg=colors["code_bg"], fg=colors["code_fg"],
                                 insertbackground=colors["fg"],
                                 highlightbackground=colors["border"],
                                 highlightcolor=colors["accent"],
                                 selectbackground=colors["select"])
            except Exception:
                pass

        for page in getattr(self, "pages", {}).values():
            page.apply_theme()
        if hasattr(self, "status_text"):
            self.status(self.status_text.cget("text") or T("common.ready"))
        if hasattr(self, "btn_theme"):
            self.btn_theme.configure(
                text=("\u25d0  " + T("side.theme.dark")) if THEME.name == "light"
                else ("\u25d1  " + T("side.theme.light")))

    def _on_close(self) -> None:
        try:
            self.cfg.save()
        except Exception:
            pass
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


# =============================================================================
# SECTION 11 - Command line interface (English output only)
# =============================================================================

CLI_HELP = f"""{APP_NAME} - {APP_FULL} v{APP_VERSION}
A local-first bilingual developer toolkit.

USAGE
  python ctn.py                      Launch the graphical interface
  python ctn.py --check <file>       Run the offline syntax check
  python ctn.py --scan <file>        Run the offline security scan
  python ctn.py --diff <A> <B>       Compare two files
  python ctn.py --selftest           Verify the built-in crypto and engines
  python ctn.py --version            Print the version
  python ctn.py --help               Show this message

OPTIONS
  --json                             Emit machine-readable JSON
  --lang <python|javascript|...>     Force a language instead of auto-detect

EXIT CODES
  0  success, no blocking issues
  1  issues found
  2  usage or runtime error
"""


def _cli_read(path: str) -> str:
    with open(path, "rb") as fh:
        raw = fh.read()
    for encoding in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _cli_print_findings(findings: List[Finding], as_json: bool, header: str) -> None:
    if as_json:
        print(json.dumps([{
            "severity": f.severity, "line": f.line, "column": f.col,
            "rule": f.rule, "category": f.category,
            "message": f.en, "fix": f.fix_en, "snippet": f.snippet,
        } for f in findings], ensure_ascii=False, indent=2))
        return
    print(header)
    print("-" * len(header))
    if not findings:
        print("No issues found.")
        return
    width = max(len(f.rule) for f in findings)
    for f in findings:
        print(f"  {f.severity.upper():<9} {f.line:>5}:{f.col:<4} "
              f"{f.rule:<{width}}  {f.en}")
        if f.snippet:
            print(f"      snippet: {f.snippet}")
        if f.fix_en:
            print(f"      fix    : {f.fix_en}")
    print()
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print("Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def _cli_selftest() -> int:
    print(f"{APP_NAME} self-test")
    print("-" * 24)
    failures = 0

    probe = "ctn/secret/\u4e2d\u6587/" + base64.b16encode(os.urandom(8)).decode()
    sealed = VAULT.seal(probe)
    try:
        ok = VAULT.open(sealed) == probe
    except Exception:
        ok = False
    print(f"  [{'PASS' if ok else 'FAIL'}] AES-256-GCM round trip")
    failures += 0 if ok else 1

    tampered = sealed[:-6] + ("A" if sealed[-6] != "A" else "B") + sealed[-5:]
    try:
        VAULT.open(tampered)
        detected = False
    except VaultError:
        detected = True
    except Exception:
        detected = True
    print(f"  [{'PASS' if detected else 'FAIL'}] GCM tamper detection")
    failures += 0 if detected else 1

    # Known-answer test for the AES-256 block cipher (FIPS-197 C.3).
    key = bytes(range(32))
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    expect = "8ea2b7ca516745bfeafc49904b496089"
    got = AES256(key).encrypt_block(plain).hex()
    ok = got == expect
    print(f"  [{'PASS' if ok else 'FAIL'}] AES-256 FIPS-197 known-answer vector")
    failures += 0 if ok else 1

    bad_python = "def broken(:\n    return 1\n"
    findings = SyntaxEngine().analyse(bad_python, "python")
    ok = any(f.severity == "error" for f in findings)
    print(f"  [{'PASS' if ok else 'FAIL'}] syntax engine detects a real SyntaxError")
    failures += 0 if ok else 1

    clean_python = "import os\n\n\ndef ok(path):\n    return os.path.exists(path)\n"
    findings = SyntaxEngine().analyse(clean_python, "python")
    ok = not any(f.severity == "error" for f in findings)
    print(f"  [{'PASS' if ok else 'FAIL'}] syntax engine stays quiet on valid code")
    failures += 0 if ok else 1

    risky = 'api_key = "sk-abcd1234efgh5678ijkl9012"\nos.system("rm -rf " + target)\n'
    findings = SecurityEngine().scan(risky, "python")
    ok = any(f.category == "secret" for f in findings) and any(
        f.category in ("danger", "path") for f in findings)
    print(f"  [{'PASS' if ok else 'FAIL'}] security engine flags secret + dangerous call")
    failures += 0 if ok else 1

    result = DiffEngine().compare("a\nb\nc\n", "a\nB\nc\nd\n")
    ok = result.changed == 1 and result.added == 1
    print(f"  [{'PASS' if ok else 'FAIL'}] diff engine line accounting")
    failures += 0 if ok else 1

    ok = extract_path({"choices": [{"message": {"content": "hi"}}]},
                      "choices.0.message.content") == "hi"
    print(f"  [{'PASS' if ok else 'FAIL'}] response path extraction")
    failures += 0 if ok else 1

    backend = "cryptography (native)" if _NATIVE_GCM is not None else "pure-python"
    print(f"\nCrypto backend : {backend}")
    print(f"Config file    : {CONFIG_PATH}")
    print(f"Tkinter        : {'available' if TK_AVAILABLE else 'NOT available'}")
    print(f"\nResult: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
    return 0 if failures == 0 else 1


def cli_main(argv: List[str]) -> int:
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    forced_lang = ""
    if "--lang" in argv:
        idx = argv.index("--lang")
        if idx + 1 < len(argv):
            forced_lang = argv[idx + 1]
            del argv[idx:idx + 2]

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(CLI_HELP)
        return 0
    command = argv[0]

    if command in ("-v", "--version", "version"):
        print(f"{APP_NAME} {APP_VERSION} (build {APP_BUILD})")
        return 0

    if command == "--selftest":
        return _cli_selftest()

    try:
        if command == "--check":
            if len(argv) < 2:
                print("Error: --check requires a file path.", file=sys.stderr)
                return 2
            path = argv[1]
            text = _cli_read(path)
            lang = forced_lang or detect_language(text, path)
            findings = SyntaxEngine().analyse(text, lang)
            _cli_print_findings(findings, as_json,
                                f"Syntax check: {path}  [{lang}]")
            return 1 if any(f.severity == "error" for f in findings) else 0

        if command == "--scan":
            if len(argv) < 2:
                print("Error: --scan requires a file path.", file=sys.stderr)
                return 2
            path = argv[1]
            text = _cli_read(path)
            lang = forced_lang or detect_language(text, path)
            findings = SecurityEngine().scan(text, lang)
            _cli_print_findings(findings, as_json,
                                f"Security scan: {path}  [{lang}]")
            return 1 if any(f.severity in ("critical", "high") for f in findings) else 0

        if command == "--diff":
            if len(argv) < 3:
                print("Error: --diff requires two file paths.", file=sys.stderr)
                return 2
            path_a, path_b = argv[1], argv[2]
            result = DiffEngine().compare(_cli_read(path_a), _cli_read(path_b),
                                          os.path.basename(path_a), os.path.basename(path_b))
            if as_json:
                print(json.dumps({
                    "added": result.added, "removed": result.removed,
                    "changed": result.changed, "unchanged": result.same,
                    "similarity": result.similarity,
                }, indent=2))
            else:
                print(f"Diff: {path_a} <-> {path_b}")
                print("-" * 48)
                print(DiffEngine.to_unified(result) or "Both files are identical.")
                print()
                print(f"Summary: +{result.added} -{result.removed} "
                      f"~{result.changed} ={result.same}  "
                      f"similarity={result.similarity}%")
            return 0 if result.identical else 1

        print(f"Error: unknown command '{command}'. Try --help.", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def main() -> None:
    args = sys.argv[1:]
    if args:
        sys.exit(cli_main(args))
    if not TK_AVAILABLE:
        print("Error: Tkinter is not available in this Python installation.", file=sys.stderr)
        print("Install it, or use the CLI: python ctn.py --help", file=sys.stderr)
        sys.exit(2)
    CtnApp().run()


if __name__ == "__main__":
    main()
