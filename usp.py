#!/usr/bin/env python3
"""
usp - Upload Static Page CLI

A single-file client for the USP static page host. Standard library only.

    usp init                 create .usp.json and .env in the current directory
    usp whoami               verify the key and print quota
    usp push [dir]           upload a directory (incremental by default)
    usp ls [prefix]          list remote files
    usp rm <path...>         delete remote files
    usp open                 print the public URL
    usp doctor               run connectivity and configuration checks

Exit codes: 0 ok, 1 runtime error, 2 usage error, 3 authentication failure.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

DEFAULT_ENDPOINT = "https://usp.kscm.top"
CONFIG_NAME = ".usp.json"
ENV_NAME = ".env"
ENV_KEY = "USP_KEY"

ALLOWED_EXT = {".html", ".htm", ".css", ".js", ".mjs", ".md", ".markdown"}
DEFAULT_IGNORE = [
    ".git/**", ".svn/**", "node_modules/**", "__pycache__/**",
    ".DS_Store", "Thumbs.db", "*.map", ".env", ".usp.json",
]

BATCH_FILES = 40
BATCH_BYTES = 6 * 1024 * 1024

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_AUTH = 0, 1, 2, 3


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

class Style:
    def __init__(self) -> None:
        self.on = self._supported()
        self.dim = "\033[2m" if self.on else ""
        self.bold = "\033[1m" if self.on else ""
        self.red = "\033[31m" if self.on else ""
        self.green = "\033[32m" if self.on else ""
        self.yellow = "\033[33m" if self.on else ""
        self.cyan = "\033[36m" if self.on else ""
        self.off = "\033[0m" if self.on else ""

    @staticmethod
    def _supported() -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        if not sys.stdout.isatty():
            return False
        if os.name == "nt":
            try:
                import ctypes
                kernel = ctypes.windll.kernel32
                kernel.SetConsoleMode(kernel.GetStdHandle(-11), 7)
            except Exception:
                return False
        return True


S = Style()


def out(line: str = "") -> None:
    print(line)


def tag(label: str, message: str, colour: str = "") -> None:
    print(f"{colour}{label:<10}{S.off}{message}")


def info(message: str) -> None:
    print(f"{S.dim}{message}{S.off}")


def warn(message: str) -> None:
    print(f"{S.yellow}warning{S.off}   {message}", file=sys.stderr)


def die(message: str, code: int = EXIT_ERROR) -> None:
    print(f"{S.red}error{S.off}     {message}", file=sys.stderr)
    sys.exit(code)


def human(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1048576:.2f} MB"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.endpoint = DEFAULT_ENDPOINT
        self.directory = "."
        self.ignore: List[str] = list(DEFAULT_IGNORE)
        self.key: Optional[str] = None
        self.source = "defaults"

    @classmethod
    def load(cls, start: Path, override_key: Optional[str] = None) -> "Config":
        root = cls._find_root(start)
        cfg = cls(root)

        path = root / CONFIG_NAME
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                die(f"cannot read {CONFIG_NAME}: {exc}")
            cfg.endpoint = str(data.get("endpoint", cfg.endpoint)).rstrip("/")
            cfg.directory = str(data.get("dir", cfg.directory))
            extra = data.get("ignore")
            if isinstance(extra, list):
                cfg.ignore = list(DEFAULT_IGNORE) + [str(x) for x in extra]
            cfg.source = str(path)

        cfg.key = (
            override_key
            or os.environ.get(ENV_KEY)
            or cls._read_env(root / ENV_NAME)
        )
        return cfg

    @staticmethod
    def _find_root(start: Path) -> Path:
        cur = start.resolve()
        for candidate in [cur, *cur.parents]:
            if (candidate / CONFIG_NAME).is_file():
                return candidate
        return cur

    @staticmethod
    def _read_env(path: Path) -> Optional[str]:
        if not path.is_file():
            return None
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                if name.strip() == ENV_KEY:
                    return value.strip().strip("'\"")
        except OSError:
            return None
        return None

    def require_key(self) -> str:
        if not self.key:
            die(
                "no API key found. Set USP_KEY, add it to .env, or pass --key.\n"
                "          Run 'usp init' to create the config files.",
                EXIT_AUTH,
            )
        return self.key  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class ApiError(Exception):
    def __init__(self, code: str, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class Client:
    def __init__(self, endpoint: str, key: str, timeout: int = 60) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.key = key
        self.timeout = timeout

    def _request(self, path: str, body: bytes, content_type: str) -> Dict[str, Any]:
        url = f"{self.endpoint}{path}"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", content_type)
        req.add_header("X-USP-Key", self.key)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", f"usp-cli/{__version__}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            raise ApiError("network", f"cannot reach {self.endpoint}: {exc.reason}") from exc
        except OSError as exc:
            raise ApiError("network", f"cannot reach {self.endpoint}: {exc}") from exc

        try:
            data = json.loads(payload.decode("utf-8", "replace"))
        except ValueError:
            snippet = payload[:160].decode("utf-8", "replace").replace("\n", " ")
            raise ApiError("bad_response", f"HTTP {status}, non-JSON response: {snippet}", status)

        if not isinstance(data, dict):
            raise ApiError("bad_response", f"HTTP {status}, unexpected response shape", status)
        if not data.get("ok"):
            raise ApiError(
                str(data.get("code", "error")),
                str(data.get("error", f"HTTP {status}")),
                status,
            )
        return data

    def form(self, path: str, fields: Dict[str, str]) -> Dict[str, Any]:
        parts = []
        for name, value in fields.items():
            parts.append(f"{urllib.parse.quote_plus(name)}={urllib.parse.quote_plus(value)}")
        body = "&".join(parts).encode("utf-8")
        return self._request(path, body, "application/x-www-form-urlencoded")

    def multipart(self, path: str, fields: List[Tuple[str, str]],
                  files: List[Tuple[str, str, bytes]]) -> Dict[str, Any]:
        boundary = "----usp" + uuid.uuid4().hex
        chunks: List[bytes] = []
        for name, value in fields:
            chunks.append(f"--{boundary}\r\n".encode())
            chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            chunks.append(value.encode("utf-8"))
            chunks.append(b"\r\n")
        for name, filename, data in files:
            ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            safe = filename.replace('"', "").replace("\\", "/")
            chunks.append(f"--{boundary}\r\n".encode())
            chunks.append(
                f'Content-Disposition: form-data; name="{name}"; filename="{safe}"\r\n'.encode()
            )
            chunks.append(f"Content-Type: {ctype}\r\n\r\n".encode())
            chunks.append(data)
            chunks.append(b"\r\n")
        chunks.append(f"--{boundary}--\r\n".encode())
        return self._request(path, b"".join(chunks), f"multipart/form-data; boundary={boundary}")


# ---------------------------------------------------------------------------
# Local scanning
# ---------------------------------------------------------------------------

def rel_posix(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def ignored(rel: str, patterns: List[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    for pattern in patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3]
            if rel == prefix or rel.startswith(prefix + "/"):
                return True
    return False


def scan(base: Path, patterns: List[str]) -> Tuple[Dict[str, Tuple[Path, int, str]], List[str]]:
    """Return {relpath: (path, size, sha256)} plus a list of filtered-out paths."""
    accepted: Dict[str, Tuple[Path, int, str]] = {}
    filtered: List[str] = []

    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = rel_posix(path, base)
        except ValueError:
            continue
        if ignored(rel, patterns):
            continue
        if path.suffix.lower() not in ALLOWED_EXT:
            filtered.append(rel)
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            warn(f"cannot read {rel}: {exc}")
            continue
        accepted[rel] = (path, len(data), hashlib.sha256(data).hexdigest())
    return accepted, filtered


def check_external_scripts(path: Path) -> List[str]:
    """Report external script sources in an HTML file. Advisory only."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits = []
    lowered = text.lower()
    cursor = 0
    while True:
        idx = lowered.find("<script", cursor)
        if idx == -1:
            break
        end = lowered.find(">", idx)
        if end == -1:
            break
        tag_text = text[idx:end]
        low = tag_text.lower()
        if "src=" in low and ("http://" in low or "https://" in low or "//" in low.split("src=")[1][:4]):
            for token in ("https://", "http://"):
                pos = low.find(token)
                if pos != -1:
                    frag = tag_text[pos:].split('"')[0].split("'")[0].split()[0]
                    hits.append(frag[:80])
                    break
        cursor = end
    return hits


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    root = Path.cwd()
    cfg_path = root / CONFIG_NAME
    env_path = root / ENV_NAME

    out(f"{S.bold}USP setup{S.off}  {root}")
    out()

    if cfg_path.exists() and not args.force:
        die(f"{CONFIG_NAME} already exists. Use --force to overwrite.", EXIT_USAGE)

    def ask(prompt: str, default: str) -> str:
        try:
            value = input(f"  {prompt} [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            out()
            die("cancelled", EXIT_USAGE)
        return value or default

    endpoint = args.endpoint or ask("Endpoint", DEFAULT_ENDPOINT)
    directory = args.dir or ask("Directory to publish", ".")
    key = args.key or ""
    if not key:
        try:
            key = input("  API key (leave blank to fill in later): ").strip()
        except (EOFError, KeyboardInterrupt):
            out()
            die("cancelled", EXIT_USAGE)

    config = {
        "endpoint": endpoint.rstrip("/"),
        "dir": directory,
        "ignore": ["*.map"],
    }
    cfg_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    tag("created", CONFIG_NAME, S.green)

    if key:
        lines = []
        if env_path.is_file():
            lines = [
                ln for ln in env_path.read_text(encoding="utf-8").splitlines()
                if not ln.strip().startswith(ENV_KEY + "=")
            ]
        lines.append(f"{ENV_KEY}={key}")
        env_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
        tag("created", f"{ENV_NAME} (contains your key)", S.green)

    gitignore = root / ".gitignore"
    entries = []
    existing = gitignore.read_text(encoding="utf-8") if gitignore.is_file() else ""
    for entry in (ENV_NAME, CONFIG_NAME):
        if entry not in existing.split():
            entries.append(entry)
    if entries:
        with gitignore.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write("\n".join(entries) + "\n")
        tag("updated", f".gitignore (+{', '.join(entries)})", S.green)

    out()
    info("Next: usp whoami")
    return EXIT_OK


def cmd_whoami(args: argparse.Namespace) -> int:
    cfg = Config.load(Path.cwd(), args.key)
    client = Client(cfg.endpoint, cfg.require_key(), args.timeout)
    data = client.form("/api/whoami.php", {})

    quota = data.get("quota", {})
    out(f"{S.bold}space{S.off}      {data.get('space')}")
    out(f"{S.bold}label{S.off}      {data.get('label')}")
    out(f"{S.bold}url{S.off}        {S.cyan}{data.get('url')}{S.off}")
    out(f"{S.bold}files{S.off}      {quota.get('files', 0)} / {quota.get('maxFiles', 0)}")
    used, cap = quota.get("bytes", 0), quota.get("maxBytes", 1)
    pct = (used / cap * 100) if cap else 0
    out(f"{S.bold}storage{S.off}    {human(used)} / {human(cap)}  ({pct:.1f}%)")
    out(f"{S.bold}accepts{S.off}    {' '.join('.' + e for e in data.get('allowed', []))}")
    out(f"{S.bold}server{S.off}     v{data.get('version')}")
    return EXIT_OK


def cmd_push(args: argparse.Namespace) -> int:
    cfg = Config.load(Path.cwd(), args.key)
    key = cfg.require_key()

    base = Path(args.dir or cfg.directory)
    if not base.is_absolute():
        base = (cfg.root / base).resolve()
    if not base.is_dir():
        die(f"not a directory: {base}", EXIT_USAGE)

    local, filtered = scan(base, cfg.ignore)
    if not local and not args.prune:
        die("nothing to upload: no .html, .md, .css or .js files found", EXIT_USAGE)

    client = Client(cfg.endpoint, key, args.timeout)
    remote_data = client.form("/api/list.php", {})
    remote = {
        item["path"]: item
        for item in remote_data.get("files", [])
        if item.get("origin") != "derived"
    }
    derived = {
        item["path"] for item in remote_data.get("files", [])
        if item.get("origin") == "derived"
    }

    changed = [rel for rel, (_, _, sha) in sorted(local.items())
               if remote.get(rel, {}).get("sha256") != sha]
    unchanged = len(local) - len(changed)
    stale = sorted(set(remote) - set(local)) if args.prune else []

    out(f"{S.bold}source{S.off}     {base}")
    out(f"{S.bold}target{S.off}     {S.cyan}{remote_data.get('url')}{S.off}")
    out()

    if not changed and not stale:
        tag("done", f"already up to date ({unchanged} unchanged)", S.green)
        return EXIT_OK

    warned = 0
    for rel in changed:
        path, size, _ = local[rel]
        if path.suffix.lower() in (".html", ".htm"):
            for hit in check_external_scripts(path)[:1]:
                warn(f"{rel} loads an external script: {hit}")
                warned += 1

    if args.dry_run:
        for rel in changed:
            tag("upload", f"{rel}  {S.dim}{human(local[rel][1])}{S.off}", S.cyan)
        for rel in stale:
            tag("delete", rel, S.yellow)
        if filtered:
            tag("filter", f"{len(filtered)} files outside the whitelist", S.dim)
        out()
        info(f"dry run: {len(changed)} to upload, {len(stale)} to delete, {unchanged} unchanged")
        return EXIT_OK

    uploaded = 0
    rendered: List[str] = []
    skipped: List[Dict[str, Any]] = []
    batches = list(chunk(changed, local))
    started = time.time()

    for index, batch in enumerate(batches):
        last = index == len(batches) - 1
        fields = [("rerender", "1" if last else "0")]
        files = []
        for rel in batch:
            path, _, _ = local[rel]
            fields.append(("paths[]", rel))
            files.append(("files[]", rel, path.read_bytes()))
        try:
            result = client.multipart("/api/upload.php", fields, files)
        except ApiError as exc:
            raise exc

        for item in result.get("uploaded", []):
            uploaded += 1
            tag("uploaded", f"{item['path']}  {S.dim}{human(item['size'])}{S.off}", S.green)
        for item in result.get("skipped", []):
            skipped.append(item)
        rendered.extend(result.get("rendered", []))

    for path in sorted(set(rendered)):
        tag("rendered", path, S.cyan)

    deleted = 0
    if stale:
        result = client.form("/api/delete.php", {"paths": json.dumps(stale)})
        for path in result.get("deleted", []):
            if path in derived:
                continue
            deleted += 1
            tag("deleted", path, S.yellow)

    noteworthy = [s for s in skipped if s.get("reason") not in ("unchanged",)]
    for item in noteworthy:
        detail = item.get("detail")
        suffix = f"  {S.dim}{detail}{S.off}" if detail not in (None, "") else ""
        tag("skipped", f"{item.get('path')}  {S.dim}[{item.get('reason')}]{S.off}{suffix}", S.yellow)

    if filtered:
        tag("filtered", f"{len(filtered)} files outside the whitelist "
                        f"{S.dim}(use --show-filtered to list){S.off}", S.dim)
        if args.show_filtered:
            for rel in filtered[:60]:
                out(f"           {S.dim}{rel}{S.off}")

    elapsed = time.time() - started
    out()
    summary = [f"{uploaded} uploaded"]
    if rendered:
        summary.append(f"{len(set(rendered))} rendered")
    if deleted:
        summary.append(f"{deleted} deleted")
    if unchanged:
        summary.append(f"{unchanged} unchanged")
    tag("done", f"{', '.join(summary)} in {elapsed:.1f}s", S.green)
    out(f"           {S.cyan}{remote_data.get('url')}{S.off}")
    return EXIT_OK


def chunk(names: List[str], local: Dict[str, Tuple[Path, int, str]]):
    batch: List[str] = []
    size = 0
    for rel in names:
        item_size = local[rel][1]
        if batch and (len(batch) >= BATCH_FILES or size + item_size > BATCH_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(rel)
        size += item_size
    if batch:
        yield batch


def cmd_ls(args: argparse.Namespace) -> int:
    cfg = Config.load(Path.cwd(), args.key)
    client = Client(cfg.endpoint, cfg.require_key(), args.timeout)
    fields = {}
    if args.prefix:
        fields["prefix"] = args.prefix
    if args.sources:
        fields["origin"] = "source"
    data = client.form("/api/list.php", fields)
    files = data.get("files", [])

    if args.json:
        out(json.dumps(data, indent=2))
        return EXIT_OK

    if not files:
        info("no files")
        return EXIT_OK

    for item in files:
        origin = item.get("origin", "source")
        mark = f"{S.dim}~{S.off}" if origin == "derived" else " "
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(item.get("mtime", 0)))
        out(f"{mark} {human(item.get('size', 0)):>9}  {S.dim}{stamp}{S.off}  {item['path']}")

    quota = data.get("quota", {})
    out()
    info(f"{data.get('total')} files  ·  {human(quota.get('bytes', 0))} used  ·  "
         f"~ marks pages generated from markdown")
    return EXIT_OK


def cmd_rm(args: argparse.Namespace) -> int:
    cfg = Config.load(Path.cwd(), args.key)
    client = Client(cfg.endpoint, cfg.require_key(), args.timeout)

    fields: Dict[str, str] = {}
    if args.prefix:
        fields["prefix"] = args.prefix
        target = f"everything under {args.prefix}/"
    else:
        if not args.paths:
            die("nothing to delete: pass file paths or --prefix", EXIT_USAGE)
        fields["paths"] = json.dumps(args.paths)
        target = f"{len(args.paths)} path(s)"

    if not args.yes:
        try:
            answer = input(f"Delete {target}? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            out()
            return EXIT_USAGE
        if answer not in ("y", "yes"):
            info("cancelled")
            return EXIT_OK

    data = client.form("/api/delete.php", fields)
    for path in data.get("deleted", []):
        tag("deleted", path, S.yellow)
    for path in data.get("missing", []):
        tag("missing", path, S.dim)
    for path in data.get("failed", []):
        tag("failed", path, S.red)
    out()
    tag("done", f"{len(data.get('deleted', []))} deleted", S.green)
    return EXIT_OK


def cmd_open(args: argparse.Namespace) -> int:
    cfg = Config.load(Path.cwd(), args.key)
    client = Client(cfg.endpoint, cfg.require_key(), args.timeout)
    data = client.form("/api/whoami.php", {})
    url = data.get("url", "")
    out(url)
    if args.browser:
        import webbrowser
        webbrowser.open(url)
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = Config.load(Path.cwd(), args.key)
    ok = True

    def check(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        mark = f"{S.green}pass{S.off}" if passed else f"{S.red}fail{S.off}"
        out(f"  {mark}  {name:<26}{S.dim}{detail}{S.off}")
        if not passed:
            ok = False

    out(f"{S.bold}usp doctor{S.off}  v{__version__}")
    out()
    check("python version", sys.version_info >= (3, 8), sys.version.split()[0])
    check("config file", (cfg.root / CONFIG_NAME).is_file(), cfg.source)
    check("api key present", bool(cfg.key), "from env or .env" if cfg.key else "not found")

    base = Path(cfg.directory)
    if not base.is_absolute():
        base = (cfg.root / base).resolve()
    check("publish directory", base.is_dir(), str(base))

    if base.is_dir():
        local, filtered = scan(base, cfg.ignore)
        check("publishable files", bool(local),
              f"{len(local)} accepted, {len(filtered)} filtered")

    if not cfg.key:
        out()
        die("cannot reach the server without a key", EXIT_AUTH)

    client = Client(cfg.endpoint, cfg.key, args.timeout)
    try:
        data = client.form("/api/whoami.php", {})
        check("server reachable", True, cfg.endpoint)
        check("key accepted", True, f"space={data.get('space')}")
        quota = data.get("quota", {})
        used, cap = quota.get("bytes", 0), quota.get("maxBytes", 1)
        check("quota headroom", used < cap * 0.9, f"{human(used)} / {human(cap)}")
    except ApiError as exc:
        check("server reachable", exc.code != "network", cfg.endpoint)
        check("key accepted", False, f"{exc.code}: {exc.message}")

    out()
    if ok:
        tag("done", "all checks passed", S.green)
        return EXIT_OK
    tag("done", "some checks failed", S.red)
    return EXIT_ERROR


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usp",
        description="Upload Static Page - push HTML, Markdown, CSS and JS to usp.kscm.top",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  usp init                    set up the current directory\n"
            "  usp push ./site             upload, keeping remote extras\n"
            "  usp push --prune            mirror the local directory exactly\n"
            "  usp push --dry-run          preview without sending anything\n"
            "  usp ls docs                 list remote files under docs/\n"
            "  usp rm old.html --yes       delete without confirmation\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"usp {__version__}")
    parser.add_argument("--key", help="API key, overrides USP_KEY and .env")
    parser.add_argument("--timeout", type=int, default=60, help="request timeout in seconds")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("init", help="create .usp.json and .env")
    p.add_argument("--endpoint", help="server endpoint")
    p.add_argument("--dir", help="directory to publish")
    p.add_argument("--force", action="store_true", help="overwrite an existing config")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("whoami", help="verify the key and show quota")
    p.set_defaults(func=cmd_whoami)

    p = sub.add_parser("push", help="upload a directory")
    p.add_argument("dir", nargs="?", help="directory to publish")
    p.add_argument("--prune", action="store_true", help="delete remote files missing locally")
    p.add_argument("--dry-run", action="store_true", help="show the plan without uploading")
    p.add_argument("--show-filtered", action="store_true", help="list files excluded by the whitelist")
    p.set_defaults(func=cmd_push)

    p = sub.add_parser("ls", help="list remote files")
    p.add_argument("prefix", nargs="?", help="only paths under this prefix")
    p.add_argument("--json", action="store_true", help="raw JSON output")
    p.add_argument("--sources", action="store_true", help="hide pages generated from markdown")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("rm", help="delete remote files")
    p.add_argument("paths", nargs="*", help="paths to delete")
    p.add_argument("--prefix", help="delete every file under this directory")
    p.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("open", help="print the public URL")
    p.add_argument("--browser", action="store_true", help="also open it in a browser")
    p.set_defaults(func=cmd_open)

    p = sub.add_parser("doctor", help="run configuration and connectivity checks")
    p.set_defaults(func=cmd_doctor)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return args.func(args)
    except ApiError as exc:
        if exc.code in ("missing_key", "invalid_key", "key_disabled"):
            die(f"{exc.code}: {exc.message}", EXIT_AUTH)
        if exc.code == "method_not_allowed":
            die("the server rejected the request method. Check the endpoint URL.", EXIT_ERROR)
        die(f"{exc.code}: {exc.message}", EXIT_ERROR)
    except KeyboardInterrupt:
        out()
        return EXIT_USAGE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
