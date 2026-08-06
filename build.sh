#!/usr/bin/env bash
# =============================================================================
#  ctn build script (POSIX)
#
#  Default engine : Nuitka  -> a genuinely compiled, native binary
#  Fallback engine: PyInstaller
#
#  WHY NUITKA IS THE DEFAULT
#  PyInstaller's one-file bootloader is a well-known antivirus false positive
#  (Windows Defender usually reports Trojan:Win32/Wacatac). Nuitka compiles the
#  Python source to C and links a normal native binary, so there is no shared
#  bootloader signature for scanners to match.
#
#  USAGE
#    ./build.sh              - build with Nuitka   (recommended)
#    ./build.sh pyinstaller  - build with PyInstaller
#
#  OUTPUT
#    dist/ctn
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ENGINE="${1:-nuitka}"

if [ "$ENGINE" = "pyinstaller" ]; then
    echo "[build] Engine: PyInstaller"
    if ! command -v pyinstaller >/dev/null 2>&1; then
        echo "[build] pyinstaller not found. Installing..."
        "$PY" -m pip install --upgrade pyinstaller
    fi
    pyinstaller --noconfirm --onefile --windowed --noupx --name ctn ctn.py
    echo
    echo "[build] Done. See: dist/ctn"
    exit 0
fi

echo "[build] Engine: Nuitka"
if ! "$PY" -c "import nuitka" >/dev/null 2>&1; then
    echo "[build] Nuitka not found. Installing..."
    "$PY" -m pip install --upgrade nuitka ordered-set zstandard
fi

"$PY" -m nuitka \
    --standalone \
    --onefile \
    --assume-yes-for-downloads \
    --enable-plugin=tk-inter \
    --output-dir=dist \
    --output-filename=ctn \
    --product-name="ctn - Chat Talk Nonsense" \
    --file-version=1.0.0.0 \
    --product-version=1.0.0.0 \
    --file-description="Local-first bilingual code workbench" \
    --remove-output \
    ctn.py

echo
echo "[build] Done. See: dist/ctn"
echo "[build] Verify with: dist/ctn --selftest"
