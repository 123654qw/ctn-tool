@echo off
rem ============================================================================
rem  ctn build script (Windows)
rem
rem  Default engine : Nuitka  -> a genuinely compiled, native ctn.exe
rem  Fallback engine: PyInstaller
rem
rem  WHY NUITKA IS THE DEFAULT
rem  PyInstaller's one-file bootloader is a well-known antivirus false positive
rem  (Windows Defender usually reports Trojan:Win32/Wacatac). The produced exe
rem  gets quarantined within seconds on many machines, and anyone you send it to
rem  will hit the same wall. Nuitka compiles the Python source to C and links a
rem  normal native binary, so there is no shared bootloader signature to match.
rem
rem  USAGE
rem    build.bat            - build with Nuitka   (recommended)
rem    build.bat pyinstaller- build with PyInstaller (may be quarantined)
rem
rem  OUTPUT
rem    dist\ctn.exe
rem ============================================================================

setlocal
cd /d "%~dp0"

rem Keep the downloaded MinGW64 toolchain and ccache off the system drive.
if not defined NUITKA_CACHE_DIR set "NUITKA_CACHE_DIR=E:\SDK\Nuitka\cache"

if /i "%~1"=="pyinstaller" goto :pyinstaller

:nuitka
echo [build] Engine: Nuitka
echo [build] Cache : %NUITKA_CACHE_DIR%
python -c "import nuitka" 2>nul
if errorlevel 1 (
    echo [build] Nuitka not found. Installing...
    python -m pip install --upgrade nuitka ordered-set zstandard || goto :err
)

rem --assume-yes-for-downloads lets Nuitka fetch MinGW64 unattended on a clean box.
python -m nuitka ^
    --standalone ^
    --onefile ^
    --mingw64 ^
    --assume-yes-for-downloads ^
    --windows-console-mode=disable ^
    --enable-plugin=tk-inter ^
    --output-dir=dist ^
    --output-filename=ctn.exe ^
    --company-name=ctn ^
    --product-name="ctn - Chat Talk Nonsense" ^
    --file-version=1.0.0.0 ^
    --product-version=1.0.0.0 ^
    --file-description="Local-first bilingual code workbench" ^
    --remove-output ^
    ctn.py
if errorlevel 1 goto :err

echo.
echo [build] Done. See: dist\ctn.exe
echo [build] Verify with: dist\ctn.exe --selftest
exit /b 0

:pyinstaller
echo [build] Engine: PyInstaller
echo [build] WARNING: the one-file bootloader is often flagged by antivirus.
echo [build]          If dist\ctn.exe disappears, that is your AV, not a build error.
echo [build]          Either add an exclusion for this folder, or use: build.bat
where pyinstaller >nul 2>nul
if errorlevel 1 (
    echo [build] pyinstaller not found. Installing...
    python -m pip install --upgrade pyinstaller || goto :err
)

pyinstaller --noconfirm --onefile --windowed --noupx --name ctn ^
    --collect-submodules tkinter ^
    ctn.py
if errorlevel 1 goto :err

echo.
echo [build] Done. See: dist\ctn.exe
exit /b 0

:err
echo.
echo [build] Build failed.
exit /b 1
