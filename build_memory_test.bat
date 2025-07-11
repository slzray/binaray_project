@echo off
echo Building Memory Tools Test...
echo ============================

REM 检查Visual Studio环境
if not defined VCINSTALLDIR (
    echo Error: Visual Studio environment not found!
    echo Please run this script from Visual Studio Developer Command Prompt
    echo or run vcvarsall.bat first.
    pause
    exit /b 1
)

REM 创建输出目录
if not exist "bin" mkdir bin
if not exist "obj" mkdir obj

echo.
echo Compiling Memory Tools Test...
echo ------------------------------

REM 编译选项
set CFLAGS=/std:c++17 /EHsc /W3 /O2 /DNDEBUG /I. /Fo:obj\ /Fe:bin\MemoryToolsTest.exe

REM 编译Memory Tools测试程序
cl %CFLAGS% ^
    Memory\MemoryToolsTest.cpp ^
    Memory\MemoryTools.cpp ^
    /link kernel32.lib user32.lib advapi32.lib psapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Memory Tools Test build completed successfully!
    echo Executable: bin\MemoryToolsTest.exe
    echo ========================================
    echo.
    echo Running test...
    echo ===============
    bin\MemoryToolsTest.exe
) else (
    echo.
    echo ========================================
    echo Build failed with error code %ERRORLEVEL%
    echo ========================================
)

echo.
echo Build process completed.
pause
