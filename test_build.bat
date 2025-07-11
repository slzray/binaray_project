@echo off
echo Testing Binary Security Tools Build...
echo =====================================

REM 创建输出目录
if not exist "test_bin" mkdir test_bin
if not exist "test_obj" mkdir test_obj

echo.
echo Compiling test program...
echo -------------------------

REM 编译选项
set CFLAGS=/std:c++17 /EHsc /W3 /O2 /DNDEBUG /I. /Fo:test_obj\ /Fe:test_bin\test_build.exe

REM 编译测试程序
cl %CFLAGS% ^
    test_build.cpp ^
    Hook\InlineHook.cpp ^
    Hook\ApiHook.cpp ^
    Injection\DllInjection.cpp ^
    Memory\MemoryTools.cpp ^
    /link kernel32.lib user32.lib advapi32.lib psapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build completed successfully!
    echo Running test program...
    echo ========================================
    echo.
    test_bin\test_build.exe
) else (
    echo.
    echo ========================================
    echo Build failed with error code %ERRORLEVEL%
    echo ========================================
)

echo.
echo Test completed.
pause
