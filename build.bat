@echo off
echo Building Windows Binary Security Tools...
echo ========================================

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
echo Compiling source files...
echo -------------------------

REM 编译选项
set CFLAGS=/std:c++17 /EHsc /W3 /O2 /DNDEBUG /I. /Fo:obj\ /Fe:bin\binaray_project.exe

REM 编译所有源文件
cl %CFLAGS% ^
    binaray_project.cpp ^
    Hook\InlineHook.cpp ^
    Hook\ApiHook.cpp ^
    Injection\DllInjection.cpp ^
    Memory\MemoryTools.cpp ^
    Examples\HookExamples.cpp ^
    Examples\InjectionExamples.cpp ^
    Examples\MemoryExamples.cpp ^
    /link kernel32.lib user32.lib advapi32.lib psapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build completed successfully!
    echo Executable: bin\binaray_project.exe
    echo ========================================
) else (
    echo.
    echo ========================================
    echo Build failed with error code %ERRORLEVEL%
    echo ========================================
)

echo.
echo Building Test DLL...
echo --------------------

REM 编译测试DLL
cl /LD /std:c++17 /EHsc /W3 /O2 /DNDEBUG /Fo:obj\ /Fe:bin\TestDLL.dll TestDLL\TestDLL.cpp /link kernel32.lib user32.lib

if %ERRORLEVEL% EQU 0 (
    echo Test DLL compiled successfully: bin\TestDLL.dll
) else (
    echo Test DLL compilation failed!
)

echo.
echo Build process completed.
pause
