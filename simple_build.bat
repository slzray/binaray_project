@echo off
echo Simple Build Test
echo =================

if not exist "test_bin" mkdir test_bin

echo Compiling simple test...
cl /std:c++17 /EHsc /I. simple_test.cpp Hook\InlineHook.cpp Hook\ApiHook.cpp Memory\MemoryTools.cpp Injection\DllInjection.cpp /Fe:test_bin\simple_test.exe /link kernel32.lib user32.lib advapi32.lib psapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful! Running test...
    echo.
    test_bin\simple_test.exe
) else (
    echo.
    echo Build failed!
)

pause
