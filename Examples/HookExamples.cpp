#include "../Hook/InlineHook.hpp"
#include "../Hook/ApiHook.hpp"
#include <iostream>
#include <Windows.h>

// 全局变量
ApiHookManager g_hookManager;
InlineHook64 g_inlineHook;

// MessageBoxA Hook示例
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "[Hook] MessageBoxA called!" << std::endl;
    std::cout << "  Text: " << (lpText ? lpText : "NULL") << std::endl;
    std::cout << "  Caption: " << (lpCaption ? lpCaption : "NULL") << std::endl;
    
    // 获取原始函数并调用
    typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
    MessageBoxA_t originalFunc = reinterpret_cast<MessageBoxA_t>(
        g_hookManager.GetOriginalFunction(HookType::IAT_HOOK, "user32.dll", "MessageBoxA"));
    
    if (originalFunc) {
        return originalFunc(hWnd, "Hooked Message!", lpCaption, uType);
    }
    
    return 0;
}

// CreateFileA Hook示例
HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                               LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                               DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::cout << "[Hook] CreateFileA called!" << std::endl;
    std::cout << "  File: " << (lpFileName ? lpFileName : "NULL") << std::endl;
    
    // 获取原始函数并调用
    typedef HANDLE (WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    CreateFileA_t originalFunc = reinterpret_cast<CreateFileA_t>(
        g_hookManager.GetOriginalFunction(HookType::IAT_HOOK, "kernel32.dll", "CreateFileA"));
    
    if (originalFunc) {
        return originalFunc(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                          dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    
    return INVALID_HANDLE_VALUE;
}

// 演示IAT Hook
void DemonstrateIATHook() {
    std::cout << "\n=== IAT Hook Demo ===" << std::endl;
    
    // 安装MessageBoxA Hook
    if (g_hookManager.InstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA", HookedMessageBoxA)) {
        std::cout << "MessageBoxA hook installed successfully!" << std::endl;
        
        // 测试Hook
        MessageBoxA(nullptr, "Original Message", "Test", MB_OK);
        
        // 卸载Hook
        g_hookManager.UninstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA");
        std::cout << "MessageBoxA hook uninstalled!" << std::endl;
    } else {
        std::cout << "Failed to install MessageBoxA hook!" << std::endl;
    }
    
    // 安装CreateFileA Hook
    if (g_hookManager.InstallHook(HookType::IAT_HOOK, "kernel32.dll", "CreateFileA", HookedCreateFileA)) {
        std::cout << "CreateFileA hook installed successfully!" << std::endl;
        
        // 测试Hook
        HANDLE hFile = CreateFileA("test.txt", GENERIC_READ, FILE_SHARE_READ, nullptr, 
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
        
        // 卸载Hook
        g_hookManager.UninstallHook(HookType::IAT_HOOK, "kernel32.dll", "CreateFileA");
        std::cout << "CreateFileA hook uninstalled!" << std::endl;
    } else {
        std::cout << "Failed to install CreateFileA hook!" << std::endl;
    }
}

// 自定义函数用于Inline Hook测试
int __stdcall TestFunction(int a, int b) {
    return a + b;
}

// Hook函数
int __stdcall HookedTestFunction(int a, int b) {
    std::cout << "[Inline Hook] TestFunction called with: " << a << ", " << b << std::endl;
    
    // 调用原始函数
    int result = g_inlineHook.CallOriginal<int>(a, b);
    std::cout << "[Inline Hook] Original result: " << result << std::endl;
    
    return result * 2; // 修改返回值
}

// 演示Inline Hook
void DemonstrateInlineHook() {
    std::cout << "\n=== Inline Hook Demo ===" << std::endl;
    
    // 测试原始函数
    int originalResult = TestFunction(3, 4);
    std::cout << "Original function result: " << originalResult << std::endl;
    
    // 安装Inline Hook
    if (g_inlineHook.InstallHook(TestFunction, HookedTestFunction)) {
        std::cout << "Inline hook installed successfully!" << std::endl;
        
        // 测试Hook后的函数
        int hookedResult = TestFunction(3, 4);
        std::cout << "Hooked function result: " << hookedResult << std::endl;
        
        // 卸载Hook
        if (g_inlineHook.UninstallHook()) {
            std::cout << "Inline hook uninstalled successfully!" << std::endl;
            
            // 再次测试原始函数
            int restoredResult = TestFunction(3, 4);
            std::cout << "Restored function result: " << restoredResult << std::endl;
        }
    } else {
        std::cout << "Failed to install inline hook!" << std::endl;
    }
}

// 演示Hook管理
void DemonstrateHookManagement() {
    std::cout << "\n=== Hook Management Demo ===" << std::endl;
    
    // 安装多个Hook
    g_hookManager.InstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA", HookedMessageBoxA);
    g_hookManager.InstallHook(HookType::IAT_HOOK, "kernel32.dll", "CreateFileA", HookedCreateFileA);
    
    // 显示Hook列表
    auto hookList = g_hookManager.GetHookList();
    std::cout << "Installed hooks: " << hookList.size() << std::endl;
    
    for (const auto& hook : hookList) {
        std::cout << "  - " << hook.moduleName << "::" << hook.functionName << std::endl;
    }
    
    // 检查特定函数是否被Hook
    if (g_hookManager.IsHooked("user32.dll", "MessageBoxA")) {
        std::cout << "MessageBoxA is hooked!" << std::endl;
    }
    
    // 卸载所有Hook
    g_hookManager.UninstallAllHooks();
    std::cout << "All hooks uninstalled!" << std::endl;
}

// 主函数
void RunHookExamples() {
    std::cout << "Windows Security Tools - Hook Examples" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    try {
        DemonstrateIATHook();
        DemonstrateInlineHook();
        DemonstrateHookManagement();
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    std::cout << "\nHook examples completed!" << std::endl;
}
