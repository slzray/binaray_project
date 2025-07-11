#include <iostream>
#include <Windows.h>
#include "Hook/InlineHook.hpp"
#include "Hook/ApiHook.hpp"
#include "Injection/DllInjection.hpp"
#include "Memory/MemoryTools.hpp"

// 简单的测试函数
int WINAPI TestMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "[TEST HOOK] MessageBoxA called with text: " << (lpText ? lpText : "NULL") << std::endl;
    return 1; // 返回IDOK
}

void TestInlineHook() {
    std::cout << "\n=== Testing Inline Hook ===" << std::endl;
    
    InlineHook64 hook;
    
    // 创建一个简单的测试函数
    auto testFunc = [](int a, int b) -> int {
        return a + b;
    };
    
    auto hookFunc = [](int a, int b) -> int {
        std::cout << "Hooked function called with: " << a << ", " << b << std::endl;
        return a * b; // 改变行为
    };
    
    std::cout << "Original function result: " << testFunc(3, 4) << std::endl;
    
    // 注意：实际的inline hook需要函数指针，lambda可能不适用
    std::cout << "Inline hook test completed (simplified)" << std::endl;
}

void TestApiHook() {
    std::cout << "\n=== Testing API Hook ===" << std::endl;
    
    try {
        ApiHookManager hookManager;
        
        // 尝试安装MessageBoxA hook
        if (hookManager.InstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA", 
                                   reinterpret_cast<void*>(TestMessageBoxA))) {
            std::cout << "MessageBoxA hook installed successfully!" << std::endl;
            
            // 测试hook
            MessageBoxA(nullptr, "Test message", "Test", MB_OK);
            
            // 卸载hook
            hookManager.UninstallAllHooks();
            std::cout << "Hook uninstalled" << std::endl;
        } else {
            std::cout << "Failed to install MessageBoxA hook" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Exception in API Hook test: " << e.what() << std::endl;
    }
}

void TestMemoryTools() {
    std::cout << "\n=== Testing Memory Tools ===" << std::endl;
    
    try {
        MemoryTools memTools(GetCurrentProcessId());
        
        if (memTools.IsValidProcess()) {
            std::cout << "MemoryTools initialized successfully for PID: " << memTools.GetProcessId() << std::endl;
            
            // 测试内存读取
            int testValue = 12345;
            int readValue = 0;
            
            if (memTools.ReadValue(&testValue, readValue)) {
                std::cout << "Memory read test: " << readValue << " (expected: " << testValue << ")" << std::endl;
            }
            
            // 测试模块枚举
            auto modules = memTools.EnumerateModules();
            std::cout << "Found " << modules.size() << " modules in current process" << std::endl;
            
            // 测试内存区域枚举
            auto regions = memTools.EnumerateMemoryRegions();
            std::cout << "Found " << regions.size() << " memory regions" << std::endl;
            
        } else {
            std::cout << "Failed to initialize MemoryTools" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Exception in Memory Tools test: " << e.what() << std::endl;
    }
}

void TestDllInjection() {
    std::cout << "\n=== Testing DLL Injection ===" << std::endl;
    
    try {
        DllInjector injector;
        
        // 测试设置目标进程（当前进程）
        if (injector.SetTargetProcess(GetCurrentProcessId())) {
            std::cout << "DllInjector initialized successfully" << std::endl;
            
            // 注意：实际的DLL注入测试需要真实的DLL文件
            std::cout << "DLL injection test completed (no actual injection performed)" << std::endl;
        } else {
            std::cout << "Failed to set target process for DLL injection" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Exception in DLL Injection test: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "Binary Security Tools - Build and Function Test" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    try {
        TestInlineHook();
        TestApiHook();
        TestMemoryTools();
        TestDllInjection();
        
        std::cout << "\n=== All Tests Completed ===" << std::endl;
        std::cout << "If you see this message, the basic compilation and linking worked!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Fatal exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "Unknown fatal exception occurred" << std::endl;
        return 1;
    }
    
    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
