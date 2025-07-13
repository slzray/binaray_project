/***********************************************************************************************
 * Copyright (c) 2025 二进制安全工具项目
 * Description: Windows平台API Hook框架
 *              实现IAT(导入地址表)Hook、EAT(导出地址表)Hook，
 *              提供统一的API Hook管理系统，包含预定义的常用API Hook
 *              和便于Hook安装管理的辅助宏。
 * Author:      lunsha498@gmail.com
 * Date:        2025.07.07
 ***********************************************************************************************/

#pragma once
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <vector>

// API Hook类型枚举
enum class HookType {
    IAT_HOOK,    // Import Address Table Hook
    EAT_HOOK,    // Export Address Table Hook
    INLINE_HOOK  // Inline Hook
};

// IAT Hook实现
class IATHook {
private:
    struct HookInfo {
        void* originalFunction;
        void* hookFunction;
        void** iatEntry;
        std::string moduleName;
        std::string functionName;
    };
    
    std::unordered_map<std::string, HookInfo> m_hooks;

public:
    IATHook();
    ~IATHook();
    
    // 安装IAT Hook
    bool InstallHook(const std::string& moduleName, const std::string& functionName, void* hookFunction);
    
    // 卸载IAT Hook
    bool UninstallHook(const std::string& moduleName, const std::string& functionName);
    
    // 卸载所有Hook
    void UninstallAllHooks();
    
    // 获取原始函数地址
    void* GetOriginalFunction(const std::string& moduleName, const std::string& functionName);

private:
    // 查找IAT条目
    void** FindIATEntry(HMODULE hModule, const std::string& moduleName, const std::string& functionName);
    
    // 修改内存保护
    bool ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect);
};

// EAT Hook实现
class EATHook {
private:
    struct HookInfo {
        void* originalFunction;
        void* hookFunction;
        DWORD* eatEntry;
        std::string moduleName;
        std::string functionName;
        DWORD originalRVA;
    };
    
    std::unordered_map<std::string, HookInfo> m_hooks;

public:
    EATHook();
    ~EATHook();
    
    // 安装EAT Hook
    bool InstallHook(const std::string& moduleName, const std::string& functionName, void* hookFunction);
    
    // 卸载EAT Hook
    bool UninstallHook(const std::string& moduleName, const std::string& functionName);
    
    // 卸载所有Hook
    void UninstallAllHooks();
    
    // 获取原始函数地址
    void* GetOriginalFunction(const std::string& moduleName, const std::string& functionName);

private:
    // 查找EAT条目
    DWORD* FindEATEntry(HMODULE hModule, const std::string& functionName, DWORD& originalRVA);
    
    // 修改内存保护
    bool ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect);
};

// API Hook管理器
class ApiHookManager {
private:
    IATHook m_iatHook;
    EATHook m_eatHook;
    
    struct HookRecord {
        HookType type;
        std::string moduleName;
        std::string functionName;
        void* hookFunction;
        void* originalFunction;
    };
    
    std::vector<HookRecord> m_hookRecords;

public:
    ApiHookManager();
    ~ApiHookManager();
    
    // 安装Hook
    bool InstallHook(HookType type, const std::string& moduleName, 
                    const std::string& functionName, void* hookFunction);
    
    // 卸载Hook
    bool UninstallHook(HookType type, const std::string& moduleName, 
                      const std::string& functionName);
    
    // 卸载所有Hook
    void UninstallAllHooks();
    
    // 获取原始函数地址
    void* GetOriginalFunction(HookType type, const std::string& moduleName, 
                             const std::string& functionName);
    
    // 获取Hook列表
    std::vector<HookRecord> GetHookList() const { return m_hookRecords; }
    
    // 检查函数是否被Hook
    bool IsHooked(const std::string& moduleName, const std::string& functionName);
};

// 常用API Hook辅助宏
#define DECLARE_API_HOOK(returnType, functionName, ...) \
    typedef returnType (WINAPI* functionName##_t)(__VA_ARGS__); \
    extern functionName##_t Original##functionName; \
    returnType WINAPI Hook##functionName(__VA_ARGS__);

#define IMPLEMENT_API_HOOK(returnType, functionName, ...) \
    functionName##_t Original##functionName = nullptr; \
    returnType WINAPI Hook##functionName(__VA_ARGS__)

#define INSTALL_API_HOOK(manager, module, functionName) \
    Original##functionName = reinterpret_cast<functionName##_t>( \
        GetProcAddress(GetModuleHandleA(module), #functionName)); \
    manager.InstallHook(HookType::IAT_HOOK, module, #functionName, Hook##functionName);

// 预定义的常用API Hook
namespace CommonHooks {
    // MessageBox Hook
    DECLARE_API_HOOK(int, MessageBoxA, HWND, LPCSTR, LPCSTR, UINT);
    DECLARE_API_HOOK(int, MessageBoxW, HWND, LPCWSTR, LPCWSTR, UINT);
    
    // File API Hook
    DECLARE_API_HOOK(HANDLE, CreateFileA, LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    DECLARE_API_HOOK(HANDLE, CreateFileW, LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    
    // Registry API Hook
    DECLARE_API_HOOK(LONG, RegOpenKeyExA, HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    DECLARE_API_HOOK(LONG, RegOpenKeyExW, HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    
    // Process API Hook
    DECLARE_API_HOOK(BOOL, CreateProcessA, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    DECLARE_API_HOOK(BOOL, CreateProcessW, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    
    // 安装所有常用Hook
    void InstallCommonHooks(ApiHookManager& manager);
    
    // 卸载所有常用Hook
    void UninstallCommonHooks(ApiHookManager& manager);
}
