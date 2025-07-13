#include "ApiHook.hpp"
#include <iostream>

// IATHook实现
IATHook::IATHook() {
}

IATHook::~IATHook() {
    UninstallAllHooks();
}

bool IATHook::InstallHook(const std::string& moduleName, const std::string& functionName, void* hookFunction) {
    std::string key = moduleName + "::" + functionName;
    
    // 检查是否已经安装
    if (m_hooks.find(key) != m_hooks.end()) {
        return false;
    }
    
    // 获取当前模块句柄
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (!hModule) {
        return false;
    }
    
    // 查找IAT条目
    void** iatEntry = FindIATEntry(hModule, moduleName, functionName);
    if (!iatEntry) {
        std::cout << "Failed to find IAT entry for " << moduleName << "::" << functionName << std::endl;
        return false;
    }
    
    // 保存原始函数地址
    void* originalFunction = *iatEntry;
    
    // 修改内存保护
    DWORD oldProtect;
    if (!ChangeMemoryProtection(iatEntry, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // 替换函数地址
    *iatEntry = hookFunction;
    
    // 恢复内存保护
    DWORD temp;
    ChangeMemoryProtection(iatEntry, sizeof(void*), oldProtect, &temp);
    
    // 保存Hook信息
    HookInfo info;
    info.originalFunction = originalFunction;
    info.hookFunction = hookFunction;
    info.iatEntry = iatEntry;
    info.moduleName = moduleName;
    info.functionName = functionName;
    
    m_hooks[key] = info;
    
    return true;
}

bool IATHook::UninstallHook(const std::string& moduleName, const std::string& functionName) {
    std::string key = moduleName + "::" + functionName;
    
    auto it = m_hooks.find(key);
    if (it == m_hooks.end()) {
        return false;
    }
    
    HookInfo& info = it->second;
    
    // 修改内存保护
    DWORD oldProtect;
    if (!ChangeMemoryProtection(info.iatEntry, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // 恢复原始函数地址
    *info.iatEntry = info.originalFunction;
    
    // 恢复内存保护
    DWORD temp;
    ChangeMemoryProtection(info.iatEntry, sizeof(void*), oldProtect, &temp);
    
    // 移除Hook信息
    m_hooks.erase(it);
    
    return true;
}

void IATHook::UninstallAllHooks() {
    for (auto& pair : m_hooks) {
        HookInfo& info = pair.second;
        
        DWORD oldProtect;
        if (ChangeMemoryProtection(info.iatEntry, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
            *info.iatEntry = info.originalFunction;
            DWORD temp;
            ChangeMemoryProtection(info.iatEntry, sizeof(void*), oldProtect, &temp);
        }
    }
    
    m_hooks.clear();
}

void* IATHook::GetOriginalFunction(const std::string& moduleName, const std::string& functionName) {
    std::string key = moduleName + "::" + functionName;
    
    auto it = m_hooks.find(key);
    if (it != m_hooks.end()) {
        return it->second.originalFunction;
    }
    
    return nullptr;
}

void** IATHook::FindIATEntry(HMODULE hModule, const std::string& moduleName, const std::string& functionName) {
    // 获取DOS头
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    
    // 获取NT头
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    
    // 获取导入表
    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        return nullptr;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(hModule) + importRVA);
    
    // 遍历导入描述符
    while (importDesc->Name != 0) {
        char* dllName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(hModule) + importDesc->Name);
        
        if (_stricmp(dllName, moduleName.c_str()) == 0) {
            // 找到目标DLL，遍历导入函数
            PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                reinterpret_cast<BYTE*>(hModule) + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                reinterpret_cast<BYTE*>(hModule) + importDesc->FirstThunk);
            
            while (thunk->u1.AddressOfData != 0) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        reinterpret_cast<BYTE*>(hModule) + thunk->u1.AddressOfData);
                    
                    if (strcmp(reinterpret_cast<char*>(importByName->Name), functionName.c_str()) == 0) {
                        return reinterpret_cast<void**>(&iatThunk->u1.Function);
                    }
                }
                
                thunk++;
                iatThunk++;
            }
            
            break;
        }
        
        importDesc++;
    }
    
    return nullptr;
}

bool IATHook::ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtect(address, size, newProtect, oldProtect) != 0;
}

// ApiHookManager实现
ApiHookManager::ApiHookManager() {
}

ApiHookManager::~ApiHookManager() {
    UninstallAllHooks();
}

bool ApiHookManager::InstallHook(HookType type, const std::string& moduleName, 
                                const std::string& functionName, void* hookFunction) {
    bool result = false;
    void* originalFunction = nullptr;
    
    switch (type) {
        case HookType::IAT_HOOK:
            result = m_iatHook.InstallHook(moduleName, functionName, hookFunction);
            if (result) {
                originalFunction = m_iatHook.GetOriginalFunction(moduleName, functionName);
            }
            break;
        case HookType::EAT_HOOK:
            result = m_eatHook.InstallHook(moduleName, functionName, hookFunction);
            if (result) {
                originalFunction = m_eatHook.GetOriginalFunction(moduleName, functionName);
            }
            break;
        default:
            return false;
    }
    
    if (result) {
        HookRecord record;
        record.type = type;
        record.moduleName = moduleName;
        record.functionName = functionName;
        record.hookFunction = hookFunction;
        record.originalFunction = originalFunction;
        
        m_hookRecords.push_back(record);
    }
    
    return result;
}

bool ApiHookManager::UninstallHook(HookType type, const std::string& moduleName, 
                                  const std::string& functionName) {
    bool result = false;
    
    switch (type) {
        case HookType::IAT_HOOK:
            result = m_iatHook.UninstallHook(moduleName, functionName);
            break;
        case HookType::EAT_HOOK:
            result = m_eatHook.UninstallHook(moduleName, functionName);
            break;
        default:
            return false;
    }
    
    if (result) {
        // 从记录中移除
        m_hookRecords.erase(
            std::remove_if(m_hookRecords.begin(), m_hookRecords.end(),
                [&](const HookRecord& record) {
                    return record.type == type && 
                           record.moduleName == moduleName && 
                           record.functionName == functionName;
                }),
            m_hookRecords.end()
        );
    }
    
    return result;
}

void ApiHookManager::UninstallAllHooks() {
    m_iatHook.UninstallAllHooks();
    m_eatHook.UninstallAllHooks();
    m_hookRecords.clear();
}

// EATHook实现
EATHook::EATHook() {
}

EATHook::~EATHook() {
    UninstallAllHooks();
}

bool EATHook::InstallHook(const std::string& moduleName, const std::string& functionName, void* hookFunction) {
    // EAT Hook实现较为复杂，这里提供基础框架
    std::cout << "EAT Hook for " << moduleName << "::" << functionName << " not fully implemented" << std::endl;
    return false;
}

bool EATHook::UninstallHook(const std::string& moduleName, const std::string& functionName) {
    std::cout << "EAT Hook uninstall not fully implemented" << std::endl;
    return false;
}

void EATHook::UninstallAllHooks() {
    m_hooks.clear();
}

void* EATHook::GetOriginalFunction(const std::string& moduleName, const std::string& functionName) {
    std::string key = moduleName + "::" + functionName;
    auto it = m_hooks.find(key);
    if (it != m_hooks.end()) {
        return it->second.originalFunction;
    }
    return nullptr;
}

DWORD* EATHook::FindEATEntry(HMODULE hModule, const std::string& functionName, DWORD& originalRVA) {
    // EAT查找实现
    return nullptr;
}

bool EATHook::ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtect(address, size, newProtect, oldProtect) != 0;
}

// ApiHookManager缺失的函数实现
void* ApiHookManager::GetOriginalFunction(HookType type, const std::string& moduleName,
                                         const std::string& functionName) {
    switch (type) {
        case HookType::IAT_HOOK:
            return m_iatHook.GetOriginalFunction(moduleName, functionName);
        case HookType::EAT_HOOK:
            return m_eatHook.GetOriginalFunction(moduleName, functionName);
        default:
            return nullptr;
    }
}

bool ApiHookManager::IsHooked(const std::string& moduleName, const std::string& functionName) {
    for (const auto& record : m_hookRecords) {
        if (record.moduleName == moduleName && record.functionName == functionName) {
            return true;
        }
    }
    return false;
}
