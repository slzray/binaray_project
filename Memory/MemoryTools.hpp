/***********************************************************************************************
 * Copyright (c) 2025 二进制安全工具项目
 * Description: Windows平台综合内存操作工具包
 *              提供跨进程内存操作、模式搜索、内存扫描、内存监控、
 *              模块枚举、内存补丁和类似Cheat Engine功能的高级内存分析能力。
 * Author:      lunsha498@gmail.com
 * Date:        2025.07.07
 ***********************************************************************************************/

#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <functional>

// 内存区域信息
struct MemoryRegion {
    LPVOID baseAddress{ nullptr };
    SIZE_T size{ 0 };
    DWORD protect{ 0 };
    DWORD state{ 0 };
    DWORD type{ 0 };
    std::string moduleName;
};

// 搜索结果
struct SearchResult {
    LPVOID address{nullptr};
    std::vector<BYTE> data;
    SIZE_T offset{0};
};

// 内存操作工具类
class MemoryTools {
private:
    HANDLE m_processHandle;
    DWORD m_processId;

public:
    MemoryTools();
    explicit MemoryTools(DWORD processId);
    explicit MemoryTools(HANDLE processHandle);
    ~MemoryTools();
    
    // 设置目标进程
    bool SetTargetProcess(DWORD processId);
    bool SetTargetProcess(HANDLE processHandle);
    
    // 内存读写操作
    bool ReadMemory(LPVOID address, void* buffer, SIZE_T size, SIZE_T* bytesRead = nullptr);
    bool WriteMemory(LPVOID address, const void* buffer, SIZE_T size, SIZE_T* bytesWritten = nullptr);
    
    // 模板化读写操作
    template<typename T>
    bool ReadValue(LPVOID address, T& value);
    
    template<typename T>
    bool WriteValue(LPVOID address, const T& value);
    
    // 字符串读写
    std::string ReadString(LPVOID address, SIZE_T maxLength = 256, bool isUnicode = false);
    bool WriteString(LPVOID address, const std::string& str, bool isUnicode = false);
    
    // 内存保护修改
    bool ChangeProtection(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect = nullptr);
    
    // 内存搜索
    std::vector<SearchResult> SearchPattern(const std::vector<BYTE>& pattern,
                                          const std::vector<BYTE>& mask = {},
                                          LPVOID startAddress = nullptr,
                                          SIZE_T searchSize = 0);

    // 在指定段中搜索字节数组模式
    std::vector<SearchResult> SearchPatternInSection(const std::vector<BYTE>& pattern,
                                                    const std::string& sectionName,
                                                    const std::vector<BYTE>& mask = {},
                                                    const std::string& moduleName = "");

    // 搜索字节数组的便捷函数
    std::vector<SearchResult> SearchBytes(const std::initializer_list<BYTE>& bytes,
                                        LPVOID startAddress = nullptr,
                                        SIZE_T searchSize = 0);

    // 搜索带通配符的字节模式 (如 "48 89 ?? 24 08")
    std::vector<SearchResult> SearchPatternString(const std::string& patternStr,
                                                 LPVOID startAddress = nullptr,
                                                 SIZE_T searchSize = 0);
    
    std::vector<SearchResult> SearchString(const std::string& str, bool caseSensitive = true,
                                         bool isUnicode = false,
                                         LPVOID startAddress = nullptr,
                                         SIZE_T searchSize = 0);
    
    std::vector<SearchResult> SearchValue(const void* value, SIZE_T valueSize,
                                        LPVOID startAddress = nullptr,
                                        SIZE_T searchSize = 0);
    
    // 内存区域枚举
    std::vector<MemoryRegion> EnumerateMemoryRegions();
    std::vector<MemoryRegion> GetExecutableRegions();
    std::vector<MemoryRegion> GetWritableRegions();
    
    // 模块相关操作
    std::vector<HMODULE> EnumerateModules();
    HMODULE GetModuleHandle(const std::string& moduleName);
    std::string GetModulePath(HMODULE hModule);
    LPVOID GetModuleBaseAddress(const std::string& moduleName);
    SIZE_T GetModuleSize(HMODULE hModule);

    // 段信息结构
    struct SectionInfo {
        std::string name;
        LPVOID baseAddress{nullptr};
        SIZE_T virtualSize{0};
        SIZE_T rawSize{0};
        DWORD characteristics{0};
    };

    // 获取模块的段信息
    std::vector<SectionInfo> GetModuleSections(HMODULE hModule);
    std::vector<SectionInfo> GetModuleSections(const std::string& moduleName);
    
    // 内存转储
    bool DumpMemory(LPVOID address, SIZE_T size, const std::string& filePath);
    bool DumpModule(const std::string& moduleName, const std::string& filePath);
    
    // 内存补丁
    bool ApplyPatch(LPVOID address, const std::vector<BYTE>& patchData, 
                   std::vector<BYTE>* originalData = nullptr);
    bool RestorePatch(LPVOID address, const std::vector<BYTE>& originalData);
    
    // 获取进程信息
    DWORD GetProcessId() const { return m_processId; }
    HANDLE GetProcessHandle() const { return m_processHandle; }
    bool IsValidProcess() const { return m_processHandle != nullptr && m_processHandle != INVALID_HANDLE_VALUE; }

private:
    // 辅助函数
    bool IsAddressValid(LPVOID address);
    SIZE_T GetRegionSize(LPVOID address);
    bool EnableDebugPrivilege();
    
    // 模式匹配辅助函数
    bool MatchPattern(const BYTE* data, const std::vector<BYTE>& pattern, const std::vector<BYTE>& mask);
    std::vector<BYTE> CreateMask(const std::string& maskStr);
};

// 内存扫描器类
class MemoryScanner {
private:
    MemoryTools* m_memoryTools;
    std::vector<SearchResult> m_lastResults;

public:
    explicit MemoryScanner(MemoryTools* memoryTools);
    
    // 首次扫描
    std::vector<SearchResult> FirstScan(const void* value, SIZE_T valueSize);
    
    // 下次扫描（基于上次结果）
    std::vector<SearchResult> NextScan(const void* value, SIZE_T valueSize);
    
    // 变化扫描
    std::vector<SearchResult> ChangedScan();
    std::vector<SearchResult> UnchangedScan();
    
    // 增加/减少扫描
    std::vector<SearchResult> IncreasedScan();
    std::vector<SearchResult> DecreasedScan();
    
    // 获取上次扫描结果
    const std::vector<SearchResult>& GetLastResults() const { return m_lastResults; }
    
    // 清除结果
    void ClearResults() { m_lastResults.clear(); }

private:
    bool CompareValues(const void* value1, const void* value2, SIZE_T size);
};

// 内存监视器类
class MemoryWatcher {
private:
    struct WatchPoint {
        LPVOID address{nullptr};
        SIZE_T size{0};
        std::vector<BYTE> lastValue;
        std::function<void(LPVOID, const std::vector<BYTE>&, const std::vector<BYTE>&)> callback;
    };
    
    MemoryTools* m_memoryTools;
    std::vector<WatchPoint> m_watchPoints;
    bool m_isWatching;
    HANDLE m_watchThread;

public:
    explicit MemoryWatcher(MemoryTools* memoryTools);
    ~MemoryWatcher();
    
    // 添加监视点
    bool AddWatchPoint(LPVOID address, SIZE_T size, 
                      std::function<void(LPVOID, const std::vector<BYTE>&, const std::vector<BYTE>&)> callback);
    
    // 移除监视点
    bool RemoveWatchPoint(LPVOID address);
    
    // 开始/停止监视
    bool StartWatching();
    bool StopWatching();
    
    // 获取监视状态
    bool IsWatching() const { return m_isWatching; }

private:
    static DWORD WINAPI WatchThreadProc(LPVOID param);
    void WatchLoop();
};

// 模板实现
template<typename T>
bool MemoryTools::ReadValue(LPVOID address, T& value) {
    return ReadMemory(address, &value, sizeof(T));
}

template<typename T>
bool MemoryTools::WriteValue(LPVOID address, const T& value) {
    return WriteMemory(address, &value, sizeof(T));
}
