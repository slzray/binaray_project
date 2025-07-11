#include "MemoryTools.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <TlHelp32.h>
#include <Psapi.h>

// MemoryTools类实现
MemoryTools::MemoryTools() : m_processHandle(nullptr), m_processId(0) {
    EnableDebugPrivilege();
}

MemoryTools::MemoryTools(DWORD processId) : m_processHandle(nullptr), m_processId(0) {
    EnableDebugPrivilege();
    SetTargetProcess(processId);
}

MemoryTools::MemoryTools(HANDLE processHandle) : m_processHandle(nullptr), m_processId(0) {
    EnableDebugPrivilege();
    SetTargetProcess(processHandle);
}

MemoryTools::~MemoryTools() {
    if (m_processHandle && m_processHandle != INVALID_HANDLE_VALUE && m_processHandle != GetCurrentProcess()) {
        CloseHandle(m_processHandle);
    }
}

bool MemoryTools::SetTargetProcess(DWORD processId) {
    if (m_processHandle && m_processHandle != INVALID_HANDLE_VALUE && m_processHandle != GetCurrentProcess()) {
        CloseHandle(m_processHandle);
    }
    
    m_processId = processId;
    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    
    if (!m_processHandle) {
        // 尝试较少的权限
        m_processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    }
    
    return m_processHandle != nullptr;
}

bool MemoryTools::SetTargetProcess(HANDLE processHandle) {
    if (m_processHandle && m_processHandle != INVALID_HANDLE_VALUE && m_processHandle != GetCurrentProcess()) {
        CloseHandle(m_processHandle);
    }
    
    m_processHandle = processHandle;
    m_processId = ::GetProcessId(processHandle);
    
    return m_processHandle != nullptr;
}

bool MemoryTools::ReadMemory(LPVOID address, void* buffer, SIZE_T size, SIZE_T* bytesRead) {
    if (!IsValidProcess() || !address || !buffer || size == 0) {
        return false;
    }
    
    SIZE_T actualBytesRead = 0;
    BOOL result = ReadProcessMemory(m_processHandle, address, buffer, size, &actualBytesRead);
    
    if (bytesRead) {
        *bytesRead = actualBytesRead;
    }
    
    return result && (actualBytesRead == size);
}

bool MemoryTools::WriteMemory(LPVOID address, const void* buffer, SIZE_T size, SIZE_T* bytesWritten) {
    if (!IsValidProcess() || !address || !buffer || size == 0) {
        return false;
    }
    
    SIZE_T actualBytesWritten = 0;
    BOOL result = WriteProcessMemory(m_processHandle, address, buffer, size, &actualBytesWritten);
    
    if (bytesWritten) {
        *bytesWritten = actualBytesWritten;
    }
    
    return result && (actualBytesWritten == size);
}

std::string MemoryTools::ReadString(LPVOID address, SIZE_T maxLength, bool isUnicode) {
    if (!IsValidProcess() || !address || maxLength == 0) {
        return "";
    }
    
    std::string result;
    
    if (isUnicode) {
        std::vector<wchar_t> buffer(maxLength);
        SIZE_T bytesRead;
        
        if (ReadMemory(address, buffer.data(), maxLength * sizeof(wchar_t), &bytesRead)) {
            // 查找字符串结束符
            for (size_t i = 0; i < maxLength && buffer[i] != L'\0'; ++i) {
                char ch = static_cast<char>(buffer[i]);
                if (ch != 0) {
                    result += ch;
                }
            }
        }
    } else {
        std::vector<char> buffer(maxLength);
        SIZE_T bytesRead;
        
        if (ReadMemory(address, buffer.data(), maxLength, &bytesRead)) {
            // 查找字符串结束符
            for (size_t i = 0; i < maxLength && buffer[i] != '\0'; ++i) {
                result += buffer[i];
            }
        }
    }
    
    return result;
}

bool MemoryTools::WriteString(LPVOID address, const std::string& str, bool isUnicode) {
    if (!IsValidProcess() || !address) {
        return false;
    }
    
    if (isUnicode) {
        std::wstring wstr(str.begin(), str.end());
        wstr += L'\0'; // 添加结束符
        return WriteMemory(address, wstr.data(), wstr.size() * sizeof(wchar_t));
    } else {
        std::string nullTerminatedStr = str + '\0';
        return WriteMemory(address, nullTerminatedStr.data(), nullTerminatedStr.size());
    }
}

LPVOID MemoryTools::AllocateMemory(SIZE_T size, DWORD allocationType, DWORD protect) {
    if (!IsValidProcess() || size == 0) {
        return nullptr;
    }
    
    return VirtualAllocEx(m_processHandle, nullptr, size, allocationType, protect);
}

bool MemoryTools::FreeMemory(LPVOID address, SIZE_T size, DWORD freeType) {
    if (!IsValidProcess() || !address) {
        return false;
    }
    
    return VirtualFreeEx(m_processHandle, address, size, freeType) != 0;
}

bool MemoryTools::ChangeProtection(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    if (!IsValidProcess() || !address || size == 0) {
        return false;
    }
    
    DWORD tempOldProtect;
    BOOL result = VirtualProtectEx(m_processHandle, address, size, newProtect, &tempOldProtect);
    
    if (oldProtect) {
        *oldProtect = tempOldProtect;
    }
    
    return result != 0;
}

std::vector<SearchResult> MemoryTools::SearchPattern(const std::vector<BYTE>& pattern, 
                                                   const std::vector<BYTE>& mask,
                                                   LPVOID startAddress,
                                                   SIZE_T searchSize) {
    std::vector<SearchResult> results;
    
    if (!IsValidProcess() || pattern.empty()) {
        return results;
    }
    
    // 如果没有提供掩码，创建全匹配掩码
    std::vector<BYTE> actualMask = mask;
    if (actualMask.empty()) {
        actualMask.resize(pattern.size(), 0xFF);
    }
    
    // 枚举内存区域进行搜索
    auto regions = EnumerateMemoryRegions();
    
    for (const auto& region : regions) {
        // 跳过不可读的区域
        if (!(region.protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            continue;
        }
        
        // 如果指定了搜索范围，检查是否在范围内
        if (startAddress && searchSize > 0) {
            LPVOID regionEnd = static_cast<BYTE*>(region.baseAddress) + region.size;
            LPVOID searchEnd = static_cast<BYTE*>(startAddress) + searchSize;
            
            if (region.baseAddress < startAddress || region.baseAddress >= searchEnd) {
                continue;
            }
        }
        
        // 读取内存区域数据
        std::vector<BYTE> regionData(region.size);
        SIZE_T bytesRead;
        
        if (!ReadMemory(region.baseAddress, regionData.data(), region.size, &bytesRead)) {
            continue;
        }
        
        // 在区域中搜索模式
        for (SIZE_T i = 0; i <= bytesRead - pattern.size(); ++i) {
            if (MatchPattern(regionData.data() + i, pattern, actualMask)) {
                SearchResult result;
                result.address = static_cast<BYTE*>(region.baseAddress) + i;
                result.data.assign(regionData.begin() + i, regionData.begin() + i + pattern.size());
                result.offset = i;
                results.push_back(result);
            }
        }
    }
    
    return results;
}

std::vector<SearchResult> MemoryTools::SearchString(const std::string& str, bool caseSensitive,
                                                   bool isUnicode, LPVOID startAddress, SIZE_T searchSize) {
    std::vector<BYTE> pattern;
    
    if (isUnicode) {
        std::wstring wstr(str.begin(), str.end());
        const BYTE* data = reinterpret_cast<const BYTE*>(wstr.data());
        pattern.assign(data, data + wstr.size() * sizeof(wchar_t));
    } else {
        std::string searchStr = str;
        if (!caseSensitive) {
            std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);
        }
        
        const BYTE* data = reinterpret_cast<const BYTE*>(searchStr.data());
        pattern.assign(data, data + searchStr.size());
    }
    
    return SearchPattern(pattern, {}, startAddress, searchSize);
}

std::vector<SearchResult> MemoryTools::SearchValue(const void* value, SIZE_T valueSize,
                                                  LPVOID startAddress, SIZE_T searchSize) {
    if (!value || valueSize == 0) {
        return {};
    }
    
    const BYTE* data = static_cast<const BYTE*>(value);
    std::vector<BYTE> pattern(data, data + valueSize);
    
    return SearchPattern(pattern, {}, startAddress, searchSize);
}

std::vector<SearchResult> MemoryTools::SearchPatternInSection(const std::vector<BYTE>& pattern,
                                                            const std::string& sectionName,
                                                            const std::vector<BYTE>& mask,
                                                            const std::string& moduleName) {
    std::vector<SearchResult> results;

    if (!IsValidProcess() || pattern.empty()) {
        return results;
    }

    // 如果指定了模块名，在该模块的代码段中搜索
    if (!moduleName.empty()) {
        HMODULE hModule = GetModuleHandle(moduleName);
        if (!hModule) {
            return results;
        }

        // 获取模块的PE头信息
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return results;
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return results;
        }

        // 查找指定段
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            // 比较段名称（段名称最多8个字符，可能没有null终止符）
            char currentSectionName[9] = {0}; // 确保null终止
            memcpy(currentSectionName, sectionHeader[i].Name, 8);

            if (sectionName == currentSectionName) {
                LPVOID sectionStart = reinterpret_cast<BYTE*>(hModule) + sectionHeader[i].VirtualAddress;
                SIZE_T sectionSize = sectionHeader[i].Misc.VirtualSize;

                std::cout << "找到段 " << sectionName << " 在模块 " << moduleName
                          << " 中，地址: 0x" << std::hex << sectionStart
                          << ", 大小: " << std::dec << sectionSize << " 字节" << std::endl;

                return SearchPattern(pattern, mask, sectionStart, sectionSize);
            }
        }
    }
    else {
        // 如果没有指定模块，在所有模块的指定段中搜索
        auto modules = EnumerateModules();

        for (HMODULE hModule : modules) {
            // 获取模块路径用于调试输出
            std::string modulePath = GetModulePath(hModule);
            std::string currentModuleName = modulePath.substr(modulePath.find_last_of("\\/") + 1);

            // 获取模块的PE头信息
            PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                continue;
            }

            PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                continue;
            }

            // 查找指定段
            PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                // 比较段名称
                char currentSectionName[9] = {0};
                memcpy(currentSectionName, sectionHeader[i].Name, 8);

                if (sectionName == currentSectionName) {
                    LPVOID sectionStart = reinterpret_cast<BYTE*>(hModule) + sectionHeader[i].VirtualAddress;
                    SIZE_T sectionSize = sectionHeader[i].Misc.VirtualSize;

                    auto sectionResults = SearchPattern(pattern, mask, sectionStart, sectionSize);
                    results.insert(results.end(), sectionResults.begin(), sectionResults.end());
                    break; // 找到段后跳出内层循环
                }
            }
        }
    }

    return results;
}

std::vector<MemoryTools::SectionInfo> MemoryTools::GetModuleSections(HMODULE hModule) {
    std::vector<SectionInfo> sections;

    if (!hModule) {
        return sections;
    }

    // 获取DOS头
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return sections;
    }

    // 获取NT头
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return sections;
    }

    // 枚举所有段
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        SectionInfo section;

        // 获取段名称（确保null终止）
        char sectionName[9] = {0};
        memcpy(sectionName, sectionHeader[i].Name, 8);
        section.name = sectionName;

        // 获取段信息
        section.baseAddress = reinterpret_cast<BYTE*>(hModule) + sectionHeader[i].VirtualAddress;
        section.virtualSize = sectionHeader[i].Misc.VirtualSize;
        section.rawSize = sectionHeader[i].SizeOfRawData;
        section.characteristics = sectionHeader[i].Characteristics;

        sections.push_back(section);
    }

    return sections;
}

std::vector<MemoryTools::SectionInfo> MemoryTools::GetModuleSections(const std::string& moduleName) {
    HMODULE hModule = GetModuleHandle(moduleName);
    return GetModuleSections(hModule);
}

std::vector<SearchResult> MemoryTools::SearchBytes(const std::initializer_list<BYTE>& bytes,
                                                  LPVOID startAddress, SIZE_T searchSize) {
    std::vector<BYTE> pattern(bytes);
    return SearchPattern(pattern, {}, startAddress, searchSize);
}

std::vector<SearchResult> MemoryTools::SearchPatternString(const std::string& patternStr,
                                                          LPVOID startAddress, SIZE_T searchSize) {
    std::vector<BYTE> pattern;
    std::vector<BYTE> mask;

    // 解析模式字符串 (如 "48 89 ?? 24 08")
    std::istringstream iss(patternStr);
    std::string token;

    while (iss >> token) {
        if (token == "??" || token == "?") {
            // 通配符
            pattern.push_back(0x00);
            mask.push_back(0x00);
        } else {
            // 十六进制字节
            try {
                BYTE value = static_cast<BYTE>(std::stoul(token, nullptr, 16));
                pattern.push_back(value);
                mask.push_back(0xFF);
            } catch (...) {
                // 无效的十六进制值，跳过
                continue;
            }
        }
    }

    if (pattern.empty()) {
        return {};
    }

    return SearchPattern(pattern, mask, startAddress, searchSize);
}

std::vector<MemoryRegion> MemoryTools::EnumerateMemoryRegions() {
    std::vector<MemoryRegion> regions;
    
    if (!IsValidProcess()) {
        return regions;
    }
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;
    
    while (VirtualQueryEx(m_processHandle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.baseAddress = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protect = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            
            // 尝试获取模块名称
            char moduleName[MAX_PATH] = {0};
            if (GetMappedFileNameA(m_processHandle, mbi.BaseAddress, moduleName, MAX_PATH)) {
                region.moduleName = moduleName;
            }
            
            regions.push_back(region);
        }
        
        address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    return regions;
}

std::vector<MemoryRegion> MemoryTools::GetExecutableRegions() {
    auto allRegions = EnumerateMemoryRegions();
    std::vector<MemoryRegion> executableRegions;
    
    for (const auto& region : allRegions) {
        if (region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
            executableRegions.push_back(region);
        }
    }
    
    return executableRegions;
}

std::vector<MemoryRegion> MemoryTools::GetWritableRegions() {
    auto allRegions = EnumerateMemoryRegions();
    std::vector<MemoryRegion> writableRegions;
    
    for (const auto& region : allRegions) {
        if (region.protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) {
            writableRegions.push_back(region);
        }
    }
    
    return writableRegions;
}

std::vector<HMODULE> MemoryTools::EnumerateModules() {
    std::vector<HMODULE> modules;

    if (!IsValidProcess()) {
        return modules;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &moduleEntry)) {
        do {
            modules.push_back(moduleEntry.hModule);
        } while (Module32Next(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return modules;
}

HMODULE MemoryTools::GetModuleHandle(const std::string& moduleName) {
    if (!IsValidProcess()) {
        return nullptr;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    HMODULE result = nullptr;
    if (Module32First(snapshot, &moduleEntry)) {
        do {
            if (_stricmp(reinterpret_cast<const char*>(moduleEntry.szModule), moduleName.c_str()) == 0) {
                result = moduleEntry.hModule;
                break;
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return result;
}

std::string MemoryTools::GetModulePath(HMODULE hModule) {
    if (!IsValidProcess()) {
        return "";
    }

    char modulePath[MAX_PATH] = {0};
    if (GetModuleFileNameExA(m_processHandle, hModule, modulePath, MAX_PATH)) {
        return std::string(modulePath);
    }

    return "";
}

LPVOID MemoryTools::GetModuleBaseAddress(const std::string& moduleName) {
    HMODULE hModule = GetModuleHandle(moduleName);
    return static_cast<LPVOID>(hModule);
}

SIZE_T MemoryTools::GetModuleSize(HMODULE hModule) {
    if (!IsValidProcess() || !hModule) {
        return 0;
    }

    MODULEINFO moduleInfo;
    if (GetModuleInformation(m_processHandle, hModule, &moduleInfo, sizeof(moduleInfo))) {
        return moduleInfo.SizeOfImage;
    }

    return 0;
}

bool MemoryTools::DumpMemory(LPVOID address, SIZE_T size, const std::string& filePath) {
    if (!IsValidProcess() || !address || size == 0) {
        return false;
    }

    std::vector<BYTE> buffer(size);
    SIZE_T bytesRead;

    if (!ReadMemory(address, buffer.data(), size, &bytesRead)) {
        return false;
    }

    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
    file.close();

    return true;
}

bool MemoryTools::DumpModule(const std::string& moduleName, const std::string& filePath) {
    HMODULE hModule = GetModuleHandle(moduleName);
    if (!hModule) {
        return false;
    }

    SIZE_T moduleSize = GetModuleSize(hModule);
    if (moduleSize == 0) {
        return false;
    }

    return DumpMemory(static_cast<LPVOID>(hModule), moduleSize, filePath);
}

bool MemoryTools::ApplyPatch(LPVOID address, const std::vector<BYTE>& patchData,
                           std::vector<BYTE>* originalData) {
    if (!IsValidProcess() || !address || patchData.empty()) {
        return false;
    }

    // 保存原始数据
    if (originalData) {
        originalData->resize(patchData.size());
        if (!ReadMemory(address, originalData->data(), patchData.size())) {
            return false;
        }
    }

    // 修改内存保护
    DWORD oldProtect;
    if (!ChangeProtection(address, patchData.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // 应用补丁
    bool result = WriteMemory(address, patchData.data(), patchData.size());

    // 恢复内存保护
    ChangeProtection(address, patchData.size(), oldProtect);

    return result;
}

bool MemoryTools::RestorePatch(LPVOID address, const std::vector<BYTE>& originalData) {
    if (!IsValidProcess() || !address || originalData.empty()) {
        return false;
    }

    // 修改内存保护
    DWORD oldProtect;
    if (!ChangeProtection(address, originalData.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // 恢复原始数据
    bool result = WriteMemory(address, originalData.data(), originalData.size());

    // 恢复内存保护
    ChangeProtection(address, originalData.size(), oldProtect);

    return result;
}

// 辅助函数实现
bool MemoryTools::IsAddressValid(LPVOID address) {
    if (!IsValidProcess() || !address) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(m_processHandle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        return (mbi.State == MEM_COMMIT) &&
               (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
    }

    return false;
}

SIZE_T MemoryTools::GetRegionSize(LPVOID address) {
    if (!IsValidProcess() || !address) {
        return 0;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(m_processHandle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        return mbi.RegionSize;
    }

    return 0;
}

bool MemoryTools::EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, nullptr, nullptr) != 0;
    CloseHandle(hToken);

    return result;
}

bool MemoryTools::MatchPattern(const BYTE* data, const std::vector<BYTE>& pattern, const std::vector<BYTE>& mask) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (mask[i] != 0 && data[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

std::vector<BYTE> MemoryTools::CreateMask(const std::string& maskStr) {
    std::vector<BYTE> mask;
    for (char c : maskStr) {
        mask.push_back(c == 'x' ? 0xFF : 0x00);
    }
    return mask;
}

// MemoryScanner类实现
MemoryScanner::MemoryScanner(MemoryTools* memoryTools) : m_memoryTools(memoryTools) {
}

std::vector<SearchResult> MemoryScanner::FirstScan(const void* value, SIZE_T valueSize) {
    if (!m_memoryTools || !value || valueSize == 0) {
        return {};
    }

    m_lastResults = m_memoryTools->SearchValue(value, valueSize);
    return m_lastResults;
}

std::vector<SearchResult> MemoryScanner::NextScan(const void* value, SIZE_T valueSize) {
    if (!m_memoryTools || !value || valueSize == 0 || m_lastResults.empty()) {
        return {};
    }

    std::vector<SearchResult> newResults;

    for (const auto& result : m_lastResults) {
        std::vector<BYTE> currentData(valueSize);
        if (m_memoryTools->ReadMemory(result.address, currentData.data(), valueSize)) {
            if (CompareValues(currentData.data(), value, valueSize)) {
                SearchResult newResult = result;
                newResult.data = currentData;
                newResults.push_back(newResult);
            }
        }
    }

    m_lastResults = newResults;
    return m_lastResults;
}

std::vector<SearchResult> MemoryScanner::ChangedScan() {
    if (!m_memoryTools || m_lastResults.empty()) {
        return {};
    }

    std::vector<SearchResult> changedResults;

    for (const auto& result : m_lastResults) {
        std::vector<BYTE> currentData(result.data.size());
        if (m_memoryTools->ReadMemory(result.address, currentData.data(), result.data.size())) {
            if (!CompareValues(currentData.data(), result.data.data(), result.data.size())) {
                SearchResult changedResult = result;
                changedResult.data = currentData;
                changedResults.push_back(changedResult);
            }
        }
    }

    m_lastResults = changedResults;
    return m_lastResults;
}

std::vector<SearchResult> MemoryScanner::UnchangedScan() {
    if (!m_memoryTools || m_lastResults.empty()) {
        return {};
    }

    std::vector<SearchResult> unchangedResults;

    for (const auto& result : m_lastResults) {
        std::vector<BYTE> currentData(result.data.size());
        if (m_memoryTools->ReadMemory(result.address, currentData.data(), result.data.size())) {
            if (CompareValues(currentData.data(), result.data.data(), result.data.size())) {
                SearchResult unchangedResult = result;
                unchangedResult.data = currentData;
                unchangedResults.push_back(unchangedResult);
            }
        }
    }

    m_lastResults = unchangedResults;
    return m_lastResults;
}

std::vector<SearchResult> MemoryScanner::IncreasedScan() {
    if (!m_memoryTools || m_lastResults.empty()) {
        return {};
    }

    std::vector<SearchResult> increasedResults;

    for (const auto& result : m_lastResults) {
        if (result.data.size() == sizeof(int)) {
            int oldValue = *reinterpret_cast<const int*>(result.data.data());
            int currentValue;

            if (m_memoryTools->ReadValue(result.address, currentValue)) {
                if (currentValue > oldValue) {
                    SearchResult increasedResult = result;
                    increasedResult.data.assign(reinterpret_cast<const BYTE*>(&currentValue),
                                              reinterpret_cast<const BYTE*>(&currentValue) + sizeof(int));
                    increasedResults.push_back(increasedResult);
                }
            }
        }
    }

    m_lastResults = increasedResults;
    return m_lastResults;
}

std::vector<SearchResult> MemoryScanner::DecreasedScan() {
    if (!m_memoryTools || m_lastResults.empty()) {
        return {};
    }

    std::vector<SearchResult> decreasedResults;

    for (const auto& result : m_lastResults) {
        if (result.data.size() == sizeof(int)) {
            int oldValue = *reinterpret_cast<const int*>(result.data.data());
            int currentValue;

            if (m_memoryTools->ReadValue(result.address, currentValue)) {
                if (currentValue < oldValue) {
                    SearchResult decreasedResult = result;
                    decreasedResult.data.assign(reinterpret_cast<const BYTE*>(&currentValue),
                                              reinterpret_cast<const BYTE*>(&currentValue) + sizeof(int));
                    decreasedResults.push_back(decreasedResult);
                }
            }
        }
    }

    m_lastResults = decreasedResults;
    return m_lastResults;
}

bool MemoryScanner::CompareValues(const void* value1, const void* value2, SIZE_T size) {
    return memcmp(value1, value2, size) == 0;
}

// MemoryWatcher类实现
MemoryWatcher::MemoryWatcher(MemoryTools* memoryTools)
    : m_memoryTools(memoryTools), m_isWatching(false), m_watchThread(nullptr) {
}

MemoryWatcher::~MemoryWatcher() {
    StopWatching();
}

bool MemoryWatcher::AddWatchPoint(LPVOID address, SIZE_T size,
                                std::function<void(LPVOID, const std::vector<BYTE>&, const std::vector<BYTE>&)> callback) {
    if (!m_memoryTools || !address || size == 0 || !callback) {
        return false;
    }

    // 检查是否已经存在相同地址的监视点
    for (const auto& watchPoint : m_watchPoints) {
        if (watchPoint.address == address) {
            return false; // 已存在
        }
    }

    WatchPoint watchPoint;
    watchPoint.address = address;
    watchPoint.size = size;
    watchPoint.callback = callback;

    // 读取初始值
    watchPoint.lastValue.resize(size);
    if (!m_memoryTools->ReadMemory(address, watchPoint.lastValue.data(), size)) {
        return false;
    }

    m_watchPoints.push_back(watchPoint);
    return true;
}

bool MemoryWatcher::RemoveWatchPoint(LPVOID address) {
    auto it = std::find_if(m_watchPoints.begin(), m_watchPoints.end(),
                          [address](const WatchPoint& wp) { return wp.address == address; });

    if (it != m_watchPoints.end()) {
        m_watchPoints.erase(it);
        return true;
    }

    return false;
}

bool MemoryWatcher::StartWatching() {
    if (m_isWatching || m_watchPoints.empty()) {
        return false;
    }

    m_isWatching = true;
    m_watchThread = CreateThread(nullptr, 0, WatchThreadProc, this, 0, nullptr);

    return m_watchThread != nullptr;
}

bool MemoryWatcher::StopWatching() {
    if (!m_isWatching) {
        return true;
    }

    m_isWatching = false;

    if (m_watchThread) {
        WaitForSingleObject(m_watchThread, 5000); // 等待最多5秒
        CloseHandle(m_watchThread);
        m_watchThread = nullptr;
    }

    return true;
}

DWORD WINAPI MemoryWatcher::WatchThreadProc(LPVOID param) {
    MemoryWatcher* watcher = static_cast<MemoryWatcher*>(param);
    if (watcher) {
        watcher->WatchLoop();
    }
    return 0;
}

void MemoryWatcher::WatchLoop() {
    while (m_isWatching) {
        for (auto& watchPoint : m_watchPoints) {
            std::vector<BYTE> currentValue(watchPoint.size);

            if (m_memoryTools->ReadMemory(watchPoint.address, currentValue.data(), watchPoint.size)) {
                // 检查值是否发生变化
                if (memcmp(currentValue.data(), watchPoint.lastValue.data(), watchPoint.size) != 0) {
                    // 调用回调函数
                    try {
                        watchPoint.callback(watchPoint.address, watchPoint.lastValue, currentValue);
                    }
                    catch (...) {
                        // 忽略回调函数中的异常
                    }

                    // 更新最后的值
                    watchPoint.lastValue = currentValue;
                }
            }
        }

        // 休眠一段时间再检查
        Sleep(100); // 100ms
    }
}
