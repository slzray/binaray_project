/***********************************************************************************************
 * Copyright (c) 2025 二进制安全工具项目
 * Description: SearchPattern函数用法示例
 *              演示如何使用SearchPattern进行内存模式搜索，包括字节数组搜索、
 *              带掩码搜索、指定代码段搜索等高级功能。
 * Author:      lunsha498@gmail.com
 * Date:        2025.07.07
 ***********************************************************************************************/

#include "../Memory/MemoryTools.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

void PrintSearchResults(const std::vector<SearchResult>& results, const std::string& description) {
    std::cout << "\n=== " << description << " ===" << std::endl;
    std::cout << "找到 " << results.size() << " 个匹配结果:" << std::endl;
    
    for (size_t i = 0; i < std::min(results.size(), size_t(10)); ++i) {
        const auto& result = results[i];
        std::cout << "  [" << i + 1 << "] 地址: 0x" << std::hex << result.address << std::dec;
        std::cout << " 偏移: " << result.offset << " 数据: ";
        
        for (size_t j = 0; j < std::min(result.data.size(), size_t(16)); ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)result.data[j] << " ";
        }
        std::cout << std::dec << std::endl;
    }
    
    if (results.size() > 10) {
        std::cout << "  ... 还有 " << (results.size() - 10) << " 个结果" << std::endl;
    }
}

void BasicPatternSearchExample() {
    std::cout << "\n========== 基础模式搜索示例 ==========" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    
    // 示例1: 搜索特定字节序列
    std::vector<BYTE> pattern1 = {0x48, 0x89, 0x5C, 0x24}; // mov [rsp+?], rbx
    auto results1 = memTools.SearchPattern(pattern1);
    PrintSearchResults(results1, "搜索 mov [rsp+?], rbx 指令");
    
    // 示例2: 搜索函数序言
    std::vector<BYTE> pattern2 = {0x55, 0x48, 0x89, 0xE5}; // push rbp; mov rbp, rsp
    auto results2 = memTools.SearchPattern(pattern2);
    PrintSearchResults(results2, "搜索函数序言 push rbp; mov rbp, rsp");
    
    // 示例3: 搜索特定数值
    int targetValue = 0x12345678;
    std::vector<BYTE> pattern3(reinterpret_cast<BYTE*>(&targetValue), 
                              reinterpret_cast<BYTE*>(&targetValue) + sizeof(targetValue));
    auto results3 = memTools.SearchPattern(pattern3);
    PrintSearchResults(results3, "搜索特定数值 0x12345678");
}

void MaskedPatternSearchExample() {
    std::cout << "\n========== 带掩码模式搜索示例 ==========" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    
    // 示例1: 搜索 call 指令（忽略具体地址）
    std::vector<BYTE> pattern = {0xE8, 0x00, 0x00, 0x00, 0x00}; // call ????????
    std::vector<BYTE> mask = {0xFF, 0x00, 0x00, 0x00, 0x00};    // 只匹配第一个字节
    auto results = memTools.SearchPattern(pattern, mask);
    PrintSearchResults(results, "搜索 call 指令（带掩码）");
    
    // 示例2: 搜索 mov reg, imm32 指令模式
    std::vector<BYTE> pattern2 = {0xB8, 0x00, 0x00, 0x00, 0x00}; // mov eax, ????????
    std::vector<BYTE> mask2 = {0xFF, 0x00, 0x00, 0x00, 0x00};    // 只匹配操作码
    auto results2 = memTools.SearchPattern(pattern2, mask2);
    PrintSearchResults(results2, "搜索 mov eax, imm32 指令");
    
    // 示例3: 搜索结构体特征（部分字段匹配）
    std::vector<BYTE> pattern3 = {0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // PE头特征
    std::vector<BYTE> mask3 = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};     // 只匹配MZ
    auto results3 = memTools.SearchPattern(pattern3, mask3);
    PrintSearchResults(results3, "搜索PE文件头 MZ 特征");
}

void CodeSectionSearchExample() {
    std::cout << "\n========== 指定代码段搜索示例 ==========" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    
    // 获取当前模块的代码段
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) {
        std::cout << "无法获取当前模块句柄" << std::endl;
        return;
    }
    
    // 获取可执行区域
    auto executableRegions = memTools.GetExecutableRegions();
    std::cout << "找到 " << executableRegions.size() << " 个可执行内存区域" << std::endl;
    
    if (executableRegions.empty()) {
        std::cout << "没有找到可执行内存区域" << std::endl;
        return;
    }
    
    // 在第一个可执行区域中搜索
    const auto& codeRegion = executableRegions[0];
    std::cout << "在代码段搜索 (地址: 0x" << std::hex << codeRegion.baseAddress 
              << ", 大小: " << std::dec << codeRegion.size << " 字节)" << std::endl;
    
    // 搜索常见的x64指令模式
    std::vector<BYTE> patterns[] = {
        {0x48, 0x83, 0xEC},           // sub rsp, ?
        {0x48, 0x83, 0xC4},           // add rsp, ?
        {0x48, 0x8B},                 // mov reg64, ?
        {0xFF, 0x15},                 // call [rip+?]
        {0x48, 0x89, 0x45},           // mov [rbp+?], reg
    };
    
    std::string descriptions[] = {
        "sub rsp 指令",
        "add rsp 指令", 
        "mov reg64 指令",
        "call [rip+?] 指令",
        "mov [rbp+?] 指令"
    };
    
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
        auto results = memTools.SearchPattern(patterns[i], {}, 
                                            codeRegion.baseAddress, 
                                            codeRegion.size);
        PrintSearchResults(results, "代码段中的 " + descriptions[i]);
    }
}

void AdvancedPatternSearchExample() {
    std::cout << "\n========== 高级模式搜索示例 ==========" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    
    // 示例1: 搜索字符串常量
    std::string targetStr = "kernel32.dll";
    std::vector<BYTE> strPattern(targetStr.begin(), targetStr.end());
    auto strResults = memTools.SearchPattern(strPattern);
    PrintSearchResults(strResults, "搜索字符串 \"kernel32.dll\"");
    
    // 示例2: 搜索Unicode字符串
    std::wstring targetWStr = L"ntdll.dll";
    std::vector<BYTE> wstrPattern(reinterpret_cast<const BYTE*>(targetWStr.data()),
                                 reinterpret_cast<const BYTE*>(targetWStr.data()) + targetWStr.size() * 2);
    auto wstrResults = memTools.SearchPattern(wstrPattern);
    PrintSearchResults(wstrResults, "搜索Unicode字符串 L\"ntdll.dll\"");
    
    // 示例3: 搜索函数特征码
    std::vector<BYTE> funcSignature = {
        0x48, 0x89, 0x5C, 0x24, 0x08,  // mov [rsp+8], rbx
        0x57,                           // push rdi
        0x48, 0x83, 0xEC, 0x20         // sub rsp, 20h
    };
    auto funcResults = memTools.SearchPattern(funcSignature);
    PrintSearchResults(funcResults, "搜索特定函数特征码");
    
    // 示例4: 搜索跳转表模式
    std::vector<BYTE> jumpPattern = {0xFF, 0x24, 0xC5}; // jmp [rax*8+?]
    std::vector<BYTE> jumpMask = {0xFF, 0xFF, 0xFF};
    auto jumpResults = memTools.SearchPattern(jumpPattern, jumpMask);
    PrintSearchResults(jumpResults, "搜索跳转表指令");
}

void SearchInSpecificModule() {
    std::cout << "\n========== 指定模块搜索示例 ==========" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    
    // 获取kernel32.dll模块
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cout << "无法获取kernel32.dll模块句柄" << std::endl;
        return;
    }
    
    // 获取模块大小
    SIZE_T moduleSize = memTools.GetModuleSize(hKernel32);
    std::cout << "kernel32.dll 模块地址: 0x" << std::hex << hKernel32 
              << ", 大小: " << std::dec << moduleSize << " 字节" << std::endl;
    
    // 在kernel32.dll中搜索特定模式
    std::vector<BYTE> apiPattern = {0x48, 0x83, 0xEC, 0x28}; // sub rsp, 28h (常见API序言)
    auto results = memTools.SearchPattern(apiPattern, {}, hKernel32, moduleSize);
    PrintSearchResults(results, "kernel32.dll中的API函数序言");
    
    // 搜索字符串引用
    std::string apiName = "GetProcAddress";
    std::vector<BYTE> namePattern(apiName.begin(), apiName.end());
    auto nameResults = memTools.SearchPattern(namePattern, {}, hKernel32, moduleSize);
    PrintSearchResults(nameResults, "kernel32.dll中的 \"GetProcAddress\" 字符串");
}

int main() {
    std::cout << "SearchPattern 函数用法示例" << std::endl;
    std::cout << "============================" << std::endl;
    
    try {
        BasicPatternSearchExample();
        MaskedPatternSearchExample();
        CodeSectionSearchExample();
        AdvancedPatternSearchExample();
        SearchInSpecificModule();
        NewSearchFeaturesExample();
        PracticalSearchExamples();
    }
    catch (const std::exception& e) {
        std::cout << "异常: " << e.what() << std::endl;
    }
    catch (...) {
        std::cout << "未知异常" << std::endl;
    }
    
void NewSearchFeaturesExample() {
    std::cout << "\n========== 新增搜索功能示例 ==========" << std::endl;

    MemoryTools memTools(GetCurrentProcessId());

    // 示例1: 使用SearchBytes便捷函数
    std::cout << "\n--- SearchBytes 便捷函数 ---" << std::endl;
    auto results1 = memTools.SearchBytes({0x48, 0x89, 0x5C, 0x24, 0x08}); // mov [rsp+8], rbx
    PrintSearchResults(results1, "使用SearchBytes搜索字节序列");

    // 示例2: 使用SearchPatternString搜索带通配符的模式
    std::cout << "\n--- SearchPatternString 通配符搜索 ---" << std::endl;
    auto results2 = memTools.SearchPatternString("48 89 ?? 24 ??"); // mov [rsp+?], reg
    PrintSearchResults(results2, "搜索带通配符的模式 \"48 89 ?? 24 ??\"");

    auto results3 = memTools.SearchPatternString("E8 ?? ?? ?? ??"); // call ????????
    PrintSearchResults(results3, "搜索call指令 \"E8 ?? ?? ?? ??\"");

    auto results4 = memTools.SearchPatternString("FF 15 ?? ?? ?? ??"); // call [rip+????????]
    PrintSearchResults(results4, "搜索间接call \"FF 15 ?? ?? ?? ??\"");

    // 示例3: 在指定段中搜索
    std::cout << "\n--- SearchPatternInSection 段搜索 ---" << std::endl;

    // 在所有模块的.text段中搜索
    auto results5 = memTools.SearchPatternInSection({0x55, 0x48, 0x89, 0xE5}, ".text"); // push rbp; mov rbp, rsp
    PrintSearchResults(results5, "在所有.text段中搜索函数序言");

    // 在kernel32.dll的.text段中搜索
    auto results6 = memTools.SearchPatternInSection({0x48, 0x83, 0xEC}, ".text", {}, "kernel32.dll");
    PrintSearchResults(results6, "在kernel32.dll的.text段中搜索 sub rsp 指令");

    // 在.data段中搜索数据
    auto results7 = memTools.SearchPatternInSection({0x4D, 0x5A}, ".data"); // MZ header in data
    PrintSearchResults(results7, "在.data段中搜索MZ特征");

    // 在.rdata段中搜索只读数据
    std::string apiStr = "GetProcAddress";
    std::vector<BYTE> apiPattern(apiStr.begin(), apiStr.end());
    auto results8 = memTools.SearchPatternInSection(apiPattern, ".rdata");
    PrintSearchResults(results8, "在.rdata段中搜索API名称字符串");

    // 示例4: 组合使用不同搜索方法
    std::cout << "\n--- 组合搜索示例 ---" << std::endl;

    // 先在代码段中搜索特定模式
    auto codeResults = memTools.SearchPatternInCodeSection({0xFF, 0x25}); // jmp [rip+????????]
    std::cout << "在代码段中找到 " << codeResults.size() << " 个间接跳转指令" << std::endl;

    // 然后搜索特定的API调用模式
    auto apiResults = memTools.SearchPatternString("FF 15 ?? ?? ?? ??"); // call [rip+????????]
    std::cout << "找到 " << apiResults.size() << " 个API调用指令" << std::endl;

    // 搜索常见的栈操作
    auto stackResults = memTools.SearchBytes({0x48, 0x83, 0xC4}); // add rsp, ?
    std::cout << "找到 " << stackResults.size() << " 个栈恢复指令" << std::endl;
}

void PracticalSearchExamples() {
    std::cout << "\n========== 实用搜索示例 ==========" << std::endl;

    MemoryTools memTools(GetCurrentProcessId());

    // 示例1: 搜索常见的shellcode特征
    std::cout << "\n--- Shellcode特征搜索 ---" << std::endl;

    // NOP sled
    auto nopResults = memTools.SearchPatternString("90 90 90 90 90 90 90 90");
    PrintSearchResults(nopResults, "搜索NOP sled");

    // 常见的shellcode序言
    auto shellcodeResults = memTools.SearchPatternString("FC 48 83 E4 F0"); // cld; and rsp, -16
    PrintSearchResults(shellcodeResults, "搜索shellcode序言");

    // 示例2: 搜索加密/解密常量
    std::cout << "\n--- 加密常量搜索 ---" << std::endl;

    // XOR key patterns
    auto xorResults = memTools.SearchBytes({0x31, 0xC0, 0x31, 0xDB}); // xor eax,eax; xor ebx,ebx
    PrintSearchResults(xorResults, "搜索XOR清零模式");

    // 示例3: 搜索异常处理结构
    std::cout << "\n--- 异常处理搜索 ---" << std::endl;

    // SEH handler patterns
    auto sehResults = memTools.SearchPatternString("64 ?? ?? ?? ?? 00 00"); // fs:[offset]
    PrintSearchResults(sehResults, "搜索SEH相关指令");

    // 示例4: 搜索反调试技术
    std::cout << "\n--- 反调试技术搜索 ---" << std::endl;

    // IsDebuggerPresent API
    std::string debugApi = "IsDebuggerPresent";
    std::vector<BYTE> debugPattern(debugApi.begin(), debugApi.end());
    auto debugResults = memTools.SearchPattern(debugPattern);
    PrintSearchResults(debugResults, "搜索IsDebuggerPresent字符串");

    // PEB检查模式
    auto pebResults = memTools.SearchPatternString("64 8B ?? 30 00 00 00"); // mov reg, fs:[30h]
    PrintSearchResults(pebResults, "搜索PEB访问模式");
}

    std::cout << "\n示例运行完成，按任意键退出..." << std::endl;
    std::cin.get();

    return 0;
}
