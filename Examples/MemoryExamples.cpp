#include "../Memory/MemoryTools.hpp"
#include <iostream>
#include <Windows.h>

// 演示内存读写
void DemonstrateMemoryReadWrite() {
    std::cout << "\n=== Memory Read/Write Demo ===" << std::endl;
    
    // 创建一些测试数据
    int testValue = 12345;
    std::string testString = "Hello, Memory!";
    
    std::cout << "Original values:" << std::endl;
    std::cout << "  Integer: " << testValue << std::endl;
    std::cout << "  String: " << testString << std::endl;
    
    // 使用当前进程进行演示
    MemoryTools memTools(GetCurrentProcess());
    
    // 读取整数值
    int readValue;
    if (memTools.ReadValue(&testValue, readValue)) {
        std::cout << "Read integer from memory: " << readValue << std::endl;
    }
    
    // 修改整数值
    int newValue = 54321;
    if (memTools.WriteValue(&testValue, newValue)) {
        std::cout << "Modified integer value to: " << testValue << std::endl;
    }
    
    // 读取字符串
    std::string readString = memTools.ReadString(const_cast<char*>(testString.c_str()), testString.length());
    std::cout << "Read string from memory: " << readString << std::endl;
}

// 演示内存搜索
void DemonstrateMemorySearch() {
    std::cout << "\n=== Memory Search Demo ===" << std::endl;
    
    // 创建测试数据数组
    int testArray[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int searchValue = 5;
    
    std::cout << "Searching for value: " << searchValue << std::endl;
    
    MemoryTools memTools(GetCurrentProcess());
    
    // 搜索特定值
    auto results = memTools.SearchValue(&searchValue, sizeof(searchValue), 
                                       testArray, sizeof(testArray));
    
    std::cout << "Search results: " << results.size() << " matches found" << std::endl;
    
    for (const auto& result : results) {
        std::cout << "  Found at address: 0x" << std::hex << result.address << std::dec << std::endl;
    }
    
    // 字符串搜索
    std::string testText = "This is a test string for memory search demonstration.";
    std::string searchText = "test";
    
    std::cout << "\nSearching for string: \"" << searchText << "\"" << std::endl;
    
    auto stringResults = memTools.SearchString(searchText, true, false, 
                                              const_cast<char*>(testText.c_str()), testText.length());
    
    std::cout << "String search results: " << stringResults.size() << " matches found" << std::endl;
    
    for (const auto& result : stringResults) {
        std::cout << "  Found at offset: " << result.offset << std::endl;
    }
}

// 演示内存扫描器
void DemonstrateMemoryScanner() {
    std::cout << "\n=== Memory Scanner Demo ===" << std::endl;
    
    // 创建测试变量
    static int gameScore = 1000;
    static int gameLevel = 1;
    static float gameHealth = 100.0f;
    
    std::cout << "Initial game state:" << std::endl;
    std::cout << "  Score: " << gameScore << std::endl;
    std::cout << "  Level: " << gameLevel << std::endl;
    std::cout << "  Health: " << gameHealth << std::endl;
    
    MemoryTools memTools(GetCurrentProcess());
    MemoryScanner scanner(&memTools);
    
    // 首次扫描分数
    std::cout << "\nScanning for score value: " << gameScore << std::endl;
    auto results = scanner.FirstScan(&gameScore, sizeof(gameScore));
    std::cout << "First scan results: " << results.size() << " matches" << std::endl;
    
    // 修改分数
    gameScore = 1500;
    std::cout << "\nScore changed to: " << gameScore << std::endl;
    
    // 下次扫描
    results = scanner.NextScan(&gameScore, sizeof(gameScore));
    std::cout << "Next scan results: " << results.size() << " matches" << std::endl;
    
    if (!results.empty()) {
        std::cout << "Found score at address: 0x" << std::hex << results[0].address << std::dec << std::endl;
        
        // 验证地址是否正确
        if (results[0].address == &gameScore) {
            std::cout << "Address verification: SUCCESS!" << std::endl;
        }
    }
}

int testFunction(int a, int b) {
    return a + b;
}

// 演示内存补丁
void DemonstrateMemoryPatching() {
    std::cout << "\n=== Memory Patching Demo ===" << std::endl;
    
    int result1 = testFunction(3, 4);
    std::cout << "Original function result: " << result1 << std::endl;
    
    MemoryTools memTools(GetCurrentProcess());
    
    // 注意：实际的内存补丁需要更复杂的汇编代码分析
    // 这里只是演示概念
    std::cout << "Note: Memory patching requires detailed assembly analysis." << std::endl;
    std::cout << "This is a conceptual demonstration." << std::endl;
    
    // 获取函数地址
    void* funcAddr = reinterpret_cast<void*>(testFunction);
    std::cout << "Function address: 0x" << std::hex << funcAddr << std::dec << std::endl;
    
    // 在实际应用中，你需要：
    // 1. 分析目标函数的汇编代码
    // 2. 创建适当的补丁字节码
    // 3. 保存原始字节码
    // 4. 应用补丁
    // 5. 测试修改后的行为
    // 6. 可选择性地恢复原始代码
}

// 演示内存监视器
void DemonstrateMemoryWatcher() {
    std::cout << "\n=== Memory Watcher Demo ===" << std::endl;
    
    static int watchedValue = 100;
    
    std::cout << "Initial watched value: " << watchedValue << std::endl;
    
    MemoryTools memTools(GetCurrentProcess());
    MemoryWatcher watcher(&memTools);
    
    // 添加监视点
    bool watchAdded = watcher.AddWatchPoint(&watchedValue, sizeof(watchedValue),
        [](LPVOID address, const std::vector<BYTE>& oldValue, const std::vector<BYTE>& newValue) {
            int oldInt = *reinterpret_cast<const int*>(oldValue.data());
            int newInt = *reinterpret_cast<const int*>(newValue.data());
            
            std::cout << "[WATCHER] Value changed at 0x" << std::hex << address << std::dec;
            std::cout << " from " << oldInt << " to " << newInt << std::endl;
        });
    
    if (watchAdded) {
        std::cout << "Memory watcher installed successfully!" << std::endl;
        
        // 开始监视
        if (watcher.StartWatching()) {
            std::cout << "Watching started. Modifying value..." << std::endl;
            
            // 修改值几次
            Sleep(100);
            watchedValue = 200;
            Sleep(100);
            watchedValue = 300;
            Sleep(100);
            watchedValue = 150;
            Sleep(100);
            
            // 停止监视
            watcher.StopWatching();
            std::cout << "Watching stopped." << std::endl;
        }
    } else {
        std::cout << "Failed to install memory watcher!" << std::endl;
    }
}

// 演示模块枚举
void DemonstrateModuleEnumeration() {
    std::cout << "\n=== Module Enumeration Demo ===" << std::endl;
    
    MemoryTools memTools(GetCurrentProcess());
    
    // 枚举所有模块
    auto modules = memTools.EnumerateModules();
    std::cout << "Loaded modules: " << modules.size() << std::endl;
    
    int count = 0;
    for (HMODULE hModule : modules) {
        std::string modulePath = memTools.GetModulePath(hModule);
        SIZE_T moduleSize = memTools.GetModuleSize(hModule);
        
        std::cout << "  [" << count++ << "] " << modulePath;
        std::cout << " (Base: 0x" << std::hex << hModule;
        std::cout << ", Size: 0x" << moduleSize << std::dec << ")" << std::endl;
        
        if (count >= 10) { // 限制显示数量
            std::cout << "  ... (showing first 10 modules)" << std::endl;
            break;
        }
    }
    
    // 获取特定模块信息
    LPVOID kernelBase = memTools.GetModuleBaseAddress("kernel32.dll");
    if (kernelBase) {
        std::cout << "\nkernel32.dll base address: 0x" << std::hex << kernelBase << std::dec << std::endl;
    }
}

// 主函数
void RunMemoryExamples() {
    std::cout << "Windows Security Tools - Memory Examples" << std::endl;
    std::cout << "=======================================" << std::endl;
    
    try {
        DemonstrateMemoryReadWrite();
        DemonstrateMemorySearch();
        DemonstrateMemoryScanner();
        DemonstrateMemoryPatching();
        DemonstrateMemoryWatcher();
        DemonstrateModuleEnumeration();
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    std::cout << "\nMemory examples completed!" << std::endl;
}
