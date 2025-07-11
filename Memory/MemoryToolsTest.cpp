#include "MemoryTools.hpp"
#include <iostream>
#include <iomanip>

void TestMemoryTools() {
    std::cout << "=== Memory Tools Test ===" << std::endl;
    
    // 测试当前进程的内存操作
    MemoryTools memTools(GetCurrentProcessId());
    
    if (!memTools.IsValidProcess()) {
        std::cout << "Failed to initialize MemoryTools for current process" << std::endl;
        return;
    }
    
    std::cout << "Successfully initialized MemoryTools for PID: " << memTools.GetProcessId() << std::endl;
    
    // 测试1: 内存读写
    std::cout << "\n--- Test 1: Memory Read/Write ---" << std::endl;
    int testValue = 12345;
    int readValue = 0;
    
    if (memTools.ReadValue(&testValue, readValue)) {
        std::cout << "Read value: " << readValue << " (Expected: " << testValue << ")" << std::endl;
    } else {
        std::cout << "Failed to read value" << std::endl;
    }
    
    // 测试2: 字符串读写
    std::cout << "\n--- Test 2: String Read/Write ---" << std::endl;
    std::string testString = "Hello, Memory Tools!";
    std::string readString = memTools.ReadString(const_cast<char*>(testString.c_str()), testString.length() + 1);
    std::cout << "Read string: \"" << readString << "\"" << std::endl;
    
    // 测试3: 内存搜索
    std::cout << "\n--- Test 3: Memory Search ---" << std::endl;
    auto searchResults = memTools.SearchValue(&testValue, sizeof(testValue));
    std::cout << "Found " << searchResults.size() << " occurrences of value " << testValue << std::endl;
    
    for (size_t i = 0; i < std::min(searchResults.size(), size_t(5)); ++i) {
        std::cout << "  Address: 0x" << std::hex << searchResults[i].address << std::dec << std::endl;
    }
    
    // 测试4: 字符串搜索
    std::cout << "\n--- Test 4: String Search ---" << std::endl;
    auto stringResults = memTools.SearchString("Memory Tools", true, false);
    std::cout << "Found " << stringResults.size() << " occurrences of string \"Memory Tools\"" << std::endl;
    
    // 测试5: 内存区域枚举
    std::cout << "\n--- Test 5: Memory Region Enumeration ---" << std::endl;
    auto regions = memTools.EnumerateMemoryRegions();
    std::cout << "Total memory regions: " << regions.size() << std::endl;
    
    auto executableRegions = memTools.GetExecutableRegions();
    std::cout << "Executable regions: " << executableRegions.size() << std::endl;
    
    auto writableRegions = memTools.GetWritableRegions();
    std::cout << "Writable regions: " << writableRegions.size() << std::endl;
    
    // 显示前几个区域的信息
    std::cout << "\nFirst 5 memory regions:" << std::endl;
    for (size_t i = 0; i < std::min(regions.size(), size_t(5)); ++i) {
        const auto& region = regions[i];
        std::cout << "  Region " << i + 1 << ": 0x" << std::hex << region.baseAddress 
                  << " - 0x" << (static_cast<BYTE*>(region.baseAddress) + region.size)
                  << " (Size: " << std::dec << region.size << " bytes, Protect: 0x" 
                  << std::hex << region.protect << ")" << std::dec << std::endl;
    }
    
    // 测试6: 模块枚举
    std::cout << "\n--- Test 6: Module Enumeration ---" << std::endl;
    auto modules = memTools.EnumerateModules();
    std::cout << "Total modules: " << modules.size() << std::endl;
    
    // 显示前几个模块
    std::cout << "\nFirst 5 modules:" << std::endl;
    for (size_t i = 0; i < std::min(modules.size(), size_t(5)); ++i) {
        std::string modulePath = memTools.GetModulePath(modules[i]);
        SIZE_T moduleSize = memTools.GetModuleSize(modules[i]);
        
        std::cout << "  Module " << i + 1 << ": 0x" << std::hex << modules[i] 
                  << " (Size: " << std::dec << moduleSize << " bytes)" << std::endl;
        if (!modulePath.empty()) {
            std::cout << "    Path: " << modulePath << std::endl;
        }
    }
    
    // 测试7: 内存分配和释放
    std::cout << "\n--- Test 7: Memory Allocation ---" << std::endl;
    LPVOID allocatedMemory = memTools.AllocateMemory(4096);
    if (allocatedMemory) {
        std::cout << "Allocated 4096 bytes at: 0x" << std::hex << allocatedMemory << std::dec << std::endl;
        
        // 写入测试数据
        int testData = 0xDEADBEEF;
        if (memTools.WriteValue(allocatedMemory, testData)) {
            std::cout << "Successfully wrote test data to allocated memory" << std::endl;
            
            // 读取验证
            int readData;
            if (memTools.ReadValue(allocatedMemory, readData)) {
                std::cout << "Read back: 0x" << std::hex << readData << std::dec << std::endl;
            }
        }
        
        // 释放内存
        if (memTools.FreeMemory(allocatedMemory)) {
            std::cout << "Successfully freed allocated memory" << std::endl;
        }
    } else {
        std::cout << "Failed to allocate memory" << std::endl;
    }
}

void TestMemoryScanner() {
    std::cout << "\n=== Memory Scanner Test ===" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    MemoryScanner scanner(&memTools);
    
    // 创建一些测试数据
    int testValues[] = {100, 200, 300, 400, 500};
    
    std::cout << "Test values: ";
    for (int value : testValues) {
        std::cout << value << " ";
    }
    std::cout << std::endl;
    
    // 首次扫描
    int searchValue = 300;
    auto results = scanner.FirstScan(&searchValue, sizeof(searchValue));
    std::cout << "First scan for value " << searchValue << ": found " << results.size() << " results" << std::endl;
    
    // 修改值
    testValues[2] = 350;
    std::cout << "Changed value from 300 to 350" << std::endl;
    
    // 变化扫描
    auto changedResults = scanner.ChangedScan();
    std::cout << "Changed scan: found " << changedResults.size() << " changed values" << std::endl;
}

void TestMemoryWatcher() {
    std::cout << "\n=== Memory Watcher Test ===" << std::endl;
    
    MemoryTools memTools(GetCurrentProcessId());
    MemoryWatcher watcher(&memTools);
    
    // 创建测试变量
    static int watchedValue = 42;
    
    std::cout << "Initial watched value: " << watchedValue << std::endl;
    
    // 添加监视点
    bool added = watcher.AddWatchPoint(&watchedValue, sizeof(watchedValue), 
        [](LPVOID address, const std::vector<BYTE>& oldValue, const std::vector<BYTE>& newValue) {
            int oldVal = *reinterpret_cast<const int*>(oldValue.data());
            int newVal = *reinterpret_cast<const int*>(newValue.data());
            std::cout << "Value at 0x" << std::hex << address << std::dec 
                      << " changed from " << oldVal << " to " << newVal << std::endl;
        });
    
    if (added) {
        std::cout << "Successfully added watch point" << std::endl;
        
        // 开始监视
        if (watcher.StartWatching()) {
            std::cout << "Started watching..." << std::endl;
            
            // 修改值几次
            for (int i = 0; i < 5; ++i) {
                Sleep(500);
                watchedValue += 10;
                std::cout << "Changed value to: " << watchedValue << std::endl;
            }
            
            // 停止监视
            watcher.StopWatching();
            std::cout << "Stopped watching" << std::endl;
        }
    }
}

int main() {
    std::cout << "Memory Tools Implementation Test" << std::endl;
    std::cout << "================================" << std::endl;
    
    try {
        TestMemoryTools();
        TestMemoryScanner();
        TestMemoryWatcher();
    }
    catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    catch (...) {
        std::cout << "Unknown exception occurred" << std::endl;
    }
    
    std::cout << "\nTest completed. Press any key to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
