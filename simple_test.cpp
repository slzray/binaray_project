#include <iostream>
#include <Windows.h>

// 只测试基本的头文件包含和类实例化
#include "Hook/InlineHook.hpp"
#include "Hook/ApiHook.hpp"
#include "Memory/MemoryTools.hpp"
#include "Injection/DllInjection.hpp"

int main() {
    std::cout << "Simple compilation test..." << std::endl;
    
    try {
        // 测试类实例化
        std::cout << "Testing class instantiation..." << std::endl;
        
        InlineHook64 inlineHook;
        std::cout << "✓ InlineHook64 created" << std::endl;
        
        ApiHookManager hookManager;
        std::cout << "✓ ApiHookManager created" << std::endl;
        
        MemoryTools memTools;
        std::cout << "✓ MemoryTools created" << std::endl;
        
        DllInjector injector;
        std::cout << "✓ DllInjector created" << std::endl;
        
        std::cout << "\nAll classes instantiated successfully!" << std::endl;
        std::cout << "Basic compilation test PASSED!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
