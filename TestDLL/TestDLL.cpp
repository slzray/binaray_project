// TestDLL.cpp - 用于测试DLL注入的示例DLL
#include <Windows.h>
#include <iostream>
#include <fstream>

// DLL入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // DLL被加载时执行
        {
            // 创建日志文件记录注入成功
            std::ofstream logFile("C:\\temp\\injection_log.txt", std::ios::app);
            if (logFile.is_open()) {
                logFile << "DLL injected successfully into process ID: " << GetCurrentProcessId() << std::endl;
                logFile.close();
            }
            
            // 显示消息框（可选，用于测试）
            MessageBoxA(nullptr, "Test DLL has been injected successfully!", "Injection Success", MB_OK | MB_ICONINFORMATION);
        }
        break;
        
    case DLL_THREAD_ATTACH:
        // 新线程创建时执行
        break;
        
    case DLL_THREAD_DETACH:
        // 线程结束时执行
        break;
        
    case DLL_PROCESS_DETACH:
        // DLL被卸载时执行
        {
            std::ofstream logFile("C:\\temp\\injection_log.txt", std::ios::app);
            if (logFile.is_open()) {
                logFile << "DLL unloaded from process ID: " << GetCurrentProcessId() << std::endl;
                logFile.close();
            }
        }
        break;
    }
    return TRUE;
}

// 导出函数：用于SetWindowsHookEx注入
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int code, WPARAM wParam, LPARAM lParam) {
    // 简单的Hook过程，不做任何处理，直接传递给下一个Hook
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

// 导出函数：测试函数
extern "C" __declspec(dllexport) void TestFunction() {
    MessageBoxA(nullptr, "Test function called from injected DLL!", "Test Function", MB_OK);
}

// 导出函数：获取DLL信息
extern "C" __declspec(dllexport) const char* GetDLLInfo() {
    return "Test DLL for injection demonstration - Version 1.0";
}

// 导出函数：执行Shellcode（用于高级注入技术）
extern "C" __declspec(dllexport) void ExecuteShellcode(LPVOID shellcode, SIZE_T size) {
    if (!shellcode || size == 0) {
        return;
    }
    
    // 分配可执行内存
    LPVOID execMem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        return;
    }
    
    // 复制shellcode
    memcpy(execMem, shellcode, size);
    
    // 执行shellcode
    typedef void(*ShellcodeFunc)();
    ShellcodeFunc func = reinterpret_cast<ShellcodeFunc>(execMem);
    
    __try {
        func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 异常处理
        MessageBoxA(nullptr, "Exception occurred while executing shellcode!", "Error", MB_OK | MB_ICONERROR);
    }
    
    // 清理内存
    VirtualFree(execMem, 0, MEM_RELEASE);
}

// 导出函数：Hook MessageBoxA（演示API Hook）
extern "C" __declspec(dllexport) int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // 修改消息内容
    std::string newText = "Hooked: ";
    if (lpText) {
        newText += lpText;
    }
    
    std::string newCaption = "Hooked: ";
    if (lpCaption) {
        newCaption += lpCaption;
    }
    
    // 调用原始MessageBoxA
    return MessageBoxA(hWnd, newText.c_str(), newCaption.c_str(), uType);
}

// 导出函数：内存操作演示
extern "C" __declspec(dllexport) BOOL ReadProcessMemoryDemo(DWORD processId, LPVOID address, LPVOID buffer, SIZE_T size) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return FALSE;
    }
    
    SIZE_T bytesRead;
    BOOL result = ReadProcessMemory(hProcess, address, buffer, size, &bytesRead);
    
    CloseHandle(hProcess);
    return result && (bytesRead == size);
}

// 导出函数：写入进程内存演示
extern "C" __declspec(dllexport) BOOL WriteProcessMemoryDemo(DWORD processId, LPVOID address, LPCVOID buffer, SIZE_T size) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
    if (!hProcess) {
        return FALSE;
    }
    
    SIZE_T bytesWritten;
    BOOL result = WriteProcessMemory(hProcess, address, buffer, size, &bytesWritten);
    
    CloseHandle(hProcess);
    return result && (bytesWritten == size);
}

// 导出函数：枚举进程模块
extern "C" __declspec(dllexport) void EnumerateModules() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    std::ofstream logFile("C:\\temp\\modules_log.txt", std::ios::out);
    if (logFile.is_open()) {
        logFile << "Modules in process " << GetCurrentProcessId() << ":" << std::endl;
        
        if (Module32First(hSnapshot, &me32)) {
            do {
                logFile << "Module: " << me32.szModule << " (Base: 0x" << std::hex << me32.modBaseAddr << ")" << std::endl;
            } while (Module32Next(hSnapshot, &me32));
        }
        
        logFile.close();
    }
    
    CloseHandle(hSnapshot);
}

// 导出函数：创建远程线程演示
extern "C" __declspec(dllexport) BOOL CreateRemoteThreadDemo(DWORD processId, LPTHREAD_START_ROUTINE startAddress, LPVOID parameter) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, processId);
    if (!hProcess) {
        return FALSE;
    }
    
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, startAddress, parameter, 0, nullptr);
    if (!hThread) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 等待线程完成
    WaitForSingleObject(hThread, 5000); // 最多等待5秒
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}
