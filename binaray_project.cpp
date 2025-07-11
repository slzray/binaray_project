#include <iostream>
#include <Windows.h>
#include <tlhelp32.h> 
#include <string>
#include "Hook/InlineHook.hpp"
#include "Hook/ApiHook.hpp"
#include "Injection/DllInjection.hpp"
#include "Memory/MemoryTools.hpp"

// 前向声明
void RunHookExamples();
void RunInjectionExamples();
void RunMemoryExamples();

// Hook函数声明
int WINAPI hookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// 显示菜单
void ShowMenu() {
    std::cout << "\n=== Windows Security Tools ===" << std::endl;
    std::cout << "1. Hook Examples (IAT Hook, Inline Hook)" << std::endl;
    std::cout << "2. Injection Examples (DLL Injection, Process Hollowing)" << std::endl;
    std::cout << "3. Memory Tools Examples (Memory Search, Patch)" << std::endl;
    std::cout << "4. Interactive Hook Demo" << std::endl;
    std::cout << "5. Interactive Injection Demo" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Choose an option: ";
}

int WINAPI hookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "[HOOK] MessageBoxA intercepted!" << std::endl;
    std::cout << "  Text: " << (lpText ? lpText : "NULL") << std::endl;
    std::cout << "  Caption: " << (lpCaption ? lpCaption : "NULL") << std::endl;

    // 修改消息内容
    return MessageBoxA(hWnd, "This message was hooked!", "Hooked!", uType);
}

// 交互式Hook演示
void InteractiveHookDemo() {
    std::cout << "\n=== Interactive Hook Demo ===" << std::endl;

    ApiHookManager hookManager;

    if (hookManager.InstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA",
                               reinterpret_cast<void*>(hookedMessageBoxA))) {
        std::cout << "MessageBoxA hook installed!" << std::endl;

        std::cout << "Press Enter to test the hook..." << std::endl;
        std::cin.get();

        // 测试Hook
        MessageBoxA(nullptr, "Original message", "Test", MB_OK);

        std::cout << "Hook test completed. Press Enter to continue..." << std::endl;
        std::cin.get();

        hookManager.UninstallAllHooks();
        std::cout << "Hook uninstalled!" << std::endl;
    } else {
        std::cout << "Failed to install hook!" << std::endl;
    }
}

// 交互式注入演示
void InteractiveInjectionDemo() {
    std::cout << "\n=== Interactive Injection Demo ===" << std::endl;

    std::cout << "Available processes:" << std::endl;

    // 列出进程
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            std::cout << "PID\tProcess Name" << std::endl;
            std::cout << "---\t------------" << std::endl;

            int count = 0;
            do {
                std::wcout << pe32.th32ProcessID << L"\t" << pe32.szExeFile << std::endl;
                count++;
                if (count > 20) { // 限制显示数量
                    std::cout << "... (showing first 20 processes)" << std::endl;
                    break;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }

    std::cout << "\nEnter target process name (e.g., notepad.exe): ";
    std::wstring processName;
    std::getline(std::wcin, processName);

    if (!processName.empty()) {
        DllInjector injector;
        if (injector.SetTargetProcess(processName)) {
            std::cout << "Target process found!" << std::endl;
            std::cout << "Note: In a real scenario, you would specify a DLL to inject." << std::endl;
            std::cout << "This demo uses a system DLL for safety." << std::endl;

            // 使用系统DLL进行安全演示
            if (injector.InjectDll("C:\\Windows\\System32\\user32.dll", InjectionMethod::CREATE_REMOTE_THREAD)) {
                std::cout << "DLL injection successful!" << std::endl;
            } else {
                std::cout << "DLL injection failed!" << std::endl;
            }
        } else {
            std::cout << "Target process not found!" << std::endl;
        }
    }
}

int main() {
    std::cout << "Windows Binary Security Tools" << std::endl;
    std::cout << "============================" << std::endl;
    std::cout << "This tool demonstrates various Windows security techniques:" << std::endl;
    std::cout << "- API Hooking (IAT Hook, Inline Hook)" << std::endl;
    std::cout << "- DLL Injection (Multiple methods)" << std::endl;
    std::cout << "- Memory Manipulation" << std::endl;
    std::cout << "- Process Hollowing" << std::endl;
    std::cout << "- Thread Hijacking" << std::endl;

    int choice;
    do {
        ShowMenu();
        std::cin >> choice;
        std::cin.ignore(); // 清除输入缓冲区

        switch (choice) {
            case 1:
                RunHookExamples();
                break;
            case 2:
                RunInjectionExamples();
                break;
            case 3:
                RunMemoryExamples();
                break;
            case 4:
                InteractiveHookDemo();
                break;
            case 5:
                InteractiveInjectionDemo();
                break;
            case 0:
                std::cout << "Exiting..." << std::endl;
                break;
            default:
                std::cout << "Invalid option!" << std::endl;
                break;
        }

        if (choice != 0) {
            std::cout << "\nPress Enter to continue...";
            std::cin.get();
        }

    } while (choice != 0);

    return 0;
}