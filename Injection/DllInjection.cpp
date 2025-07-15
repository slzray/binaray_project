#include "DllInjection.hpp"
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <string>

DllInjector::DllInjector() 
    : m_targetProcessId(0)
    , m_targetProcess(nullptr) {
    EnableDebugPrivilege();
}

DllInjector::~DllInjector() {
    if (m_targetProcess) {
        CloseHandle(m_targetProcess);
    }
}

bool DllInjector::SetTargetProcess(DWORD processId) {
    if (m_targetProcess) {
        CloseHandle(m_targetProcess);
    }
    
    m_targetProcessId = processId;
    m_targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    
    return m_targetProcess != nullptr;
}

bool DllInjector::SetTargetProcess(const std::wstring& processName) {
    DWORD processId = GetProcessIdByName(processName);
    if (processId == 0) {
        return false;
    }
    
    return SetTargetProcess(processId);
}

bool DllInjector::InjectDll(const std::string& dllPath, InjectionMethod method) {
    if (!m_targetProcess) {
        return false;
    }
    
    m_dllPath = dllPath;
    
    switch (method) {
        case InjectionMethod::CREATE_REMOTE_THREAD:
            return InjectByCreateRemoteThread(dllPath);
        case InjectionMethod::SET_WINDOWS_HOOK:
            return InjectBySetWindowsHook(dllPath);
        case InjectionMethod::MANUAL_DLL_MAPPING:
            return InjectByManualMapping(dllPath);
        case InjectionMethod::THREAD_HIJACKING:
            return InjectByThreadHijacking(dllPath);
        case InjectionMethod::PROCESS_HOLLOWING:
            return InjectByProcessHollowing(dllPath);
        default:
            return false;
    }
}

bool DllInjector::InjectByCreateRemoteThread(const std::string& dllPath) {
    // 1. 在目标进程中分配内存
    SIZE_T pathSize = dllPath.length() + 1;
    LPVOID remoteMemory = VirtualAllocEx(
        m_targetProcess,
        nullptr,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!remoteMemory) {
        return false;
    }
    
    // 2. 写入DLL路径
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(m_targetProcess, remoteMemory, dllPath.c_str(), pathSize, &bytesWritten)) {
        VirtualFreeEx(m_targetProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }
    
    // 3. 获取LoadLibraryA地址
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        return false;
    }

    FARPROC loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
    
    if (!loadLibraryAddr) {
        VirtualFreeEx(m_targetProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }
    
    // 4. 创建远程线程
    HANDLE remoteThread = CreateRemoteThread(
        m_targetProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
        remoteMemory,
        0,
        nullptr
    );
    
    if (!remoteThread) {
        VirtualFreeEx(m_targetProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }
    
    // 5. 等待线程完成
    WaitForSingleObject(remoteThread, INFINITE);
    
    // 6. 清理资源
    CloseHandle(remoteThread);
    VirtualFreeEx(m_targetProcess, remoteMemory, 0, MEM_RELEASE);
    
    return true;
}

bool DllInjector::InjectBySetWindowsHook(const std::string& dllPath) {
    // 加载DLL到当前进程
    HMODULE hMod = LoadLibraryA(dllPath.c_str());
    if (!hMod) {
        return false;
    }
    
    // 获取hook过程地址（假设DLL导出了HookProc函数）
    HOOKPROC hookProc = reinterpret_cast<HOOKPROC>(GetProcAddress(hMod, "HookProc"));
    if (!hookProc) {
        FreeLibrary(hMod);
        return false;
    }
    
    // 安装hook
    HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, hookProc, hMod, 0);
    if (!hHook) {
        FreeLibrary(hMod);
        return false;
    }
    
    // 触发hook（发送消息到目标进程）
    PostThreadMessage(m_targetProcessId, WM_NULL, 0, 0);
    
    // 注意：在实际应用中，你可能需要保持hook活跃状态
    // 这里为了演示，立即卸载hook
    UnhookWindowsHookEx(hHook);
    FreeLibrary(hMod);
    
    return true;
}

DWORD DllInjector::GetProcessIdByName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
    return 0;
}

bool DllInjector::EnableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    
    TOKEN_PRIVILEGES privileges;
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    
    bool result = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr) != 0;
    CloseHandle(token);
    
    return result;
}

// 手动DLL映射实现
bool DllInjector::InjectByManualMapping(const std::string& dllPath) {
    std::cout << "Manual DLL mapping - Loading DLL file..." << std::endl;

    // 读取DLL文件
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << "Failed to open DLL file: " << dllPath << std::endl;
        return false;
    }

    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> dllData(fileSize);
    file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
    file.close();

    // 解析PE头
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "Invalid DOS signature" << std::endl;
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        dllData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "Invalid NT signature" << std::endl;
        return false;
    }

    // 在目标进程中分配内存
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    LPVOID remoteImage = VirtualAllocEx(m_targetProcess, nullptr, imageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        std::cout << "Failed to allocate memory in target process" << std::endl;
        return false;
    }

    std::cout << "Manual DLL mapping partially implemented - allocated memory at: 0x"
              << std::hex << remoteImage << std::dec << std::endl;

    // 注意：完整的手动映射需要处理重定位、导入表等，这里只是演示框架
    VirtualFreeEx(m_targetProcess, remoteImage, 0, MEM_RELEASE);
    return true;
}

// 线程劫持实现
bool DllInjector::InjectByThreadHijacking(const std::string& dllPath) {
    std::cout << "Thread hijacking injection..." << std::endl;

    // 获取目标进程的线程
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    DWORD targetThreadId = 0;
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == m_targetProcessId) {
                targetThreadId = threadEntry.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);

    if (targetThreadId == 0) {
        std::cout << "No suitable thread found for hijacking" << std::endl;
        return false;
    }

    // 打开目标线程
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
    if (!hThread) {
        std::cout << "Failed to open target thread" << std::endl;
        return false;
    }

    // 挂起线程
    if (SuspendThread(hThread) == -1) {
        CloseHandle(hThread);
        return false;
    }

    std::cout << "Thread hijacking - thread suspended, creating shellcode..." << std::endl;

    // 创建LoadLibrary shellcode（简化版本）
    std::string loadLibraryShellcode =
        "\\x48\\x83\\xEC\\x28"          // sub rsp, 28h
        "\\x48\\xB9";                   // mov rcx, dllPath (需要填入实际地址)

    // 恢复线程
    ResumeThread(hThread);
    CloseHandle(hThread);

    std::cout << "Thread hijacking demonstration completed" << std::endl;
    return true;
}

// 进程挖空实现
bool DllInjector::InjectByProcessHollowing(const std::string& dllPath) {
    std::cout << "Process hollowing injection..." << std::endl;

    // 创建挂起的目标进程
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::string targetPath = "C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessA(targetPath.c_str(), nullptr, nullptr, nullptr, FALSE,
                       CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cout << "Failed to create suspended process" << std::endl;
        return false;
    }

    std::cout << "Created suspended process: " << pi.dwProcessId << std::endl;

    // 获取进程上下文
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &context)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    std::cout << "Process hollowing - got thread context" << std::endl;

    // 注意：完整的进程挖空需要：
    // 1. 卸载目标进程的原始映像
    // 2. 在目标进程中分配新的内存空间
    // 3. 将载荷写入目标进程
    // 4. 修复重定位和导入表
    // 5. 设置新的入口点
    // 6. 恢复线程执行

    std::cout << "Process hollowing demonstration - cleaning up..." << std::endl;

    // 清理资源
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

bool DllInjector::EjectDll(const std::wstring& dllName) {
    // DLL卸载实现
    HMODULE hMod = GetRemoteModuleHandle(dllName);
    if (!hMod) {
        return false;
    }

    // 获取FreeLibrary地址
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        return false;
    }
    
    FARPROC freeLibraryAddr = GetProcAddress(kernel32, "FreeLibrary");
    if (!freeLibraryAddr) {
        return false;
    }
    
    HANDLE remoteThread = CreateRemoteThread(
        m_targetProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibraryAddr),
        hMod,
        0,
        nullptr
    );
    
    if (!remoteThread) {
        return false;
    }
    
    WaitForSingleObject(remoteThread, INFINITE);
    CloseHandle(remoteThread);
    
    return true;
}

HMODULE DllInjector::GetRemoteModuleHandle(const std::wstring& moduleName) {
    // 获取远程进程中模块句柄的实现
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_targetProcessId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    HMODULE result = nullptr;
    if (Module32First(snapshot, &moduleEntry)) {
        do {
            if (_wcsicmp(moduleEntry.szModule, moduleName.c_str()) == 0) {
                result = moduleEntry.hModule;
                break;
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return result;
}

// ProcessHollower实现
ProcessHollower::ProcessHollower() {
    ZeroMemory(&m_processInfo, sizeof(m_processInfo));
}

ProcessHollower::~ProcessHollower() {
    Cleanup();
}

bool ProcessHollower::HollowProcess(const std::string& targetPath, const std::string& payloadPath) {
    m_targetPath = targetPath;
    m_payloadPath = payloadPath;

    std::cout << "Starting process hollowing..." << std::endl;
    std::cout << "Target: " << targetPath << std::endl;
    std::cout << "Payload: " << payloadPath << std::endl;

    // 1. 创建挂起的目标进程
    if (!CreateSuspendedProcess(targetPath)) {
        std::cout << "Failed to create suspended process" << std::endl;
        return false;
    }

    std::cout << "Created suspended process with PID: " << m_processInfo.dwProcessId << std::endl;

    // 2. 卸载目标进程的原始映像
    if (!UnmapTargetImage()) {
        std::cout << "Failed to unmap target image" << std::endl;
        Cleanup();
        return false;
    }

    std::cout << "Unmapped target image" << std::endl;

    // 3. 读取载荷文件
    std::ifstream payloadFile(payloadPath, std::ios::binary | std::ios::ate);
    if (!payloadFile.is_open()) {
        std::cout << "Failed to open payload file" << std::endl;
        Cleanup();
        return false;
    }

    size_t payloadSize = payloadFile.tellg();
    payloadFile.seekg(0, std::ios::beg);

    std::vector<BYTE> payloadData(payloadSize);
    payloadFile.read(reinterpret_cast<char*>(payloadData.data()), payloadSize);
    payloadFile.close();

    std::cout << "Loaded payload file, size: " << payloadSize << " bytes" << std::endl;

    // 4. 分配内存并写入载荷
    if (!AllocatePayloadMemory(payloadSize)) {
        std::cout << "Failed to allocate payload memory" << std::endl;
        Cleanup();
        return false;
    }

    if (!WritePayloadToTarget(payloadData)) {
        std::cout << "Failed to write payload to target" << std::endl;
        Cleanup();
        return false;
    }

    std::cout << "Payload written to target process" << std::endl;

    // 注意：完整实现还需要修复重定位表、导入表等
    std::cout << "Process hollowing completed (simplified version)" << std::endl;

    return true;
}

bool ProcessHollower::CreateSuspendedProcess(const std::string& path) {
    STARTUPINFOA si = { sizeof(si) };

    return CreateProcessA(
        path.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &si,
        &m_processInfo
    ) != 0;
}

bool ProcessHollower::UnmapTargetImage() {
    // 获取目标进程的PEB地址
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(m_processInfo.hThread, &context)) {
        return false;
    }

    // 简化实现：在实际应用中需要读取PEB并卸载映像
    std::cout << "Unmapping target image (simplified)" << std::endl;
    return true;
}

bool ProcessHollower::AllocatePayloadMemory(SIZE_T imageSize) {
    // 在目标进程中分配内存
    LPVOID allocatedMemory = VirtualAllocEx(
        m_processInfo.hProcess,
        nullptr,
        imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    return allocatedMemory != nullptr;
}

bool ProcessHollower::WritePayloadToTarget(const std::vector<BYTE>& payloadData) {
    // 简化实现：写入载荷数据
    SIZE_T bytesWritten;
    return WriteProcessMemory(
        m_processInfo.hProcess,
        reinterpret_cast<LPVOID>(0x400000), // 简化的基地址
        payloadData.data(),
        payloadData.size(),
        &bytesWritten
    ) && (bytesWritten == payloadData.size());
}

void ProcessHollower::Cleanup() {
    if (m_processInfo.hProcess) {
        TerminateProcess(m_processInfo.hProcess, 0);
        CloseHandle(m_processInfo.hProcess);
        m_processInfo.hProcess = nullptr;
    }

    if (m_processInfo.hThread) {
        CloseHandle(m_processInfo.hThread);
        m_processInfo.hThread = nullptr;
    }
}

// ThreadHijacker实现
bool ThreadHijacker::HijackThread(DWORD threadId, const std::vector<BYTE>& shellcode) {
    std::cout << "Attempting to hijack thread: " << threadId << std::endl;

    // 打开目标线程
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) {
        std::cout << "Failed to open thread: " << GetLastError() << std::endl;
        return false;
    }

    // 获取线程上下文
    CONTEXT originalContext;
    if (!GetThreadContext(threadId, originalContext)) {
        CloseHandle(hThread);
        return false;
    }

    // 挂起线程
    if (SuspendThread(hThread) == -1) {
        std::cout << "Failed to suspend thread" << std::endl;
        CloseHandle(hThread);
        return false;
    }

    std::cout << "Thread suspended successfully" << std::endl;

    // 获取线程所属进程
    DWORD processId = 0;

    // 通过线程快照获取进程ID
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(snapshot, &te32)) {
            do {
                if (te32.th32ThreadID == threadId) {
                    processId = te32.th32OwnerProcessID;
                    break;
                }
            } while (Thread32Next(snapshot, &te32));
        }
        CloseHandle(snapshot);
    }

    if (processId == 0) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (!hProcess) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // 在目标进程中分配内存存放shellcode
    LPVOID shellcodeMemory = AllocateMemoryInProcess(hProcess, shellcode.size());
    if (!shellcodeMemory) {
        CloseHandle(hProcess);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // 写入shellcode
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, shellcodeMemory, shellcode.data(),
                           shellcode.size(), &bytesWritten)) {
        VirtualFreeEx(hProcess, shellcodeMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    std::cout << "Shellcode written to target process at: 0x" << std::hex << shellcodeMemory << std::dec << std::endl;

    // 修改线程上下文，将RIP指向shellcode
    CONTEXT newContext = originalContext;
#ifdef _WIN64
    newContext.Rip = reinterpret_cast<DWORD64>(shellcodeMemory);
#else
    newContext.Eip = reinterpret_cast<DWORD>(shellcodeMemory);
#endif

    // 设置新的线程上下文
    if (!SetThreadContext(threadId, newContext)) {
        std::cout << "Failed to set thread context" << std::endl;
        VirtualFreeEx(hProcess, shellcodeMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    std::cout << "Thread context modified successfully" << std::endl;

    // 恢复线程执行
    ResumeThread(hThread);

    // 清理资源
    CloseHandle(hProcess);
    CloseHandle(hThread);

    std::cout << "Thread hijacking completed" << std::endl;
    return true;
}

bool ThreadHijacker::RestoreThread(DWORD threadId, const CONTEXT& originalContext) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) {
        return false;
    }

    SuspendThread(hThread);
    bool result = SetThreadContext(threadId, originalContext);
    ResumeThread(hThread);

    CloseHandle(hThread);
    return result;
}

bool ThreadHijacker::GetThreadContext(DWORD threadId, CONTEXT& context) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
    if (!hThread) {
        return false;
    }

    context.ContextFlags = CONTEXT_FULL;
    bool result = ::GetThreadContext(hThread, &context);

    CloseHandle(hThread);
    return result;
}

bool ThreadHijacker::SetThreadContext(DWORD threadId, const CONTEXT& context) {
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
    if (!hThread) {
        return false;
    }

    bool result = ::SetThreadContext(hThread, &context);

    CloseHandle(hThread);
    return result;
}

LPVOID ThreadHijacker::AllocateMemoryInProcess(HANDLE hProcess, SIZE_T size) {
    return VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// 获取目标进程中的模块列表
std::vector<std::string> DllInjector::GetModuleList() {
    std::vector<std::string> moduleList;

    if (!m_targetProcess || m_targetProcessId == 0) {
        std::cout << "Error: No target process set" << std::endl;
        return moduleList;
    }

    // 创建模块快照
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_targetProcessId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cout << "Failed to create module snapshot. Error: " << error << std::endl;

        // 如果是权限问题，尝试只使用TH32CS_SNAPMODULE
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_targetProcessId);
        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cout << "Failed to create module snapshot (second attempt). Error: " << GetLastError() << std::endl;
            return moduleList;
        }
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    // 遍历模块列表
    if (Module32First(snapshot, &moduleEntry)) {
        do {
            // 将宽字符模块名转换为多字节字符串
            char moduleName[MAX_PATH];
            int result = WideCharToMultiByte(CP_UTF8, 0, moduleEntry.szModule, -1,
                                           moduleName, MAX_PATH, nullptr, nullptr);

            if (result > 0) {
                std::string moduleInfo = std::string(moduleName);

                // 添加模块路径信息（如果可用）
                char modulePath[MAX_PATH];
                result = WideCharToMultiByte(CP_UTF8, 0, moduleEntry.szExePath, -1,
                                           modulePath, MAX_PATH, nullptr, nullptr);

                if (result > 0) {
                    moduleInfo += " (" + std::string(modulePath) + ")";
                }

                // 添加基地址和大小信息
                moduleInfo += " [Base: 0x" + std::to_string(reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr)) +
                             ", Size: " + std::to_string(moduleEntry.modBaseSize) + "]";

                moduleList.push_back(moduleInfo);
            }
        } while (Module32Next(snapshot, &moduleEntry));
    } else {
        std::cout << "Failed to enumerate modules. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(snapshot);

    std::cout << "Found " << moduleList.size() << " modules in target process (PID: " << m_targetProcessId << ")" << std::endl;

    return moduleList;
}

// 获取远程进程中函数的地址
FARPROC DllInjector::GetRemoteProcAddress(HMODULE hModule, const std::string& procName) {
    if (!hModule || !m_targetProcess) {
        return nullptr;
    }

    // 在当前进程中获取同名模块
    HMODULE localModule = nullptr;

    // 首先尝试通过模块名获取本地模块句柄
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_targetProcessId);
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &moduleEntry)) {
            do {
                if (moduleEntry.hModule == hModule) {
                    // 将宽字符转换为多字节字符
                    char moduleName[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, moduleEntry.szModule, -1, moduleName, MAX_PATH, nullptr, nullptr);
                    localModule = GetModuleHandleA(moduleName);
                    break;
                }
            } while (Module32Next(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
    }

    if (!localModule) {
        std::cout << "Failed to find local module corresponding to remote module" << std::endl;
        return nullptr;
    }

    // 获取本地函数地址
    FARPROC localProcAddress = GetProcAddress(localModule, procName.c_str());
    if (!localProcAddress) {
        std::cout << "Failed to find function '" << procName << "' in local module" << std::endl;
        return nullptr;
    }

    // 计算偏移量
    DWORD_PTR localBase = reinterpret_cast<DWORD_PTR>(localModule);
    DWORD_PTR remoteBase = reinterpret_cast<DWORD_PTR>(hModule);
    DWORD_PTR offset = reinterpret_cast<DWORD_PTR>(localProcAddress) - localBase;

    // 返回远程地址
    FARPROC remoteProcAddress = reinterpret_cast<FARPROC>(remoteBase + offset);

    std::cout << "Function '" << procName << "' found at remote address: 0x"
              << std::hex << remoteProcAddress << std::dec << std::endl;

    return remoteProcAddress;
}
