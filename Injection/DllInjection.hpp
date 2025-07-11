/***********************************************************************************************
 * Copyright (c) 2025 二进制安全工具项目
 * Description: Windows平台DLL注入框架
 *              实现多种DLL注入技术，包括CreateRemoteThread、SetWindowsHookEx、
 *              手动DLL映射、线程劫持和进程挖空等技术。
 *              提供全面的进程操作和代码注入功能。
 * Author:      lunsha498@gmail.com
 * Date:        2025.07.07
 ***********************************************************************************************/

#pragma once
#include <Windows.h>
#include <string>
#include <vector>

// DLL注入方法枚举
enum class InjectionMethod {
    CREATE_REMOTE_THREAD,    // CreateRemoteThread + LoadLibrary
    SET_WINDOWS_HOOK,        // SetWindowsHookEx
    MANUAL_DLL_MAPPING,      // 手动DLL映射
    THREAD_HIJACKING,        // 线程劫持
    PROCESS_HOLLOWING        // 进程挖空
};

// DLL注入器类
class DllInjector {
private:
    DWORD m_targetProcessId;
    HANDLE m_targetProcess;
    std::string m_dllPath;

public:
    DllInjector();
    ~DllInjector();
    
    // 设置目标进程
    bool SetTargetProcess(DWORD processId);
    bool SetTargetProcess(const std::wstring& processName);
    
    // 注入DLL
    bool InjectDll(const std::string& dllPath, InjectionMethod method = InjectionMethod::CREATE_REMOTE_THREAD);
    
    // 卸载DLL
    bool EjectDll(const std::wstring& dllName);
    
    // 获取目标进程中的模块列表
    std::vector<std::string> GetModuleList();

private:
    // CreateRemoteThread方法注入
    bool InjectByCreateRemoteThread(const std::string& dllPath);
    
    // SetWindowsHookEx方法注入
    bool InjectBySetWindowsHook(const std::string& dllPath);
    
    // 手动DLL映射注入
    bool InjectByManualMapping(const std::string& dllPath);
    
    // 线程劫持注入
    bool InjectByThreadHijacking(const std::string& dllPath);
    
    // 进程挖空注入
    bool InjectByProcessHollowing(const std::string& dllPath);
    
    // 辅助函数
    DWORD GetProcessIdByName(const std::wstring& processName);
    HMODULE GetRemoteModuleHandle(const std::wstring& moduleName);
    FARPROC GetRemoteProcAddress(HMODULE hModule, const std::string& procName);
    bool EnableDebugPrivilege();
};

// 进程挖空器类
class ProcessHollower {
private:
    PROCESS_INFORMATION m_processInfo;
    std::string m_targetPath;
    std::string m_payloadPath;

public:
    ProcessHollower();
    ~ProcessHollower();
    
    // 执行进程挖空
    bool HollowProcess(const std::string& targetPath, const std::string& payloadPath);
    
    // 清理资源
    void Cleanup();

private:
    // 创建挂起的进程
    bool CreateSuspendedProcess(const std::string& path);
    
    // 卸载目标进程的映像
    bool UnmapTargetImage();
    
    // 分配新的内存空间
    bool AllocatePayloadMemory(SIZE_T imageSize);
    
    // 写入载荷数据
    bool WritePayloadToTarget(const std::vector<BYTE>& payloadData);
    
    // 修复重定位表
    bool FixRelocations(LPVOID baseAddress, LPVOID preferredBase);
    
    // 修复导入表
    bool FixImports(LPVOID baseAddress);
    
    // 设置入口点
    bool SetEntryPoint(LPVOID entryPoint);
};

// 线程劫持器类
class ThreadHijacker {
public:
    // 劫持线程执行shellcode
    static bool HijackThread(DWORD threadId, const std::vector<BYTE>& shellcode);
    
    // 恢复线程执行
    static bool RestoreThread(DWORD threadId, const CONTEXT& originalContext);
    
private:
    // 获取线程上下文
    static bool GetThreadContext(DWORD threadId, CONTEXT& context);
    
    // 设置线程上下文
    static bool SetThreadContext(DWORD threadId, const CONTEXT& context);
    
    // 在目标进程中分配内存
    static LPVOID AllocateMemoryInProcess(HANDLE hProcess, SIZE_T size);
};
