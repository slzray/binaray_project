/***********************************************************************************************
 * Copyright (c) 2025 二进制安全工具项目
 * Description: Windows平台x64内联Hook实现
 *              提供全面的内联Hook功能，支持短跳转(5字节)和长跳转(14字节)，
 *              自动Hook管理和安全的原始函数调用机制。
 * Author:      lunsha498@gmail.com
 * Date:        2025.07.07
 ***********************************************************************************************/

#pragma once
#include <Windows.h>
#include <vector>
#include <memory>
#include <stdexcept>

// x64架构下的inline hook实现
class InlineHook64 {
private:
    void* m_targetFunction;      // 目标函数地址
    void* m_hookFunction;        // hook函数地址
    std::vector<BYTE> m_originalBytes;  // 原始字节码
    bool m_isHooked;             // hook状态

    // x64跳转指令结构 (14字节)
    #pragma pack(push, 1)
    struct JumpInstruction64 {
        BYTE movRax[2];     // 48 B8 - mov rax, address
        UINT64 address;     // 8字节地址
        BYTE jmpRax[2];     // FF E0 - jmp rax
    };
    #pragma pack(pop)

    // 短跳转指令结构 (5字节)
    #pragma pack(push, 1)
    struct ShortJump {
        BYTE opcode;        // E9 - jmp
        DWORD offset;       // 相对偏移
    };
    #pragma pack(pop)

public:
    InlineHook64();
    ~InlineHook64();

    // 安装hook
    bool InstallHook(void* targetFunction, void* hookFunction);

    // 卸载hook
    bool UninstallHook();

    // 调用原始函数
    template<typename T, typename... Args>
    T CallOriginal(Args... args);

    // 获取hook状态
    bool IsHooked() const { return m_isHooked; }

    // 获取目标函数地址
    void* GetTargetFunction() const { return m_targetFunction; }

private:
    // 修改内存保护属性
    bool ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect);

    // 计算相对跳转偏移
    bool CanUseShortJump(void* from, void* to);

    // 创建跳转指令
    void CreateJumpInstruction(void* from, void* to, void* buffer);
};

// 模板实现
template<typename T, typename... Args>
T InlineHook64::CallOriginal(Args... args) {
    if (!m_isHooked || !m_targetFunction) {
        throw std::runtime_error("Hook not installed or invalid target function");
    }

    // 临时卸载hook
    UninstallHook();

    // 调用原始函数
    typedef T(*FunctionType)(Args...);
    FunctionType originalFunc = reinterpret_cast<FunctionType>(m_targetFunction);
    T result = originalFunc(args...);

    // 重新安装hook
    InstallHook(m_targetFunction, m_hookFunction);

    return result;
}