#include "InlineHook.hpp"
#include <iostream>

InlineHook64::InlineHook64() 
    : m_targetFunction(nullptr)
    , m_hookFunction(nullptr)
    , m_isHooked(false) {
}

InlineHook64::~InlineHook64() {
    if (m_isHooked) {
        UninstallHook();
    }
}

bool InlineHook64::InstallHook(void* targetFunction, void* hookFunction) {
    if (!targetFunction || !hookFunction) {
        return false;
    }
    
    if (m_isHooked) {
        return false; // 已经安装了hook
    }
    
    m_targetFunction = targetFunction;
    m_hookFunction = hookFunction;
    
    // 保存原始字节码
    size_t hookSize = sizeof(JumpInstruction64);
    if (CanUseShortJump(targetFunction, hookFunction)) {
        hookSize = sizeof(ShortJump);
    }
    
    m_originalBytes.resize(hookSize);
    memcpy(m_originalBytes.data(), targetFunction, hookSize);
    
    // 修改内存保护属性
    DWORD oldProtect;
    if (!ChangeMemoryProtection(targetFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // 创建跳转指令
    std::vector<BYTE> jumpBytes(hookSize);
    CreateJumpInstruction(targetFunction, hookFunction, jumpBytes.data());
    
    // 写入跳转指令
    memcpy(targetFunction, jumpBytes.data(), hookSize);
    
    // 恢复内存保护属性
    DWORD temp;
    ChangeMemoryProtection(targetFunction, hookSize, oldProtect, &temp);
    
    m_isHooked = true;
    return true;
}

bool InlineHook64::UninstallHook() {
    if (!m_isHooked || !m_targetFunction) {
        return false;
    }
    
    // 修改内存保护属性
    DWORD oldProtect;
    size_t hookSize = m_originalBytes.size();
    if (!ChangeMemoryProtection(m_targetFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // 恢复原始字节码
    memcpy(m_targetFunction, m_originalBytes.data(), hookSize);
    
    // 恢复内存保护属性
    DWORD temp;
    ChangeMemoryProtection(m_targetFunction, hookSize, oldProtect, &temp);
    
    m_isHooked = false;
    return true;
}

bool InlineHook64::ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtect(address, size, newProtect, oldProtect) != 0;
}

bool InlineHook64::CanUseShortJump(void* from, void* to) {
    INT64 distance = reinterpret_cast<INT64>(to) - reinterpret_cast<INT64>(from) - sizeof(ShortJump);
    return (distance >= INT32_MIN && distance <= INT32_MAX);
}

void InlineHook64::CreateJumpInstruction(void* from, void* to, void* buffer) {
    if (CanUseShortJump(from, to)) {
        // 使用短跳转 (5字节)
        ShortJump* jump = reinterpret_cast<ShortJump*>(buffer);
        jump->opcode = 0xE9;
        jump->offset = static_cast<DWORD>(
            reinterpret_cast<INT64>(to) - reinterpret_cast<INT64>(from) - sizeof(ShortJump)
        );
    } else {
        // 使用长跳转 (14字节)
        JumpInstruction64* jump = reinterpret_cast<JumpInstruction64*>(buffer);
        jump->movRax[0] = 0x48;  // REX.W prefix
        jump->movRax[1] = 0xB8;  // MOV RAX, imm64
        jump->address = reinterpret_cast<UINT64>(to);
        jump->jmpRax[0] = 0xFF;  // JMP r/m64
        jump->jmpRax[1] = 0xE0;  // ModR/M byte for RAX
    }
}

// 注意：模板实现已移动到头文件中
