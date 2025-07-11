# SearchPattern 函数使用说明

## 概述

SearchPattern 是 MemoryTools 类中的核心内存搜索功能，提供了强大的字节模式搜索能力。本文档详细介绍了各种搜索函数的用法和示例。

## 主要搜索函数

### 1. SearchPattern - 基础模式搜索

```cpp
std::vector<SearchResult> SearchPattern(const std::vector<BYTE>& pattern, 
                                      const std::vector<BYTE>& mask = {},
                                      LPVOID startAddress = nullptr,
                                      SIZE_T searchSize = 0);
```

**参数说明：**
- `pattern`: 要搜索的字节模式
- `mask`: 搜索掩码（可选），0x00表示忽略该位置，0xFF表示精确匹配
- `startAddress`: 搜索起始地址（可选）
- `searchSize`: 搜索范围大小（可选）

**使用示例：**
```cpp
MemoryTools memTools(GetCurrentProcessId());

// 搜索特定字节序列
std::vector<BYTE> pattern = {0x48, 0x89, 0x5C, 0x24, 0x08}; // mov [rsp+8], rbx
auto results = memTools.SearchPattern(pattern);

// 带掩码搜索 - 搜索call指令但忽略具体地址
std::vector<BYTE> callPattern = {0xE8, 0x00, 0x00, 0x00, 0x00}; // call ????????
std::vector<BYTE> callMask = {0xFF, 0x00, 0x00, 0x00, 0x00};    // 只匹配第一个字节
auto callResults = memTools.SearchPattern(callPattern, callMask);
```

### 2. SearchPatternInCodeSection - 代码段搜索

```cpp
std::vector<SearchResult> SearchPatternInCodeSection(const std::vector<BYTE>& pattern,
                                                   const std::vector<BYTE>& mask = {},
                                                   const std::string& moduleName = "");
```

**功能：** 专门在可执行代码段中搜索，提高搜索效率和准确性。

**使用示例：**
```cpp
// 在所有代码段中搜索函数序言
auto results1 = memTools.SearchPatternInCodeSection({0x55, 0x48, 0x89, 0xE5}); // push rbp; mov rbp, rsp

// 在指定模块的代码段中搜索
auto results2 = memTools.SearchPatternInCodeSection({0x48, 0x83, 0xEC}, {}, "kernel32.dll");
```

### 3. SearchBytes - 便捷字节搜索

```cpp
std::vector<SearchResult> SearchBytes(const std::initializer_list<BYTE>& bytes,
                                    LPVOID startAddress = nullptr,
                                    SIZE_T searchSize = 0);
```

**功能：** 提供更简洁的字节序列搜索语法。

**使用示例：**
```cpp
// 直接使用初始化列表搜索
auto results = memTools.SearchBytes({0x48, 0x89, 0x5C, 0x24, 0x08});
```

### 4. SearchPatternString - 字符串模式搜索

```cpp
std::vector<SearchResult> SearchPatternString(const std::string& patternStr,
                                            LPVOID startAddress = nullptr,
                                            SIZE_T searchSize = 0);
```

**功能：** 支持使用字符串表示的十六进制模式，支持通配符。

**模式格式：**
- 十六进制字节：`"48 89 5C 24 08"`
- 通配符：`"48 89 ?? 24 ??"`（?? 或 ? 表示任意字节）

**使用示例：**
```cpp
// 搜索带通配符的模式
auto results1 = memTools.SearchPatternString("48 89 ?? 24 ??"); // mov [rsp+?], reg
auto results2 = memTools.SearchPatternString("E8 ?? ?? ?? ??"); // call ????????
auto results3 = memTools.SearchPatternString("FF 15 ?? ?? ?? ??"); // call [rip+????????]
```

## 搜索结果处理

### SearchResult 结构

```cpp
struct SearchResult {
    LPVOID address;           // 找到的地址
    std::vector<BYTE> data;   // 匹配的数据
    SIZE_T offset;            // 在内存区域中的偏移
};
```

### 结果处理示例

```cpp
auto results = memTools.SearchPattern(pattern);

for (const auto& result : results) {
    std::cout << "地址: 0x" << std::hex << result.address << std::endl;
    std::cout << "数据: ";
    for (BYTE b : result.data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    }
    std::cout << std::endl;
}
```

## 实用搜索模式

### 1. 常见x64指令模式

```cpp
// 函数序言
memTools.SearchPatternString("55 48 89 E5");           // push rbp; mov rbp, rsp
memTools.SearchPatternString("48 83 EC ??");           // sub rsp, ?
memTools.SearchPatternString("48 89 5C 24 ??");        // mov [rsp+?], rbx

// 函数调用
memTools.SearchPatternString("E8 ?? ?? ?? ??");        // call relative
memTools.SearchPatternString("FF 15 ?? ?? ?? ??");     // call [rip+offset]
memTools.SearchPatternString("FF D0");                 // call rax

// 跳转指令
memTools.SearchPatternString("EB ??");                 // jmp short
memTools.SearchPatternString("E9 ?? ?? ?? ??");        // jmp near
memTools.SearchPatternString("FF 25 ?? ?? ?? ??");     // jmp [rip+offset]
```

### 2. 系统调用模式

```cpp
// 系统调用
memTools.SearchPatternString("0F 05");                 // syscall
memTools.SearchPatternString("CD 2E");                 // int 2Eh (legacy)

// 异常处理
memTools.SearchPatternString("64 ?? ?? ?? ?? 00 00");  // fs:[offset]
```

### 3. 字符串和常量搜索

```cpp
// API名称搜索
std::string apiName = "GetProcAddress";
std::vector<BYTE> apiPattern(apiName.begin(), apiName.end());
auto apiResults = memTools.SearchPattern(apiPattern);

// Unicode字符串搜索
std::wstring wstr = L"kernel32.dll";
std::vector<BYTE> wstrPattern(reinterpret_cast<const BYTE*>(wstr.data()),
                             reinterpret_cast<const BYTE*>(wstr.data()) + wstr.size() * 2);
auto wstrResults = memTools.SearchPattern(wstrPattern);
```

## 性能优化建议

1. **限制搜索范围：** 使用 `startAddress` 和 `searchSize` 参数限制搜索范围
2. **使用代码段搜索：** 对于指令搜索，优先使用 `SearchPatternInCodeSection`
3. **合理使用掩码：** 使用掩码可以提高匹配的灵活性
4. **批量搜索：** 一次搜索多个相关模式比多次单独搜索更高效

## 注意事项

1. **权限要求：** 需要足够的进程访问权限，建议以管理员身份运行
2. **内存保护：** 只会搜索可读的内存区域
3. **大小限制：** 搜索大型进程时可能需要较长时间
4. **模式长度：** 过短的模式可能产生大量误报，建议使用至少4-8字节的模式

## 完整示例

参见 `Examples/SearchPatternExamples.cpp` 文件，包含了所有搜索功能的详细使用示例。
