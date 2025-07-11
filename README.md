# Windows Binary Security Tools

这是一个Windows平台的二进制安全工具集，实现了多种常见的安全技术，包括API Hook、DLL注入、内存操作等功能。

## 功能特性

### 🎯 Hook技术
- **Inline Hook**: 支持x64架构的内联Hook，可以拦截任意函数调用
- **IAT Hook**: 导入地址表Hook，修改PE文件的导入表来拦截API调用
- **EAT Hook**: 导出地址表Hook，修改DLL的导出表
- **API Hook管理器**: 统一管理多种Hook类型

### 💉 注入技术
- **DLL注入**:
  - CreateRemoteThread + LoadLibrary方法
  - SetWindowsHookEx方法
  - 手动DLL映射
  - 线程劫持注入
- **进程挖空**: Process Hollowing技术实现
- **线程劫持**: Thread Hijacking技术

### 🧠 内存操作
- **内存读写**: 跨进程内存读写操作
- **模式搜索**: 支持字节模式和字符串搜索
- **内存扫描器**: 类似Cheat Engine的内存扫描功能
- **内存监视器**: 实时监控内存变化
- **内存补丁**: 运行时代码修改
- **模块枚举**: 获取进程加载的所有模块信息

## 项目结构

```
binaray_project/
├── Hook/                    # Hook相关功能
│   ├── InlineHook.hpp      # Inline Hook类定义
│   ├── InlineHook.cpp      # Inline Hook实现
│   ├── ApiHook.hpp         # API Hook类定义
│   └── ApiHook.cpp         # API Hook实现
├── Injection/              # 注入相关功能
│   ├── DllInjection.hpp    # DLL注入类定义
│   └── DllInjection.cpp    # DLL注入实现
├── Memory/                 # 内存操作功能
│   └── MemoryTools.hpp     # 内存工具类定义
├── Examples/               # 示例代码
│   ├── HookExamples.cpp    # Hook使用示例
│   ├── InjectionExamples.cpp # 注入使用示例
│   └── MemoryExamples.cpp  # 内存操作示例
├── binaray_project.cpp     # 主程序入口
├── binaray_project.vcxproj # Visual Studio项目文件
└── README.md              # 项目说明文档
```

## 编译要求

- **操作系统**: Windows 10/11
- **编译器**: Visual Studio 2019/2022 (MSVC v143)
- **架构**: x64 (推荐)
- **Windows SDK**: 10.0 或更高版本

## 编译步骤

1. 使用Visual Studio打开 `binaray_project.sln`
2. 选择Release或Debug配置
3. 选择x64平台
4. 点击"生成解决方案"

## 使用说明

### 基本使用

运行程序后会显示交互式菜单：

```
=== Windows Security Tools ===
1. Hook Examples (IAT Hook, Inline Hook)
2. Injection Examples (DLL Injection, Process Hollowing)
3. Memory Tools Examples (Memory Search, Patch)
4. Interactive Hook Demo
5. Interactive Injection Demo
0. Exit
```

### Hook示例

```cpp
#include "Hook/ApiHook.hpp"

// 创建Hook管理器
ApiHookManager hookManager;

// 安装MessageBoxA Hook
hookManager.InstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA", MyHookFunction);

// 卸载Hook
hookManager.UninstallHook(HookType::IAT_HOOK, "user32.dll", "MessageBoxA");
```

### DLL注入示例

```cpp
#include "Injection/DllInjection.hpp"

// 创建注入器
DllInjector injector;

// 设置目标进程
injector.SetTargetProcess("notepad.exe");

// 注入DLL
injector.InjectDll("C:\\path\\to\\your.dll", InjectionMethod::CREATE_REMOTE_THREAD);
```

### 内存操作示例

```cpp
#include "Memory/MemoryTools.hpp"

// 创建内存工具
MemoryTools memTools(processId);

// 读取内存
int value;
memTools.ReadValue(address, value);

// 写入内存
memTools.WriteValue(address, newValue);

// 搜索内存
auto results = memTools.SearchValue(&searchValue, sizeof(searchValue));
```

## 安全警告

⚠️ **重要提示**: 本工具仅用于教育和研究目的！

- 这些技术可能被反病毒软件检测为恶意行为
- 不要在生产环境或他人计算机上使用
- 使用前请确保了解相关法律法规
- 建议在虚拟机环境中进行测试

## 技术细节

### Hook技术原理

1. **Inline Hook**: 通过修改目标函数的前几个字节，插入跳转指令到Hook函数
2. **IAT Hook**: 修改PE文件的导入地址表，将API调用重定向到Hook函数
3. **EAT Hook**: 修改DLL的导出地址表，影响所有调用该API的进程

### 注入技术原理

1. **CreateRemoteThread**: 在目标进程中创建远程线程执行LoadLibrary
2. **SetWindowsHookEx**: 利用Windows消息Hook机制注入DLL
3. **Manual DLL Mapping**: 手动解析PE文件并映射到目标进程
4. **Process Hollowing**: 创建挂起进程，替换其内存映像

## 常见问题

### Q: 编译时出现链接错误？
A: 确保项目配置为x64平台，并且包含了所有必要的源文件。

### Q: Hook不生效？
A: 检查目标函数是否正确，确保有足够的权限，某些系统API可能受到保护。

### Q: 注入失败？
A: 确保以管理员权限运行，目标进程存在且可访问。

### Q: 被杀毒软件拦截？
A: 这是正常现象，可以添加到白名单或在虚拟机中测试。

## 贡献指南

欢迎提交Issue和Pull Request！

1. Fork本项目
2. 创建功能分支
3. 提交更改
4. 发起Pull Request

## 许可证

本项目仅供学习和研究使用，请遵守当地法律法规。

## 免责声明

本工具仅用于教育目的，开发者不对任何滥用行为承担责任。使用者应当遵守相关法律法规，不得将本工具用于非法用途。
