# Windows Binary Security Tools

这是一个Windows平台的二进制安全工具集，实现了多种常见的安全技术，包括API Hook、DLL注入、内存操作等功能。

## 功能特性

###  Hook技术
- **Inline Hook**: 支持x64架构的内联Hook，可以拦截任意函数调用
- **IAT Hook**: 导入地址表Hook，修改PE文件的导入表来拦截API调用
- **EAT Hook**: 导出地址表Hook，修改DLL的导出表
- **API Hook管理器**: 统一管理多种Hook类型

###  注入技术
- **DLL注入**:
  - CreateRemoteThread + LoadLibrary方法
  - SetWindowsHookEx方法
  - 手动DLL映射
  - 线程劫持注入
- **进程挖空**: Process Hollowing技术实现
- **线程劫持**: Thread Hijacking技术

###  内存操作
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

## 许可证

本项目仅供学习和研究使用，请遵守当地法律法规。

## 免责声明

本工具仅用于教育目的，开发者不对任何滥用行为承担责任。使用者应当遵守相关法律法规，不得将本工具用于非法用途。
