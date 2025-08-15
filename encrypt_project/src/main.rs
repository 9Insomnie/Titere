use std::{fs::{File, read_dir}, io::{Read, Write}, path::Path};
use std::env;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use clap::{App, Arg};

// 多态代码区域
fn dummy_func_1() { let mut v = Vec::new(); v.push(1); v.push(2); let _ = v.len(); }
fn dummy_func_2() { let s = "hello".to_string(); let _ = s.len(); }
fn dummy_func_3() { let v: Vec<u8> = (10..20).collect(); let _ = v.len(); }

fn encrypt_aes_gcm(data: &[u8], key_str: &str) -> Vec<u8> {
    // 使用SHA-256生成固定长度密钥
    let mut hasher = Sha256::new();
    hasher.update(key_str.as_bytes());
    let key_bytes = hasher.finalize();
    
    // 创建AES-GCM密钥和随机nonce
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    
    // 加密数据
    match cipher.encrypt(nonce, data) {
        Ok(ciphertext) => {
            // 将nonce附加到加密数据前面
            let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            result
        },
        Err(_) => {
            eprintln!("加密失败，回退到XOR加密");
            xor_encrypt(data, key_str.as_bytes())
        }
    }
}

fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn main() {
    let matches = App::new("Titere Encryptor")
        .version("2.0")
        .author("Titere Team")
        .about("加密工具 - 用于处理Shellcode文件")
        .arg(Arg::with_name("input")
            .short('i')
            .long("input")
            .value_name("FILE")
            .help("输入文件路径")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("输出文件路径")
            .takes_value(true)
            .default_value("output.bin"))
        .arg(Arg::with_name("key")
            .short('k')
            .long("key")
            .value_name("KEY")
            .help("加密密钥")
            .takes_value(true)
            .default_value("1A2B3C4D5E6F7A8B"))
        .arg(Arg::with_name("algorithm")
            .short('a')
            .long("algorithm")
            .value_name("ALGO")
            .help("加密算法: aes-gcm 或 xor")
            .takes_value(true)
            .default_value("aes-gcm"))
        .get_matches();
    
    // 获取输入文件
    let input_file = if let Some(input) = matches.value_of("input") {
        Path::new(input).to_path_buf()
    } else {
        // 自动扫描当前目录，查找第一个可用的.bin文件
        read_dir(".")
            .expect("无法读取当前目录")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file() && 
                p.extension().map(|ext| ext == "bin").unwrap_or(false) && 
                p.file_name().map(|n| n != "output.bin").unwrap_or(true)
            })
            .next()
            .expect("未找到可用的 .bin 文件")
    };
    
    println!("处理文件: {}", input_file.display());
    
    // 读取文件内容
    let mut f = File::open(&input_file).expect("无法打开输入文件");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("读取数据失败");
    
    // 获取加密参数
    let key = matches.value_of("key").unwrap();
    let algorithm = matches.value_of("algorithm").unwrap();
    let output_file = matches.value_of("output").unwrap();
    
    // 加密数据
    let processed = match algorithm {
        "aes-gcm" => encrypt_aes_gcm(&buffer, key),
        _ => xor_encrypt(&buffer, key.as_bytes())
    };
    
    // 写入输出文件
    let mut fout = File::create(output_file).expect("无法创建输出文件");
    fout.write_all(&processed).expect("写入输出文件失败");
    println!("处理完成，输出文件: {}", output_file);
    
    // 混淆代码
    dummy_func_1();
    dummy_func_2();
    dummy_func_3();
}