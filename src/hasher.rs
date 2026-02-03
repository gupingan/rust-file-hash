use crate::cli::HashAlgorithm;
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// 哈希计算结果
#[derive(Debug, Clone)]
pub struct HashResult {
    pub algorithm: HashAlgorithm,
    pub hash: Vec<u8>,
    pub hash_string: String,
}

/// 文件哈希计算器
pub struct FileHasher;

impl FileHasher {
    /// 使用内存映射计算文件哈希 - 高效处理大文件
    pub fn hash_file_mmap(path: &Path, algorithm: HashAlgorithm) -> Result<HashResult> {
        let file = File::open(path).with_context(|| format!("无法打开文件: {}", path.display()))?;

        let metadata = file
            .metadata()
            .with_context(|| format!("无法获取文件元数据: {}", path.display()))?;

        // 对于空文件或特殊文件，使用普通读取方式
        if metadata.len() == 0 {
            return Self::hash_empty_file(path, algorithm);
        }

        // 使用内存映射
        let mmap = unsafe {
            Mmap::map(&file).with_context(|| format!("无法内存映射文件: {}", path.display()))?
        };

        let hash = Self::hash_bytes(&mmap, algorithm);
        let hash_string = hex::encode(&hash);

        Ok(HashResult {
            algorithm,
            hash,
            hash_string,
        })
    }

    /// 流式计算哈希 - 适用于无法内存映射的文件
    pub fn hash_file_stream(path: &Path, algorithm: HashAlgorithm) -> Result<HashResult> {
        let file = File::open(path).with_context(|| format!("无法打开文件: {}", path.display()))?;

        let hash = Self::hash_reader(file, algorithm)?;
        let hash_string = hex::encode(&hash);

        Ok(HashResult {
            algorithm,
            hash,
            hash_string,
        })
    }

    /// 处理空文件
    fn hash_empty_file(_path: &Path, algorithm: HashAlgorithm) -> Result<HashResult> {
        let hash = Self::hash_bytes(&[], algorithm);
        let hash_string = hex::encode(&hash);

        Ok(HashResult {
            algorithm,
            hash,
            hash_string,
        })
    }

    /// 从字节数组计算哈希
    fn hash_bytes(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::Md5 => md5::compute(data).to_vec(),
            HashAlgorithm::Sha1 => {
                use sha1::Digest;
                let mut hasher = sha1::Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
        }
    }

    /// 从读取器计算哈希 (流式)
    fn hash_reader<R: Read>(mut reader: R, algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        const BUFFER_SIZE: usize = 64 * 1024; // 64KB 缓冲区
        let mut buffer = vec![0u8; BUFFER_SIZE];

        match algorithm {
            HashAlgorithm::Md5 => {
                let mut hasher = md5::Context::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.consume(&buffer[..n]);
                }
                Ok(hasher.compute().to_vec())
            }
            HashAlgorithm::Sha1 => {
                use sha1::Digest;
                let mut hasher = sha1::Sha1::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha256 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha512::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                Ok(hasher.finalize().as_bytes().to_vec())
            }
        }
    }

    /// 获取文件的多个哈希值
    pub fn hash_file_multiple(
        path: &Path,
        algorithms: &[HashAlgorithm],
        use_mmap: bool,
    ) -> Result<Vec<HashResult>> {
        let mut results = Vec::with_capacity(algorithms.len());

        if use_mmap {
            // 读取文件一次，计算所有哈希
            let file =
                File::open(path).with_context(|| format!("无法打开文件: {}", path.display()))?;

            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                for &algorithm in algorithms {
                    let hash = Self::hash_bytes(&mmap, algorithm);
                    results.push(HashResult {
                        algorithm,
                        hash_string: hex::encode(&hash),
                        hash,
                    });
                }
                return Ok(results);
            }
        }

        // 回退到流式处理
        for &algorithm in algorithms {
            results.push(Self::hash_file_stream(path, algorithm)?);
        }

        Ok(results)
    }
}

/// 进度报告回调
type ProgressCallback<'a> = Box<dyn Fn(u64) + 'a + Send>;

/// 带进度报告的哈希计算
pub struct ProgressHasher<'a> {
    callback: Option<ProgressCallback<'a>>,
}

impl<'a> ProgressHasher<'a> {
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(u64) + 'a + Send,
    {
        Self {
            callback: Some(Box::new(callback)),
        }
    }

    pub fn hash_file(&self, path: &Path, algorithm: HashAlgorithm) -> Result<HashResult> {
        let file = File::open(path).with_context(|| format!("无法打开文件: {}", path.display()))?;

        let metadata = file
            .metadata()
            .with_context(|| format!("无法获取文件元数据: {}", path.display()))?;

        if metadata.len() == 0 {
            return FileHasher::hash_empty_file(path, algorithm);
        }

        const BUFFER_SIZE: usize = 64 * 1024;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut processed = 0u64;

        let hash = match algorithm {
            HashAlgorithm::Md5 => {
                let mut hasher = md5::Context::new();
                loop {
                    let n = io::Read::read(&mut &file, &mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.consume(&buffer[..n]);
                    processed += n as u64;
                    if let Some(ref cb) = self.callback {
                        cb(processed);
                    }
                }
                hasher.compute().to_vec()
            }
            HashAlgorithm::Sha1 => {
                use sha1::Digest;
                let mut hasher = sha1::Sha1::new();
                loop {
                    let n = io::Read::read(&mut &file, &mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                    processed += n as u64;
                    if let Some(ref cb) = self.callback {
                        cb(processed);
                    }
                }
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                loop {
                    let n = io::Read::read(&mut &file, &mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                    processed += n as u64;
                    if let Some(ref cb) = self.callback {
                        cb(processed);
                    }
                }
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha512::new();
                loop {
                    let n = io::Read::read(&mut &file, &mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                    processed += n as u64;
                    if let Some(ref cb) = self.callback {
                        cb(processed);
                    }
                }
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                loop {
                    let n = io::Read::read(&mut &file, &mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                    processed += n as u64;
                    if let Some(ref cb) = self.callback {
                        cb(processed);
                    }
                }
                hasher.finalize().as_bytes().to_vec()
            }
        };

        Ok(HashResult {
            algorithm,
            hash_string: hex::encode(&hash),
            hash,
        })
    }
}

/// 获取文件大小（格式化）
pub fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    if size == 0 {
        return "0 B".to_string();
    }
    let exp = (size as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = size as f64 / 1024f64.powi(exp as i32);
    format!("{:.2} {}", value, UNITS[exp])
}

/// 计算传输速度
pub fn format_speed(bytes: u64, elapsed_secs: f64) -> String {
    if elapsed_secs <= 0.0 {
        return "N/A".to_string();
    }
    let speed = bytes as f64 / elapsed_secs;
    format!("{}/s", format_size(speed as u64))
}
