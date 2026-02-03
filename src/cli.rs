use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum HashAlgorithm {
    /// MD5 (128位) - 快速但不够安全
    Md5,
    /// SHA1 (160位) - 较快速
    Sha1,
    /// SHA256 (256位) - 推荐用于安全场景
    Sha256,
    /// SHA512 (512位) - 最高安全级别
    Sha512,
    /// BLAKE3 (256位) - 现代高性能哈希算法
    Blake3,
}

impl HashAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "MD5",
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha512 => "SHA512",
            HashAlgorithm::Blake3 => "BLAKE3",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "file-hash",
    version = "1.0.0",
    about = "高性能文件哈希计算器",
    long_about = r#"
高性能文件哈希计算器

支持特性:
  • 多种哈希算法 (MD5, SHA1, SHA256, SHA512, BLAKE3)
  • 内存映射技术处理大文件，内存占用极低
  • 并行处理多个文件
  • 实时进度显示
  • 导出/校验哈希清单

使用示例:
  file-hash file.iso                    # 默认SHA256
  file-hash -a blake3 file.iso          # 指定BLAKE3算法
  file-hash -a md5 -a sha256 *.exe      # 多算法同时计算
  file-hash -o checksum.txt file.iso    # 导出校验文件
  file-hash -r -o checksum.txt ./dir    # 递归导出目录校验
  file-hash -c checksum.txt file.iso    # 校验文件哈希
"#
)]
pub struct Args {
    /// 要计算哈希的文件路径
    #[arg(required_unless_present = "check")]
    pub files: Vec<PathBuf>,

    /// 哈希算法 (可多次指定)
    #[arg(short, long, value_enum, default_value = "sha256")]
    pub algorithm: Vec<HashAlgorithm>,

    /// 校验模式: 从文件读取哈希值进行验证
    #[arg(short, long, value_name = "HASH_FILE")]
    pub check: Option<PathBuf>,

    /// 递归处理目录
    #[arg(short, long)]
    pub recursive: bool,

    /// 不显示进度条
    #[arg(long)]
    pub no_progress: bool,

    /// 仅输出哈希值 (适合脚本使用)
    #[arg(short, long)]
    pub quiet: bool,

    /// 输出格式
    #[arg(short, long, default_value = "hex")]
    pub format: OutputFormat,

    /// 导出校验文件 (标准md5sum格式)
    #[arg(short, long, value_name = "OUTPUT_FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// 十六进制格式
    Hex,
    /// 大写十六进制
    UpperHex,
    /// 十六进制带冒号分隔
    HexWithColon,
}

impl OutputFormat {
    pub fn format(&self, hash: &[u8]) -> String {
        match self {
            OutputFormat::Hex => hex::encode(hash),
            OutputFormat::UpperHex => hex::encode_upper(hash),
            OutputFormat::HexWithColon => {
                hash.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":")
            }
        }
    }
}
