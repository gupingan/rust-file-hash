mod cli;
mod hasher;

use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use colored::Colorize;
use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cli::{Args, HashAlgorithm, OutputFormat};
use hasher::{format_size, format_speed, FileHasher, ProgressHasher};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// 处理结果
#[derive(Debug)]
struct FileResult {
    path: PathBuf,
    hashes: Vec<hasher::HashResult>,
    file_size: u64,
    elapsed: f64,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "错误:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    // 处理校验模式
    if let Some(check_file) = args.check.clone() {
        return verify_hashes(&check_file, &args);
    }

    // 收集所有文件
    let files = collect_files(&args.files, args.recursive)?;

    if files.is_empty() {
        println!("{} 未找到文件", "警告:".yellow().bold());
        return Ok(());
    }

    // 确定要使用的算法
    let algorithms = if args.algorithm.is_empty() {
        vec![HashAlgorithm::Sha256]
    } else {
        args.algorithm.clone()
    };

    // 计算总大小
    let total_size: u64 = files
        .iter()
        .filter_map(|p| fs::metadata(p).ok().map(|m| m.len()))
        .sum();

    if !args.quiet {
        print_header(&files, total_size, &algorithms);
    }

    // 处理文件
    let results = if files.len() == 1 {
        // 单个文件，使用流式处理带进度
        process_single_file(&files[0], &algorithms, &args)?
    } else {
        // 多个文件，使用并行处理
        process_multiple_files(&files, &algorithms, &args)?
    };

    // 输出结果
    if !args.quiet {
        println!();
        print_summary(&results, total_size);
    }

    // 导出校验文件
    if let Some(output_path) = args.output {
        export_checksum_file(&output_path, &results, &algorithms, &args.format)?;
    }

    Ok(())
}

/// 收集文件列表
fn collect_files(paths: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for path in paths {
        let path_str = path.to_string_lossy();
        
        // 检查是否包含通配符
        if path_str.contains('*') || path_str.contains('?') {
            // 处理通配符模式
            let mut matched = false;
            match glob(&path_str) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(entry_path) => {
                                if entry_path.is_file() {
                                    files.push(entry_path);
                                    matched = true;
                                }
                            }
                            Err(e) => {
                                eprintln!("{} 读取匹配项失败: {}", "警告:".yellow(), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} 无效的通配符模式 '{}': {}", "警告:".yellow(), path_str, e);
                }
            }
            
            if !matched {
                eprintln!("{} 没有文件匹配 '{}'", "警告:".yellow(), path_str);
            }
        } else if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            if recursive {
                collect_files_recursive(path, &mut files)?;
            } else {
                eprintln!(
                    "{} {} 是目录，使用 -r 递归处理",
                    "跳过:".yellow(),
                    path.display()
                );
            }
        } else {
            eprintln!("{} {} 不存在或无法访问", "警告:".yellow(), path.display());
        }
    }

    // 去重并排序
    files.sort();
    files.dedup();

    Ok(files)
}

/// 递归收集文件
fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("无法读取目录: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            collect_files_recursive(&path, files)?;
        }
    }
    Ok(())
}

/// 处理单个文件（带进度条）
fn process_single_file(
    path: &Path,
    algorithms: &[HashAlgorithm],
    args: &Args,
) -> Result<Vec<FileResult>> {
    let file_size = fs::metadata(path)?.len();
    let start = Instant::now();

    let hashes = if args.no_progress {
        // 无进度模式
        FileHasher::hash_file_multiple(path, algorithms, true)?
    } else {
        // 带进度条
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        let pb_clone = pb.clone();
        let hasher = ProgressHasher::new(move |processed| {
            pb_clone.set_position(processed);
        });

        let mut hashes = Vec::with_capacity(algorithms.len());
        for &alg in algorithms {
            hashes.push(hasher.hash_file(path, alg)?);
        }

        pb.finish_and_clear();
        hashes
    };

    let elapsed = start.elapsed().as_secs_f64();

    // 输出结果
    if !args.quiet {
        print_file_result(path, &hashes, file_size, elapsed, &args.format);
    } else {
        // 安静模式只输出哈希
        for hash in &hashes {
            println!("{}", args.format.format(&hash.hash));
        }
    }

    Ok(vec![FileResult {
        path: path.to_path_buf(),
        hashes,
        file_size,
        elapsed,
    }])
}

/// 并行处理多个文件
fn process_multiple_files(
    files: &[PathBuf],
    algorithms: &[HashAlgorithm],
    args: &Args,
) -> Result<Vec<FileResult>> {
    let processed_size = Arc::new(AtomicU64::new(0));
    let total_files = files.len();

    // 创建进度条
    let pb = if args.no_progress {
        None
    } else {
        let pb = ProgressBar::new(total_files as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} 文件 {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    };

    let results: Vec<FileResult> = files
        .par_iter()
        .enumerate()
        .filter_map(|(idx, path)| {
            let file_start = Instant::now();

            match FileHasher::hash_file_multiple(path, algorithms, true) {
                Ok(hashes) => {
                    let file_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    processed_size.fetch_add(file_size, Ordering::Relaxed);

                    if let Some(ref pb) = pb {
                        pb.set_position(idx as u64 + 1);
                        pb.set_message(format!(
                            "{}",
                            path.file_name().unwrap_or_default().to_string_lossy()
                        ));
                    }

                    if !args.quiet && args.no_progress {
                        print_file_result(
                            path,
                            &hashes,
                            file_size,
                            file_start.elapsed().as_secs_f64(),
                            &args.format,
                        );
                    }

                    Some(FileResult {
                        path: path.clone(),
                        hashes,
                        file_size,
                        elapsed: file_start.elapsed().as_secs_f64(),
                    })
                }
                Err(e) => {
                    eprintln!("{} {}: {}", "错误".red(), path.display(), e);
                    None
                }
            }
        })
        .collect();

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // 输出结果
    if !args.quiet && !args.no_progress {
        println!("\n{}", "处理结果:".bold());
        println!("{}", "─".repeat(80));
        for result in &results {
            print_file_result(
                &result.path,
                &result.hashes,
                result.file_size,
                result.elapsed,
                &args.format,
            );
        }
    }

    Ok(results)
}

/// 校验哈希值
fn verify_hashes(check_file: &Path, _args: &Args) -> Result<()> {
    println!("{} {}", "正在校验:".bold(), check_file.display());
    println!();

    // 获取校验文件所在目录作为基准路径
    let check_file_dir = check_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let file = File::open(check_file)
        .with_context(|| format!("无法打开校验文件: {}", check_file.display()))?;
    let reader = BufReader::new(file);

    let mut checks = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some((hash, filename)) = parse_hash_line(line) {
            checks.push((hash, PathBuf::from(filename)));
        }
    }

    if checks.is_empty() {
        anyhow::bail!("校验文件中没有找到有效的哈希条目");
    }

    println!("找到 {} 个校验项\n", checks.len());

    let mut passed = 0;
    let mut failed = 0;
    let mut missing = 0;

    for (expected_hash, filepath) in checks {
        // 尝试解析文件路径：
        // 1. 首先尝试相对于校验文件目录的路径
        // 2. 然后尝试相对于当前工作目录的路径
        // 3. 最后尝试直接使用路径
        let resolved_path = if filepath.is_absolute() {
            filepath.clone()
        } else {
            let relative_to_check = check_file_dir.join(&filepath);
            if relative_to_check.exists() {
                relative_to_check
            } else if filepath.exists() {
                filepath.clone()
            } else {
                relative_to_check // 返回这个路径用于错误显示
            }
        };

        if !resolved_path.exists() {
            println!("{} {} (文件不存在)", "⛔ 跳过".yellow(), filepath.display());
            missing += 1;
            continue;
        }

        // 检测哈希算法
        let algorithm = detect_algorithm(&expected_hash)?;

        match FileHasher::hash_file_mmap(&resolved_path, algorithm) {
            Ok(result) => {
                if result.hash_string.eq_ignore_ascii_case(&expected_hash) {
                    println!(
                        "{} {} ({})",
                        "✓ 通过".green(),
                        filepath.display(),
                        algorithm.name()
                    );
                    passed += 1;
                } else {
                    println!(
                        "{} {} ({})",
                        "✗ 失败".red(),
                        filepath.display(),
                        algorithm.name()
                    );
                    println!("  期望: {}", expected_hash.to_lowercase());
                    println!("  实际: {}", result.hash_string);
                    failed += 1;
                }
            }
            Err(e) => {
                println!("{} {}: {}", "✗ 错误".red(), filepath.display(), e);
                failed += 1;
            }
        }
    }

    println!();
    println!("{}", "校验完成".bold());
    println!("  通过: {}", passed.to_string().green());
    println!("  失败: {}", failed.to_string().red());
    if missing > 0 {
        println!("  缺失: {}", missing.to_string().yellow());
    }

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// 解析哈希行
fn parse_hash_line(line: &str) -> Option<(String, &str)> {
    // 格式1:: filename = HASH
    if let Some(pos) = line.find('=') {
        let (filename, hash) = line.split_at(pos);
        return Some((
            normalize_hash(hash.trim_matches(|c| c == ' ' || c == '=')),
            filename.trim(),
        ));
    }

    // 格式2: HASH *filename (标准md5sum格式)
    if let Some(pos) = line.find("  ") {
        let (hash, filename) = line.split_at(pos);
        return Some((normalize_hash(hash), filename.trim()));
    }

    // 格式3: HASH filename (单个空格)
    if let Some(pos) = line.find(' ') {
        let hash = &line[..pos];
        if hash.len() >= 32 && hash.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Some((normalize_hash(hash), line[pos..].trim()));
        }
    }

    None
}

/// 将哈希值标准化为小写 hex 格式（不带冒号）
fn normalize_hash(hash: &str) -> String {
    hash.replace(':', "").to_lowercase()
}

/// 根据哈希长度检测算法
fn detect_algorithm(hash: &str) -> Result<HashAlgorithm> {
    match hash.len() {
        32 => Ok(HashAlgorithm::Md5),
        40 => Ok(HashAlgorithm::Sha1),
        64 => Ok(HashAlgorithm::Sha256),
        128 => Ok(HashAlgorithm::Sha512),
        _ => anyhow::bail!("无法识别哈希算法 (长度: {})", hash.len()),
    }
}

/// 打印文件结果
fn print_file_result(
    path: &Path,
    hashes: &[hasher::HashResult],
    file_size: u64,
    elapsed: f64,
    format: &OutputFormat,
) {
    let filename = path.file_name().unwrap_or_default().to_string_lossy();

    println!("{}  {}", "文件:".bold(), filename.cyan());
    println!("{} {}", "路径:".bold(), path.display());
    println!("{} {}", "大小:".bold(), format_size(file_size).yellow());
    println!(
        "{} {}/s",
        "速度:".bold(),
        format_speed(file_size, elapsed).green()
    );

    for hash in hashes {
        let formatted = format.format(&hash.hash);
        println!(
            "{} {}: {}",
            "哈希:".bold(),
            hash.algorithm.name().magenta(),
            formatted.bright_white()
        );
    }
    println!("{}", "─".repeat(80));
}

/// 打印头部信息
fn print_header(files: &[PathBuf], total_size: u64, algorithms: &[HashAlgorithm]) {
    println!();
    println!(
        "Welcome to {} {}",
        NAME.cyan(),
        format!("v{}", VERSION).yellow()
    );
    println!();
    println!("{} {}", "文件数:".bold(), files.len().to_string().yellow());
    println!("{} {}", "总大小:".bold(), format_size(total_size).yellow());
    println!(
        "{} {}",
        "算法:".bold(),
        algorithms
            .iter()
            .map(|a| a.name().magenta().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
}

/// 导出校验文件
fn export_checksum_file(
    output_path: &Path,
    results: &[FileResult],
    algorithms: &[HashAlgorithm],
    format: &OutputFormat,
) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(output_path)
        .with_context(|| format!("无法创建校验文件: {}", output_path.display()))?;

    // 获取当前时间
    let datetime = Local::now().format("%Y年%m月%d日 %H:%M:%S").to_string();

    // 计算输出文件的父目录作为基准路径
    let base_dir: &Path = if output_path.is_absolute() {
        output_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    } else {
        // 对于相对路径，使用当前工作目录
        &std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf())
    };

    // 写入文件头注释
    writeln!(file, "# 文件哈希校验清单")?;
    writeln!(file, "# 生成时间: {}", datetime)?;
    writeln!(
        file,
        "# 算法: {}",
        algorithms
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(file, "# 格式: <哈希值>  <文件路径>")?;
    writeln!(file)?;

    // 辅助函数：获取相对路径
    let get_relative_path = |full_path: &Path| -> String {
        // 将文件路径转换为绝对路径
        let abs_path = if full_path.is_absolute() {
            full_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cd| cd.join(full_path))
                .unwrap_or_else(|_| full_path.to_path_buf())
        };

        // 规范化路径（统一使用正斜杠）
        let full_path_str = abs_path.to_string_lossy().replace('\\', "/");
        let base_dir_str = base_dir.to_string_lossy().replace('\\', "/");

        // 尝试剥离基准目录前缀
        if let Some(stripped) = full_path_str.strip_prefix(&base_dir_str) {
            let result = stripped.trim_start_matches('/');
            if !result.is_empty() {
                return result.to_string();
            }
        }

        // 尝试获取相对于当前工作目录的路径
        if let Ok(current_dir) = std::env::current_dir() {
            let current_dir_str = current_dir.to_string_lossy().replace('\\', "/");
            if let Some(stripped) = full_path_str.strip_prefix(&current_dir_str) {
                let result = stripped.trim_start_matches('/');
                if !result.is_empty() {
                    return result.to_string();
                }
            }
        }

        // 最后回退到文件名
        full_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    };

    // 如果只有一个算法，使用标准md5sum格式
    // 如果有多个算法，为每个算法创建一个section
    if algorithms.len() == 1 {
        // 标准格式: HASH  filepath
        for result in results {
            if let Some(hash_result) = result.hashes.first() {
                let filepath = get_relative_path(&result.path);
                let formatted_hash = format.format(&hash_result.hash);
                writeln!(file, "{}  {}", formatted_hash, filepath)?;
            }
        }
    } else {
        // 多算法格式，按算法分组
        for algorithm in algorithms {
            writeln!(file, "# {} 校验值", algorithm.name())?;
            for result in results {
                if let Some(hash_result) = result.hashes.iter().find(|h| h.algorithm == *algorithm)
                {
                    let filepath = get_relative_path(&result.path);
                    let formatted_hash = format.format(&hash_result.hash);
                    writeln!(file, "{}  {}", formatted_hash, filepath)?;
                }
            }
            writeln!(file)?;
        }
    }

    println!(
        "{} 校验文件已保存至: {}",
        "✓".green(),
        output_path.display().to_string().cyan()
    );
    println!(
        "  共导出 {} 个文件的校验值",
        results.len().to_string().yellow()
    );

    Ok(())
}

/// 打印摘要
fn print_summary(results: &[FileResult], total_size: u64) {
    let total_elapsed: f64 = results.iter().map(|r| r.elapsed).sum();
    let avg_speed = if total_elapsed > 0.0 {
        total_size as f64 / total_elapsed
    } else {
        0.0
    };

    println!("{}", "处理摘要".bold());
    println!("{}", "═".repeat(80));
    println!(
        "{} {}",
        "成功处理:".bold(),
        results.len().to_string().green()
    );
    println!("{} {}", "总大小:".bold(), format_size(total_size).yellow());
    println!("{} {:.2}秒", "总用时:".bold(), total_elapsed);
    println!(
        "{} {}/s",
        "平均速度:".bold(),
        format_size(avg_speed as u64).green()
    );
    println!();
}
