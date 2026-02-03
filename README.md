# rfhash-cli

使用 Rust 编写的文件哈希计算器，支持多种哈希算法、内存映射技术处理大文件、并行处理和实时进度显示。

## 特性

- **多种哈希算法**：支持 MD5、SHA1、SHA256、SHA512、BLAKE3
- **高性能**：使用内存映射技术处理大文件，内存占用极低
- **并行处理**：支持同时处理多个文件，充分利用多核 CPU
- **实时进度**：显示进度条和处理速度
- **灵活输出**：支持多种哈希格式（hex、大写 hex、带冒号分隔）
- **校验功能**：支持导出和校验哈希清单（兼容 md5sum 格式）
- **递归处理**：支持递归处理目录中的所有文件
- **通配符支持**：支持 `*` 和 `?` 通配符匹配文件

## 安装

### 从源码编译

```bash
git clone https://github.com/gupingan/rust-rfhash.git
cd rust-rfhash
cargo build --release
```

编译后的可执行文件位于 `target/release/rfhash.exe`（Windows）或 `target/release/rfhash`（Linux/macOS）。

### 使用 Cargo 安装

```bash
cargo install --path .
```

## 使用方法

### 基本用法

计算单个文件的哈希值（默认使用 SHA256）：

```bash
rfhash file.iso
```

指定哈希算法：

```bash
rfhash -a md5 file.iso
rfhash -a blake3 file.iso
```

同时计算多个算法的哈希值：

```bash
rfhash -a md5 -a sha256 -a sha512 file.iso
```

### 处理多个文件

```bash
rfhash *.exe
rfhash file1.txt file2.txt file3.txt
```

#### 通配符支持

支持使用 `*` 和 `?` 通配符来匹配文件：

```bash
# 匹配所有 .rs 文件
rfhash src/*.rs

# 匹配所有 .toml 和 .md 文件
rfhash *.toml *.md

# 匹配特定模式的文件
rfhash test_*.txt
```

通配符模式说明：
- `*`：匹配任意数量的任意字符
- `?`：匹配单个任意字符

### 递归处理目录

```bash
rfhash -r ./data
rfhash -r -o checksum.txt ./data
```

### 输出格式

支持三种输出格式：

- `hex`：小写十六进制（默认）- `2a94011e58aa0170ee1972235d81bc0bfe78423159815bfdc1a453431c269312`
- `upper-hex`：大写十六进制 - `2A94011E58AA0170EE1972235D81BC0BFE78423159815BFDC1A453431C269312`
- `hex-with-colon`：带冒号分隔 - `2a:94:01:1e:58:aa:01:70:ee:19:72:23:5d:81:bc:0b:fe:78:42:31:59:81:5b:fd:c1:a4:53:43:1c:26:93:12`

```bash
rfhash -f hex file.iso
rfhash -f upper-hex file.iso
rfhash -f hex-with-colon file.iso
```

### 导出校验文件

```bash
rfhash -o checksum.txt file.iso
rfhash -f hex-with-colon -o checksum.txt file.iso
```

导出的校验文件格式：

```
# 文件哈希校验清单
# 生成时间: 2026年2月17日 08:07:08
# 算法: SHA256
# 格式: <哈希值>  <文件路径>

2a94011e58aa0170ee1972235d81bc0bfe78423159815bfdc1a453431c269312  file.iso
```

### 校验文件

校验文件的哈希值：

```bash
rfhash -c checksum.txt file.iso
```

校验时会自动识别哈希格式（包括带冒号的格式），并统一转换为 hex 进行比较。

### 安静模式

仅输出哈希值，适合脚本使用：

```bash
rfhash -q file.iso
rfhash -q -f hex-with-colon file.iso
```

### 禁用进度条

```bash
rfhash --no-progress file.iso
```

## 命令行选项

| 选项 | 说明 |
|------|------|
| `-a, --algorithm <ALGORITHM>` | 哈希算法（可多次指定）<br>可选值：`md5`、`sha1`、`sha256`（默认）、`sha512`、`blake3` |
| `-c, --check <HASH_FILE>` | 校验模式：从文件读取哈希值进行验证 |
| `-r, --recursive` | 递归处理目录 |
| `--no-progress` | 不显示进度条 |
| `-q, --quiet` | 仅输出哈希值（适合脚本使用） |
| `-f, --format <FORMAT>` | 输出格式<br>可选值：`hex`（默认）、`upper-hex`、`hex-with-colon` |
| `-o, --output <OUTPUT_FILE>` | 导出校验文件 |
| `-h, --help` | 显示帮助信息 |
| `-V, --version` | 显示版本信息 |

## 使用示例

### 示例 1：计算 ISO 文件的哈希值

```bash
rfhash ubuntu-22.04.iso
```

输出：

```
Welcome to rfhash v1.0.0

文件数: 1
总大小: 3.59 GB
算法: SHA256

文件:  ubuntu-22.04.iso
路径: ubuntu-22.04.iso
大小: 3.59 GB
速度: 1.23 GB/s
哈希: SHA256: 2a94011e58aa0170ee1972235d81bc0bfe78423159815bfdc1a453431c269312
────────────────────────────────────────────────────────────────────────────────

处理摘要
════════════════════════════════════════════════════════════════════════════════
成功处理: 1
总大小: 3.59 GB
总用时: 2.92秒
平均速度: 1.23 GB/s
```

### 示例 2：多算法计算

```bash
rfhash -a md5 -a sha256 -a blake3 file.iso
```

### 示例 3：导出目录校验清单

```bash
rfhash -r -o checksums.txt ./downloads
```

### 示例 4：校验下载的文件

```bash
# 先下载校验文件
wget https://example.com/checksums.txt

# 校验文件
rfhash -c checksums.txt ubuntu-22.04.iso
```

### 示例 5：在脚本中使用

```bash
# 获取文件的 SHA256 哈希值
HASH=$(rfhash -q file.iso)
echo "SHA256: $HASH"

# 获取带冒号格式的哈希值
HASH=$(rfhash -q -f hex-with-colon file.iso)
echo "MAC format: $HASH"
```

## 性能特点

- **内存映射**：使用 `memmap2` 库，大文件处理时内存占用极低
- **并行处理**：使用 `rayon` 库，多文件处理时充分利用多核 CPU
- **高效哈希**：使用优化的哈希算法实现（md5、sha1、sha2、blake3）

## 许可证

[MIT License](LICENSE)
