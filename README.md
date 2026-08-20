<div align="center">

# stegseek-rs

**纯 Rust 实现的极速 steghide 破解器** —— [StegSeek](https://github.com/RickdeJager/stegseek) 0.6(steghide 0.5.1 的一个分支)的重写版

[![CI](https://github.com/adomore/stegseek-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/adomore/stegseek-rs/actions/workflows/ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/许可证-GPL%20v2%2B-blue.svg)](COPYING)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)
![无C依赖](https://img.shields.io/badge/C库依赖-无-brightgreen.svg)
![体积](https://img.shields.io/badge/二进制-823%20KB-informational.svg)

[English](README.en.md) | **简体中文**

</div>

---

对核心用途 —— **破解 (crack) 与提取 (extract)** —— 本移植版与原版 **功能等价**、**双向可互操作**,且 **比 C++ 原版快 1.2–1.5×**(经端到端差分实测,见 [BENCHMARK.md](BENCHMARK.md) 与 [AUDIT.md](AUDIT.md))。嵌入 (embed) 同样可互操作,只是在调色板/RGB 图像上失真略高(仅影响隐蔽性,**不影响正确性**)。

与原版不同(原版依赖 libmcrypt、libmhash、libjpeg、zlib),本移植 **零 C 库依赖** —— 全部纯 Rust,单个 **823 KB** 二进制,开箱即用。

## ✨ 亮点

| | |
|---|---|
| ⚡ **更快** | 每个线程数都比 C++ 原版快 **1.2–1.5×**;16 核 **66 M 口令/秒**,rockyou.txt 约 **0.2 秒**扫完 |
| 🔗 **可互操作** | 破解/提取与 steghide 0.6 **字节一致**,双向验证 |
| 📦 **零依赖** | 无需 libmcrypt/libmhash/libjpeg/zlib —— 纯 Rust,单文件 823 KB |
| 🔐 **全套加密** | **18 种密码 × 8 种 mcrypt 模式** + KEYGEN_MCRYPT,108 条 golden 向量校验 |
| 🖼️ **多格式** | BMP(调色板/RGB)、WAV(PCM8/16)、AU(PCM/µ-law)、JPEG(baseline + progressive) |
| 🕵️ **无密码检测** | `--seed` 暴力 RNG 种子检测/恢复(CVE-2021-27211) |
| 🛡️ **健壮** | 损坏/截断的 JPEG 返回干净错误(经 fuzz 加固),绝不 panic |
| 🧩 **steghide 兼容** | `--embed` / `--extract` / `--info` / `--encinfo` 命令与输出对齐 |

## ⚡ 性能

对 `none.jpg` 用 **rockyou 规模(14,344,391 条不命中口令)** 做最坏情况全量扫描,16 核机器,best-of-5:

| 线程 | stegseek-rs | C++ `-O2`(发行默认) | 加速比 |
|:---:|:---:|:---:|:---:|
| 1 | **5.14 M/s** | 4.15 M/s | **1.24×** |
| 2 | **10.43 M/s** | 8.27 M/s | **1.26×** |
| 16 | **66.0 M/s** | 45.4 M/s | **1.46×** |

> C++ 用 `-O3 -flto` 重编**并不会更快**(与 `-O2` 持平),所以公平基准就是发行版默认的 `-O2`。完整方法与数据见 [BENCHMARK.md](BENCHMARK.md)。

## 📦 安装 / 构建

```bash
cargo build --release        # 产物: target/release/stegseek-rs
cargo test --workspace
```

- 最低 Rust 版本:**1.75**。详见 [BUILD-rs.md](BUILD-rs.md)。
- Docker:`docker build -t stegseek-rs .`

## 🚀 用法

```bash
# 破解(默认命令)
stegseek-rs [stego.jpg] [wordlist.txt] [输出]
stegseek-rs --crack -sf stego.jpg -wl rockyou.txt -xf out.bin

# 无密码检测 / 恢复(CVE-2021-27211)
stegseek-rs --seed stego.jpg

# 提取 / 嵌入(与 steghide 兼容)
stegseek-rs --extract -sf stego.jpg -p 口令 -xf out
stegseek-rs --embed -cf cover.jpg -ef secret.txt -sf stego.jpg -p 口令

# 信息
stegseek-rs --info file.jpg     # 加 -p 口令 可显示内嵌文件信息
stegseek-rs --encinfo           # 列出支持的加密算法
```

常用参数:`-t` 线程数 · `-c/--continue` 命中后继续找多个内嵌文件 · `-q` 隐藏进度 · `-s` 跳过默认猜测 · `-f` 覆盖已存在文件。

## 🧱 项目结构

| Crate | 职责 |
|---|---|
| `crates/stegseek-core` | BitString、PRNG、选择器、EmbData、格式、破解器、嵌入 |
| `crates/stegseek-crypto` | libmcrypt/libmhash 兼容加密(18 密码、KEYGEN_MCRYPT) |
| `crates/stegseek-jpeg` | 纯 Rust JPEG DCT 解码(baseline+progressive)+ baseline 编码 |
| `crates/stegseek-cli` | `stegseek-rs` 可执行文件 |
| `xtask` | 热路径 + 端到端吞吐基准 |

## ✅ 测试与审计

- **86 项内建测试** + 针对现编 C++ stegseek 0.6 oracle 的**双向差分**,覆盖全部 18 密码 × 4 格式 × 明文/加密/压缩。
- JPEG 解码器有**确定性 fuzz** 覆盖(穷举替换 + 随机损坏),已把多处越界 panic 变为干净错误。
- 一份 [审计报告 AUDIT.md](AUDIT.md) 对活体 C++ oracle 复核了兼容性,并驱动了当前修复(损坏 JPEG 干净报错、`--info -p`、口令交互、`--continue`、实时进度、`-r/-g` 等)。

```bash
cargo test --workspace                          # 快速套件
cargo test -p stegseek-core -- --ignored        # 含慢速 seed 全扫描测试
STEGSEEK_REF=/path/to/stegseek cargo test       # 启用差分(需自建 C++ oracle,见 BENCHMARK.md)
cargo run -p xtask --release -- crack-bench      # 复现吞吐基准
```

## 📄 许可证与致谢

**GPL-2.0-or-later**,基于 steghide 0.5.1(Stefan Hetzl)与 stegseek 0.6(Rick de Jager)。许可证全文见 [COPYING](COPYING),兼容性说明见 [COMPATIBILITY.md](COMPATIBILITY.md)。

> ⚠️ 仅供授权的安全研究、CTF 与教育用途。请勿用于未经授权的目的。
