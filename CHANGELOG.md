# Changelog

本项目所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/),
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> *本文档仅有中文版,暂无英文镜像;GitHub Release 说明由本文件自动抽取,因此发布页同样是中文。
> This changelog is Chinese-only; the GitHub Release notes are generated from it.*

## [Unreleased]

## [1.1.0] - 2026-08-31

维护版本:修复从干净 clone 构建失败的问题,订正文档中的过时事实,并为中英 README 建立结构对齐门禁。二进制行为完全不变 —— 破解、提取、嵌入的结果、命令行接口与退出码均与 1.0.0 一致。

### 修复 (Fixed)
- **`--locked` 构建从干净 clone 失败**:`Cargo.lock` 此前被 `.gitignore` 排除,导致 `Dockerfile` 与两份 README 都推荐的 `cargo build --release --locked` 与 `docker build` 在新克隆的仓库上直接报错。锁文件现已入库,CI 与 release workflow 的 cargo 步骤统一加 `--locked` —— 分发的五个平台二进制与 CI 验证的是同一份依赖树,依赖漂移会在 CI 暴露,而不是等到 `docker build` 时才发现。

### 变更 (Changed)
- **CI 新增 `docs` 作业**:`scripts/lockstep.py` 强制 `README.md` 与 `README.en.md` 结构等价(标题层级序列、代码块数量、表格行数、行内代码字面量集合),只改一份即 CI 红。
- **英文 README 补齐**:此前退化为摘要 —— 缺三张数据表、测试命令、参数速查、`COPYING` 链接与授权使用警告,章节顺序也与中文版不同;现已逐节对齐。两份 README 同时新增预编译二进制的下载说明,以及各文档的语言标注。
- **文档事实订正**:二进制体积 823 KB 改为 **873 KB**(strip 后 744 KB,共 6 处)、测试数 61 改为 **86**、`--version` 横幅描述与代码对齐、`BUILD-rs.md` 中失效的产物路径与差分测试命令、CHANGELOG 中指向已删除标签的悬空链接。

### 移除 (Removed)
- **`libjpeg` cargo feature**:该 feature 未 gate 任何代码,连同 `BUILD-rs.md` 中列出的 `libjpeg8-dev` 前置依赖一并删除。
- 三个不含任何测试的空测试文件(`dbg.rs`、`dbg2.rs`、`distortion.rs`);CI 此前为每个多链接一个测试二进制。

## [1.0.0] - 2026-08-20

首个稳定版。经完整审计、双向差分校验与 fuzz 健壮性加固后正式定为 1.0。

### 变更 (Changed)
- **二进制改名**:产物 / 安装 / 命令名由 `stegseek` 统一为 **`stegseek-rs`**(deb 包、Docker `ENTRYPOINT`、GitHub Release 资产名同步更新),避免与上游 steghide / stegseek 命令冲突。
- 版本号升至 **1.0.0**。
- **`--version` 横幅改为自报身份**:`stegseek-rs <version> - https://github.com/adomore/stegseek-rs`(加 `-v` 追加一行 `based on steghide 0.5.1, compatible with stegseek 0.6`),不再镜像上游的 `StegSeek 0.6 - …`。这是刻意的偏离,只影响这一行身份标识;逐条结果输出(`[i] Found passphrase`、`Original filename`、`Extracting to`、`[i]`/`[w]`/`[e]` 前缀)与退出码不变,解析结果行的脚本不受影响。详见 [`COMPATIBILITY.md`](COMPATIBILITY.md)。

### 说明 (Notes)
- 功能、格式、加密、性能均与 0.6.0 一致(见下);1.0.0 是在通过双向差分、86 项内建测试与 JPEG 解码器 fuzz 加固之后,对成熟度与稳定性的正式标记。

## [0.6.0] - 2026-08-20

首个发布 —— 纯 Rust 实现的极速 steghide 破解器,对标 stegseek 0.6 / steghide 0.5.1。

> 说明:0.6.0 未单独打标签发布,其内容随 `v1.0.0` 一并发出;此节保留为变更记录。

### 新增 (Added)
- **破解 / 提取**:与 steghide 0.6 **双向互操作、字节一致**(破解结果、提取内容)。
- **加密**:18 种密码 × 8 种 mcrypt 模式 + KEYGEN_MCRYPT,108 条 golden 向量校验。
- **格式**:BMP(调色板/RGB)、WAV(PCM8/16)、AU(PCM/µ-law)、JPEG(baseline + progressive)。
- **`--seed`**:无密码检测/恢复(CVE-2021-27211)。
- **steghide 兼容命令**:`--embed` / `--extract` / `--info`(`-p` 显示内嵌信息)/ `--encinfo`。
- **CLI**:`--continue` 多文件恢复、实时进度指标(`-q` 隐藏)、`-r/--radius` 与 `-g/--goal`、缺 `-p` 时交互提示口令。
- **性能**:每个线程数都比 C++ 原版快 **1.2–1.5×**(16 核 66 M 口令/秒,rockyou.txt ~0.2 s);零 C 库依赖,873 KB 二进制(strip 后 744 KB)。
- **测试**:86 项内建测试 + 针对现编 C++ oracle 的双向差分;JPEG 解码器确定性 fuzz 覆盖。

### 特性 (Notes)
- **无 C 依赖**:不再需要 libmcrypt / libmhash / libjpeg / zlib —— 全部纯 Rust。
- **健壮**:损坏/截断的 JPEG 返回干净错误,绝不 panic(fuzz 加固,含 DC 幅度类别、Huffman 表、谱选择等多处越界防护)。

### 已知差异 (Known differences)
- 嵌入 (embed) 可互操作,但在调色板/RGB 图像上失真约 **1.34×**(仅影响隐蔽性,不影响正确性);音频/JPEG 持平。
- 算术编码/无损 JPEG 明确拒绝(不解码);部分 steghide CLI 细节(stdin/stdout `-`、逐命令参数校验等)未完全对齐。详见 [`COMPATIBILITY.md`](COMPATIBILITY.md) 与 [`AUDIT.md`](AUDIT.md)。

### 许可证 (License)
GPL-2.0-or-later,基于 steghide 0.5.1(Stefan Hetzl)与 stegseek 0.6(Rick de Jager)。

[Unreleased]: https://github.com/adomore/stegseek-rs/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/adomore/stegseek-rs/releases/tag/v1.1.0
[1.0.0]: https://github.com/adomore/stegseek-rs/releases/tag/v1.0.0
