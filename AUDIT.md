# stegseek-rs 全面审计报告 · Full Audit Report

**审计日期 / Date:** 2026-08-18
**方法 / Method:** 逐子系统源码对比（Rust ↔ C++）+ 针对真实 C++ oracle 的端到端差分实测
Subsystem-by-subsystem source comparison (Rust ↔ C++) **plus** end-to-end differential testing against a freshly-built C++ `stegseek` 0.6 oracle.
**被审对象 / Subject:** `stegseek-rs` (workspace @ `crates/`, v0.6.0)
**参照 / Reference:** `stegseek` 0.6 (fork of `steghide` 0.5.1), source in `stegseek-master.zip`, built from `src/` and linked against the system `libmcrypt 2.5.8-8+b2`, `libmhash 0.9.9.9`, `libjpeg-turbo 3.x`.

---

## 摘要 / Executive summary

stegseek-rs 是对 stegseek 0.6 的**纯 Rust 重写**，无任何 C 库依赖。本次审计在 16 核 Kali 机器上，用同一台机器现编译的 C++ `stegseek` 0.6 作为 oracle，做了**双向端到端实测**（这正是重写项目自身文档一直缺失的验证）。结论分三档：

| 能力 | 结论 | 证据 |
|------|------|------|
| **破解 Cracking** | ✅ 忠实且**比 C++ 快 1.24–1.46×** | 18/18 密码、破解结果字节一致、61/61 测试通过 |
| **提取 Extraction** | ✅ 近乎完整、字节一致 | 全部 4 格式 × 全部变体双向 round-trip |
| **嵌入 Embedding** | ⚠️ 可互操作但**失真更高**（仅影响隐蔽性，不影响正确性） | 24-bit BMP 失真 1.34×；音频/JPEG 持平 |

**一句话：** 对"破解 + 提取"这一核心用途，重写是高保真且更快的；对"嵌入"，产物始终是合法可提取的 steghide 0.6 文件，但抗隐写分析的质量弱于原版。CLI/管道外围有多处偏差。

**One line:** For its headline purpose — cracking and extraction — the port is high-fidelity and **faster** than the C++ original. Embedding is interoperable but lower-fidelity (imperceptibility only). The CLI/pipeline surface diverges in several places.

> **审计过程中纠正了一处多智能体审计的误判**：关于 `safer-sk64/safer-sk128/threeway/panama` 四个密码"缺失导致高危兼容性破坏"的说法，经对真实 libmcrypt 二进制核验后**不成立**——这些模块在该 libmcrypt 构建中本就不存在，参照版 steghide 同样拒绝它们，故 stegseek-rs 的行为与 oracle **一致**。（源码阅读会误导，二进制实测才是准绳。）

---

## 0. 已修复项 / Fixes applied (2026-08-18)

审计后按用户要求修复了 JPEG panic 与全部已确认的 CLI/功能差距。全部改动均**已对 C++ oracle 实测验证**，且未破坏互操作性（差分测试 2+7+10 全过、单元测试 **61/61**、双向 embed/extract 仍字节一致）。

| # | 修复项 | 状态 | 验证 |
|:--:|--------|:----:|------|
| F1 | JPEG 解码器截断/损坏输入 **panic → 干净报错** | ✅ 已修 | 全部截断点不再 panic，返回 `truncated jpeg`；`decoder.rs` parse() 全部改为边界检查读取 + SOF 尺寸/分量校验 |
| F5 | 算术编码/无损/差分 JPEG **明确拒绝**（非 `no frame`）| ✅ 已修 | SOF9/10/11 等 marker 返回 `unsupported: arithmetic-coded…`；12-bit 精度也明确拒绝 |
| F9 | `--info -p` **读取并显示内嵌数据信息** | ✅ 已修 | 输出与 oracle **逐字节一致**（name/size/encrypted/compressed）|
| F8 | 缺 `-p` **交互提示口令**（echo-off，embed 二次确认）；非 TTY 时报错 | ✅ 已修 | 不再静默用空口令；显式 `-p ""` 仍按空口令处理 |
| F10 | `--extract` 默认输出名 = **内嵌原始文件名**（无名且无 `-xf` 时报错）| ✅ 已修 | 写出 `secret.txt`（原为 `<stego>.out`），与 steghide 一致 |
| F4 | `-c/--continue` **接线生效**：命中后继续扫描，多结果写 `.out`/`.out.1`/… | ✅ 已修 | 实测：含两个 `Sesame` 的表，无 `-c` 得 1 个结果、`-c` 得 2 个文件 |
| F11 | **实时进度指标**（`Progress: X.XX% (…)`），`-q` 正确隐藏 | ✅ 已修 | 格式匹配 steghide；`-q` 热路径零开销（不影响破解吞吐）|
| F6 | `-r/--radius`、`-g/--goal` **被接受**（radius 实际生效于嵌入；goal=0 关闭优化器）| ✅ 已修 | 不再 `unknown argument`；`-z` 也加了 1..9 范围校验 |
| — | seed 破解 **测试到 `0xFFFFFFFF`**（原 `seed < end` 漏测最后一个 seed）| ✅ 已修 | 末分片改为 inclusive 上界 |

**仍作为已知差异保留**（本次未改，属深度/低价值项）：完整的算术编码 JPEG **解码**（工程量大、格式罕见——现为干净拒绝）；图匹配失真优化器逼近 DFSAP（纯隐蔽性，§7）；stdin/stdout `-` 约定；逐命令参数/重复旗标校验；`--help -v` steghide 帮助块；argv 口令抹除；含 NUL 口令的密钥派生分歧。详见 §5 与 `COMPATIBILITY.md`。

### 测试覆盖 / Test coverage added

为固化上述修复，新增 **25 个测试**（套件 61 → **86**，全过）：

- `crates/stegseek-jpeg/tests/robustness.rs`（7）：有效 JPEG 回归、逐前缀截断不 panic、**确定性 fuzz**（穷举单字节替换 + LCG 多字节损坏 + 随机截断）、算术/无损/差分/12-bit/超大尺寸拒绝、垃圾输入。
- `crates/stegseek-core/tests/crackers.rs`（6）：无 `-c` 恒 1 结果（重复口令 × 多线程的去重守卫回归）、`-c` 得全部命中、无命中为空、skip-default、进度计数、seed 破解找到 `0x58c8cc6c`。
- `crates/stegseek-cli/tests/cli.rs`（12，端到端跑真实二进制）：`--info -p`、`--extract` 默认名、缺 `-p` 报错、`-r/-g` round-trip、`-z` 越界、未知参数、`--continue` 多文件、`-q` 进度开关、截断/算术 JPEG、退出码。

> **fuzz 覆盖额外揪出并修复了 5 个更深的解码器 panic**（原 F1 只修了头部 marker 读取）：DHT 码数溢出 `huffcode[k]`、scan 块索引越界、Huffman 表选择子 `td/ta≥4`、谱选择 `Se>63` 越界 `NATURAL_ORDER[k]`、Huffman 值索引越界 `t.values[idx]`、空扫描 `sc[0]`。全部改为返回 `JpegError`。**这正是"完成功能测试覆盖"的价值——测试驱动出了仅靠代码审查未发现的健壮性缺陷。**

**性能测试**：新增可从仓库直接复现的端到端吞吐基准 `cargo run -p xtask --release -- crack-bench`（最坏情况全量扫描，多线程,内置生成词表,无需外部文件或 C++），与 `bench`（每候选热路径微基准）互补。见 `BENCHMARK.md`。

下面 §5 保留**审计当时**的原始发现记录（作为审计留痕）；带 ✅ 的条目现已按上表修复。

---

## 1. 审计范围与方法 / Scope & method

审计覆盖 9 个子系统，每个都做了 Rust 与 C++ 的源码逐项对照，并对**可测项做了针对 oracle 的实测**：

- 加解密（18 密码 × 8 模式、KEYGEN_MCRYPT、MD5、CRC32）
- JPEG 量化 DCT 编解码
- BMP / WAV / AU 格式与样本逻辑
- 核心原语（BitString、PRNG、Selector、AUtils）
- EmbData 帧编解码与 embed/extract 流水线
- 图匹配失真优化器（嵌入）
- 破解器（wordlist / seed）与线程模型
- CLI / 参数解析 / 会话调度 / 输出

**验证等级标注：** 🟢 = 已对 oracle 实测确认；🟡 = 仅源码阅读推断；🔵 = 已实测**证伪/纠正**。

工具与环境见 [`BENCHMARK.md`](BENCHMARK.md)（性能）与 [`COMPATIBILITY.md`](COMPATIBILITY.md)（兼容性结论）。

---

## 2. 实测确认的一致性 / Empirically-proven parity 🟢

以下均为**对真实 C++ oracle 的双向实测**结果（非仅测试夹具、非仅源码推断）：

| 项目 | 实测结果 |
|------|----------|
| **密码集合** | `--encinfo` 列出的 18 个算法与参照版**完全相同**（仅排序不同）；`safer-sk64/sk128/threeway/panama` 两边都没有 |
| **跨工具破解** | C++ 用 13 个分组密码(cbc) + 3 个流密码(stream) 各嵌入一次 → Rust 破解并提取，**payload 字节一致** |
| **双向嵌入/提取** | 9 种封面变体（调色板 BMP、24-bit BMP、PCM8/16 WAV、PCM8/mulaw AU、baseline JPEG、progressive JPEG）**两个方向都 round-trip 成功** |
| **容量计算** | `--info` 报告的 capacity 对 6 种格式**逐字节相同**（含 progressive JPEG 203.0 B） |
| **压缩** | zlib `-z 1/5/9` 双向 round-trip 均成功 |
| **`--seed`（CVE-2021-27211）** | 两边找到**相同 seed `58c8cc6c`**、相同明文大小、相同算法/模式/文件名，提取结果**字节一致** |
| **退出码** | 找到=0 / 未找到=1，两边一致 |
| **内部测试** | `cargo test --workspace --release` → **61 passed, 0 failed** |

> 这填补了原文档 `under_examined` 中最大的一条：此前"全兼容"仅靠 golden 夹具与源码阅读，从未跑过真实 steghide 二进制。本次已补齐。

---

## 3. 性能 / Performance 🟢

完整方法与数据见 [`BENCHMARK.md`](BENCHMARK.md)。要点：在 16 核机器上，以 rockyou 规模（14,344,391 条不命中口令）做**最坏情况全量扫描**，best-of-5：

| 线程 | Rust | C++ `-O2`（发行默认） | Rust 加速比 |
|:---:|:---:|:---:|:---:|
| 1 | **5.14 M pw/s** | 4.15 M pw/s | **1.24×** |
| 2 | **10.43 M pw/s** | 8.27 M pw/s | **1.26×** |
| 16 | **66.0 M pw/s** | 45.4 M pw/s | **1.46×** |

- **纯 Rust 端口在每个线程数上都比 C++ 原版快 1.2–1.5×。**
- C++ 用 `-O3 -flto -DNDEBUG` 重编**并不会更快**（与 `-O2` 持平，个别更慢）——所以公平（甚至偏向 C++）的比较基准就是发行版默认的 `-O2`。
- 真实 rockyou.txt 破解 `none.jpg`（口令 `Sesame` 在第 10.6M 行，~74%）：Rust 16 线程 **0.19 s**，C++ 0.31 s。"rockyou 2 秒内"的招牌在本机被轻松满足。
- 二进制体积：Rust **823 KB（零外部依赖）** vs C++ 1029 KB（静态链接 libmcrypt/libmhash/libjpeg）。

---

## 4. 功能差距矩阵 / Gap matrix

| 子系统 | 判定 | 头号差距 |
|--------|:----:|----------|
| 密钥派生/哈希 (KEYGEN/MD5/CRC32) | 🟢 full | 无 CLI 可达差距；仅口令含 NUL 字节时派生分歧 |
| 核心原语 (LCG/Selector/BitString) | 🟢 full | 可复现路径逐行忠实（bit-exact 由破解一致性反证） |
| 密码 × 模式 | 🟡 partial | 4 个 libmcrypt 密码未实现——**但本环境 oracle 也不支持**（见 §6 纠正） |
| JPEG 编解码 | 🟡 partial | 算术编码 JPEG (SOF9/10) 直接拒绝；截断头会 **panic** |
| BMP/WAV/AU | 🟡 partial | 24-bit BMP 嵌入**从不改 R 通道** → 失真升高 |
| EmbData/嵌入提取流水线 | 🟡 partial | `--extract` 默认输出名与 steghide 不同 |
| 图匹配失真优化器 | 🟡 partial | 仅贪心匹配 + 8192 顶点上限；无 DFSAP 增广路 |
| 破解器/线程 | 🟡 partial | `--continue` 被解析但未接线；无进度输出 |
| CLI/参数/会话 | 🟡 partial | 无口令交互提示、`--info` 浅、多个 steghide 惯例缺失 |

---

## 5. 确认的缺陷与差距（按影响排序）/ Confirmed findings, ranked

### 🔴 影响正确性/健壮性 / Correctness & robustness

**F1 · JPEG 解码器对截断/损坏输入 panic（而非报错）** 🟢 已实测
- `crates/stegseek-jpeg/src/decoder.rs:306` 与 `:329` 在头部被截断时数组越界 panic。实测：把 `std.jpg` 截到 5%/10%/前 50–200 字节，`stegseek-rs --info` 直接 `thread 'main' panicked … index out of bounds`。
- 因发行 profile 为 `panic = "abort"`，进程直接**中止**；而 steghide 对同样输入给出干净的 `[!] error:`。
- **影响：** 扫描/破解一批不可信文件时，一个损坏的 JPEG 会让进程崩溃。**建议修复**：把 decoder 的切片访问改为返回 `JpegError`。

**F2 · 24-bit RGB BMP 嵌入从不修改 R 通道** 🟢 已实测（并已量化）
- 对同一 200×200 BMP 嵌入相同 payload：stegseek-rs 改动分布 **B=1043 / G=1075 / R=0**，全部为 ±1；steghide 为 **B=552 / G=519 / R=513**，全部 ±1。
- 两者都只做距离-1（±1）改动（此处**纠正**了审计智能体"距离-2"的说法），但 Rust 把全部改动挤在 2 个通道，加之匹配更弱，导致**改动样本数为 steghide 的 1.34×**（2118 vs 1584）。
- **影响：仅隐蔽性**——产物仍是合法、可被 steghide 正确提取的 stego（已证）。属嵌入质量问题，不影响破解/提取。详见 §5 图匹配条目。

**F3 · 口令含 NUL 字节时密钥派生分歧** 🟡 源码阅读
- C++ 在首个 NUL 处截断口令，Rust 用完整字节切片。含 NUL 的口令罕见，但会导致密钥不一致 → 互相无法提取。低危。

### 🟠 功能缺失 / Missing functionality

**F4 · `-c/--continue` 被解析但为空操作** 🟡（两个独立子系统审计一致，高置信）
- `args.rs` 解析了 `cont`，但 `crack.rs` 从不读取它；破解器命中即停，只写一个文件。steghide 会继续搜索并把多个内嵌文件写成 `.out`/`.out.1`/…。**影响：** 单容器多 payload 只能恢复第一个。

**F5 · 算术编码 JPEG (SOF9/SOF10) 被直接拒绝** 🟡 源码阅读
- `decoder.rs` 的 SOF 分支只认 `0xC0/0xC1/0xC2`（Huffman baseline/extended/progressive）。算术编码帧 → `UnsupportedFileFormat`。steghide 经 libjpeg 可读。真实世界少见，但确为差距。

**F6 · `-r/--radius`、`-g/--goal` 嵌入调优参数缺失** 🟢 已实测
- 实测 `stegseek-rs --embed … -r 5` → `[!] error: unknown argument "-r"`（`-g` 同）。steghide 支持这两个嵌入半径/目标参数。

**F7 · 12-bit JPEG 精度被静默误解码** 🟡 源码阅读
- SOF 精度字节被读入 `_prec` 后忽略，按 8-bit（`i16`）解码。12-bit 帧会得到错误系数而非报错。exotic。

### 🟡 CLI / 交互 / 输出偏差 (steghide 惯例)

**F8 · 缺 `-p` 时静默使用空口令（不提示）** 🟢 已实测
- 实测 `--extract`（无 `-p`，stdin 关闭）：Rust → `could not extract any data with that passphrase!`（即用了空口令）；C++ → `Enter passphrase:`（交互提示，echo-off，embed 时二次确认）。**影响：** embed 无 `-p` 会静默用空密钥，属安全/易用性隐患。

**F9 · `--info` 不读取内嵌数据信息** 🟢 已实测
- 给定口令时，steghide `--info -p` 会额外打印内嵌文件名、大小、加密算法/模式、是否压缩；stegseek-rs `--info` 只打印 `format` 与 `capacity`。（无口令时 steghide 还会交互询问是否尝试读取。）

**F10 · `--extract` 默认输出文件名不同** 🟢 已实测
- 无 `-xf` 时：Rust 写 `<stegofile>.out`（如 `clean.stg.out`）；steghide 写**内嵌的原始文件名**（如 `secret.txt`）。行为可见地不同，且 steghide 在内嵌名为空且无 `-xf` 时会报错要求指定名字，Rust 则默认 `.out` 从不报错。

**F11 · 无实时进度指标；`-q` 近乎空操作** 🟢 已实测
- 实测慢速扫描：C++ 打印 `Progress: X%`；Rust **零进度输出**。`--seed` 同样如此。文档称 `-q` 用于"隐藏性能指标"，但 Rust 本就无指标可隐藏，长任务无 ETA 反馈。

**F12 · stdin/stdout `-` 约定失效** 🟡 源码阅读
- steghide 把位置/关键字参数 `-` 视为空串=stdin/stdout；Rust 原样当作名为 `-` 的真实文件。管道用法受影响。

**F13 · 逐命令参数校验较宽松** 🟡 源码阅读
- steghide 拒绝"用错命令的旗标"和重复旗标（`… can be used only once.`）、校验 `-e` 的算法/模式兼容与冲突、校验 `-z` 范围 1..9；Rust 大多静默接受（`-z` 接受任意 `i32`，`-e` 不做 `AlgoSupportsMode` 校验，末次生效）。错误面不同，但对合法输入无影响。

**F14 · 口令未从 argv 抹除** 🟡 源码阅读
- steghide 构造时把 `-p` 的 argv 覆盖为空格，避免 `ps` 泄露；Rust 不抹除。低危信息泄露。

**F15 · `--help`/`--help -v` 文本与 steghide 有出入** 🟡 源码阅读
- Rust `print_help` 忽略 `-v`（不追加 steghide 帮助块），且自撰的命令/参数条目与原版措辞不一致。

### ℹ️ 仅信息性（无数据通路影响）

- **F16 · 封面安全性警告缺失**：steghide 会对黑白/16 色封面（"very insecure"）、非零填充字节、非零 RGBQUAD 保留位打印警告；Rust 全部省略。
- **F17 · BMP 写回不归零填充字节**：steghide 输出时把扫描线填充清零；Rust 保留原字节。产物字节不同，提取无碍。
- **F18 · top-down（负高度）BMP**：🟢 实测 Rust 能嵌入并正确 round-trip，而 steghide 对该封面**崩溃/拒绝**（本机为 `std::bad_alloc`）。双向互操作在此类封面上断裂——但这类文件本就非常规。
- **F19 · `--encinfo` 排序**：Rust 与 C++ 列出的算法集合相同，但顺序不同（C++ 按 libmcrypt 内部顺序）。纯外观差异。

---

## 6. 纠正：4 个"缺失密码"并非高危差距 🔵

多智能体审计中一个子系统给出**高危**结论：`safer-sk64 / safer-sk128 / threeway / panama` 未实现会导致"stock steghide 加密的文件在 stegseek-rs 里无法破解/提取"。该结论**经二进制实测证伪**：

- 本机 `libmcrypt.so.4`（Debian/Kali `2.5.8-8+b2`）导出的算法模块经 `strings` 提取仅为：`arcfour blowfish enigma gost loki97 rc2 saferplus serpent tripledes twofish wake xtea` + `rijndael-128/192/256`（及 des/cast）。**`safer-sk64/safer-sk128/threeway/panama` 模块根本不在其中**（只有不同的 `saferplus`=Safer+）。
- 因此参照版 steghide（链接同一 libmcrypt）对这 4 个密码在**所有模式**下都报错 `… can not be used with the mode …`。实测逐一确认。
- 结论：**stegseek-rs 拒绝这 4 个密码的行为与 oracle 完全一致**，`COMPATIBILITY.md` 的说法在实质上正确。

**建议的措辞收紧**（已在 `COMPATIBILITY.md` 落实）：这是**该 libmcrypt 构建**的限制，而非普适保证。若某发行版把 libmcrypt 编全了全部模块，用它的 steghide 以这 4 个密码加密的文件，stegseek-rs 确实无法提取——这是一个**可移植性注意事项**，而非针对标准发行包的兼容性破坏。

**教训：** 智能体基于 `reference/mcrypt-2.5.8/algorithms/*.c` 源码存在就推断"默认编译进库"，而实际二进制并未包含。**源码阅读会误导，实测二进制才是准绳**——本报告所有 🟢 项均如此核验。

---

## 7. 图匹配失真优化器：已知短板的量化 / Quantifying the known gap

这是重写唯一的"设计性"短板，`EMBED_NOTES.md` 已坦承。本次给出**实测数字**：

- steghide 为最小化嵌入失真，跨 5 个构造启发式（WKS/SMD/DMD/BFSAP/**DFSAP** 增广路）做**最大基数最小权匹配**。stegseek-rs 用**单趟贪心 beneficial 最小权匹配**替代全部，并有两个限制：
  1. `MATCHING_VERTEX_CAP = 8192`：错配顶点超过 8192 时**整个优化器被跳过**，全部退化为贪心单样本改动（对 modulus-2 封面 = 大 payload 时优化器基本失效）。
  2. beneficial 剪枝（`2·weight ≤ greedy(v1)+greedy(v2)`）会丢弃 steghide 会保留的、有利于直方图保持的交换。
- **实测失真（改动样本数，越小越隐蔽）：**

| 封面 | stegseek-rs | steghide (C++) | 比值 |
|------|:---:|:---:|:---:|
| 24-bit BMP（RGB） | ~2118 | ~1584 | **1.34×** |
| 16-bit PCM WAV | ~2150 | ~2161 | **~1.0×（持平）** |

- **关键判断：** 对 1-D、modulus-2 的格式（JPEG、音频），贪心 ±1 改动本就近乎最优，`EMBED_NOTES` 的"失真中性"说法被实测支持（WAV 持平）。差距**只在调色板/RGB 图像**上显现（约 +34%）。
- **影响面：** 纯隐蔽性（抗 chi-square/直方图隐写分析）。产物**始终是合法、可提取、可破解的 steghide 0.6 文件**（双向已证）。破解与提取**零影响**。

---

## 8. 代码质量 / Code-quality themes

**优点：**
- 全程**内存安全**：无 `unsafe`，合法数据的 crypto/keygen 路径无 panic；破解热路径有"零堆分配"回归测试（`hotpath_no_alloc.rs`）守护。
- 密钥派生与哈希**对真实 libmhash 0.9.9.9 实测 bit-exact**（KEYGEN_MCRYPT 多块延续、CRC-32/BZIP2 而非反射的 CRC32B）。
- 8 个 mcrypt 模式（含 cfb8/ofb8 反馈宽度、ncfb/nofb 全块反馈、big-endian CTR）细节忠实，108 条 golden 向量。
- JPEG baseline **与** progressive 均复现 libjpeg 的精确量化 DCT 系数。

**待改进：**
- **F1 的 panic 是最需要修的质量问题**：解码器应对不可信输入返回 `Result` 而非越界 panic。
- 文档过度泛化：把"本 libmcrypt 构建缺 4 密码"写成普适兼容保证（§6，已修正）。
- `facade::crypt` 对不支持的组合返回 `bool` 而非 typed `Result`，把失败处理推给调用方。
- `modes.rs` 头注释称 CTR 小端自增，与其自身（正确的大端）代码矛盾——注释错误，无行为影响。
- 大封面内存：原始文件整份留在 `Vec<u8>` 且 JPEG 会重扫熵段——未做压力评估（列为 under-examined）。

---

## 9. 建议的后续项 / Recommended follow-ups

按性价比排序：

1. **修 F1（JPEG panic → error）** — 唯一真正的健壮性缺陷，改动局部，收益明确。
2. **接线 F4（`--continue`）与 F9（`--info -p` 读内嵌信息）** — 用户可见、被文档承诺的功能。
3. **对齐 F8/F10（缺 `-p` 提示、`--extract` 默认名）** — steghide 兼容性关键的可见行为。
4. **收紧文档措辞（§6）** — 已在 `COMPATIBILITY.md` 落实。
5. **（可选）提升 RGB BMP 嵌入质量** — 让嵌入也考虑 R 通道、放宽/去掉 8192 上限、逼近 DFSAP。纯隐蔽性收益，工作量大。
6. **（可选）算术编码/12-bit JPEG、stdin/stdout `-`、逐命令参数校验** — 完备性收尾。

**没有任何一项影响"破解 + 提取"这一核心用途**——那部分已被实测证明忠实且更快。

---

## 附:证据可复现 / Reproducing the evidence

- oracle 构建：见 `BENCHMARK.md` §Reproduce（无 root，用 `apt-get download` + `dpkg-deb -x` 抽取 `-dev` 头文件与静态库）。
- 互操作矩阵、失真测量、panic 复现、CLI 差异：本次审计脚本均为 `bash`/`python3` 一次性命令，逐条列于各 §（如 §5 F1 的截断 panic、F2 的通道分布统计）。
- 内部测试：`cargo test --workspace --release`（61 passed）。
