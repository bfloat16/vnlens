# AGENTS.md — nvlens 开发规范

nvlens 是使用 Rust 编写的视觉小说（Visual Novel / Galgame）资源提取器：识别专有归档格式，提取其中条目，并将专有图像/音频解码为通用格式。本文件是所有贡献者与 AI 代理的强制约束，动手前须通读。

---

## 1. 目标与范围

**目标**
- 无损提取各类专有归档（`.arc/.dat/.pak/.xp3/...`）中的文件条目。
- 将专有图像解码为 PNG，音频解码为 WAV/OGG。
- 核心库与界面无关，可在 CLI、GUI、第三方 crate 三种形态复用。
- 架构可扩展至数百种格式家族，新增格式无需改动核心。

**非目标**
- 不提供归档创建/回写，除非个别格式明确需要。
- 不追求与任何既有工具的字节级兼容，只要求提取内容语义等价。
- GUI 为后续可选层，其类型不得渗入核心库。

---

## 2. 工具链约束

| 项 | 规定 |
|---|---|
| Edition | 2024 |
| MSRV | 固定写入根 `Cargo.toml` 的 `rust-version`（当前 1.85）；升级须在 PR 说明理由 |
| 注释语言 | **代码内一切注释与 doc 注释一律英文**（本规范文档除外）。标识符、日志、错误信息也用英文 |
| `lib.rs` | 只做对外暴露（`mod`/`pub use`/`pub fn init`），**不写业务逻辑**；逻辑放独立 `.rs` 模块 |
| 二进制 I/O | 所有字节读写唯一走 `nvlens-io`（见 §4），其它 crate 不得手写 `from_le_bytes`/`to_le_bytes` 之类裸解码 |
| 日志 | 统一用 `nvlens-io::log` 管理器初始化，各处用 `tracing` 宏输出 |
| 格式化 | `cargo fmt` 必须通过，排版以 `rustfmt.toml` 为准 |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` 零告警 |
| unsafe | 默认 `#![forbid(unsafe_code)]`；仅 `nvlens-io` 的 mmap 封装局部放开，每处 `unsafe` 附 `// SAFETY:` |
| panic | 库代码正常路径禁止 `unwrap/expect/panic!/unreachable!/todo!`；失败一律走 `Result`。测试与 `main` 例外 |

根 `Cargo.toml` 统一 lint：

```toml
[workspace.lints.rust]
missing_debug_implementations = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

---

## 3. 架构总览

### 3.1 Workspace 布局

```
nvlens/
├─ Cargo.toml            # [workspace]，统一 lints 与依赖版本
├─ crates/
│  ├─ nvlens-io/         # I/O：唯一的二进制读写模块 + mmap 视图 + 统一日志管理器。唯一允许 unsafe
│  ├─ nvlens-core/       # 抽象层：trait、Entry、注册表、探测、错误、scheme。无具体格式
│  ├─ nvlens-crypto/     # 纯计算算法：解压、加解密、校验和等（与格式无关，输入字节出字节）
│  ├─ nvlens-archive/    # 归档格式实现（按引擎分模块）
│  ├─ nvlens-image/      # 图像格式解码 + 通用 Image 模型、调色板工具
│  ├─ nvlens-audio/      # 音频格式解码
│  ├─ nvlens-script/     # 脚本格式解码与文本提取
│  ├─ nvlens-video/      # 视频格式处理
│  ├─ nvlens-cli/        # 二进制 `nvlens`
│  └─ nvlens-gui/        # 可选，后期；不被上述任何 crate 依赖
└─ tests/fixtures/
```

依赖方向单向，禁止回环（`io` 是最底层，`core`/`crypto` 建立其上）：

```
cli / gui → {archive, image, audio, script, video} → core, crypto
core → io
crypto → io
```

`io` 不依赖任何其它内部 crate；`core` 依赖 `io` 并重导出 `ArcView`。各格式 crate 依赖 `core`，需要纯算法时依赖 `crypto`。

**纯计算算法集中于 `nvlens-crypto`**：压缩/解压（LZSS、zlib…）、加解密（Blowfish、Camellia、自定义密钥流…）、校验和/哈希（CRC…）等与格式无关的例程一律放此 crate，按 `compress/`、`cipher/`、`checksum/` 等子模块组织。它们只吞吐字节、不含归档/格式概念；读取长度前缀等字节 framing 仍走 `nvlens-io`（保持二进制 I/O 单一来源）。

### 3.2 条目模型

```rust
/// 归档中的一个文件条目。
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,           // 归档内相对路径；禁止绝对路径与 `..`
    pub kind: ResourceKind,
    pub offset: u64,
    pub size: u64,
    pub packed: Option<Packed>, // Some 表示压缩条目
}

#[derive(Clone, Copy, Debug)]
pub struct Packed {
    pub unpacked_size: u64,
    pub is_packed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind { Archive, Image, Audio, Script, Video, Unknown }
```

- 资源类型用枚举 `ResourceKind`，禁止裸字符串比较。
- “可能压缩”用组合 `Option<Packed>` 表达，不用继承式 trait 对象模拟。
- 条目边界校验（`offset + size <= archive_len` 且不溢出）在打开归档时强制执行。

### 3.3 格式 trait 层级

```rust
/// 一切格式处理器的公共元信息。
pub trait Format: Sync + Send {
    /// 唯一短标签，通常为主扩展名，如 "xp3"、"spack"。
    fn tag(&self) -> &'static str;
    fn description(&self) -> &'static str;
    /// 可能的首 4 字节签名（小端 u32）；`0` 表示签名不固定，探测时兜底。
    fn signatures(&self) -> &'static [u32] { &[0] }
    /// 关联扩展名（小写，无点），用于探测排序与类型推断。
    fn extensions(&self) -> &'static [&'static str];
}

/// 归档格式。
pub trait ArchiveFormat: Format {
    fn is_hierarchic(&self) -> bool { false }
    /// 探测并打开。匹配成功返回归档实例；非本格式返回 `Ok(None)`；数据损坏返回 `Err`。
    /// 传入 `&Arc<ArcView>`，实现可 `Arc::clone` 存入归档以支持后续读取。
    fn try_open(&self, view: &Arc<ArcView>) -> Result<Option<Box<dyn Archive>>>;
}

/// 已打开的归档，持有自身状态（索引、密钥、视图引用）。
pub trait Archive: Send {
    fn entries(&self) -> &[Entry];
    /// 打开条目内容：原始条目零拷贝借用映射，变换后条目返回拥有的缓冲。
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>>;
}

/// 图像格式。分两阶段：先读元信息，再解码像素。
pub trait ImageFormat: Format {
    fn read_meta(&self, r: &mut BinaryReader) -> Result<Option<ImageMeta>>;
    fn read(&self, r: &mut BinaryReader, meta: &ImageMeta) -> Result<Image>;
}

/// 音频格式，返回解码后的 PCM 源。
pub trait AudioFormat: Format {
    fn try_open(&self, r: &mut BinaryReader) -> Result<Option<Box<dyn AudioSource>>>;
}
```

设计要点：
- **探测三态**：`Ok(Some)` 匹配成功；`Ok(None)` 非本格式，试下一个；`Err` 是本格式但已损坏。探测循环只吞 `Ok(None)` 与 `Err`，绝不 panic。
- **状态归属实例**：`try_open` 返回实现 `Archive` 的自定义 struct，把密钥、索引存入其中，杜绝全局可变状态。
- **界面无关**：图像 trait 返回自有 `Image`，不引用任何窗口/位图系统类型。

### 3.4 注册与探测

用 `inventory` 做编译期分布式注册，格式实现无需触碰核心：

```rust
// nvlens-core
pub struct ArchiveRegistration(pub fn() -> Box<dyn ArchiveFormat>);
inventory::collect!(ArchiveRegistration);

#[macro_export]
macro_rules! register_archive {
    ($ty:ty) => {
        inventory::submit! { $crate::ArchiveRegistration(|| Box::new(<$ty>::default())) }
    };
}
```

格式文件末尾一行完成注册：

```rust
register_archive!(SpackArchive);
```

`Catalog` 惰性构建（`OnceLock`），非全局单例，可注入以便测试。索引结构：

```rust
pub struct Catalog {
    by_signature: HashMap<u32, Vec<&'static dyn ArchiveFormat>>,
    by_extension: HashMap<String, Vec<&'static dyn ArchiveFormat>>,
    // image / audio / script 同理
}
```

探测算法：

1. 读首 4 字节，取小端 u32 作为 `signature`。
2. 取 `by_signature[signature]` 候选集合。
3. 候选多于一个时，扩展名匹配者排前。
4. 处于嵌套归档中时，父归档声明的 `contained_formats` 内的 tag 优先。
5. 逐个 `try_open`；全部失败则以 `signature = 0` 的兜底格式再试一轮。
6. 仍失败则视为普通文件（`ResourceKind::Unknown`）。

签名统一取 `u32::from_le_bytes(header[..4])`。

### 3.5 图像模型

```rust
/// 解码后的图像，界面无关，通道统一 8-bit。
#[derive(Clone)]
pub struct Image {
    pub meta: ImageMeta,
    pub pixels: PixelBuffer,
}

pub enum PixelBuffer {
    Rgba8(Vec<u8>),
    Bgra8(Vec<u8>),                              // 原生序，避免无谓换序，导出时定序
    Indexed { data: Vec<u8>, palette: Vec<[u8; 4]> },
    Gray8(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct ImageMeta {
    pub width: u32,
    pub height: u32,
    pub offset_x: i32,
    pub offset_y: i32,
    pub bpp: u16,
    pub file_name: Option<String>,
}
```

- 调色板读取（RGB/BGR/RGBA/BGRA 及各变体）作为 `nvlens-image` 的复用工具函数，供大量格式共用。
- 导出统一走 `nvlens-image` 的 PNG 编码器；带偏移的图像在导出时保留偏移信息，不静默丢弃。

### 3.6 格式模块组织

每个域 crate（`nvlens-archive` 等）下，每个引擎一个模块目录：

```
nvlens-archive/src/
├─ lib.rs              # 仅 mod 声明 + pub use + init()，无逻辑
├─ kirikiri/
│  ├─ mod.rs
│  └─ xp3.rs
├─ will/
│  └─ arc.rs
└─ ...
```

- 模块名用引擎 snake_case（`kirikiri`、`cat_system`、`will`）。
- 引擎内共享的小工具放该引擎 `mod.rs`。
- 与格式无关的纯算法（解压、加解密、校验和）放 `nvlens-crypto`，格式代码调用之。
- 每个格式文件顶部用英文 doc 注释注明格式来源与结构要点。
- 图像/音频/脚本/视频格式分别落在对应域 crate，组织方式相同。

---

## 4. I/O 层（nvlens-io）

底层 crate，唯一允许 `unsafe`（仅 mmap），并承担三项职责：**二进制读写的唯一来源**、mmap 视图、统一日志管理器。

### 4.1 二进制读写（`binary` 模块，全项目唯一来源）

所有字节 ↔ 整数的转换只在此模块发生；其它 crate 不得手写 `from_le_bytes` 之类裸解码，一律经此。按输入形态分三个入口：

- **`BinaryReader<'a>`**：`&[u8]` 上的游标 + 无状态解码器。
  - 无状态：`BinaryReader::u32_le(&buf)`、`u16_le_at(&buf, off)` 等（输入须恰为对应字节数）。
  - 游标：`new/new_at`、`read_u8/u16_le/i32_le/u64_le`、`read_bytes(len)`、`read_utf16_units_le(n)`、`position/set_position/remaining/align4`。
- **`BinaryWriter`**：无状态编码器写入调用方缓冲（`u32_le(v, &mut out)`、`u32_le_at(...)`）。
- **`BinaryIo`**：`std::io::Read/Seek` 流适配（`read_u32_le(r)`、`read_u32_le_at(r, off)`）与错误构造器（`invalid_input`、`unexpected_eof`）。
- **`Endian`**：`Little/Big`，按运行期字节序选择解码。

### 4.2 ArcView（随机访问，`memmap2` 只读映射）

读取方法返回 `std::io::Result`，越界为 `UnexpectedEof`；**内部解码委托 `BinaryReader`**，不重复实现字节解析：

```rust
impl ArcView {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self>;
    pub fn len(&self) -> u64;
    pub fn file_name(&self) -> &str;
    pub fn slice(&self, offset: u64, size: u64) -> io::Result<&[u8]>; // 边界检查
    pub fn read_u8(&self, off: u64) -> io::Result<u8>;
    pub fn read_u16_le(&self, off: u64) -> io::Result<u16>;
    pub fn read_u32_le(&self, off: u64) -> io::Result<u32>;
    pub fn read_i32_le(&self, off: u64) -> io::Result<i32>;
}
```

### 4.3 日志管理器（`log` 模块）

统一初始化入口 `nvlens_io::log::init(verbosity)`（基于 `tracing` + `tracing-subscriber`，`Once` 幂等，`RUST_LOG` 可覆盖）。二进制启动时调用一次；各 crate 用 `tracing` 宏输出，不各自初始化 subscriber。

### 4.4 规则
- 偏移与长度一律 `u64`，支持大于 4GB 的文件。
- 所有读取先边界检查，越界返回 `Err`，绝不 panic。
- 探测/解析中，“读越界=非本格式”是常态控制流：用 `.ok()?` 将 `io::Result` 收敛为 `Option` 并短路，最终 `try_open` 包成 `Ok(None)`；`core::Error` 供格式层显式自校验使用。
- 多字节默认小端；大端方法名显式带 `_be` 或经 `Endian`。
- 文本默认 CP932/Shift-JIS，用 `encoding_rs` 解码，禁止假设 UTF-8（UTF-16LE 文件名用 `String::from_utf16`）。
- 位流（MSB/LSB）后续置于 `nvlens-io::bitstream`，供图像与压缩格式复用。

---

## 5. 加密与 Scheme 数据

部分归档按游戏加密，密钥数据与代码分离：

- Scheme 数据用 `serde` + JSON，可读、可 diff、可社区贡献；字节数组以 hex 字符串存储。
- 每个需要密钥的格式定义自己的 `#[derive(Serialize, Deserialize)]` scheme struct，集中登记于 `schemes/*.json`。
- 交互（如按游戏标题选择密钥）抽象为 trait，不绑定任何界面：

```rust
pub trait SchemeProvider {
    /// 归档需要密钥时调用；返回 None 表示用户取消。
    fn request(&self, notice: &str, options: &[&str]) -> Option<Selection>;
}
```

- 核心库不弹窗、不读 stdin；CLI/测试各自实现。
- 用户取消映射为 `Error::Cancelled`，不视为数据损坏。

---

## 6. 依赖策略

优先标准库；新增依赖须必要且维护良好，并在 PR 说明。默认批准清单：

| 用途 | crate |
|---|---|
| mmap | `memmap2` |
| 错误（库 / 二进制） | `thiserror` / `anyhow` |
| 分布式注册 | `inventory` |
| 惰性单例 | `std::sync::OnceLock` / `once_cell` |
| 文本编码 | `encoding_rs` |
| 压缩 | `flate2`（zlib/deflate），其余 LZSS 等自研于 `nvlens-crypto` |
| 序列化 | `serde`, `serde_json` |
| 图像输出 | `image` 或自研精简编码器 |
| CLI | `clap`（derive） |
| 日志 | `tracing`, `tracing-subscriber`（subscriber 仅由 `nvlens-io::log::init` 初始化） |
| 并行 | `rayon`（批量提取，可选） |

加密算法（Blowfish/Camellia/自定义密钥流）优先自研于 `nvlens-crypto`，以保证位级可控。禁止引入无维护、带未审计 `unsafe`、或把界面依赖拖入核心的 crate。

---

## 7. 错误处理

`nvlens-core` 统一错误类型：

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),        // 含越界读取（UnexpectedEof）
    #[error("invalid format")]
    InvalidFormat,
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("data corrupted at 0x{offset:x}: {reason}")]
    Corrupt { offset: u64, reason: String },
    #[error("unknown encryption scheme")]
    UnknownScheme(Option<String>),
    #[error("operation cancelled")]
    Cancelled,
}
pub type Result<T> = std::result::Result<T, Error>;
```

规则：
- “非本格式”用 `Ok(None)`，不用 `Err`——探测循环据此区分“换下一个”与“记录损坏”。
- 越界读取由 `nvlens-io` 返回 `UnexpectedEof`，经 `#[from]` 收敛为 `Error::Io`，绝不 panic。
- 库不打印错误；用 `tracing` 记录，展示交给上层。
- 单个条目提取失败不中断整包：上层捕获、记录、继续。

---

## 8. 添加一个格式

1. 在对应域 crate（如 `nvlens-archive/src/<engine>/<name>.rs`）建文件，顶部英文 doc 注释注明格式结构。
2. 定义 `#[derive(Default)] struct XxxFormat;` 实现 `Format` + `ArchiveFormat`（或 Image/Audio）。
3. 定义持状态的 `struct XxxArchive { view, entries, key, ... }` 实现 `Archive`。
4. 在 `try_open` 中：校验签名/版本不符即 `Ok(None)`；条目数用 `is_sane_count` 校验；每个条目做边界与名称校验（`check_placement` + `has_valid_name`）。一切字节读取经 `nvlens-io`（`ArcView` 或 `BinaryReader`）。
5. 在 `open_entry` 中按需解压/解密，纯算法调用 `nvlens-crypto`，读长度前缀等仍走 `nvlens-io`。
6. 文件末尾 `register_archive!(XxxFormat);`。
7. 补测试：至少覆盖签名判定；有样本时加集成测试。

数值与位运算准则：
- 明确整型宽度与符号；回绕语义用 `wrapping_*`，算术右移显式用有符号类型。
- 魔法常数保守直译并加注释，不做“看似等价”的化简。

---

## 9. 测试

- **单元测试**：与代码同文件 `#[cfg(test)] mod tests`，覆盖签名判定、边界、压缩算法（已知输入/输出向量）。
- **集成测试**：对应域 crate 的 `tests/`，跑真实样本。
- **fixture**：受版权限制的游戏原始资源不入库；仅提交经许可或自造的最小样本，或用下载脚本，无法入库者用 `#[ignore]` 并在文档说明获取方式。
- **黄金测试**：解码结果（如像素哈希）与已知正确值比对，防回归。
- **fuzz**：探测/解析入口用 `cargo-fuzz`，保证任意字节流不 panic、不 OOM、不无限循环。
- CI 强制：`fmt --check`、`clippy -D warnings`、`test`。

---

## 10. 性能与安全

- **零拷贝**：解析索引直接在 mmap 的 `&[u8]` 上切片，避免整文件 `read_to_end`。
- **分配前设限**：任何来自文件的计数/长度，分配前先用 `is_sane_count`（如 `0 < n < 0x40000`）或与 `view.len()` 比对上限。
- **不可信输入三铁律**：读前边界检查；分配前上限检查；循环有明确终止条件（防解压炸弹与环形索引）。
- 批量提取可用 `rayon` 并行；含可变解密状态的归档需保证 `Sync` 或每线程独立实例。

---

## 11. CLI 约定（nvlens）

`clap` 子命令：

- `nvlens list <archive>` — 列出条目。
- `nvlens extract <archive> [--out DIR] [--filter GLOB] [--raw]` — 提取，默认图像转 PNG、音频转 WAV，`--raw` 保留原始字节。
- `nvlens info <file>` — 显示探测到的格式与元信息。
- `nvlens formats` — 列出已注册格式。
- 加密归档用 `--game <title>` 或交互选择提供密钥。

退出码 `0` 成功、非 `0` 失败；`--json` 输出机器可读；日志走 `tracing`，`-v/-vv` 调级别。

---

## 12. 提交检查清单

- [ ] `cargo fmt --all --check` 通过。
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 零告警。
- [ ] `cargo test --all` 通过。
- [ ] 库正常路径无 `unwrap/expect/panic`。
- [ ] 新格式已 `register_*!` 注册，文件头有结构说明，位运算已核对。
- [ ] 不可信输入路径具备边界检查、分配上限、循环终止三项。
- [ ] 界面类型未渗入 `io/core` 及各域格式 crate。
- [ ] 注释/日志/错误信息均为英文；`lib.rs` 无业务逻辑；字节读写全部经 `nvlens-io`。
- [ ] 依赖方向无回环。

Commit 用祈使句聚焦单一改动，新增格式建议 `formats(<engine>): add <format> archive`；一个 PR 聚焦一个引擎或一组相关格式。
