# 后续开发规范

本文件是仓库的根规范，适用于所有目录。nvlens 是 Rust 编写的视觉小说资源提取器；根 `Cargo.toml` 统一管理构建、依赖和 lint，排版遵循 `cargo fmt` 及仓库内的 `rustfmt.toml`（如存在）。本文件只记录通用开发规范，不记录具体功能实现、界面尺寸、控件布局、按钮文案或当前开发进度。

格式实现以格式规范和已验证的实际行为为准，不设置人为的文件大小、条目数量、字符串长度、解压大小、嵌套深度或密钥长度限制。字段范围、结构关系和处理流程均从格式本身推导；不能为适配工具内部模型而拒绝合法数据、截断内容或改变语义。

## 1. 环境与构建

- 使用 Rust 2024、resolver `3`；编译器通过根 `rust-toolchain.toml` 固定为 `1.99.1`，与根 `Cargo.toml` 的 `rust-version` 保持一致。升级时查询最新稳定版并固定具体版本号，同步更新两处配置；不使用浮动的 `stable`。开发环境需要目标平台链接工具，rustfmt 和 Clippy 由工具链配置安装。
- 新 crate 放入 `crates/` 并加入 workspace；继承 `version`、`edition`、`rust-version`、`license` 和 workspace lints。依赖统一在根 `[workspace.dependencies]` 声明，成员使用 `dep.workspace = true`。
- 保留根 lint：`missing_debug_implementations`、Clippy `all` 为 warn，`unwrap_used`、`expect_used`、`panic` 为 deny。检查必须零告警，不通过全局 `allow` 或降低检查等级规避。
- 优先标准库和已有依赖；新增依赖须必要、维护良好、许可兼容并说明理由，不引入未审计 unsafe 或把 GUI 依赖带入核心库。
- Features 只能增加能力，不得关闭安全检查或改变 API 语义。`build.rs` 只处理必要资产，保持确定性和幂等。

## 2. 目录与模块职责

| 路径 | 职责 |
| --- | --- |
| `crates/nvlens-gui` | GPUI 桌面入口、资源浏览、预览、提取调度与结果展示。 |
| `crates/nvlens-engine` | 游戏引擎特征识别、封包定向路由和密钥参数解析。 |
| `crates/nvlens-unpack` | PE 包装的内存解包，仅恢复静态识别需要的节数据，不执行或保存 PE。 |
| `crates/nvlens-io` | 二进制读写、mmap 视图、日志初始化。 |
| `crates/nvlens-core` | 资源模型、错误、格式 trait、注册与探测。 |
| `crates/nvlens-crypto` | 压缩、加解密、哈希与校验和。 |
| `crates/nvlens-bin` | 外部密钥资产、构建期复制与运行期加载。 |
| `crates/nvlens-archive` | 按引擎路由读取归档、索引解析与条目读取。 |
| `crates/nvlens-{image,audio,script,video}` | 对应资源的识别、解码与导出。 |
| `crates/*/tests/`、`tests/fixtures/` | 集成测试与共享最小样本，按需建立。 |

## 3. 模块规范

以下小节依次对应第 2 节。依赖方向为界面层 → engine/域格式 → core/crypto/bin/io，engine 可依赖 unpack，但不依赖域格式；unpack → core/crypto/io，core 和 crypto → io；bin 仅依赖 std 与 tracing，io 不依赖内部 crate。域之间仅允许 archive 为内嵌资源调用 audio/script，禁止反向依赖和回环。GUI 遵守同一分层，核心库不依赖 GPUI。封包目录和资源处理必须持有成功识别的引擎上下文。

### 3.1 `crates/nvlens-gui`

- 唯一应用入口为 GPUI 桌面程序 `nvlens`，不保留 CLI。GPUI 使用最新稳定发布版本并固定具体版本，依赖统一在 workspace 声明。
- 入口统一初始化域注册与日志；格式解析、算法和路径写入复用库。GUI 只负责交互、展示、任务调度和播放设备，不包含格式解析。
- 目录与封包导航支持任意嵌套层级，大型列表使用虚拟化；界面展示不改变资源原名和路径语义，文字截断遵循 Unicode 字素边界。
- 挂载与列表展示只读取索引及必要元信息，资源内容和关联文件按访问需要读取。解析、读取和提取在后台执行，不阻塞界面线程。
- 长任务提供进度和取消；单条目失败继续后续条目并汇总错误。提取保留格式名称，落盘路径交给 io 处理，不把宿主文件系统命名限制当成格式损坏。
- 资源预览与转换调用对应域 crate；字节码通过通用 IR 展示反汇编，纯文本直接展示。界面不宣称尚未实现的解码或导出能力。

### 3.2 `crates/nvlens-engine`

- 每个引擎一个模块，通过 inventory 注册识别器；优先检查 PE 内的字符串和代码特征，再检查当前游戏目录结构。识别器只读取证据及必要参数，不通过解析封包内容猜测引擎。
- PE 中的 x86 代码统一使用 iced-x86 解码，按指令、操作数和控制流识别；不得以原始机器码字节模式匹配替代。字符串、资源记录与格式签名仍按其数据格式解析。
- 识别结果包含引擎身份、证据、支持的封包路由及所需密钥；未知、证据冲突或必要密钥未解析时停止后续资源处理，不回退尝试其它封包格式。
- 识别结果按游戏实例共享，嵌套封包继承同一上下文。PE 地址映射留在 io，纯算法留在 crypto，大型密钥资产由 bin 加载；密钥不得出现在 Debug、日志或错误中。

### 3.3 `crates/nvlens-io`

- 字节与整数的编码、解码统一在 `binary` 实现，其它模块及测试复用 `BinaryReader`、`BinaryWriter`、`BinaryIo`、`Endian`，不得手写 `from_*_bytes`、`to_*_bytes` 或移位拼装替代。
- `ArcView` 负责只读 mmap，整数读取委托 `BinaryReader`。读前校验范围；无状态读取需先保证切片长度，越界返回 `UnexpectedEof`，不得 panic。大文件按需切片，不整文件读入内存再解析。
- 长度、偏移、计数和解压结果按格式字段、索引关系及实际数据边界校验，不使用统一的“合理数量”或固定资源上限。大数据采用分块、流式或按需读取；嵌套和引用按格式遍历，依据实际引用关系处理循环，不靠固定深度拒绝合法结构。
- 字节序和文本编码由格式决定，大端通过 `_be` 或 `Endian::Big` 明示。CP932/Shift-JIS 使用 `encoding_rs`；UTF-16LE 经 reader 读取码元后调用 `String::from_utf16`，不预设小端或 UTF-8。位流能力集中在 io。

### 3.4 `crates/nvlens-core`

- 只定义 `Entry`、`Packed`、`ResourceKind`、错误、路由参数、trait 和 `Catalog` 等抽象，不放具体格式或算法。Catalog 按明确的格式 tag 定向调用一个读取器，不按扩展名、签名或失败结果轮询读取器；保持可测试、可注入，格式状态属于打开后的实例。
- `Format` 按 `tag`、`signatures`、`extensions`、`description` 顺序显式实现。tag 唯一，扩展名小写且不带点；`SIGNATURES` 随识别入口放在引擎 `mod.rs` 或具体格式文件中，使用已核对的小端 `u32` 字面量，无固定签名用 `&[0]`。
- 归档通过 `inventory` 和 `register_archive!` 注册，不维护手写格式列表。各资源域提供对应的解码 trait 与 inventory 注册；ResourceResolver 只在格式请求时读取关联资源。

### 3.5 `crates/nvlens-crypto`

- 按 `compress/`、`cipher/`、`hash/`、`checksum/` 组织。算法只处理字节和参数，不包含归档概念、不读文件、不依赖 bin；密钥由调用方传入。
- 优先复用已有算法；zlib/deflate 使用 `flate2`，专有算法集中实现。字节 framing 仍走 io，不在格式模块复制算法。
- 共享缓存只存不可变数据；并行读取使用独立游标，可变解密状态按实例或线程隔离。

### 3.6 `crates/nvlens-bin`

- 大型密钥块放入 `keys/<engine>/*.bin`，禁止 `include_bytes!`。路径常量放在 `nvlens_bin::keys::<engine>`，调用方统一使用 `nvlens_bin::load`，返回并缓存 `Arc<[u8]>`。
- `build.rs` 递归复制到产物同级 `bin/<engine>/`，保留目录层级，对目录和每个 key 发出 `cargo:rerun-if-changed`。
- 支持外部密钥目录配置及相对可执行文件的资产加载。发布时携带 bin 目录，不依赖开发期源码路径；此 crate 不放解密或格式逻辑。
- 短口令可用格式常量，小型 scheme 可用 JSON，字节数组用 hex。游戏参数属于引擎模块；用户选择通过 trait 交给宿主，库不读 stdin、不弹窗。
- 密钥长度、编码和表结构遵循所属算法或格式，不设置全局大小限制。

### 3.7 `crates/nvlens-archive`

- 每个引擎一个 `src/<engine>/`，格式类型实现 `Format`、`ArchiveFormat`；格式声明与 `register_archive!` 可放在引擎 `mod.rs` 或具体格式文件中，每个格式只注册一次。新增格式同时接入模块声明和测试。
- 挂载封包必须懒加载：只读取、解析索引及其必要元信息，保存条目的位置和读取参数；`ArchiveFormat::open()`、`entries()` 和列表展示不预读条目内容，也不批量解压、解密或解码资源。
- 访问哪个条目，才在 `open_entry()` / `open_entry_raw()` 中读取该条目并按格式处理；索引自身需要的解压、解密与条目内容处理分开。嵌套封包和关联数据文件同样按访问需要打开，缓存仅保存已经请求的数据。
- 按格式规定检查签名、版本、条目数和索引范围；计数由字段宽度、索引布局和实际数据推导，不使用 `is_sane_count` 一类人为阈值。名称按原格式解析与保留，存储范围按实际数据源校验，落盘路径由输出层处理。
- Entry 的 offset/size 表示所在文件内的存储范围，压缩信息用 `Option<Packed>`，类型用 `ResourceKind`。索引、密钥和视图保存在 Archive 实例中，不用全局可变状态。
- 原始切片返回 `Cow::Borrowed`，变换后返回 `Cow::Owned`。有独立原始数据路径时覆盖 `open_entry_raw()`，其默认实现委托 `open_entry()`。容器调用 audio/script 处理内嵌资源，不复制跨域解析。

### 3.8 `crates/nvlens-{image,audio,script,video}`

- image：先读取元信息再解码像素；使用自有 Image/PixelBuffer 模型，通用与专有图像处理均在本域。导出保留图像偏移等格式元信息，不依赖 GUI 类型。
- audio：负责音频识别、解密、解码与导出，PCM 保留采样率、声道等信息。原样提取保留通用编码，播放设备属于 GUI。
- script：负责脚本和结构化资源。字节码做到 disasm，以通用、可扩展的 IR 保存指令、操作数、表达式 token、源位置和未知字段，不要求高层源码还原；纯文本可直接展示。
- 引擎识别及 PE 密钥提取统一由 engine 提供，资源域接收已解析参数，不自行扫描 EXE 或尝试其它引擎；命令表等关联脚本按访问需要读取。
- video：只处理视频资源；通用容器逻辑留在 archive。按实际格式需求补齐抽象，不预建无调用方框架。

### 3.9 测试

- 单元测试放在同文件 `#[cfg(test)] mod tests`，使用 `use super::*;`；集成测试放在对应 crate 的 `tests/`。
- 识别覆盖 PE 证据优先级、未知引擎、冲突、密钥缺失及无回退路由；格式覆盖签名、正常提取、错误输入、截断、边界和文件名安全；算法提供已知输入/输出向量，解码器提供像素、PCM、文本摘要或条目列表黄金测试。
- 归档测试验证懒加载：挂载和列索引不读取条目内容；访问单个条目只触发其所需读取与变换，未访问条目的内容错误不影响挂载。
- 优先合成数据和许可明确的最小样本。受限游戏资源不入库，本机样本测试用 `#[ignore]` 并说明获取和运行方式；临时目录唯一且用后清理。
- 测试以格式规定的合法与非法数据为依据，覆盖大文件、多条目和嵌套变体，不为人为限制编写拒绝测试；探测、解析和解压入口逐步接入 fuzz，检查越界、溢出及遍历错误。

## 4. 取消、进度与错误

- 长任务的取消和进度通过宿主 trait 或回调传入，阶段及循环边界响应取消；跳过项计入进度，取消返回 `Error::Cancelled`，不得按条目损坏继续处理。
- 域库使用 `nvlens_core::Error` / `Result`；io、crypto、bin 保持依赖方向，不反向引用 core。引擎识别返回 `Ok(Some(_))` 表示识别完成、`Ok(None)` 表示未知引擎；封包定向打开失败必须返回错误，不把损坏作为尝试其它格式的信号。
- 越界经 `Error::Io` 保留 `UnexpectedEof`；损坏用 `Corrupt { offset, reason }`，不支持用 `Unsupported`，未知密钥用 `UnknownScheme`。错误保留原因链及格式、条目、偏移上下文。
- 日志和错误信息使用英文，库只用 `tracing`，最终错误由宿主展示一次；不输出密钥或大块二进制内容。

## 5. 代码风格

### 格式

- 排版统一使用 `cargo fmt --all`；文件使用无 BOM 的 UTF-8、LF 和末尾换行。

### 语言特性

- 库正常路径禁止 `unwrap`、`expect`、`panic!`、`unreachable!`、`todo!`，失败返回 Result；测试确需 unwrap 时局部添加 `#[allow(clippy::unwrap_used)]`。
- 默认使用 `#![forbid(unsafe_code)]`；确需 mmap 或 SIMD 的 crate 可使用 `#![deny(unsafe_code)]`，仅在经过审查的最小封装模块内局部允许。每处 unsafe 前写 `// SAFETY:` 说明边界、对齐、别名及 CPU 特性等不变量；新增需求说明理由并补测试，SIMD 保留标量回退并验证结果一致。
- 文件偏移和长度用 `u64`，内存索引用 `usize`，转换优先 `TryFrom`。边界计算用 `checked_*`，协议回绕用 `wrapping_*`，饱和语义用 `saturating_*`；算术右移显式使用有符号类型。
- 优先借用与 Cow，避免无意义 clone；公共状态用 enum/newtype，类型按需实现 Debug/Clone 等 trait，重要返回值标记 `#[must_use]`，Debug 不泄露密钥。

### 命名

- 类型、trait、枚举成员用 `UpperCamelCase`；函数、变量、模块用 `snake_case`；常量用 `SCREAMING_SNAKE_CASE`。不顺带重命名无关代码。

### 文件组织

- `lib.rs` 只放模块声明、公开导出和 `init()`。按引擎与职责组织文件，不新增泛化的 utils/helpers 目录。
- 引擎 `mod.rs` 可集中放格式元数据、签名、识别与分派逻辑，以及引擎共享代码；复杂的索引解析和解码实现按格式拆到独立文件。

### 注释

- 代码注释和 doc 使用英文。格式文件顶部说明格式依据、布局、字节序、关键变换及变体；公共入口说明错误、所有权和缓冲约束，不复述代码。
- 依据写可核对的类名、方法、字段或逆向位置，不引用不存在的报告或本机路径。算法常数和位运算保持可验证，不做未经验证的等价化简。

## 6. 简洁性：不写与要删除的代码

以下写法不得新增；清理时保持格式行为和安全约束，限定在任务相关范围：

- **无用封装**：一对一字段复制的中间类型、纯转发薄封装、没有替换需求的 trait，以及仅为测试增加的生产选项。
- **无调用方的成员**：不可达开关、分支或输出。删除前用 `rg` 核对源码、测试、宏注册和公开 API 用途；不能误删 inventory 注册或第三方可用的扩展点。
- **无意义赋值**：只写不读、立即覆盖、无用别名和临时集合复制；只需跳过的字段直接读过，仍保留范围检查。
- **过度防御**：格式没有要求的大小、数量、长度或深度阈值；重复校验已由类型或受控内部契约保证的条件；对固定内部常量做运行期检查。
- **重复实现**：已有二进制 I/O、算法、key 加载或域入口覆盖的功能；只为合并相似代码而新增跨引擎抽象。

保留格式本身要求的签名、版本、范围、计数、校验和及结构一致性检查，以及落盘路径处理、取消和进度。格式变体差异、原始读取路径、格式依据注释和正式扩展点按实际需要保留；任何格式约束都应能说明其依据。

## 7. 验证

代码或 Cargo 配置修改后，在仓库根目录按顺序执行；失败时先修复再进入下一步：

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

- 格式失败先运行 `cargo fmt --all`；Clippy 零告警、workspace 测试全部通过。新增格式同时确认注册和对应样本测试。
- GUI 交互由用户自行测试。代理不主动启动或操作 GUI，不进行界面截图、点击、播放等交互验证；继续执行编译、静态检查、库层测试和不启动界面的数据处理测试。
- 修改 key 复制、外部资产路径或 build script 后，追加 `cargo clean -p nvlens-bin`、`cargo test -p nvlens-bin`，确认产物同级 `bin/<engine>/*.bin` 层级与加载正常，不能只依赖源码 fallback。
- 纯文档修改核对路径、命令和实现，执行 `git diff --check -- <修改的文档>`，无需运行 Rust 测试。未执行或失败的检查如实说明。

## 8. 文档与交付

- README 只写如何构建和支持的封包，不写使用方法或增加其它章节；构建方式和支持范围变化时同步更新，不把规划写成现有能力。
- 保留已有未提交改动，不执行丢弃或隐藏它们的 checkout/restore/reset/stash/clean；未经明确要求不提交或推送。
- 不提交 target、测试输出、提取结果和受限样本。源 key 放 `crates/nvlens-bin/keys/`，发布 bin 为构建产物；外部代码和数据保留必要许可证与署名。
- 提交使用 `type(scope): summary`，scope 为 crate 或引擎，summary 用英文祈使句；一个提交聚焦单一改动，一个 PR 聚焦一个引擎或一组相关格式。
- 交付说明变更内容、验证结果和未完成检查；新增依赖、MSRV 或资产布局变化写明理由。
