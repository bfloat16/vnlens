# nvlens

## 构建

安装 rustup 和 Visual Studio C++ 生成工具（MSVC 与 Windows SDK）。仓库固定 Rust 1.99.1，GUI 使用 GPUI 0.2.2。视频预览链接 FFmpeg 9 共享库，生成 FFmpeg 绑定需要 LLVM（libclang）；首次构建前执行 `cargo ffmpeg`，下载固定版本的 FFmpeg-Builds win64 LGPL shared 包，校验 SHA-256 后解压到 `target/ffmpeg/9.0/`，之后直接复用。使用其它 FFmpeg 9 共享构建时设置 `FFMPEG_DIR`。

```bash
cargo ffmpeg
cargo build --release
```

程序位于 `target/release/nvlens.exe`。分发时一并携带 `THIRD_PARTY_NOTICES.md`、`target/release/` 下的 FFmpeg DLL 和 `target/release/bin/`，保留其中引擎目录与密钥文件。

Enigma section 解密与内嵌 EVB 读取使用 `enigma_rs` 的恢复逻辑，默认构建包含 CPU 和 wgpu salt 搜索后端；wgpu 不可用时使用 CPU。wgpu 后端通过固定版本 CubeCL 0.10.0 构建，无需 CUDA Toolkit。分发时同时携带 `licenses/`。

## 支持的格式

| 引擎 | 封包 | 音频 | 图片 | 脚本 | 视频 |
| --- | --- | --- | --- | --- | --- |
| Softpal | `.pac` | `.ogg` | `.pgd`、`.jpg`、`.tga` | `.src`、`.dat`、`.csv`、`.txt`、`.ini` | `<ffmpeg>` |
| C,system | `.dat` | `head("Tink")`、`.j0`、`.k0`、`.u0`、`.ogg` | `.b0`、`.n0`、`.o0`、`.cimg`、`head("a")`、`head("b")`、`head("c")`、`head("d")` | `.a0`、`.b0`、`.c0`、`.e0`、`.f0`、`.i0`、`.l0`、`.m0`、`.q0`、`.r0`、`.s0`、`.t0`、`.v0`、`.x0` | `.y0`、`<ffmpeg>` |
| Kaleido ADV Workshop | `.psb`、`.m`、`.bin` | `.xwma` | `.dds` | `.nut`、`.scn`、`.ks`、`.psb` | `.webm`、`<ffmpeg>` |
| YU-RIS | `.ypf` | `.ogg`、`.wav` | `.ycg`、`.png` | `.ybn` | `.ymv`、`<ffmpeg>` |
| WillPlus AdvHD | `.arc`、`.ar2` | `.ogg` | `.png`、`.pna`、`.mos` | `.ws2`、`.json` | `.dat`、`<ffmpeg>` |
| BGI / Ethornell | `.arc` | `.bw`、`.hw`、`._bw`、`.ogg`、`head("bw  ")`、`head("hw  ")` | `.bgi`、`.bg`、`._bg`、`head("CompressedBG___\0")` | `._bp`、`.bss`、`head("BurikoCompiledScriptVer1.00\0")`、`hex("10000000")` | `<ffmpeg>` |
| AGES-MK2 | `.fpd`、`.dat` | `.fcd`、`head("FCD\0")` | — | `.epk` | — |
| SiglusEngine | `.pck`、`.ovk`、`.nwk`、`.omv`、`.dat` | `.nwa`、`.ogg` | `.g00` | `.ss`、`.gan` | `.omv` |
| ExHIBIT | `.grp` | `.ogg`、`.wav` | `.gyu`、`.lvg`、`.dlt` | `.rld`、`.rnf`、`.ini` | `<ffmpeg>` |
| escude | `.bin` | `.ogg` | `.png` | `.c`、`.h`、`.inc`、`.txt`、`.cfg`、`.001`、`.bin`、`.lsf`、`.mot`、`.sfx` | — |
| propeller | `.mpk` | `.ogv`、`.wav` | `.mgr` | `.msc` | `.mpk` |
| rugp | `.rio`、`.ici`、`.ruo` | `.oor`、`.coptimizedobs`、`.coptimizedobsforr` | `.cr6ti`、`.cr6tix`、`.crmti`、`.cs5i`、`.csbm`、`.cicon`、`.crsi_frame` | `.crsa`、`.cprocessocean`、`.cstdb`、`.crsi`、`.cs5rfont`、`hex("a4cbf629")`、`hex("7c92db1e")`、`hex("cd326e59")` | — |
| SystemNNN | `.gpk`、`.gtb`、`.vpk`、`.vtb` | `.vaw`、`.wgq` | `.dwq` | `.spt`、`.fxf`、`.xtx`、`.mml` | — |
| krkr | `.xp3` | `.ogg`、`.opus` | `.png`、`.tlg`、`.tlg5`、`.tlg6` | `.tjs`、`.ks`、`.scn`、`.asd` | `<ffmpeg>` |
| krkrz_hxv4 | `.xp3` | `.ogg`、`.opus` | `.png`、`.tlg`、`.tlg5`、`.tlg6` | `.tjs`、`.ks`、`.scn`、`.psb`、`.m` | `<ffmpeg>` |

| 中间件 | 封包 | 音频 | 图片 | 脚本 | 视频 |
| --- | --- | --- | --- | --- | --- |
| E-mote / M2 | `.psb`、`.mdf`、`.m`、`.bin`、`head("mzs\0")` | `.xwma` | `.dds` | — | — |
| Enigma / EVB | `.exe`、`.dll` | — | — | — | — |
| Lua | — | — | — | `.lua`、`.luac`、`head("\x1bLua")` | — |
