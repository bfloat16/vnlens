# nvlens

## 构建

安装 rustup 和 Visual Studio C++ 生成工具（MSVC 与 Windows SDK）。仓库固定 Rust 1.99.1，GUI 使用 GPUI 0.2.2。

```bash
cargo build --release
```

程序位于 `target/release/nvlens.exe`。分发时一并携带 `THIRD_PARTY_NOTICES.md` 和 `target/release/bin/`，保留其中引擎目录与密钥文件。

## 支持的格式

| 引擎 | 封包 | 音频 | 图片 | 脚本 |
| --- | --- | --- | --- | --- |
| YU-RIS | `.ypf` | `.ogg`、`.wav` | `.ycg`、`.png` | `.ybn` |
| WillPlus AdvHD | `.arc`、`.ar2` | `.ogg` | `.png`、`.pna`、`.mos` | `.ws2`（CP932／UTF-16LE）、`.json` |
| BGI / Ethornell | `.arc` | `.bw`、`.hw`、`._bw`、`.ogg`、`head("bw  ")`、`head("hw  ")` | `.bgi`、`.bg`、`._bg`、`head("CompressedBG___\0")` | `._bp`、`.bss`、`head("BurikoCompiledScriptVer1.00\0")`、`hex("10000000")` |
| AGES-MK2 | `.fpd`、`.dat` | `.fcd`、`head("FCD\0")` | — | `.epk` |
| SiglusEngine | `.pck`、`.ovk`、`.nwk`、`.omv`、`.dat` | `.nwa`、`.ogg` | `.g00` | `.ss`、`.gan` |
| ExHIBIT | `.grp` | `.ogg`、`.wav` | `.gyu`、`.lvg`、`.dlt` | `.rld`、`.rnf`、`.ini` |
| escude | `.bin` | `.ogg` | `.png` | `.c`、`.h`、`.inc`、`.txt`、`.cfg`、`.001`、`.bin`、`.lsf`、`.mot`、`.sfx` |
| propeller（Stuff v1.0a） | `.mpk` | `.ogv`（Ogg Vorbis）、`.wav` | `.mgr`（LZF BMP，多帧与透明通道） | `.msc`（标签表、七组字节码指令、CP932 文本） |
| rugp | `.rio`（`.ici` 索引、分卷、`.ruo` 对象补丁） | `COptimizedObs` → Ogg Vorbis | `Cr6Ti`、`Cr6Tix`、`CRmti`、`CS5i`、`CSbm`、ICO、`CRsi` RGB/YUV 关键帧与差分帧 | `CRsa`、序列化对象的原生父子层级及按需引用、`CRsi` 帧索引与原始帧提取、内嵌 `CS5RFont`；未实现的像素格式保留原始载荷 |
| SystemNNN | `.gpk`、`.gtb`、`.vpk`、`.vtb` | `.vaw`、`.wgq` | `.dwq` | `.spt`、`.fxf`、`.xtx`、`.mml` |
| krkr | `.xp3` | `.ogg`、`.opus` | `.png`、`.tlg`、`.tlg5`、`.tlg6` | `.tjs`、`.ks`、`.scn`、`.asd` |
| krkrz_hxv4 | `.xp3` | `.ogg`、`.opus` | `.png`、`.tlg`、`.tlg5`、`.tlg6` | `.tjs`、`.ks`、`.scn`、`.psb`、`.m` |

| 中间件 | 封包 | 音频 | 图片 | 脚本 |
| --- | --- | --- | --- | --- |
| E-mote / M2 | `.psb`、`.mdf`、`.m`、`.bin` | — | — | — |
| Lua | — | — | — | `.lua`、`.luac`、`head("\x1bLua")` |
