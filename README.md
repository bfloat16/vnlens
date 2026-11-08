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
| YU-RIS | YPF | Ogg Vorbis、WAV | YCG、PNG | YBN |
| WillPlus AdvHD | ARC、AR2 | Ogg Vorbis | PNG、PNA、MOS | WS2、JSON |
| BGI / Ethornell | PackFile、ARC20 | BW、HW | BGI Bitmap、CompressedBG v1/v2 | `_bp`、BSS |
| AGES-MK2 | FPD、DAT | FCD | — | EPK |
| SiglusEngine | PCK、OVK、NWK、OMV、Gameexe.dat | NWA、Ogg Vorbis | G00 | SS、GAN |
| ExHIBIT | AiFS／GRP | Ogg Vorbis、WAV | GYU、DLT | RLD、RNF／INI |
| krkrz_hxv4 | XP3 | Ogg Vorbis、Ogg Opus | PNG、TLG5 | TJS2、TJS／KS 文本、PSB／MDF（KS.SCN） |

| 中间件 | 封包 | 音频 | 图片 | 脚本 |
| --- | --- | --- | --- | --- |
| E-mote / M2 | PSB、MDF | — | — | — |
| Lua | — | — | — | Lua 5.0–5.5 字节码 |
