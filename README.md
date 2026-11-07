# nvlens

## 构建

安装 rustup 和 Visual Studio 2022 C++ 生成工具（MSVC 与 Windows SDK）。仓库固定 Rust 1.99.1，GUI 使用 GPUI 0.2.2。

```bash
cargo build --release
```

程序位于 `target/release/nvlens.exe`。分发时一并携带 `target/release/bin/`，保留其中引擎目录与密钥文件。

## 支持的封包

| 引擎 | 格式标签 | 扩展名 | 说明 |
| --- | --- | --- | --- |
| YU-RIS | `ypf/yuris` | `.ypf` | YU-RIS YPF 资源封包 |
| WillPlus AdvHD | `arc/willv2` | `.arc`、`.ar2` | Will Co. 引擎 v2 资源封包 |
| AGES-MK2 | `fpd` | `.fpd`、`.dat` | AGES-MK2 PackFile 资源封包 |
| E-mote / M2 | `psb/emote-archive-info` | `.psb`、`.m` | 配合同目录 `body.bin` 的索引封包 |
| E-mote / M2 | `psb/emote-resources` | `.psb`、`.m` | 独立 PSB 内嵌资源块 |

