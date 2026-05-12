# Reference Value Calculator

本仓库提供一组与 **td-shim / 机密容器** 场景相关的参考值计算脚本，以及容器镜像清单 digest 查询工具。各脚本尽量与上游实现对齐，便于与 [td-shim](https://github.com/confidential-containers/td-shim) 工具链对照。

## 依赖

- **Python 3.7+**（已避免依赖 `from __future__ import annotations`，以便在较旧解释器上运行；推荐使用 **3.10+**。）
- 仅使用标准库（无需 `pip install`）。

## 脚本一览

| 脚本 | 作用 |
|------|------|
| `td_shim.py` | 由 shim 二进制计算 **MRTD**（SHA384 十六进制）。 |
| `kernel.py` | 由 **vmlinuz** 与填充大小计算 **kernel** 模式下的 td-payload 参考值（SHA384 十六进制）。 |
| `kernel_cmdline.py` | 由 **内核命令行字符串** 与填充大小计算 **param** 模式下的参考值（SHA384 十六进制）。 |
| `image_digest.py` | 解析容器镜像 reference，输出一行 **`sha256:` + 64 位十六进制**（manifest digest）。 |

---

### `td_shim.py` — Shim MRTD

从 td-shim（或兼容布局）镜像文件计算 MRTD 测量值。

```bash
python3 td_shim.py -i <shim二进制路径> [-l info|debug|error|warn|off]
```

示例：

```bash
python3 td_shim.py -i path/to/td-shim.bin
```

成功时向标准输出打印 **一行** 小写十六进制（SHA384，无 `0x` 前缀）。

---

### `kernel.py` — Kernel 参考值（td-payload-reference-calculator `kernel` 模式）

逻辑与上游 `td-payload-reference-calculator` 的 **kernel** 子命令一致（协议版本检查、`KERNEL_SIZE` 零填充后整段 SHA384），参见：

[td-shim `main.rs`（kernel / padding_digest）](https://github.com/confidential-containers/td-shim/blob/main/td-shim-tools/src/bin/td-payload-reference-calculator/main.rs)

```bash
python3 kernel.py -k <vmlinuz路径> [-s <KERNEL_SIZE>]
```

- **`-k` / `--kernel`**：bzImage / vmlinuz 文件路径（必填）。
- **`-s` / `--size`**：目标 td-shim 的 `KERNEL_SIZE`（十进制或 `0x` 十六进制），默认 **`0x2000000`**。

约束（与上游一致）：

- 文件大小不得超过 `KERNEL_SIZE`。
- 映像 `0x206` 处 x86 boot protocol 版本字段须 **≥ 0x0206**（2.06+）。

示例：

```bash
python3 kernel.py -k /boot/vmlinuz-$(uname -r)
python3 kernel.py -k ./vmlinuz -s 0x2000000
```

---

### `kernel_cmdline.py` — 内核命令行参考值（`param` 模式）

逻辑与上游 **param** 子命令一致：将参数字符串按 **UTF-8** 编码为字节，零填充至 `KERNEL_PARAM_SIZE` 后对整段做 **SHA384**，输出小写十六进制（无前缀）。

```bash
python3 kernel_cmdline.py -p "<内核命令行>" [-s <KERNEL_PARAM_SIZE>]
```

- **`-p` / `--parameter`**：内核命令行字符串（必填）。
- **`-s` / `--size`**：目标 td-shim 的 `KERNEL_PARAM_SIZE`，默认 **`0x1000`**。

参数字节长度不得超过 `KERNEL_PARAM_SIZE`。

示例：

```bash
python3 kernel_cmdline.py -p "console=ttyS0 root=/dev/vda1 ro"
python3 kernel_cmdline.py -p "quiet" -s 0x1000
```

---

### `image_digest.py` — 容器镜像 manifest digest

查询镜像在仓库中的 **manifest digest**。标准输出**仅一行**，格式固定为 **`sha256:` + 64 位小写十六进制**（不含 `repo@` 等前缀）。若引用已带 `@sha256:…`，则校验后原样规范化输出。

```bash
python3 image_digest.py <镜像引用>
```

示例：

```bash
python3 image_digest.py alpine:3.19
python3 image_digest.py docker.io/library/nginx:latest
```

说明与限制（私有仓库、ECR 等）见脚本内注释；需联网访问 registry。

---

## 许可证

仓库内 `LICENSE`（如 Apache-2.0）为准；各脚本文件头 SPDX 标识与上游约定一致处已标注。
