#!/usr/bin/env python3
# Copyright (c) 2025 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0

"""
Kernel payload reference value for td-shim td-payload-reference-calculator (kernel mode).

Logic aligned with:
https://github.com/confidential-containers/td-shim/blob/main/td-shim-tools/src/bin/td-payload-reference-calculator/main.rs
"""

import argparse
import hashlib
import sys
from pathlib import Path

# Matches td-payload-reference-calculator KERNEL_SIZE default
DEFAULT_KERNEL_SIZE = 0x2000000

# https://www.kernel.org/doc/html/latest/arch/x86/boot.html#details-of-header-fields
IMAGE_PROTOCOL_ADDR = 0x0206


def parse_size(s: str) -> int:
    t = s.strip()
    if t.startswith(("0x", "0X")):
        return int(t, 16)
    return int(t, 10)


def padding_digest(buf: bytearray, length: int) -> str:
    if len(buf) > length:
        raise ValueError("buffer length exceeds target size")
    diff = length - len(buf)
    buf.extend(b"\x00" * diff)
    return hashlib.sha384(buf).hexdigest()


def kernel_reference(path: Path, size: int) -> str:
    file_size = path.stat().st_size
    if file_size > size:
        raise ValueError("file size must be less than or equal to kernel-size")
    buf = bytearray(path.read_bytes())
    if len(buf) < IMAGE_PROTOCOL_ADDR + 2:
        raise ValueError(
            f"kernel image too short for protocol field at 0x{IMAGE_PROTOCOL_ADDR:X}"
        )
    protocol = int.from_bytes(
        buf[IMAGE_PROTOCOL_ADDR : IMAGE_PROTOCOL_ADDR + 2], "little"
    )
    if protocol < 0x0206:
        raise ValueError("protocol version must be 2.06+ (field at 0x206 >= 0x0206)")
    return padding_digest(buf, size)


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Compute td-payload kernel reference (SHA384 hex over vmlinuz padded to "
            "KERNEL_SIZE), matching td-shim td-payload-reference-calculator kernel mode."
        )
    )
    p.add_argument(
        "-k",
        "--kernel",
        required=True,
        type=Path,
        help="path to vmlinuz (bzImage) kernel image",
    )
    p.add_argument(
        "-s",
        "--size",
        default=hex(DEFAULT_KERNEL_SIZE),
        help=f"KERNEL_SIZE of target td-shim (decimal or 0x hex) [default: {hex(DEFAULT_KERNEL_SIZE)}]",
    )
    args = p.parse_args()
    try:
        size = parse_size(args.size)
        out = kernel_reference(args.kernel, size)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
