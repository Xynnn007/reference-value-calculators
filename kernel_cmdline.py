#!/usr/bin/env python3
# Copyright (c) 2025 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0

"""
Kernel command-line payload reference value for td-shim td-payload-reference-calculator (param mode).

Logic aligned with:
https://github.com/confidential-containers/td-shim/blob/main/td-shim-tools/src/bin/td-payload-reference-calculator/main.rs
"""

from __future__ import annotations

import argparse
import hashlib
import sys


# Matches td-payload-reference-calculator KERNEL_PARAM_SIZE default
DEFAULT_PARAM_SIZE = 0x1000


def parse_size(s: str) -> int:
    t = s.strip()
    if t.startswith(("0x", "0X")):
        return int(t, 16)
    return int(t, 10)


def padding_digest(buf: bytearray, length: int) -> str:
    if len(buf) > length:
        raise ValueError("parameter byte length exceeds target size")
    diff = length - len(buf)
    buf.extend(b"\x00" * diff)
    return hashlib.sha384(buf).hexdigest()


def param_reference(parameter: str, size: int) -> str:
    # Rust tool takes a string; use UTF-8 bytes (ASCII cmdline is a subset).
    buf = bytearray(parameter.encode("utf-8"))
    return padding_digest(buf, size)


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Compute td-payload kernel cmdline reference (SHA384 hex over parameter "
            "bytes padded to KERNEL_PARAM_SIZE), matching td-payload-reference-calculator "
            "param mode."
        )
    )
    p.add_argument(
        "-p",
        "--parameter",
        required=True,
        help='kernel command-line string (e.g. "console=ttyS0 ...")',
    )
    p.add_argument(
        "-s",
        "--size",
        default=hex(DEFAULT_PARAM_SIZE),
        help=f"KERNEL_PARAM_SIZE of target td-shim (decimal or 0x hex) [default: {hex(DEFAULT_PARAM_SIZE)}]",
    )
    args = p.parse_args()
    try:
        size = parse_size(args.size)
        out = param_reference(args.parameter, size)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
