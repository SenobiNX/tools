#!/usr/bin/env python3

import argparse
import os
import shutil
import struct
import sys
import typing


def abort(msg: str):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)

def abort_unless(cond: bool, msg: str):
    if not cond:
        abort(msg)


def read_bytes(data: bytes, offset: int, size: int) -> bytes:
    abort_unless(offset + size < len(data), "unexpected EOF")
    return data[offset:offset+size]

def read_string(data: bytes, offset: int, size: int = -1, encoding_name: str = "ascii") -> str:
    if size == -1:
        out = b""
        i = 0
        while (char := read_bytes(data, offset+i, 1)) != b'\x00':
            out += char
            i += 1
    else:
        out = read_bytes(data, offset, size)
    
    return out.decode(encoding_name)

def read_signature(data: bytes, offset: int, size: int, expected: str) -> str:
    signature = read_string(data, offset, size)
    abort_unless(signature == expected, f"file signature was {signature}, expected {expected}")
    return signature

def read_u8(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 1)
    return int(*struct.unpack("<B", out))

def read_u16(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 2)
    return int(*struct.unpack("<H", out))

def read_u32(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 4)
    return int(*struct.unpack("<I", out))

def read_u64(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 8)
    return int(*struct.unpack("<Q", out))

def align(offset: int, alignment: int):
    delta = (-offset % alignment + alignment) % alignment
    return offset + delta

def pretty_size(size: int) -> str:
    if size < 1024:
        return "{} ".format(size)
    elif size < 1024 * 1024:
        return "{:.1f}K".format(size / 1024)
    elif size < 1024 * 1024 * 1024:
        return "{:.1f}M".format(size / 1024 / 1024)
    elif size < 1024 * 1024 * 1024 * 1024:
        return "{:.1f}G".format(size / 1024 / 1024 / 1024)
    else:
        return "{}".format(size)

def main():
    parser = argparse.ArgumentParser(description="extract PFS0 file to directory")
    parser.add_argument("infile")
    parser.add_argument("outdir", nargs="?")
    parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()

    abort_unless(os.path.isfile(args.infile), "input file doesn't exist")
    outdir = os.path.splitext(args.infile)[0] if args.outdir is None else args.outdir

    os.makedirs(outdir, exist_ok=True)

    with open(args.infile, "rb") as f:
        header = f.read(0x10)
    
        read_signature(header, 0x0, 4, "PFS0")
        entry_count = read_u32(header, 0x4)
        string_pool_size = read_u32(header, 0x8)
        string_pool_offset = 0x10 + 0x18 * entry_count
        data_offset = string_pool_offset + string_pool_size

        if entry_count == 0:
            print("finished (PFS0 entry count: 0)")
            return 0

        f.seek(string_pool_offset)
        string_pool = f.read(string_pool_size)

        entries = []
        f.seek(0x10)
        for i in range(entry_count):
            entry_header = f.read(0x18)
            offset = read_u64(entry_header, 0x0)
            size = read_u64(entry_header, 0x8)
            name_offset = read_u32(entry_header, 0x10)

            name = read_string(string_pool, name_offset)
            entry_data_offset = data_offset + offset

            entries.append((entry_data_offset, size, name))
        
        if not args.quiet:
            longest_name_len = max(map(lambda k: len(k[2]), entries))
            longest_size_len = max(map(lambda k: len(pretty_size(k[1])), entries))
            print("{:^{width}} | size".format("file name", width=longest_name_len))
            print("{}+{}".format("-" * (longest_name_len + 1), "-" * (longest_size_len + 2)))

            for _, size, name in sorted(entries, key=lambda k: k[1], reverse=True):
                print("{:{name_width}} | {:>{size_width}}".format(name, pretty_size(size), name_width=longest_name_len, size_width=longest_size_len))
            
            print()

        for offset, size, name in entries:
            out_path = os.path.join(outdir, name)

            if not args.quiet:
                print("copying {} to {}...".format(name, out_path))

            f.seek(offset)
            with open(out_path, "wb") as outf:
                shutil.copyfileobj(f, outf, size)


if __name__ == "__main__":
    main()
