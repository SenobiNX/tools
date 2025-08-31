#!/usr/bin/env python3

import argparse
import os
import sys

from common import *


def main():
    parser = argparse.ArgumentParser(description="generate PFS0 file from directory")
    parser.add_argument("indir")
    parser.add_argument("outfile", nargs="?")
    # parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()

    abort_unless(os.path.isdir(args.indir), "input dir doesn't exist")
    outfile = f"{args.indir}.nsp" if args.outfile is None else args.outfile

    filenames = os.listdir(args.indir)
    entry_count = len(filenames)
    entries_offset = 0x10
    string_pool_offset = entries_offset + 0x18 * entry_count

    outf = open(outfile, "wb")

    # write filenames to string pool
    string_offsets = {}
    outf.seek(string_pool_offset)
    for filename in filenames:
        abort_unless(not os.path.isdir(os.path.join(args.indir, filename)), "input dir mustn't contain other directories")
        string_offsets[filename] = outf.tell() - string_pool_offset
        write_string(outf, filename)
        write_bytes(outf, b"\x00")
    align(outf, 0x10)
    data_offset = outf.tell()
    string_pool_size = data_offset - string_pool_offset
    
    # write file header
    outf.seek(0)
    write_string(outf, "PFS0")
    write_u32(outf, entry_count)
    write_u32(outf, string_pool_size)

    # write PFS0 entries
    entry_data_offset = data_offset
    for i, filename in enumerate(filenames):
        string_offset = string_offsets[filename]
        entry_offset = entries_offset + 0x18 * i

        outf.seek(entry_data_offset)
        with open(os.path.join(args.indir, filename), "rb") as f:
            while (chunk := f.read(0x100000)):
                write_bytes(outf, chunk)
        entry_size = outf.tell() - entry_data_offset

        outf.seek(entry_offset)
        write_u64(outf, entry_data_offset - data_offset)
        write_u64(outf, entry_size)
        write_u32(outf, string_offset)

        entry_data_offset += entry_size
            
if __name__ == "__main__":
    main()
