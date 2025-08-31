#!/usr/bin/env python3

import argparse
import json
import sys

# import ndspy.codeCompression as blz
from elftools.elf.elffile import ELFFile
from common import *

def main():
    parser = argparse.ArgumentParser(description="generate KIP file from ELF and JSON")
    parser.add_argument("in_elf")
    parser.add_argument("in_json")
    parser.add_argument("outfile", nargs="?")
    # parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()

    with open(args.in_json) as f:
        contents = json.load(f)
    
    writer = BinaryWriter()

    # write header

    header_size = 0x100

    is_use_compression = False
    is_64_bit = True

    flags  = 0b0000_0000
    flags |= 0b0000_0111 if is_use_compression else 0
    flags |= 0b0001_1000 if is_64_bit else 0
    flags |= 0b0010_0000 if json_read_bool(contents, "use_secure_memory", True) else 0
    flags |= 0b0100_0000 if json_read_bool(contents, "immortal", True) else 0

    writer.write_string("KIP1")
    writer.write_string(json_read_str(contents, "name", max_len=0xc), max_len=0xc)
    writer.write_u64(json_read_u64(contents, ("program_id", "title_id")))
    writer.write_u32(json_read_u32(contents, ("version", "process_category"), 1))
    writer.write_u8(json_read_int(contents, "main_thread_priority", 0, 0x3f))
    writer.write_u8(json_read_u8(contents, "default_cpu_id"))
    writer.seek_rel(1)
    writer.write_u8(flags)

    main_thread_stack_size = json_read_u32(contents, "main_thread_stack_size")
    abort_unless(main_thread_stack_size & 0xfff == 0, "`main_thread_stack_size` must be aligned to 0x1000")
    writer.seek(0x3c)
    writer.write_u32(main_thread_stack_size)

    # write kernel capabilities

    kc_writer = write_kc(contents)
    writer.seek(0x80)
    writer.write_bytes(b"\xff" * 0x80) # pad kernel caps section with FF
    writer.seek(0x80)
    writer.write_bytes(kc_writer.stream)

    # read ELF segment headers

    fp_elf = open(args.in_elf, "rb")
    elf = ELFFile(fp_elf)
    abort_unless(elf.get_machine_arch() in ("ARM", "AArch64"), "must be an ARM or AArch64 ELF")

    pt_load_segments = []
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_LOAD":
            pt_load_segments.append(segment)
    
    abort_unless(len(pt_load_segments) == 3, "expected 3 loadable segments")

    rx_segment = pt_load_segments[0]
    ro_segment = pt_load_segments[1]
    rw_segment = pt_load_segments[2]

    bss_start = round_up(rw_segment.header.p_filesz, 0x1000)
    bss_end = rw_segment.header.p_memsz
    bss_decomp_size = round_up(max(0, bss_end - bss_start), 0x1000)

    # write KIP segment headers

    file_offset = header_size
    mem_offset = 0

    for i, segment in enumerate((rx_segment, ro_segment, rw_segment)):
        decomp_size = segment.header.p_filesz
        elf.stream.seek(segment.header.p_offset)
        segment_data = elf.stream.read(decomp_size)

        with open(f"segment{i}.bin", "wb") as outf:
            outf.write(segment_data)

        writer.seek(file_offset)
        if is_use_compression:
            raise NotImplementedError("BLZ compression not supported")
        else:
            comp_size = writer.write_bytes(segment_data)

        writer.seek(0x20 + i * 0x10)
        writer.write_u32(mem_offset)
        writer.write_u32(decomp_size)
        writer.write_u32(comp_size)

        file_offset += comp_size
        mem_offset = round_up(mem_offset + decomp_size, 0x1000)

    # write BSS segment header

    writer.seek(0x50)
    writer.write_u32(mem_offset)
    writer.write_u32(bss_decomp_size)
    writer.write_u32(0) # BSS has no data in the compressed KIP file

    # Use ndspy for Compression (codeCompression.py for BLZ)
    # The footer is now 0xC bytes instead of 0x8, and has the form u32 compressed_data_len; u32 footer_size; u32 additional_len_when_uncompressed; 

    fp_elf.close()
    writer.save(args.outfile)

if __name__ == "__main__":
    main()
