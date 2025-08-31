#!/usr/bin/env python3

import argparse
import json
import sys

from common import *


def write_sac(contents: dict) -> BinaryWriter:
    writer = BinaryWriter()
    service_host = json_read_list(contents, "service_host")
    service_access = json_read_list(contents, "service_access")
    for service in service_host:
        abort_unless(isinstance(service, str), "services must be strings")
        abort_unless(1 <= len(service) <= 8, "services must be between 1 and 8 chars long")

        writer.write_u8(0x80 | (len(service) - 1))
        writer.write_string(service)
    
    for service in service_access:
        abort_unless(isinstance(service, str), "services must be strings")
        abort_unless(1 <= len(service) <= 8, "services must be between 1 and 8 chars long")
        
        writer.write_u8(len(service) - 1)
        writer.write_string(service)
    
    return writer


def write_acid(contents: dict, sac_writer: BinaryWriter, kc_writer: BinaryWriter) -> BinaryWriter:
    writer = BinaryWriter()

    writer.write_bytes(b"\x00"*0x100) # RSA2048 signature
    writer.write_bytes(b"\x00"*0x100) # RSA2048 public key

    writer.write_string("ACID")
    writer.seek_rel(4) # skip size for now
    writer.seek_rel(4) # TODO: skipped version and unknown 0x209 thingy
    
    acid_flags = 0
    acid_flags |= 0b00000001 if json_read_bool(contents, "is_retail") else 0
    acid_flags |= 0b00000010 if json_read_bool(contents, "unqualified_approval", False) else 0
    acid_flags |= json_read_int(contents, "pool_partition", 0, 3) << 2
    writer.write_u32(acid_flags)
    writer.write_u64(json_read_u64(contents, ("program_id_range_min", "title_id_range_min")))
    writer.write_u64(json_read_u64(contents, ("program_id_range_max", "title_id_range_max")))
    writer.seek_rel(0x20)
    
    # ACID - Filesystem Access Control

    fs_access = json_read_dict(contents, "filesystem_access")
    fs_permissions = json_read_u64(fs_access, "permissions")

    fac_offset = writer.position
    writer.write_u8(1) # version
    writer.write_u8(0) # content owner ID count
    writer.write_u8(0) # save data owner ID count
    writer.seek(fac_offset + 4)
    writer.write_u64(fs_permissions)
    writer.write_u64(0) # content owner ID min
    writer.write_u64(0) # content owner ID max
    writer.write_u64(0) # save data owner ID min
    writer.write_u64(0) # save data owner ID max
    fac_size = writer.position - fac_offset

    # ACID - Service Access Control

    writer.align(0x10)
    sac_offset = writer.position
    sac_size = len(sac_writer.stream)
    writer.seek(sac_offset)
    writer.write_sub(sac_writer)

    # ACID - Kernel Capabilities

    writer.align(0x10)
    kc_offset = writer.position
    kc_size = len(kc_writer.stream)
    writer.seek(kc_offset)
    writer.write_sub(kc_writer)

    acid_size = writer.position

    writer.seek(0x204)
    writer.write_u32(acid_size - 0x100)
    writer.seek(0x220)
    writer.write_u32(fac_offset)
    writer.write_u32(fac_size)
    writer.write_u32(sac_offset)
    writer.write_u32(sac_size)
    writer.write_u32(kc_offset)
    writer.write_u32(kc_size)

    print(hex(len(writer.stream)))

    return writer


def write_aci(contents: dict, sac_writer: BinaryWriter, kc_writer: BinaryWriter) -> BinaryWriter:
    writer = BinaryWriter()

    fs_access = json_read_dict(contents, "filesystem_access")
    content_owner_ids = json_read_list(fs_access, "content_owner_ids", [])
    save_data_owner_ids = json_read_list(fs_access, "save_data_owner_ids", [])
    fs_permissions = json_read_u64(fs_access, "permissions")

    writer.write_string("ACI0")
    writer.seek_rel(0xc) # reserved
    writer.write_u64(json_read_u64(contents, ("program_id", "title_id")))
    writer.seek_rel(0x8) # reserved
    writer.seek_rel(0x20) # skip over offsets and sizes for now

    # ACI - Filesystem Access Header

    fah_offset = writer.position
    writer.write_u32(1) # version
    writer.write_u64(fs_permissions)
    writer.seek_rel(0x10) # skip over coi/sdoi offsets + sizes for now
    
    coi_offset = writer.position
    if len(content_owner_ids):
        writer.write_u32(len(content_owner_ids))
    for coi in content_owner_ids:
        if isinstance(coi, int):
            val = coi
        elif isinstance(coi, str):
            val = int(coi, 16)
        else:
            abort(isinstance(coi, (int, str)), f"`content_owner_ids` entries must be integers")
        abort_unless(0 <= val <= (1 << 64) - 1, f"`content_owner_ids` entries must be between 0 and {(1 << 64) - 1:#x}")

        writer.write_u64(val)
    coi_size = writer.position - coi_offset
 
    sdoi_offset = writer.position
    if len(save_data_owner_ids):
        writer.write_u32(len(save_data_owner_ids))
    sdoi_accessibilities = []
    sdoi_ids = []
    for sdoi in save_data_owner_ids:
        abort_unless(isinstance(sdoi, dict), "`save_data_owner_ids` entries must be dicts")
        sdoi_accessibilities.append(json_read_int(sdoi, "accessibility", 1, 3))
        sdoi_ids.append(json_read_u64(sdoi, "id"))
    
    for accessibility in sdoi_accessibilities:
        writer.write_u8(accessibility)
    writer.align(4)
    for id_ in sdoi_ids:
        writer.write_u64(id_)
    sdoi_size = writer.position - sdoi_offset

    fah_size = writer.position - fah_offset
    writer.seek(fah_offset + 0xc)
    writer.write_u32(coi_offset - fah_offset) # content owner IDs offset
    writer.write_u32(coi_size) # content owner IDs size
    writer.write_u32(sdoi_offset - fah_offset) # save data owner IDs offset
    writer.write_u32(sdoi_size) # save data owner IDs size

    # ACI - Service Access Control

    writer.seek(fah_offset + fah_size)
    writer.align(0x10)
    sac_offset = writer.position
    writer.write_sub(sac_writer)

    # ACI - Kernel Capabilities

    writer.align(0x10)
    kc_offset = writer.position
    writer.write_sub(kc_writer)

    aci_size = writer.position

    writer.seek(0x20)
    writer.write_u32(fah_offset)
    writer.write_u32(fah_size)
    writer.write_u32(sac_offset)
    writer.write_u32(len(sac_writer.stream))
    writer.write_u32(kc_offset)
    writer.write_u32(len(kc_writer.stream))

    return writer


def write_meta(contents: dict) -> BinaryWriter:
    writer = BinaryWriter()

    writer.write_string("META")
    writer.write_u32(json_read_u32(contents, "signature_key_generation", 0))
    writer.seek_rel(0x4) # reserved

    cap = 0
    cap |= 0b00000001 if json_read_bool(contents, "is_64_bit") else 0
    cap |= json_read_int(contents, "address_space_type", 0, 3) << 1
    cap |= 0b00010000 if json_read_bool(contents, "optimize_memory_allocation", False) else 0
    cap |= 0b00100000 if json_read_bool(contents, "disable_device_address_space_merge", False) else 0
    cap |= 0b01000000 if json_read_bool(contents, "enable_alias_region_extra_size", False) else 0
    cap |= 0b10000000 if json_read_bool(contents, "prevent_code_reads", False) else 0
    writer.write_u8(cap)
    writer.seek(0xe)
    writer.write_u8(json_read_int(contents, "main_thread_priority", 0, 0x3f))
    writer.write_u8(json_read_u8(contents, "default_cpu_id"))
    writer.seek(0x14)
    writer.write_u32(json_read_int(contents, "system_resource_size", 0, 0x1fe00000, 0))
    writer.write_u32(json_read_u32(contents, "version", 0))

    main_thread_stack_size = json_read_u32(contents, "main_thread_stack_size")
    abort_unless(main_thread_stack_size & 0xfff == 0, "`main_thread_stack_size` must be aligned to 0x1000")
    writer.write_u32(main_thread_stack_size)

    name = json_read_str(contents, "name", max_len=0x10)
    writer.write_string(name, max_len=0x10)
    writer.write_bytes(b"\0"*16) # product code
    writer.seek_rel(0x30) # reserved
    writer.seek_rel(0x10) # skip ACI/ACID offsets + sizes for now

    return writer


def main():
    parser = argparse.ArgumentParser(description="generate NPDM file from JSON")
    parser.add_argument("infile")
    parser.add_argument("outfile", nargs="?")
    # parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()

    with open(args.infile) as f:
        contents = json.load(f)
    
    writer = BinaryWriter()

    sac_writer = write_sac(contents)
    kc_writer = write_kc(contents)

    # META section

    meta_writer = write_meta(contents)
    meta_size = len(meta_writer.stream)
    writer.write_sub(meta_writer)

    # ACID section

    writer.seek(meta_size)
    writer.align(0x10)
    acid_offset = writer.position
    acid_writer = write_acid(contents, sac_writer, kc_writer)
    acid_size = len(acid_writer.stream)
    writer.write_sub(acid_writer)

    # ACI section

    writer.align(0x10)
    aci_offset = writer.position
    aci_writer = write_aci(contents, sac_writer, kc_writer)
    aci_size = len(aci_writer.stream)
    writer.write_sub(aci_writer)

    # write ACI/ACID offsets + size into META

    writer.seek(0x70)
    writer.write_u32(aci_offset)
    writer.write_u32(aci_size)
    writer.write_u32(acid_offset)
    writer.write_u32(acid_size)

    writer.save(args.outfile)

if __name__ == "__main__":
    main()
