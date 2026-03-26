#!/usr/bin/env python3

import argparse

from common import *


ADDRESS_SPACE = {
    0: "32 bit",
    1: "64 bit (old)",
    2: "32 bit (no alias)",
    3: "64 bit"
}

FS_ACCESS_FLAGS = {
    0: "ApplicationInfo",
    1: "BootModeControl",
    2: "Calibration",
    3: "SystemSaveData",
    4: "GameCard",
    5: "SaveDataBackUp",
    6: "SaveDataManagement",
    7: "BisAllRaw",
    8: "GameCardRaw",
    9: "GameCardPrivate",
    10: "SetTime",
    11: "ContentManager",
    12: "ImageManager",
    13: "CreateSaveData",
    14: "SystemSaveDataManagement",
    15: "BisFileSystem",
    16: "SystemUpdate",
    17: "SaveDataMeta",
    18: "DeviceSaveData",
    19: "SettingsControl",
    20: "SystemData",
    21: "SdCard",
    22: "Host",
    23: "FillBis",
    24: "CorruptSaveData",
    25: "SaveDataForDebug",
    26: "FormatSdCard",
    27: "GetRightsId",
    28: "RegisterExternalKey",
    29: "RegisterUpdatePartition",
    30: "SaveDataTransfer",
    31: "DeviceDetection",
    32: "AccessFailureResolution",
    33: "SaveDataTransferVersion2",
    34: "RegisterProgramIndexMapInfo",
    35: "CreateOwnSaveData",
    36: "MoveCacheStorage",
    37: "DeviceTreeBlob",
    38: "NotifyErrorContextServiceReady",
    39: "CalibrationSystemData",
    40: "CalibrationLog",
    41: "StorageSecure",
    42: "StorageControl",
    43: "GameCardReport",
    44: "MarkBeforeEraseBis",
    62: "Debug",
    63: "FullPermission"
}

KERNEL_CAPS = {
    3: "core_priority",
    4: "syscalls",
    6: "map_range",
    7: "map_io_page",
    10: "map_region",
    11: "interrupts",
    13: "program_type",
    14: "kernel_version",
    15: "handle_table_size",
    16: "misc_flags"
}

SVC = {
    0x01: "SetHeapSize",
    0x02: "SetMemoryPermission",
    0x03: "SetMemoryAttribute",
    0x04: "MapMemory",
    0x05: "UnmapMemory",
    0x06: "QueryMemory",
    0x07: "ExitProcess",
    0x08: "CreateThread",
    0x09: "StartThread",
    0x0a: "ExitThread",
    0x0b: "SleepThread",
    0x0c: "GetThreadPriority",
    0x0d: "SetThreadPriority",
    0x0e: "GetThreadCoreMask",
    0x0f: "SetThreadCoreMask",
    0x10: "GetCurrentProcessorNumber",
    0x11: "SignalEvent",
    0x12: "ClearEvent",
    0x13: "MapSharedMemory",
    0x14: "UnmapSharedMemory",
    0x15: "CreateTransferMemory",
    0x16: "CloseHandle",
    0x17: "ResetSignal",
    0x18: "WaitSynchronization",
    0x19: "CancelSynchronization",
    0x1a: "ArbitrateLock",
    0x1b: "ArbitrateUnlock",
    0x1c: "WaitProcessWideKeyAtomic",
    0x1d: "SignalProcessWideKey",
    0x1e: "GetSystemTick",
    0x1f: "ConnectToNamedPort",
    0x20: "SendSyncRequestLight",
    0x21: "SendSyncRequest",
    0x22: "SendSyncRequestWithUserBuffer",
    0x23: "SendAsyncRequestWithUserBuffer",
    0x24: "GetProcessId",
    0x25: "GetThreadId",
    0x26: "Break",
    0x27: "OutputDebugString",
    0x28: "ReturnFromException",
    0x29: "GetInfo",
    0x2a: "FlushEntireDataCache",
    0x2b: "FlushDataCache",
    0x2c: "MapPhysicalMemory",
    0x2d: "UnmapPhysicalMemory",
    0x2e: "GetDebugFutureThreadInfo",
    0x2f: "GetLastThreadInfo",
    0x30: "GetResourceLimitLimitValue",
    0x31: "GetResourceLimitCurrentValue",
    0x32: "SetThreadActivity",
    0x33: "GetThreadContext3",
    0x34: "WaitForAddress",
    0x35: "SignalToAddress",
    0x36: "SynchronizePreemptionState",
    0x37: "GetResourceLimitPeakValue",
    0x39: "CreateIoPool",
    0x3a: "CreateIoRegion",
    0x3c: "DumpInfo",
    0x3c: "KernelDebug",
    0x3d: "ChangeKernelTraceState",
    0x40: "CreateSession",
    0x41: "AcceptSession",
    0x42: "ReplyAndReceiveLight",
    0x43: "ReplyAndReceive",
    0x44: "ReplyAndReceiveWithUserBuffer",
    0x45: "CreateEvent",
    0x46: "MapIoRegion",
    0x47: "UnmapIoRegion",
    0x48: "MapPhysicalMemoryUnsafe",
    0x49: "UnmapPhysicalMemoryUnsafe",
    0x4a: "SetUnsafeLimit",
    0x4b: "CreateCodeMemory",
    0x4c: "ControlCodeMemory",
    0x4d: "SleepSystem",
    0x4e: "ReadWriteRegister",
    0x4f: "SetProcessActivity",
    0x50: "CreateSharedMemory",
    0x51: "MapTransferMemory",
    0x52: "UnmapTransferMemory",
    0x53: "CreateInterruptEvent",
    0x54: "QueryPhysicalAddress",
    0x55: "QueryMemoryMapping",
    0x56: "CreateDeviceAddressSpace",
    0x57: "AttachDeviceAddressSpace",
    0x58: "DetachDeviceAddressSpace",
    0x59: "MapDeviceAddressSpaceByForce",
    0x5a: "MapDeviceAddressSpaceAligned",
    0x5b: "MapDeviceAddressSpace",
    0x5c: "UnmapDeviceAddressSpace",
    0x5d: "InvalidateProcessDataCache",
    0x5e: "StoreProcessDataCache",
    0x5f: "FlushProcessDataCache",
    0x60: "DebugActiveProcess",
    0x61: "BreakDebugProcess",
    0x62: "TerminateDebugProcess",
    0x63: "GetDebugEvent",
    0x64: "ContinueDebugEvent",
    0x65: "GetProcessList",
    0x66: "GetThreadList",
    0x67: "GetDebugThreadContext",
    0x68: "SetDebugThreadContext",
    0x69: "QueryDebugProcessMemory",
    0x6a: "ReadDebugProcessMemory",
    0x6b: "WriteDebugProcessMemory",
    0x6c: "SetHardwareBreakPoint",
    0x6d: "GetDebugThreadParam",
    0x6f: "GetSystemInfo",
    0x70: "CreatePort",
    0x71: "ManageNamedPort",
    0x72: "ConnectToPort",
    0x73: "SetProcessMemoryPermission",
    0x74: "MapProcessMemory",
    0x75: "UnmapProcessMemory",
    0x76: "QueryProcessMemory",
    0x77: "MapProcessCodeMemory",
    0x78: "UnmapProcessCodeMemory",
    0x79: "CreateProcess",
    0x7a: "StartProcess",
    0x7b: "TerminateProcess",
    0x7c: "GetProcessInfo",
    0x7d: "CreateResourceLimit",
    0x7e: "SetResourceLimitLimitValue",
    0x7f: "CallSecureMonitor",
    0x80: "SetGpuMemoryAttribute",
    0x81: "LockGpuSharableMemory",
    0x80: "UnlockGpuSharableMemory",
    0x90: "MapInsecurePhysicalMemory",
    0x91: "UnmapInsecurePhysicalMemory"
}

REGION_TYPES = {
    0: "None",
    1: "KernelTraceBuffer",
    2: "OnMemoryBootImage",
    3: "DTB"
}

PROGRAM_TYPES = {
    0: "System",
    1: "Application",
    2: "Applet"
}

IRQ_NAMES = {
    0: "TMR1",
    1: "TMR2",
    2: "RTC",
    3: "CEC",
    4: "SHR_SEM_INBOX_FULL",
    5: "SHR_SEM_INBOX_EMPTY",
    6: "SHR_SEM_OUTBOX_FULL",
    7: "SHR_SEM_OUTBOX_EMPTY",
    8: "NVJPEG",
    9: "NVDEC",
    10: "QUAD_SPI",
    11: "DPAUX_INT1",
    13: "SATA_RX_STAT",
    14: "SDMMC1",
    15: "SDMMC2",
    16: "VGPIO_INT",
    17: "VII2C_INT",
    19: "SDMMC3",
    20: "USB",
    21: "USB2",
    23: "SATA_CTL",
    24: "PMC_INT",
    25: "FC_INT",
    26: "APB_DMA_CPU",
    28: "ARB_SEM_GNT_COP",
    29: "ARB_SEM_GNT_CPU",
    31: "SDMMC4",
    32: "GPIO1",
    33: "GPIO2",
    34: "GPIO3",
    35: "GPIO4",
    36: "UARTA",
    37: "UARTB",
    38: "I2C",
    39: "USB3_HOST_INT",
    40: "USB3_HOST_SMI",
    41: "TMR3",
    42: "TMR4",
    43: "USB3_HOST_PME",
    44: "USB3_DEV_HOST",
    45: "ACTMON",
    46: "UARTC",
    48: "THERMAL",
    49: "XUSB_PADCTL",
    50: "TSEC",
    51: "EDP",
    53: "I2C5",
    55: "GPIO5",
    56: "USB3_DEV_SMI",
    57: "USB3_DEV_PME",
    58: "SE",
    59: "SPI1",
    60: "APB_DMA_COP",
    62: "CLDVFS",
    63: "I2C6",
    64: "HOST1X_SYNCPT_COP",
    65: "HOST1X_SYNCPTR_CPU",
    66: "HOST1X_GEN_COP",
    67: "HOST1X_GEN_CPU",
    68: "NVENC",
    69: "VI",
    70: "ISPB",
    71: "ISP",
    72: "VIC",
    73: "DISPLAY",
    74: "DISPLAYB",
    75: "SOR1",
    76: "SOR",
    77: "MC",
    78: "EMC",
    80: "TSECB",
    81: "HDA",
    82: "SPI2",
    83: "SPI3",
    84: "I2C2",
    86: "PMU_EXT",
    87: "GPIO6",
    89: "GPIO7",
    90: "UARTD",
    92: "I2C3",
    93: "SPI4",
    96: "DTV",
    98: "PCIE_INT",
    99: "PCIE_MSI",
    101: "AVP_CACHE",
    102: "APE_INT1",
    103: "APE_INT0",
    104: "APB_DMA_CH0",
    105: "APB_DMA_CH1",
    106: "APB_DMA_CH2",
    107: "APB_DMA_CH3",
    108: "APB_DMA_CH4",
    109: "APB_DMA_CH5",
    110: "APB_DMA_CH6",
    111: "APB_DMA_CH7",
    112: "APB_DMA_CH8",
    113: "APB_DMA_CH9",
    114: "APB_DMA_CH10",
    115: "APB_DMA_CH11",
    116: "APB_DMA_CH12",
    117: "APB_DMA_CH13",
    118: "APB_DMA_CH14",
    119: "APB_DMA_CH15",
    120: "I2C4",
    121: "TMR5",
    123: "WDT_CPU",
    124: "WDT_AVP",
    125: "GPIO8",
    126: "CAR",
    128: "APB_DMA_CH16",
    129: "APB_DMA_CH17",
    130: "APB_DMA_CH18",
    131: "APB_DMA_CH19",
    132: "APB_DMA_CH20",
    133: "APB_DMA_CH21",
    134: "APB_DMA_CH22",
    135: "APB_DMA_CH23",
    136: "APB_DMA_CH24",
    137: "APB_DMA_CH25",
    138: "APB_DMA_CH26",
    139: "APB_DMA_CH27",
    140: "APB_DMA_CH28",
    141: "APB_DMA_CH29",
    142: "APB_DMA_CH30",
    143: "APB_DMA_CH31",
    144: "CPU0_PMU_INTR",
    145: "CPU1_PMU_INTR",
    146: "CPU2_PMU_INTR",
    147: "CPU3_PMU_INTR",
    148: "SDMMC1_SYS",
    149: "SDMMC2_SYS",
    150: "SDMMC3_SYS",
    151: "SDMMC4_SYS",
    152: "TMR6",
    153: "TMR7",
    154: "TMR8",
    155: "TMR9",
    156: "TMR0",
    157: "GPU_STALL",
    158: "GPU_NONSTALL",
    159: "DPAUX",
    160: "MPCORE_AXIERRIRQ",
    161: "MPCORE_INTERRIRQ",
    162: "EVENT_GPIO_A",
    163: "EVENT_GPIO_B",
    164: "EVENT_GPIO_C",
    168: "FLOW_RSM_CPU",
    169: "FLOW_RSM_COP",
    170: "TMR_SHARED",
    171: "MPCORE_CTIIRQ0",
    172: "MPCORE_CTIIRQ1",
    173: "MPCORE_CTIIRQ2",
    174: "MPCORE_CTIIRQ3",
    175: "MSELECT_ERROR",
    176: "TMR10",
    177: "TMR11",
    178: "TMR12",
    179: "TMR13"
}

MEMORY_REGIONS = {
    0: "Application",
    1: "Applet",
    2: "SecureSystem",
    3: "NonSecureSystem"
}

PAGE_SIZE = 4 * 1024


def get_bits(x: int, start: int, length: int = 1) -> int:
    return (x >> start) & ((1 << length) - 1)


class Meta:
    def __init__(self, reader: BinaryReader):
        reader.read_signature(4, "META")
        self.signature_key_generation = reader.read_u32()
        reader.seek_rel(0x4) # reserved

        flags = reader.read_u8()
        self.is_64_bit = bool(get_bits(flags, 0))
        address_space_type_idx = get_bits(flags, 1, 3)
        warn_unless(address_space_type_idx < 4, "address space type must be in the range 0-3 (got: {})".format(address_space_type_idx))
        self.address_space_type = ADDRESS_SPACE.get(address_space_type_idx)
        self.optimize_memory_allocation = bool(get_bits(flags, 4))
        self.disable_device_address_space_merge = bool(get_bits(flags, 5))
        self.enable_alias_region_extra_size = bool(get_bits(flags, 6))
        self.prevent_code_reads = bool(get_bits(flags, 7))

        reader.seek_rel(1) # reserved
        self.main_thread_priority = reader.read_u8()
        warn_unless(self.main_thread_priority <= 0x3f, "main thread priority must be in the range 0-0x3f (got: {:#x})".format(self.main_thread_priority))
        self.main_thread_cpu_id = reader.read_u8()
        reader.seek_rel(4) # reserved
        self.system_resource_size = reader.read_u32()
        warn_unless(self.system_resource_size <= 0x1fe00000, "system resource size must be below 0x1fe00000 (got: {:#x})".format(self.system_resource_size))
        self.version = reader.read_u32()
        
        self.main_thread_stack_size = reader.read_u32()
        warn_unless(self.main_thread_stack_size & 0xfff == 0, "main thread stack size must be aligned to 0x1000")

        self.name = reader.read_string("utf-8", 0x10)
        self.product_code = reader.read_bytes(0x10)
        reader.seek_rel(0x30) # reserved

        self.aci_offset = reader.read_u32()
        self.aci_size = reader.read_u32()
        self.acid_offset = reader.read_u32()
        self.acid_size = reader.read_u32()


class FilesystemAccessControl:
    def __init__(self, reader: BinaryReader, size: int):
        version = reader.read_u8()
        content_owner_id_count = reader.read_u8()
        save_data_owner_id_count = reader.read_u8()
        reader.seek_rel(1)
        
        access_flags = reader.read_u64()
        self.flags = []
        for i in range(64):
            flag_name = FS_ACCESS_FLAGS.get(i, hex(i))
            if access_flags & (1 << i):
                self.flags.append(flag_name)

        self.content_owner_id_min = reader.read_u64()
        self.content_owner_id_max = reader.read_u64()
        self.save_data_owner_id_min = reader.read_u64()
        self.save_data_owner_id_max = reader.read_u64()
        self.content_owner_ids = reader.read_u64s(content_owner_id_count)
        self.save_data_owner_ids = reader.read_u64s(save_data_owner_id_count)


class FilesystemAccessHeader:
    def __init__(self, reader: BinaryReader, size: int):
        start = reader.position

        version = reader.read_u8()
        reader.seek_rel(3) # reserved
        
        access_flags = reader.read_u64()
        self.flags = []
        for i in range(64):
            flag_name = FS_ACCESS_FLAGS.get(i, hex(i))
            if access_flags & (1 << i):
                self.flags.append(flag_name)

        content_owner_id_offset = start + reader.read_u32()
        content_owner_id_size = reader.read_u32()
        save_data_owner_id_offset = start + reader.read_u32()
        save_data_owner_id_size = reader.read_u32()

        if content_owner_id_size > 0:
            reader.seek(content_owner_id_offset)
            content_owner_id_count = reader.read_u32()
            self.content_owner_ids = reader.read_u64s(content_owner_id_count)
        else:
            self.content_owner_ids = []

        if save_data_owner_id_size > 0:
            reader.seek(save_data_owner_id_offset)
            save_data_owner_id_count = reader.read_u32()

            accessibilities_start = save_data_owner_id_offset + 4
            ids_start = accessibilities_start + save_data_owner_id_count

            self.save_data_owner_ids = {"read": [], "write": []}

            for i in range(save_data_owner_id_count):
                reader.seek(accessibilities_start + i)
                accessibility = reader.read_u8()
                reader.seek(ids_start + i * 8)
                id_ = reader.read_u64()

                can_read = get_bits(accessibility, 0)
                can_write = get_bits(accessibility, 1)

                if can_read:
                    self.save_data_owner_ids["read"].append(id_)
                if can_write:
                    self.save_data_owner_ids["write"].append(id_)
        else:
            self.save_data_owner_ids = {}


class ServiceAccess:
    def __init__(self, reader: BinaryReader, size: int):
        self.host = []
        self.access = []

        start = reader.position

        while reader.position < start + size and reader.peek(2)[1] != b'\x00':
            byte = reader.read_u8()
            is_host = bool(get_bits(byte, 7))
            str_len = get_bits(byte, 0, 7) + 1
            service_name = reader.read_string("utf-8", str_len)
            if is_host:
                self.host.append(service_name)
            else:
                self.access.append(service_name)


class KernelCapabilities:
    class Range:
        def __init__(self, address: int, size: int, is_ro: bool):
            self.address = address
            self.size = size
            self.is_ro = is_ro
    
    class Region:
        def __init__(self, type_idx: int, is_ro: bool):
            warn_unless(region_type_0_idx in REGION_TYPES, f"map_region region type must be in range 0-3 (got: {region_type_0_idx})")
            self.type: str = REGION_TYPES.get(type_idx)
            self.is_ro = is_ro

    class CorePriority:
        def __init__(self, capability: int):
            self.max_priority = get_bits(capability, 4, 6)
            self.min_priority = get_bits(capability, 10, 6)
            self.min_core = get_bits(capability, 16, 8)
            self.max_core = get_bits(capability, 24, 8)

            warn_unless(self.min_priority <= self.max_priority, f"minimum thread priority must be <= maximum (max: {self.min_priority}, min: {self.max_priority})")
            warn_unless(self.min_core <= self.max_core, f"minimum CPU core must be <= maximum (min: {self.min_core}, max: {self.max_core})")

    class MiscFlags:
        def __init__(self, capability: int):
            self.enable_debug = bool(get_bits(capability, 17))
            self.force_debug_prod = bool(get_bits(capability, 18))
            self.force_debug = bool(get_bits(capability, 19))

            warn_unless(self.enable_debug + self.force_debug_prod + self.force_debug <= 1, "only one of enable_debug, force_debug_prod, force_debug can be set")

    def __init__(self, reader: BinaryReader, caps_size: int):
        self.core_priority: self.CorePriority = None
        self.syscalls: list[int] = []
        self.mapped_io_ranges: list[self.Range] = []
        self.mapped_static_ranges: list[self.Range] = []
        self.map_regions: list[self.Region] = None
        self.interrupts: list[str] = []
        self.program_type: str = None
        self.kernel_version: str = None
        self.handle_table_size: int = None
        self.misc_flags: self.MiscFlags = None

        cap_offset = 0
        while cap_offset < caps_size:
            capability = reader.read_u32()
            if capability == 0:
                break
            capability_idx = (~capability & (capability + 1)).bit_length() - 1
            cap_name = KERNEL_CAPS.get(capability_idx)
            # print(f"{reader.position-4:03x} {capability:08x} {cap_name}")

            if cap_name == "core_priority":
                warn_unless(self.core_priority is None, "duplicate core_priority kernel capability")
                self.core_priority = self.CorePriority(capability)
            
            elif cap_name == "syscalls":
                svc_ids = get_bits(capability, 5, 24)
                index   = get_bits(capability, 29, 3)

                for i in range(svc_ids.bit_length()):
                    has_id = svc_ids & (1 << i)
                    if has_id:
                        svc_id = index * 24 + i
                        self.syscalls.append(svc_id)
            
            elif cap_name == "map_range":
                warn_unless(cap_offset + 4 <= caps_size, "map range capability is truncated")

                begin_addr = get_bits(capability, 7, 24)
                is_ro      = bool(get_bits(capability, 31))

                cap_offset += 4
                capability = reader.read_u32()
                capability_idx = (~capability & (capability + 1)).bit_length() - 1
                warn_unless(KERNEL_CAPS[capability_idx] == "map_range", "map range capability pair is incomplete")
                
                range_size = get_bits(capability, 7, 20)
                is_static = bool(get_bits(capability, 31))

                map_ = self.Range(begin_addr, range_size, is_ro)

                if is_static:
                    self.mapped_static_ranges.append(map_)
                else:
                    self.mapped_io_ranges.append(map_)
            
            elif cap_name == "map_io_page":
                begin_addr = get_bits(capability, 8, 24) * PAGE_SIZE
                self.mapped_io_ranges.append(self.Range(begin_addr, PAGE_SIZE, False))
            
            elif cap_name == "map_region":
                warn_unless(self.map_regions is None, "duplicate map_region kernel capability")

                region_0_type_idx = get_bits(capability, 11, 6)
                region_0_is_ro = bool(get_bits(capability, 17))
                region_1_type_idx = get_bits(capability, 18, 6)
                region_1_is_ro = bool(get_bits(capability, 24))
                region_2_type_idx = get_bits(capability, 25, 6)
                region_2_is_ro = bool(get_bits(capability, 31))

                self.map_regions = []
                self.map_regions.append(self.Region(region_0_type_idx, region_0_is_ro))
                self.map_regions.append(self.Region(region_1_type_idx, region_1_is_ro))
                self.map_regions.append(self.Region(region_2_type_idx, region_2_is_ro))

            elif cap_name == "interrupts":
                first  = get_bits(capability, 12, 10)
                second = get_bits(capability, 22, 10)

                if first == 0x3ff:
                    continue
                if first < 32 or first > 223:
                    warn(f"IRQ number must be in range 32-223 (got: {first:#x})")
                    continue
                first = IRQ_NAMES.get(first - 32, f"Unassigned ({first:#x})")
                self.interrupts.append(first)

                if second == 0x3ff:
                    continue
                if second < 32 or second > 223:
                    warn(f"IRQ number must be in range 32-223 (got: {second:#x})")
                    continue
                second = IRQ_NAMES.get(second - 32, f"Unassigned ({second:#x})")
                self.interrupts.append(second)
            
            elif cap_name == "program_type":
                warn_unless(self.program_type is None, "duplicate program_type kernel capability")

                program_type_idx = get_bits(capability, 14, 3)
                self.program_type = PROGRAM_TYPES.get(program_type_idx)
                warn_unless(self.program_type is not None, f"unrecognised program_type: {program_type_idx}")
            
            elif cap_name == "kernel_version":
                warn_unless(self.kernel_version is None, "duplicate kernel_version kernel capability")

                minor_version = get_bits(capability, 15, 4)
                major_version = get_bits(capability, 19, 13)

                version = (major_version, minor_version)
                version_str = f"{major_version}.{minor_version}"

                warn_unless(version >= (3, 0), f"kernel_version must be at least 3.0 (got: {version_str})")

                self.kernel_version = version_str
            
            elif cap_name == "handle_table_size":
                warn_unless(self.handle_table_size is None, "duplicate handle_table_size kernel capability")
                self.handle_table_size = get_bits(capability, 16, 10)
            
            elif cap_name == "misc_flags":
                warn_unless(self.misc_flags is None, "duplicate misc_flags kernel capability")
                self.misc_flags = self.MiscFlags(capability)

            else:
                warn(f"unrecognised kernel capability {capability_idx}")
        
            cap_offset += 4


class AccessControlInfoDescriptor:
    def __init__(self, reader: BinaryReader, meta: Meta):
        reader.seek(meta.acid_offset)
        self.rsa2048_signature = reader.read_bytes(0x100)
        self.rsa2048_public_key = reader.read_bytes(0x100)

        reader.read_signature(4, "ACID")
        acid_size = reader.read_u32()
        version = reader.read_u16()
        reader.seek_rel(2)
        flags = reader.read_u32()
        self.is_retail = bool(get_bits(flags, 0))
        self.unqualified_approval = bool(get_bits(flags, 1))
        memory_region_idx = get_bits(flags, 2, 5)
        warn_unless(memory_region_idx <= 3, "memory_region must be in the range 0-3")
        self.memory_region = MEMORY_REGIONS.get(memory_region_idx)
        self.load_browser_core_dll = bool(get_bits(flags, 7))
        self.program_id_range = reader.read_u64s(2)

        fs_access_offset = meta.acid_offset + reader.read_u32()
        fs_access_size = reader.read_u32()
        services_offset = meta.acid_offset + reader.read_u32()
        services_size = reader.read_u32()
        kernel_caps_offset = meta.acid_offset + reader.read_u32()
        kernel_caps_size = reader.read_u32()
        reader.seek_rel(8) # reserved

        reader.seek(fs_access_offset)
        self.fs_access = FilesystemAccessControl(reader, fs_access_size)

        reader.seek(services_offset)
        self.services = ServiceAccess(reader, services_size)

        reader.seek(kernel_caps_offset)
        self.kernel_caps_data = reader.peek(kernel_caps_size)
        self.kernel_caps = KernelCapabilities(reader, kernel_caps_size)


class AccessControlInfo:
    def __init__(self, reader: BinaryReader, meta: Meta):
        reader.seek(meta.aci_offset)
        reader.read_signature(4, "ACI0")
        reader.seek_rel(0xc)

        self.program_id = reader.read_u64()
        reader.seek_rel(8) # reserved
        fs_access_offset = meta.aci_offset + reader.read_u32()
        fs_access_size = reader.read_u32()
        services_offset = meta.aci_offset + reader.read_u32()
        services_size = reader.read_u32()
        kernel_caps_offset = meta.aci_offset + reader.read_u32()
        kernel_caps_size = reader.read_u32()
        reader.seek_rel(8) # reserved

        reader.seek(fs_access_offset)
        self.fs_access = FilesystemAccessHeader(reader, fs_access_size)

        reader.seek(services_offset)
        self.services = ServiceAccess(reader, services_size)

        reader.seek(kernel_caps_offset)
        self.kernel_caps_data = reader.peek(kernel_caps_size)
        self.kernel_caps = KernelCapabilities(reader, kernel_caps_size)        


def write_toml(out_path: str, meta: Meta, acid: AccessControlInfoDescriptor, aci: AccessControlInfo):
    with open(out_path, "w") as f:
        f.write("[npdm]\n")
        f.write("name = \"{}\"\n".format(meta.name))
        f.write("program_id = 0x{:016x}\n".format(aci.program_id))
        f.write("version = 0x{:08x}\n".format(meta.version))
        f.write("signature_key_generation = {:#x}\n".format(meta.signature_key_generation))
        f.write("is_64_bit = {}\n".format(("false", "true")[meta.is_64_bit]))
        f.write("address_space_type = \"{}\"\n".format(meta.address_space_type))
        f.write("optimize_memory_allocation = {}\n".format(("false", "true")[meta.optimize_memory_allocation]))
        f.write("disable_device_address_space_merge = {}\n".format(("false", "true")[meta.disable_device_address_space_merge]))
        f.write("enable_alias_region_extra_size = {}\n".format(("false", "true")[meta.enable_alias_region_extra_size]))
        f.write("prevent_code_reads = {}\n".format(("false", "true")[meta.prevent_code_reads]))
        f.write("system_resource_size = {:#x}\n".format(meta.system_resource_size))
        f.write("is_retail = {}\n".format(("false", "true")[acid.is_retail]))
        f.write("unqualified_approval = {}\n".format(("false", "true")[acid.unqualified_approval]))
        f.write("memory_region = \"{}\"\n".format(acid.memory_region))
        f.write("load_browser_core_dll = {}\n".format(("false", "true")[acid.load_browser_core_dll]))

        f.write("\n[main_thread]\n")
        f.write("stack_size = {:#x}\n".format(meta.main_thread_stack_size))
        f.write("priority = {}\n".format(meta.main_thread_priority))
        f.write("cpu_id = {}\n".format(meta.main_thread_cpu_id))

        f.write("\n[program_id_range]\n")
        f.write("min = 0x{:016x}\n".format(acid.program_id_range[0]))
        f.write("max = 0x{:016x}\n".format(acid.program_id_range[1]))

        f.write("\n[filesystem_access]\n")

        if aci.fs_access.flags:
            f.write("permission_flags = [\n")
            for i, permission_flag in enumerate(aci.fs_access.flags):
                f.write("\t\"{}\"".format(permission_flag))
                if i != len(aci.fs_access.flags) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        else:
            f.write("permission_flags = []\n")

        if aci.fs_access.content_owner_ids:
            f.write("content_owner_ids = [\n")
            for i, content_owner_id in enumerate(aci.fs_access.content_owner_ids):
                f.write("\t0x{:016x}".format(content_owner_id))
                if i != len(aci.fs_access.content_owner_ids) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        else:
            f.write("content_owner_ids = []\n")

        if acid.fs_access.content_owner_id_min != 0 or acid.fs_access.content_owner_id_max != 0:
            f.write("content_owner_id_limits = {\n")
            f.write("\tmin = 0x{:016x}\n".format(acid.fs_access.content_owner_id_min))
            f.write("\tmax = 0x{:016x}\n".format(acid.fs_access.content_owner_id_max))
            f.write("}\n")

        if aci.fs_access.save_data_owner_ids:
            f.write("save_data_owner_ids = {\n")

            reads = aci.fs_access.save_data_owner_ids["read"]
            writes = aci.fs_access.save_data_owner_ids["write"]

            if reads:
                f.write("\tread {\n")
                for i, save_data_owner_id in enumerate(reads):
                    f.write("\t\t0x{:016x}".format(save_data_owner_id))
                    if i != len(reads) - 1:
                        f.write(",")
                    f.write("\n")
                f.write("\t}\n")
            else:
                f.write("\tread = {}\n")

            if writes:
                f.write("\twrite {\n")
                for i, save_data_owner_id in enumerate(writes):
                    f.write("\t\t0x{:016x}".format(save_data_owner_id))
                    if i != len(writes) - 1:
                        f.write(",")
                    f.write("\n")
                f.write("\t}\n")
            else:
                f.write("\twrite = {}\n")
        else:
            f.write("save_data_owner_ids = {}\n")

        if acid.fs_access.save_data_owner_id_min != 0 or acid.fs_access.save_data_owner_id_max != 0:
            f.write("save_data_owner_id_limits = {\n")
            f.write("\tmin = 0x{:016x}\n".format(acid.fs_access.save_data_owner_id_min))
            f.write("\tmax = 0x{:016x}\n".format(acid.fs_access.save_data_owner_id_max))
            f.write("}\n")
        
        f.write("\n[services]\n")

        if aci.services.host:
            f.write("host = [\n")
            for i, service in enumerate(aci.services.host):
                f.write("\t\"{}\"".format(service))
                if i != len(aci.services.host) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        else:
            f.write("host = []\n")

        if aci.services.access:
            f.write("access = [\n")
            for i, service in enumerate(aci.services.access):
                f.write("\t\"{}\"".format(service))
                if i != len(aci.services.access) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        else:
            f.write("access = []\n")

        f.write("\n[kernel_capabilities]\n")

        core_prio = aci.kernel_caps.core_priority
        if core_prio is not None:
            f.write("core_priority = {\n")
            f.write("\tmin_thread_priority = {},\n".format(core_prio.min_priority))
            f.write("\tmax_thread_priority = {},\n".format(core_prio.max_priority))
            f.write("\tmin_cpu_id = {},\n".format(core_prio.min_core))
            f.write("\tmax_cpu_id = {}\n".format(core_prio.max_core))
            f.write("}\n")
        
        syscalls = aci.kernel_caps.syscalls
        if syscalls:
            f.write("syscalls = [\n")
            for i, syscall_idx in enumerate(syscalls):
                syscall = SVC.get(syscall_idx)
                if syscall:
                    f.write("\t\"{}\"".format(syscall))
                else:
                    f.write("\t0x{:02x}".format(syscall_idx))

                if i != len(syscalls) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        else:
            f.write("syscalls = []\n")
        
        io_ranges = aci.kernel_caps.mapped_io_ranges
        if io_ranges:
            f.write("mapped_io_ranges = [\n")
            for i, io_range in enumerate(io_ranges):
                f.write("\t{\n")
                f.write("\t\taddress = {:#x},\n".format(io_range.address))
                f.write("\t\tsize = {:#x},\n".format(io_range.size))
                f.write("\t\tis_ro = {}\n".format(("false", "true")[io_range.is_ro]))
                f.write("\t}")
                if i != len(io_ranges) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        
        static_ranges = aci.kernel_caps.mapped_static_ranges
        if static_ranges:
            f.write("mapped_static_ranges = [\n")
            for i, static_range in enumerate(static_ranges):
                f.write("\t{\n")
                f.write("\t\taddress = {:#x},\n".format(static_range.address))
                f.write("\t\tsize = {:#x},\n".format(static_range.size))
                f.write("\t\tis_ro = {}\n".format(("false", "true")[static_range.is_ro]))
                f.write("\t}")
                if i != len(static_ranges) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        
        map_regions = aci.kernel_caps.map_regions
        if map_regions is not None:
            f.write("map_regions = [\n")
            for i, region in enumerate(map_regions):
                f.write("\t{\n")
                f.write("\t\ttype = \"{}\",\n".format(region.type))
                f.write("\t\tis_ro = {}\n".format(("false", "true")[region.is_ro]))
                f.write("\t}")
                if i != len(map_regions) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        
        interrupts = aci.kernel_caps.interrupts
        if interrupts:
            f.write("interrupts = [\n")
            for i, interrupt in enumerate(interrupts):
                f.write("\t\"{}\"".format(interrupt))
                if i != len(interrupts) - 1:
                    f.write(",")
                f.write("\n")
            f.write("]\n")
        
        program_type = aci.kernel_caps.program_type
        if program_type is not None:
            f.write("program_type = \"{}\"\n".format(program_type))
        
        kernel_version = aci.kernel_caps.kernel_version
        if kernel_version is not None:
            f.write("kernel_version = \"{}\"\n".format(kernel_version))

        handle_table_size = aci.kernel_caps.handle_table_size
        if handle_table_size is not None:
            f.write("handle_table_size = {:#x}\n".format(handle_table_size))
        
        misc_flags = aci.kernel_caps.misc_flags
        if misc_flags is not None:
            f.write("misc_flags = {\n")
            f.write("\tenable_debug = {},\n".format(("false", "true")[misc_flags.enable_debug]))
            f.write("\tforce_debug = {},\n".format(("false", "true")[misc_flags.force_debug]))
            f.write("\tforce_debug_prod = {}\n".format(("false", "true")[misc_flags.force_debug_prod]))
            f.write("}\n")


def main():
    parser = argparse.ArgumentParser(description="generate TOML from NPDM file")
    parser.add_argument("infile")
    parser.add_argument("outfile")

    args = parser.parse_args()

    with open(args.infile, "rb") as f:
        data = f.read()
    
    reader = BinaryReader(data)
    meta = Meta(reader)
    acid = AccessControlInfoDescriptor(reader, meta)
    aci = AccessControlInfo(reader, meta)

    if acid.kernel_caps_data != aci.kernel_caps_data:
        print("info: ACID and ACI kernel caps are different", file=sys.stderr)

    write_toml(args.outfile, meta, acid, aci)

if __name__ == "__main__":
    main()
