import enum
import io
import struct
import typing

def abort(msg: str):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)

def abort_unless(cond: bool, msg: str):
    if not cond:
        abort(msg)

def round_up(x: int, alignment: int) -> int:
    abort_unless(alignment > 0 and ((alignment & (alignment - 1)) == 0), "alignment must be a power of 2")
    return (x + alignment - 1) & ~(alignment - 1)


class ByteOrder(enum.Enum):
    little = "<"
    big = ">"

class BinaryWriter:
    def __init__(self, size: int = 0, byte_order: ByteOrder = ByteOrder.little):
        self.stream = bytearray(size)
        self.byte_order = byte_order
        self._position = 0

    @property
    def position(self) -> int:
        return self._position

    def save(self, filename: str):
        with open(filename, "wb") as f:
            f.write(self.stream)
    
    def write_sub(self, other: typing.Self):
        self.write_bytes(other.stream)

    def seek(self, offset: int, *, relative: bool = False):
        if relative:
            self._position += offset
        else:
            self._position = offset
        
        self._fill_bytes(0)
    
    def seek_rel(self, offset: int):
        self.seek(offset, relative=True)

    def align(self, alignment: int):
        self.seek(round_up(self.position, alignment))

    def _fill_bytes(self, offset: int, relative: bool = True):
        bytes_to_add = offset - len(self.stream)
        if relative:
            bytes_to_add += self.position

        if bytes_to_add > 0:
            self.stream += bytearray(bytes_to_add)

    def write(self, raw: bytes) -> int:
        start = self._position
        self._fill_bytes(len(raw))
        for byte in raw:
            self.stream[self._position] = byte
            self._position += 1
        return self._position - start

    def _write(self, fmt: str, value) -> int:
        endianness = self.byte_order.value
        raw = struct.pack(endianness + fmt, value)
        return self.write(raw)

    def write_bool(self, value: bool) -> int:
        return self._write("?", value)

    def write_s8(self, value: int) -> int:
        return self._write("b", value)

    def write_u8(self, value: int) -> int:
        return self._write("B", value)

    def write_s16(self, value: int) -> int:
        return self._write("h", value)

    def write_u16(self, value: int) -> int:
        return self._write("H", value)

    def write_u24(self, value: int) -> int:
        if self.byte_order == ByteOrder.little:
            return self.write(struct.pack("<I", value)[:3])
        else:
            return self.write(struct.pack(">I", value)[1:])

    def write_s32(self, value: int) -> int:
        return self._write("i", value)

    def write_u32(self, value: int) -> int:
        return self._write("I", value)

    def write_s64(self, value: int) -> int:
        return self._write("q", value)

    def write_u64(self, value: int) -> int:
        return self._write("Q", value)

    def write_f32(self, value: float) -> int:
        return self._write("f", value)

    def write_f64(self, value: float) -> int:
        return self._write("d", value)

    def write_bytes(self, value: bytes) -> int:
        return self.write(value)
    
    def write_string(self, value: str, *, max_len: int = -1) -> int:
        if max_len > 0:
            value = value[:max_len]
            return self.write("{:\0<{max_len}}".format(value, max_len=max_len).encode("ascii"))
        else:
            return self.write(value.encode("ascii"))


def write_u8(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<B", value))

def write_u16(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<H", value))

def write_u32(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<I", value))

def write_u64(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<Q", value))

def write_bytes(fp: io.BufferedWriter, value: bytes):
    fp.write(value)

def write_string(fp: io.BufferedWriter, value: str, *, max_len: int = -1):
    if max_len > 0:
        value = value[:max_len]
        fp.write("{:\0<{max_len}}".format(value, max_len=max_len).encode("ascii"))
    else:
        fp.write(value.encode("ascii"))

def align(fp: io.BufferedWriter, alignment: int):
    fp.seek(round_up(fp.tell(), alignment), io.SEEK_CUR)


def json_read_value(json: dict, keys: str, default: typing.Any) -> (str, typing.Any):
    if isinstance(keys, str):
        keys = (keys,)
    
    for key in keys:
        if key in json:
            return (key, json[key])
    
    if default is not None:
        return (key[0], default)
    abort(f"couldn't find key `{key[0]}`")

def json_read_dict(json: dict, key: str, default: dict = None) -> dict:
    key, data = json_read_value(json, key, default)
    abort_unless(isinstance(data, dict), f"`{key}` must be a dict")
    return data

def json_read_list(json: dict, key: str, default: list = None) -> list:
    key, data = json_read_value(json, key, default)
    abort_unless(isinstance(data, list), f"`{key}` must be a list")
    return data

def json_read_bool(json: dict, key: str, default: bool = None) -> bool:
    key, data = json_read_value(json, key, default)
    abort_unless(isinstance(data, bool), f"`{key}` must be a boolean")
    return data

def json_read_str(json: dict, key: str, max_len: int = -1, default: str = None) -> str:
    key, data = json_read_value(json, key, default)
    abort_unless(isinstance(data, str), f"`{key}` must be a string")
    abort_unless(max_len <= 0 or len(data) <= max_len, f"string `{key}` must be less than {max_len} in length")
    return data

def json_read_int(json: dict, key: str, min_val: int, max_val: int, default: int = None) -> int:
    key, data = json_read_value(json, key, default)
    if isinstance(data, int):
        val = data
    elif isinstance(data, str):
        val = int(data, 16)
    else:
        abort(isinstance(data, (int, str)), f"`{key}` must be an integer")

    abort_unless(min_val <= val <= max_val, f"`{key}` must be between {min_val:#x} and {max_val:#x}")
    return val

def json_read_u64(json: dict, key: str, default: int = None) -> int:
    return json_read_int(json, key, 0, (1 << 64) - 1, default)

def json_read_u32(json: dict, key: str, default: int = None) -> int:
    return json_read_int(json, key, 0, (1 << 32) - 1, default)

def json_read_u16(json: dict, key: str, default: int = None) -> int:
    return json_read_int(json, key, 0, (1 << 16) - 1, default)

def json_read_u8(json: dict, key: str, default: int = None) -> int:
    return json_read_int(json, key, 0, (1 << 8) - 1, default)


def write_kc(contents: dict) -> BinaryWriter:
    writer = BinaryWriter()
    kernel_caps = json_read_list(contents, "kernel_capabilities")
    for cap_idx, cap in enumerate(kernel_caps):
        abort_unless(isinstance(cap, dict), "kernel capabilities must be dicts")
        abort_unless(cap_idx < 32, "too many kernel capabilities (max = 32)")
        
        type_ = json_read_str(cap, "type")
        if type_ == "kernel_flags":
            value = json_read_dict(cap, "value")
            cap = (1 << 3) - 1
            cap |= json_read_int(value, "highest_thread_priority", 0, 63) << 4
            cap |= json_read_int(value, "lowest_thread_priority", 0, 63) << 10
            cap |= json_read_u8(value, "lowest_cpu_id") << 16
            cap |= json_read_u8(value, "highest_cpu_id") << 24
            writer.write_u32(cap)
        elif type_ == "syscalls":
            value = json_read_dict(cap, "value")
            groups = [0] * 8
            for name, data in value.items():
                if isinstance(data, int):
                    val = data
                elif isinstance(data, str):
                    val = int(data, 16)
                else:
                    abort(isinstance(data, (int, str)), f"syscalls must be integers")

                abort_unless(0 <= val <= 0xbf, "syscall values must be between 0 and 0xbf")
                groups[val // 24] |= 1 << (val % 24)
            
            for idx, group in enumerate(groups):
                if group:
                    cap = (1 << 4) - 1
                    cap |= group << 5
                    cap |= idx << 29
                    writer.write_u32(cap)
        elif type_ == "map":
            value = json_read_dict(cap, "value")

            cap = (1 << 6) - 1
            cap |= json_read_int(value, "address", 0, (1 << 24) - 1) << 7
            cap |= (1 << 31) if json_read_bool(value, "is_ro") else 0
            writer.write_u32(cap)

            cap = (1 << 6) - 1
            cap |= json_read_int(value, "size", 0, (1 << 20) - 1) << 7
            cap |= (1 << 31) if json_read_bool(value, "is_io") else 0
            writer.write_u32(cap)
        elif type_ == "map_page":
            cap = (1 << 7) - 1
            cap |= json_read_int(cap, "value", 0, (1 << 24) - 1) << 8
            writer.write_u32(cap)
        elif type_ == "map_region":
            value = json_read_list(cap, "value")
            abort_unless(len(value) <= 3, "`map_region` can have a maximum of 3 regions")
            cap = (1 << 10) - 1
            for i, region in enumerate(value):
                abort_unless(isinstance(region, dict), "`map_region` entries must be dicts")
                cap |= json_read_int(region, "region_type", 0, 3) << (11 + 7 * i)
                cap |= (1 << (17 + 7 * i)) if json_read_bool(region, "is_ro") else 0
            
            writer.write_u32(cap)
        elif type_ == "irq_pair":
            value = json_read_list(cap, "value")
            abort_unless(len(value) == 2, "`irq_pair` must contain 2 elements")
            cap = (1 << 11) - 1
            for i, irq in enumerate(value):
                if irq is None:
                    irq_value = 0x3ff
                else:
                    if isinstance(data, int):
                        irq_value = data
                    elif isinstance(data, str):
                        irq_value = int(data, 16)
                    else:
                        abort(isinstance(data, (int, str)), f"`irq_pair` values must be a integers")

                    abort_unless(0 <= val <= (1 << 10) - 1, f"`irq_pair` values must be between {0:#x} and {(1 << 10) - 1:#x}")

                cap |= irq_value << (11 + i * 10)

            writer.write_u32(cap)
        elif type_ == "application_type":
            value = json_read_int(cap, "value", 0, 2, 0)
            cap = (1 << 13) - 1
            cap |= value << 14
            writer.write_u32(cap)
        elif type_ == "min_kernel_version":
            value = json_read_u16(cap, "value")
            cap = (1 << 14) - 1
            cap |= value << 15
            writer.write_u32(cap)
        elif type_ == "handle_table_size":
            value = json_read_int(cap, "value", 0, (1 << 10) - 1)
            cap = (1 << 15) - 1
            cap |= value << 16
            writer.write_u32(cap)
        elif type_ == "debug_flags":
            value = json_read_dict(cap, "value")
            allow_debug = json_read_bool(value, "allow_debug", False)
            force_debug = json_read_bool(value, "force_debug", False)
            force_debug_prod = json_read_bool(value, "force_debug_prod", False)
            abort_unless(
                allow_debug + force_debug + force_debug_prod <= 1,
                "only one of `allow_debug`, `force_debug`, or `force_debug_prod` can be set"
            )

            cap = (1 << 16) - 1
            cap |= (1 << 17) if allow_debug else 0
            cap |= (1 << 18) if force_debug_prod else 0
            cap |= (1 << 19) if force_debug else 0
            writer.write_u32(cap)
        else:
            abort(f"unrecognised kernel capability type `{type_}`")
    
    return writer
