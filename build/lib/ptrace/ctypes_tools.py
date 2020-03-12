from struct import pack, unpack
from ptrace.cpu_info import CPU_64BITS
from ctypes import cast, POINTER


def int2uint64(value):
    """
    Convert a signed 64 bits integer into an unsigned 64 bits integer.

    >>> print(int2uint64(1))
    1
    >>> print(int2uint64(2**64 + 1))  # ignore bits larger than 64 bits
    1
    >>> print(int2uint64(-1))
    18446744073709551615
    >>> print(int2uint64(-2))
    18446744073709551614
    """
    return (value & 0xffffffffffffffff)


def uint2int64(value):
    """
    Convert an unsigned 64 bits integer into a signed 64 bits integer.

    >>> print(uint2int64(1))
    1
    >>> print(uint2int64(2**64 + 1))  # ignore bits larger than 64 bits
    1
    >>> print(uint2int64(18446744073709551615))
    -1
    >>> print(uint2int64(18446744073709551614))
    -2
    """
    value = value & 0xffffffffffffffff
    if value & 0x8000000000000000:
        return value - 0x10000000000000000
    else:
        return value


def truncateWord32(value):
    """
    Truncate an unsigned integer to 32 bits.
    """
    return value & 0xFFFFFFFF


def truncateWord64(value):
    """
    Truncate an unsigned integer to 64 bits.
    """
    return value & 0xFFFFFFFFFFFFFFFF


def formatUintHex16(value):
    """
    Format an 16 bits unsigned integer.
    """
    return u"0x%04x" % value


def formatUintHex32(value):
    """
    Format an 32 bits unsigned integer.
    """
    return u"0x%08x" % value


def formatUintHex64(value):
    """
    Format an 64 bits unsigned integer.
    """
    return u"0x%016x" % value


def int2uint32(value):
    """
    Convert a signed 32 bits integer into an unsigned 32 bits integer.

    >>> print(int2uint32(1))
    1
    >>> print(int2uint32(2**32 + 1))  # ignore bits larger than 32 bits
    1
    >>> print(int2uint32(-1))
    4294967295
    """
    return value & 0xffffffff


def uint2int32(value):
    """
    Convert an unsigned 32 bits integer into a signed 32 bits integer.

    >>> print(uint2int32(1))
    1
    >>> print(uint2int32(2**32 + 1))  # ignore bits larger than 32 bits
    1
    >>> print(uint2int32(4294967295))
    -1
    >>> print(uint2int32(4294967294))
    -2
    >>> print(uint2int32(18446744073709551615))
    -1
    """
    value = value & 0xffffffff
    if value & 0x80000000:
        v = value - 0x100000000
    else:
        v = value
    return v


uint2int = uint2int32
int2uint = int2uint32
if CPU_64BITS:
    ulong2long = uint2int64
    long2ulong = int2uint64
    formatWordHex = formatUintHex64
    truncateWord = truncateWord64
else:
    ulong2long = uint2int32
    long2ulong = int2uint32
    formatWordHex = formatUintHex32
    truncateWord = truncateWord32


def formatAddress(address):
    """
    Format an address to hexadecimal.
    Return "NULL" for zero.
    """
    if address:
        return formatWordHex(address)
    else:
        return u"NULL"


def formatAddressRange(start, end):
    """
    Format an address range, e.g. "0x80004000-0x8000ffff".
    """
    return u"%s-%s" % (formatWordHex(start), formatWordHex(end))


def ntoh_ushort(value):
    """
    Convert an unsigned short integer from network endian to host endian.
    """
    return unpack("<H", pack(">H", value))[0]


def ntoh_uint(value):
    """
    Convert an unsigned integer from network endian to host endian.
    """
    return unpack("<I", pack(">I", value))[0]


def word2bytes(word):
    """
    Convert an unsigned integer (a CPU word) to a bytes string.
    """
    return pack("L", word)


def bytes2word(bytes):
    """
    Convert a bytes string to an unsigned integer (a CPU word).
    """
    return unpack("L", bytes)[0]


def bytes2type(bytes, type):
    """
    Cast a bytes string to an object of the specified type.
    """
    return cast(bytes, POINTER(type))[0]


def bytes2array(bytes, basetype, size):
    """
    Cast a bytes string to an array of objects of the specified type
    and size.
    """
    return bytes2type(bytes, basetype * size)
