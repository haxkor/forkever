from typing import List
import re

PROC_MAP_REGEX = re.compile(
    # Address range: '08048000-080b0000 '
    r'([0-9a-f]+)-([0-9a-f]+) '
    # Permission: 'r-xp '
    r'(.{4}) '
    # Offset: '0804d000'
    r'([0-9a-f]+) '
    # Device (major:minor): 'fe:01 '
    r'([0-9a-f]{2}):([0-9a-f]{2}) '
    # Inode: '3334030'
    r'([0-9]+)'
    # Filename: '  /usr/bin/synergyc'
    r'(?: +(.*))?')


class MemoryMappingSimple(object):
    """
    Process memory mapping (metadata about the mapping).

    Attributes:
     - start (int): first byte address
     - end (int): last byte address + 1
     - permissions (str)
     - offset (int): for file, offset in bytes from the file start
     - major_device / minor_device (int): major / minor device number
     - inode (int)
     - pathname (str)
     - _process: weak reference to the process

    (copied from ptrace)
   """

    def __init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.major_device = major_device
        self.minor_device = minor_device
        self.inode = inode
        self.pathname = pathname


def makeMapObj(line: str) -> MemoryMappingSimple:
    line = line.rstrip()
    match = PROC_MAP_REGEX.match(line)
    return MemoryMappingSimple(
        int(match.group(1), 16),
        int(match.group(2), 16),
        match.group(3),
        int(match.group(4), 16),
        int(match.group(5), 16),
        int(match.group(6), 16),
        int(match.group(7)),
        match.group(8))


def getMappings(pid: int, filterstr="") -> List[MemoryMappingSimple]:
    with open("/proc/%d/maps" % pid, "r") as maps:
        func = lambda line: filterstr in line
        return list(makeMapObj(line) for line in filter(func, maps.readlines()))
