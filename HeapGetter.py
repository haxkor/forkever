import re
import utils

UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
SZ_SIZET = 8


def getHeapAsBytes(pid, printall=False):
    def getStart(line):  # extracts the start/end out of the found line
        start, end = re.findall(r"\b[0-9A-Fa-f]+\b", line)[:2]
        return int(start, 16), int(end, 16)

    # find out where the heap is and make sure there is only one segment
    with open("/proc/%d/maps" % pid, "r") as maps:
        f = lambda l: "[heap]" in l
        start_end_tuple = list(getStart(line) for line in filter(f, maps.readlines()))
        assert len(start_end_tuple) == 1
        start, end = start_end_tuple[0]

    with open("/proc/%d/mem" % pid, "rb") as mem, open(utils.tmppath + "heap", "wb") as heapcopy:
        towrite = end - start
        mem.seek(start)
        heapcopy.write(mem.read(towrite))


# name idea: forkAndError, freefork, forlloc,

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack


class HyxTalker():
    def __init__(self):
        self.rootsock = socket(AF_UNIX, SOCK_STREAM)
        self.rootsock.bind("mystupidsock")
        self.rootsock.listen(3)
        self.hyxsock, _ = self.rootsock.accept()

        self.path_mem = "m"
        self.heap_start = 1

    def sendUpdates(self, tuplelist):
        def makeChangeStruct(start, data):
            ret = pack("<I", start)
            ret += pack("<I", len(data))
            ret += data

            return ret

        code = b"\x01"
        code += pack("<I", len(tuplelist))

        code += b"".join(makeChangeStruct(start, data) for (start, data) in tuplelist)

        return self.hyxsock.send(code)

    def getUpdate(self):
        sock = self.hyxsock
        check = sock.recv(1)
        assert (check in (UPD_FROMBLOB, UPD_FROMBLOBNEXT))

        length = unpack("<I", sock.recv(SZ_SIZET))[0]
        if check != UPD_FROMBLOBNEXT:
            pos = unpack("<I", sock.recv(SZ_SIZET))[0]
            self.nextpos = pos + length
        else:
            assert (self.nextpos)
            pos = self.nextpos
            self.nextpos += length

        data = sock.recv(length)
        return (pos, data)

    def writeUpdate(self, *data_list):
        with open(self.path_mem, "bw+") as mem:
            for datapack in data_list:
                (pos, data) = datapack
                mem.seek(self.heap_start + pos)
                mem.write(data)

