from socket import socket, AF_UNIX, SOCK_STREAM
from subprocess import Popen
from struct import pack, unpack

UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
SZ_SIZET = 8

class HyxTalker():
    def __init__(self, path_mem, heap_start):
        self.rootsock = socket(AF_UNIX, SOCK_STREAM)
        self.rootsock.bind("mystupidsock")

        self.launchHyx()

        self.rootsock.listen(3)
        self.hyxsock, _ = self.rootsock.accept()

        self.path_mem = path_mem
        self.heap_start = heap_start

    def launchHyx(self):
        # prepare args
        heapStart = 1
        socketadr = ""
        file = heapcopy
        args = ["x-terminal-emulator", "-e",
                hyx_path, "-offset", str(heapStart), "-socket", socketadr]
        return Popen(args)

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
        assert check in (UPD_FROMBLOB, UPD_FROMBLOBNEXT)

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
