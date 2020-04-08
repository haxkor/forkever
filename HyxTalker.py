from socket import socket, AF_UNIX, SOCK_STREAM
from subprocess import Popen
from struct import pack, unpack

UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
SZ_SIZET = 8

hyx_path = "/home/jasper/github/hyxWIPclion/hyx-0.1.5/myhyx"
import os


class HyxTalker():
    def __init__(self, socketname, filepath, offset):
        self.rootsock = socket(AF_UNIX, SOCK_STREAM)

        try:
            os.unlink(socketname)
        except FileNotFoundError:
            pass
        self.rootsock.bind(socketname)

        self.hyxprocess=self.launchHyx(filepath, offset, socketname)

        self.rootsock.listen(3)
        self.hyxsock, _ = self.rootsock.accept()

    def launchHyx(self, filepath, offset, socketname):
        def argsStr(args):
            return "".join(arg + " " for arg in args)
        # prepare args
        args = ["x-terminal-emulator", "-e",
                hyx_path, "-offset", hex(offset), "-socket", socketname, filepath]

        print(argsStr(args))
        return Popen(args)

    def getSockFd(self):
        return self.hyxsock.fileno()

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
