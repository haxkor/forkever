from socket import socket, AF_UNIX, SOCK_STREAM
from subprocess import Popen
from struct import pack, unpack
from Constants import hyx_path

from utilsFolder.PaulaPoll import PaulaPoll

from HeapClass import Heap

SZ_SIZET = 8

from Constants import UPD_FROMBLOB, UPD_FROMBLOBNEXT, UPD_FROMPAULA, UPD_FROMPAULA_ALLHEAP

import os


class HyxTalker():
    def __init__(self, socketname: str, heapobj: Heap, poll:PaulaPoll):
        self.rootsock = socket(AF_UNIX, SOCK_STREAM)
        self._socketname = socketname

        try:
            os.unlink(socketname)
        except FileNotFoundError:
            pass
        self.rootsock.bind(socketname)
        self.heap = heapobj

        self.hyxprocess = None
        self.hyxsock = None
        self.launchHyx(heapobj)


        self.poll=poll

    def launchHyx(self, heapobj: Heap):
        def argsStr(args):
            return "".join(arg + " " for arg in args)

        filepath = heapobj.newHeapfile()
        offset = heapobj.start

        # prepare args
        args = ["x-terminal-emulator", "-e",
                hyx_path, "-offset", hex(offset), "-socket", self._socketname, filepath]

        print(argsStr(args))  # incase spawning new window isnt possible
        self.hyxprocess = Popen(args)
        self.rootsock.listen(1)
        self.hyxsock, _ = self.rootsock.accept()

        self.poll.register(self.getSockFd(), "hyx")

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

    def getUpdate(self, isNextByte=False):
        sock = self.hyxsock
        if not isNextByte:
            pos = unpack("<Q", sock.recv(SZ_SIZET))[0]
            self.nextpos = pos
        else:
            pos = self.nextpos

        length = unpack("<Q", sock.recv(SZ_SIZET))[0]
        self.nextpos += length

        data = sock.recv(length)
        assert len(data) == length

        self.heap.writeUpdates(pos, data)

        return pos, data

    def updateHyx(self):

        change = self.heap.checkChange()

        if change == "same":
            # print("no change detected")
            pass
        elif change == "length":
            self.destroy()
            self.launchHyx(self.heap)
        elif isinstance(change, list):
            self.sendUpdates(change)
        else:
            raise NotImplementedError

    def recvCommand(self):
        cmd = bytearray(0x100)
        assert self.hyxsock.recv_into(cmd) == 0x100
        replace = cmd.find(b"\x00")
        cmd[replace:replace + 1] = b" "
        end = cmd.find(b"\x00")
        return cmd[:end].decode()

    def sendCommandResponse(self, cmd):
        if isinstance(cmd, str):
            cmd = cmd.encode()
        cmd = cmd[:0x100]
        self.hyxsock.send(cmd.ljust(0x100, b"\x00"))

    def destroy(self, rootsock=False):
        self.poll.unregister(self.getSockFd())
        self.hyxsock.close()
        self.hyxprocess.kill()
        if rootsock:
            self.rootsock.close()
