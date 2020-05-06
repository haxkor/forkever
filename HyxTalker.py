from socket import socket, AF_UNIX, SOCK_STREAM
from subprocess import Popen
from struct import pack, unpack
from Constants import hyx_path, runargs

from utilsFolder.PaulaPoll import PaulaPoll

from HeapClass import Heap

SZ_SIZET = 8

from Constants import UPD_FROMBLOB, UPD_FROMBLOBNEXT, UPD_FROMPAULA, UPD_FROMPAULA_INSERT

import os


class HyxTalker():
    def __init__(self, socketname: str, heapobj: Heap, poll: PaulaPoll):
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
        self.poll = poll
        self.launchHyx(heapobj)


    def launchHyx(self, heapobj: Heap):
        """ open new Hyx Window"""
        def argsStr(args):
            return "".join(arg + " " for arg in args)

        filepath = heapobj.newHeapfile()
        offset = heapobj.start

        # prepare args
        args=[hyx_path, "-offset", hex(offset), "-socket", self._socketname, filepath]

        if runargs:
            args = runargs + args
            self.hyxprocess = Popen(args)
        else:
            pref = ["gdb -ex \"b updater.c:getUpdates_fromPaula_insert\"  --args"]
            print(argsStr(pref+args))  # incase spawning new window isnt possible

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

    def sendNewHeap(self, oldstart, oldstop):
        if self.heap.start != oldstart:
            raise NotImplementedError
        if self.heap.stop < oldstop:
            raise NotImplementedError

        # replace old heap with new heap

        self.hyxsock.send(UPD_FROMPAULA_INSERT)
        length = self.heap.stop - self.heap.start
        self.hyxsock.send(pack("<Q", length))
        ret=self.hyxsock.send(self.heap.heapbytes)
        print("sent %#x bytes" % ret )
        print("heapbytes len= %x" % len(self.heap.heapbytes))

    def getUpdate(self, isNextByte=False):
        """receive the changes made in Hyx and write them to Memory"""
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
        """checks if the heap has changed. If yes, forward the changes to Hyx"""

        changetype, changeret = self.heap.checkChange()

        if changetype == "same":
            # print("no change detected")
            pass
        elif changetype == "length":
            self.sendNewHeap(*changeret)

        elif changetype == "bytes":
            self.sendUpdates(changeret)

        else:
            raise NotImplementedError

    def recvCommand(self):
        """receive a :!command from Hyx"""
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
