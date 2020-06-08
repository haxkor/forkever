import os
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from subprocess import Popen

from Constants import hyx_path, runargs, socketname, UPD_FROMPAULA_INSERT
from logging2 import debug
from utilsFolder.HeapClass import Heap
from utilsFolder.PaulaPoll import PaulaPoll

SZ_SIZET = 8


class HyxTalker():
    def __init__(self, heapobj: Heap, poll: PaulaPoll):
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
        """open a segment with Hyx. You can specify the permissions of the segment, default is rwp.
    You can use slicing syntax, [1:-3] will open the segment starting with an offset of 0x1000
    You can also trim the segment to start at the first page that has some non-zero bytes in it.

    Example use:
    hyx heap [2:]
    hyx stack [i:i]
    hyx libc rp
    """

        # this docstring shouldnt really be here, but i dont want the
        # helper to import from inputhandler to avoid import loop

        def argsStr(args):
            return "".join(arg + " " for arg in args)

        filepath = heapobj.newHeapfile()
        offset = heapobj.start

        # prepare args
        args = [hyx_path, "-offset", hex(offset), "-socket", self._socketname, filepath]

        if runargs:
            # print(argsStr(args))
            args = runargs + args
            self.hyxprocess = Popen(args)
        else:
            pref = ["gdb -ex \"b updater.c:requestCommandPaula\"  --args"]
            print(argsStr(pref + args))  # incase spawning new window isnt possible

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
        ret = self.hyxsock.send(self.heap.heapbytes)
        debug("sent %#x bytes" % ret)
        debug("heapbytes len= %x" % len(self.heap.heapbytes))

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
            pass

        elif changetype == "length":
            abort = self.heap.args.start_nonzero or self.heap.args.stop_nonzero
            if abort:
                raise NotImplementedError("heapsize changed, "
                                          "but you are only viewing a slice")

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
        cmd[replace:replace + 1] = b" "  # strtok used in hyx replaced the first " " with a nullbyte
        end = cmd.find(b"\x00")
        return cmd[:end].decode()

    def sendCommandResponse(self, cmd):
        if isinstance(cmd, str):
            cmd = cmd.encode()
        assert isinstance(cmd, bytes)
        cmd = cmd[:0x100]
        self.hyxsock.send(cmd.ljust(0x100, b"\x00"))

    def destroy(self, rootsock=False):
        self.poll.unregister(self.getSockFd())
        self.hyxsock.close()
        if rootsock:
            self.rootsock.close()
