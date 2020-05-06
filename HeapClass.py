from utilsFolder.utils import tmppath
from re import findall

import hashlib
from utilsFolder.MapsReader import getMappings


def hashfunc(obj):
    return hashlib.sha3_224(obj).digest()


class Heap:

    def __init__(self, procWrap):
        self.processWrapper = procWrap
        self.pid = procWrap.getPid()
        self.start, self.stop = self.getStartStop()

        self.file_path = tmppath + "heapcopy%d" % procWrap.ptraceProcess.pid
        self.mem_path = "/proc/%d/mem" % self.pid

        self.heapbytes = bytearray(self.stop - self.start)
        self.hash = 0

        self.checkChange()

    def getStartStop(self):
        heapmap = getMappings(self.pid, "heap")
        assert len(heapmap) == 1
        info = heapmap[0]
        print("start %#x stop %#x" % (info.start, info.end))
        return info.start, info.end

    def checkChange(self):
        """ check memory for change and save them.
            returns what changed so Hyxtalker can send updates to Hyx
        """

        def findChanges():
            from itertools import count
            start = 0
            length = 0
            result = []
            for old, new, ind in zip(self.heapbytes, buf, count()):
                if old == new:
                    if length > 0:
                        data = buf[start:start + length]
                        # if length == 1:     # if data is a single byte, python converts it to an int
                        #    data= bytes([data])
                        result.append((start, data))
                    length = 0
                    start = ind + 1
                else:
                    length += 1

            if self.heapbytes[-1] != buf[-1]:   # edge case for very last byte in heap
                data = buf[start:start + length]
                result.append((start, data))
            return result

        # check if something changed
        newstart, newstop = self.getStartStop()
        if newstart == self.start and newstop == self.stop:
            with open("/proc/%d/mem" % self.pid, "rb") as mem:
                mem.seek(self.start)
                buf = bytearray(self.stop - self.start)
                assert self.stop - self.start == mem.readinto(buf)
            newhash = hashlib.sha3_224(buf).digest()

            if newhash != self.hash:
                self.hash = newhash
                tuplelist = findChanges()
                self.heapbytes = buf
                return "bytes", tuplelist
            else:
                return "same", 0

        else:
            ret = self.start, self.stop
            self.start = newstart
            self.stop = newstop

            with open("/proc/%d/mem" % self.pid, "rb") as mem:
                mem.seek(self.start)
                self.heapbytes = bytearray(self.stop - self.start)
                assert self.stop - self.start == mem.readinto(self.heapbytes)
            self.hash = hashlib.sha3_224(self.heapbytes).digest()

            return "length", ret

    def readHeap(self):
        with  open("/proc/%d/mem" % self.pid, "rb") as mem:
            mem.seek(self.start)
            mem.readinto(self.heapbytes)

    def newHeapfile(self):
        start, end = self.getStartStop()
        with open("/proc/%d/mem" % self.pid, "rb") as mem, open(self.file_path, "wb") as heapcopy:
            mem.seek(start)
            heapcopy.write(mem.read(end - start))
        return self.file_path

    def writeUpdates(self, pos: int, data: bytes):
        pos += self.start
        assert self.start <= pos <= self.stop and pos + len(data) <= self.stop
        self.processWrapper.ptraceProcess.writeBytes(pos, data)

        pos -= self.start
        self.heapbytes[pos:pos + len(data)] = data
        self.hash = hashlib.sha3_224(self.heapbytes).digest()
