from utils import tmppath
from re import findall

import hashlib
from weakref import ref


def hashfunc(obj):
    return hashlib.sha3_224(obj).digest()


class Heap:

    def __init__(self, procWrap):
        print("\nyo im heap\n")
        self.processWrapper = procWrap
        self.pid = procWrap.getPid()
        self.start, self.stop = self.getStartStop()

        self.file_path = tmppath + "heapcopy%d" % procWrap.ptraceProcess.pid
        self.mem_path = "/proc/%d/mem" % self.pid

        self.heapbytes = bytearray(self.stop - self.start)
        self.hash = 0

        self.checkChange()

    def getStartStop(self):
        def extractAddresses(line):  # extracts the start/end out of the found line
            start, end = findall(r"\b[0-9A-Fa-f]+\b", line)[:2]
            return int(start, 16), int(end, 16)

        with open("/proc/%d/maps" % self.pid, "r") as maps:
            f = lambda l: "[heap]" in l  # filter for the one line we care about
            start_end_tuple = list(extractAddresses(line) for line in filter(f, maps.readlines()))

            if len(start_end_tuple) == 0:
                raise KeyError("no heap")
            assert len(start_end_tuple) == 1  # make sure there is only one segment
            start, end = start_end_tuple[0]
        return start, end


    def checkChange(self):
        """checks if the heap changed. if some bytes changed, return the tuplelist indicating the changes.
            if the size of the heap changed, return that (does not change the bytearray)"""     # TODO make this an iterator

        def findChanges():
            from itertools import count
            start = 0
            length = 0
            result = []
            for old, new,ind in zip(self.heapbytes, buf, count()):
                if old == new:
                    if length > 0:
                        data= buf[start:start+length]
                        #if length == 1:     # if data is a single byte, python converts it to an int
                        #    data= bytes([data])
                        result.append((start, data))
                    length = 0
                    start = ind + 1
                else:
                    length += 1

            if self.heapbytes[-1] != buf[-1]:
                data = buf[start:start + length]
                if length == 1:  # if data is a single byte, python converts it to an int
                    data = bytes([data])
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
            #print("hash= %s" % newhash)
            if newhash != self.hash:
                self.hash = newhash
                tuplelist = findChanges()
                self.heapbytes = buf
                return tuplelist
            else:
                return "same"

        else:
            self.start = newstart
            self.stop = newstop
            return "length"

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

    def writeUpdates(self,pos:int,data:bytes):
        pos+=self.start
        assert self.start <= pos <= self.stop and pos + len(data) <= self.stop
        self.processWrapper.ptraceProcess.writeBytes(pos,data)

        pos-= self.start
        self.heapbytes[pos:pos+len(data)] = data
        self.hash= hashlib.sha3_224(self.heapbytes).digest()




