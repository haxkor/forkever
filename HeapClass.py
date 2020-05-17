from utilsFolder.utils import tmppath
from re import findall

import hashlib
from utilsFolder.MapsReader import getMappings


def hashfunc(obj):
    return hashlib.sha3_224(obj).digest()


class MemorySegmentInitArgs:

    def __init__(self, path: str, permissions: str, start_offset: int, stop_offset: int, start_nonzero=False, stop_nonzero=False):
        self.path = path
        self.permissions = permissions
        self.start_offset = start_offset
        self.stop_offset = stop_offset

        self.start_nonzero=start_nonzero
        self.stop_nonzero= stop_nonzero


class Heap:

    def __init__(self, procWrap, init_args: MemorySegmentInitArgs):
        self.processWrapper = procWrap
        self.pid = procWrap.getPid()
        self.args = init_args

        self.start, self.stop = self.getStartStop()

        self.file_path = tmppath + "%s%d" % (self.args.path.strip("/"), procWrap.ptraceProcess.pid)
        self.mem_path = "/proc/%d/mem" % self.pid

        self.heapbytes = bytearray(self.stop - self.start)
        self.hash = 0

        self.checkChange()

    def getStartStop(self):
        heapmap = getMappings(self.pid, self.args.path)
        if len(heapmap) == 0:
            raise ValueError("no segment with that name found")

        #        filter_func = lambda mapping: all(perm_letter in mapping.permissions
        #                                          for perm_letter in self.permissions)

        def filter_func(mapping):
            my_perms= sorted(self.args.permissions)
            map_perms= sorted(mapping.permissions.replace("-",""))
            return my_perms == map_perms

        heapmap = list(filter(filter_func, heapmap))
        if len(heapmap) == 0:
            raise ValueError("no segment with these permissions available")

        keyfunc = lambda mapping: mapping.start
        start = min(heapmap, key=keyfunc).start

        keyfunc = lambda mapping: mapping.end
        stop = max(heapmap, key=keyfunc).end

        # add the offsets specified by user. special case if stop_offset is negative
        start_offset = self.args.start_offset
        stop_offset = self.args.stop_offset
        start += start_offset

        if stop_offset < 0:
            stop += stop_offset
        elif stop_offset > 0:
            stop = (start-start_offset) + stop_offset   # start was already modified

        assert start % 0x1000 == 0 and stop % 0x1000 == 0, "%x:%x" % (start,stop)

        if self.args.start_nonzero:
            with open("/proc/%d/mem" % self.pid, "rb") as mem:
                mem.seek(start)
                while start + 0x1000 < stop and sum(mem.read(0x1000)) == 0:
                    start += 0x1000

        if self.args.stop_nonzero:
            with open("/proc/%d/mem" % self.pid, "rb") as mem:

                mem.seek(stop-0x1000)
                while start + 0x1000 < stop and sum(mem.read(0x1000)) == 0:
                    stop-=0x1000
                    mem.seek(stop - 0x1000)

        if start >= stop:
            raise ValueError("start >= stop")

        print("start= %x, stop= %x" % (start, stop))

        return start, stop

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

            if self.heapbytes[-1] != buf[-1]:  # edge case for very last byte in heap
                data = buf[start:start + length]
                result.append((start, data))
            return result

        # check if something changed
        newstart, newstop = self.getStartStop()
        if newstart == self.start and newstop == self.stop:
            with open("/proc/%d/mem" % self.pid, "rb") as mem:
                mem.seek(self.start)
                buf = bytearray(self.stop - self.start)
                print(len(buf))
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
