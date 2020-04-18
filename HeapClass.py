from utils import tmppath
from re import findall

import hashlib
def hashfunc(obj):
    return hashlib.sha3_224(obj).digest()


class Heap:

    def __init__(self, procWrap):
        print("\nyo im heap\n")
        self.processWrapper= procWrap
        self.pid= procWrap.getPid()
        self.start, self.stop = self.getStartStop()

        self.file_path = tmppath + "heapcopy%d" % procWrap.ptraceProcess.pid
        self.newHeapcopy()



    def getStartStop(self):
        def getStart(line):  # extracts the start/end out of the found line
            start, end = findall(r"\b[0-9A-Fa-f]+\b", line)[:2]
            return int(start, 16), int(end, 16)

        with open("/proc/%d/maps" % self.pid, "r") as maps:
            f = lambda l: "[heap]" in l     # filter for the one line we care about
            start_end_tuple = list(getStart(line) for line in filter(f, maps.readlines()))

            if len(start_end_tuple) == 0:
                raise KeyError("no heap")
            assert len(start_end_tuple) == 1    # make sure there is only one segment
            start, end = start_end_tuple[0]
        return start, end


    def update(self):


        # check if something changed
        newstart,newend = self.getStartStop()
        if newstart == self.start and newend== self.end:
            if 


    def newHeapcopy(self):
        start, end= self.getStartStop()
        with open("/proc/%d/mem" % self.pid, "rb") as mem, open(self.file_path, "wb") as heapcopy:
            mem.seek(start)
            heapcopy.write(mem.read(end-start))
        return self.file_path

