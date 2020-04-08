from utils import tmppath
from re import findall


class Heap:

    def __init__(self, pid):
        self.start, self.stop = self.getHeap_startstop()


        self.pid= pid
        self.file_path = tmppath + "heapcopy%d" % pid


    def getHeap_startstop(self):
        def getStart(line):  # extracts the start/end out of the found line
            start, end = findall(r"\b[0-9A-Fa-f]+\b", line)[:2]
            return int(start, 16), int(end, 16)

        with open("/proc/%d/maps" % self.pid, "r") as maps:
            f = lambda l: "[heap]" in l     # filter for the one line we care about
            start_end_tuple = list(getStart(line) for line in filter(f, maps.readlines()))

            assert len(start_end_tuple) == 1    # make sure there is only one segment
            start, end = start_end_tuple[0]
        return start, end


    def newHeapcopy(self):
        start, end= self.getHeap_startstop()
        with open("/proc/%d/mem" % self.pid, "rb") as mem, open(self.file_path, "wb") as heapcopy:
            mem.seek(start)
            heapcopy.write(mem.read(end-start))
        return self.file_path

