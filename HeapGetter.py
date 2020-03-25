import re
import utils

def getHeapAsBytes(pid, printall=False):
    def getStart(line): # extracts the start/end out of the found line
        start,end=re.findall(r"\b[0-9A-Fa-f]+\b", line)[:2]
        return int(start,16),int(end,16)

    # find out where the heap is and make sure there is only one segment
    with open("/proc/%d/maps" % pid, "r") as maps:
        f=lambda l: "[heap]" in l
        start_end_tuple = list( getStart(line) for line in filter(f, maps.readlines()))
        assert len(start_end_tuple)==1
        start,end= start_end_tuple[0]

    with open("/proc/%d/mem" % pid, "rb") as mem, open(utils.tmppath + "heap", "wb") as heapcopy:
        towrite=end-start
        mem.seek(start)
        heapcopy.write(mem.read(towrite))



