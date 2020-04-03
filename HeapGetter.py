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




from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
class HyxTalker():
    def __init__(self):
        self.rootsock = socket(AF_UNIX, SOCK_STREAM)
        self.rootsock.bind("mystupidsock")
        self.rootsock.listen(3)
        self.rootsock.accept()

        self.


    def makeChangeStruct(start, data):
        ret=pack("<I",start)
        ret+= pack("<I",len(data))
        ret+= data

        return ret

    def sendUpdates(tuplelist):
        code=b"\x01"
        code+= pack("<I", len(tuplelist))

        code+= b"".join( makeChangeStruct(start,data) for (start,data) in tuplelist)

        return newsock.send(code)




