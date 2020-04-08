import re
import utils

UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
SZ_SIZET = 8


from HyxTalker import HyxTalker


class HeapWriter():


    def __init__(self, pid):
        self.hyxtalker= None
        self.pid=pid
        self.heapfile= self.getHeap_file()



    def initHyx(self, socketname):
        offset, _ = self.getHeap_startstop()
        self.hyxtalker= HyxTalker(socketname, self.heapfile, offset)

    def getSockFd(self):
        return self.hyxtalker.getSockFd()





# name idea: forkAndError, freefork, forlloc,


if __name__ == "__main__":
    getter= HeapWriter()
