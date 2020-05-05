from utilsFolder.PollableQueue import PollableQueue
from sys import stdin
from threading import Thread

class InputReader(Thread):
    def __init__(self,stdinQ:PollableQueue, startupfile=None):
        Thread.__init__(self, daemon=True)
        self.stdinQ=stdinQ
        if startupfile:
            self.startup(startupfile)


    def startup(self,file):
        print("in startup")
        with open(file,"r") as f:
            for line in f.readlines():
                self.stdinQ.put(line)
                print("put %s" % line)

    def run(self):
        lastcmd=""
        for line in iter(stdin.readline, ""):
            if line == b"\n":
                line=lastcmd
            else:
                lastcmd=line
            self.stdinQ.put(line.decode())


