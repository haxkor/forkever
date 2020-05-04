from utilsFolder.PollableQueue import PollableQueue
from sys import stdin
from threading import Thread

# this will be run in a seperate thread
class InputReader(Thread):
    def __init__(self,stdinQ:PollableQueue, startupfile=None):
        self.stdinQ=stdinQ
        if startupfile:
            self.startup(startupfile)
        Thread.__init__(self)


    def startup(self,file):
        with open(file,"r") as f:
            for line in f.readlines():
                self.stdinQ.put(line)

    def run(self):
        for line in iter(stdin.readline, b""):
            #determine result(line)
            self.stdinQ.put(line.decode())


