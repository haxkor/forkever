from utilsFolder.PollableQueue import PollableQueue
from sys import stdin
from threading import Thread


class InputReader(Thread):
    def __init__(self, stdinQ: PollableQueue, startupfile=None):
        Thread.__init__(self, daemon=True)
        self.stdinQ = stdinQ
        if startupfile:
            self.startup(startupfile)

        self.start()

    def startup(self, file):
        print("in startup")
        with open(file, "r") as f:
            for line in f.readlines():
                self.stdinQ.put(line)
                print("put %s" % line)

    def run(self):
        lastcmd = b""
        for line in iter(stdin.readline, ""):
            if line == b"\n":
                line = lastcmd
            elif not line.startswith(b"?"):
                lastcmd = line
            self.stdinQ.put(line.decode())

from Constants import HOST, PORT
import socket
from functools import partial
import os

class InputSockReader(Thread):
    def __init__(self, stdinQ: PollableQueue):
        Thread.__init__(self, daemon=True)
        self.stdinQ = stdinQ
        self.sock= socket.socket()

        self.start()

    def run(self):
        try:
            os.unlink(HOST)
        except FileNotFoundError:
            pass

        self.sock.bind((HOST,PORT))
        print("listening")
        self.sock.listen(1)
        print("listened")
        self.acc_sock, _ = self.sock.accept()
        print("accepted")


        f= partial(self.acc_sock.recv, 0x1000)
        for line_bytes in iter(f, b""):
            line = "write %s \n" % str(line_bytes)
            self.stdinQ.put(line)





