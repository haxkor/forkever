from sys import stdin
from threading import Thread
from utilsFolder.PollableQueue import PollableQueue


class InputReader(Thread):
    """listens for userinput"""
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
    """Listens for input for processes STDIN.
    Output will be sent to the socket as well."""
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
        self.sock.listen(1)
        self.acc_sock, _ = self.sock.accept()

        f= partial(self.acc_sock.recv, 0x1000)
        for line_bytes in iter(f, b""):
            line = "write %s \n" % str(line_bytes)
            self.stdinQ.put(line)





