import os
import socket
from functools import partial
from sys import stdin
from threading import Thread

from Constants import HOST, PORT
from logging2 import debug
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
        with open(file, "r") as f:
            for line in f.readlines():
                if len(line) > 0:
                    self.stdinQ.put(line)
                    debug("put %s" % line)

    def run(self):
        lastcmd = b""
        for line in iter(stdin.readline, ""):
            if line == b"\n":
                line = lastcmd
            elif not line.startswith(b"?"):
                lastcmd = line
            self.stdinQ.put(line.decode())


class InputSockReader(Thread):
    """Listens for input for processes STDIN.
    Output will be sent to the socket as well."""

    def __init__(self, stdinQ: PollableQueue):
        Thread.__init__(self, daemon=True)
        self.stdinQ = stdinQ
        self.sock = socket.socket()

        self.start()

    def run(self):
        try:
            os.unlink(HOST)
        except FileNotFoundError:
            pass

        self.sock.bind((HOST, PORT))
        self.sock.listen(1)
        acc_sock, _ = self.sock.accept()

        f = partial(acc_sock.recv, 0x1000)
        for line_bytes in iter(f, b""):
            line = "write %s \n" % str(line_bytes)
            self.stdinQ.put(line)
