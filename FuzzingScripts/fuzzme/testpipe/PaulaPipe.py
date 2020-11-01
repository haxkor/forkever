import pty
import os
import subprocess

PIPE_BUFSIZE = 4096


class Pipe:

    def __init__(self, flags=0, terminal=False):
        """Creates a Pipe you can easily write to and read from. Default is to open up a regular pipe."""

        if flags or not terminal:
            self._readfd, self._writefd = os.pipe2(flags)
        else:  # terminal
            self._readfd, self._writefd = pty.openpty()

        os.set_inheritable(self._readfd, True)
        os.set_inheritable(self._writefd, True)

        self.readobj = open(self._readfd, "rb", 0)
        self.writeobj = open(self._writefd, "wb", 0)

    def fileno(self, which):
        if which == "read":
            return self._readfd
        elif which == "write":
            return self._writefd
        else:
            raise KeyError

    def write(self, text):
        if isinstance(text, str):
            text = text.encode()

        result = self.writeobj.write(text)
        self.writeobj.flush()
        return result

    def read(self, n):
        self.writeobj.flush()
        return self.readobj.read(n)
