import pty
import os
import subprocess

PIPE_BUFSIZE = 4096


class Pipe:

    def __init__(self, flags=0, terminal=False):
        """Creates a Pipe you can easily write to and read from. Default is to open up a pseudo-terminal.
            If you supply flags, pipe2 is used."""

        if flags or not terminal:
            self._readfd, self._writefd = os.pipe2(flags)
        else:  # default
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

        # als nächstes das in processwrapper umsetzen, thread der auf IO vom programm listend und stderr,out bündelt?

    def write(self, text):
        if isinstance(text, str):
            text = text.encode()

        result = self.writeobj.write(text)
        self.writeobj.flush()
        return result

    def read(self, n):
        self.writeobj.flush()
        return self.readobj.read(n)
