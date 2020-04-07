import time
import pty
import os
import subprocess
PIPE_BUFSIZE = 4096
_control = False


class Pipe:

    def __init__(self, flags=None, terminal=True):
        """Creates a Pipe you can easily write to and read from. Default is to open up a pseudo-terminal.
            If you supply flags, pipe2 is used."""

        if flags or not terminal:
            self._readfd, self._writefd = os.pipe2(flags)
        else:   # default
            self._readfd, self._writefd = pty.openpty()

        self.readobj = open(self._readfd, "rb", 0)  
        self.writeobj = open(self._writefd, "wb", 0)

    def write(self, text):
        if isinstance(text, str):
            text = text.encode()

        result = self.writeobj.write(text)
        self.writeobj.flush()
        return result

    def read(self, n):
        self.writeobj.flush()
        return self.readobj.read(n)


class ProcessIOWrapper:
    """Provides an easy way to redirect stdout and stderr using pipes. Write to the processes STDIN and read from STDOUT at any time! """

    def __init__(self, args, inittext=None, redirect=True):

        #create three pseudo terminals
        self.in_pipe = Pipe()
        self.out_pipe = Pipe()
        self.err_pipe = Pipe()

        # if we want to redirect, tell the subprocess to write to our pipe, else it will print to normal stdout
        if redirect:
            stdout_arg= self.out_pipe.writeobj
            stderr_arg= self.err_pipe.writeobj
        else:
            stdout_arg=None
            stderr_arg= None

        self.process = subprocess.Popen(args, stdin=self.in_pipe.readobj, stdout=stdout_arg, stderr=stderr_arg)


    def write(self, text):
        return self.in_pipe.write(text)

    def read(self, n, channel="out"):
        if channel == "out":
            return self.out_pipe.read(n)
        else:
            return self.err_pipe.read(n)


