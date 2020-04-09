import time
from PaulaPipe import Pipe

from ptrace.debugger.process import PtraceProcess
from ptrace.debugger.process_event import ProcessExecution
import pwn
from subprocess import Popen
from utils import path_launcher


class ProcessWrapper:
    """Provides an easy way to redirect stdout and stderr using pipes. Write to the processes STDIN and read from STDOUT at any time! """

    def __init__(self, args=None, debugger=None, redirect=False, parent=None, ptraceprocess=None):

        if args:
            assert debugger is not None
            assert not parent
            # create three pseudo terminals
            self.in_pipe = Pipe()
            self.out_pipe = Pipe()
            self.err_pipe = Pipe()

            # if we want to redirect, tell the subprocess to write to our pipe, else it will print to normal stdout
            if redirect:
                stdout_arg = self.out_pipe.writeobj
                stderr_arg = self.err_pipe.writeobj
            else:
                stdout_arg = None
                stderr_arg = None

            self.popen_obj = Popen(args, stdin=self.in_pipe.readobj, stdout=stdout_arg, stderr=stderr_arg)

            self.debugger = debugger
            self.ptraceProcess = self.setupPtraceProcess()
        else:
            assert isinstance(parent, ProcessWrapper) and isinstance(ptraceprocess, PtraceProcess)
            self.in_pipe = parent.in_pipe.dupe()  # TODO
            self.out_pipe = parent.out_pipe
            self.err_pipe = parent.err_pipe

            self.debugger = parent.debugger
            self.ptraceProcess = ptraceprocess

    def setupPtraceProcess(self):
        from ptrace.debugger.debugger import PtraceDebugger

        assert isinstance(self.debugger, PtraceDebugger)
        ptrace_proc = self.debugger.addProcess(self.popen_obj.pid, is_attached=False, seize=True)
        ptrace_proc.interrupt()  # seize does not automatically interrupt the process
        ptrace_proc.setoptions(self.debugger.options)

        launcher_ELF = pwn.ELF(path_launcher)  # get ready to launch
        ad = launcher_ELF.symbols["go"]
        ptrace_proc.writeBytes(ad, b"gogo")

        # process will be interrupted after new execution   # TODO put this functionality into ptrace, addprocess?
        ptrace_proc.cont()
        assert isinstance(ptrace_proc.waitEvent(),ProcessExecution)

        return ptrace_proc

    def write(self, text):
        return self.in_pipe.write(text)

    def read(self, n, channel="out"):
        if channel == "out":
            return self.out_pipe.read(n)
        else:
            return self.err_pipe.read(n)

    def getfileno(self,which):
        if which == "err":
            return self.err_pipe.fileno("read")
        elif which == "out":
            return self.out_pipe.fileno("read")
        elif which == "in":
            return self.in_pipe.fileno("write")
        else:
            raise KeyError("specify which")

    def forkProcess(self):
        process = self.ptraceProcess
        ip = process.getInstrPointer()
        regs = process.getregs()

        injectcode = codeWriteEax
        inject = pwn.asm(injectcode, arch="amd64")

        original = process.readBytes(ip, len(inject))

        process.writeBytes(ip, inject)

        process.cont()

        event = process.waitEvent()
        print("got event_stop", event, "pid=", process.pid)
        from ptrace.debugger.process_event import NewProcessEvent
        assert isinstance(event, NewProcessEvent)

        process.setInstrPointer(ip)
        process.setregs(regs)
        process.writeBytes(ip, original)

        child = process.debugger.list[-1]
        assert child != process
        child.setInstrPointer(ip)
        child.setregs(regs)
        child.writeBytes(ip, original)

        return ProcessWrapper(parent=self, ptraceprocess=child)


codeWriteEax = """
nop
nop
mov rax, 57     # fork
syscall
nop
"""
