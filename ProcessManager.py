from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

from time import sleep

from ProcessWrapper import ProcessWrapper
from select import poll, POLLIN, POLLERR, POLLPRI

from subprocess import Popen

from ptrace.debugger import PtraceDebugger

import pwn
from ptrace.debugger.process_event import ProcessExecution

hyx_path = "/"

path_launcher = "launcher/dummylauncher"
path_tohack = "launcher/babymalloc"
socketname = "/tmp/paulasock"

from PaulaPoll import PaulaPoll


class ProcessManager():
    def __init__(self, socketname:str, pollobj:PaulaPoll):
        self.socketname = socketname
        self.pollobj= pollobj   # PollObj used by the input monitor, needed to register new processes



        self.processList = []
        self.debugger = self.startDebugger([path_launcher, path_tohack])
        self.currentProcess= self.processList[0]




    def addProcess(self, proc: ProcessWrapper):
        self.processList.append(proc)
        self.pollobj.register(proc.getfileno("err"), "%d-err" % proc.ptraceProcess.pid)
        self.pollobj.register(proc.getfileno("out"), "%d-out" % proc.ptraceProcess.pid)

    def startDebugger(self, args):

        debugger = PtraceDebugger()
        debugger.traceFork()
        debugger.traceExec()
        debugger.enableSysgood()    # to differentiate between traps by syscall, no syscall

        newProcess = ProcessWrapper(args=args, debugger=debugger, redirect=True)  # first process
        self.addProcess(newProcess)

        return debugger

    def getCurrentProcess(self):
        return self.currentProcess

    def cont(self):
        from ptrace.debugger.process import PtraceProcess
        def manageSyscall(proc:PtraceProcess):
            try:
                proc.entering_syscall
            except AttributeError:  # first time its called, the process exits from ecexve
                proc.entering_syscall = False

            regs= proc.getregs()
            rax= getattr(regs, "rax")
            orig_rax= getattr(regs, "orig_rax")

            if proc.entering_syscall:
                if orig_rax in self.syscallsToTrace:    # or True:
                    print("process is gonna syscall: %d" % orig_rax)
                    print("stopped")
                    # what should be done here?

                    proc.entering_syscall= False
                else:
                    proc.syscall()  # continue execution
                    proc.waitSyscall()
                    rax= proc.getreg("rax") # TODO maybe extract this?
                    print("process called syscall %d, returned result was %#x" % (orig_rax,rax))

                    proc.entering_syscall= False

            else:   # process just exited syscall
                rax = proc.getreg("rax")
                print("process called syscall %d, returned result was %#x" % (orig_rax, rax))

                proc.entering_syscall = True



        procWrap= self.getCurrentProcess()
        assert isinstance(procWrap, ProcessWrapper)
        proc = procWrap.ptraceProcess

        #assert proc.is_stopped  # might be wrong sometimes according to docs

        # we can call continue if
        proc.syscall()  # we want to register every syscall
        event= proc.waitEvent()

        from ptrace.debugger.ptrace_signal import ProcessSignal, ProcessEvent
        from signal import SIGTRAP
        self.syscallsToTrace= [0,1, 12, 21]
        if isinstance(event, ProcessSignal):
            if event.signum == 0x80 | SIGTRAP:  #syscall trap
                manageSyscall(proc)

        #print("cont got something else:", event)
        print("instruction pointer= %#x" % proc.getInstrPointer())





