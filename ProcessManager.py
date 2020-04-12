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
    def __init__(self, path_to_hack, socketname:str, pollobj:PaulaPoll):
        self.socketname = socketname
        self.pollobj= pollobj   # PollObj used by the input monitor, needed to register new processes



        self.processList = []
        self.debugger = self.startDebugger([path_launcher, path_to_hack])
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

    def getCurrentProcess(self) -> ProcessWrapper:
        return self.currentProcess

    def cont(self):
        from ptrace.debugger.process import PtraceProcess

        def manageSyscall():

            def manageReadSyscall():
                assert isinstance(procWrap,ProcessWrapper)
                if proc.getreg("rdi") != 0:         # check if process will read from stdin
                    return "cont"

                read_count = proc.getreg("rdx")
                written= procWrap.writeBufToPipe(read_count)
                print("read %d bytes from stdin, ( %d available written)" % (read_count,written))




            try:
                proc.entering_syscall
            except AttributeError:  # first time its called, the process exits from ecexve
                proc.entering_syscall = False

            if proc.entering_syscall:
                # find out what syscall will be called, stop or skip over it
                orig_rax= proc.getreg("orig_rax")
                if orig_rax == 0:       # read syscall
                    manageReadSyscall()
                elif orig_rax in self.syscallsToTrace:

                    print("process is gonna syscall: %d" % orig_rax)
                    print("stopped")

                    proc.entering_syscall= False
                    return
                else:   # dont stop till the syscall returns
                    #proc.syscall()
                    proc.entering_syscall= False
                    return "cont"
                    proc.waitSyscall()
                    #self.cont()     # this causes a bug with the orig_rax


            else:   # process just exited syscall, next time we get a syscall-trap it will be at the start of another
                proc.entering_syscall = True

            regs = proc.getregs()
            rax = getattr(regs, "rax")
            orig_rax = getattr(regs, "orig_rax")




        procWrap= self.getCurrentProcess()
        assert isinstance(procWrap, ProcessWrapper)
        proc = procWrap.ptraceProcess

        #assert proc.is_stopped  # might be wrong sometimes according to docs

        # we can call continue if
        proc.syscall()  # we want to register every syscall
        event= proc.waitEvent()

        from ptrace.debugger.ptrace_signal import ProcessSignal, ProcessEvent
        from signal import SIGTRAP
        self.syscallsToTrace= [0, 1, 12, 21]
        if isinstance(event, ProcessSignal):
            if event.signum == 0x80 | SIGTRAP:  #syscall trap
                if manageSyscall() == "cont":
                    self.cont()
                    return              # its not pretty
            elif event.signum == SIGTRAP:    # normal trap, maybe breakpoint?
                # check if breakpoint
                pass
            else:
                raise NotImplementedError



        #print("cont got something else:", event)
        print("instruction pointer= %#x" % proc.getInstrPointer())


    def write(self,text):
        procWrap= self.getCurrentProcess()
        procWrap.writeToBuf(text)






if False:
    if read_count >= available or procWrap.justAskedForStdin:
        procWrap.writeBufToPipe(read_count)
        procWrap.justAskedForStdin = False
    elif available == 0:
        print("process wants to read from stdin, nothing to be read")
        procWrap.justAskedForStdin = False
    else:
        print("process wants to read %d bytes from stdin, only %d are available" % (read_count, available))
        print("you can write more or continue")
        procWrap.justAskedForStdin = False
