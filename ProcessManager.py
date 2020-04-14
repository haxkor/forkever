from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

from ptrace.debugger.ptrace_signal import ProcessSignal, ProcessEvent
from signal import SIGTRAP

from time import sleep

from ProcessWrapper import ProcessWrapper
from select import poll, POLLIN, POLLERR, POLLPRI

from subprocess import Popen

from ptrace.debugger import PtraceDebugger, PtraceProcess

from ptrace.func_call import FunctionCallOptions

import pwn
from ptrace.debugger.process_event import ProcessExecution

hyx_path = "/"

path_launcher = "launcher/dummylauncher"
path_tohack = "launcher/babymalloc"
socketname = "/tmp/paulasock"

from PaulaPoll import PaulaPoll


class ContextContinue:
    def __init__(self):
        self.about_to_call_interesting_syscall = False
        self.firsttime = True
        self.writeStdin = False


class ProcessManager:
    def __init__(self, path_to_hack, socketname: str, pollobj: PaulaPoll):
        self.socketname = socketname
        self.pollobj = pollobj  # PollObj used by the input monitor, needed to register new processes

        self.processList = []
        self.debugger = self.startDebugger([path_launcher, path_to_hack])
        self.currentProcess = self.processList[0]

        self.syscall_options = FunctionCallOptions(
            write_types=True,
            write_argname=True,
            write_address=True,
        )

    def addProcess(self, proc: ProcessWrapper):
        self.processList.append(proc)
        self.pollobj.register(proc.out_pipe.fileno("read"), "proc-out")
        self.pollobj.register(proc.err_pipe.fileno("read"), "proc-err")

    def startDebugger(self, args):

        debugger = PtraceDebugger()
        debugger.traceFork()
        debugger.traceExec()
        debugger.enableSysgood()  # to differentiate between traps by syscall, no syscall

        newProcess = ProcessWrapper(args=args, debugger=debugger, redirect=True)  # first process
        self.addProcess(newProcess)

        return debugger

    def getCurrentProcess(self) -> ProcessWrapper:
        return self.currentProcess


    def getNextEvent(self, procWrap):
        def isSysTrap(event):
            return isinstance(event, ProcessSignal) and event.signum == 0x80 | SIGTRAP

        proc = procWrap.ptraceProcess
        assert isinstance(proc, PtraceProcess)
        proc.syscall()
        event = proc.waitEvent()

        if not isSysTrap(event):
            return event

        state = proc.syscall_state
        syscall = state.event(self.syscall_options)


        print("ip=", hex(proc.getInstrPointer()), "rax=", proc.getreg("rax"), "orig_rax=", proc.getreg("orig_rax"))

        # skip over boring syscalls
        if syscall.name not in self.syscallsToTrace:
            if syscall.result is not None: # print results of boring syscalls
                print("syscall %s returned %s\n" % (syscall.name, syscall.result_text))
            return self.getNextEvent(procWrap)

        else:       # we are tracing the specific syscall
            if syscall.result is not None:
                print("%s = %s" % (syscall.name, syscall.result_text))
            else:
                print("process is about to syscall %s" % syscall.format())

        return



    def cont(self):

        procWrap = self.getCurrentProcess()

        assert isinstance(procWrap, ProcessWrapper)
        proc = procWrap.ptraceProcess
        self.syscallsToTrace = ["read", "write"]

        event = self.getNextEvent(procWrap)
        if event is None:
            return

        print("cont event=", event)


        if isinstance(event, ProcessSignal):
            if event.signum == SIGTRAP:  # normal trap, maybe breakpoint?
                # check if breakpoint
                pass
            else:
                raise NotImplementedError

        # print("cont got something else:", event)
        print("instruction pointer= %#x" % proc.getInstrPointer())

    def fork(self):
        procWrap = self.getCurrentProcess()
        self.addProcess(procWrap.forkProcess())

    def switchProcess(self, pid=None):
        processList = self.processList
        if len(processList) == 1:
            print("there is just one process")
            return

        print(pid)

        if pid:
            proc = self.getCurrentProcess()
            while proc.ptraceProcess.pid != pid:
                try:
                    proc = next(iter(processList))
                except StopIteration:
                    print("no process with pid %d" % pid)
                    return
            self.currentProcess = proc
            print("switched process")
        else:
            ind = processList.index(self.getCurrentProcess())
            nextproc = processList[(ind + 1) % len(processList)]
            self.currentProcess = nextproc
            print("switched to next process, pid= %d" % nextproc.ptraceProcess.pid)

    def write(self, text):
        procWrap = self.getCurrentProcess()
        procWrap.writeToBuf(text)
