from ProcessWrapper import ProcessWrapper
from ptrace.debugger.process_event import ProcessEvent, ProcessExit

from ptrace.debugger import PtraceDebugger

from ptrace.func_call import FunctionCallOptions

import pwn
from Constants import path_launcher

hyx_path = "/"

socketname = "/tmp/paulasock"

from utilsFolder.PaulaPoll import PaulaPoll


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
        debugger.enableSysgood()  # to differentiate between traps raised by syscall, no syscall

        newProcess = ProcessWrapper(args=args, debugger=debugger, redirect=True)  # first process
        self.addProcess(newProcess)

        return debugger

    def getCurrentProcess(self) -> ProcessWrapper:
        return self.currentProcess

    def free(self, pointer):
        try:
            return self.getCurrentProcess().free(pointer)
        except ProcessEvent as event:
            self.handle_ProcessEvent(event)

    def malloc(self, val):
        return self.getCurrentProcess().malloc(val)

    def tryFunction(self, funcname, args):
        args = list(int(arg, 16) for arg in args)
        print("trying function %s with args %s" % (funcname, args))
        self.getCurrentProcess().tryFunction(funcname, *args)

    def fork(self):
        procWrap = self.getCurrentProcess()
        self.addProcess(procWrap.forkProcess())

    def addBreakpoint(self, adress, force_absolute=False):
        return self.getCurrentProcess().insertBreakpoint(adress, force_absolute=force_absolute)

    def handle_ProcessEvent(self,event):
        def handle_Exit():
            procWrap=self.getCurrentProcess()
            print(event, "procManag\n")
            if procWrap.parent:
                self.switchProcess(procWrap.parent.getPid())
                self.processList.remove(procWrap)
                del procWrap
            else:
                if len(self.processList)>1:
                    self.processList.remove(procWrap)
                    del procWrap
                    self.switchProcess()
                else:
                    print("all processes exited")
                    exit(1)

        if isinstance(event,ProcessExit):
            return handle_Exit()

        else:
            raise NotImplementedError

    def cont(self,singlestep=False):
        procWrap=self.getCurrentProcess()
        try:
            return procWrap.cont(singlestep=singlestep)
        except ProcessEvent as event:
            self.handle_ProcessEvent(event)

    def switchProcess(self, pid=None):
        processList = self.processList
        if len(processList) == 1:
            print("there is just one process")
            self.currentProcess=processList[0]
            return

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
