from ProcessWrapper import ProcessWrapper
from ptrace.debugger.process_event import ProcessEvent, ProcessExit

from ptrace.debugger import PtraceDebugger

from ptrace.func_call import FunctionCallOptions

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
        return proc

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
        return self.callFunction("free", pointer)

    def callFunction(self, funcname, *args, tillResult=False):
        try:
            return self.getCurrentProcess().callFunction(funcname, *args, tillResult=tillResult)
        except ProcessEvent as event:
            self.handle_ProcessEvent(event)

    def malloc(self, val):
        return self.callFunction("malloc", val)

    def dumpMaps(self):
        return "".join(str(mapping) + "\n" for mapping in self.getCurrentProcess().ptraceProcess.readMappings())

    def tryFunction(self, funcname, args):
        args = list(int(arg, 16) for arg in args)
        print("trying function %s with args %s" % (funcname, args))
        self.getCurrentProcess().tryFunction(funcname, *args)

    def fork(self):
        procWrap = self.getCurrentProcess()
        child = self.addProcess(procWrap.forkProcess())
        return self.switchProcess(str(child.getPid()))

    def addBreakpoint(self, cmd):
        _, _, cmd = cmd.partition(" ")
        return self.getCurrentProcess().insertBreakpoint(cmd)

    def handle_ProcessEvent(self, event):
        def handle_Exit():
            procWrap = self.getCurrentProcess()
            if procWrap.parent:
                self.switchProcess(procWrap.parent.getPid())
                self.processList.remove(procWrap)
                del procWrap
            else:
                if len(self.processList) > 1:
                    self.processList.remove(procWrap)
                    del procWrap
                    self.switchProcess()
                else:
                    print("all processes exited")
                    exit(1)

        if isinstance(event, ProcessExit):
            return handle_Exit()

        else:
            raise NotImplementedError

    def cont(self, singlestep=False):
        procWrap = self.getCurrentProcess()
        try:
            return procWrap.cont(singlestep=singlestep)
        except ProcessEvent as event:
            self.handle_ProcessEvent(event)

    def switchProcess(self, cmd:str):
        """ ? prints root family
            up switches to parent
            101 switches to given process"""
        if "?" in cmd:
            return self.processList[0].getFamily()

        currProc= self.getCurrentProcess()
        if "up" in cmd:
            if not currProc.parent:
                return "this is root"
            pid=currProc.parent.getPid()
        else:   # look for number
            try:
                pid=int(cmd)
                assert pid in list(proc.getPid() for proc in self.processList)
            except (ValueError, AssertionError):
                return "process not found"

        processList = self.processList
        if len(processList) == 1:
            self.currentProcess = processList[0]
            return "there is only one process"

        if pid:
            proc = self.getCurrentProcess()
            procIter = iter(processList)
            while proc.ptraceProcess.pid != pid:
                try:
                    proc = next(procIter)
                except StopIteration:
                    return "no process with pid %d" % pid
            self.currentProcess = proc
            return "switched to %d" % pid
        else:
            ind = processList.index(self.getCurrentProcess())
            nextproc = processList[(ind + 1) % len(processList)]
            self.currentProcess = nextproc
            return "switched to %d" % nextproc.ptraceProcess.pid

    def family(self):
        return self.getCurrentProcess().getFamily()

    def write(self, text):
        procWrap = self.getCurrentProcess()
        procWrap.writeToBuf(text)
