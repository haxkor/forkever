from ProcessWrapper import ProcessWrapper, LaunchArguments
from ptrace.debugger.process_event import ProcessEvent, ProcessExit

from ptrace.debugger import PtraceDebugger

from ptrace.func_call import FunctionCallOptions
from ptrace.debugger.process import ProcessError

from Constants import path_launcher
from signal import SIGCHLD
from re import compile as compile_regex

hyx_path = "/"

from utilsFolder.PaulaPoll import PaulaPoll
from utilsFolder.Parsing import parseInteger


class ProcessManager:
    def __init__(self, args: LaunchArguments, pollobj: PaulaPoll):
        self.pollobj = pollobj  # PollObj used by the input monitor, needed to register new processes
        self.syscalls_to_trace = []

        self.processList = []
        self.debugger = self.startDebugger(args)
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
        newProcess.syscalls_to_trace = self.syscalls_to_trace
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
            self._handle_ProcessEvent(event)

    def malloc(self, val):
        return self.callFunction("malloc", val)

    def dumpMaps(self):
        """print /proc/pid/maps of current process"""
        return "".join(str(mapping) + "\n" for mapping in self.getCurrentProcess().ptraceProcess.readMappings())

    def tryFunction(self, cmd:str):
        funcname, _, argstr = cmd.partition(" ")
        print(funcname, argstr)

        currProc= self.getCurrentProcess()
        args= [parseInteger(arg,currProc) for arg in argstr.split()]

        print("trying function %s with args %s" % (funcname, args))
        self.getCurrentProcess().tryFunction(funcname, *args)

    def callFunction(self, cmd:str):
        _,_, cmd= cmd.partition(" ")
        funcname, _, argstr = cmd.partition(" ")
        print(funcname, argstr)

        currProc = self.getCurrentProcess()
        args = [parseInteger(arg, currProc) for arg in argstr.split()]

        print("trying function %s with args %s" % (funcname, args))
        self.getCurrentProcess().callFunction(funcname, *args)

    def fork(self):
        """fork the current process and switch to it.
        print all processes with 'family' """
        procWrap = self.getCurrentProcess()
        child = self.addProcess(procWrap.forkProcess())
        return self.switchProcess(str(child.getPid()))

    def addBreakpoint(self, cmd):
        _, _, cmd = cmd.partition(" ")
        try:
            self.getCurrentProcess().insertBreakpoint(cmd)
        except ProcessError as e:
            return str(e).split(":")[0]  # happens if breakpoint is already set

    def _handle_ProcessEvent(self, event):
        def handle_Exit():
            procWrap = self.getCurrentProcess()
            procWrap.is_terminated = True
            if procWrap.parent:
                return self.switchProcess(procWrap.parent.getPid())
            else:
                if len(self.processList) > 1:
                    return self.switchProcess("up")
                else:
                    print("all processes exited")
                    raise KeyboardInterrupt

        if isinstance(event, ProcessExit):
            return handle_Exit()
        else:
            raise event

    def cont(self, singlestep=False):
        procWrap = self.getCurrentProcess()
        if procWrap.is_terminated:
            return "process %d terminated already" % procWrap.getPid()
        else:
            try:
                return procWrap.cont(singlestep=singlestep)
            except ProcessEvent as event:
                return self._handle_ProcessEvent(event)

    def switchProcess(self, cmd: str):
        """ switch ?  prints all processes
            switch up  switches to parent
            switch 137  switches to process 137"""
        if isinstance(cmd, int):
            cmd = str(cmd)
        if "?" in cmd:
            return self.processList[0].getFamily()

        currProc = self.getCurrentProcess()
        if "up" in cmd:
            if not currProc.parent:
                return "this is root"
            pid = currProc.parent.getPid()
        else:  # look for number
            try:
                pid = int(cmd)
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

    def finish(self):
        return self.getCurrentProcess().finish()

    def family(self):
        return self.getCurrentProcess().getFamily()

    def write(self, text):
        procWrap = self.getCurrentProcess()
        procWrap.writeToBuf(text)

    def print(self, cmd):
        return self.getCurrentProcess().print(cmd)

    def examine(self, cmd):
        return self.getCurrentProcess().examine(cmd)

    def trace_syscall(self, cmd: str):
        """trace a specified syscall, which means that the program will halt
        whenever the syscall is called/returns.
        usage:  trace fork   /   trace not fork"""
        _, _, cmd = cmd.partition(" ")
        from ptrace.syscall.ptrace_syscall import SYSCALL_NAMES
        cmd = cmd.strip()
        cmd_match = TRACE_SYSCALL_ARGS.match(cmd)
        delete = bool(cmd_match.group(1))  # if "not" is present, delete
        which = cmd_match.group(2)

        syscall_list = self.syscalls_to_trace

        if delete:
            if which in syscall_list:
                syscall_list.remove(which)
            else:
                return "not found. currently tracing " + " ".join(syscall_list)

        else:

            if which in SYSCALL_NAMES.values() and which not in syscall_list:
                syscall_list.append(which)
            else:
                return "currently tracing " + " ".join(syscall_list)


TRACE_SYSCALL_ARGS = compile_regex(r"(not )?([\w]+)")
