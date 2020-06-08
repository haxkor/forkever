from os import kill
from re import compile as compile_regex
from signal import SIGKILL

from Constants import FOLLOW_NEW_PROCS, COLOR_NORMAL, COLOR_CURRENT_PROCESS
from ProcessWrapper import ProcessWrapper, LaunchArguments
from logging2 import debug
from ptrace.debugger import PtraceDebugger, PtraceProcess
from ptrace.debugger.process import ProcessError
from ptrace.debugger.process_event import ProcessEvent, ProcessExit, NewProcessEvent, ProcessExecution
from ptrace.func_call import FunctionCallOptions
from utilsFolder.Parsing import parseInteger
from utilsFolder.PaulaPoll import PaulaPoll, BiDict
from utilsFolder.tree import format_tree

TRACE_SYSCALL_ARGS = compile_regex(r"(not )?([\w]+|\*)")


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

        self.named_processes = BiDict()

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

    def malloc(self, val):
        return self.callFunction("malloc", val)

    def dumpMaps(self):
        """print /proc/pid/maps of current process"""
        return "".join(str(mapping) + "\n" for mapping in self.getCurrentProcess().ptraceProcess.readMappings())

    def callFunction(self, cmd: str):
        _, _, cmd = cmd.partition(" ")
        funcname, _, argstr = cmd.partition(" ")
        print(funcname, argstr)

        currProc = self.getCurrentProcess()
        args = [parseInteger(arg, currProc) for arg in argstr.split()]

        debug("trying function %s with args %s" % (funcname, args))
        try:
            return self.getCurrentProcess().callFunction(funcname, *args)
        except ProcessEvent as event:
            self._handle_ProcessEvent(event)

    def fork(self, cmd: str):
        """fork the current process and switch to it.
        print all processes with 'family' """
        procWrap = self.getCurrentProcess()
        child = self.addProcess(procWrap.forkProcess())

        _, _, name = cmd.partition(" ")
        if name:
            self.name_process(name, child.getPid())
            self.name_process(name + "p", procWrap.getPid())

        return self.switchProcess(str(child.getPid()))

    def addBreakpoint(self, cmd):
        _, _, cmd = cmd.partition(" ")
        try:
            self.getCurrentProcess().insertBreakpoint(cmd)
        except ProcessError as e:
            return str(e).split(":")[0]  # happens if breakpoint is already set

    def _handle_ProcessEvent(self, event: ProcessEvent):
        print("handleprocevent",event)
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

        def handle_NewProcess(event):
            """this is called if a new process is created by the program (and not artificially by the user)"""
            new_ptrace_proc = self.debugger.list[-1]  # this process was just spawned

            if FOLLOW_NEW_PROCS:
                curr_proc = self.getCurrentProcess()
                new_proc = ProcessWrapper(parent=curr_proc, ptraceprocess=new_ptrace_proc)
                print("created newproc=", new_proc)

                curr_proc.children.append(new_proc)
                self.addProcess(new_proc)
                print("added process")

                pid = int(str(event).split(" ")[2])
                self.switchProcess(pid)

                return str(event)
            else:
                print("new process, running till exit")
                assert isinstance(new_ptrace_proc, PtraceProcess)
                new_ptrace_proc.setoptions(0)
                new_ptrace_proc.detach()

        def handle_ProcessExecution(event):
            """this is called if a processes calls execve"""
            return str(event)

        if isinstance(event, ProcessExit):
            return handle_Exit()
        elif isinstance(event, NewProcessEvent):
            return handle_NewProcess(event)

        elif isinstance(event, ProcessExecution):
            return handle_ProcessExecution(event)

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

    def name_process(self, name, pid=None):
        if pid is None:
            pid = self.getCurrentProcess().getPid()

        # make sure no duplicates are inserted, rename them if necessary
        if name in self.named_processes:
            i = 1
            while name + "(%d)" % i in self.named_processes:
                i += 1
            name += "(%d)" % i

        if pid in self.named_processes:
            del self.named_processes[pid]
            self.named_processes[pid] = name
            return "renamed process"
        else:
            self.named_processes[pid] = name

    def switchProcess(self, cmd: str):
        """ switch ?  prints all processes
            switch up  switches to parent
            switch 137  switches to process 137"""
        if isinstance(cmd, int):
            cmd = str(cmd)
        if "?" in cmd:
            return self.family()

        currProc = self.getCurrentProcess()
        if "up" in cmd:
            if not currProc.parent:
                return "this is root"
            pid = currProc.parent.getPid()
        else:  # look for number
            try:
                if cmd.isnumeric():
                    pid = int(cmd)
                    assert pid in list(proc.getPid() for proc in self.processList)
                else:
                    pid = self.named_processes[cmd]

            except (AssertionError, KeyError):
                return "not found"

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
            return "switched to %d\n%s" % (pid, self.currentProcess.where())
        else:
            ind = processList.index(self.getCurrentProcess())
            nextproc = processList[(ind + 1) % len(processList)]
            self.currentProcess = nextproc
            return "switched to %d\n%s" % (pid, self.currentProcess.where())

    def finish(self):
        return self.getCurrentProcess().finish()

    def family(self):
        curr_pid = self.getCurrentProcess().getPid()

        def getRepr(procWrap: ProcessWrapper):
            pid = procWrap.getPid()
            name = ""
            if pid in self.named_processes:
                name = "(%s)" % self.named_processes[pid]

            as_str = "%d  %s" % (pid, name)
            if pid == curr_pid:
                as_str = COLOR_CURRENT_PROCESS + as_str + COLOR_NORMAL

            return as_str

        def getChildren(procWrap: ProcessWrapper):
            return procWrap.children

        root_proc = self.processList[0]

        tree = format_tree(root_proc, getRepr, getChildren)

        return tree

    def write(self, text: str):
        procWrap = self.getCurrentProcess()
        if text:
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
        syscall_name = cmd_match.group(2)
        all_sys = cmd_match.group()

        syscall_list = self.syscalls_to_trace

        def add_all_to_list():
            self.syscalls_to_trace.extend(syscall for syscall in SYSCALL_NAMES.values()
                                          if syscall not in self.syscalls_to_trace)

        if delete:
            if syscall_name in syscall_list:
                syscall_list.remove(syscall_name)
            elif syscall_name is "*":
                self.syscalls_to_trace.clear()

            else:
                return "not found. currently tracing " + " ".join(syscall_list)
        else:
            if syscall_name in SYSCALL_NAMES.values() and syscall_name not in syscall_list:
                syscall_list.append(syscall_name)
            elif syscall_name is "*":
                add_all_to_list()
            else:
                return "currently tracing " + " ".join(syscall_list)

    def quit(self):
        pids = [procWrap.getPid() for procWrap in self.processList]
        for pid in reversed(pids):
            try:
                kill(pid, SIGKILL)
            except ProcessLookupError:
                pass
