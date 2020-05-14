from utilsFolder.PaulaPipe import Pipe
from utilsFolder.tree import format_tree

from ptrace.debugger.process import PtraceProcess
from ptrace.debugger.process_event import ProcessExecution, ProcessEvent
from subprocess import Popen
from utilsFolder.utils import path_launcher
from ptrace.debugger.ptrace_signal import ProcessSignal
from signal import SIGTRAP

from HeapClass import Heap

from ptrace.func_call import FunctionCallOptions
from Constants import (RELATIVE_ADRESS_THRESHOLD, PRINT_BORING_SYSCALLS, logfile,
                       SIGNALS_IGNORE)

from utilsFolder.Parsing import parseInteger, parseBytes

from struct import iter_unpack

import pwn

from utilsFolder.ProgramInfo import ProgramInfo
from logging2 import warning


class ProcessWrapper:
    """Provides an easy way to redirect stdout and stderr using pipes. Write to the processes STDIN and read from STDOUT at any time! """

    def __init__(self, args=None, debugger=None, redirect=False, parent=None, ptraceprocess=None):

        self.syscall_options = FunctionCallOptions(
            write_types=True,
            write_argname=True,
            write_address=True,
        )
        self.stdinRequested = False
        self.remember_insert_bp = False
        self.atBreakpoint = False
        self.inserted_function_data = False
        self.parent = None
        self.children = []
        self.is_terminated = False

        if args:
            assert debugger is not None
            assert not parent
            # create three pseudo terminals
            self.in_pipe = Pipe()
            self.out_pipe = Pipe()
            self.err_pipe = Pipe()

            self.stdin_buf = b""
            self.stdout_buf = b""
            self.stderr_buf = b""

            # if we want to redirect, tell the subprocess to write to our pipe, else it will print to normal stdout
            if redirect:
                stdout_arg = self.out_pipe.writeobj
                stderr_arg = self.err_pipe.writeobj
            else:
                stdout_arg = None
                stderr_arg = None

            self.popen_obj = Popen(args, stdin=self.in_pipe.readobj, stdout=stdout_arg, stderr=stderr_arg)

            self.debugger = debugger
            self.ptraceProcess = self.setupPtraceProcess()  # launches actual program, halts immediately

            self.heap = None  # Heap(self.ptraceProcess.pid)

            self.programinfo = ProgramInfo(args[1], self.getPid(), self)

        # this is used when a process is forked by user
        else:
            assert isinstance(parent, ProcessWrapper) and isinstance(ptraceprocess, PtraceProcess)
            self.parent = parent
            self.in_pipe = parent.in_pipe  # TODO
            self.out_pipe = parent.out_pipe
            self.err_pipe = parent.err_pipe

            self.stdin_buf = parent.stdin_buf
            self.stdout_buf = parent.stdout_buf
            self.stderr_buf = parent.stderr_buf

            self.debugger = parent.debugger
            self.ptraceProcess = ptraceprocess
            self.copyBreakpoints()

            self.heap = None
            self.programinfo = parent.programinfo

    def copyBreakpoints(self):
        from ptrace.debugger.process import Breakpoint
        for bp in self.parent.ptraceProcess.breakpoints.values():
            assert isinstance(bp, Breakpoint)
            new_bp = self.ptraceProcess.createBreakpoint(bp.address)
            new_bp.old_bytes = bp.old_bytes

    def getHeap(self):
        if self.heap is None:
            self.heap = Heap(self.ptraceProcess.pid)
            return self.heap
        else:
            return self.heap

    def setupPtraceProcess(self) -> PtraceProcess:
        from ptrace.debugger.debugger import PtraceDebugger

        assert isinstance(self.debugger, PtraceDebugger)
        ptrace_proc = self.debugger.addProcess(self.popen_obj.pid, is_attached=False, seize=True)
        ptrace_proc.interrupt()  # seize does not automatically interrupt the process
        ptrace_proc.setoptions(self.debugger.options)

        print("launching")

        launcher_ELF = pwn.ELF(path_launcher, False)  # get ready to launch
        ad = launcher_ELF.symbols["go"]
        ptrace_proc.writeBytes(ad, b"x")

        ptrace_proc.cont()
        event = ptrace_proc.waitEvent()
        assert isinstance(event, ProcessExecution), event  # execve syscall is hit

        ptrace_proc.syscall()
        ptrace_proc.waitSyscall()
        result = ptrace_proc.getreg("orig_rax")

        print("initial execve returned %d" % result)

        return ptrace_proc

    def addBreakpoints(self, *bp_list):
        def addSingleBP(breakpoint):
            self.ptraceProcess.createBreakpoint(breakpoint)

        for bp in bp_list:
            addSingleBP(bp)

    def readMappings(self):
        return self.ptraceProcess.readMappings()

    def getPieAdress(self, reload=False):
        maps = self.readMappings()

    def writeToBuf(self, text):
        """write to the processes stdin buffer, awaiting read syscall"""
        self.stdin_buf += text

    def writeBufToPipe(self, n: int):
        """write N bytes to the stdin pipe"""
        towrite = self.stdin_buf[0:n]
        self.stdin_buf = self.stdin_buf[n:]
        return self.in_pipe.write(towrite)

    def read(self, n, channel="out"):
        if channel == "out":
            ret = self.out_pipe.read(n)
            self.stdout_buf += ret
            return ret
        elif channel == "err":
            ret = self.err_pipe.read(n)
            self.stderr_buf += ret
            return ret
        else:
            raise KeyError

    def getfileno(self, which):
        if which == "err":
            return self.err_pipe.fileno("read")
        elif which == "out":
            return self.out_pipe.fileno("read")
        elif which == "in":
            return self.in_pipe.fileno("write")
        else:
            raise KeyError("specify which")

    def getPid(self):
        return self.ptraceProcess.pid

    def setHeap(self):
        if self.heap is None:
            self.heap = Heap(self)

    def forkProcess(self):
        """ forks the process. If the process just syscalled (and is trapped in the syscall entry),
            the forked child starts just before that syscall."""

        def printregs(s, proc):
            print(s, "ip= %#x\trax=%#x\torig_rax=%#x" % (
                proc.getInstrPointer(), proc.getreg("rax"), proc.getreg("orig_rax")))

        process = self.ptraceProcess
        ip = process.getInstrPointer()  # save state
        regs = process.getregs()

        at_syscall_entry = process.syscall_state.next_event == "exit"  # if process is about to syscall, dont inject

        if at_syscall_entry:  # user wants to fork just before a syscall
            assert process.getreg(
                "rax") == 0xffFFffFFffFFffda  # rax == -ENOSYS means we are most likely about to enter a syscall
            process.setreg("orig_rax", 57)
        else:
            original = process.readBytes(ip, len(inject))
            process.setreg("rax", 57)  # fork code
            process.writeBytes(ip, inject)

        process.singleStep()  # continue till fork happended
        event = process.waitEvent()
        # print("got event_stop", event, "pid=", process.pid)
        from ptrace.debugger.process_event import NewProcessEvent
        assert isinstance(event, NewProcessEvent)

        process.syscall()  # exit fork syscall
        process.waitSyscall()

        # restore state in parent and child process
        child = process.debugger.list[-1]
        assert child.getreg("rax") == 0  # successful fork

        process.setregs(regs)
        child.setregs(regs)

        if at_syscall_entry:
            # we just returned from our "inserted" fork syscall
            # now we need to restore the original state, meaning our
            # parent has to enter a syscall again. After that, restore registers
            ip = process.getInstrPointer()
            process.setInstrPointer(ip - 2)

            process.syscall()
            process.waitSyscall()
            process.setregs(regs)

            orig_rax = process.getreg("orig_rax")  # child will enter syscall when user continues
            child.setreg("rax", orig_rax)
            child.setInstrPointer(ip - 2)
        else:
            process.writeBytes(ip, original)
            child.writeBytes(ip, original)

        child = ProcessWrapper(parent=self, ptraceprocess=child)
        self.children.append(child)
        return child

    def getFamily(self):
        def getRepr(procWrap: ProcessWrapper):
            return str(procWrap.getPid())

        def getChildren(procWrap: ProcessWrapper):
            return procWrap.children

        return format_tree(self, getRepr, getChildren)

    def insertBreakpoint(self, adress):
        adress = self.programinfo.getAddrOf(adress)
        if adress is None:
            return

        return self.ptraceProcess.createBreakpoint(adress)

    def reinstertBreakpoint(self):
        """makes sure that breakpoints are reinserted"""
        proc = self.ptraceProcess

        ip = proc.getInstrPointer() - 1
        bp = proc.findBreakpoint(ip)
        bp.desinstall(set_ip=True)

        # if the breakpoint was set at a syscall, it will be reinserted after the syscall was executed
        self.remember_insert_bp = ip

    def _reinstertBreakpoint(self):
        """ this is the actual insertion of the breakpoint"""
        ip = self.remember_insert_bp
        proc = self.ptraceProcess
        self.remember_insert_bp = False
        proc.singleStep()
        event = proc.waitEvent()

        proc.createBreakpoint(ip)
        assert isinstance(event, ProcessSignal)
        return event

    def removeBreakpoint(self, address):
        proc = self.ptraceProcess
        bp = proc.findBreakpoint(address)
        if not bp:
            print("no breakpoint at %#x" % address)
        else:
            proc.removeBreakpoint(bp)
            print("breakpoint removed")

    def tryFunction(self, funcname, *args):
        clone = self.forkProcess()
        clone.callFunction(funcname, *args)

    def callFunction(self, funcname, *args, tillResult=False):
        """ immediately calls a desired function by overwriting code that is about to be executed.
            State will be restored as soon as function returns.
            Can not be called if the process just entered syscall"""
        func_ad = self.programinfo.getAddrOf(funcname)
        if func_ad is None:
            print("function %s not found" % funcname)
            return

        proc = self.ptraceProcess
        if proc.syscall_state.next_event == "exit":
            print("about to call syscall, returning")
            return
        if self.inserted_function_data:
            print("already in an inserted function, returning")
            return

        inject = """
            mov eax, %#x
            call eax
            int3""" % func_ad
        inject = pwn.asm(inject)

        oldregs = proc.getregs()

        argregs = ["rdi", "rsi", "rdx", "r10"]  # set new args (depends on calling convention)
        if len(args) > len(argregs):
            raise ValueError("too many arguments supplied")
        for (val, reg) in zip(args, argregs):
            proc.setreg(reg, val)

        ip = proc.getInstrPointer()
        oldbytes = proc.readBytes(ip, len(inject))
        proc.writeBytes(ip, inject)
        finish = ip + len(inject)  # if ip==finish, call afterCallFunction

        self.inserted_function_data = (ip, finish, oldbytes, oldregs, funcname)

        res = self.cont()
        return "none" if res is None else res

    def _afterCallFunction(self):
        proc = self.ptraceProcess
        originalip, finish, oldbytes, oldregs, funcname = self.inserted_function_data

        proc.writeBytes(originalip, oldbytes)
        result = proc.getreg("rax")
        proc.setregs(oldregs)
        self.inserted_function_data = None
        return "%s returned %#x" % (funcname, result)

    def malloc(self, n):
        return self.callFunction("plt.malloc", n)

    def free(self, pointer, force=False):
        return self.callFunction("plt.free", pointer)

    def singlestep(self):
        return self.cont(singlestep=True)

    def cont(self, signum=0, singlestep=False):

        proc = self.ptraceProcess

        self.syscallsToTrace = ["read", "write", "fork"]

        event = self.getNextEvent(signum, singlestep)
        if isinstance(event, str):  # happens if an interesting syscall is hit
            return event

        if isinstance(event, ProcessSignal):
            if event.signum == SIGTRAP:  # normal trap, maybe breakpoint?
                ip = proc.getInstrPointer()

                if self.inserted_function_data and self.inserted_function_data[1] == ip:
                    return self._afterCallFunction()

                elif ip - 1 in proc.breakpoints.keys():  # did we hit a breakpoint?
                    self.reinstertBreakpoint()
                    return "hit breakpoint at %#x" % (ip - 1)

                elif singlestep:
                    return "ip=%#x" % ip

                else:
                    print(event)
                    raise NotImplementedError
            else:
                if event.signum in SIGNALS_IGNORE.values():
                    event.signum = 0
                else:
                    print("got %s, sending it back and continuing" % event)

                return self.cont(event.signum, singlestep)

        else:
            print(event, type(event))
            if isinstance(event, ProcessEvent):
                raise event

            raise NotImplementedError

    #
    #
    def getNextEvent(self, signum=0, singlestep=False):
        """ continues execution until an interesing syscall is entered/exited or
            some other event (hopyfully breakpoint sigtrap) happens"""

        def isSysTrap(event):
            return isinstance(event, ProcessSignal) and event.signum == 0x80 | SIGTRAP

        def isTrap(event):
            return isinstance(event, ProcessSignal) and event.signum == SIGTRAP

        def feedStdin(syscall):
            """called if process wants to read from stdin"""
            assert syscall.result is None  # make sure we are not returning from a syscall
            count = syscall.arguments[2].value  # how much is read
            if len(self.stdin_buf) == 0:
                print("process requests %d bytes from stdin" % (count))
                self.stdinRequested = count
                return 0
            else:
                return count, self.writeBufToPipe(count)

        if self.stdinRequested:
            if self.writeBufToPipe(self.stdinRequested) == 0:
                return "no data to stdin was provided"
            self.stdinRequested = 0

        #
        '''this is the actual start of the function'''
        proc = self.ptraceProcess
        assert isinstance(proc, PtraceProcess)  # useless comment:

        # if we are continuing from a breakpoint, singlestep over the breakpoint and reinsert it.
        # if we are not singlestepping and did not hit a syscall / exceptional event, continue till next syscall
        if self.remember_insert_bp:
            event = self._reinstertBreakpoint()
            if not singlestep and isTrap(event):
                proc.syscall()
                event = proc.waitEvent()
        else:
            if singlestep:
                proc.singleStep(signum)
            else:
                proc.syscall(signum)
            event = proc.waitEvent()

        if not isSysTrap(event):
            return event

        state = proc.syscall_state
        syscall = state.event(self.syscall_options)

        # if process is about to read from stdin, feed it what we have. if nothing is available, notify user
        if syscall.name == "read" and state.next_event == "exit" and \
                syscall.arguments[0].value == 0:
            written = feedStdin(syscall)
            if written == 0:
                return "no data to stdin was provided"
            else:
                print("process requests %d bytes from stdin (%d written)" % written)

        # skip over boring syscalls
        if syscall.name not in self.syscallsToTrace:
            if syscall.result is not None and PRINT_BORING_SYSCALLS:  # print results of boring syscalls
                print("syscall %s = %s" % (syscall.format(), syscall.result_text))

            return self.getNextEvent()

        # we are tracing the specific syscall
        else:
            if syscall.result is not None:  # just returned
                return "%s = %s" % (syscall.name, syscall.result_text)
            else:  # about to call
                return "process is about to syscall %s" % syscall.format()

    def finish(self):
        """ run until the current function is finished
            detected by monitoring $rsp
            might break with compiler-optimisations"""
        proc = self.ptraceProcess
        saved_rsp = rsp = proc.getreg("rsp")

        while rsp <= saved_rsp:
            self.cont(singlestep=True)
            rsp = proc.getreg("rsp")

        print("rsp = %#x" % proc.getreg("rsp"))
        print("rip = %#x" % proc.getreg("rip"))

        print(self.programinfo.where(proc.getreg("rip")))

    def examine(self, cmd):
        size_modifiers = dict([("b", (1, "B")), ("h", (2, "H")), ("w", (4, "L")), ("g", (8, "Q"))])
        instr, _, cmd = cmd.partition(" ")

        # check if user specified some special formatting
        if "/" in instr:
            _, _, instr = instr.partition("/")
            args = PRINT_ARGS_REGEX.match(instr)
            count = int(args.group(1))
            fmt = args.group(2)
            if fmt not in size_modifiers.keys():
                if fmt:
                    warning("fmt %s is not an option" % fmt)
                fmt = "w"
        else:
            count = 1
            fmt = "w"

        size, unpack_fmt = size_modifiers[fmt]
        unpack_fmt = "<" + unpack_fmt

        try:
            address = parseInteger(cmd, self.ptraceProcess)

            # make sure adress is in virtual adress space
            where_symbol, where_ad = self.programinfo.where(address)
        except ValueError as e:
            return str(e)

        # read data from memory and print it accordingly
        symbol_delta = address - where_ad
        bytesread = self.ptraceProcess.readBytes(address, size * count)

        newLineAfter = 16 // size
        line_pref = lambda offset: where_symbol + "+%#x" % (symbol_delta + offset)
        result = ""

        format_str = "  %0" + "%d" % (size * 2) + "x"

        for i, value in enumerate(iter_unpack(unpack_fmt, bytesread)):
            if i % newLineAfter == 0:
                result += "\n" + line_pref(i)
            result += format_str % value

        return result[1:]  # remove first newline

    def print(self, cmd: str):
        instr, _, cmd = cmd.partition(" ")
        try:
            result = hex(parseInteger(cmd, self.ptraceProcess))
        except ValueError as e:
            result = str(e)
        return result


import re

PRINT_ARGS_REGEX = re.compile(r"([0-9]*)"
                              r"([gbw]?)")

inject = pwn.asm("syscall", arch="amd64")
