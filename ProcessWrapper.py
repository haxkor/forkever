import re
from mmap import PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS
from signal import SIGTRAP
from struct import iter_unpack, pack, error as struct_error
from subprocess import Popen

import pwn

from Constants import (PRINT_BORING_SYSCALLS, USE_ASCII,
                       SIGNALS_IGNORE, path_launcher, LOAD_PROGRAMINFO)
from logging2 import info, debug, warning
from ptrace.debugger.process import PtraceProcess, PtraceError
from ptrace.debugger.process_event import ProcessExecution, ProcessEvent
from ptrace.debugger.ptrace_signal import ProcessSignal
from ptrace.func_call import FunctionCallOptions
from ptrace.tools import locateProgram
from utilsFolder.Parsing import parseInteger
from utilsFolder.PaulaPipe import Pipe
from utilsFolder.ProgramInfo import ProgramInfo
from utilsFolder.tree import format_tree, format_ascii_tree


class LaunchArguments:

    def __init__(self, argvlist, random: bool):
        self.path = locateProgram(argvlist[0])
        argvlist[0] = self.path
        self.argvlist = argvlist
        self.random = random


class InsertedGadgets:
    """bundles the addresses for the various inserted  instructions"""

    def __init__(self, segmentstart: int, functioncall: int, nop: int, forkcode: int):
        self.segmentstart = segmentstart
        self.functioncall = functioncall
        self.nop = nop
        self.forkcode = forkcode


PRINT_ARGS_REGEX = re.compile(r"([0-9]*)"
                              r"([ighbw]?)")

write_arg_regex = re.compile(
    r"(pack\(\"?([<>][a-zA-Z])?\"?,?[ ]*((0x)?[0-9a-fA-F]+)\))|"
    r"(b\"[\w\W]*\"|b\'[\w\W]*\')|([\w\W]*)")

inject_syscall_instr = pwn.asm("syscall", arch="amd64")


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
        self.syscalls_to_trace = parent.syscalls_to_trace if parent else None  # first will be set by ProcessManager
        self.own_segment = None
        self._nop_addr = None

        if args:
            assert debugger is not None
            assert not parent

            self.disable_randomization = not args.random

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

            args = [path_launcher] + args.argvlist
            self.popen_obj = Popen(args, stdin=self.in_pipe.readobj, stdout=stdout_arg, stderr=stderr_arg)

            self.debugger = debugger
            self.ptraceProcess = self.setupPtraceProcess()  # launches actual program, halts immediately

            self.heap = None

            self.programinfo = ProgramInfo(args[1], self.getPid(), self)

            self.wait_for_SIGNAL(0)  # setup own mmap page

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
            self._copyBreakpoints()

            self.heap = None
            self.own_segment = parent.own_segment
            self._nop_addr = parent._nop_addr

            # if the process spawns new children for other purposes, it might load another library.
            # the loaded path could be determined TODO
            if LOAD_PROGRAMINFO:  # can be disabled in Constants to improve performance
                try:
                    self.programinfo = ProgramInfo(parent.programinfo.path_to_hack,
                                                   self.ptraceProcess.pid, self)
                except ValueError as e:  # if another library is loaded instead of our initial executable
                    self.programinfo = ProgramInfo(None, self.ptraceProcess.pid, self)

    def _copyBreakpoints(self):
        """this is used to creaty new breakpoint python objects for a forked process
        It could be optimized to create these Breakpoints without reading/writing again"""
        debug("cloning breakpoints")
        from ptrace.debugger.process import Breakpoint
        debug(self.parent.ptraceProcess.breakpoints)
        for bp in self.parent.ptraceProcess.breakpoints.values():
            debug("bp= %s" % bp)
            assert isinstance(bp, Breakpoint)
            new_bp = self.ptraceProcess.createBreakpoint(bp.address)
            new_bp.old_bytes = bp.old_bytes

        # cover edge case where we just ran into a breakpoint (bp has been temporarily disabled)
        ip = self.parent.remember_insert_bp
        if ip:  # this var stores the address of where the bp has to be inserted
            self.insertBreakpoint(ip)

    def getHeap(self):
        return self.heap

    def setupPtraceProcess(self) -> PtraceProcess:
        from ptrace.debugger.debugger import PtraceDebugger

        assert isinstance(self.debugger, PtraceDebugger)
        ptrace_proc = self.debugger.addProcess(self.popen_obj.pid, is_attached=False, seize=True)
        ptrace_proc.interrupt()  # seize does not automatically interrupt the process
        ptrace_proc.setoptions(self.debugger.options)

        # as soon as this variable is changed, process will launch. Here you can alter the process' personality
        # warning: right now you can only SET flags, you CANNOT UNSET them. This feature can easily be added in launcher
        launcher_ELF = pwn.ELF(path_launcher, False)  # get ready to launch
        ad = launcher_ELF.symbols["add_personality"]

        add_personality = 0
        if self.disable_randomization:
            add_personality += 0x40000
        add_personality = pack("<I", add_personality)
        ptrace_proc.writeBytes(ad, add_personality)

        ptrace_proc.cont()
        event = ptrace_proc.waitEvent()
        assert isinstance(event, ProcessExecution), str(event)  # execve syscall is hit

        ptrace_proc.syscall()
        ptrace_proc.waitSyscall()

        return ptrace_proc

    def addBreakpoints(self, *bp_list):
        def addSingleBP(breakpoint):
            self.ptraceProcess.createBreakpoint(breakpoint)

        for bp in bp_list:
            addSingleBP(bp)

    def readMappings(self):
        return self.ptraceProcess.readMappings()

    def writeToBuf(self, text: str):
        """write to the processes stdin.
        Use:
        w AA
        w b"\x41\x41\n"
        w b'AA'     (no newline added)
        w pack(421)     (equal to pack("<Q",421)
        w pack(<I, 421)

        If you write a normal string, a newline is added at the end.
        Note that it isnt directly written to its stdin, but instead written to an internal buffer.
        Upon a read syscall (trying to consume from stdin), the buffers contents are written to the actual stdin.
        This means that if you write to stdin and fork before consumption, both processes will get to consume
        what you have previously written."""

        match = write_arg_regex.match(text)

        if match.group(1):
            fmt = match.group(2) if match.group(2) else "<Q"  # remove , from fmt
            val = match.group(3)
            debug("%s %s" % (val, fmt))
            val = int(val, 16 if val.startswith("0x") else 10)
            try:
                text = pack(fmt, val)
            except struct_error as e:
                print(e)
                return

        else:
            text = (match.group(6) + "\n").encode() if match.group(6) \
                else eval(match.group(5))

        assert isinstance(text, bytes), "%s" % type(text)
        print("writing ", text)

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
            raise ValueError

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

    def forkProcess(self):
        """ forks the process. If the process just syscalled (and is trapped in the syscall entry),
        the forked child starts just before that syscall.

        The processManager will switch to the newly created child automatically.

        Usage:  fork gonna_crash_this       (name is optional)"""
        """How does it work?
        If the process is about to enter a syscall:
            Modify $rax to contain the "fork" syscall code.
        Else:
            Insert a syscall instruction at the current $rip

        Step over the syscall, start tracing the new child.
        Restore the states of both processes. (Child does not reenter syscall)
        """

        process = self.ptraceProcess
        ip = process.getInstrPointer()  # save state
        regs = process.getregs()

        at_syscall_entry = process.syscall_state.next_event == "exit"  # if process is about to syscall, dont inject

        if at_syscall_entry:  # user wants to fork just before a syscall
            assert process.getreg(
                "rax") == 0xffFFffFFffFFffda  # rax == -ENOSYS means we are most likely about to enter a syscall
            process.setreg("orig_rax", 57)
        else:
            original = process.readBytes(ip, len(inject_syscall_instr))
            process.setreg("rax", 57)  # fork code
            process.writeBytes(ip, inject_syscall_instr)

        process.singleStep()  # continue till fork happended
        event = process.waitEvent()
        from ptrace.debugger.process_event import NewProcessEvent
        if not isinstance(event, NewProcessEvent):
            rax = process.getreg("rax") - 2 ** 64
            import errno
            warning(errno.errorcode[-rax])
        assert isinstance(event, NewProcessEvent), str(event)

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
        """print all children of the process"""

        def getRepr(procWrap: ProcessWrapper):
            return str(procWrap.getPid())

        def getChildren(procWrap: ProcessWrapper):
            return procWrap.children

        if USE_ASCII:
            return format_ascii_tree(self, getRepr, getChildren)
        else:
            return format_tree(self, getRepr, getChildren)

    def insertBreakpoint(self, adress):
        if not isinstance(adress, int):
            adress = parseInteger(adress, self)

        if adress is None:
            return

        result = self.ptraceProcess.createBreakpoint(adress)
        return result

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
        """removes breakpoint"""
        if isinstance(address, str):
            address = parseInteger(address, self)
        assert isinstance(address, int)

        proc = self.ptraceProcess
        bp = proc.findBreakpoint(address)
        if not bp:
            return "no breakpoint at %#x" % address
        else:
            bp.desinstall()
            return "breakpoint removed"

    def callFunction(self, funcname, *args, tillResult=False):
        """ Redirect control flow to call the specified function with given arguments.
            Registers will be restored as soon as function returns.
            If you dont see a result immediately, continue till you have stepped through all
            breakpoints/syscalls
            Does nothing if the process just entered syscall

            If you want to do something right after this syscall, singlestep over it.
            If its a read(stdin) syscall, you need to "trace write"
            or disable auto-continue for write  in Constants.py

            use: call libc:memset $rbp 0x41 0x10
            """
        """How does this work:
            call mmap to map a page where we can inject code.
            the injected code will call the specified function.
            After the specified function is called, it runs into an interrupt.
            The "continue" logic will check for each received trap if we have
            reached this certain interrupt.
            Once that is the case, _afterCallFunction will be called"""

        func_ad = self.programinfo.getAddrOf(funcname)
        if func_ad is None:
            return "function %s not found" % funcname

        proc = self.ptraceProcess
        if proc.syscall_state.next_event == "exit":
            return "about to call syscall, returning"
        if self.inserted_function_data:
            return "already in an inserted function, returning"

        oldregs = proc.getregs()
        inject_at = self.get_own_segment().functioncall

        argregs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]  # set new args (depends on calling convention)
        if len(args) > len(argregs):
            raise ValueError("too many arguments supplied")  # TODO add push(var) functionality
        for (val, reg) in zip(args, argregs):
            proc.setreg(reg, val)

        ip = proc.getInstrPointer()
        finish = inject_at + 3 # if ip==finish, call afterCalen(pwn.asm("call rax\nint3", arch="amd64")) llFunction
        debug(proc.readBytes(inject_at+2,1))

        info("inject_at= %x" % inject_at)
        proc.setInstrPointer(inject_at)
        proc.setreg("rax",func_ad)

        self.inserted_function_data = (ip, finish, oldregs, funcname)

        res = self.cont()  # if you want to debug the injected function, change this to cont(singlestep=True)
        return res if res else "none"

    def _afterCallFunction(self):
        proc = self.ptraceProcess
        _, _, oldregs, funcname = self.inserted_function_data

        result = proc.getreg("rax")
        proc.setregs(oldregs)
        self.inserted_function_data = None
        return "%s returned %#x" % (funcname, result)

    def malloc(self, n):
        """call plt.malloc(n)"""
        return self.callFunction("plt.malloc", n)

    def free(self, pointer):
        """call plt.free(pointer)
        If you want to call libc.free, use callFunction(libc:free, pointer)"""
        return self.callFunction("plt.free", pointer)

    def singlestep(self):
        """singlestep"""
        return self.cont(singlestep=True)

    def cont(self, signum=0, singlestep=False):
        """continue execution of the process
        stops at:
            - a traced syscall  (?trace)
            - an inserted function
            - specified breakpoints"""

        proc = self.ptraceProcess

        event = self._getNextEvent(signum, singlestep)
        if isinstance(event, str):  # happens if an interesting syscall is hit
            return event

        if isinstance(event, ProcessSignal):
            if event.signum == SIGTRAP:  # normal trap, maybe breakpoint?
                ip = proc.getInstrPointer()

                if self.inserted_function_data and self.inserted_function_data[1] == ip:
                    return self._afterCallFunction()

                elif ip - 1 in proc.breakpoints.keys() and not singlestep:  # did we hit a breakpoint?
                    debug("cont calls reinsertBreakpoint")
                    self.reinstertBreakpoint()
                    return "hit breakpoint at %#x" % (ip - 1)

                elif singlestep:
                    return self.where()

                else:
                    print(self.where(), event)
                    raise NotImplementedError
            else:
                if event.signum in SIGNALS_IGNORE.values():
                    event.signum = 0
                else:
                    info("got %s, sending it back and continuing" % event)
                    info(self.where())

                return self.cont(event.signum, singlestep)

        else:
            debug("encountered %s" % event)
            if isinstance(event, ProcessEvent):
                raise event

            raise NotImplementedError

    #
    #
    def _getNextEvent(self, signum=0, singlestep=False):
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

        # check if process is trying to read from stdin, if yes give him what we got
        if self.stdinRequested:
            if self.writeBufToPipe(self.stdinRequested) == 0:
                return "no data to stdin was provided"
            self.stdinRequested = 0

        #
        '''this is the actual start of the function'''
        proc = self.ptraceProcess
        assert isinstance(proc, PtraceProcess)

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
            debug(" getNextEvent returns %s" % event)
            return event

        # everything from hereon is just about dealing with syscalls
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
        if syscall.name not in self.syscalls_to_trace:
            if syscall.result is not None and PRINT_BORING_SYSCALLS:  # print results of boring syscalls
                print("syscall %s = %s" % (syscall.format(), syscall.result_text))

            return self._getNextEvent()

        # we are tracing the specific syscall
        else:
            if syscall.result is not None:  # just returned
                return "%s = %s" % (syscall.name, syscall.result_text)
            else:  # about to call
                return "process is about to syscall %s" % syscall.format()

    def finish(self):
        """DOES NOT WORK PROPERLY
         run until the current function is finished
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
        """examine memory. (use of $reg is possible)
                formatting options:  b,w,h,g"""
        size_modifiers = dict([("b", (1, "B")), ("h", (2, "H")), ("w", (4, "L")), ("g", (8, "Q"))])
        instr, _, cmd = cmd.partition(" ")

        try:
            address = parseInteger(cmd, self)
            # make sure adress is in virtual adress space
            where_symbol, where_ad = self.programinfo.where(address)
        except ValueError as e:
            return str(e)
        except FileNotFoundError:  # happens if we inspect something that is not an ELF file
            where_symbol, where_ad = "", address

        # check if user specified some special formatting
        if "/" in instr:
            _, _, instr = instr.partition("/")
            args = PRINT_ARGS_REGEX.match(instr)
            count = int(args.group(1)) if args.group(1) else 1
            fmt = args.group(2)

            if fmt not in size_modifiers.keys() and fmt is not "i":
                if fmt:
                    print("fmt %s is not an option" % fmt)
                fmt = "w"
        else:
            count = 1
            fmt = "w"

        # special case, disassemble and return early
        if fmt == "i":
            count_read = count
            grow_factor = .5
            while True:
                count_read = int(count_read * (1 + grow_factor))
                try:
                    bytesread = self.ptraceProcess.readBytes(address, count_read)
                except PtraceError as e:  # incase we cant read count*1.5 bytes because memory isnt mapped
                    print(e)  # this is shitty code, but it should almost never occur
                    if grow_factor <= .5 ** (2 * 6):
                        count //= 2
                        grow_factor = 0.5
                    count_read = count
                    grow_factor = grow_factor ** 2
                    continue

                lines = pwn.disasm(bytesread, byte=False, vma=address).splitlines(keepends=True)

                # keep reading more bytes until we cleanly disassemlbe COUNT instructions
                if any(".byte" in line for line in lines[:count]):
                    continue
                else:
                    return "".join(lines)

        # regular case
        size, unpack_fmt = size_modifiers[fmt]
        unpack_fmt = "<" + unpack_fmt

        # read data from memory and print it accordingly
        try:
            bytesread = self.ptraceProcess.readBytes(address, size * count)
        except PtraceError as e:
            return str(e)

        # to print offset
        symbol_delta = address - where_ad
        line_pref = lambda offset: where_symbol + "+%#x" % (symbol_delta + offset)

        format_str = "  %0" + "%d" % (size * 2) + "x"  # to pad with zeros
        newLineAfter = 16 // size

        result = ""
        for i, value in enumerate(iter_unpack(unpack_fmt, bytesread)):
            if i % newLineAfter == 0:
                result += "\n" + line_pref(i)
            result += format_str % value

        return result[1:]  # remove first newline

    def where(self):
        ip = self.ptraceProcess.getInstrPointer()
        where_symbol, where_ad = self.programinfo.where(ip)
        delta = ip - where_ad

        return "RIP = %s + %#x" % (where_symbol, delta)

    def print(self, cmd: str):
        """print.  prefixing with * dereferences the result.
        Otherwise, the * works as the multiplication operator.
        use: p $rax+1+malloc
            p *$rbp+0x10"""
        instr, _, cmd = cmd.partition(" ")
        try:
            result = hex(parseInteger(cmd, self))
        except ValueError as e:
            result = str(e)
        return result

    def getrlimit(self, resource):
        segment = self.get_own_segment() + 0x100
        proc = self.ptraceProcess

        regs = proc.getregs()

        struct_ad = proc.getreg("rsp") - 0x100
        print("struct ad = %x" % struct_ad)
        print(proc.readBytes(struct_ad, 100))

        proc.setreg("rax", 97)
        proc.setreg("rdi", resource)
        proc.setreg("rsi", struct_ad)
        proc.setInstrPointer(segment)
        proc.writeBytes(segment, inject_syscall_instr)

        proc.singleStep()
        proc.waitEvent()

        rax = proc.getreg("rax")
        import errno

        print("rax = %x" % rax, errno.errorcode[-(rax - 2 ** 64)] if rax > 100 else rax)

        print("ip = %x" % proc.getInstrPointer())

        print(proc.readBytes(struct_ad, 100))

    def get_own_segment(self, address=None):  # 0x7f00e1337e000
        """injects an MMAP syscall so we get our own page for code"""
        if self.own_segment:
            return self.own_segment

        start = self.programinfo.getElfStart()
        address = address if address else start - 0x2000

        debug("getownsegment adress = %x" % address)
        proc = self.ptraceProcess

        if proc.syscall_state.next_event == "exit":
            print("about to call syscall, returning")
            return

        # save state
        ip = proc.getInstrPointer()
        old_regs = proc.getregs()
        old_code = proc.readBytes(ip, len(inject_syscall_instr))

        # prepare mmap syscall
        MAP_FIXED_NOREPLACE = 1048576
        prot = PROT_EXEC
        mapflags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE
        length = 0x1000

        fill_regs = ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"]  # calling convention for syscalls
        args = [9, address, length, prot, mapflags, -1, 0]  # syscallcode, ..., filedescriptor, offset
        assert len(args) == len(fill_regs)
        for reg, arg in zip(fill_regs, args):
            proc.setreg(reg, arg)

        proc.writeBytes(ip, inject_syscall_instr)

        # step over the syscall
        proc.syscall()
        proc.waitSyscall()
        proc.syscall()
        proc.waitSyscall()

        result = proc.getreg("rax")
        debug("result= %x" % result)
        if result > 2 ** 63 - 1:
            result -= 2 ** 64
            import errno
            if errno.EEXIST == -result:
                warning("mapping exists")
                return self.get_own_segment(address * 2)

        # restore state
        proc.writeBytes(ip, old_code)
        proc.setregs(old_regs)

        func_addr = address + 0x100
        inject_code = """
                    call rax
                    int3
                    int3
                    int3"""
        inject_code = pwn.asm(inject_code, arch="amd64")
        proc.writeBytes(func_addr, inject_code)

        nop_addr = address + 0x200
        proc.writeBytes(nop_addr, pwn.asm("nop\nint3"))  # TODO jmp 0

        fork_addr = address + 0x300

        self.own_segment = InsertedGadgets(address, func_addr, nop_addr, fork_addr)

        return self.own_segment

    def wait_for_SIGNAL(self, signal: int):
        """catches a signal without changing the state of the process
        (except the own page mapping, but that is currently done at initialization of the process)(docstrings lie sometimes)"""
        if not signal:
            return
        proc = self.ptraceProcess


        regs = proc.getregs()
        proc.setInstrPointer(self.get_own_segment().nop)
        proc.singleStep()
        event = proc.waitEvent()

        assert isinstance(event, ProcessSignal) and event.signum == signal

        proc.setregs(regs)
