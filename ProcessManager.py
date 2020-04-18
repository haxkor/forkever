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


class ProgramInfo:

    def __init__(self, path_to_hack):
        self.elf= pwn.ELF(path_to_hack)

    def getAddrOf(self, symbol):
        try:
            return self.elf.symbols[symbol]
        except KeyError:
            return None


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

        self.programinfo= ProgramInfo(path_to_hack)

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

    def getNextEvent(self, procWrap):
        """ continues execution until an interesing syscall is entered/exited or
            some other event (hopyfully breakpoint sigtrap) happens"""

        def isSysTrap(event):
            return isinstance(event, ProcessSignal) and event.signum == 0x80 | SIGTRAP

        def printregs(s="", proc=procWrap.ptraceProcess):
            print(s, "ip= %#x\trax=%#x\torig_rax=%#x" % (
                proc.getInstrPointer(), proc.getreg("rax"), proc.getreg("orig_rax")))

        if procWrap.stdinRequested:
            if procWrap.writeBufToPipe(procWrap.stdinRequested) == 0:
                print("no data to stdin was provided")
                return
            procWrap.stdinRequested = 0

        proc = procWrap.ptraceProcess
        assert isinstance(proc, PtraceProcess)

        proc.syscall()
        event = proc.waitEvent()

        if not isSysTrap(event):  # TODO check if event happened while in syscall
            return event

        state = proc.syscall_state
        syscall = state.event(self.syscall_options)

        # if process is about to read from stdin, feed it what we have. if nothing, notify user
        if syscall.name == "read" and state.next_event == "exit" and \
                syscall.arguments[0].value == 0:
            assert syscall.result is None  # make sure we are not returning from a syscall

            count = syscall.arguments[2].value  # how much is read
            if len(procWrap.stdin_buf) == 0:
                print("process requests %d bytes from stdin" % (count))
                procWrap.stdinRequested = count
                return
            written = procWrap.writeBufToPipe(count)
            print("process requests %d bytes from stdin (%d written)" % (count, written))

        # skip over boring syscalls
        if syscall.name not in self.syscallsToTrace:
            if syscall.result is not None:  # print results of boring syscalls
                #print("syscall %s = %s" % (syscall.format(), syscall.result_text))
                pass

            return self.getNextEvent(procWrap)

        # we are tracing the specific syscall
        else:
            if syscall.result is not None:  # just returned
                print("%s = %s" % (syscall.name, syscall.result_text))
            else:  # about to call
                print("process is about to syscall %s" % syscall.format())

    def insertBreakpoint(self, adress):
        procWrap = self.getCurrentProcess()

        proc = procWrap.ptraceProcess

        return proc.createBreakpoint(adress)

    def _reinstertBreakpointAfterSyscall(self, procWrap):
        """if a breakpoint was set on a syscall, it is readded after the syscall is done
            (called by getNextEvent)"""
        proc = procWrap
        ip = proc.getInstrPointer() - 2  # syscall instruction is 2 long
        proc.createBreakpoint(ip)
        procWrap.remember_readd_breakpoint = False

    def reinstertBreakpoint(self):
        """makes sure that breakpoints are reinserted"""
        from ptrace.debugger.process import Breakpoint
        procWrap = self.getCurrentProcess()
        proc = procWrap.ptraceProcess

        ip = proc.getInstrPointer() - 1
        bp = proc.findBreakpoint(ip)
        bp.desinstall(set_ip=True)

        # if the breakpoint was set at a syscall, it will be reinserted after the syscall was executed
        if proc.readBytes(ip, 2) == b'\x0f\x05':
            procWrap.remember_insert_bp = True

        else:
            proc.singleStep()
            proc.waitSignals(SIGTRAP)
            proc.createBreakpoint(ip)

    def removeBreakpoint(self, address):
        procWrap = self.getCurrentProcess()
        proc = procWrap.ptraceProcess

        bp = proc.findBreakpoint(address)
        if not bp:
            print("no breakpoint at %#x" % address)
            return

        proc.removeBreakpoint(bp)
        print("breakpoint removed")


    def callFunction(self, funcname, *args):
        func_ad= self.programinfo.getAddrOf(funcname)

        procWrap= self.getCurrentProcess()
        proc= procWrap.ptraceProcess
        if proc.syscall_state.next_event == "exit":
            print("about to call syscall, returning")
            return
        if procWrap.inserted_function_data:
            print("already in an inserted function, returning")
            return

        inject="""
            mov eax, %d
            call eax
            int3""" % func_ad
        inject=pwn.asm(inject)

        oldregs= proc.getregs()

        proc.setreg("rdi", args[0])

        ip= proc.getInstrPointer()
        oldbytes= proc.readBytes(ip, len(inject))
        proc.writeBytes(ip,inject)
        finish= ip + len(inject)

        procWrap.inserted_function_data= (ip,finish, oldbytes, oldregs, funcname )
        self.cont()

    def _afterCallFunction(self):
        procWrap = self.getCurrentProcess()
        proc = procWrap.ptraceProcess

        originalip, finish, oldbytes, oldregs, funcname =  procWrap.inserted_function_data

        proc.writeBytes(originalip, oldbytes)

        result= proc.getreg("rax")
        print("%s returned %#x" % (funcname, result))
        proc.setregs(oldregs)
        procWrap.inserted_function_data= None


    def malloc(self,n):
        self.callFunction("plt.malloc",n)





    def singlestep(self):
        procWrap = self.getCurrentProcess()
        proc = procWrap.ptraceProcess

        proc.singleStep()
        event = proc.waitEvent()
        print(event, "signum= %#x" % event.signum)

    def cont(self):
        procWrap = self.getCurrentProcess()
        proc = procWrap.ptraceProcess


        if procWrap.inserted_function_data:
            print(procWrap.inserted_function_data)



        self.syscallsToTrace = ["read", "write", "fork"]

        event = self.getNextEvent(procWrap)
        if event is None:  # happens if an interesting syscall is hit
            return

        if procWrap.inserted_function_data:
            print("finiship= %#x" % procWrap.inserted_function_data[1])
            print("calling aftercall")
            self._afterCallFunction()

        print("cont event=", event)

        if isinstance(event, ProcessSignal):
            if event.signum == SIGTRAP:  # normal trap, maybe breakpoint?
                ip = proc.getInstrPointer()
                if ip - 1 in proc.breakpoints.keys():
                    print("hit breakpoint at %#x" % (ip - 1))
                    procWrap.atBreakpoint = True
                    # self.resumeFromBreakpoint()

                if procWrap.atBreakpoint:   # did we just return from an inserted function?
                    self.reinstertBreakpoint()
                    procWrap.atBreakpoint = False



                # check if breakpoint
                pass
            else:
                print(event)

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
