from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

from ptrace.debugger.ptrace_signal import ProcessSignal, ProcessEvent
from signal import SIGTRAP

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


class ContextContinue:
    def __init__(self):
        self.about_to_call_interesting_syscall = False
        self.firsttime=True
        self.writeStdin=False

class ProcessManager:
    def __init__(self, path_to_hack, socketname:str, pollobj:PaulaPoll):
        self.socketname = socketname
        self.pollobj= pollobj   # PollObj used by the input monitor, needed to register new processes



        self.processList = []
        self.debugger = self.startDebugger([path_launcher, path_to_hack])
        self.currentProcess= self.processList[0]




    def addProcess(self, proc: ProcessWrapper):
        self.processList.append(proc)
        self.pollobj.register(proc.out_pipe.fileno("read"), "proc-out")
        self.pollobj.register(proc.err_pipe.fileno("read"), "proc-err")

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
        def isSysTrap(event):
            return isinstance(event,ProcessSignal) and event.signum == 0x80 | SIGTRAP


        try:
            context=self.context
        except AttributeError:
            self.context = ContextContinue()
            context=self.context



        def getNextEvent():
            """ continues execution until either an interesting syscall is about to be executed
                or a non-syscall-trap occurs"""

            def manageStdinRead():
                # if the user does not care about read or some data is available, just give that data to stdin
                # returns wether to continue or not
                requested= proc.getreg("rdx")
                if len(procWrap.stdin_buf) > 0:
                    written=procWrap.writeBufToPipe(requested)
                    print("wrote %d bytes to stdin" % written)
                    return True
                else:
                    context.writeStdin= requested
                    if len(procWrap.stdin_buf) == 0:
                        print("process wants to read %d bytes from stdin, none is available." % (requested))
                        print("use w data to avoid lock")
                    return False



            # getNextEvent might be called for the first time when the process just entried syscall
            if context.firsttime:
                context.firsttime=False
                if proc.getreg("rax") != -38:   # rax is -38 if process is about to enter a syscall
                    # treat the first syscall as interesting, meaning we stop after it.
                    context.about_to_call_interesting_syscall=True
                    return getNextEvent()

            if context.writeStdin:  # if stdin is hungry and we did not feed it in the previous call, do it now
                procWrap.writeBufToPipe(context.writeStdin)
                context.writeStdin= 0

            if context.about_to_call_interesting_syscall:   # we previosly halted at syscall entry because it was interesting
                proc.syscall()
                event= proc.waitEvent() # wait for return of syscall
                if isSysTrap(event):
                    # interesting syscall completed
                    context.about_to_call_interesting_syscall= False
                    print("syscall %d returned %#x" % (proc.getreg("orig_rax"), proc.getreg("rax")))
                    return None
                else:   # event happened in the syscall
                    raise NotImplementedError

            # step to next event, if its a syscall-entry-trap check if the syscall is interesting
            # if its an interesting syscall return, otherwise continue until
            # an interesting syscall or another event occurs
            else:
                proc.syscall()
                event=proc.waitEvent()  # this might be syscall entry

                if isSysTrap(event):
                    orig_rax = proc.getreg("orig_rax")
                    if orig_rax == 0 and proc.getreg("rdi") == 0:   # write this when continuing
                        can_continue= manageStdinRead()
                        if not can_continue:
                            context.about_to_call_interesting_syscall= True

                            return None
                        #written = procWrap.writeBufToPipe(proc.getreg("rdi"))
                        #print("read %d bytes from stdin" % written)

                    if orig_rax in self.syscallsToTrace:
                        print("stopped, process is about to syscall %d" % orig_rax)
                        context.about_to_call_interesting_syscall=True
                        return None
                    else:       # finish syscall, continue execution
                        proc.syscall()
                        proc.waitSyscall()    # this is syscall exit
                        print("syscall %d returned %#x" % (proc.getreg("orig_rax"), proc.getreg("rax")))
                        return getNextEvent()

                else:       # not syscall entry
                    return event
        procWrap= self.getCurrentProcess()










        assert isinstance(procWrap, ProcessWrapper)
        proc = procWrap.ptraceProcess
        self.syscallsToTrace= [0,16, 21]

        event= getNextEvent()
        if event is None:
            return

        assert not isSysTrap(event)

        if isinstance(event, ProcessSignal):
            if event.signum == SIGTRAP:    # normal trap, maybe breakpoint?
                # check if breakpoint
                pass
            else:
                raise NotImplementedError



        #print("cont got something else:", event)
        print("instruction pointer= %#x" % proc.getInstrPointer())

    def fork(self):
        procWrap= self.getCurrentProcess()
        self.addProcess(procWrap.forkProcess())



    def procSwitch(self):
        ind= self.processList.index(self.getCurrentProcess())

        if ind==0:
            self.currentProcess= self.processList[1]
        else:
            self.currentProcess= self.processList[0]






    def write(self,text):
        procWrap= self.getCurrentProcess()
        procWrap.writeToBuf(text)




