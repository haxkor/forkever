from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

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
    def __init__(self, socketname:str, pollobj:PaulaPoll):
        self.socketname = socketname
        self.pollobj= pollobj   # PollObj used by the input monitor, needed to register new processes



        self.processList = []
        self.debugger = self.startDebugger([path_launcher, path_tohack])
        self.currentProcess= self.processList[0]




    def addProcess(self, proc: ProcessWrapper):
        self.processList.append(proc)
        self.pollobj.register(proc.getfileno("err"), "%d-err" % proc.ptraceProcess.pid)
        self.pollobj.register(proc.getfileno("out"), "%d-out" % proc.ptraceProcess.pid)

    def startDebugger(self, args):

        debugger = PtraceDebugger()
        debugger.traceFork()
        debugger.traceExec()

        newProcess = ProcessWrapper(args=args, debugger=debugger, redirect=True)  # first process
        self.addProcess(newProcess)

        return debugger

    def getCurrentProcess(self):
        return self.currentProcess


if __name__ == "__main__":

    p = ProcessManager(socketname)
    try:
        p.inputLoop()
    except EOFError:  # KeyboardInterrupt:
        print("exit")
        exit(5)
