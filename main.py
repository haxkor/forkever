from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

from ProcIOWrapper import ProcessWrapper
from select import poll, POLLIN, POLLERR, POLLPRI

from subprocess import Popen

from ptrace.debugger import PtraceDebugger

import pwn
from ptrace.debugger.process_event import ProcessExecution

hyx_path = "/"

path_launcher = "launcher/dummylauncher"
path_tohack = "launcher/babymalloc"
socketname = "/tmp/paulasock"

from HeapGetter import HeapWriter

from PaulaPoll import PaulaPoll

class Paula():
    def __init__(self, socketname):
        self.socketname = socketname
        self.inputPoll = PaulaPoll()

        self.stdinQ = PollableQueue()
        self.inputPoll.register(self.stdinQ.fileno(), "userinput")

        self.reader_thread = Thread(target=mainReader, args=(self.stdinQ,))
        self.reader_thread.start()

        self.hyxTalker=None

        self.processList = []
        self.debugger = self.startDebugger([path_launcher, path_tohack])


    # attach everything, then (maybe) launch hyx

    def inputLoop(self):
        # input loop

        mask = POLLERR | POLLPRI | POLLIN
        self.inputPoll.register(self.stdinQ.fileno(), mask)

        self.quit_var = False
        while not self.quit_var:
            pollresult = self.inputPoll.poll()
            assert len(pollresult) > 0


            if len(pollresult) == 1:
                name,pollfd,event = pollresult[0]
                if name== "hyx":
                    pass
                elif name == "userinput":
                    self.handle_stdin(pollfd,event)
                elif True:
                    pass

            else:
                raise NotImplementedError

    # this is called when a new line has been put to the stdinQ
    def handle_stdin(self, fd,event):
        cmd = self.stdinQ.get()

        if cmd == "hyx" and not self.hyxTalker:
            # TODO
            self.init_hyx()

    def handle_hyx(self, pollresult):
        fd, events = pollresult
        assert self.hyxTalker  # user asked for hyx first
        # check events here

        check = self.hyxTalker.hyxsock.recv(1)

    def addProcess(self,proc:ProcessWrapper):
        self.processList.append(proc)
        self.inputPoll.register(proc.getfileno("err"), "%d-err"%proc.ptraceProcess.pid)
        self.inputPoll.register(proc.getfileno("out"), "%d-out"%proc.ptraceProcess.pid)


    def startDebugger(self, args):

        debugger = PtraceDebugger()
        debugger.traceFork()
        debugger.traceExec()

        newProcess = ProcessWrapper(args=args, debugger=debugger, redirect=True)  # first process
        self.addProcess(newProcess)

        return debugger


    def init_hyx(self):
        from HyxTalker import HyxTalker
        assert len(self.processList) == 1
        procWrap = self.processList[0]
        file_path = procWrap.heap.file_path
        offset= procWrap.heap.start
        self.hyxTalker= HyxTalker(socketname, file_path, offset )

        self.inputPoll.register(self.hyxTalker.getSockFd(), "hyx")


if __name__ == "__main__":

    p=Paula(socketname)
    p.inputPoll()

