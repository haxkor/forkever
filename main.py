from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

from ProcIOWrapper import ProcessIOWrapper
from select import poll, POLLIN,POLLERR,POLLPRI

from subprocess import Popen

from ptrace.debugger import PtraceDebugger

import pwn
from ptrace.debugger.process_event import ProcessExecution



hyx_path= "/"

path_launcher = "/launcher/dummylauncher"
path_tohack = "/launcher/babymalloc"



class Paula():
    def __init__(self):

        self.stdinQ=PollableQueue()
        self.reader_thread= Thread(target=mainReader, args=(self.stdinQ,))
        self.reader_thread.start()

        args=[path_launcher, path_tohack]   # extract this
        self.setupProcess(args)  # self attributes will be set in here

        self.inputPoll= poll()


        self.inputLoop()


    #attach everything, then (maybe) launch hyx


    def inputLoop(self):
        # input loop

        todopoll = self.inputPoll
        mask= POLLERR | POLLPRI | POLLIN
        todopoll.register(self.stdinQ.fileno(),mask)
        todopoll.register(tohack.out_pipe.readobj.fileno())

        self.quit_var= False
        while not self.quit_var:
            pollresult= todopoll.poll()

            assert len(pollresult) > 0

            if len(pollresult) == 1:
                pollfd= pollresult[0][0]
                if hyxfd == pollfd:
                    handle_hyx(pollresult[0])

                elif stdinQ.fileno() in pollfd:
                    self.handle_stdin( pollresult[0])
                elif True:
                    handle("debug", pollresult[0])

            else:
                raise NotImplementedError


    # this is called when a new line has been put to the stdinQ

    def handle_stdin(self,pollresult):
        from HyxTalker import HyxTalker
        fd, events= pollresult
        cmd= self.stdinQ.get()

        if cmd == "hyx":
            self.hyxTalker= HyxTalker()



    def handle_hyx(self,pollresult):
        fd, events= pollresult
        assert self.hyxTalker   # user asked for hyx first
        # check events here

        check= self.hyxTalker.hyxsock.recv(1)








    def setupProcess(self,args):

        self.debugger= PtraceDebugger()
        self.debugger.traceFork()
        self.debugger.traceExec()

        self.ProcWrap=ProcessIOWrapper(args)

        ptrace_proc= self.debugger.addProcess(self.procWrap.process.pid, is_attached=False, seize=True)
        ptrace_proc.interrupt() # seize does not automatically interrupt the process
        ptrace_proc.setoptions(self.debugger.options)

        launcher_ELF= pwn.ELF(path_launcher)    # get ready to launch
        ad=launcher_ELF.symbols["go"]
        ptrace_proc.writeBytes(ad, b"gogo")

        # process will be interrupted after new execution
        ptrace_proc.cont()
        assert ptrace_proc.waitEvent() == ProcessExecution

        self.procWrap.PtraceProcess = ptrace_proc
        return ptrace_proc




















