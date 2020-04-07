from PollableQueue import PollableQueue
from threading import Thread
from InputReader import mainReader

from ProcIOWrapper import ProcessIOWrapper
from select import poll, POLLIN,POLLERR,POLLPRI

from subprocess import Popen

from ptrace.debugger import PtraceDebugger



hyx_path= "/"

path_launcher = "/launcher/dummylauncher"
path_tohack = "/launcher/babymalloc"



def main():

    stdinQ=PollableQueue()
    reader_thread= Thread(target=mainReader, args=(stdinQ,))
    reader_thread.start()

    args=[path_launcher, path_tohack]

    tohack= ProcessIOWrapper(args)


    # setupProcess()
    #attach everything, then (maybe) launch hyx





    # input loop

    todopoll = poll()
    mask= POLLERR | POLLPRI | POLLIN
    todopoll.register(stdinQ.fileno(),mask)
    todopoll.register(hyxfd,mask)
    todopoll.register(tohack.out_pipe.readobj.fileno())

    quit_var= False
    while not quit_var:
        pollresult= todopoll.poll()

        assert len(pollresult) > 0

        if len(pollresult) == 1:
            pollfd= pollresult[0][0]
            if hyxfd == pollfd:
                handle("hyx", pollresult[0])

            elif stdinQ.fileno() in poll:
                handle("stdin", pollresult[0])
            elif True:
                handle("debug", pollresult[0])

        else:
            raise NotImplementedError





debugger=None


import pwn
from ptrace.debugger.process_event import ProcessExecution
def setupProcess(procWrap: ProcessIOWrapper):
    global debugger
    debugger= PtraceDebugger()
    debugger.traceFork()
    debugger.traceExec()

    ptrace_proc= debugger.addProcess(procWrap.process.pid, is_attached=False, seize=True)
    ptrace_proc.interrupt() # seize does not automatically interrupt the process
    ptrace_proc.setoptions(debugger.options)

    launcher_ELF= pwn.ELF(path_launcher)    # get ready to launch
    ad=launcher_ELF.symbols["go"]
    ptrace_proc.writeBytes(ad, b"gogo")

    # process will be interrupted after new execution
    ptrace_proc.cont()
    assert ptrace_proc.waitEvent() == ProcessExecution
    return ptrace_proc


















