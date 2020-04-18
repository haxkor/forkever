from PaulaPoll import PaulaPoll
from ProcessManager import ProcessManager
from PollableQueue import PollableQueue

from threading import Thread
from InputReader import mainReader

from ProcessWrapper import ProcessWrapper
from HyxTalker import HyxTalker

class InputHandler:

    def __init__(self, path_to_hack):
        self.inputPoll = PaulaPoll()
        self.manager = ProcessManager(path_to_hack,"/tmp/paulasock", self.inputPoll)

        self.stdinQ = PollableQueue()
        self.inputPoll.register(self.stdinQ.fileno(), "userinput")
        self.reader_thread = Thread(target=mainReader, args=(self.stdinQ,))
        self.reader_thread.start()

        self.hyxTalker = None

    def inputLoop(self):

        quit_var = False
        while not quit_var:
            pollresult = self.inputPoll.poll()
            #print(pollresult)
            assert len(pollresult) > 0

            if len(pollresult) == 1:
                name, pollfd, event = pollresult[0]
                if name == "hyx":
                    pass
                elif name == "userinput":
                    self.handle_stdin(pollfd, event)
                elif "-out" in name:
                    self.handle_procout(name, pollfd, event)
                    pass

            else:  # this happens when two sockets are written to at the "same" time
                print(pollresult)
                raise NotImplementedError

    # this is called when a new line has been put to the stdinQ
    def handle_stdin(self, fd, event):
        cmd = self.stdinQ.get()[:-1]  # remove newline
        print(cmd)
        assert isinstance(cmd, str)
        import signal
        if event == signal.SIGWINCH:
            return

        if cmd == "hyx" and not self.hyxTalker:
            self.init_hyx()


        elif cmd.startswith("c"):   # continue
            self.manager.cont()

        elif cmd.startswith("w"):
            self.manager.write(cmd[2:].encode() + b"\n")    #TODO

        elif cmd.startswith("fork"):
            self.manager.fork()

        elif cmd.startswith("proclist"):
            print(self.manager.processList)

        elif cmd.startswith("switch"):
            self.manager.switchProcess()

        elif cmd.startswith("b"):
            if cmd.startswith("b1"):
                self.manager.insertBreakpoint(0x401153)
            elif cmd.startswith("b2"):
                self.manager.insertBreakpoint(0x401148)
            elif cmd.startswith("b3"):
                self.manager.insertBreakpoint(0x401158)
            else:
                self.manager.insertBreakpoint(int(cmd[2:], 16))

        elif cmd.startswith("malloc"):
            self.manager.malloc(10)




        elif cmd.startswith("list b"):
            print(self.manager.getCurrentProcess().ptraceProcess.breakpoints)

        elif cmd.startswith("s"):
            self.manager.singlestep()

        elif cmd.startswith("res"):

            print(self.manager.getCurrentProcess().ptraceProcess.breakpoints)
            self.manager.resumeFromBreakpoint()


    def handle_hyx(self, pollresult):
        raise NotImplementedError
        # should input handler or processmanager handle this? or hyxtalker?
        # receive check value here, forward to the respective hyxtalker function

    def handle_procout(self, name, fd, event):
        procWrap = self.manager.getCurrentProcess()
        assert isinstance(procWrap, ProcessWrapper)
        print("proc %s wrote: " % name, procWrap.out_pipe.read(4096))

    def init_hyx(self):

        currentProcess = self.manager.getCurrentProcess()
        assert isinstance(currentProcess, ProcessWrapper)

        if currentProcess.heap is None:  # TODO
            from HeapClass import Heap
            try:
                currentProcess.setHeap()
            except KeyError:
                print("there is no heap yet, not starting hyx.")
                return

        file_path = currentProcess.heap.file_path
        offset = currentProcess.heap.start
        self.hyxTalker = HyxTalker(self.manager.socketname, file_path, offset)

        self.inputPoll.register(self.hyxTalker.getSockFd(), "hyx")


if __name__ == "__main__":
    import utils
    utils.changeLogHandler()

    path_to_hack = "/home/jasper/university/barbeit/utilstest/infgets"
    path_to_hack= "/home/jasper/university/barbeit/utilstest/cprograms/mallocinfgets"
    path_to_hack= "/home/jasper/university/barbeit/syscalltrap/t2"
    path_to_hack = "/home/jasper/university/barbeit/dummy/minimalloc"
    i= InputHandler(path_to_hack)
    i.inputLoop()
