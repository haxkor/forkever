from utilsFolder.PaulaPoll import PaulaPoll
from ProcessManager import ProcessManager
from utilsFolder.PollableQueue import PollableQueue
from signal import SIGWINCH

from threading import Thread
from utilsFolder.InputReader import InputReader

from ProcessWrapper import ProcessWrapper
from HyxTalker import HyxTalker
from utilsFolder.Parsing import parseInteger


class InputHandler:

    def __init__(self, path_to_hack, startupfile=None):
        self.inputPoll = PaulaPoll()
        self.manager = ProcessManager(path_to_hack, "/tmp/paulasock", self.inputPoll)

        self.stdinQ = PollableQueue()
        self.inputPoll.register(self.stdinQ.fileno(), "userinput")
        self.reader_thread = InputReader(self.stdinQ, startupfile)    #Thread(target=mainReader, args=(self.stdinQ,), daemon=True)
        self.reader_thread.start()

        self.hyxTalker = None

    def execute(self,cmd):
        try:
            return self._execute(cmd)
        except ValueError as err:
            return str(err)


    def _execute(self, cmd):
        manager = self.manager
        proc = manager.getCurrentProcess().ptraceProcess

        result=""
        if cmd == "hyx" and not self.hyxTalker:
            self.init_hyx()

        elif cmd.startswith("c"):  # continue
            result=manager.cont()

        elif cmd.startswith("w"):
            result=manager.write(cmd[2:].encode() + b"\n")  # TODO

        elif cmd.startswith("fork"):
            result=manager.fork()

        elif cmd.startswith("proclist"):
            print(manager.processList)

        elif cmd.startswith("sw"):  #switch
            _,_,pid=cmd.partition(" ")
            if pid!="":
                pid=int(pid)
            else:
                pid=None
            result= manager.switchProcess(pid=pid)

        elif cmd.startswith("b"):
            _,_,adress= cmd.partition(" ")
            adress= parseInteger(adress, ptraceProc=proc)
            result=manager.insertBreakpoint(adress)

        elif cmd.startswith("malloc"):
            _,_,val= cmd.partition(" ")
            val=parseInteger(val,proc)
            result= manager.malloc(val)

        elif cmd.startswith("free"):
            _,_,pointer= cmd.partition(" ")
            pointer=parseInteger(pointer,proc)
            result=manager.free(pointer)

        elif cmd.startswith("try"):
            result=manager.tryFunction(cmd.split(" ")[1],cmd.split(" ")[2:])

        elif cmd.startswith("list b"):
            print(manager.getCurrentProcess().ptraceProcess.breakpoints)

        elif cmd.startswith("s"):
            result=manager.cont(singlestep=True)

        return result

    def inputLoop(self):

        quit_var = False
        while not quit_var:
            pollresult = self.inputPoll.poll()
            # print(Numerik partieller Diffepollresult)
            assert len(pollresult) > 0

            if len(pollresult) == 1:
                name, pollfd, event = pollresult[0]
                if name == "hyx":
                    self.handle_hyx(event)
                elif name == "userinput":
                    self.handle_stdin(pollfd, event)
                elif "-out" in name:
                    self.handle_procout(name, pollfd, event)

                elif "-err" in name:
                    self.handle_stderr(event)

            else:  # this happens when two sockets are written to at the "same" time
                for name,pollfd,event in pollresult:
                    if "-out" in name:
                        self.handle_procout(name, pollfd, event)
                        break

                print(pollresult)
                #raise NotImplementedError

            if self.hyxTalker:
                self.hyxTalker.updateHyx()

    def handle_stderr(self,event):
        print("got this on stderr")
        print(self.manager.getCurrentProcess().read(0x1000,"err"))

    # this is called when a new line has been put to the stdinQ
    def handle_stdin(self, fd, event):
        cmd = self.stdinQ.get()[:-1]  # remove newline
        assert isinstance(cmd, str)

        if event == SIGWINCH:
            return
        print(self.execute(cmd))


    def handle_hyx(self, event):
        # should input handler or processmanager handle this? or hyxtalker?
        # receive check value here, forward to the respective hyxtalker function
        hyxtalker = self.hyxTalker

        from select import POLLHUP, POLLIN
        import Constants as cons

        if event & POLLHUP:
            print("hyx closed, remaining data = %s" % hyxtalker.hyxsock.recv(1000))
            self.delete_hyx()
            return
        if event != POLLIN:
            print(event)
            raise NotImplementedError

        check = hyxtalker.hyxsock.recv(1)
        if check == cons.CMD_REQUEST:
            cmd=hyxtalker.recvCommand()
            print("%s   (hyx) " % cmd)
            result=self.execute(cmd)
            print(result)
            hyxtalker.sendCommandResponse(result)

        elif check == cons.UPD_FROMBLOB or check == cons.UPD_FROMBLOBNEXT:
            hyxtalker.getUpdate(isNextByte=check == cons.UPD_FROMBLOBNEXT)
        else:
            print(check, event)
            raise NotImplementedError

    def handle_procout(self, name, fd, event):
        procWrap = self.manager.getCurrentProcess()
        assert isinstance(procWrap, ProcessWrapper)
        print("proc %s wrote: " % name, procWrap.out_pipe.read(4096))

    def delete_hyx(self):
        self.hyxTalker.destroy(rootsock=True)
        self.hyxTalker=None



    def init_hyx(self):

        currentProcess = self.manager.getCurrentProcess()
        assert isinstance(currentProcess, ProcessWrapper)

        if currentProcess.heap is None:  # TODO
            try:
                currentProcess.setHeap()
            except KeyError:
                print("there is no heap yet, not starting hyx.")
                return
        else:
            print("there already is a heap")

        heap = currentProcess.getHeap()
        print(heap.start, heap.file_path)

        file_path = currentProcess.heap.file_path
        offset = currentProcess.heap.start
        self.hyxTalker = HyxTalker(self.manager.socketname, currentProcess.heap, self.inputPoll)



if __name__ == "__main__":
    from utilsFolder import utils

    utils.changeLogHandler()

    #path_to_hack = "/home/jasper/university/barbeit/utilstest/cprograms/mallocinfgets"
    # path_to_hack= "/home/jasper/university/barbeit/syscalltrap/t2"

    #path_to_hack = "/home/jasper/university/barbeit/utilstest/infgets"
    path_to_hack = "/home/jasper/university/barbeit/dummy/a.out"


    i = InputHandler(path_to_hack)
    i.inputLoop()
