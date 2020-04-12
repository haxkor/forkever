def cycleSyscalls(boring=False):
    # proc is in a syscall trapped state when this is called

    if self.trapIsEntry:
        orig_rax = proc.getreg("orig_rax")
        if orig_rax == 0 and proc.getreg("rdi") == 0:  # read from stdin
            written = procWrap.writeBufToPipe(proc.getreg("rdx"))
            print("read %d bytes from stdin" % written)
            return None

        elif orig_rax in self.syscallsToTrace:
            print("stopped, process is about to syscall %d" % orig_rax)
            self.trapIsEntry = False
            print("returning in 130")
            return None

        else:  # skip over it till we find something interesting
            proc.syscall()
            nextEvent = proc.waitEvent()
            if isinstance(nextEvent, ProcessSignal) and nextEvent.signum == 0x80 | SIGTRAP:
                self.trapIsEntry = False
                # print("syscall %d returned %#x" % (orig_rax, proc.getreg("rax")))
                print("returning cycleSyscalls in 137")
                return cycleSyscalls(boring=True)

            else:
                return nextEvent

    # this branch is entered when the user continues after execution halted at
    # a syscall of interest. this syscall  is now finished
    else:
        print("syscall %d returned %#x" % (proc.getreg("orig_rax"), proc.getreg("rax")))
        self.trapIsEntry = True
        if boring:
            # print("boring, recursing..")
            return cycleSyscalls()
        else:
            # print("not boring")
            return None


def cycleSyscalls2():
    orig_rax = proc.getreg("orig_rax")
    if orig_rax == 0 and proc.getreg("rdi") == 0:
        written = procWrap.writeBufToPipe(proc.getreg("rdi"))
        print("read %d bytes from stdin" % written)

    if orig_rax in self.syscallsToTrace:
        print("stopped, process is about to syscall %d" % orig_rax)
        return "stopped"
    else:
        proc.syscall()
        try:
            proc.waitSyscall()
        except ProcessEvent:
            raise NotImplementedError

        print("syscall %d returned %#x" % (orig_rax, proc.getreg("rax")))