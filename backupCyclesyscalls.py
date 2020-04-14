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

        def getNextEvent():
            """ continues execution until either an interesting syscall is about to be executed
                or a non-syscall-trap occurs"""

            def manageStdinRead():
                # if the user does not care about read or some data is available, just give that data to stdin
                # returns wether to continue or not
                requested = proc.getreg("rdx")
                if len(procWrap.stdin_buf) > 0:
                    written = procWrap.writeBufToPipe(requested)
                    print("wrote %d bytes to stdin" % written)
                    return True
                else:
                    context.writeStdin = requested
                    if len(procWrap.stdin_buf) == 0:
                        print("process wants to read %d bytes from stdin, none is available." % (requested))
                        print("use w data to avoid lock")
                    return False

            # getNextEvent might be called for the first time when the process just entried syscall
            if context.firsttime:
                context.firsttime = False
                if proc.getreg("rax") != -38:  # rax is -38 if process is about to enter a syscall
                    # treat the first syscall as interesting, meaning we stop after it.
                    context.about_to_call_interesting_syscall = True
                    return getNextEvent()

            if context.writeStdin:  # if stdin is hungry and we did not feed it in the previous call, do it now
                procWrap.writeBufToPipe(context.writeStdin)
                context.writeStdin = 0

            if context.about_to_call_interesting_syscall:  # we previosly halted at syscall entry because it was interesting
                proc.syscall()
                event = proc.waitEvent()  # wait for return of syscall
                if isSysTrap(event):
                    # interesting syscall completed
                    context.about_to_call_interesting_syscall = False
                    print("syscall %d returned %#x" % (proc.getreg("orig_rax"), proc.getreg("rax")))
                    return None
                else:  # event happened in the syscall
                    raise NotImplementedError

            # step to next event, if its a syscall-entry-trap check if the syscall is interesting
            # if its an interesting syscall return, otherwise continue until
            # an interesting syscall or another event occurs
            else:
                proc.syscall()
                event = proc.waitEvent()  # this might be syscall entry

                if isSysTrap(event):
                    orig_rax = proc.getreg("orig_rax")
                    if orig_rax == 0 and proc.getreg("rdi") == 0:  # write this when continuing
                        can_continue = manageStdinRead()
                        if not can_continue:
                            context.about_to_call_interesting_syscall = True

                            return None
                        # written = procWrap.writeBufToPipe(proc.getreg("rdi"))
                        # print("read %d bytes from stdin" % written)

                    if orig_rax in self.syscallsToTrace:
                        print("stopped, process is about to syscall %d" % orig_rax)
                        context.about_to_call_interesting_syscall = True
                        return None
                    else:  # finish syscall, continue execution
                        proc.syscall()
                        proc.waitSyscall()  # this is syscall exit
                        print("syscall %d returned %#x" % (proc.getreg("orig_rax"), proc.getreg("rax")))
                        return getNextEvent()

                else:  # not syscall entry
                    return event
