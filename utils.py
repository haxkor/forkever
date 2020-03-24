import ptrace.debugger.process as process
import os
import logging
import pwn

import subprocess


def timestamp():
    import datetime
    import time
    timestamp = time.time()
    value = datetime.datetime.fromtimestamp(timestamp)
    return str(value.strftime('%H:%M:%S'))


def forkProcess(process: process.PtraceProcess):
    from ptrace.debugger.process_event import NewProcessEvent
    ip = process.getInstrPointer()
    regs = process.getregs()

    injectcode = codeWriteEax
    inject = pwn.asm(injectcode, arch="amd64")

    original = process.readBytes(ip, len(inject))

    process.writeBytes(ip, inject)

    # nextcode = pwn.disasm(process.readBytes(ip, len(inject)+10))
    #    print("next up:", hex(ip), len(inject), nextcode)

    print("continuing now! \n")
    process.cont()

    event = process.waitEvent()
    print("got event_stop", event, "pid=", process.pid)
    assert isinstance(event, NewProcessEvent)

    process.setInstrPointer(ip)
    process.setregs(regs)
    process.writeBytes(ip, original)

    child = process.debugger.list[-1]
    assert child != process
    child.setInstrPointer(ip)
    child.setregs(regs)
    child.writeBytes(ip, original)


codeWriteEax = """
nop
nop
mov rax, 57     # fork
syscall
nop
"""


def setregs(process, args):
    for (reg, val) in args:
        process.setreg(reg, val)


mmapargs = [("rdi", 0), ("rsi", 0x1000), ("rdx", 7), ("r10", 0x20), ("r8", 0), ("r9", 0)]


def changeLogHandler():
    """
    this stops the log from being printed to the console,
    instead the logs will be written to a logfile
    """
    logfile = open(tmppath + "logfile", "w")
    rootlog = logging.getLogger()
    roothandlers = rootlog.handlers
    lh1 = logging.StreamHandler(logfile)

    rootlog.addHandler(lh1)
    rootlog.removeHandler(roothandlers[0])


tmppath = "/tmp/paula-%s/" % timestamp()
os.mkdir(tmppath)

