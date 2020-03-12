from ptrace.debugger.process import PtraceProcess
import ptrace.logging_tools
import time
import subprocess
import signal
import ptrace.debugger
import pwn

import utils

babymalloc = "/home/jasper/university/pythonptracetesterei/scripts/babymalloc"


def insertCode(process: PtraceProcess, ad):
    code = """
        mov eax,57  # fork 
        syscall
        int3	"""

    code = pwn.asm(code)
    process.writeBytes(ad, code)


def getHeapAsBytes(pid, printall=False):
    with open("/proc/%d/maps" % pid, "rb") as maps:
        # print(maps.read(200000))
        buf = maps.readlines()

        for l in buf:
            if b"heap" in l or printall:
                print(l)


def debugger_example(pid):
    debugger = ptrace.debugger.PtraceDebugger()

    print("debugger created")
    process = debugger.addProcess(pid, False, seize=True)
    utils.changeLogHandler()
    print("process seized")

    print("in main, before interrupting")

    process.interrupt()

    print("process interrupted")
    print(debugger.options)
    debugger.traceFork()
    debugger.traceExec()
    process.setoptions(debugger.options)
    print("options=", debugger.options)

    go_ad = launchelf.symbols["go"]
    process.writeBytes(go_ad, b"gogo")

    process.cont()
    time.sleep(1)

    print("process continues")

    print("waiting for signals")

    # because of the waitsignals implementation, the event is not
    # expected and therefore raised. this way, we wait for our correct event
    try:
        process.waitSignals()
    except ptrace.debugger.process_event.ProcessExecution:
        print("programm execd new program")

    process.setoptions(0x6)

    ###############

    oldpid = process.pid
    ip = process.getInstrPointer()

    print(pwn.disasm(process.readBytes(ip, 1000)))
    # inject = pwn.asm("nop\nnop\nnop\nsyscall\nnop\nnop\nnop")
    injectcode = "syscall\n" * 3 + "int3"
    injectcode = utils.codeWriteEax
    inject = pwn.asm(injectcode, arch="amd64")


    original = process.readBytes(ip, 10 * len(inject))
    print("in inject, ip=", hex(ip))

    process.writeBytes(ip, inject)

    nextcode = pwn.disasm(process.readBytes(ip, len(inject)))
    print("next up:", hex(ip), len(inject), nextcode)

    #process.setreg("rax", 57)  # syscall fork
    #print(process.getreg(("rax")))

    # process.singleStep()
    print("continuing now! \n")
    process.cont()
    PTRACE_EVENT_STOP = 0x80

    import os
    # os.waitpid(process.pid, 0x80)

    # process.waitSignals(PTRACE_EVENT_STOP)  # from the parent process

    # event= process.ptraceEvent()
    # event= debugger.waitProcessEvent()

    import os
    event = os.waitpid(process.pid, 0)
    print("got event_stop", event, "pid=", process.pid)

    print(hex(process.getInstrPointer()))

    # event= debugger.waitProcessEvent()
    # print("got event_stop", event)

    # now syscall

    ip = process.getInstrPointer()
    nextcode = pwn.disasm(process.readBytes(ip, 19))
    print(hex(ip), len(inject), nextcode)

    msg = b"A" * 8 + b"xx"  # b"AAAAAAAA\xab" + b"\x00"  + b"\xcdaaaaaaa"
    msg_ad = id(msg) + 32

    import ctypes
    # print("msg= ", ctypes.string_at(msg_ad+ 32,80))
    time.sleep(1)
    PTRACE_GETEVENTMSG = 0x4201
    process.ptrace(PTRACE_GETEVENTMSG, oldpid, 0, msg_ad)  # store

    time.sleep(.1)
    import struct
    newpid = struct.unpack("<Q", ctypes.string_at(msg_ad, 8))
    print("newpid=%d oldpid=%d" % (newpid[0], oldpid))

    # time.sleep(1)
    ip2 = process.getInstrPointer()
    print("ip2=", hex(ip2))
    print(process.getreg(("rax")))

    print(process.pid)
    #    parent = PtraceProcess.ptrace(0x4206, process.pid, 0,0)

    #################

    # getHeapAsBytes(process.pid, True)
    # utils.changeLogHandler()    # debugger.addProcess messes up the pwntools logging
    print("instr pointer= %x" % process.getInstrPointer())
    print("setting breakpoint\n\n")
    malloc_plt = hackelf.symbols["plt.malloc"]
    process.createBreakpoint(malloc_plt)

    process.cont()
    print("now it should hit the breakpoint")

    process.waitSignals(signal.SIGTRAP)
    # getHeapAsBytes(process.pid, True)

    print("IP after: %#x\n\n\n" % process.getInstrPointer())
    time.sleep(1)

    tomalloc = int(input("\n\n\nrdi= ?"))
    print(tomalloc)
    process.setreg("rdi", tomalloc)

    process.cont()
    time.sleep(2)

    getHeapAsBytes(process.pid, True)
    process.detach()
    debugger.quit()


def injectsyscall(process: PtraceProcess):
    pass


import pathlib

workingpath = str(pathlib.Path().absolute())
hackpath = workingpath + "/launcher/babymalloc"

launchelf = pwn.ELF(workingpath + "/launcher/dummylauncher")
hackelf = pwn.ELF(hackpath)


def main():
    print("in main")
    args = []
    args.append(workingpath + "/launcher/dummylauncher")
    args.append(hackpath)

    # args.append("/bin/echo")
    # args.append("hello")

    with subprocess.Popen(args) as child:
        print(child.pid)
        debugger_example(child.pid)
        child.kill()


if __name__ == "__main__":
    # pwn.asm(utils.codeWriteEax,arch="amd64")

    main()
