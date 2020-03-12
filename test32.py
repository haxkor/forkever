import logging
from ptrace.debugger.process import PtraceProcess as type_ptraceproc
import ptrace.logging_tools
import time
import sys
import subprocess
import signal
import ptrace.debugger
import pwn

import utils

babymalloc = "/home/jasper/university/pythonptracetesterei/scripts/babymalloc"


def insertCode(process: type_ptraceproc, ad):
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
    getHeapAsBytes(pid)

    debugger = ptrace.debugger.PtraceDebugger()

    pwn.ELF(babymalloc)
    print("debugger created")

    time.sleep(.3)
    print("Attach the running process %s" % pid)

    process = debugger.addProcess(pid, False)
    # process is a PtraceProcess instance

    # utils.changeLogHandler()    # debugger.addProcess messes up the pwntools logging

    print("setting breakpoint\n\n")
    pwn.asm("int3")

    malloc_plt = 0x401050
    process.createBreakpoint(malloc_plt)

    vuln = pwn.ELF(babymalloc)
    ad = vuln.entry

    if process.getInstrPointer() - 5 < ad:
        print("attached too soon, cant overwrite entrypoint")

    insertCode(process, ad)

    process.cont()
    print("now it should hit the breakpoint")

    process.waitSignals(signal.SIGTRAP)

    print("IP after: %#x\n\n\n" % process.getInstrPointer())

    tomalloc = int(input("rdi= ?"))
    process.setreg("rdi", tomalloc)

    process.cont()
    time.sleep(.1)
    print("alrite..")
    time.sleep(.8)
    process.detach()
    debugger.quit()


r = None
p = None

import pathlib

workingpath = str(pathlib.Path().absolute())


def main():
    args = []
    args.append(workingpath + "/launcher/dummylauncher")
    args.append(workingpath + "/launcher/testmalloc")

    with subprocess.Popen(args) as child:
        debugger_example(child.pid)
        child.kill()


if __name__ == "__main__":
    main()
