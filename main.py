from ptrace.debugger.process import PtraceProcess
import ptrace.logging_tools
import time
import subprocess
import signal
import ptrace.debugger
import pwn
import ptrace.debugger.ptrace_signal as procsignal

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


    utils.forkProcess(process)


    # getHeapAsBytes(process.pid, True)
    # utils.changeLogHandler()    # debugger.addProcess messes up the pwntools logging
    print("instr pointer= %x" % process.getInstrPointer())
    print("setting breakpoint\n\n")
    malloc_plt = hackelf.symbols["plt.malloc"]
    process.createBreakpoint(malloc_plt)

    process.cont()
    print("now it should hit the breakpoint")

    print(process.pid)

    try:
        process.waitSignals(signal.SIGTRAP)

    except procsignal.ProcessSignal as psignal:
        import cptrace
        print("aight we trying both processes")

    # getHeapAsBytes(process.pid, True)

    print("IP after: %#x\n\n\n" % process.getInstrPointer())
    time.sleep(4)

    tomalloc = int(input("\n\n\nrdi= ?"))
    print(tomalloc)
    process.setreg("rdi", tomalloc)

    process.cont()
    time.sleep(8)

    getHeapAsBytes(process.pid, True)
    process.detach()
    debugger.quit()



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
        try:
            print(child.pid)
            debugger_example(child.pid)
            child.kill()
        except Exception as e:
            raise e
        except ptrace.debugger.ptrace_signal.ProcessSignal as p:
            raise p


if __name__ == "__main__":
    # pwn.asm(utils.codeWriteEax,arch="amd64")

    main()
