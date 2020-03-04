import ptrace.debugger
import signal
import subprocess
import sys
import time

import mypwntools as pwn
#from __future__ import annotations

from ptrace.debugger.process import PtraceProcess as type_ptraceproc

#context(arch="amd64", os="linux",log_level="error")
#context.update(log_level="error")
#context.log_level="error"
#context.local()

#context.log_file= "/tmp/paula/pwntoolslog"

#log.rootlogger.

pwn.context(log_level="error")



babymalloc= "/home/jasper/university/pythonptracetesterei/scripts/babymalloc"

print("context.log.level=", pwn.context.log_level)
pwn.ELF(babymalloc)
print("yoyo")

def insertCode(process:type_ptraceproc, ad):
	code= """
		mov eax,57  # fork 
		syscall
		int3	"""

	code=pwn.asm(code)

	#print( pwn.disasm( code))

	process.writeBytes(ad,code)



def getHeapAsBytes(pid, printall=False):
	with open("/proc/%d/maps" % pid, "rb") as maps:
		# print(maps.read(200000))
		buf = maps.readlines()

		for l in buf:
			if b"heap" in l or printall: print(l)


def debugger_example(pid):
	getHeapAsBytes(pid)

	debugger = ptrace.debugger.PtraceDebugger()

	time.sleep(.3)
	print("Attach the running process %s" % pid)
	process = debugger.addProcess(pid, False)
	# process is a PtraceProcess instance


	print("setting breakpoint")

	malloc_plt = 0x401050
	process.createBreakpoint(malloc_plt)

#	context.log_file = "/tmp/paula/pwntoolslog"

#	context.log_level="error"

	print("context.log.level=",pwn.context.log_level)
	vuln = pwn.ELF(babymalloc)
	ad = vuln.entry

	if process.getInstrPointer() -5 < ad:
		print("attached too soon, cant overwrite entrypoint")

	insertCode(process,ad)

	process.cont()
	print("now it should hit the breakpoint")

	process.waitSignals(signal.SIGTRAP)

	print("IP after: %#x" % process.getInstrPointer())

	print("gonna return getregs")
	global p
	global r
	r = process.getregs()
	p = process

	time.sleep(.1)
	tomalloc = int(input("rdi= ?"))
	print(tomalloc)
	process.setreg("rdi", tomalloc)

	process.cont()
	time.sleep(.1)
	print("alrite..")
	time.sleep(.8)
	process.detach()
	debugger.quit()

	print("quit")


r = None
p = None


def main():
	args = [
		"/home/jasper/university/pythonptracetesterei/scripts/babymalloc"]
	child_popen = subprocess.Popen(args)
	debugger_example(child_popen.pid)

	print("sleeping")
	time.sleep(2)
	print("sleep done")
	child_popen.kill()
	child_popen.wait()


if __name__ == "__main__":
	main()

