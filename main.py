
import pwn
pwn.context.log_level="ERROR"

from Constants import logfile
from argparse import ArgumentParser
from ptrace.tools import locateProgram
from InputHandler import InputHandler
from os import kill
from signal import SIGKILL

from contextlib import redirect_stdout

print(pwn.log)


parser=ArgumentParser()
parser.add_argument("program")
parser.add_argument("-init")

args=parser.parse_args()
abspath= locateProgram(args.program)

handler= InputHandler(abspath, startupfile=args.init)


try:
    handler.inputLoop()
except KeyboardInterrupt:

    for proc in handler.manager.processList:
        proc.ptraceProcess.kill(SIGKILL)
    exit(1)




