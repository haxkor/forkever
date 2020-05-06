from argparse import ArgumentParser
from ptrace.tools import locateProgram
from InputHandler import InputHandler
from os import kill
from signal import SIGKILL

parser=ArgumentParser()
parser.add_argument("program")
parser.add_argument("-init")

args=parser.parse_args()
abspath= locateProgram(args.program)

handler= InputHandler(abspath, startupfile=args.init)


try:
    handler.inputLoop()
except Exception:

    for proc in handler.manager.processList:
        proc.ptraceProcess.kill(SIGKILL)
    exit(1)




