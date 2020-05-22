import pwn
pwn.context.log_level = "ERROR"

from argparse import ArgumentParser
from ptrace.tools import locateProgram
from InputHandler import InputHandler
from ProcessWrapper import LaunchArguments

print(pwn.log)

parser = ArgumentParser()
parser.add_argument("program")
parser.add_argument("-init")
parser.add_argument("-rand", action="store_false")

args = parser.parse_args()
abspath = locateProgram(args.program)
launch_args = LaunchArguments(abspath,args.rand)

handler = InputHandler(launch_args, startupfile=args.init)

try:
    handler.inputLoop()
except KeyboardInterrupt:
    handler.manager.debugger.quit()

    exit(1)
