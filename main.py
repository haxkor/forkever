from argparse import ArgumentParser
from ptrace.tools import locateProgram
from InputHandler import InputHandler

parser=ArgumentParser()
parser.add_argument("program")

args=parser.parse_args()
abspath= locateProgram(args.program)
handler= InputHandler(abspath)

try:
    handler.inputLoop()
except KeyboardInterrupt:
    exit(1)




