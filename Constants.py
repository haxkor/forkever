from signal import SIGCHLD
from pwn import asm
from ptrace.tools import locateProgram

# relevant for communication with hyx
UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
UPD_FROMPAULA_INSERT = b"\x02"
MSG_FROMPAULA = b"\x03"
CMD_REQUEST = b"\x50"
CMD_REQUEST_SUCCESS = b"\x51"

SIGNALS_IGNORE = {}      # dict([("SIGCHLD", SIGCHLD)])

SYSCALL_INSTR = asm("syscall")

# relevant for performance optimization (Fuzzer.py)
DO_SYSCALL = True
LOAD_PROGRAMINFO = True

# ------- DONT MODIFY STUFF ABOVE ------  #

USE_ASCII = True
COLOR_NORMAL = "\033[m"
COLOR_CURRENT_PROCESS = "\033[0;31m"  # red
COLOR_TERMINATED_PROCESS = "\033[0;34m"  # blue

hyx_path = locateProgram("../hyx4forkever/hyx")
path_launcher = "launcher/launcher"
socketname = "/tmp/forkever_hyx_sock"

# this will be used to launch hyx, set to "None" and the command will be printed out so you can launch it yourself
runargs = ["x-terminal-emulator", "-e"]  # , "-e"]

# Breakpoints in PIEs will be relative to the base adress if they are below this value
RELATIVE_ADRESS_THRESHOLD = 0xFFffFFff

PRINT_BORING_SYSCALLS = False  # all syscalls will be printed if true

CONT_AFTER_WRITE = True     # no need to explicitly continue after writing to stdin

# if this is true, you need to be careful to not continue on a process that is waiting on another process.
# It also isnt really tested
FOLLOW_NEW_PROCS = False


# when looking up a symbol, other symbols matching the lookup will be printed
PRINT_OTHER_CANDIDATES = False

# this is relevant if you want forkever to send and receive output of the debugged program via a sock
# enable this feature when launching
HOST = ""
PORT = 9999
