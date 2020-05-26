UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
UPD_FROMPAULA_INSERT = b"\x02"
CMD_REQUEST = b"\x50"
CMD_REQUEST_SUCCESS = b"\x51"

from signal import SIGCHLD

SIGNALS_IGNORE = dict([("SIGCHLD", SIGCHLD)])
from pwn import asm

SYSCALL_INSTR = asm("syscall")

# ------- DONT MODIFY STUFF ABOVE ------  #

hyx_path = "/home/jasper/CLionProjects/hyxWIP/hyx-0.1.5/myhyx"
hyx_path = "../hyx4forkever/hyx"

path_launcher = "launcher/launcher"
socketname = "/tmp/forkever_hyx_sock"

# this will be used to launch hyx, set to "None" and the command will be printed out so you can launch it yourself
runargs = ["x-terminal-emulator", "--hold", "-e"]

# Breakpoints in PIEs will be relative to the base adress if they are below this value
RELATIVE_ADRESS_THRESHOLD = 0xFFffFFff

PRINT_BORING_SYSCALLS = True

# if this is true, you need to be careful to not continue on a process that is waiting on another process. It also isnt really tested
FOLLOW_NEW_PROCS = False

# when looking up a symbol, other symbols matching the lookup will be printed
PRINT_OTHER_CANDIDATES = False

HOST = ""
PORT = 9999
