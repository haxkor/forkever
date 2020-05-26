UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
UPD_FROMPAULA_INSERT = b"\x02"
CMD_REQUEST = b"\x50"
CMD_REQUEST_SUCCESS = b"\x51"

hyx_path = "/home/jasper/CLionProjects/hyxWIP/hyx-0.1.5/myhyx"

path_launcher = "launcher/launcher"
socketname= "forkever_hyx_sock"

runargs = None# ["x-terminal-emulator", "--hold", "-e"   ]

RELATIVE_ADRESS_THRESHOLD = 0xFFffFFff

PRINT_BORING_SYSCALLS = True

FOLLOW_NEW_PROCS = False

# when looking up a symbol, other symbols matching the lookup will be printed
PRINT_OTHER_CANDIDATES = False

HOST = ""
PORT = 9999

from signal import SIGCHLD

SIGNALS_IGNORE = dict([("SIGCHLD", SIGCHLD)])

from pwn import asm

SYSCALL_INSTR = asm("syscall")
