UPD_FROMBLOB = b"\x40"
UPD_FROMBLOBNEXT = b"\x41"
UPD_FROMPAULA = b"\x01"
UPD_FROMPAULA_ALLHEAP= b"\x02"
CMD_REQUEST = b"\x50"
CMD_REQUEST_SUCCESS = b"\x51"


hyx_path = "/home/jasper/CLionProjects/hyxWIP/hyx-0.1.5/myhyx"

path_launcher = "launcher/dummylauncher"




RELATIVE_ADRESS_THRESHOLD = 0xFFffFFff

PRINT_BORING_SYSCALLS = True


from pwn import asm
SYSCALL_INSTR= asm("syscall")