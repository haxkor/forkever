msg = b"A" * 8 + b"xx"  # b"AAAAAAAA\xab" + b"\x00"  + b"\xcdaaaaaaa"
msg_ad = id(msg) + 32

import ctypes

# print("msg= ", ctypes.string_at(msg_ad+ 32,80))
time.sleep(1)
PTRACE_GETEVENTMSG = 0x4201
process.ptrace(PTRACE_GETEVENTMSG, oldpid, 0, msg_ad)  # store

time.sleep(.1)
import struct

newpid = struct.unpack("<Q", ctypes.string_at(msg_ad, 8))[0]
print("newpid=%d oldpid=%d" % (newpid, oldpid))
