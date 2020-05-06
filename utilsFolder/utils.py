import ptrace.debugger.process as process
import os
import logging
import pwn



def timestamp():
    import datetime
    import time
    timestamp = time.time()
    value = datetime.datetime.fromtimestamp(timestamp)
    return str(value.strftime('%H:%M:%S'))


codeWriteEax = """
nop
nop
mov rax, 57     # fork
syscall
nop
"""


def changeLogHandler():
    """
    this stops the log from being printed to the console,
    instead the logs will be written to a logfile
    """
    logfile = open(tmppath + "logfile", "w")
    rootlog = logging.getLogger()
    roothandlers = rootlog.handlers
    lh1 = logging.StreamHandler(logfile)

    rootlog.addHandler(lh1)
    rootlog.removeHandler(roothandlers[0])


tmppath = "/tmp/paula-%s/" % timestamp()
os.mkdir(tmppath)

from ptrace.tools import locateProgram
path_launcher = "launcher/dummylauncher"
#path_launcher = locateProgram("launcher/dummylauncher")


print(path_launcher)
