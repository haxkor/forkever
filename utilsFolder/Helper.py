from ProcessWrapper import ProcessWrapper
from ProcessManager import ProcessManager
from HyxTalker import HyxTalker

help_dict = {
    "fork": ProcessWrapper.forkProcess,
    "continue": ProcessWrapper.cont,
    "single": ProcessWrapper.singlestep,
    "call": ProcessWrapper.callFunction,
    "print": ProcessWrapper.print,
    "xamine": ProcessWrapper.examine,
    "malloc": ProcessWrapper.malloc,
    "free": ProcessWrapper.free,
    "breakpoint": ProcessWrapper.insertBreakpoint,
    "family": ProcessWrapper.getFamily,
    "write": ProcessWrapper.writeToBuf,

    "maps": ProcessManager.dumpMaps,
    "trace": ProcessManager.trace_syscall,
    "switch": ProcessManager.switchProcess,

    "hyx": HyxTalker.launchHyx,
}


def available_commands():
    """
    continue (c)
    single   (si)
    write    (w)

    breakpoint (b)
    remove breakpoint (rb)

    fork
    switch
        family
        tree

    call
    malloc
    free

    print   (p)
    xamine  (x)
    maps
    trace
    hyx

    Type ?command to get a detailed description"""

    pass


def my_help(cmd: str):
    _, _, cmd = cmd.partition("?")
    cmd = cmd.strip()

    if cmd in help_dict:
        help(help_dict[cmd])
    else:
        help(available_commands)
