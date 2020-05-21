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



class Helper:

    @staticmethod
    def _help(cmd: str):
        _, _, cmd = cmd.partition("?")

        cmd = cmd.strip()

        if cmd in help_dict:
            help(help_dict[cmd])
        else:
            print(" ".join(help_dict.keys()))
