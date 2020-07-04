from operator import itemgetter
import random

ALP_START = "a"
ALP_SIZE = 7


class Fuzzer:

    def __init__(self, path_to_fuzzme: str):
        self.path = path_to_fuzzme
        self.scores = []  # list of (input,score) tuples

    def evalInput(self, input):
        """run input through the program and check its output"""
        raise NotImplementedError

    def evalGeneration(self):
        self.trimGeneration()
        self.scores = [ (inp, self.evalInput(inp)) for (inp,oldscore) in self.scores + self.mutate_inputs() ]

    def trimGeneration(self):
        split_at = 100
        self.scores.sort(key=itemgetter(1), reverse=True)
        self.scores= self.scores[:split_at]
        return self.scores

    def mutate_inputs(self):
        return [(self.mutate_single(inp),0) for inp, _ in self.scores]

    def mutate_single(self, inp):
        def change_char(char, delta):
            return chr(ord(ALP_START) + (ord(char) + delta - ord(ALP_START)) % ALP_SIZE)

        inp_len = len(inp)
        num_changes = random.randint(0, inp_len)  # how many bytes to change
        change_inds = random.sample(range(inp_len+1), num_changes)  # which bytes to change

        result = ""
        for i, char in enumerate(inp):
            delta = random.randint(0, ALP_SIZE) if i in change_inds else 0
            result += change_char(char, delta)

        if inp_len in change_inds:
            result += change_char(ALP_START, random.randint(0, ALP_SIZE))

        return result

    def main(self, num_generation):
        self.scores=[("a",0)]
        out = open("/dev/null", "w")
        for i in range(num_generation):
            print("gen %d" % i)

            #with redirect_stdout(out):
            self.evalGeneration()

        self.trimGeneration()
        return self.scores




import subprocess
from ProcessWrapper import ProcessWrapper, LaunchArguments
from ProcessManager import ProcessManager
from utilsFolder.PaulaPoll import PaulaPoll
dummy_poll = PaulaPoll()

import pwn
pwn.context.log_level = "ERROR"


class NaiveFuzzer(Fuzzer):

    def evalInput(self, input):
        try:
            out= subprocess.check_output(self.path, input=input.encode())
            assert out.startswith(b",") and out.endswith(b".")
        except subprocess.CalledProcessError as e:
            print(input, e)
            return 0
        return int(out[1:-1])

from contextlib import redirect_stdout
from ptrace import PtraceError

class NaiveFuzzerForkever(Fuzzer):

    def evalInput(self, input):
        args = LaunchArguments([self.path],True)
        try:
            manager = ProcessManager(args,None)
        except PtraceError as e:
            print(e)
            return 0

        proc_wrap = manager.getCurrentProcess()
        proc_wrap.writeToBuf(input)
        #proc_wrap.cont()

        try:
            manager.cont()
        except KeyboardInterrupt:
            pass

        out = proc_wrap.read(0x1000)
        assert out.startswith(b",") and out.endswith(b".")
        return int(out[1:-1])

from ptrace.debugger.process_event import ProcessExit
class FuzzerForkserver(Fuzzer):

    def __init__(self, path_to_fuzzme: str):
        super().__init__(path_to_fuzzme)
        args= LaunchArguments([path], False)
        self.manager = manager = ProcessManager(args, None)
        manager.addBreakpoint("b main")
        print(manager.cont())

    def evalInput(self, input):
        proc_wrap = self.manager.getCurrentProcess().forkProcess()
        proc_wrap.writeToBuf(input)

        try:
            print(proc_wrap.cont())
        except ProcessExit:
            pass

        out = proc_wrap.read(0x100)
        assert out.startswith(b",") and out.endswith(b".")
        return int(out[1:-1])


if __name__ == '__main__':
    path = "fuzzme/fuzzme"
    naive = NaiveFuzzer(path)
    #result_naive = naive.main(2000)


    naive_fork = NaiveFuzzerForkever(path)
    #result_naivefork = naive_fork.main(10)

    forkserver = FuzzerForkserver(path)
    result_forkserver = forkserver.main(10)








