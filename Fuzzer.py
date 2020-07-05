from operator import itemgetter
import random

import subprocess
from ProcessWrapper import ProcessWrapper, LaunchArguments
from ProcessManager import ProcessManager, SIGCHLD
from utilsFolder.PaulaPoll import PaulaPoll

dummy_poll = PaulaPoll()

import pwn
import os

ALP_START = "a"
ALP_SIZE = 6

redirect = False

out_file = open("/dev/null", "w")


class Fuzzer:

    def __init__(self, path_to_fuzzme: str):
        self.path = path_to_fuzzme
        self.scores = []  # list of (input,score) tuples

    def evalInput(self, input):
        """run input through the program and check its output"""
        raise NotImplementedError

    def evalGeneration(self):
        self.trimGeneration()
        self.scores = [(inp, self.evalInput(inp)) for (inp, oldscore) in self.scores + self.mutate_inputs()]

    def trimGeneration(self):
        split_at = 100

        self.scores = list(set(self.scores))  # remove duplicates
        self.scores.sort(key=itemgetter(1), reverse=True)
        self.scores = self.scores[:split_at]
        return self.scores

    def mutate_inputs(self):
        # print("scores = %s" % self.scores)
        return [(self.mutate_single(inp), -1) for inp, _ in self.scores]

    def mutate_single(self, inp):
        def change_char(char, delta):
            return chr(ord(ALP_START) + (ord(char) + delta - ord(ALP_START)) % ALP_SIZE)

        inp_len = len(inp)
        num_changes = random.randint(0, inp_len)  # how many bytes to change
        change_inds = random.sample(range(inp_len + 1), num_changes)  # which bytes to change

        result = ""
        for i, char in enumerate(inp):
            delta = random.randint(0, ALP_SIZE) if i in change_inds else 0
            result += change_char(char, delta)

        if inp_len in change_inds:
            result += change_char(ALP_START, random.randint(0, ALP_SIZE))

        return result

    def main(self, num_generation):
        self.scores = [("b", 0)]
        for i in range(num_generation):
            print("gen %d" % i)
            self.trimGeneration()

            if redirect:
                with redirect_stdout(out_file):
                    self.evalGeneration()
            else:
                self.evalGeneration()

            # os.closerange(10, 1000)

        self.trimGeneration()
        return self.scores


pwn.context.log_level = "WARNING"


class NaiveFuzzer(Fuzzer):

    def evalInput(self, input):
        try:
            out = subprocess.check_output(self.path, input=input.encode())
            assert out.startswith(b",") and out.endswith(b".")
        except subprocess.CalledProcessError as e:
            print(input, e)
            return 0
        return int(out[1:-1])


from contextlib import redirect_stdout
from ptrace import PtraceError


class NaiveFuzzerForkever(Fuzzer):

    def evalInput(self, input):
        args = LaunchArguments([self.path], True)
        try:
            manager = ProcessManager(args, None)
        except PtraceError as e:
            print(e)
            return 0

        proc_wrap = manager.getCurrentProcess()
        proc_wrap.writeToBuf(input)
        # proc_wrap.cont()

        try:
            manager.cont()
        except KeyboardInterrupt:
            pass

        out = proc_wrap.read(0x1000)
        assert out.startswith(b",") and out.endswith(b".")
        return int(out[1:-1])


from ptrace.debugger.process_event import ProcessExit

from signal import SIGTRAP
import time


class FuzzerForkserver(Fuzzer):

    def __init__(self, path_to_fuzzme: str):
        super().__init__(path_to_fuzzme)
        args = LaunchArguments([path], False)
        self.manager = manager = ProcessManager(args, None)
        self.pending_SIGCHLDs = 0
        manager.addBreakpoint("b main")
        manager.cont()
        print(manager.getCurrentProcess().where())

        # manager.getCurrentProcess().wait_for_SIGNAL(SIGTRAP)

    def evalGeneration(self):
        inputs = [inp for inp, _ in self.mutate_inputs()]
        scores = [int(out[1:-1]) for out in self.tryinputs(inputs)]

        self.scores += [(i, s) for i, s in zip(inputs, scores)]
        return self.scores

    def tryinputs(self, inputs):
        os.closerange(30, 1023)
        procs = [self.manager.getCurrentProcess().forkProcess() for _ in inputs]
        results = []
        print("inputs len %d" % len(inputs))

        for proc_wrap, inp in zip(procs, inputs):
            proc_wrap.in_pipe.write(inp + "\n")
            proc_wrap.ptraceProcess.detach()
            results.append(proc_wrap.out_pipe.read(100))
            self.manager.getCurrentProcess().wait_for_SIGNAL(SIGCHLD)

        return results


from utilsFolder.ProgramInfo import ProgramInfo


class ForkFuzzer(Fuzzer):

    def __init__(self, path_to_fuzzme: str):
        super().__init__(path_to_fuzzme)
        args = LaunchArguments([path_to_fuzzme], False)
        self.manager = manager = ProcessManager(args, None)

        # manager.addBreakpoint("b main")
        root_proc = manager.getCurrentProcess()

        root_proginfo = ProgramInfo(path, root_proc.getPid(), root_proc)

        break_at = root_proginfo.getAddrOf("fgetc")
        # break_at = root_proginfo.baseDict[path] + 0x1251
        # break_at = 0x555555555251
        manager.addBreakpoint("b %d" % break_at)
        manager.cont()
        print(root_proc.where())

        self.pref_dict = dict([("", self.manager.getCurrentProcess())])

    def get_prefix_child(self, inp: str):
        # find longest matching prefix
        inp_len = len(inp)
        keys = filter(lambda k: len(k) <= inp_len and inp.startswith(k), self.pref_dict.keys())
        longest_pref = max(keys, key=len)

        # matching process for prefix, prefix, suffix
        return self.pref_dict[longest_pref], inp[:len(longest_pref)], inp[len(longest_pref):]

    def evalInput(self, inp: str):
        root_parent, prefix, suffix = self.get_prefix_child(inp)

        # print("inp = %s prefix = %s,  suffix = %s,  dict = %s" % (inp, prefix, suffix, self.pref_dict.keys()))

        parent = root_parent.forkProcess()

        for c in suffix:
            parent.writeToBuf('b"%s"' % c)  # convert this so that no newline is added
            try:
                parent.cont()
            except ProcessExit:
                parent.parent.wait_for_SIGNAL(SIGCHLD)
                print("\noh no \n")
                return -1

            prefix += c
            assert prefix not in self.pref_dict
            self.pref_dict[prefix] = parent

            parent = parent.forkProcess()

        parent.in_pipe.write("\n")
        parent.ptraceProcess.detach()
        result = int(parent.out_pipe.read(100)[1:-1])

        # print(parent.parent.where())
        parent.parent.wait_for_SIGNAL(SIGCHLD)

        return result

import resource
soft,hard = resource.getrlimit(resource.RLIMIT_NOFILE)
soft *= 64
resource.setrlimit(resource.RLIMIT_NOFILE, (soft,hard))

from timeit import default_timer

if __name__ == '__main__':
    path = "fuzzme/fuzzme"
    num_gens = 30
    time_dict = dict()


    naive = NaiveFuzzer(path)
    random.seed(1)

    time_dict["naive_start"] = default_timer()
    result_naive = naive.main(num_gens)
    time_dict["naive_end"] = default_timer()


    random.seed(1)
    naive_fork = NaiveFuzzerForkever(path)
    # result_naivefork = naive_fork.main(10)


    random.seed(1)
    forkserver = FuzzerForkserver(path)
    #result_forkserver = forkserver.main(num_gens)


    time.sleep(2)

    random.seed(1)
    forkfuzzer = ForkFuzzer(path)
    time_dict["forkfuzzer_start"] = default_timer()
    result_forkfuzzer = forkfuzzer.main(num_gens)
    time_dict["forkfuzzer_end"] = default_timer()


    print( "naive time = ", time_dict["naive_end"] - time_dict["naive_start"])
    print( "forkfuzzer time = ", time_dict["forkfuzzer_end"] - time_dict["forkfuzzer_start"])



