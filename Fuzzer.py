from operator import itemgetter
import random
random.seed(5)

from numpy.random import geometric, seed as npseed


from Constants import DO_SYSCALL
import subprocess
from ProcessWrapper import ProcessWrapper, LaunchArguments
from ProcessManager import ProcessManager, SIGCHLD
from utilsFolder.PaulaPoll import PaulaPoll

dummy_poll = PaulaPoll()

import pwn
import os

ALP_START = "a"
ALP_SIZE = 6

split_at = 30

redirect = 1
LOG_EVERY = 5

SKIP_CHAR_CHANCE = 0.1

#log_file = open("fuzzme/results", "a")
#out_file = open("/dev/null", "w")

def prand(s=""):
    print(s,"rand %d" % random.randint(0, 99))

class Fuzzer:

    def __init__(self, path_to_fuzzme: str):
        self.path = path_to_fuzzme
        self.scores = []  # list of (input,score) tuples

    def evalInput(self, input):
        """run input through the program and check its output"""
        raise NotImplementedError

    def evalGeneration(self):
        edges_list = [(inp, self.evalInput(inp)) for (inp, oldscore) in self.mutate_inputs()]
        self.scores += [ (inp, edges, edges - 0.4*(len(inp) - edges))  for inp,edges in edges_list]


    def trimGeneration(self):
        def remove_duplicates():
            newscores = []
            for tup in self.scores:
                if tup not in newscores:
                    newscores.append(tup)
            return newscores

        self.scores = remove_duplicates()

        #self.scores = [ (inp, score - (len(inp)-score)*0.2) for (inp, score) in self.scores]    # deduce points for unneccessarily long words

        sortfunc = lambda s: len(s)
        self.scores.sort(key=sortfunc)

        self.scores.sort(key=itemgetter(2), reverse=True)
        #warning("%s" % self.scores)

        self.scores = self.scores[:split_at]
        return self.scores

    def mutate_inputs(self):
        # print("scores = %s" % self.scores)
        return [(self.mutate_single(inp), -1) for inp, _, _ in self.scores]

    def mutate_single(self, inp):
        def change_char(char, delta):
            return chr(ord(ALP_START) + (ord(char) + delta - ord(ALP_START)) % ALP_SIZE)

        inp_len = len(inp)
        num_changes = random.randint(0, inp_len)  # how many bytes to change
        # change_inds = random.sample(range(inp_len + 1), num_changes)  # which bytes to change
        change_inds = (1+inp_len) - geometric(0.2, num_changes)

        result = ""
        for i, char in enumerate(inp):
            if random.random() < SKIP_CHAR_CHANCE:
                continue

            delta = random.randint(0, ALP_SIZE) if i in change_inds else 0
            result += change_char(char, delta)

        if inp_len in change_inds:
            result += change_char(ALP_START, random.randint(0, ALP_SIZE))

        return result

    def main(self, num_generation):
        time_start = default_timer()
        self.scores = [(chr(ord(ALP_START) + i), -9, -9) for i in range(ALP_SIZE)]
        for i in range(num_generation):
            print("gen %d" % i)
            self.trimGeneration()

            if redirect:
                with redirect_stdout(out_file):
                    self.evalGeneration()
            else:
                self.evalGeneration()

            if i % LOG_EVERY == 0:
                #warning(self.scores)
                print(self.__class__, "gen %d" % i, self.scores[0], default_timer()-time_start,
                      "seed= %d, DO_SYSCALL= %d" % (seed, DO_SYSCALL), file=log_file)

        self.trimGeneration()
        return self.scores


pwn.context.log_level = "WARNING"


class NaiveFuzzer(Fuzzer):

    def evalInput(self, input):
        try:
            out = subprocess.check_output(self.path, input=input.encode())
            assert out.startswith(b",") and out.endswith(b".")
        except subprocess.CalledProcessError as e:
            warning("%s %s" % (input, e))
            return -1
        return int(out[1:-1])


from contextlib import redirect_stdout, redirect_stderr
from ptrace import PtraceError


class NaiveFuzzerForkever(Fuzzer):

    def evalInput(self, input):
        args = LaunchArguments([self.path], True)
        try:
            manager = ProcessManager(args, None)
        except PtraceError as e:
            warning(e)
            return -1

        def do_write(proc_wrap:ProcessWrapper, s:str):
            if DO_SYSCALL:
                proc_wrap.writeToBuf('b"""%s"""' % s) # convert this so that no newline is added
            else:
                proc_wrap.in_pipe.write(s)


        proc_wrap = manager.getCurrentProcess()
        do_write(proc_wrap, input + "\n")

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
        self.trimGeneration()
        inputs = [inp for inp, _ in self.mutate_inputs()]
        scores = [int(out[1:-1]) for out in self.tryinputs(inputs)]

        self.scores += [ (inp, edges, edges - 0.4*(len(inp) - edges))  for inp,edges in zip(inputs,scores)]
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

    def __del__(self):
        with redirect_stderr(out_file):
            self.manager.debugger.quit()


from utilsFolder.ProgramInfo import ProgramInfo
from logging2 import *


class ForkFuzzer(Fuzzer):

    def __init__(self, path_to_fuzzme: str):
        super().__init__(path_to_fuzzme)
        args = LaunchArguments([path_to_fuzzme], False)
        self.manager = manager = ProcessManager(args, None)

        # manager.addBreakpoint("b main")
        self.root_proc = manager.getCurrentProcess()

        self.root_proginfo = ProgramInfo(path, self.root_proc.getPid(), self.root_proc)

        break_at = self.root_proginfo.getAddrOf("read")
        # break_at = root_proginfo.baseDict[path] + 0x1251
        # break_at = 0x555555555251
        manager.addBreakpoint("b %d" % break_at)
        manager.cont()
        print(self.root_proc.where())

        self.pref_dict = dict([("", self.manager.getCurrentProcess())])
        self.spawned_procs = 0

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

        # if something does not work with the process in the dict, remove it from the dict and try again
        try:
            parent = root_parent.forkProcess()
            self.spawned_procs+=1
        except AssertionError as e:
            del self.pref_dict[prefix]
            return self.evalInput(inp)

        def do_write(proc_wrap:ProcessWrapper, s:str):
            if DO_SYSCALL:
                proc_wrap.writeToBuf('b"%s"' % s) # convert this so that no newline is added
            else:
                proc_wrap.in_pipe.write(s)



        for c in suffix:
            #parent.writeToBuf('b"%s"' % c)  # convert this so that no newline is added
            do_write(parent, c)
            try:
                parent.cont()
            except ProcessExit:
                parent.parent.wait_for_SIGNAL(SIGCHLD)
                #warning("\noh no \n")
                return -1

            prefix += c
            assert prefix not in self.pref_dict
            self.pref_dict[prefix] = parent

            try:
                parent = parent.forkProcess()
                self.spawned_procs += 1
            except AssertionError as e:
                print(e, "rip = %x" % parent.ptraceProcess.getInstrPointer())
                # self.root_proginfo.where(parent.ptraceProcess.getInstrPointer())

        parent.in_pipe.write("\n")
        parent.ptraceProcess.detach()
        result = int(parent.out_pipe.read(100)[1:-1])

        # print(parent.parent.where())
        parent.parent.wait_for_SIGNAL(SIGCHLD)

        return result

    def __del__(self):
        with redirect_stdout(out_file):
            self.manager.debugger.quit()

        warning("spawned procs = %d" % self.spawned_procs)
        print("forkfuzzer spawned procs = %d" % self.spawned_procs, file=log_file)


import resource

soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
soft_filelimit = soft * 256
resource.setrlimit(resource.RLIMIT_NOFILE, (soft_filelimit, hard))
print("set filelimit")

from timeit import default_timer


def time_fuzzer(fuzzerClass: type, path: str, num_gens: int):
    os.closerange(20, soft_filelimit - 2)

    start = default_timer()
    fuzzer = fuzzerClass(path)

    result = fuzzer.main(num_gens)
    end = default_timer()

    del fuzzer
    # time.sleep(10)

    return result, (end - start)


from sys import argv


path = "fuzzme/fuzzme_busy4_read"
num_gens = int(argv[2] if len(argv)>2 else 30)

ind = int(argv[1])
seed = int(argv[3] if len(argv) > 3 else 1)
to_test = [ForkFuzzer, NaiveFuzzer, NaiveFuzzerForkever, FuzzerForkserver][ind]

log_file = open("fuzzme/results%d-%d" % (ind, seed), "a")
out_file = open("/dev/null", "w")

for num_gens in [num_gens+1]: #range(30,90,5):
    random.seed(seed)
    npseed(seed)

    if redirect:
        with redirect_stdout(out_file):
            result = time_fuzzer(to_test, path, num_gens)
    else:
        result = time_fuzzer(to_test, path, num_gens)

    #print(str(to_test),"num_gens = %d" % num_gens, result[0][0], result[1], "seed = %d" % seed, "DO_SYSCALL = %d" % DO_SYSCALL, file=log_file)
    os.closerange(out_file.fileno()+1, soft_filelimit)
