from ProcessWrapper import ProcessWrapper, LaunchArguments
from ProcessManager import ProcessManager
from utilsFolder.PaulaPoll import PaulaPoll

import pwn
pwn.context.log_level = "ERROR"

from subprocess import Popen, PIPE

from timeit import default_timer as time
import resource

print( resource.getrlimit(resource.RLIMIT_NPROC))

args = ["ls"]
launch_args = LaunchArguments(args, random=False)
dummy_poll = PaulaPoll()

time_dict = dict()
time_dict["start"] = time()

manager = ProcessManager(launch_args, dummy_poll)
time_dict["launch"] = time()
num_children = 30000

monitor_args = "free -s 0.01 -w".split()
monitor = Popen(monitor_args, stdout=PIPE)

root_proc = manager.getCurrentProcess()
new_procs = []

root_proc.getrlimit(1)

#new_procs = [root_proc.forkProcess() for _ in range(num_children)]

for i in range(num_children):
    try:
        new_procs.append( root_proc.forkProcess())
    except BaseException as e:
        print(i)
        num_children = i
        print( new_procs[-2].getPid())
        raise e

time_dict["done"] = time()

monitor.kill()
monitor_log = monitor.communicate()[0].splitlines(keepends=True)

while len(monitor_log) % 3:
    monitor_log.append(b"s\n")

outputs_count = len(monitor_log) // 3

free_outputs = []
single_result= b""
for line in monitor_log:
    if len(line) <= 5:
        continue
    else:
        single_result += line
        if b"Swap" in single_result:
            free_outputs.append(single_result)
            single_result=b""



print("average=", (time_dict["done"] - time_dict["launch"])/ num_children)

def parse_free_output(output:bytes):
    r= dict()
    lines= output.splitlines()

    vals = map(int, lines[1].split()[1:])
    r["total"], r["used"], r["free"], r["shared"], r["buffers"], r["free"], r["available"] = vals

    return r

import os
os.closerange(10, 1000)

import matplotlib.pyplot as plt

def makeY(outputs, value:str):
    return [ parse_free_output(single_output)[value] for single_output in outputs]


plt.scatter( range(len(free_outputs)), makeY(free_outputs, "free"))
plt.show()
