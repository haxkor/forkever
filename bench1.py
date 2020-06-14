from ProcessWrapper import ProcessWrapper, LaunchArguments
from ProcessManager import ProcessManager
from utilsFolder.PaulaPoll import PaulaPoll

import matplotlib.pyplot as plt
import os
import pwn
pwn.context.log_level = "ERROR"

from subprocess import Popen, PIPE
from time import sleep

from timeit import default_timer 
import resource

print( resource.getrlimit(resource.RLIMIT_NPROC))

args = ["ls"]
launch_args = LaunchArguments(args, random=False)
dummy_poll = PaulaPoll()

time_dict = dict()
time_dict["start"] = default_timer()

manager = ProcessManager(launch_args, dummy_poll)
time_dict["launch"] = default_timer()
num_children = 600

monitor_args = "free -s 4.6 -w".split()
monitor = Popen(monitor_args, stdout=PIPE)

top_outfile = open("top_log","wb")
top_monitor_args = "top -b -d 0.1".split()
top_monitor = Popen(top_monitor_args, stdout=top_outfile)

root_proc = manager.getCurrentProcess()
new_procs = []

#root_proc.getrlimit(1)

#new_procs = [root_proc.forkProcess() for _ in range(num_children)]

for i in range(num_children):
    try:
        new_procs.append( root_proc.forkProcess())
        if i%(num_children//10) == 0:
            print(i)

    except BaseException as e:
        print(i)
        num_children = i
        print( new_procs[-2].getPid())
        break
        #raise e

time_dict["done"] = default_timer()

monitor.kill()
sleep(1)
top_monitor.kill()

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

interesting_columns = [ ("virt",4), ("res",5), ("share",6) ]
def parse_top_output(out):
    out=out.split()
    try:
        return dict((name, int(out[ind])) for name,ind in interesting_columns)
    except IndexError:
        print(out)

#top_monitor_log = top_monitor.communicate()[0]

top_outfile.close()
with open("top_log", "rb") as f:
    top_monitor_log = f.read()

pids = [procWrap.getPid() for procWrap in new_procs]
def filter_func(line):
    line= line.split()
    try:
        return int(line[0]) in pids
    #if line[0].decode().isdecimal() 
    except (ValueError, IndexError):
        return False

top_results = []
for top_out in top_monitor_log.split(b"top - ")[1:]:
    top_results.append( list(map( parse_top_output, filter( filter_func, top_out.splitlines()))))

os.closerange(10, 1000)


def makeY(outputs, value:str):
    return [ parse_free_output(single_output)[value] for single_output in outputs]

dimension="a"
try:
    while dimension:

        dimension= input("what u wanna plot\n>")[:-1]
        plt.scatter( range(len(free_outputs)), makeY(free_outputs, dimension))
        plt.show()
except (KeyboardInterrupt, KeyError):
    pass


def makeBar(value:str, dim:int):
    y = [top_results[dim][i][value] for i in range(len(top_results[0]))]
    plt.bar(range(len(y)), y)
    plt.show()

def q():
    manager.quit()
    exit()
