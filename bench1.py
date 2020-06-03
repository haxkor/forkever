from ProcessWrapper import ProcessWrapper, LaunchArguments
from ProcessManager import ProcessManager
from utilsFolder.PaulaPoll import PaulaPoll

import pwn
pwn.context.log_level= "ERROR"

from subprocess import Popen, PIPE

from timeit import default_timer as time

args = ["ls"]
launch_args = LaunchArguments(args, random=False)
dummy_poll = PaulaPoll()

time_dict = dict()
time_dict["start"] = time()

manager = ProcessManager(launch_args, dummy_poll)
time_dict["launch"] = time()
num_children = 100

monitor_args = "free -s 1 -w".split()
monitor = Popen(monitor_args, stdout=PIPE)

root_proc = manager.getCurrentProcess()
new_procs = [root_proc.forkProcess() for _ in range(num_children)]

time_dict["done"] = time()

monitor.kill()
monitor_log = monitor.communicate()[0].splitlines(keepends=True)

len_log= len(monitor_log)
while(len_log % 3):
    monitor_log += b"spam\n"
    len_log= len(monitor_log)

outputs_count = len(monitor_log) // 3

free_outputs = [monitor_log[i * 3] + monitor_log[i * 3 + 1] + monitor_log[i * 3 + 2]
                for i in range(outputs_count)]

print("done - launch=", time_dict["done"] - time_dict["launch"])

for o in free_outputs:
    print(o.decode())
