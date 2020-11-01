from PaulaPipe import Pipe
import subprocess

args="python3 waiter.py"

p=Pipe()

subprocess.Popen(args.split(), stdout=p.writeobj)

print(p.read(100))
