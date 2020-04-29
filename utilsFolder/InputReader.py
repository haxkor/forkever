from utilsFolder.PollableQueue import PollableQueue
from sys import stdin

# this will be run in a seperate thread
def mainReader(stdinQ:PollableQueue):

    for line in iter(stdin.readline, b""):
        #determine result(line)
        stdinQ.put(line.decode())


