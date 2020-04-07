import threading
import socket
from queue import Queue, Empty
import time

import PollableQueue

import sys


sock1, sock2 = socket.socketpair()

def test1():


    global sock1
    global sock2

    t1= threading.Thread(target=threadfunc)
    t1.run()

    print("gonna recv from new thread")
    print(sock1.recv(1000))



def threadfunc():

    print("other thread here, ident= %d" % threading.get_ident())

    sock2.send(b"thread speaking")
    sock2.send(b"fuck")
    #sock2.close()


pollq = PollableQueue.PollableQueue()
def test2():

    t2= threading.Thread(target=threadfunc2)
    t2.run()

    print("after run")


    for line in iter(sys.stdin.readline, b""):
        pollq.put(line)



def threadfunc2():


    line= pollq.get()
    print(line)









def main():
    test2()

if __name__ == "__main__":
    test2()
