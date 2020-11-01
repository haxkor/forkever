from os import fork, getpid
from errno import errorcode
from time import sleep
from random import uniform


i=0

print( "pid = %d " % getpid())

with open("/proc/%d/limits" % getpid(), "r") as f:
    print(f.read())


try:
    while fork():
        i+=1

except BaseException as e:
    print(i)
    print(e)
    sleep(10)
    print("done")

exit(1)
