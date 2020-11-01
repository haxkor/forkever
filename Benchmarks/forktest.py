from os import fork
from errno import errorcode
from time import sleep
from random import uniform


i=0
while 1:
    i+=1
    try:
        ret= fork()
        if not ret:
            sleep(uniform(0, 10))
            exit(1)
    except BaseException as e:
        print(i)
        print(ret)
        print(e)
        break
        exit(1)

exit(2)
