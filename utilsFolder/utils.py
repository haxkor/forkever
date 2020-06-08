import os
import time
import datetime


def timestamp():
    timestamp = time.time()
    value = datetime.datetime.fromtimestamp(timestamp)
    return str(value.strftime('%H:%M:%S'))


tmppath = "/tmp/forkever-%s/" % timestamp()
os.mkdir(tmppath)
