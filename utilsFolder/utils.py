import ptrace.debugger.process as process
import os
import logging2

def timestamp():
    import datetime
    import time
    timestamp = time.time()
    value = datetime.datetime.fromtimestamp(timestamp)
    return str(value.strftime('%H:%M:%S'))


tmppath = "/tmp/paula-%s/" % timestamp()
os.mkdir(tmppath)



