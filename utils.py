import os
import logging


def timestamp():
    import datetime
    import time
    timestamp = time.time()
    value = datetime.datetime.fromtimestamp(timestamp)
    return str(value.strftime('%H:%M:%S'))


def changeLogHandler():
    """
    this stops the log from being printed to the console,
    instead the logs will be written to a logfile
    """
    logfile = open(tmppath + "logfile", "w")
    rootlog = logging.getLogger()
    roothandlers = rootlog.handlers
    lh1 = logging.StreamHandler(logfile)

    rootlog.addHandler(lh1)
    rootlog.removeHandler(roothandlers[0])


tmppath = "/tmp/paula-%s/" % timestamp()
os.mkdir(tmppath)
