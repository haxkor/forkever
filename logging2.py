#
#   This is a very dirty hack
#   Because pwntools uses its own logging implementation, things get messy
#   when ptrace.debugger wants to make use of the standard module.
#   This logging2 module is a proxy that forwards the "critical imports"
#   by python-ptrace to pwntools
#

from logging import *
from pwnlib.log import getLogger

logger = getLogger("pwnlib")


def info(msg):
    logger.info(msg)

def debug(msg):
    logger.debug(msg)


def warning(msg):
    logger.warning(msg)


def error(msg):
    logger.error(msg)


def log(msg):
    logger.log(msg)
