#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pwn
pwn.context.log_level = "ERROR"

from argparse import ArgumentParser, REMAINDER
from InputHandler import InputHandler
from ProcessWrapper import LaunchArguments

p = ArgumentParser()
p.add_argument("-init", help="Pass a file for initial commands")
p.add_argument("-rand", action="store_true",help="to disable randomization")    # randomization disabled by default
p.add_argument("-sock", action="store_true",
               help="if you want to communicate with the program via a socket. (Adjust in Constants.py)")    # no socket by default
p.add_argument("runargs", nargs=REMAINDER)

parsed_args = p.parse_args()
print("runargs= %s" % parsed_args.runargs)
print("inputsock = ", parsed_args.sock)
launch_args = LaunchArguments(parsed_args.runargs, parsed_args.rand)

handler = InputHandler(launch_args, startupfile=parsed_args.init, inputsock=parsed_args.sock)

try:
    handler.inputLoop()
except KeyboardInterrupt:
    handler.manager.debugger.quit()
    handler.handle_procout(None,None,None)
    exit(1)
except BaseException as e:
    raise e
