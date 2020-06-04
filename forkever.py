#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pwn

from os import kill
from signal import SIGKILL

from argparse import ArgumentParser, REMAINDER
from InputHandler import InputHandler
from ProcessWrapper import LaunchArguments



def main():
    pwn.context.log_level = "ERROR"

    def _handle_final_outputs(poll_res):
        outs = map(lambda poll_elem: poll_elem[0], poll_res)

        if any("out" in out for out in outs):
            handler.handle_procout(None, None, None)
        if any("err" in out for out in outs):
            handler.handle_stderr(None)

    p = ArgumentParser()
    p.add_argument("-init", help="Pass a file for initial commands")
    p.add_argument("-rand", action="store_true", help="to enable randomization")  # randomization disabled by default
    p.add_argument("-sock", action="store_true",                                  # no socket by default
                   help="if you want to communicate with the program via a socket. (Adjust in Constants.py)")
    p.add_argument("runargs", nargs=REMAINDER)

    parsed_args = p.parse_args()
    launch_args = LaunchArguments(parsed_args.runargs, parsed_args.rand)

    handler = InputHandler(launch_args, startupfile=parsed_args.init, inputsock=parsed_args.sock)

    try:
        handler.inputLoop()
    except KeyboardInterrupt:
        #pids= [proc.pid for proc in handler.manager.debugger.list]
        handler.manager.quit()

        #   for pid in pids:
        #    kill(pid, SIGKILL)

        poll_res = handler.inputPoll.poll(10)
        if poll_res:
            _handle_final_outputs(poll_res)

        exit(1)

    except BaseException as e:
        handler.manager.quit() # otherwise launched children stay alive
        raise e


if __name__ == "__main__":
    main()
