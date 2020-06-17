#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from argparse import ArgumentParser, REMAINDER

import pwn

from InputHandler import InputHandler
from ProcessWrapper import LaunchArguments


def main():
    pwn.context.log_level = "ERROR"

    def _handle_final_outputs(poll_res):
        if not poll_res:
            return
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

    # for now, Ctrl + C exits. The issue is that the event might abort
    # a procedure right in the middle of it.
    except KeyboardInterrupt:
        handler.manager.quit()
        _handle_final_outputs(handler.inputPoll.poll(10))
        exit(1)

    except BaseException as e:
        print("oh noes, a bug! please copy everything and send it to haxkor")
        print(handler.manager.family())
        handler.manager.quit() # otherwise launched children stay alive
        raise e


if __name__ == "__main__":
    main()
