# This file is part of harpy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""hARPy -who uses ARP-: Active/passive ARP discovery tool."""

import os
import re
import sys
import time
import atexit
import traceback
import logging.config
from harpy import data
from harpy.data import run_main
from harpy.threads import SendThread, SniffThread
from harpy.handlers import (
    EchoHandler, ExceptionHandler, InterfaceHandler, ParserHandler,
    ResultHandler, SignalHandler, SocketHandler, WindowHandler,
)


@ExceptionHandler()
def terminator():
    """Terminates all threads and closes the socket."""

    # Disable the handler to prevent activating it again
    getattr(main, data.SIGNAL, SignalHandler()).ignore(*data.IGNORE_SIGNALS)

    # Join first to prevent the "Set changed size during iteration" error
    for _ in data.THREADS:
        vars(main)[_].flag.set()  # Tell the thread to terminate itself
        vars(main)[_].join()

    if hasattr(main, data.SOCKET):
        vars(main)[data.SOCKET].close()  # Close the socket

    print("\n")
    for _ in data.EXIT_MSGS:
        print(_)
    print(flush=True)

    # Errors?
    if any([re.search(data.RE_ANSI, _) for _ in data.EXIT_MSGS]):
        sys.exit(1)


def hard_terminator(*args):
    """
    Logs the exception and terminates all threads the hard way.

    :param args: Container that stores type, value and traceback.
    """

    log_conf_file = os.path.join(os.path.dirname(__file__), "logging.conf")
    logging.config.fileConfig(log_conf_file)
    logger = logging.getLogger("harpy")
    logger.critical("%s\n", traceback.format_exception(*args))  # pylint: disable=E1120

    # atexit.register will not work when os._exit is called, so...
    getattr(main, data.ECHO, EchoHandler()).enable()
    vars(os)["_exit"](34)  # Force to exit with code 34


def main():
    setattr(main, data.SIGNAL, SignalHandler())
    vars(main)[data.SIGNAL].catch(*data.CATCH_SIGNALS)
    vars(main)[data.SIGNAL].ignore(*data.IGNORE_SIGNALS)

    setattr(main, data.ECHO, EchoHandler())
    atexit.register(vars(main)[data.ECHO].enable)
    vars(main)[data.ECHO].disable()

    setattr(main, data.PARSER, ParserHandler())
    commands = vars(main)[data.PARSER].create_arguments()
    vars(main)[data.PARSER].create_links(commands)

    if False in vars(main)[data.PARSER].check_arguments():
        sys.exit(1)

    setattr(main, data.SOCKET, SocketHandler(data.SOC_PRO))
    vars(main)[data.SOCKET].set_options()
    vars(main)[data.SOCKET].bind(data.INT, data.SOC_POR)

    data.SRC_MAC = InterfaceHandler.get_mac(vars(main)[data.SOCKET].l2soc)
    data.SND_MAC = data.SRC_MAC

    setattr(main, data.SNIFF, SniffThread(vars(main)[data.SOCKET].l2soc))
    vars(main)[data.SNIFF].name = data.SNIFF
    data.THREADS.append(vars(main)[data.SNIFF].name)
    vars(main)[data.SNIFF].start()  # Start sniffing the packets

    # Active mode?
    if not data.PAS:
        setattr(main, data.SEND, SendThread(vars(main)[data.SOCKET].l2soc))
        vars(main)[data.SEND].name = data.SEND
        data.THREADS.append(vars(main)[data.SEND].name)
        vars(main)[data.SEND].start()  # Start sending the packets

    time_timeout = time.time()  # Countdown start time
    while data.RUN_MAIN:
        vars(main)[data.SIGNAL].ignore(*data.IGNORE_SIGNALS)
        setattr(main, data.WINDOW, WindowHandler(data.SNIFF_ALL))
        os.system("clear")
        vars(main)[data.WINDOW].draw_skeleton()
        vars(main)[data.WINDOW]()
        vars(main)[data.SIGNAL].catch(*data.CATCH_SIGNALS)

        time_main = time.time()  # Create a new one at every step
        while data.RUN_MAIN and time.time() - time_main < data.WAIT_MAIN:
            # Improve packet sending performance in other thread
            time.sleep(.0001)
            run_main(data.RUN_MAIN, time.time() - time_timeout >= data.TIM)
            if data.SNIFF_A:
                setattr(main, data.RESULT, ResultHandler(data.SNIFF_A.pop(0)))
                data.SNIFF_ALL = vars(main)[data.RESULT](data.SNIFF_ALL)


def setup_py_main():
    sys.excepthook = hard_terminator

    if sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty():
        if os.getpgrp() == os.tcgetpgrp(sys.stdout.fileno()):
            main()
            terminator()


if __name__ == "__main__":
    setup_py_main()
