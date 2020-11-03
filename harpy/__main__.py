# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""hARPy -who uses ARP-: Active/passive ARP discovery tool."""

import os
import sys
import time
import atexit
import traceback
import logging.handlers
from harpy.data import variables as core
from harpy.data import functions as func
from harpy.threads.send_thread import SendThread
from harpy.threads.sniff_thread import SniffThread
from harpy.handlers.echo_handler import EchoHandler
from harpy.handlers.parser_handler import ParserHandler
from harpy.handlers.result_handler import ResultHandler
from harpy.handlers.signal_handler import SignalHandler
from harpy.handlers.socket_handler import SocketHandler
from harpy.handlers.window_handler import WindowHandler
from harpy.handlers.interface_handler import InterfaceHandler


def terminator():
    """Terminate all threads."""

    # Disable the handler to prevent activating it again
    getattr(main, core.SIGNAL).ignore(*core.IGNORE_SIGNALS)

    for i, _ in enumerate(core.EXIT_MESSAGES):
        # Not hanged up?
        if sys.stdout.isatty():
            print('\n\n' + _ if i == 0 else _)
            # Last message?
            if i == len(core.EXIT_MESSAGES) - 1:
                print('cleaning...\n', flush=True)

    for i, _ in enumerate(core.THREADS):
        vars(main)[_].flag.set()
        time_terminator = time.time()  # Restore for each thread
        while vars(main)[_].is_alive():
            # Still alive?
            if time.time() - time_terminator >= core.SLEEP_TERMINATOR:
                # Last thread?
                if i == len(core.THREADS) - 1:
                    hard_terminator()  # Force to exit without logging
                else:
                    break

    vars(main)[core.SOCKET].close()  # Close the socket


def hard_terminator(*args):
    """
    Terminate all threads the hard way.

    :param args: Container that stores type, value and traceback.
    """

    # Container full?
    if args:
        logger = logging.getLogger()
        logger.addHandler(logging.handlers.SysLogHandler(core.DEV_LOG))
        logger.critical(traceback.format_exception(args[0], args[1], args[-1]))

    # atexit.register will not work when os._exit() is called, so...
    getattr(main, core.ECHO, EchoHandler()).enable()
    vars(os)['_exit'](34)  # Force to exit


def main():
    """The main function."""

    sys.excepthook = hard_terminator

    setattr(main, core.SIGNAL, SignalHandler(func.signal_handler))
    vars(main)[core.SIGNAL].catch(*core.CATCH_SIGNALS)
    vars(main)[core.SIGNAL].ignore(*core.IGNORE_SIGNALS)

    setattr(main, core.ECHO, EchoHandler())
    atexit.register(vars(main)[core.ECHO].enable)
    vars(main)[core.ECHO].disable()

    setattr(main, core.PARSER, ParserHandler())
    parser = vars(main)[core.PARSER].create_arguments()
    core.COMMANDS = parser.parse_args()
    if False in vars(main)[core.PARSER].check_arguments():
        sys.exit(parser.print_help())

    setattr(main, core.SOCKET, SocketHandler(core.SOC_PRO))
    vars(main)[core.SOCKET].set_options()
    vars(main)[core.SOCKET].bind(core.COMMANDS.i, core.SOC_POR)

    core.SRC_MAC = InterfaceHandler.get_mac(vars(main)[core.SOCKET].l2soc)
    core.SND_MAC = core.SRC_MAC
    core.COMMANDS.r = func.new_range()

    setattr(main, core.SNIFF, SniffThread(vars(main)[core.SOCKET].l2soc))
    core.THREADS.append(vars(main)[core.SNIFF].name)
    vars(main)[core.SNIFF].start()  # Start sniffing the packets

    # Active mode?
    if not core.COMMANDS.p:
        setattr(main, core.SEND, SendThread(vars(main)[core.SOCKET].l2soc))
        core.THREADS.append(vars(main)[core.SEND].name)
        vars(main)[core.SEND].start()  # Start sending the packets

    while core.RUN_MAIN:
        vars(main)[core.SIGNAL].ignore(*core.IGNORE_SIGNALS)
        setattr(main, core.WINDOW, WindowHandler(core.SNIFF_ALL))
        os.system('clear')
        vars(main)[core.WINDOW].draw_skeleton()
        vars(main)[core.WINDOW]()
        vars(main)[core.SIGNAL].catch(*core.CATCH_SIGNALS)

        time_main = time.time()
        while core.RUN_MAIN and time.time() - time_main < core.SLEEP_MAIN:
            func.run_main()
            if core.SNIFF_A:
                setattr(main, core.RESULT, ResultHandler(core.SNIFF_A.pop(0)))
                core.SNIFF_ALL = vars(main)[core.RESULT]()


def setup_main():
    """The main function for the setup script."""

    if sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty():
        if os.getpgrp() == os.tcgetpgrp(sys.stdout.fileno()):
            main()
            terminator()


if __name__ == '__main__':
    setup_main()
