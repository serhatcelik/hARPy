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
import harpy.data.core as core
import harpy.data.functions as func
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
    SignalHandler(*core.SIGNALS).disable()

    # Not hanged up?
    while sys.stdout.isatty():
        print('\n')
        for _ in core.EXIT_MESSAGES:
            print(_, end='')
        print('cleaning...\n', flush=True)
        break

    for i, _ in enumerate(core.THREADS):
        vars(main)[_].flag.set()
        time_terminator = time.time()  # Restore for every thread
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

    :param args: Container that contains type, value and traceback.
    """

    # Container full?
    if args:
        logger = logging.getLogger()
        logger.addHandler(logging.handlers.SysLogHandler(address=core.DEV_LOG))
        logger.critical(traceback.format_exception(args[0], args[1], args[-1]))

    # atexit.register will not work when os._exit() is called, so...
    EchoHandler().enable()
    vars(os)['_exit'](34)  # Force to exit


def main():
    """Main function."""

    sys.excepthook = hard_terminator

    # Pipe used?
    if False in [sys.stdin.isatty(), sys.stdout.isatty(), sys.stderr.isatty()]:
        sys.exit(1)
    # Background?
    elif os.getpgrp() != os.tcgetpgrp(sys.stdout.fileno()):
        sys.exit(1)

    SignalHandler(core.SIGHUP).enable(func.signal_handler)
    SignalHandler(core.SIGCHLD).disable()
    SignalHandler(core.SIGWINCH).disable()
    SignalHandler(*core.SIGNALS).disable()

    # Register to enable the terminal echo at normal program termination
    atexit.register(EchoHandler().enable)
    EchoHandler().disable()

    parser = ParserHandler.add_arguments()
    core.COMMANDS = parser.parse_args()
    if True in [
            not core.COMMANDS.p and not core.COMMANDS.r,
            core.COMMANDS.f and not core.COMMANDS.r
    ]:
        sys.exit(parser.print_help())
    elif False in ParserHandler.check_arguments(core.COMMANDS):
        sys.exit(1)

    setattr(main, core.SOCKET, SocketHandler(core.SOC_PRO))  # Open a socket
    vars(main)[core.SOCKET].set_options()
    vars(main)[core.SOCKET].bind(interface=core.COMMANDS.i, port=core.SOC_POR)

    core.ETH_SRC = InterfaceHandler.get_mac(vars(main)[core.SOCKET].l2soc)
    core.ARP_SND = core.ETH_SRC
    core.COMMANDS.r = func.new_range()

    setattr(main, core.SNIFF, SniffThread(vars(main)[core.SOCKET].l2soc))
    core.THREADS.append(vars(main)[core.SNIFF].name)
    vars(main)[core.SNIFF].start()  # Start sniffing packets

    # Active mode?
    if not core.COMMANDS.p:
        setattr(main, core.SEND, SendThread(vars(main)[core.SOCKET].l2soc))
        core.THREADS.append(vars(main)[core.SEND].name)
        vars(main)[core.SEND].start()  # Start sending packets

    while core.RUN_MAIN:
        SignalHandler(*core.SIGNALS).disable()
        window = WindowHandler(core.SNIFF_RESULTS)
        os.system('clear')
        window.draw_skeleton()
        window()
        SignalHandler(*core.SIGNALS).enable(func.signal_handler)

        time_main = time.time()  # Restore after a certain period of time
        while core.RUN_MAIN and time.time() - time_main < core.SLEEP_MAIN:
            func.run_main()
            if core.SNIFF_RESULT:
                core.SNIFF_RESULTS = ResultHandler(
                    result=core.SNIFF_RESULT.pop(0),
                    results=core.SNIFF_RESULTS
                )()


def multi_main():
    """Main function for the setup script."""

    main()
    terminator()


if __name__ == '__main__':
    multi_main()
