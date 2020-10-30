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
import harpy.core.data as data
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
    SignalHandler(*data.SIGNALS).disable()

    # Not hanged up?
    while sys.stdout.isatty():
        print('\n')
        if data.ERRORS:
            for _ in data.ERRORS:
                print(_)
            print()

        if data.TIMED_OUT:
            print('timed out,', end=' ')
        elif data.SIGNAL_NUMBER is not None:
            print('received signal {},'.format(data.SIGNAL_NUMBER), end=' ')
        print('cleaning...\n', flush=True)
        break

    for i, _ in enumerate(data.THREADS):
        start_terminator = time.time()  # Restore for every thread
        vars(main)[_].flag.set()
        while vars(main)[_].is_alive():
            # Still alive?
            if time.time() - start_terminator >= data.SLEEP_TERMINATOR:
                # Last thread?
                if i == len(data.THREADS) - 1:
                    hard_terminator()  # Force to exit without logging
                else:
                    break

    vars(main)[data.SOCKET].close()  # Close the socket


def hard_terminator(*args):
    """
    Terminate all threads the hard way.

    :param args: Container that contains type, value and traceback.
    """

    # Container full?
    if args:
        logger = logging.getLogger()
        logger.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
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

    SignalHandler(data.SIGHUP).enable(data.signal_handler)
    SignalHandler(data.SIGCHLD).disable()
    SignalHandler(data.SIGWINCH).disable()
    SignalHandler(*data.SIGNALS).disable()

    # Register to enable the terminal echo at normal program termination
    atexit.register(EchoHandler().enable)
    EchoHandler().disable()

    parser = ParserHandler.add_arguments()
    # No arguments?
    if len(sys.argv) == 1:
        sys.exit(parser.print_help())

    data.COMMANDS = parser.parse_args()
    if False in ParserHandler.check_arguments(data.COMMANDS):
        sys.exit(1)

    setattr(main, data.SOCKET, SocketHandler(data.SOC_PRO))  # Open a socket
    vars(main)[data.SOCKET].set_options()
    vars(main)[data.SOCKET].bind(interface=data.COMMANDS.i, port=data.SOC_POR)

    data.ETH_SRC = InterfaceHandler.get_mac(vars(main)[data.SOCKET].raw_soc)
    data.ARP_SND = data.ETH_SRC
    data.COMMANDS.r = data.new_range()

    setattr(main, data.SNIFF, SniffThread(vars(main)[data.SOCKET].raw_soc))
    data.THREADS.append(vars(main)[data.SNIFF].name)
    vars(main)[data.SNIFF].start()  # Start sniffing packets

    # Active mode?
    if not data.COMMANDS.p:
        setattr(main, data.SEND, SendThread(vars(main)[data.SOCKET].raw_soc))
        data.THREADS.append(vars(main)[data.SEND].name)
        vars(main)[data.SEND].start()  # Start sending packets

    while data.RUN_MAIN:
        data.run_main()
        ################################################################
        SignalHandler(*data.SIGNALS).disable()
        window = WindowHandler(data.SNIFF_RESULTS)
        os.system('clear')
        window.draw_skeleton()
        window()
        SignalHandler(*data.SIGNALS).enable(data.signal_handler)
        ################################################################
        time.sleep(data.SLEEP_MAIN)

        if data.SNIFF_RESULT:
            result = ResultHandler(
                result=data.SNIFF_RESULT.pop(0),
                results=data.SNIFF_RESULTS
            )
            data.SNIFF_RESULTS = result()


def multi_main():
    """Main function for the setup script."""

    main()
    terminator()


if __name__ == '__main__':
    multi_main()
