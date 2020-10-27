# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""hARPy: Active/passive ARP discovery tool."""

import os
import sys
import time
import traceback
import logging.handlers
import harpy.core.data as data
from harpy.core.data import with_red
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

    if not data.HANGED_UP:
        print('\n')
        if data.ERRORS:
            for _ in data.ERRORS:
                print(_)
            print()

        if data.TIMED_OUT:
            print('timed out', end=',' + ' ')
        elif data.SIGNAL_NUMBER is not None:
            print('received signal', end=' ' + data.SIGNAL_NUMBER + ',' + ' ')
        print('cleaning...', end=' ', flush=True)

    terminator_start = time.time()
    for i, _ in enumerate(data.THREADS):
        vars(main)[_].flag.set()
        while vars(main)[_].is_alive():
            # Still alive?
            if time.time() - terminator_start >= data.SLEEP_TERMINATOR:
                # Last thread?
                if i == len(data.THREADS) - 1:
                    if not data.HANGED_UP:
                        print('[' + data.F_RED + 'fail' + data.RESET + ']')
                    hard_terminator()  # Force to exit without logging
                else:
                    break

    vars(main)[data.SOCKET].close()  # Close the socket

    if not data.HANGED_UP:
        print('[' + data.F_GREEN + 'done' + data.RESET + ']')


def hard_terminator(*args):
    """
    Terminate all threads the hard way.

    :param args: Container that contains type, value and traceback.
    """

    # Container full?
    if args:
        logger = logging.getLogger()
        logger.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
        logger.critical(traceback.format_exception(*args))

    EchoHandler().enable()
    vars(os)['_exit'](34)  # Force to exit


def main():
    """Main function."""

    sys.excepthook = hard_terminator

    EchoHandler().disable()

    SignalHandler(*data.SIGNALS).disable()
    SignalHandler(data.SIGCHLD).disable()
    SignalHandler(data.SIGWINCH).disable()
    SignalHandler(data.SIGHUP).enable(data.signal_handler)

    parser = ParserHandler.add_arguments()
    # No arguments?
    if len(sys.argv) == 1:
        sys.exit(parser.print_help())

    data.COMMANDS = parser.parse_args()
    if None in ParserHandler.check_arguments(data.COMMANDS):
        sys.exit(with_red('problem with interface'))
    elif False in ParserHandler.check_arguments(data.COMMANDS):
        sys.exit(with_red('problem with range'))

    setattr(main, data.SOCKET, SocketHandler(data.SOC_PRO))  # Open a socket
    vars(main)[data.SOCKET].set_options()
    vars(main)[data.SOCKET].bind(interface=data.COMMANDS.i, port=data.SOC_POR)

    data.ETH_SRC = InterfaceHandler.get_mac(vars(main)[data.SOCKET].raw_soc)
    data.ARP_SND = data.ETH_SRC
    data.COMMANDS.r = data.new_range(data.COMMANDS)

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
