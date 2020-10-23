# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""hARPy: Active/passive ARP discovery tool."""

import os
import sys
import time
import atexit
import datetime
import threading
import traceback
import harpy.core.data as data
from harpy.core.data import with_red, with_green
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
    """Terminate the program."""

    print()
    if data.ERRORS:
        print()
        for _ in data.ERRORS:
            print(_)

    print('\ntrying to exit cleanly, please wait...', end=' ', flush=True)
    for i, _ in enumerate(data.THREADS):
        start_time = time.time()
        if hasattr(main, _):
            getattr(main, _).flag.set()
            while getattr(main, _).is_alive():
                # Still alive?
                if time.time() - start_time > data.TERMINATE_TIMEOUT:
                    # Last thread?
                    if i == len(data.THREADS) - 1:
                        print(with_red(data.FAIL))
                        # Go to the finally clause without logging
                        hard_terminator()
                    else:
                        break

    if hasattr(main, 'socket'):
        getattr(main, 'socket').close()  # Close the socket

    print(with_green(data.SUCCESS))


def hard_terminator(*args):
    """
    Terminate the program the hard way.

    :param args: Container that contains type, value and traceback.
    """

    try:
        # Container full?
        if args:
            today = str(datetime.datetime.today())
            with open(data.LOGS_FILE, 'a') as logs:
                logs.write(today + '\n' + len(today) * '#' + '\n')
                # pylint: disable=E1120
                for _ in traceback.format_exception(*args):
                    logs.write(_)
                logs.write('\n')
    finally:
        EchoHandler().enable_echo()
        getattr(os, '_exit')(34)  # Force to exit


def main():
    """Main function."""

    sys.excepthook = hard_terminator

    # Register to enable echoing on normal exits
    atexit.register(EchoHandler().enable_echo)

    EchoHandler().disable_echo()

    SignalHandler(*data.SIGNALS).disable_handler()
    SignalHandler(data.SIGCHLD).disable_handler()
    SignalHandler(data.SIGWINCH).disable_handler()

    parser = ParserHandler.add_arguments()
    # No arguments?
    if len(sys.argv) == 1:
        sys.exit(parser.print_help())

    data.COMMANDS = parser.parse_args()
    if data.COMMANDS.a:
        sys.exit(parser.description)
    elif data.COMMANDS.l:
        if os.path.isfile(data.LOGS_FILE):
            sys.exit(os.system(f'cat {data.LOGS_FILE}'))
        sys.exit('no logs')
    if False in ParserHandler.check_arguments(data.COMMANDS):
        sys.exit(1)

    setattr(main, 'socket', SocketHandler(data.SOC_PRO))  # Open a socket
    getattr(main, 'socket').set_options()
    getattr(main, 'socket').bind(interface=data.COMMANDS.i, port=data.SOC_POR)

    data.ETH_SRC = InterfaceHandler.get_mac(getattr(main, 'socket').raw_soc)
    data.ARP_SND = data.ETH_SRC
    data.COMMANDS.r = data.new_range(data.COMMANDS)

    setattr(main, 'sniff', SniffThread(getattr(main, 'socket').raw_soc))
    data.THREADS.append('sniff')
    getattr(main, 'sniff').start()  # Start sniffing packets

    # Active mode?
    if not data.COMMANDS.p:
        setattr(main, 'send', SendThread(getattr(main, 'socket').raw_soc))
        data.THREADS.append('send')
        getattr(main, 'send').start()  # Start sending packets

    while data.RUN_HARPY:
        SignalHandler(*data.SIGNALS).disable_handler()
        window = WindowHandler(data.SNIFF_RESULTS)
        os.system('clear')
        window.draw_skeleton()
        window()
        SignalHandler(*data.SIGNALS).activate_handler(data.signal_handler)

        try:
            result = ResultHandler(
                result=data.SNIFF_RESULT.pop(0),
                results=data.SNIFF_RESULTS
            )
        except IndexError:
            # Reduce screen flickering
            time.sleep(0.025)
        else:
            result.vendor = result.get_vendor(result.eth_src_mac)
            data.SNIFF_RESULTS = result()
            time.sleep(0.025)

    # Disable the handler to prevent activating it again
    if threading.current_thread() is threading.main_thread():
        SignalHandler(*data.SIGNALS).disable_handler()


def multi_main():
    main()
    terminator()


if __name__ == '__main__':
    multi_main()
