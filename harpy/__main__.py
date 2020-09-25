# This file is part of hARPy

import os
import sys
import queue
import signal
import threading
import traceback
from harpy.data.constants import SOC_PRO, SOC_POR
from harpy.handlers.echo_handler import EchoHandler
from harpy.handlers.packet_handler import PacketHandler
from harpy.handlers.parser_handler import ParserHandler
from harpy.handlers.result_handler import ResultHandler
from harpy.handlers.socket_handler import SocketHandler
from harpy.handlers.window_handler import WindowHandler
from harpy.handlers.interface_handler import InterfaceHandler


def ctrl_c_handler(signum, _frame):
    EchoHandler().enable_echo()
    if getattr(main, "raw_socket", None) is not None:
        getattr(main, "raw_socket").raw_socket.close()  # Close the socket
    sys.exit(f"\n\nharpy: info: received signal {signum}, exiting\n")


def ctrl_z_handler(signum, _frame):
    ctrl_c_handler(signum=signum, _frame=_frame)


def uncaught_exception_handler(*args):
    print("\nharpy: fatal: unexpected error, sending signal 2\n")
    traceback.print_exception(*args)
    os.kill(os.getpid(), signal.SIGINT)


def main():
    signal.signal(signal.SIGINT, ctrl_c_handler)  # Capture signal 2 (SIGINT)
    signal.signal(signal.SIGTSTP, ctrl_z_handler)  # Capture signal 20

    sys.excepthook = uncaught_exception_handler  # Customize the exception hook

    parser = ParserHandler.add_arguments()
    if len(sys.argv) == 1:  # No arguments are given
        sys.exit(parser.print_help())

    commands = parser.parse_args()
    ParserHandler.check_arguments(commands=commands)

    main.raw_socket = SocketHandler(protocol=SOC_PRO)  # Open a socket
    main.raw_socket.set_options()
    main.raw_socket.bind(interface=commands.i, port=SOC_POR)

    packet = PacketHandler(
        raw_socket=main.raw_socket.raw_socket,
        own_src_mac=InterfaceHandler.get_mac_address(
            raw_socket=main.raw_socket.raw_socket
        ),
        rng=commands.r
    )  # Create an object to handle packets

    sniff_results = list()  # An empty container to store sniff results
    sniff_queue = queue.Queue()  # A queue to get results from sniff thread

    EchoHandler().disable_echo()  # Disable ECHO
    os.system("clear")
    while True:
        sys.stdout.write("\033[H\033[J")  # Clear without clear for performance
        window = WindowHandler(results=sniff_results)
        window.draw_skeleton(
            ["IP ADDRESS", window.max_ip_len],
            ["ETH MAC ADDRESS", window.max_eth_mac_len],
            ["ARP MAC ADDRESS", window.max_arp_mac_len],
            ["REQ.", window.max_req_len],
            ["REP.", window.max_rep_len],
            ["VENDOR", -1]
        )
        window_thread = threading.Thread(target=window(), daemon=True)
        window_thread.start()
        window_thread.join()

        while True:
            sniff_thread = threading.Thread(
                target=lambda q: q.put(packet.sniff()),
                args=(sniff_queue,),
                daemon=True
            )
            sniff_thread.start()  # Start sniffing packets

            if not commands.p:  # Is mode passive?
                sender_thread = threading.Thread(
                    target=packet.send,
                    args=(commands.c, commands.n, commands.s,),
                    daemon=True
                )
                sender_thread.start()  # Start sending packets
                commands.p = True  # Prevent sending packets again

            sniff_result = sniff_queue.get()  # Get a result from the queue
            if sniff_result is not None:
                result = ResultHandler(
                    result=sniff_result, results=sniff_results
                )
                result.vendor = result.get_mac_vendor(
                    src_mac=result.eth_src_mac
                )
                sniff_results = result()
                break


if __name__ == "__main__":
    main()
