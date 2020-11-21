# This file is part of harpy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global handler classes to control external modules."""

import os
import re
import sys
import json
import signal
import socket
import struct
import termios
import binascii
import argparse
import threading
from harpy import data
from harpy.data import (
    green, red, yellow, logo, banner, add_colons, add_dots, run_main,
)


class ExceptionHandler:
    def __init__(self, who=None):
        self.who = who

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except (OSError, termios.error) as err:
                # 5: Input/output error
                if err.args[0] == 5:
                    pass
                elif err.args[0] in (6, 9, 19, 100):
                    # 6: No such device or address
                    # 9: Bad file descriptor
                    # 19: No such device
                    # 100: Network is down
                    self.add_exception(err.args[0], err.args[1])
                else:
                    raise

                run_main(False)

        return wrapper

    def add_exception(self, errnum, error):
        """
        Updates the exit messages container with a new error message.

        :param errnum: Error number.
        :param error: Error content.
        """

        full_error = "[%s] %s" % (red("Errno %d" % errnum), error)

        data.EXIT_MSGS.add("%s > %s" % (self.who, full_error))


class ArgumentHandler:
    @staticmethod
    def count_handler(arg):
        if arg < data.MIN_CNT:
            data.CNT = data.MIN_CNT

    @staticmethod
    def interface_handler(arg):
        if arg is False:
            print("No carrier in, %s" % data.SYS_PATH)
            return False
        if arg == "lo":
            print("lo > This is not an Ethernet interface")
            return False
        if arg not in InterfaceHandler().members:
            print("%s > No such interface" % arg)
            return False
        if InterfaceHandler().members[arg] == "down":
            print("%s > Interface is in down state" % arg)
            return False
        return True

    @staticmethod
    def log_handler():
        if os.path.isfile(data.LOG_FILE):
            with open(data.LOG_FILE, "r") as log:
                if log.read().strip():
                    os.system("cat %s" % data.LOG_FILE)
                    return False

        print("No logs")

        return False

    @staticmethod
    def node_handler(arg):
        if not data.MIN_NOD <= arg <= data.MAX_NOD:
            data.NOD = data.DEF_NOD

    @staticmethod
    def passive_handler(arg):
        # Passive mode?
        if arg:
            # Fast mode only makes sense in active mode, so...
            data.FST = False

    @staticmethod
    def range_handler(arg):
        if arg is None:
            # Filtering is only allowed if a scanning range is specified, so...
            data.FLT = False
            arg = data.RNG = data.DEF_RNG

        octet = "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"  # [0, 255]
        expression = r"^({0}\.{0}\.{0}\.{0}/(8|16|24))$".format(octet)

        for _ in arg:
            if not bool(re.search(expression, _)):
                print("Problem with scanning range, %s" % _)
                return False

        data.RNG = [[
            _.split(".")[0],
            _.split(".")[1],
            _.split(".")[2],
            _.split(".")[-1].split("/")[0],
            _.split(".")[-1].split("/")[-1],
        ] for _ in arg]  # Convert the scanning range to list format

        return True

    @staticmethod
    def sleep_handler(arg):
        if arg < data.MIN_SLP:
            data.SLP = data.MIN_SLP
        elif arg > data.MAX_SLP:
            data.SLP = data.MAX_SLP

    @staticmethod
    def timeout_handler(arg):
        if arg < data.MIN_TIM:
            data.TIM = data.MIN_TIM


class EchoHandler:
    def __init__(self):
        self.descriptor = sys.stdin.fileno()

    @ExceptionHandler()
    def enable(self):
        """Enables terminal echo."""

        new = termios.tcgetattr(self.descriptor)
        new[3] |= termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, new)

    @ExceptionHandler()
    def disable(self):
        """Disables terminal echo."""

        new = termios.tcgetattr(self.descriptor)
        new[3] &= ~termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, new)


class InterfaceHandler:
    members = dict()  # All interfaces

    def __init__(self):
        if os.path.isdir(data.SYS_PATH):
            self.members = {_: None for _ in os.listdir(data.SYS_PATH)}

        for _ in self.members:
            if _ != "lo":
                operstate_file = os.path.join(data.SYS_PATH, _, "operstate")
                if os.path.isfile(operstate_file):
                    with open(operstate_file, "r") as operstate:
                        self.members[_] = operstate.read().strip().lower()

    def __call__(self):
        for _ in self.members:
            if self.members[_] == "up":
                return _
        return False

    @staticmethod
    def get_mac(l2soc):
        """
        Returns the MAC address of an interface.

        :param l2soc: Layer 2 RAW socket.
        """

        return binascii.hexlify(l2soc.getsockname()[-1]).decode("utf-8")


class PacketHandler:
    @staticmethod
    def create_eth_frame():
        """Creates an Ethernet frame."""

        return struct.pack(
            "!6s6s2s",
            binascii.unhexlify(data.DST_MAC),
            binascii.unhexlify(data.SRC_MAC),
            binascii.unhexlify(data.ETH_TYP),
        )

    @staticmethod
    def create_arp_header(snd_ip, tgt_ip):
        """
        Creates an ARP header.

        :param snd_ip: Sender IP address.
        :param tgt_ip: Target IP address.
        """

        return struct.pack(
            "!2s2s1s1s2s6s4s6s4s",
            binascii.unhexlify(data.ARP_HWT),
            binascii.unhexlify(data.ARP_PRT),
            binascii.unhexlify(data.ARP_HWS),
            binascii.unhexlify(data.ARP_PRS),
            binascii.unhexlify(data.ARP_REQ),
            binascii.unhexlify(data.SND_MAC),
            socket.inet_aton(snd_ip),
            binascii.unhexlify(data.TGT_MAC),
            socket.inet_aton(tgt_ip),
        )


class ParserHandler:
    @staticmethod
    def create_arguments():
        parser = argparse.ArgumentParser(
            prog="harpy", description="- Active/passive ARP discovery tool -",
            epilog="Written by %s ( %s )" % (data.AUTHOR, data.PROJECT_URL),
        )

        parser.add_argument(
            "-a", action="version", version=parser.epilog,
            help="show program author information and exit",
        )
        parser.add_argument(
            "-c", default=data.DEF_CNT, type=int, metavar="count", dest="c",
            help="number of times to send each request (def:%%(default)s"
                 "|min:%d)" % data.MIN_CNT,
        )
        parser.add_argument(
            "-f", action="store_true", dest="f",
            help="fast mode, only scan for specific hosts",
        )
        parser.add_argument(
            "-F", action="store_true", dest="F",
            help="filter the sniff results using the given scanning range",
        )
        parser.add_argument(
            "-i", default=InterfaceHandler()(), metavar="interface", dest="i",
            help="network device to send/sniff packets",
        )
        parser.add_argument(
            "-l", action="store_true", dest="l", help="show logs and exit",
        )
        parser.add_argument(
            "-n", default=data.DEF_NOD, type=int, metavar="node", dest="n",
            help="last ip octet to be used to send packets (def:%%(default)s"
                 "|min:%d|max:%d)" % (data.MIN_NOD, data.MAX_NOD),
        )
        parser.add_argument(
            "-p", action="store_true", dest="p",
            help="passive mode, do not send any packets",
        )
        parser.add_argument(
            "-r", nargs="+", metavar="range", dest="r", help="scanning range",
        )
        parser.add_argument(
            "-s", default=data.DEF_SLP, type=int, metavar="time", dest="s",
            help="time to sleep between each request in ms (def:%%(default)s"
                 "|min:%d|max:%d)" % (data.MIN_SLP, data.MAX_SLP),
        )
        parser.add_argument(
            "-t", default=data.DEF_TIM, type=int, metavar="time", dest="t",
            help="timeout to stop scanning in sec (def:%%(default)s"
                 "|min:%d)" % data.MIN_TIM,
        )
        parser.add_argument(
            "-v", action="version", version="v" + data.VERSION,
            help="show program version and exit",
        )

        return parser.parse_args()

    @staticmethod
    def create_links(commands):
        """
        Creates shortcuts to the commands.

        :param commands: Parsed command-line arguments.
        """

        data.CNT = commands.c
        data.FST = commands.f
        data.FLT = commands.F
        data.INT = commands.i
        data.LOG = commands.l
        data.NOD = commands.n
        data.PAS = commands.p
        data.RNG = commands.r
        data.SLP = commands.s
        data.TIM = commands.t

    @staticmethod
    def check_arguments():
        return [
            ArgumentHandler.count_handler(data.CNT),
            ArgumentHandler.interface_handler(data.INT),
            ArgumentHandler.node_handler(data.NOD),
            ArgumentHandler.passive_handler(data.PAS),
            ArgumentHandler.range_handler(data.RNG),
            ArgumentHandler.sleep_handler(data.SLP),
            ArgumentHandler.timeout_handler(data.TIM),
        ] if not data.LOG else [ArgumentHandler.log_handler()]


class ResultHandler:
    def __init__(self, result):
        self.snd_ip = result[0]
        self.src_mac = result[1]
        self.snd_mac = result[2]
        self.arp_opc = result[3]

    def __call__(self, results):
        if self.snd_ip in results:
            for _ in range(0, len(results), data.CONT_STP_SIZ):
                if all([
                        self.snd_ip == results[_],
                        self.src_mac == results[_ + 1],
                        self.snd_mac == results[_ + 2],
                ]):
                    if self.arp_opc != data.ARP_REQ:
                        results[_ + 3] += 1
                    else:
                        results[_ + 4] += 1
                    return results

        results.append(self.snd_ip)  # Sender IP address
        results.append(self.src_mac)  # Source MAC address
        results.append(self.snd_mac)  # Sender MAC address
        results.append(1 if self.arp_opc != data.ARP_REQ else 0)  # Reply
        results.append(1 if self.arp_opc == data.ARP_REQ else 0)  # Request
        results.append(self.get_vendor(self.src_mac))  # Vendor

        return results

    @staticmethod
    def get_vendor(mac):
        """
        Finds a vendor using the given MAC address.

        :param mac: MAC address to find the vendor.
        """

        vendors_file = os.path.join(os.path.dirname(__file__), "ouis.json")
        if os.path.isfile(vendors_file):
            with open(vendors_file, "r") as vendors:
                try:
                    ouis = json.load(vendors)
                except json.decoder.JSONDecodeError:
                    return ""
            if mac[:6] not in ouis:
                return "unknown"
            return ouis[mac[:6]]
        return ""


class SignalHandler:
    @staticmethod
    def __call__(_signum, _frame):
        data.EXIT_MSGS.add("Exiting, received signal %d" % _signum)
        run_main(False)

    def catch(self, *signals):
        if threading.current_thread() is threading.main_thread():
            for _ in signals:
                signal.signal(_, self.__call__)

    @staticmethod
    def ignore(*signals):
        if threading.current_thread() is threading.main_thread():
            # Be sure to ignore the signals
            while True:
                try:
                    for _ in signals:
                        signal.signal(_, signal.SIG_IGN)
                    return
                except TypeError:
                    # Workaround for the _thread.interrupt_main bug
                    # ( https://bugs.python.org/issue23395 )
                    continue


class SocketHandler:
    def __init__(self, protocol):
        self.l2soc = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol)
        )  # Open a socket

    def set_options(self):
        self.l2soc.setblocking(False)  # Non-blocking mode
        self.l2soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l2soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    @ExceptionHandler(data.SOCKET)
    def bind(self, interface, port):
        """
        Binds the socket to an interface.

        :param interface: Network device to send/sniff packets.
        :param port: Port to bind to an interface.
        """

        self.l2soc.bind((interface, port))

    def close(self):
        self.l2soc.close()


class WindowHandler:
    logo = logo()
    logo_len = len(re.sub(data.RE_ANSI, "", logo[0]))
    logo_space_len = data.MAX_IP_LEN - logo_len

    def __init__(self, results):
        self.results = results

        self.banner = banner()
        self.banner_results = [
            len(list(_ for _ in range(0, len(results), data.CONT_STP_SIZ))),
            sum(results[_] for _ in range(3, len(results), data.CONT_STP_SIZ)),
            sum(results[_] for _ in range(4, len(results), data.CONT_STP_SIZ)),
        ]

        for i, _ in enumerate(self.banner_results):
            self.banner[i] += str(_)

    @ExceptionHandler()
    def __call__(self):
        for _ in range(0, len(self.results), data.CONT_STP_SIZ):
            ip_address = self.results[_]
            eth_mac_address = add_colons(self.results[_ + 1])
            arp_mac_address = add_colons(self.results[_ + 2])
            arp_rep = str(self.results[_ + 3])
            rep_space_len = data.MAX_REP_LEN - len(arp_rep)
            # Prevent column distortion
            arp_rep = data.MAX_REP_LEN * "9" if rep_space_len < 0 else arp_rep
            arp_req = str(self.results[_ + 4])
            req_space_len = data.MAX_REQ_LEN - len(arp_req)
            arp_req = data.MAX_REQ_LEN * "9" if req_space_len < 0 else arp_req
            vendor = self.results[_ + 5]

            print(ip_address.ljust(data.MAX_IP_LEN), end=" | ")
            # Suspicious packet?!
            if eth_mac_address != arp_mac_address:
                if data.ETHER_TO_ARP:
                    eth_mac_address = yellow(arp_mac_address) + "?"
                else:
                    eth_mac_address = yellow(eth_mac_address) + "?"
            print(eth_mac_address.ljust(data.MAX_MAC_LEN), end=" | ")
            print(arp_rep.ljust(data.MAX_REP_LEN), end=" | ")
            print(arp_req.ljust(data.MAX_REQ_LEN), end=" | ")
            vendor = add_dots(vendor, self.get_column_size(), data.MAX_ALL_LEN)
            print(vendor + data.RESET, flush=True)

    @staticmethod
    @ExceptionHandler()
    def get_column_size():
        return os.get_terminal_size().columns

    @ExceptionHandler()
    def draw_a_line(self):
        print(self.get_column_size() * "-", flush=True)

    @staticmethod
    @ExceptionHandler()
    def draw_row(*args):
        """
        Draw a row for the result window.

        :param args: Container that stores column texts.
        """

        for i, _ in enumerate(args):
            # Last column?
            if i == len(args) - 1:
                print(_, flush=True)
            else:
                print(_, end=" | ")

    @ExceptionHandler()
    def draw_skeleton(self):
        #################
        # Logo & Banner #
        #################
        for i, _ in enumerate(self.logo):
            print(_ + self.logo_space_len * " ", end=" | ")
            print(self.banner[i], flush=True)

        ######################
        # MAC Address Column #
        ######################
        data.ETHER_TO_ARP = not data.ETHER_TO_ARP

        ########
        # Rows #
        ########
        if data.SEND_FINISHED:
            info_col = green("Sending finished")
        elif data.SEND_ADDRESS is None:
            info_col = ""
        else:
            info_col = "Sending %s" % data.SEND_ADDRESS

        self.draw_a_line()
        self.draw_row("Exit with ^C".ljust(data.MAX_IP_LEN), info_col)
        self.draw_a_line()
        self.draw_row(
            "IP Address".ljust(data.MAX_IP_LEN),
            "MAC Address".ljust(data.MAX_MAC_LEN),
            "Reply".ljust(data.MAX_REP_LEN),
            "Request".ljust(data.MAX_REQ_LEN),
            "Vendor",
        )
        self.draw_a_line()
