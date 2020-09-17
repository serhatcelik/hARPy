# This file is part of hARPy

import sys
import argparse
from harpy.__version__ import __version__
from harpy.handlers.argument_handler import ArgumentHandler
from harpy.handlers.interface_handler import InterfaceHandler


class ParserHandler:
    @staticmethod
    def add_arguments():
        parser = argparse.ArgumentParser(
            prog="harpy",
            description="Written by Serhat Celik <prjctsrht@gmail.com>",
            epilog="Use at your own risk!"
        )
        group = parser.add_argument_group("required arguments")

        parser.add_argument(
            "-c",
            default=1,
            type=int,
            help="number of times to send each arp request "
                 "(default: %(default)s)",
            metavar="count",
            dest="c"
        )
        parser.add_argument(
            "-i",
            default=InterfaceHandler()(),
            help="the network device to send/sniff packets "
                 "(default: first available)",
            metavar="interface",
            dest="i"
        )
        parser.add_argument(
            "-n",
            default=43,
            type=int,
            help="last ip octet to be used to send packets "
                 "(default: %(default)s)",
            metavar="node",
            dest="n"
        )
        parser.add_argument(
            "-p",
            action="store_true",
            help="enable passive mode, do not send any packets",
            dest="p"
        )
        group.add_argument(
            "-r",
            required=True,
            help="scan a given range, e.g. 192.168.2.1/24 "
                 "(valid: /8, /16, /24)",
            metavar="range",
            dest="r"
        )
        parser.add_argument(
            "-s",
            default=3,
            type=int,
            help="time to sleep between each arp request in ms "
                 "(default: %(default)s)",
            metavar="sleep",
            dest="s"
        )
        parser.add_argument(
            "-v",
            action="version",
            version=f"v{__version__}",
            help="show program version and exit"
        )

        return parser

    @staticmethod
    def check_arguments(commands):
        if False in [
                ArgumentHandler.count_handler(arg=commands.c),
                ArgumentHandler.interface_handler(arg=commands.i),
                ArgumentHandler.node_handler(arg=commands.n),
                ArgumentHandler.range_handler(arg=commands.r),
                ArgumentHandler.sleep_handler(arg=commands.s)
        ]:  # Check if there are any errors with the arguments
            sys.exit(1)
