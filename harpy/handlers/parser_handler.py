# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling command-line arguments."""

import argparse
import harpy.core.data as data
from harpy.__version__ import __version__
from harpy.__author__ import __author__, __email__, __gitlink__
from harpy.handlers.argument_handler import ArgumentHandler
from harpy.handlers.interface_handler import InterfaceHandler


class ParserHandler:
    """Handler of command-line arguments."""

    @staticmethod
    def add_arguments():
        """Create new command-line arguments."""

        parser = argparse.ArgumentParser(
            prog='harpy',
            description=f'By {__author__} <{__email__}> ( {__gitlink__} )',
            epilog='Use at your own risk!'
        )
        group = parser.add_argument_group('required arguments')

        parser.add_argument(
            '-a',
            action='store_true',
            help='show program author information and exit',
            dest='a'
        )
        parser.add_argument(
            '-c',
            default=data.DEF_CNT,
            type=int,
            help='number of times to send each arp request '
                 '(default: %(default)s)',
            metavar='count',
            dest='c'
        )
        parser.add_argument(
            '-i',
            default=InterfaceHandler()(),
            help='network device to send/sniff packets',
            metavar='interface',
            dest='i'
        )
        parser.add_argument(
            '-l',
            action='store_true',
            help='show error logs and exit',
            dest='l'
        )
        parser.add_argument(
            '-n',
            default=data.DEF_NOD,
            type=int,
            help='last ip octet to be used to send packets '
                 '(default: %(default)s)',
            metavar='node',
            dest='n'
        )
        parser.add_argument(
            '-p',
            action='store_true',
            help='enable passive mode, do not send any packets',
            dest='p'
        )
        group.add_argument(
            '-r',
            required=True,
            help='scan range, e.g. 192.168.2.1/24 (valid: /8, /16, /24)',
            metavar='range',
            dest='r'
        )
        parser.add_argument(
            '-s',
            default=data.DEF_SLP,
            type=int,
            help='time to sleep between each arp request in ms '
                 '(default: %(default)s)',
            metavar='sleep',
            dest='s'
        )
        parser.add_argument(
            '-v',
            action='version',
            version=f'v{__version__}',
            help='show program version and exit'
        )

        return parser

    @staticmethod
    def check_arguments(commands):
        """
        Check if there are any errors with the command-line arguments.

        :param commands: Parsed command-line arguments.
        """

        return [
            ArgumentHandler.count_handler(commands.c),
            ArgumentHandler.interface_handler(commands.i),
            ArgumentHandler.node_handler(commands.n),
            ArgumentHandler.range_handler(commands.r),
            ArgumentHandler.sleep_handler(commands.s)
        ]
