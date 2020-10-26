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
            prog=data.HARPY, epilog='Use at your own risk!',
            description=f'By {__author__} <{__email__}> ( {__gitlink__} )',
        )

        group = parser.add_argument_group('required arguments')

        parser.add_argument(
            '-a', '--author', action='version', version=parser.description,
            help='show program author information and exit'
        )
        parser.add_argument(
            '-c', default=data.DEF_CNT, type=int, metavar='count', dest='c',
            help='number of times to send each request (def: %(default)s, '
                 f'min: {data.LIM_CNT})'
        )
        parser.add_argument(
            '-i', default=InterfaceHandler()(), metavar='interface', dest='i',
            help='network device to send/sniff packets'
        )
        parser.add_argument(
            '-l', '--log', action='version', version=data.LOG_FILE,
            help='show the location of log file and exit'
        )
        parser.add_argument(
            '-n', default=data.DEF_NOD, type=int, metavar='node', dest='n',
            help='last ip octet to be used to send packets (def: %(default)s, '
                 f'min: {data.LIM_NOD[0]}, max: {data.LIM_NOD[-1]})'
        )
        parser.add_argument(
            '-p', '--passive', action='store_true', dest='p',
            help='enable passive mode, do not send any packets'
        )
        group.add_argument(
            '-r', required=True, metavar='range', dest='r',
            help='scan range, e.g. 192.168.2.1/24 (valid: /8, /16, /24)'
        )
        parser.add_argument(
            '-s', default=data.DEF_SLP, type=int, metavar='sleep', dest='s',
            help='time to sleep between each request in ms (def: %(default)s, '
                 f'min: {data.LIM_SLP[0]}, max: {data.LIM_SLP[-1]})'
        )
        parser.add_argument(
            '-t', default=data.DEF_TIM, type=int, metavar='timeout', dest='t',
            help='timeout to stop scanning in sec (def: %(default)s, '
                 f'min: {data.LIM_TIM})'
        )
        parser.add_argument(
            '-v', '--version', action='version', version='v' + __version__,
            help='show program version and exit'
        )

        return parser

    @staticmethod
    def check_arguments(commands):
        """
        Check the command-line arguments.

        :param commands: Parsed command-line arguments.
        """

        return [
            ArgumentHandler.count_handler(commands.c),
            ArgumentHandler.interface_handler(commands.i),
            ArgumentHandler.node_handler(commands.n),
            ArgumentHandler.range_handler(commands.r),
            ArgumentHandler.sleep_handler(commands.s),
            ArgumentHandler.timeout_handler(commands.t)
        ]
