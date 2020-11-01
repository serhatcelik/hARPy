# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling arguments obtained from the command-line."""

import re
import harpy.data.core as core
from harpy.data.functions import with_red
from harpy.handlers.interface_handler import InterfaceHandler


class ArgumentHandler:
    """Handler of arguments obtained from the command-line."""

    @staticmethod
    def count_handler(arg):
        """
        Check the count.

        :param arg: Number of times to send each request.
        """

        if arg < core.MIN_CNT:
            core.COMMANDS.c = core.MIN_CNT

    @staticmethod
    def interface_handler(arg):
        """
        Check the interface.

        :param arg: Network interface to send/sniff packets.
        """

        if arg is None:
            print(with_red('no carrier in, %s' % core.SYS_NET))
            return False
        if arg == 'lo':
            print(with_red('do not use lo'))
            return False
        if arg not in InterfaceHandler().members:
            print(with_red('no such network interface, %s' % arg))
            return False
        if InterfaceHandler().members[arg] != 'up':
            print(with_red('network interface is in down state, %s' % arg))
            return False
        return True

    @staticmethod
    def node_handler(arg):
        """
        Check the node.

        :param arg: Last IP octet to be used to send packets.
        """

        if not core.MIN_NOD <= arg <= core.MAX_NOD:
            core.COMMANDS.n = core.DEF_NOD

    @staticmethod
    def range_handler(arg):
        """
        Check the range.

        :param arg: Scan range, e.g. 192.168.2.1/24.
        """

        octet = '([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'  # [0, 255]
        expression = fr'^({octet}\.{octet}\.{octet}\.{octet}/(8|16|24))$'

        if not core.COMMANDS.p and not bool(re.search(expression, arg)):
            print(with_red('scan range syntax is invalid, %s' % arg))
            return False
        return True

    @staticmethod
    def sleep_handler(arg):
        """
        Check the sleep.

        :param arg: Time to sleep between each request in ms.
        """

        if arg < core.MIN_SLP:
            core.COMMANDS.s = core.MIN_SLP
        elif arg > core.MAX_SLP:
            core.COMMANDS.s = core.MAX_SLP

    @staticmethod
    def timeout_handler(arg):
        """
        Check the timeout.

        :param arg: Timeout to stop scanning in sec.
        """

        if arg < core.MIN_TIM:
            core.COMMANDS.t = core.MIN_TIM
