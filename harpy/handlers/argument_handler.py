# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling arguments obtained from the command-line."""

import re
from harpy.data import variables as core
from harpy.data import functions as func
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

        :param arg: Network device to send/sniff packets.
        """

        if arg is None:
            print(func.with_red('no carrier in, %s' % core.SYS_NET))
            return False
        if arg == 'lo':
            print(func.with_red('do not use lo as an interface'))
            return False
        if arg not in InterfaceHandler().members:
            print(func.with_red('no such interface, %s' % arg))
            return False
        if InterfaceHandler().members[arg] == 'down':
            print(func.with_red('interface is in down state, %s' % arg))
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

        :param arg: Scanning range, e.g. 192.168.1.1/24.
        """

        octet = '([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'  # [0, 255]
        regex = fr'^({octet}\.{octet}\.{octet}\.{octet}/(8|16|24))$'

        if core.COMMANDS.r is not None and not bool(re.search(regex, arg)):
            print(func.with_red('incorrect scanning range, %s' % arg))
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
