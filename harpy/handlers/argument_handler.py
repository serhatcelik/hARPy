# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling arguments obtained from the command-line."""

import re
import harpy.core.data as data
from harpy.handlers.interface_handler import InterfaceHandler


class ArgumentHandler:
    """Handler of arguments obtained from the command-line."""

    @staticmethod
    def count_handler(arg):
        """
        Check the count.

        :param arg: Number of times to send each request.
        """

        if arg < data.LIM_CNT:
            data.COMMANDS.c = data.LIM_CNT

        return True

    @staticmethod
    def interface_handler(arg):
        """
        Check the interface.

        :param arg: Network device to send/sniff packets.
        """

        return None if arg is None or arg == 'lo' or not (
                arg in InterfaceHandler().mems and InterfaceHandler().mems[arg]
        ) else True

    @staticmethod
    def node_handler(arg):
        """
        Check the node.

        :param arg: Last IP octet to be used to send packets.
        """

        if not data.LIM_NOD[0] <= arg <= data.LIM_NOD[-1]:
            data.COMMANDS.n = data.DEF_NOD

        return True

    @staticmethod
    def range_handler(arg):
        """
        Check the range.

        :param arg: Scan range, e.g. 192.168.2.1/24.
        """

        octet = '([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'  # [0, 255]
        expression = fr'^({octet}\.{octet}\.{octet}\.{octet}/(8|16|24))$'

        return bool(re.search(expression, arg))

    @staticmethod
    def sleep_handler(arg):
        """
        Check the sleep.

        :param arg: Time to sleep between each request in ms.
        """

        if arg < data.LIM_SLP[0]:
            data.COMMANDS.s = data.LIM_SLP[0]
        elif arg > data.LIM_SLP[-1]:
            data.COMMANDS.s = data.LIM_SLP[-1]

        return True

    @staticmethod
    def timeout_handler(arg):
        """
        Check the timeout.

        :param arg: Timeout to stop scanning in sec.
        """

        if arg < data.LIM_TIM:
            data.COMMANDS.t = data.LIM_TIM

        return True
