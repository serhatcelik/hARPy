# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling arguments obtained from the command-line."""

import re
import harpy.core.data as data
from harpy.core.data import with_red
from harpy.handlers.interface_handler import InterfaceHandler


class ArgumentHandler:
    """Handler of arguments obtained from the command-line."""

    @staticmethod
    def count_handler(arg):
        """
        Return True or False while keeping the current count value.

        :param arg: Number of times to send each ARP request.
        """

        if arg <= data.LIM_CNT:
            print(with_red(f'{data.ERR_COUNT} expected an int greater than '
                           f'{data.LIM_CNT}, not {arg}'))
            return False
        return True

    @staticmethod
    def interface_handler(arg):
        """
        Return True or False while keeping the current interface value.

        :param arg: Network device to send/sniff packets.
        """

        if arg is None:
            print(with_red(f'{data.ERR_INTERFACE} no up interface found in, '
                           f'{data.SYS_PATH}'))
            return False
        if arg not in InterfaceHandler().members:
            print(with_red(f'{data.ERR_INTERFACE} no such interface, {arg}'))
            return False
        if not InterfaceHandler().members[arg]:
            print(with_red(
                f'{data.ERR_INTERFACE} interface cannot be used, {arg}'))
            return False
        return True

    @staticmethod
    def node_handler(arg):
        """
        Return True or False while keeping the current node value.

        :param arg: Last IP octet to be used to send packets.
        """

        if not data.LIM_NOD[0] <= arg <= data.LIM_NOD[1]:
            print(with_red(
                f'{data.ERR_NODE} expected an int between '
                f'{data.LIM_NOD[0]} and {data.LIM_NOD[1]}, not {arg}'))
            return False
        return True

    @staticmethod
    def range_handler(arg):
        """
        Return True or False while keeping the current range value.

        :param arg: Scan range, e.g. 192.168.2.1/24.
        """

        octet = '([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'  # [0, 255]
        expression = fr'^({octet}\.{octet}\.{octet}\.{octet}/(8|16|24))$'
        if not re.search(expression, arg):
            print(with_red(
                f'{data.ERR_RANGE} provided an invalid syntax, {arg}'))
            return False
        return True

    @staticmethod
    def sleep_handler(arg):
        """
        Return True or False while keeping the current sleep value.

        :param arg: Time to sleep between each ARP request in ms.
        """

        if arg <= data.LIM_SLP:
            print(with_red(f'{data.ERR_SLEEP} expected an int greater than '
                           f'{data.LIM_SLP}, not {arg}'))
            return False
        return True
