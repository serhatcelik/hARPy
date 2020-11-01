# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the result window."""

import os
import harpy.data.core as core
import harpy.data.functions as func
from harpy.data.logo import create_logo, create_banner
from harpy.handlers.exception_handler import ExceptionHandler


class WindowHandler:
    """Handler of the result window."""

    logo = create_logo()
    logo_space_len = core.MAX_IP_LEN - vars(create_logo)['logo_len']

    def __init__(self, results):
        self.results = results

        self.banner = create_banner()
        self.banner_results = [
            len(list(_ for _ in range(0, len(results), core.CONT_STP_NUM))),
            sum(results[_] for _ in range(3, len(results), core.CONT_STP_NUM)),
            sum(results[_] for _ in range(4, len(results), core.CONT_STP_NUM))
        ]

        ##########
        # BANNER #
        ##########
        for i, _ in enumerate(self.banner_results):
            self.banner[i] += str(_)

        ##########################################
        # ETHERNET MAC ADDRESS & ARP MAC ADDRESS #
        ##########################################
        core.CHANGE_TO_ARP = not core.CHANGE_TO_ARP

    @ExceptionHandler()
    def __call__(self):
        for _ in range(0, len(self.results), core.CONT_STP_NUM):
            ip_address = self.results[_]
            eth_mac_address = self.results[_ + 1]
            arp_mac_address = self.results[_ + 2]
            arp_request = self.results[_ + 3]
            req_space_len = core.MAX_REQ_LEN - len(str(arp_request))
            if req_space_len < 0:
                arp_request = core.MAX_REQ_LEN * '9'  # Prevent distortion
            arp_reply = self.results[_ + 4]
            rep_space_len = core.MAX_REP_LEN - len(str(arp_reply))
            if rep_space_len < 0:
                arp_reply = core.MAX_REP_LEN * '9'
            vendor = self.results[_ + 5]

            # Suspicious packet?!
            if eth_mac_address != arp_mac_address:
                if core.CHANGE_TO_ARP:
                    eth_mac_address += '?'
                else:
                    eth_mac_address = arp_mac_address + '?'
                print(core.BG_YELLOW + core.BLACK, end='')
            print(ip_address.ljust(core.MAX_IP_LEN), end=' | ')
            print(eth_mac_address.ljust(core.MAX_MAC_LEN), end=' | ')
            print(str(arp_request).ljust(core.MAX_REQ_LEN), end=' | ')
            print(str(arp_reply).ljust(core.MAX_REP_LEN), end=' | ')
            vendor = func.with_dot(
                text=vendor,
                width=os.get_terminal_size().columns,
                xref=core.MAX_ALL_LEN
            )
            print(vendor + core.RESET)

    @staticmethod
    @ExceptionHandler()
    def draw_line():
        """Draw a horizontal line for the result window. """

        print(os.get_terminal_size().columns * '-')

    @staticmethod
    @ExceptionHandler()
    def draw_row(*args):
        """
        Draw a row for the result window.

        :param args: Container that contains column texts.
        """

        for _ in args:
            # Last column?
            if len(_) > 1:
                print(_[0])
                return
            print(_[0], end=' | ')

    @ExceptionHandler()
    def draw_skeleton(self):
        """Draw the skeleton with the program logo."""

        if core.COMMANDS.p:
            info_col = 'PASSIVE MODE'
        elif core.SEND_FINISHED:
            info_col = core.GREEN + 'SENDING FINISHED' + core.RESET
        else:
            info_col = 'SENDING' + ' ' + core.SEND_ADDRESS

        #################
        # LOGO & BANNER #
        #################
        for i, _ in enumerate(self.logo):
            print(_ + self.logo_space_len * ' ', end=' | ')
            print(self.banner[i])

        #######
        # ROW #
        #######
        self.draw_line()
        self.draw_row(
            ['PRESS ^C TO EXIT'.ljust(core.MAX_IP_LEN)],
            [info_col, None]
        )
        self.draw_line()
        self.draw_row(
            ['IP ADDRESS'.ljust(core.MAX_IP_LEN)],
            ['MAC ADDRESS'.ljust(core.MAX_MAC_LEN)],
            ['REQ.'.ljust(core.MAX_REQ_LEN)],
            ['REP.'.ljust(core.MAX_REP_LEN)],
            ['VENDOR', None]
        )
        self.draw_line()
