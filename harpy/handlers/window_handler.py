# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the result window."""

import os
import re
from harpy.data import variables as core
from harpy.data import functions as func
from harpy.data.logo import create_logo, create_banner
from harpy.handlers.exception_handler import ExceptionHandler


class WindowHandler:
    """Handler of the result window."""

    logo = create_logo()
    logo_len = len(re.sub(core.ANSI_REGEX, '', logo[0]))
    logo_space_len = core.MAX_IP_LEN - logo_len

    def __init__(self, results):
        self.results = results

        self.banner = create_banner()
        self.banner_results = [
            len(list(_ for _ in range(0, len(results), core.CONT_STP_NUM))),
            sum(results[_] for _ in range(3, len(results), core.CONT_STP_NUM)),
            sum(results[_] for _ in range(4, len(results), core.CONT_STP_NUM))
        ]

        for i, _ in enumerate(self.banner_results):
            self.banner[i] += str(_)

        self.pas = core.COMMANDS.p

    @ExceptionHandler()
    def __call__(self):
        for _ in range(0, len(self.results), core.CONT_STP_NUM):
            ip_address = self.results[_]
            eth_mac_address = func.with_colon(self.results[_ + 1])
            arp_mac_address = func.with_colon(self.results[_ + 2])
            arp_req = self.results[_ + 3]
            req_space_len = core.MAX_REQ_LEN - len(str(arp_req))
            arp_req = core.MAX_REQ_LEN * '9' if req_space_len < 0 else arp_req
            arp_rep = self.results[_ + 4]
            rep_space_len = core.MAX_REP_LEN - len(str(arp_rep))
            arp_rep = core.MAX_REP_LEN * '9' if rep_space_len < 0 else arp_rep
            vendor = self.results[_ + 5]

            # Suspicious packet?!
            if eth_mac_address != arp_mac_address:
                if core.ETHER_TO_ARP:
                    eth_mac_address = arp_mac_address + '?'
                else:
                    eth_mac_address += '?'
                print(core.BG_YELLOW + core.BLACK, end='')
            print(ip_address.ljust(core.MAX_IP_LEN), end=' | ')
            print(eth_mac_address.ljust(core.MAX_MAC_LEN), end=' | ')
            print(str(arp_req).ljust(core.MAX_REQ_LEN), end=' | ')
            print(str(arp_rep).ljust(core.MAX_REP_LEN), end=' | ')
            vendor = func.with_dot(
                text=vendor,
                width=os.get_terminal_size().columns,
                xref=core.MAX_ALL_LEN
            )
            print(vendor + core.RESET, flush=True)

    @staticmethod
    @ExceptionHandler()
    def draw_line():
        """Draw a horizontal line for the result window."""

        print(os.get_terminal_size().columns * '-')

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
                print(_, end=' | ')

    @ExceptionHandler()
    def draw_skeleton(self):
        """Draw the skeleton with the program logo."""

        #################
        # LOGO & BANNER #
        #################
        for i, _ in enumerate(self.logo):
            print(_ + self.logo_space_len * ' ', end=' | ')
            print(self.banner[i], flush=True)

        ######################
        # INFORMATION COLUMN #
        ######################
        if self.pas:
            info_col = 'PASSIVE MODE'
        elif core.SEND_FINISHED:
            info_col = func.with_green('SENDING FINISHED')
        else:
            info_col = 'SENDING' + ' ' + core.SEND_ADDRESS

        ########
        # ROWS #
        ########
        self.draw_line()
        self.draw_row(r'^C / ^\ TO EXIT'.ljust(core.MAX_IP_LEN), info_col)
        self.draw_line()
        self.draw_row(
            'IP ADDRESS'.ljust(core.MAX_IP_LEN),
            'MAC ADDRESS'.ljust(core.MAX_MAC_LEN),
            'REQ.'.ljust(core.MAX_REQ_LEN),
            'REP.'.ljust(core.MAX_REP_LEN),
            'VENDOR'
        )
        self.draw_line()

        ################################
        # ETHERNET COLUMN / ARP COLUMN #
        ################################
        core.ETHER_TO_ARP = not core.ETHER_TO_ARP
