# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the result window."""

import os
import harpy.core.data as data
from harpy.core.logo import create_logo, create_banner
from harpy.handlers.exception_handler import ExceptionHandler


class WindowHandler:
    """Handler of the result window."""

    logo = create_logo()
    logo_space_len = data.MAX_IP_LEN - vars(create_logo)['logo_len']

    @ExceptionHandler()
    def __init__(self, results):
        self.results = results

        self.banner = create_banner()
        self.banner_results = [
            len(list(_ for _ in range(0, len(results), data.MAIN_COL_NUM))),
            sum(results[_] for _ in range(3, len(results), data.MAIN_COL_NUM)),
            sum(results[_] for _ in range(4, len(results), data.MAIN_COL_NUM))
        ]

        ##########
        # BANNER #
        ##########
        for i, _ in enumerate(self.banner_results):
            self.banner[i] += str(_)

        self.term_col_len = os.get_terminal_size().columns

    @ExceptionHandler()
    def __call__(self):
        for _ in range(0, len(self.results), data.MAIN_COL_NUM):
            ip_address = self.results[_]
            ip_space_len = data.MAX_IP_LEN - len(ip_address)
            eth_mac_address = self.results[_ + 1]
            eth_mac_space_len = data.MAX_ETH_MAC_LEN - len(eth_mac_address)
            arp_mac_address = self.results[_ + 2]
            arp_mac_space_len = data.MAX_ARP_MAC_LEN - len(arp_mac_address)
            arp_request = self.results[_ + 3]
            req_space_len = data.MAX_REQ_LEN - len(str(arp_request))
            if req_space_len < 0:
                arp_request = '9' * data.MAX_REQ_LEN  # Prevent distortion
                req_space_len = data.MAX_REQ_LEN - len(str(arp_request))
            arp_reply = self.results[_ + 4]
            rep_space_len = data.MAX_REP_LEN - len(str(arp_reply))
            if rep_space_len < 0:
                arp_reply = '9' * data.MAX_REP_LEN
                rep_space_len = data.MAX_REP_LEN - len(str(arp_reply))
            vendor = self.results[_ + 5]

            # Suspicious packet?!
            if eth_mac_address != arp_mac_address:
                print(data.B_YELLOW + data.F_BLACK, end='')
            print(ip_address + ip_space_len * ' ', end=' | ')
            print(eth_mac_address + eth_mac_space_len * ' ', end=' | ')
            print(arp_mac_address + arp_mac_space_len * ' ', end=' | ')
            print(str(arp_request) + req_space_len * ' ', end=' | ')
            print(str(arp_reply) + rep_space_len * ' ', end=' | ')
            if data.MAX_ALL_LEN + len(vendor) > self.term_col_len:
                limit = self.term_col_len - data.MAX_ALL_LEN - len('...')
                vendor = vendor[0:limit] + '...'  # Shorten the result
            print(vendor + data.RESET)

    @staticmethod
    @ExceptionHandler()
    def draw_row(*args):
        """
        Draw a row for the result window.

        :param args: Container that contains column text and column length.
        """

        for col_txt, col_len in args:
            # Last column?
            if col_len < 0:
                print(col_txt)
                return
            print(col_txt + (col_len - len(col_txt)) * ' ', end=' | ')

    @ExceptionHandler()
    def draw_skeleton(self):
        """Draw the skeleton with the program logo."""

        if data.SEND_FINISHED:
            info_col = data.F_GREEN + 'SENDING FINISHED' + data.RESET
        elif data.SEND_PAUSED:
            info_col = data.F_YELLOW + 'SENDING PAUSED' + data.RESET
        else:
            if data.SEND_ADDRESS is None:
                info_col = ''  # For the first opening delay or passive mode
            else:
                info_col = 'SENDING' + ' ' + data.SEND_ADDRESS

        #################
        # LOGO & BANNER #
        #################
        for i, _ in enumerate(self.logo):
            print(_ + self.logo_space_len * ' ', end=' | ')
            print(self.banner[i])

        #######
        # ROW #
        #######
        print(self.term_col_len * '-')
        self.draw_row([r'^C / ^\ TO EXIT', data.MAX_IP_LEN], [info_col, -1])
        print(self.term_col_len * '-')
        self.draw_row(
            ['IP ADDRESS', data.MAX_IP_LEN],
            ['ETH MAC ADDRESS', data.MAX_ETH_MAC_LEN],
            ['ARP MAC ADDRESS', data.MAX_ARP_MAC_LEN],
            ['REQ.', data.MAX_REQ_LEN],
            ['REP.', data.MAX_REP_LEN],
            ['VENDOR', -1]
        )
        print(self.term_col_len * '-')
