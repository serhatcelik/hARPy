# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling result window."""

import os
import harpy.core.data as data
from harpy.core.data import with_green
from harpy.core.logo import create_logo, create_banner


class WindowHandler:
    """Handler of result window."""

    logo = create_logo()

    def __init__(self, results):
        self.results = results

        self.banner = create_banner()
        self.banner_results = [
            len(list(_ for _ in range(0, len(results), data.MAIN_COL_NUM))),
            sum(results[_] for _ in range(3, len(results), data.MAIN_COL_NUM)),
            sum(results[_] for _ in range(4, len(results), data.MAIN_COL_NUM))
        ]

        # Update banner results
        for i, _ in enumerate(self.banner_results):
            self.banner[i] += str(_)

        self.term_col_len = os.get_terminal_size().columns

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
                arp_request = float('inf')  # Prevent column distortion
                req_space_len = data.MAX_REQ_LEN - len(str(arp_request))
            arp_reply = self.results[_ + 4]
            rep_space_len = data.MAX_REP_LEN - len(str(arp_reply))
            if rep_space_len < 0:
                arp_reply = float('inf')
                rep_space_len = data.MAX_REP_LEN - len(str(arp_reply))
            vendor = self.results[_ + 5]

            # Suspicious packet?!
            if eth_mac_address != arp_mac_address:
                print(data.BG_YELLOW + data.FG_BLACK, end='')
            print(ip_address + ip_space_len * ' ', end=' | ')
            print(eth_mac_address + eth_mac_space_len * ' ', end=' | ')
            print(arp_mac_address + arp_mac_space_len * ' ', end=' | ')
            print(str(arp_request) + req_space_len * ' ', end=' | ')
            print(str(arp_reply) + rep_space_len * ' ', end=' | ')
            if data.MAX_ALL_LEN + len(vendor) > self.term_col_len:
                limit = self.term_col_len - data.MAX_ALL_LEN - len('...')
                # Shorten the result
                print(vendor[0:limit] + f'...{data.RESET}')
            else:
                print(vendor + data.RESET)

    def create_skeleton(self, *args):
        """
        Create a skeleton for result window.

        :param args: Container that contains column text and column length.
        """

        for col_txt, col_len in args:
            # Last column?
            if col_len < 0:
                print(col_txt)
                print(self.term_col_len * '-')
                return
            print(col_txt + (col_len - len(col_txt)) * ' ', end=' | ')

    def draw_skeleton(self):
        """Draw the skeleton with the program logo."""

        if not data.SENDING_FINISHED:
            if data.SENDING_ADDRESS is None:
                # For the first opening delay or passive mode
                info_col = ''
            else:
                info_col = f'SENDING: {data.SENDING_ADDRESS}'
        else:
            info_col = with_green('SENDING FINISHED')

        for i, _ in enumerate(self.logo):
            print(_ + (data.MAX_IP_LEN - len(_)) * ' ', end=' | ')
            print(self.banner[i])
        print(self.term_col_len * '-')
        self.create_skeleton(
            [r'^C / ^\ TO EXIT', data.MAX_IP_LEN],
            [info_col, -1]
        )
        self.create_skeleton(
            ['IP ADDRESS', data.MAX_IP_LEN],
            ['ETH MAC ADDRESS', data.MAX_ETH_MAC_LEN],
            ['ARP MAC ADDRESS', data.MAX_ARP_MAC_LEN],
            ['REQ.', data.MAX_REQ_LEN],
            ['REP.', data.MAX_REP_LEN],
            ['VENDOR', -1]
        )
