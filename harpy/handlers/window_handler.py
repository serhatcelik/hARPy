# This file is part of hARPy

import os
import sys


class WindowHandler:
    max_ip_len = 15
    max_eth_mac_len = 17
    max_arp_mac_len = 17
    max_req_len = 6
    max_rep_len = 6
    total_col_len_except_vendor_col = (
        max_ip_len
        + max_eth_mac_len
        + max_arp_mac_len
        + max_req_len
        + max_rep_len
        + 5 * len(" | ")
    )

    def __init__(self, results):
        self.results = results
        self.total_host = len(list(i for i in range(0, len(results), 6)))
        self.total_request = sum(results[i] for i in range(3, len(results), 6))
        self.total_reply = sum(results[i] for i in range(4, len(results), 6))

        self.terminal_column_len = os.get_terminal_size().columns

    def __call__(self):
        for i in range(0, len(self.results), 6):
            ip_address = self.results[i]
            ip_space_len = self.max_ip_len - len(ip_address)
            eth_mac_address = self.results[i + 1]
            eth_mac_space_len = self.max_eth_mac_len - len(eth_mac_address)
            arp_mac_address = self.results[i + 2]
            arp_mac_space_len = self.max_arp_mac_len - len(arp_mac_address)
            arp_request = self.results[i + 3]
            req_space_len = self.max_req_len - len(str(arp_request))
            if req_space_len < 0:
                arp_request = float("inf")  # Prevent column distortion
                req_space_len = self.max_req_len - len(str(arp_request))
            arp_reply = self.results[i + 4]
            rep_space_len = self.max_rep_len - len(str(arp_reply))
            if rep_space_len < 0:
                arp_reply = float("inf")
                rep_space_len = self.max_rep_len - len(str(arp_reply))
            vendor = self.results[i + 5]

            if eth_mac_address != arp_mac_address:  # Suspicious packet!
                sys.stdout.write("\033[0;33m")  # Yellow color
            print(ip_address + ip_space_len * " ", end=" | ")
            print(eth_mac_address + eth_mac_space_len * " ", end=" | ")
            print(arp_mac_address + arp_mac_space_len * " ", end=" | ")
            print(str(arp_request) + req_space_len * " ", end=" | ")
            print(str(arp_reply) + rep_space_len * " ", end=" | ")
            if (self.total_col_len_except_vendor_col + len(vendor)
                    > self.terminal_column_len):
                limit = (
                    self.terminal_column_len
                    - self.total_col_len_except_vendor_col
                    - len("...")
                )
                print(vendor[0:limit] + "...\033[0m")  # Shorten the result
            else:
                print(vendor + "\033[0m")

    def draw_skeleton(self, *args):
        print(fr"|_  _  _ _      | TOTAL HOST: {self.total_host}")
        print(fr"| |(_|| |_)\/   | TOTAL REQ.: {self.total_request}")
        print(fr"        |  /    | TOTAL REP.: {self.total_reply}")
        print(self.terminal_column_len * "-")
        for column, column_len in args:
            if column_len < 0:
                print(column)  # Last column
                print(self.terminal_column_len * "-")
                break
            print(column + (column_len - len(column)) * " ", end=" | ")
