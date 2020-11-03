# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the sniff result."""

import os
import json
from harpy.data import variables as core


class ResultHandler:
    """Handler of the sniff result."""

    def __init__(self, result):
        self.result = result

        self.results = core.SNIFF_ALL

        self.src_mac = self.result[0]
        self.arp_opc = self.result[1]
        self.snd_mac = self.result[2]
        self.snd_ip = self.result[-1]

    def __call__(self):
        if self.snd_mac in self.results and self.snd_ip in self.results:
            for _ in range(0, len(self.results), core.CONT_STP_NUM):
                if False not in [
                        self.snd_ip == self.results[_],
                        self.src_mac == self.results[_ + 1],
                        self.snd_mac == self.results[_ + 2]
                ]:
                    if self.arp_opc == core.ARP_REQ:
                        self.results[_ + 3] += 1
                    elif self.arp_opc == core.ARP_REP:
                        self.results[_ + 4] += 1
                    return self.results
        self.results.append(self.snd_ip)  # Sender IP address
        self.results.append(self.src_mac)  # Source MAC address
        self.results.append(self.snd_mac)  # Sender MAC address
        self.results.append(1 if self.arp_opc == core.ARP_REQ else 0)  # Req.
        self.results.append(1 if self.arp_opc == core.ARP_REP else 0)  # Rep.
        self.results.append(self.get_vendor(self.src_mac))  # Vendor

        return self.results

    @staticmethod
    def get_vendor(src_mac):
        """
        Find a vendor using a source MAC address.

        :param src_mac: Source MAC Address.
        """

        if os.path.exists(core.VENDORS_FILE):
            with open(core.VENDORS_FILE, 'r') as vendors_file:
                try:
                    vendors = json.load(vendors_file)
                except json.decoder.JSONDecodeError:
                    return ':('
            if src_mac[0:6] not in vendors:
                return 'unknown'
            return vendors[src_mac[0:6]]
        return ':(('
