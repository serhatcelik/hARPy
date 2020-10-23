# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling sniff result."""

import os
import json
import harpy.core.data as data


class ResultHandler:
    """Handler of sniff result."""

    vendor = None

    def __init__(self, result, results):
        # Add colons to the MAC address
        self.eth_src_mac = ':'.join(
            result[0][_:_ + 2] for _ in range(0, len(result[0]), 2)
        )
        self.arp_opcode = result[1]
        self.arp_snd_mac = ':'.join(
            result[2][_:_ + 2] for _ in range(0, len(result[2]), 2)
        )
        self.arp_snd_ip = result[3]
        self.results = results

    def __call__(self):
        if False not in [
            self.arp_snd_mac in self.results, self.arp_snd_ip in self.results
        ]:
            for _ in range(0, len(self.results), data.MAIN_COL_NUM):
                if False not in [
                    self.arp_snd_ip == self.results[_],
                    self.eth_src_mac == self.results[_ + 1],
                    self.arp_snd_mac == self.results[_ + 2]
                ]:
                    if self.arp_opcode == data.ARP_REQ:
                        self.results[_ + 3] += 1  # ARP request count
                    else:
                        self.results[_ + 4] += 1  # ARP reply count
                    return self.results
        self.results.append(self.arp_snd_ip)  # Sender IP address
        self.results.append(self.eth_src_mac)  # Source MAC address
        self.results.append(self.arp_snd_mac)  # Sender MAC address
        self.results.append(1 if self.arp_opcode == data.ARP_REQ else 0)
        self.results.append(1 if self.arp_opcode != data.ARP_REQ else 0)
        self.results.append(self.vendor)  # OUI

        return self.results

    @staticmethod
    def get_vendor(src_mac):
        """
        Find a vendor using a source MAC address.

        :param src_mac: Source MAC Address.
        """

        if os.path.exists(data.VENDORS_FILE):
            with open(data.VENDORS_FILE, 'r') as vendors_file:
                try:
                    vendors = json.load(vendors_file)
                except json.decoder.JSONDecodeError:
                    return ':(('
            if src_mac.replace(':', '')[0:6] not in vendors:
                return 'unknown'
            return vendors[src_mac.replace(':', '')[0:6]]
        return ':('
