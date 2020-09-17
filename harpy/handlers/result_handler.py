# This file is part of hARPy

import os
import json
from harpy.data import constants
from harpy.data.constants import ARP_REQ


class ResultHandler:
    vendors_file = os.path.join(
        os.path.abspath(os.path.dirname(constants.__file__)), "vendors.json"
    )
    vendor = None

    def __init__(self, result, results):
        self.eth_src_mac = ":".join(
            result[0][i:i + 2] for i in range(0, len(result[0]), 2)
        )  # Add colons to the MAC address
        self.arp_opcode = result[1]
        self.arp_src_mac = ":".join(
            result[2][i:i + 2] for i in range(0, len(result[2]), 2)
        )
        self.arp_src_ip = result[-1]
        self.results = results

    def __call__(self):
        if (self.arp_src_mac in self.results
                and self.arp_src_ip in self.results):
            for i in range(0, len(self.results), 6):
                if (self.arp_src_ip == self.results[i]
                        and self.eth_src_mac == self.results[i + 1]
                        and self.arp_src_mac == self.results[i + 2]):
                    if self.arp_opcode == ARP_REQ:
                        self.results[i + 3] += 1  # ARP request count +1
                    else:
                        self.results[i + 4] += 1  # ARP reply count +1
                    return self.results
        self.results.append(self.arp_src_ip)  # IP address
        self.results.append(self.eth_src_mac)  # Ethernet MAC address
        self.results.append(self.arp_src_mac)  # ARP MAC address
        self.results.append(1 if self.arp_opcode == ARP_REQ else 0)
        self.results.append(1 if self.arp_opcode != ARP_REQ else 0)
        self.results.append(self.vendor)  # Vendor

        return self.results

    def get_mac_vendor(self, src_mac):
        if os.path.exists(self.vendors_file):
            vendors_file = open(self.vendors_file, "r")
            try:
                vendors = json.load(vendors_file)
            except json.decoder.JSONDecodeError:
                return "harpy: warning: corrupted vendors file"
            finally:
                vendors_file.close()
            if src_mac.replace(":", "")[0:6] not in vendors:
                return "unknown"
            return vendors[src_mac.replace(":", "")[0:6]]  # Find the vendor
        return "harpy: warning: no vendors file"
