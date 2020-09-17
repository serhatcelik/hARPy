# This file is part of hARPy

import os
import time
import signal
import socket
import struct
import binascii
from harpy.data.constants import SOC_BUF
from harpy.data.constants import ETH_DST, ETH_TYP
from harpy.data.constants import (
    ARP_HWT, ARP_PRT, ARP_HWS, ARP_PRS, ARP_REQ, ARP_DST
)


class PacketHandler:
    def __init__(self, raw_socket, own_src_mac, rng):
        self.raw_socket = raw_socket
        self.own_src_mac = own_src_mac
        self.rng = [
            rng.split(".")[0],
            rng.split(".")[1],
            rng.split(".")[2],
            rng.split(".")[-1].split("/")[0],
            rng.split(".")[-1].split("/")[-1]
        ]

    def create(self, src_ip, dst_ip):
        ethernet_frame = struct.pack(
            "!6s6s2s",
            binascii.unhexlify(ETH_DST),
            binascii.unhexlify(self.own_src_mac),
            binascii.unhexlify(ETH_TYP)
        )  # Create an Ethernet frame

        arp_header = struct.pack(
            "!2s2s1s1s2s6s4s6s4s",
            binascii.unhexlify(ARP_HWT),
            binascii.unhexlify(ARP_PRT),
            binascii.unhexlify(ARP_HWS),
            binascii.unhexlify(ARP_PRS),
            binascii.unhexlify(ARP_REQ),
            binascii.unhexlify(self.own_src_mac),
            socket.inet_aton(src_ip),
            binascii.unhexlify(ARP_DST),
            socket.inet_aton(dst_ip)
        )  # Create an ARP header

        return ethernet_frame + arp_header  # Create a packet

    def send(self, count, src_node, sleep):
        if self.rng[-1] == "24":
            first_ip = ".".join([self.rng[0], self.rng[1], self.rng[2], "1"])
            last_ip = ".".join([self.rng[0], self.rng[1], self.rng[2], "254"])
        elif self.rng[-1] == "16":
            first_ip = ".".join([self.rng[0], self.rng[1], "0", "1"])
            last_ip = ".".join([self.rng[0], self.rng[1], "255", "254"])
        else:
            first_ip = ".".join([self.rng[0], "0", "0", "1"])
            last_ip = ".".join([self.rng[0], "255", "255", "254"])

        start = struct.unpack("!I", socket.inet_aton(first_ip))[0]
        stop = struct.unpack("!I", socket.inet_aton(last_ip))[0]
        for i in range(start, stop + 1):
            dst_ip = socket.inet_ntoa(struct.pack("!I", i))
            new_count = count  # Restore the original value at every step
            while new_count > 0:
                if int(dst_ip.split(".")[-1]) != src_node:
                    src_ip = ".".join(dst_ip.split(".")[0:3] + [str(src_node)])
                else:  # Prevent sending gratuitous ARP request
                    src_ip = ".".join(dst_ip.split(".")[0:3] + ["0"])

                try:
                    self.raw_socket.send(
                        self.create(src_ip=src_ip, dst_ip=dst_ip)
                    )  # Create a packet
                except OSError as err:
                    if err.errno == 100:  # 100: Network is down
                        print(
                            "\nsend: error: network is down, sending signal 2"
                        )
                        os.kill(os.getpid(), signal.SIGINT)
                time.sleep(sleep / 1000)
                new_count -= 1

    def sniff(self):
        try:
            packet = self.raw_socket.recvfrom(SOC_BUF)  # Capture a packet
        except OSError as err:
            if err.errno == 100:  # 100: Network is down
                print("\nsniff: error: network is down, sending signal 2")
                os.kill(os.getpid(), signal.SIGINT)
            return None

        ethernet_frame = struct.unpack(
            "!6s6s2s", packet[0][0:14]
        )  # Ethernet frame from the packet

        eth_src_mac = binascii.hexlify(ethernet_frame[1]).decode("utf-8")
        if eth_src_mac != self.own_src_mac:  # Ignore your own MAC address
            eth_type = binascii.hexlify(ethernet_frame[2]).decode("utf-8")
            if eth_type == ETH_TYP:  # Is EtherType ARP?

                arp_header = struct.unpack(
                    "!2s2s1s1s2s6s4s6s4s", packet[0][14:42]
                )  # ARP header from the packet

                arp_opcode = binascii.hexlify(arp_header[4]).decode("utf-8")
                arp_src_mac = binascii.hexlify(arp_header[5]).decode("utf-8")
                arp_src_ip = socket.inet_ntoa(arp_header[6])
                if (self.rng[-1] == "24"
                        and arp_src_ip.split(".")[0:3] == self.rng[0:3]):
                    return [eth_src_mac, arp_opcode, arp_src_mac, arp_src_ip]
                if (self.rng[-1] == "16"
                        and arp_src_ip.split(".")[0:2] == self.rng[0:2]):
                    return [eth_src_mac, arp_opcode, arp_src_mac, arp_src_ip]
                if (self.rng[-1] == "8"
                        and arp_src_ip.split(".")[0:1] == self.rng[0:1]):
                    return [eth_src_mac, arp_opcode, arp_src_mac, arp_src_ip]
        return None
