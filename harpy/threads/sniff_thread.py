# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling sniff thread."""

import select
import socket
import struct
import binascii
import threading
import harpy.core.data as data


class SniffThread(threading.Thread):
    """Handler of sniff thread."""

    def __init__(self, raw_soc):
        super().__init__()
        self.name = 'Thread-Sniff'

        self.raw_soc = raw_soc

        self.rng = data.COMMANDS.r
        self.flag = threading.Event()

    def run(self):
        while not self.flag.is_set() and data.RUN_HARPY:
            try:
                # No socket?
                if self.raw_soc.fileno == -1:
                    raise OSError
                # Set a timeout
                if select.select([self.raw_soc], [], [], 0.25)[0]:
                    self.sniff()
            except OSError as err:
                if data.oserror_handler(err=err, who=data.ERR_SNIFF) is None:
                    raise

    def sniff(self):
        """Sniff ARP packets."""

        packet = self.raw_soc.recvfrom(data.SOC_BUF)  # Capture a packet

        # Ethernet frame from the packet
        ethernet_frame = struct.unpack('!6s6s2s', packet[0][0:14])
        eth_src_mac = binascii.hexlify(ethernet_frame[1]).decode('utf-8')
        # Own MAC address?
        if eth_src_mac != data.ETH_SRC:
            eth_type = binascii.hexlify(ethernet_frame[2]).decode('utf-8')
            # EtherType ARP?
            if eth_type == data.ETH_TYP:
                # ARP header from the packet
                arp_header = struct.unpack(
                    '!2s2s1s1s2s6s4s6s4s', packet[0][14:42]
                )
                arp_opcode = binascii.hexlify(arp_header[4]).decode('utf-8')
                arp_snd_mac = binascii.hexlify(arp_header[5]).decode('utf-8')
                arp_snd_ip = socket.inet_ntoa(arp_header[6])
                for _ in [
                    [
                        self.rng[-1] == '24',
                        arp_snd_ip.split('.')[0:3] == self.rng[0:3]
                    ],
                    [
                        self.rng[-1] == '16',
                        arp_snd_ip.split('.')[0:2] == self.rng[0:2]
                    ],
                    [
                        self.rng[-1] == '8',
                        arp_snd_ip.split('.')[0:1] == self.rng[0:1]
                    ]
                ]:
                    if False not in _:
                        data.SNIFF_RESULT.append(
                            [eth_src_mac, arp_opcode, arp_snd_mac, arp_snd_ip]
                        )
                        break
