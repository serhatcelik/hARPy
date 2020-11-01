# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the sniff thread."""

import time
import socket
import struct
import binascii
import threading
import harpy.data.core as core
import harpy.data.functions as func
from harpy.handlers.exception_handler import ExceptionHandler


class SniffThread(threading.Thread):
    """Handler of the sniff thread."""

    packet = None

    def __init__(self, l2soc):
        super().__init__()

        self.name = core.SNIFF
        self.flag = threading.Event()

        self.l2soc = l2soc

    @ExceptionHandler(core.SNIFF)
    def run(self):
        while not self.flag.is_set() and core.RUN_MAIN:
            try:
                # Receive a packet
                self.packet = self.l2soc.recv(core.SOC_BUF)
            except BlockingIOError:
                time.sleep(core.SLEEP_SNIFF)
            else:
                self.sniff()

    def sniff(self):
        """Sniff ARP packets."""

        # Ethernet frame from the packet
        eth_frame = struct.unpack('!6s6s2s', self.packet[0:14])
        eth_src_mac = binascii.hexlify(eth_frame[1]).decode('utf-8')
        # Not own MAC address?
        if eth_src_mac != core.ETH_SRC:
            eth_type = binascii.hexlify(eth_frame[2]).decode('utf-8')
            # EtherType ARP?
            if eth_type == core.ETH_TYP:
                # ARP header from the packet
                arp_header = struct.unpack(
                    '!2s2s1s1s2s6s4s6s4s', self.packet[14:42]
                )
                arp_opcode = binascii.hexlify(arp_header[4]).decode('utf-8')
                arp_snd_mac = binascii.hexlify(arp_header[5]).decode('utf-8')
                arp_snd_ip = socket.inet_ntoa(arp_header[6])

                if True in [
                        core.COMMANDS.f and func.new_ip(arp_snd_ip),
                        not core.COMMANDS.f
                ]:
                    core.SNIFF_RESULT.append(
                        [eth_src_mac, arp_opcode, arp_snd_mac, arp_snd_ip]
                    )
