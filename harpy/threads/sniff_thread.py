# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the sniff thread."""

import time
import socket
import struct
import binascii
import threading
from harpy.data import variables as core
from harpy.data import functions as func
from harpy.handlers.exception_handler import ExceptionHandler


class SniffThread(threading.Thread):
    """Handler of the sniff thread."""

    packet = None

    def __init__(self, l2soc):
        super().__init__()

        self.l2soc = l2soc

        self.name = core.SNIFF
        self.flag = threading.Event()

        self.fil = core.COMMANDS.f

    @ExceptionHandler(core.SNIFF)
    def run(self):
        while not self.flag.is_set() and core.RUN_MAIN:
            try:
                self.packet = self.l2soc.recv(core.SOC_BUF)  # Receive a packet
            except BlockingIOError:
                time.sleep(core.SLEEP_SNIFF)
            else:
                self.sniff()

    def sniff(self):
        """Sniff ARP packets."""

        # Ethernet frame from the packet
        eth_frame = struct.unpack('!6s6s2s', self.packet[0:14])
        src_mac = binascii.hexlify(eth_frame[1]).decode('utf-8')
        # Not own MAC address?
        if src_mac != core.SRC_MAC:
            eth_typ = binascii.hexlify(eth_frame[2]).decode('utf-8')
            # EtherType ARP?
            if eth_typ == core.ETH_TYP:
                # ARP header from the packet
                arp_header = struct.unpack(
                    '!2s2s1s1s2s6s4s6s4s', self.packet[14:42]
                )
                arp_opc = binascii.hexlify(arp_header[4]).decode('utf-8')
                snd_mac = binascii.hexlify(arp_header[5]).decode('utf-8')
                snd_ip = socket.inet_ntoa(arp_header[6])

                if not self.fil or self.fil and func.check_ip(snd_ip):
                    core.SNIFF_A.append([src_mac, arp_opc, snd_mac, snd_ip])
