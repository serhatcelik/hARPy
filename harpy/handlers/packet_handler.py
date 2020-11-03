# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling packets."""

import socket
import struct
import binascii
from harpy.data import variables as core


class PacketHandler:
    """Handler of packets."""

    @staticmethod
    def create_eth_frame():
        """Create an Ethernet frame."""

        return struct.pack(
            '!6s6s2s',
            binascii.unhexlify(core.DST_MAC),
            binascii.unhexlify(core.SRC_MAC),
            binascii.unhexlify(core.ETH_TYP)
        )

    @staticmethod
    def create_arp_header(snd_ip, tgt_ip):
        """
        Create an ARP header.

        :param snd_ip: Sender IP address.
        :param tgt_ip: Target IP address.
        """

        return struct.pack(
            '!2s2s1s1s2s6s4s6s4s',
            binascii.unhexlify(core.ARP_HWT),
            binascii.unhexlify(core.ARP_PRT),
            binascii.unhexlify(core.ARP_HWS),
            binascii.unhexlify(core.ARP_PRS),
            binascii.unhexlify(core.ARP_REQ),
            binascii.unhexlify(core.SND_MAC),
            socket.inet_aton(snd_ip),
            binascii.unhexlify(core.TGT_MAC),
            socket.inet_aton(tgt_ip)
        )
