# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling packets."""

import socket
import struct
import binascii
import harpy.data.core as core


class PacketHandler:
    """Handler of packets."""

    @staticmethod
    def create_eth_frame(src_mac):
        """
        Create an Ethernet frame.

        :param src_mac: Source MAC address.
        """

        return struct.pack(
            '!6s6s2s',
            binascii.unhexlify(core.ETH_DST),
            binascii.unhexlify(src_mac),
            binascii.unhexlify(core.ETH_TYP)
        )

    @staticmethod
    def create_arp_header(snd_mac, snd_ip, tgt_ip):
        """
        Create an ARP header.

        :param snd_mac: Sender MAC address.
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
            binascii.unhexlify(snd_mac),
            socket.inet_aton(snd_ip),
            binascii.unhexlify(core.ARP_TGT),
            socket.inet_aton(tgt_ip)
        )
