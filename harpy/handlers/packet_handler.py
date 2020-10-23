# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling packet creation."""

import socket
import struct
import binascii
import harpy.core.data as data


class PacketHandler:
    """Handler of packet creation."""

    @staticmethod
    def create_eth_frame(src_mac):
        """
        Create an Ethernet frame.

        :param src_mac: Source MAC address.
        """

        return struct.pack(
            '!6s6s2s',
            binascii.unhexlify(data.ETH_DST),
            binascii.unhexlify(src_mac),
            binascii.unhexlify(data.ETH_TYP)
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
            binascii.unhexlify(data.ARP_HWT),
            binascii.unhexlify(data.ARP_PRT),
            binascii.unhexlify(data.ARP_HWS),
            binascii.unhexlify(data.ARP_PRS),
            binascii.unhexlify(data.ARP_REQ),
            binascii.unhexlify(snd_mac),
            socket.inet_aton(snd_ip),
            binascii.unhexlify(data.ARP_TGT),
            socket.inet_aton(tgt_ip)
        )
