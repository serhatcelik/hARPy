# This file is part of harpy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global thread classes to control external modules."""

import socket
import struct
import binascii
import threading
from harpy import data
from harpy.data import check_ip
from harpy.handlers import ExceptionHandler, PacketHandler


class SendThread(threading.Thread):
    def __init__(self, l2soc):
        self.l2soc = l2soc

        super().__init__()
        self.flag = threading.Event()

    def run(self):
        for _ in data.RNG:
            if self.flag.is_set():
                return
            self.send(_)

        data.SEND_FINISHED = True

    @ExceptionHandler(data.SEND)
    def send(self, range_):
        if range_[-1] == "24":
            first_ip = ".".join([range_[0], range_[1], range_[2], "1"])
            last_ip = ".".join([range_[0], range_[1], range_[2], "254"])
        elif range_[-1] == "16":
            first_ip = ".".join([range_[0], range_[1], "0", "1"])
            last_ip = ".".join([range_[0], range_[1], "255", "254"])
        else:
            first_ip = ".".join([range_[0], "0", "0", "1"])
            last_ip = ".".join([range_[0], "255", "255", "254"])

        start = struct.unpack("!I", socket.inet_aton(first_ip))[0]
        stop = struct.unpack("!I", socket.inet_aton(last_ip))[0]

        for _ in range(start, stop + 1):
            if self.flag.is_set():
                return

            tgt_ip = socket.inet_ntoa(struct.pack("!I", _))
            if data.FST and int(tgt_ip.split(".")[3]) not in data.SEND_FAST:
                continue
            data.SEND_ADDRESS = tgt_ip

            new_count = data.CNT  # Restore the original at every step
            while not self.flag.is_set() and new_count > 0:
                # Gratuitous ARP?
                if tgt_ip.split(".")[3] == str(data.NOD):
                    snd_ip = ".".join(tgt_ip.split(".")[:3] + ["0"])
                else:
                    snd_ip = ".".join(tgt_ip.split(".")[:3] + [str(data.NOD)])

                eth_frame = PacketHandler.create_eth_frame()
                arp_header = PacketHandler.create_arp_header(snd_ip, tgt_ip)

                try:
                    self.l2soc.send(eth_frame + arp_header)  # Send a packet
                except BlockingIOError:
                    self.flag.wait(data.WAIT_SEND)
                else:
                    self.flag.wait(data.SLP / 1000)  # Non-blocking sleep
                    new_count -= 1


class SniffThread(threading.Thread):
    packet = None

    def __init__(self, l2soc):
        self.l2soc = l2soc

        super().__init__()
        self.flag = threading.Event()

    @ExceptionHandler(data.SNIFF)
    def run(self):
        while not self.flag.is_set():
            try:
                self.packet = self.l2soc.recv(data.SOC_BUF)  # Receive a packet
            except BlockingIOError:
                self.flag.wait(data.WAIT_SNIFF)
            else:
                self.sniff()

    def sniff(self):
        # Ethernet frame from the packet
        eth_frame = struct.unpack("!6s6s2s", self.packet[:14])
        # ARP header from the packet
        arp_header = struct.unpack("!2s2s1s1s2s6s4s6s4s", self.packet[14:42])

        src_mac = binascii.hexlify(eth_frame[1]).decode("utf-8")
        # Not your address?
        if src_mac != data.SRC_MAC:
            eth_typ = binascii.hexlify(eth_frame[2]).decode("utf-8")
            # EtherType ARP?
            if eth_typ == data.ETH_TYP:
                arp_opc = binascii.hexlify(arp_header[4]).decode("utf-8")
                snd_mac = binascii.hexlify(arp_header[5]).decode("utf-8")
                snd_ip = socket.inet_ntoa(arp_header[6])
                if not data.FLT or data.FLT and check_ip(snd_ip, data.RNG):
                    data.SNIFF_A.append([snd_ip, src_mac, snd_mac, arp_opc])
