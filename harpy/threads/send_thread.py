# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the send thread."""

import time
import socket
import struct
import threading
import harpy.core.data as data
from harpy.handlers.packet_handler import PacketHandler
from harpy.handlers.exception_handler import ExceptionHandler


class SendThread(threading.Thread):
    """Handler of the send thread."""

    def __init__(self, raw_soc):
        super().__init__()

        self.name = data.SEND
        self.flag = threading.Event()

        self.raw_soc = raw_soc

        self.cnt = data.COMMANDS.c
        self.nod = data.COMMANDS.n
        self.rng = data.COMMANDS.r
        self.slp = data.COMMANDS.s

    def run(self):
        while not self.flag.is_set() and data.RUN_MAIN:
            self.send()

    @ExceptionHandler(data.SEND)
    def send(self):
        """Send ARP packets."""

        if self.rng[-1] == '24':
            first_ip = '.'.join([self.rng[0], self.rng[1], self.rng[2], '1'])
            last_ip = '.'.join([self.rng[0], self.rng[1], self.rng[2], '254'])
        elif self.rng[-1] == '16':
            first_ip = '.'.join([self.rng[0], self.rng[1], '0', '1'])
            last_ip = '.'.join([self.rng[0], self.rng[1], '255', '254'])
        else:
            first_ip = '.'.join([self.rng[0], '0', '0', '1'])
            last_ip = '.'.join([self.rng[0], '255', '255', '254'])

        start = struct.unpack('!I', socket.inet_aton(first_ip))[0]
        stop = struct.unpack('!I', socket.inet_aton(last_ip))[0]
        for _ in range(start, stop + 1):
            if self.flag.is_set():
                return
            tgt_ip = socket.inet_ntoa(struct.pack('!I', _))
            data.SEND_ADDRESS = tgt_ip
            new_count = self.cnt  # Restore the original value at every step
            while not self.flag.is_set() and new_count > 0:
                # Gratuitous ARP?
                if int(tgt_ip.split('.')[-1]) == self.nod:
                    snd_ip = '.'.join(tgt_ip.split('.')[0:3] + ['0'])
                else:
                    snd_ip = '.'.join(tgt_ip.split('.')[0:3] + [str(self.nod)])

                eth_frame = PacketHandler.create_eth_frame(data.ETH_SRC)
                arp_header = PacketHandler.create_arp_header(
                    snd_mac=data.ARP_SND,
                    snd_ip=snd_ip,
                    tgt_ip=tgt_ip
                )

                try:
                    self.raw_soc.send(eth_frame + arp_header)  # Send a packet
                except BlockingIOError:
                    time.sleep(data.SLEEP_SEND)
                else:
                    time.sleep(self.slp / 1000)
                    new_count -= 1

        data.SEND_FINISHED = True
        self.flag.set()
