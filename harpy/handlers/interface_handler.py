# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling interfaces."""

import os
import binascii
import harpy.core.data as data


class InterfaceHandler:
    """Handler of interfaces."""

    def __init__(self):
        if os.path.isdir(data.SYS_PATH):
            self.mems = {
                _: None for _ in os.listdir(data.SYS_PATH) if _ != 'lo'
            }  # All interfaces

        for _ in self.mems:
            carrier_file = os.path.join(data.SYS_PATH, _, 'carrier')
            if os.path.isfile(carrier_file):
                with open(carrier_file, 'r') as carrier:
                    self.mems[_] = int(carrier.readline(1))

    def __call__(self):
        for _ in self.mems:
            # Interface up?
            if self.mems[_]:
                return _
        return None

    @classmethod
    def get_mac(cls, raw_soc):
        """
        Return an interface's MAC address.

        :param raw_soc: Layer 2 RAW socket.
        """

        return binascii.hexlify(raw_soc.getsockname()[-1]).decode('utf-8')
