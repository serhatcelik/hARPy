# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling interfaces."""

import os
import binascii
import harpy.core.data as data


class InterfaceHandler:
    """Handler of interfaces."""

    members = dict()

    def __init__(self):
        if os.path.isdir(data.SYS_PATH):
            self.members = {
                _: None for _ in os.listdir(data.SYS_PATH) if _ != 'lo'
            }  # All interfaces

        for _ in self.members:
            carrier_path = os.path.join(data.SYS_PATH, _, 'carrier')
            if os.path.isfile(carrier_path):
                with open(carrier_path, 'r') as carrier:
                    try:
                        self.members[_] = int(carrier.readline(1))
                    finally:
                        continue

    def __call__(self):
        for _ in self.members:
            # Interface up?
            if self.members[_]:
                return _
        return None

    @classmethod
    def get_mac(cls, raw_soc):
        """
        Return an interface's MAC address.

        :param raw_soc: Layer 2 RAW socket.
        """

        return binascii.hexlify(raw_soc.getsockname()[-1]).decode('utf-8')
