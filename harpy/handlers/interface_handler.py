# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling interfaces."""

import os
import binascii
import harpy.data.core as core


class InterfaceHandler:
    """Handler of interfaces."""

    def __init__(self):
        if os.path.isdir(core.SYS_NET):
            self.members = {
                _: None for _ in os.listdir(core.SYS_NET)
            }  # All interfaces

        for _ in self.members:
            if _ != 'lo':
                operstate_file = os.path.join(core.SYS_NET, _, 'operstate')
                if os.path.isfile(operstate_file):
                    with open(operstate_file, 'r') as operstate:
                        self.members[_] = operstate.read().strip().lower()

    def __call__(self):
        for _ in self.members:
            # Interface up?
            if self.members[_] == 'up':
                return _
        return None

    @staticmethod
    def get_mac(l2soc):
        """
        Return an interface's MAC address.

        :param l2soc: Layer 2 RAW socket.
        """

        return binascii.hexlify(l2soc.getsockname()[-1]).decode('utf-8')
