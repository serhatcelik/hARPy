# This file is part of hARPy

import os
import binascii


class InterfaceHandler:
    sys_path = "/sys/class/net/"
    members = dict()

    def __init__(self):
        if os.path.isdir(self.sys_path):
            self.members = {
                i: None for i in os.listdir(self.sys_path) if i != "lo"
            }  # Obtain all interfaces except lo

        for i in self.members:
            carrier_path = os.path.join(self.sys_path, i, "carrier")
            if os.path.isfile(carrier_path):
                carrier = open(carrier_path, "r")
                try:
                    self.members[i] = int(carrier.readline(1))  # Add carrier
                except ValueError:
                    pass
                finally:
                    carrier.close()

    def __call__(self):
        for i in self.members:
            if self.members[i]:  # Is interface up? (1)
                return i
        return None

    @classmethod
    def get_mac_address(cls, raw_socket):
        return binascii.hexlify(raw_socket.getsockname()[-1]).decode("utf-8")
