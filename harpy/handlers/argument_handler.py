# This file is part of hARPy

import re
from harpy.handlers.interface_handler import InterfaceHandler


class ArgumentHandler:
    @staticmethod
    def count_handler(arg):
        if arg <= 0:
            print(f"count: error: expected an int greater than 0, got {arg}")
            return False
        return True

    @staticmethod
    def interface_handler(arg):
        if arg is None:
            print(f"interface: error: no up interface found in directory, "
                  f"{InterfaceHandler.sys_path}")
            return False
        if arg == "lo":
            print(f"interface: error: interface cannot be used, {arg}")
            return False
        if arg not in InterfaceHandler().members:
            print(f"interface: error: no such interface, {arg}")
            return False
        if not InterfaceHandler().members[arg]:
            print(f"interface: error: interface is not up, {arg}")
            return False
        return True

    @staticmethod
    def node_handler(arg):
        if not 2 <= arg <= 253:
            print(f"node: error: expected an int between 2 and 253, got {arg}")
            return False
        return True

    @staticmethod
    def range_handler(arg):
        octet = "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"  # [0, 255]
        expression = fr"^({octet}\.{octet}\.{octet}\.{octet}/(8|16|24))$"
        if not re.search(expression, arg):
            print(f"range: error: provided a range with invalid syntax, {arg}")
            return False
        return True

    @staticmethod
    def sleep_handler(arg):
        if arg <= 1:
            print(f"sleep: error: expected an int greater than 1, got {arg}")
            return False
        return True
