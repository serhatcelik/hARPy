# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling terminal echo."""

import sys
import termios


class EchoHandler:
    """Handler of terminal echo."""

    def __init__(self):
        self.descriptor = sys.stdin.fileno()

    def enable(self):
        """Enable terminal echo."""

        if sys.stdin.isatty():
            new = termios.tcgetattr(self.descriptor)
            new[3] |= termios.ECHO
            termios.tcsetattr(self.descriptor, termios.TCSANOW, new)

    def disable(self):
        """Disable terminal echo."""

        if sys.stdin.isatty():
            new = termios.tcgetattr(self.descriptor)
            new[3] &= ~termios.ECHO
            termios.tcsetattr(self.descriptor, termios.TCSANOW, new)
