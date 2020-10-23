# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling terminal echo."""

import termios


class EchoHandler:
    """Handler of terminal echo."""

    def __init__(self):
        self.descriptor = 0  # STDIN
        self.new = termios.tcgetattr(self.descriptor)

    def enable_echo(self):
        """Enable echoing input characters."""

        self.new[3] |= termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, self.new)

    def disable_echo(self):
        """Disable echoing input characters."""

        self.new[3] &= ~termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, self.new)
