# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling the terminal echo."""

import atexit
import termios


class EchoHandler:
    """Handler of the terminal echo."""

    def __init__(self):
        self.descriptor = 0  # STDIN
        self.new = termios.tcgetattr(self.descriptor)

    @staticmethod
    @atexit.register  # Enable the terminal echo at normal program termination
    def enable():
        """Enable the terminal echo."""

        descriptor = 0
        new = termios.tcgetattr(descriptor)

        new[3] |= termios.ECHO
        termios.tcsetattr(descriptor, termios.TCSANOW, new)

    def disable(self):
        """Disable the terminal echo."""

        self.new[3] &= ~termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, self.new)
