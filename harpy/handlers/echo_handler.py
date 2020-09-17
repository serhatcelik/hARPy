# This file is part of hARPy

import sys
try:
    import termios
except ModuleNotFoundError:
    sys.exit(f"harpy: error: unsupported platform, {sys.platform}")


class EchoHandler:
    def __init__(self):
        self.descriptor = sys.stdin.fileno()
        self.new = termios.tcgetattr(self.descriptor)

    def enable_echo(self):
        self.new[3] |= termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, self.new)
        sys.stdout.write("\033[?25h")

    def disable_echo(self):
        self.new[3] &= ~termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, self.new)
        sys.stdout.write("\033[?25l")  # Hide cursor
