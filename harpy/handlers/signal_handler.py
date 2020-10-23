# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling signals."""

import signal


class SignalHandler:
    """Handler of signals."""

    def __init__(self, *signals):
        self.signals = signals

    def activate_handler(self, handler):
        """
        Activate the handler to catch incoming signals.

        :param handler: Incoming signal handler.
        """

        for _ in self.signals:
            signal.signal(_, handler)

    def disable_handler(self):
        """Disable the handler to ignore incoming signals."""

        # Be sure to disable the handler
        while True:
            try:
                for _ in self.signals:
                    signal.signal(_, signal.SIG_IGN)
                return
            except TypeError:
                # Workaround for _thread.interrupt_main() bug
                # ( https://bugs.python.org/issue23395 )
                continue
