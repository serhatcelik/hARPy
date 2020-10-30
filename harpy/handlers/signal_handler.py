# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling signals."""

import signal
import threading


class SignalHandler:
    """Handler of signals."""

    def __init__(self, *signals):
        self.signals = signals

    def enable(self, handler):
        """
        Enable the handler to capture incoming signals.

        :param handler: Incoming signal handler.
        """

        if threading.current_thread() is threading.main_thread():
            for _ in self.signals:
                signal.signal(_, handler)

    def disable(self):
        """Disable the handler to ignore incoming signals."""

        if threading.current_thread() is threading.main_thread():
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
