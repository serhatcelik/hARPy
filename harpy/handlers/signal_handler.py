# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling signals."""

import signal
import threading


class SignalHandler:
    """Handler of signals."""

    def __init__(self, handler):
        self.handler = handler

    def catch(self, *signals):
        """
        Catch the signals.

        :param signals: Signals to be caught.
        """

        if threading.current_thread() is threading.main_thread():
            for _ in signals:
                signal.signal(_, self.handler)

    @staticmethod
    def ignore(*signals):
        """
        Ignore the signals.

        :param signals: Signals to be ignored.
        """

        if threading.current_thread() is threading.main_thread():
            # Be sure to ignore the signals
            while True:
                try:
                    for _ in signals:
                        signal.signal(_, signal.SIG_IGN)
                    return
                except TypeError:
                    # Workaround for the _thread.interrupt_main() bug
                    # ( https://bugs.python.org/issue23395 )
                    pass
