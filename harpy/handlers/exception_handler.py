# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling exceptions."""

import sys
import harpy.core.data as data
from harpy.core.data import with_red


class ExceptionHandler:
    """Handler of exceptions."""

    def __init__(self, who=data.HARPY):
        self.who = who  # Responsible for the error

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except OSError as err:
                # Operation not permitted
                if err.errno == 1:
                    sys.exit(self.with_who('run me as root'))
                # Input/output error
                elif err.errno == 5:
                    data.HANGED_UP = True
                # Bad file descriptor
                elif err.errno == 9:
                    data.ERRORS.add(self.with_who('problem with socket'))
                # No such device
                elif err.errno == 19:
                    sys.exit(self.with_who('problem with interface'))
                # Network is down
                elif err.errno == 100:
                    data.ERRORS.add(self.with_who('problem with network'))
                else:
                    raise

                data.run_main(False)

        return wrapper

    def with_who(self, text):
        """
        Print the text with the responsible for the error.

        :param text: Text to be printed.
        """

        return with_red(self.who + ':' + ' ' + text)
