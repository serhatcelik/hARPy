# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling exceptions."""

import sys
import harpy.core.data as data
from harpy.core.data import with_red


class ExceptionHandler:
    """Handler of exceptions."""

    def __init__(self, who=None):
        self.who = who  # Responsible for the error

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except OSError as err:
                # Operation not permitted
                if err.args[0] == 1:
                    sys.exit(self.with_who('run me as root'))
                # Input/output error
                elif err.args[0] == 5:
                    pass
                # Bad file descriptor
                elif err.args[0] == 9:
                    data.ERRORS.add(self.with_who('problem with socket'))
                # No such device
                elif err.args[0] == 19:
                    sys.exit(self.with_who('problem with network device'))
                # Network is down
                elif err.args[0] == 100:
                    data.ERRORS.add(self.with_who('problem with network'))
                else:
                    raise

                data.run_main(False)

        return wrapper

    def with_who(self, text):
        """
        Print the text with responsible for the error.

        :param text: Text to be printed.
        """

        return with_red('{}: {}'.format(self.who, text))
