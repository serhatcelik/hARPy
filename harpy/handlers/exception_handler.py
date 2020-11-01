# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling exceptions."""

import sys
import harpy.data.core as core
import harpy.data.functions as func
from harpy.data.functions import with_red


class ExceptionHandler:
    """Handler of exceptions."""

    def __init__(self, who=None):
        self.who = who  # Responsible for the error

    def __call__(self, function):
        def wrapper(*args, **kwargs):
            try:
                function(*args, **kwargs)
            except OSError as err:
                # Operation not permitted
                if err.args[0] == 1:
                    sys.exit(with_red('run me as root'))
                # Input/output error
                elif err.args[0] == 5:
                    pass
                # Bad file descriptor
                elif err.args[0] == 9:
                    core.EXIT_MESSAGES.add(self.with_who('socket\n'))
                # No such device
                elif err.args[0] == 19:
                    sys.exit(self.with_who('network interface'))
                # Network is down
                elif err.args[0] == 100:
                    core.EXIT_MESSAGES.add(self.with_who('network\n'))
                else:
                    raise

                func.run_main(False)

        return wrapper

    def with_who(self, text):
        """
        Print the text with responsible for the error.

        :param text: Text to be printed.
        """

        return with_red('%s: problem with %s' % (self.who, text))
