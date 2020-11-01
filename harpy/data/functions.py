# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global functions for handling external modules."""

import time
import harpy.data.core as core


def with_red(text):
    """
    Color the text with red.

    :param text: Text to be colored with red.
    """

    return core.RED + text + core.RESET


def with_dot(text, width, xref=0):
    """
    Return a new dotted text if it exceeds the width.

    :param text: Text to be shortened.
    :param width: The terminal width.
    :param xref: The x coordinate where the text will begin.
    """

    if xref + len(text) > width:
        return text[0:width - xref - len('...')] + '...'  # Shorten the text
    return text


def new_range():
    """Return a new scan range in list format."""

    if core.COMMANDS.r is not None:
        return [
            core.COMMANDS.r.split('.')[0],
            core.COMMANDS.r.split('.')[1],
            core.COMMANDS.r.split('.')[2],
            core.COMMANDS.r.split('.')[-1].split('/')[0],
            core.COMMANDS.r.split('.')[-1].split('/')[-1]
        ]
    return None


def new_ip(snd_ip):
    """
    Return True or False while keeping the current scan range value.

    :param snd_ip: Sender IP address.
    """

    if core.COMMANDS.r[-1] == '24':
        criteria = snd_ip.split('.')[0:3] == core.COMMANDS.r[0:3]
    elif core.COMMANDS.r[-1] == '16':
        criteria = snd_ip.split('.')[0:2] == core.COMMANDS.r[0:2]
    else:
        criteria = snd_ip.split('.')[0:1] == core.COMMANDS.r[0:1]

    return criteria


def run_main(run=True):
    """
    Handler of main process of the program.

    :param run: Determine whether the program will continue to run.
    """

    if not run:
        core.RUN_MAIN = False
    elif time.time() - core.TIME_TIMEOUT >= core.COMMANDS.t:
        core.EXIT_MESSAGES.add('timed out,' + ' ')
        core.RUN_MAIN = False


def signal_handler(_signum, _frame):
    """
    Handler of incoming signal.

    :param _signum: Signal number.
    :param _frame: Signal frame.
    """

    core.EXIT_MESSAGES.add('received signal %d,' % _signum + ' ')
    run_main(False)
