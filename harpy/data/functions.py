# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global functions for handling external modules."""

import time
from harpy.data import variables as core


def with_red(text):
    """
    Color the text with red.

    :param text: The text to be colored with red.
    """

    return core.RED + text + core.RESET


def with_green(text):
    """
    Color the text with green.

    :param text: The text to be colored with green.
    """

    return core.GREEN + text + core.RESET


def with_dot(text, width, xref=0):
    """
    Return a new dotted text if it exceeds the width.

    :param text: The text to be shortened.
    :param width: Terminal width.
    :param xref: The x coordinate where the text will begin.
    """

    if xref + len(text) > width:
        return text[0:width - xref - len('...')] + '...'
    return text


def with_colon(mac_address):
    """
    Add colons to the given MAC address.

    :param mac_address: The MAC address to be added with colons.
    """

    return ':'.join(
        mac_address[_:_ + 2] for _ in range(0, len(mac_address), 2)
    )


def new_range():
    """Return a new scanning range in list format."""

    if core.COMMANDS.r is not None:
        return [
            core.COMMANDS.r.split('.')[0],
            core.COMMANDS.r.split('.')[1],
            core.COMMANDS.r.split('.')[2],
            core.COMMANDS.r.split('.')[-1].split('/')[0],
            core.COMMANDS.r.split('.')[-1].split('/')[-1]
        ]
    return None


def check_ip(snd_ip):
    """
    Check the sender IP address.

    :param snd_ip: Sender IP address.
    """

    if core.COMMANDS.r[-1] == '24':
        return snd_ip.split('.')[0:3] == core.COMMANDS.r[0:3]
    if core.COMMANDS.r[-1] == '16':
        return snd_ip.split('.')[0:2] == core.COMMANDS.r[0:2]
    return snd_ip.split('.')[0:1] == core.COMMANDS.r[0:1]


def run_main(run=True):
    """
    Handler of the main process of the program.

    :param run: Determine whether the program will continue to run.
    """

    if not run:
        core.RUN_MAIN = False
    elif time.time() - core.TIME_TIMEOUT >= core.COMMANDS.t:
        core.EXIT_MESSAGES.add('timed out')
        run_main(False)


def signal_handler(_signum, _frame):
    """
    Handler of incoming signals.

    :param _signum: Signal number.
    :param _frame: Signal frame.
    """

    core.EXIT_MESSAGES.add('received signal %d' % _signum)
    run_main(False)
