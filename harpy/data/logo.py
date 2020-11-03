# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Functions for handling the program logo."""

from harpy.data import variables as core


def create_logo():
    """Create the logo for the program."""

    logo = [
        r'{1}|_ {2} _  _ _ {1}  {0}'.format(core.RESET, core.BLUE, core.GREEN),
        r'{1}| |{2}(_|| |_){1}\/{0}'.format(core.RESET, core.BLUE, core.GREEN),
        r'{1}   {2}     |  {1}/ {0}'.format(core.RESET, core.BLUE, core.GREEN)
    ]

    return logo


def create_banner():
    """Create a banner for the program logo."""

    return [
        'TOTAL HOST: ',
        'TOTAL REQ.: ',
        'TOTAL REP.: '
    ]
