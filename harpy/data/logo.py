# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Functions for handling the program logo."""

import re
import harpy.data.core as core


def create_logo():
    """Create the logo for the program."""

    logo = [
        r'{0}|_ {1} _  _ _ {0}  {2}'.format(core.BLUE, core.GREEN, core.RESET),
        r'{0}| |{1}(_|| |_){0}\/{2}'.format(core.BLUE, core.GREEN, core.RESET),
        r'{0}   {1}     |  {0}/ {2}'.format(core.BLUE, core.GREEN, core.RESET)
    ]

    setattr(
        create_logo, 'logo_len', len(re.sub(core.ANSI_EXPRESSION, '', logo[0]))
    )  # Remove ANSI escape sequences

    return logo


def create_banner():
    """Create a banner for the program logo."""

    return [
        'TOTAL HOST: ',
        'TOTAL REQ.: ',
        'TOTAL REP.: '
    ]
