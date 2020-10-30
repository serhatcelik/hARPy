# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Functions for handling the program logo."""

import re
import harpy.core.data as data


def create_logo():
    """Create the logo for the program."""

    logo = [
        r'{0}|_ {1} _  _ _ {0}  {2}'.format(data.BLUE, data.GREEN, data.RESET),
        r'{0}| |{1}(_|| |_){0}\/{2}'.format(data.BLUE, data.GREEN, data.RESET),
        r'{0}   {1}     |  {0}/ {2}'.format(data.BLUE, data.GREEN, data.RESET)
    ]

    expression = r'\033\[([0-9]|[0-9]{2})m'  # ESC[ n m
    # Remove ANSI escape sequences
    setattr(create_logo, 'logo_len', len(re.sub(expression, '', logo[0])))

    return logo


def create_banner():
    """Create a banner for the program logo."""

    return [
        'TOTAL HOST: ',
        'TOTAL REQ.: ',
        'TOTAL REP.: '
    ]
