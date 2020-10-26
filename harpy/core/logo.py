# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Functions for handling the program logo."""

import re
import harpy.core.data as data


def create_logo():
    """Create the logo for the program."""

    logo = [
        fr'{data.F_BLUE}|_ {data.F_GREEN} _  _ _ {data.F_BLUE}  {data.RESET}',
        fr'{data.F_BLUE}| |{data.F_GREEN}(_|| |_){data.F_BLUE}\/{data.RESET}',
        fr'{data.F_BLUE}   {data.F_GREEN}     |  {data.F_BLUE}/ {data.RESET}'
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
