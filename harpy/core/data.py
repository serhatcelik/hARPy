# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global variables and functions for handling external modules."""

import os
import sys

##############
# CROSS-DATA #
##############
COMMANDS = None  # Parsed command-line arguments
RUN_HARPY = True
ERRORS = set()  # Container to store errors as non-recurring
THREADS = list()  # Container to store all threads
TERMINATE_TIMEOUT = 5
SNIFF_RESULT = list()  # Container to store a sniff result
SNIFF_RESULTS = list()  # Container to store all sniff results
SENDING_ADDRESS = None
SENDING_FINISHED = False

#############
# LOCATIONS #
#############
SYS_PATH = '/sys/class/net/'
VENDORS_FILE = os.path.join(os.path.dirname(__file__), 'vendors.json')
LOGS_FILE = os.path.join(os.path.dirname(__file__), 'LOGS')

###########
# SIGNALS #
###########
SIGCHLD = 17  # Child stopped or terminated
SIGWINCH = 28  # Window resize signal (4.3BSD, Sun)
SIGNALS = [
    _ for _ in range(1, 65) if _ not in (SIGCHLD, SIGWINCH, 9, 19, 32, 33)
]  # 9: SIGKILL, 19: SIGSTOP

##########
# STYLES #
##########
RESET = '\033[0m'  # Reset all attributes to their defaults
FG_BLACK = '\033[30m'  # Black
FG_RED = '\033[31m'  # Red
FG_GREEN = '\033[32m'  # Green
BG_YELLOW = '\033[43m'  # Yellow (Background)

#################
# NOTIFICATIONS #
#################
FAIL = '[FAIL]'
SUCCESS = '[SUCCESS]'
ERR_COUNT = 'count: error:'
ERR_INTERFACE = 'interface: error:'
ERR_NODE = 'node: error:'
ERR_RANGE = 'range: error:'
ERR_SEND = 'send: error:'
ERR_SLEEP = 'sleep: error:'
ERR_SNIFF = 'sniff: error:'
ERR_SOCKET = 'socket: error:'

##########################
# COMMAND-LINE ARGUMENTS #
##########################
DEF_CNT = 1  # Count default
DEF_NOD = 43  # Node default
DEF_SLP = 3  # Sleep default
LIM_CNT = 0  # Count limit
LIM_NOD = 2, 253  # Node limit
LIM_SLP = 1  # Sleep limit

#################
# RESULT WINDOW #
#################
MAIN_COL_NUM = 6  # Total number of columns
MAX_IP_LEN = 15  # Max length an IP address can take
MAX_ETH_MAC_LEN = 17  # Max length an Ethernet MAC address can take
MAX_ARP_MAC_LEN = 17  # Max length an ARP MAC address can take
MAX_REQ_LEN = 6  # Max allowed length of ARP request column
MAX_REP_LEN = 6  # Max allowed length of ARP reply column
MAX_ALL_LEN = sum(
    [MAX_IP_LEN, MAX_ETH_MAC_LEN, MAX_ARP_MAC_LEN, MAX_REQ_LEN, MAX_REP_LEN]
) + MAIN_COL_NUM * len(' | ')  # Max length of all columns except last column

##############
# RAW SOCKET #
##############
SOC_BUF = 2 ** 6  # Buffer size in bytes: 64 (Min allowed value is 42)
SOC_POR = 0  # Port to bind to an interface
SOC_PRO = 3  # GGP ( https://www.iana.org/assignments/protocol-numbers )

##################
# ETHERNET FRAME #
##################
ETH_SRC = None  # Source MAC address: Own MAC address
ETH_DST = 'ff' * 6  # Destination MAC address: Broadcast
ETH_TYP = '0806'  # EtherType: ARP

##############
# ARP HEADER #
##############
ARP_HWT = '0001'  # Hardware type: Ethernet
ARP_PRT = '0800'  # Protocol type: IPv4
ARP_HWS = '06'  # Hardware size: 6 bytes
ARP_PRS = '04'  # Protocol size: 4 bytes
ARP_REQ = '0001'  # Opcode: Request
ARP_SND = None  # Sender MAC address: Own MAC address
ARP_TGT = 'ff' * 6  # Target MAC address: Broadcast

#############
# FUNCTIONS #
#############


def with_red(text):
    """
    Color the text with red.

    :param text: Text to be colored with red.
    """

    return FG_RED + text + RESET


def with_green(text):
    """
    Color the text with green.

    :param text: Text to be colored with green.
    """

    return FG_GREEN + text + RESET


def new_range(commands):
    """
    Return a new scan range in list format.

    :param commands: Parsed command-line arguments.
    """

    return [
        commands.r.split('.')[0],
        commands.r.split('.')[1],
        commands.r.split('.')[2],
        commands.r.split('.')[3].split('/')[0],
        commands.r.split('.')[3].split('/')[1]
    ]


def oserror_handler(err, who):
    """
    Handler of OSError.

    :param err: Error to handle.
    :param who: Responsible for the error.
    """

    # [Errno 1] Operation not permitted
    if err.errno == 1:
        sys.exit(with_red(f'{who} you are not root user'))
    # [Errno 9] Bad file descriptor
    elif err.errno == 9:
        ERRORS.add(with_red(f'{who} problem with socket'))
    # [Errno 19] No such device
    elif err.errno == 19:
        sys.exit(with_red(f'{who} cannot use the current interface'))
    # [Errno 100] Network is down
    elif err.errno == 100:
        ERRORS.add(with_red(f'{who} network is down'))
    else:
        globals()['RUN_HARPY'] = False
        return None

    globals()['RUN_HARPY'] = False
    return False


def signal_handler(_signum, _frame):
    """
    Handler of incoming signal.

    :param _signum: Signal number.
    :param _frame: Signal frame.
    """

    globals()['RUN_HARPY'] = False
