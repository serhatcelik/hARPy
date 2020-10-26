# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global variables and functions for handling external modules."""

import os
import time

################
# OVER CONTROL #
################
START_MAIN = time.time()
RUN_MAIN = True
TIMED_OUT = False
SIGNAL_NUMBER = None
COMMANDS = None  # Parsed command-line arguments
THREADS = list()  # Container to store all threads
ERRORS = set()  # Container to store errors as non-recurring
SLEEP_MAIN = 0.025  # Reduce window flickering
SLEEP_TERMINATOR = 5.25  # Prevent looping indefinitely
SLEEP_SEND = 0.75  # Reduce window flickering
SLEEP_SNIFF = 0.025  # Reduce window flickering
SNIFF_RESULT = list()  # Container to store a sniff result
SNIFF_RESULTS = list()  # Container to store all sniff results
SEND_FINISHED = False
SEND_PAUSED = False
SEND_ADDRESS = None

#############
# LOCATIONS #
#############
SYS_PATH = '/sys/class/net/'
LOG_FILE = '/var/log/user.log'
VENDORS_FILE = os.path.join(os.path.dirname(__file__), 'vendors.json')

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
F_BLACK = '\033[30m'  # Black
F_RED = '\033[31m'  # Red
F_GREEN = '\033[32m'  # Green
F_YELLOW = '\033[33m'  # Yellow
F_BLUE = '\033[34m'  # Blue
B_YELLOW = '\033[43m'  # Yellow (Background)

#################
# NOTIFICATIONS #
#################
FAIL = '[' + F_RED + 'fail' + RESET + ']'
SUCCESS = '[' + F_GREEN + 'done' + RESET + ']'
HARPY = 'harpy'
SEND = 'send'
SNIFF = 'sniff'
SOCKET = 'socket'

##########################
# COMMAND-LINE ARGUMENTS #
##########################
DEF_CNT = 1  # Count default
DEF_NOD = 43  # Node default
DEF_SLP = 3  # Sleep default
DEF_TIM = 1800  # Timeout default
LIM_CNT = 1  # Count limit
LIM_NOD = 2, 253  # Node limit
LIM_SLP = 2, 1000  # Sleep limit
LIM_TIM = 5  # Timeout limit

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
ARP_REP = '0002'  # Opcode: Reply
ARP_SND = None  # Sender MAC address: Own MAC address
ARP_TGT = 'ff' * 6  # Target MAC address: Broadcast


#############
# FUNCTIONS #
#############
def with_red(text):
    """
    Color the text with red.

    :param text: Text to be colored.
    """

    return globals()['F_RED'] + text + globals()['RESET']


def new_range(commands):
    """
    Return a new scan range in list format.

    :param commands: Parsed command-line arguments.
    """

    return [
        commands.r.split('.')[0],
        commands.r.split('.')[1],
        commands.r.split('.')[2],
        commands.r.split('.')[-1].split('/')[0],
        commands.r.split('.')[-1].split('/')[-1]
    ]


def run_main(run=True):
    """
    Determine whether the program will continue to run.

    :param run: Value to determine.
    """

    if not run:
        globals()['RUN_MAIN'] = False
    elif not time.time() - globals()['START_MAIN'] < globals()['COMMANDS'].t:
        globals()['RUN_MAIN'] = False
        globals()['TIMED_OUT'] = True


def signal_handler(_signum, _frame):
    """
    Handler of incoming signal.

    :param _signum: Signal number.
    :param _frame: Signal frame.
    """

    globals()['SIGNAL_NUMBER'] = str(_signum)
    run_main(False)
