# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global variables for handling external modules."""

import os
import time

################
# OVER CONTROL #
################
RUN_MAIN = True
TIME_TIMEOUT = time.time()
EXIT_MESSAGES = set()  # Container to store exit messages as non-recurring
COMMANDS = None  # Parsed command-line arguments
THREADS = list()  # Container to store threads
SLEEP_MAIN = 2.5  # Reduce window flickering
SLEEP_TERMINATOR = 3  # Prevent looping indefinitely
SLEEP_SNIFF = 0.025  # Reduce window flickering
SLEEP_SEND = 0.05  # Reduce window flickering
SNIFF_RESULT = list()  # Container to store a sniff result
SNIFF_RESULTS = list()  # Container to store all sniff results
SEND_ADDRESS = None
SEND_FINISHED = False

#############
# LOCATIONS #
#############
DEV_LOG = '/dev/log'
SYS_NET = '/sys/class/net/'
VENDORS_FILE = os.path.join(os.path.dirname(__file__), 'vendors.json')

###########
# SIGNALS #
###########
SIGHUP = 1  # Hangup detected on controlling terminal
SIGKILL = 9  # Kill signal (Cannot be caught or ignored)
SIGCHLD = 17  # Child stopped or terminated
SIGSTOP = 19  # Stop process (Cannot be caught or ignored)
SIGWINCH = 28  # Window resize signal (4.3BSD, Sun)
SIGNALS = [
    _ for _ in range(1, 65) if _ not in (
        SIGHUP, SIGKILL, SIGCHLD, SIGSTOP, SIGWINCH, 32, 33
    )
]

##########
# STYLES #
##########
RESET = '\033[0m'  # Reset all attributes to their defaults
BLACK = '\033[30m'  # Black
RED = '\033[31m'  # Red
GREEN = '\033[32m'  # Green
YELLOW = '\033[33m'  # Yellow
BLUE = '\033[34m'  # Blue
BG_YELLOW = '\033[43m'  # Yellow (Background)
ANSI_EXPRESSION = r'\033\[([0-9]|[0-9]{2})m'  # ESC[ n m

#########
# NAMES #
#########
SEND = 'send'
SNIFF = 'sniff'
SOCKET = 'socket'

##########################
# COMMAND-LINE ARGUMENTS #
##########################
DEF_CNT = 1  # Default count
DEF_NOD = 43  # Default node
DEF_SLP = 3  # Default sleep
DEF_TIM = 1800  # Default timeout
MIN_CNT = 1  # Min count value
MIN_NOD = 2  # Min node value
MIN_SLP = 3  # Min sleep value
MIN_TIM = 5  # Min timeout value
MAX_NOD = 253  # Max node value
MAX_SLP = 1000  # Max sleep value

#################
# RESULT WINDOW #
#################
CHANGE_TO_ARP = False  # Ethernet MAC <-> ARP MAC
CONT_STP_NUM = 6  # Step size for iterable sniff results container
MAIN_COL_NUM = 5  # Total number of columns
MAX_IP_LEN = 17  # Max length of IP address column
MAX_MAC_LEN = 18  # Max length of MAC address column
MAX_REQ_LEN = 6  # Max length of ARP request column
MAX_REP_LEN = 6  # Max length of ARP reply column
MAX_ALL_LEN = sum(
    [MAX_IP_LEN, MAX_MAC_LEN, MAX_REQ_LEN, MAX_REP_LEN]
) + (MAIN_COL_NUM - 1) * len(' | ')  # Max length of columns except last column

##############
# RAW SOCKET #
##############
SOC_BUF = 42  # Buffer size in bytes
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
