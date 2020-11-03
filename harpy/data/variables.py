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
EXIT_MESSAGES = set()  # Container for storing exit messages as non-recurring
THREADS = list()  # Container for storing threads
COMMANDS = None  # Parsed command-line arguments
SLEEP_MAIN = 2  # Reduce window flickering
SLEEP_TERMINATOR = 3  # Prevent looping indefinitely
SLEEP_SNIFF = 0.025  # Reduce window flickering
SLEEP_SEND = 0.075  # Reduce window flickering
SNIFF_A = list()  # Container for storing a sniff result
SNIFF_ALL = list()  # Container for storing all sniff results
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
# SIGNALS TO BE CAUGHT
HUP = 1  # Hangup detected on controlling terminal

# SIGNALS TO BE IGNORED
CHLD = 17  # Child stopped or terminated
WINCH = 28  # Window resize signal (4.3BSD, Sun)

# SIGNALS THAT CANNOT BE CAUGHT OR IGNORED
KILL = 9  # Kill signal
STOP = 19  # Stop process

CATCHABLE_SIGNALS = [_ for _ in range(1, 65) if _ not in [KILL, STOP, 32, 33]]
CATCH_SIGNALS = [_ for _ in CATCHABLE_SIGNALS if _ not in [CHLD, WINCH]]
IGNORE_SIGNALS = [_ for _ in CATCHABLE_SIGNALS if _ not in [HUP]]

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
ANSI_REGEX = r'\033\[([0-9]|[0-9]{2})m'  # ESC[ N m

###################
# NAMES & OBJECTS #
###################
ECHO = 'echo'
SEND = 'send'
SNIFF = 'sniff'
PARSER = 'parser'
RESULT = 'result'
SIGNAL = 'signal'
SOCKET = 'socket'
WINDOW = 'window'

##########################
# COMMAND-LINE ARGUMENTS #
##########################
# DEFAULTS
DEF_CNT = 1  # Default count
DEF_NOD = 43  # Default node
DEF_SLP = 3  # Default sleep (ms)
DEF_TIM = 1800  # Default timeout (sec)

# MINIMUMS
MIN_CNT = 1  # Min count value
MIN_NOD = 2  # Min node value
MIN_SLP = 3  # Min sleep value (ms)
MIN_TIM = 10  # Min timeout value (sec)

# MAXIMUMS
MAX_NOD = 253  # Max node value
MAX_SLP = 1000  # Max sleep value (ms)

#################
# RESULT WINDOW #
#################
ETHER_TO_ARP = False  # Ethernet MAC <-> ARP MAC
CONT_STP_NUM = 6  # Step size for the iterable sniff results container
MAX_IP_LEN = 15  # Max IP address column length
MAX_MAC_LEN = 18  # Max MAC address column length
MAX_REQ_LEN = 6  # Max ARP request column length
MAX_REP_LEN = 6  # Max ARP reply column length
ALL_COLUMNS = MAX_IP_LEN, MAX_MAC_LEN, MAX_REQ_LEN, MAX_REP_LEN
MAX_ALL_LEN = sum(ALL_COLUMNS) + len(ALL_COLUMNS) * len(' | ')

######################
# LAYER 2 RAW SOCKET #
######################
SOC_BUF = 42  # Buffer size in bytes
SOC_POR = 0  # Port to bind to an interface
SOC_PRO = 3  # GGP ( https://www.iana.org/assignments/protocol-numbers )

##################
# ETHERNET FRAME #
##################
SRC_MAC = None  # Source MAC address: Own MAC address
DST_MAC = 'ff' * 6  # Destination MAC address: Broadcast
ETH_TYP = '0806'  # EtherType: ARP

##############
# ARP HEADER #
##############
ARP_HWT = '0001'  # Hardware type: Ethernet
ARP_PRT = '0800'  # Protocol type: IPv4
ARP_HWS = '06'  # Hardware size: 6 bytes
ARP_PRS = '04'  # Protocol size: 4 bytes
ARP_REQ = '0001'  # Opcode: Req.
ARP_REP = '0002'  # Opcode: Rep.
SND_MAC = None  # Sender MAC address: Own MAC address
TGT_MAC = 'ff' * 6  # Target MAC address: Broadcast
