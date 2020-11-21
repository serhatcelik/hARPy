# This file is part of harpy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Global variables and functions for handling external modules."""

VERSION = "2020.11.21.post1"
AUTHOR = "Serhat Çelik"
AUTHOR_EMAIL = "prjctsrht@gmail.com"
PROJECT_URL = "https://github.com/serhatcelik/harpy"

################
# Over Control #
################
RUN_MAIN = True
THREADS = list()  # Container for storing threads
EXIT_MSGS = set()  # Container for storing exit messages

# Flicker reduction
WAIT_MAIN = 2
WAIT_SEND = .1
WAIT_SNIFF = .05

# Threads
SEND_FAST = 1, 2, 100, 127, 200, 254  # Last IP octets for fast mode
SEND_ADDRESS = None
SEND_FINISHED = False
SNIFF_A = list()  # Container for storing a sniff result
SNIFF_ALL = list()  # Container for storing all sniff results

#############
# Locations #
#############
SYS_PATH = "/sys/class/net/"
LOG_FILE = "/var/log/harpy-error.log"

###########
# Signals #
###########
# Signals to be caught
HUP = 1  # Hangup detected on controlling terminal

# Signals to be ignored
CHLD = 17  # Child stopped or terminated
WINCH = 28  # Window resize signal (4.3BSD, Sun)

# Signals that cannot be caught or ignored
KILL = 9  # Kill signal
STOP = 19  # Stop process

CATCHABLE_SIGNALS = [_ for _ in range(1, 65) if _ not in [KILL, STOP, 32, 33]]
CATCH_SIGNALS = [_ for _ in CATCHABLE_SIGNALS if _ not in [CHLD, WINCH]]
IGNORE_SIGNALS = [_ for _ in CATCHABLE_SIGNALS if _ not in [HUP]]

##########
# Styles #
##########
RESET = "\x1B[0m"
BOLD = "\x1B[1m"
RED = BOLD + "\x1B[31m"
GREEN = BOLD + "\x1B[32m"
YELLOW = BOLD + "\033[33m"
BLUE = BOLD + "\x1B[34m"
RE_ANSI = r"\x1B\[([0-9]|[0-9]{2})m"  # ESC[ N m

#########
# Names #
#########
# Threads
SEND = "SendThread"
SNIFF = "SniffThread"

# Handlers
ECHO = "EchoHandler"
PARSER = "ParserHandler"
RESULT = "ResultHandler"
SIGNAL = "SignalHandler"
SOCKET = "SocketHandler"
WINDOW = "WindowHandler"

##########################
# Command-Line Arguments #
##########################
# Links
CNT = None  # Count
FST = None  # Fast
FLT = None  # Filter
INT = None  # Interface
LOG = None  # Log
NOD = None  # Node
PAS = None  # Passive
RNG = None  # Range
SLP = None  # Sleep
TIM = None  # Timeout

# Defaults
DEF_CNT = 1
DEF_NOD = 43
DEF_RNG = "192.168.0.1/16", "172.16.0.1/16", "10.0.0.1/8"
DEF_SLP = 3  # In milliseconds
DEF_TIM = float("inf")  # In seconds

# Minimums
MIN_CNT = 1
MIN_NOD = 2
MIN_SLP = 3
MIN_TIM = 10

# Maximums
MAX_NOD = 253
MAX_SLP = 1000

#################
# Result Window #
#################
CONT_STP_SIZ = 6  # Step size for the iterable sniff results container
ETHER_TO_ARP = False  # Ethernet MAC <-> ARP MAC
MAX_IP_LEN = 15
MAX_MAC_LEN = 18
MAX_REP_LEN = 7
MAX_REQ_LEN = 7
ALL_COLUMNS = MAX_IP_LEN, MAX_MAC_LEN, MAX_REP_LEN, MAX_REQ_LEN
MAX_ALL_LEN = sum(ALL_COLUMNS) + len(ALL_COLUMNS) * len(" | ")

######################
# Layer 2 RAW Socket #
######################
SOC_BUF = 42  # Buffer size in bytes
SOC_POR = 0  # Port to bind to an interface
SOC_PRO = 3  # GGP ( https://www.iana.org/assignments/protocol-numbers )

##################
# Ethernet Frame #
##################
SRC_MAC = None  # Source MAC address
DST_MAC = 6 * "ff"  # Destination MAC address: Broadcast
ETH_TYP = "0806"  # EtherType: ARP

##############
# ARP Header #
##############
ARP_HWT = "0001"  # Hardware type: Ethernet
ARP_PRT = "0800"  # Protocol type: IPv4
ARP_HWS = "06"  # Hardware size: 6 bytes
ARP_PRS = "04"  # Protocol size: 4 bytes
ARP_REQ = "0001"  # Opcode: Request
SND_MAC = None  # Sender MAC address
TGT_MAC = 6 * "ff"  # Target MAC address: Broadcast


#############
# Functions #
#############
def green(text):
    return GREEN + str(text) + RESET


def red(text):
    return RED + str(text) + RESET


def yellow(text):
    return YELLOW + str(text) + RESET


def logo():
    return [
        r"{1}|_ {2} _  _ _ {1}  {0}".format(RESET, BLUE, GREEN),
        r"{1}| |{2}(_|| |_){1}\/{0}".format(RESET, BLUE, GREEN),
        r"{1}   {2}     |  {1}/ {0}".format(RESET, BLUE, GREEN),
    ]


def banner():
    return [
        ("Fast   : %s" % FST).ljust(MAX_MAC_LEN) + " | Hosts   : ",
        ("Filter : %s" % FLT).ljust(MAX_MAC_LEN) + " | Replies : ",
        ("Passive: %s" % PAS).ljust(MAX_MAC_LEN) + " | Requests: ",
    ]


def add_colons(mac):
    """
    Adds colons to the given MAC address.

    :param mac: MAC address to be added with colons.
    """

    return ":".join(mac[_:_ + 2] for _ in range(0, len(mac), 2))


def add_dots(text, width, xref=0):
    """
    Returns a new dotted text if the text length exceeds the width.

    :param text: Text to be shortened.
    :param width: Terminal width.
    :param xref: X coordinate where the text will begin.
    """

    # Terminal width is None when there is no active terminal is found, so...
    if width is not None:
        if xref + len(str(text)) > width:
            return str(text[:width - xref - len("...")]) + "..."
    return str(text)


def check_ip(ip_address, range_):
    """
    Checks an IP address using the given scanning range.

    :param ip_address: IP address to check.
    :param range_: Scanning range.
    """

    __ = {"24": 3, "16": 2, "8": 1}  # Scanning range slicing indexes by prefix

    return any([
        ip_address.split(".")[:__[_[-1]]] == _[:__[_[-1]]] for _ in range_
    ])


def run_main(run, timed_out=False):
    """
    The controller of the main thread of the program.

    :param run: Determines whether the program will continue to run.
    :param timed_out: True if timed out False otherwise.
    """

    if not run or timed_out:
        if timed_out:
            EXIT_MSGS.add("Exiting, timed out")

        globals()["RUN_MAIN"] = False
