# coding=utf-8
# This file is part of harpy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""
MIT License

Copyright (c) 2021 Serhat Çelik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

################
# Over Control #
################
RUN_MAIN = True
EXIT_MSGS = set()  # Container for storing exit messages
FAST_NODE = [1, 2, 100, 127, 200, 254]

# Flicker reduction times (in seconds)
WAIT_MAIN = 2
WAIT_SEND = float(2) / 10
WAIT_SNIFF = float(1) / 10

# Results
RESULT_A = list()  # Container for storing a sniff result
RESULT_ALL = list()  # Container for storing all sniff results

#############
# Locations #
#############
SYS_PATH = "/sys/class/net/"  # Directory that stores all interfaces
LOG_FILE = "/var/log/harpy.log"

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
NOD = None  # Node
PAS = None  # Passive
RNG = None  # Range
REP = None  # Repeat
SLP = None  # Sleep
TIM = None  # Timeout

# Defaults
DEF_CNT = 1
DEF_NOD = 43
DEF_RNG = ["192.168.0.1/16", "172.16.0.1/16", "10.0.0.1/8"]
DEF_SLP = 3  # In milliseconds
DEF_TIM = float("inf")  # In seconds

# Minimums
MIN_CNT = 1
MIN_NOD = 2
MIN_SLP = 2
MIN_TIM = 10

# Maximums
MAX_NOD = 253
MAX_SLP = 1000

#################
# Result Window #
#################
SEPARATOR = " | "
CONT_STP_SIZ = 7  # Step size for the iterable sniff results container
CONT_MAX_SIZ = ((256 ** 3) - 2 - 1) * CONT_STP_SIZ  # (/8 - (.0 + .255) - you)
ETHER_TO_ARP = False  # Ethernet MAC <-> ARP MAC
MAX_IP_LEN = 15
MAX_MAC_LEN = 18
MAX_REP_LEN = 7
MAX_REQ_LEN = 7
ALL_COLUMNS = [MAX_IP_LEN, MAX_MAC_LEN, MAX_REP_LEN, MAX_REQ_LEN]
MAX_ALL_LEN = sum(ALL_COLUMNS) + (len(ALL_COLUMNS) * len(SEPARATOR))

######################
# Layer 2 RAW Socket #
######################
MIN_BUF = 42  # Minimum buffer size in bytes (14 for Ethernet, 28 for ARP)
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
SND_IP = None  # Sender IP address
TGT_MAC = 6 * "ff"  # Target MAC address: Broadcast
TGT_IP = None  # Target IP address


#############
# Functions #
#############
def logo():
    return [
        r"|_  _  _ _   ",
        r"| |(_|| |_)\/",
        r"        |  / ",
    ]


def banner():
    return [
        ("Fast   : %s" % FST).ljust(MAX_MAC_LEN) + SEPARATOR + "Hosts   : ",
        ("Filter : %s" % FLT).ljust(MAX_MAC_LEN) + SEPARATOR + "Replies : ",
        ("Passive: %s" % PAS).ljust(MAX_MAC_LEN) + SEPARATOR + "Requests: ",
    ]


def add_colons(mac):
    """
    Adds colons to the given MAC address.

    :param mac: MAC address to be added with colons.
    """

    return ":".join(mac[_:_ + 2] for _ in range(0, len(mac), 2))


def add_dots(text, width, xref=0):
    """
    Creates a new dotted text if the text length exceeds the width.

    :param text: Text to be shortened.
    :param width: Terminal width.
    :param xref: X coordinate where the text will begin.
    """

    # Terminal width is "None" when there is no active terminal is found, so...
    if width is not None:
        if (xref + len(str(text))) > width:
            return str(text[:width - xref - len("...")]) + "..."
    return str(text)


def check_ip(ip_addr, range_):
    """
    Checks an IP address using the given scanning range.

    :param ip_addr: IP address to check.
    :param range_: Scanning range.
    """

    i = {"24": 3, "16": 2, "8": 1}  # Scanning range slicing indexes by prefix

    return any([ip_addr.split(".")[:i[_[-1]]] == _[:i[_[-1]]] for _ in range_])


def first_last(range_):
    """
    Determines the first/last IP address using the given scanning range.

    :param range_: Scanning range.
    """

    if range_[-1] == "24":
        first_ip = ".".join([range_[0], range_[1], range_[2], "1"])
        last_ip = ".".join([range_[0], range_[1], range_[2], "254"])
    elif range_[-1] == "16":
        first_ip = ".".join([range_[0], range_[1], "0", "1"])
        last_ip = ".".join([range_[0], range_[1], "255", "254"])
    else:
        first_ip = ".".join([range_[0], "0", "0", "1"])
        last_ip = ".".join([range_[0], "255", "255", "254"])

    return [first_ip, last_ip]


def run_main(run, timed_out=False):
    """
    The controller of the main thread of the program.

    :param run: Determines whether the program will continue to run.
    :param timed_out: True if timed out False otherwise.
    """

    if (not run) or timed_out or (len(RESULT_ALL) > CONT_MAX_SIZ):
        if timed_out:
            EXIT_MSGS.add("Exiting, timed out")
        elif len(RESULT_ALL) > CONT_MAX_SIZ:
            EXIT_MSGS.add("Exiting, no space left in the container")

        globals()["RUN_MAIN"] = False
