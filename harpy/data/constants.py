# This file is part of hARPy

# RAW SOCKET ##################################################################
SOC_PRO = 3  # Protocol: GGP (ETH_P_ALL)                                      #
SOC_POR = 0  # Port to bind the interface                                     #
SOC_BUF = 42  # Buffer size in bytes                                          #
# ETHERNET FRAME ##############################################################
ETH_DST = "ff" * 6  # Destination: Broadcast                                  #
# Source: (Reserved)                                                          #
ETH_TYP = "0806"  # EtherType: ARP (ETH_P_ARP)                                #
# ARP HEADER ##################################################################
ARP_HWT = "0001"  # Hardware type: Ethernet                                   #
ARP_PRT = "0800"  # Protocol type: IPv4                                       #
ARP_HWS = "06"  # Hardware size: 6 bytes                                      #
ARP_PRS = "04"  # Protocol size: 4 bytes                                      #
ARP_REQ = "0001"  # Opcode: Request                                           #
# Sender MAC Address: (Reserved)                                              #
# Sender IP Address: (Reserved)                                               #
ARP_DST = "ff" * 6  # Target MAC address: Broadcast                           #
# Target IP Address: (Reserved)                                               #
###############################################################################
