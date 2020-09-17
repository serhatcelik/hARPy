# hARPy

Active/passive ARP discovery tool.

---

# Features

- Suspicious packet detection.
- Active or passive scan option.
- Ability to send packets from a fake IP address.
- Option to determine the amount of ARP requests to be sent.
- Option to determine the sleep time between each ARP request.

---

# Supported Platforms

Linux only.

---

# Preparation (APT)

```shell script
# apt update
# apt install python3 python3-pip
```

---

# Installation

```shell script
# pip3 install harpy-prjct
```

---

# Upgrade

```shell script
# pip3 install --upgrade harpy-prjct
```

---

# Usage

```shell script
# harpy -h
```
```
usage: harpy [-h] [-c count] [-i interface] [-n node] [-p] -r range [-s sleep] [-v]

Written by Serhat Celik <prjctsrht@gmail.com>

optional arguments:
  -h, --help    show this help message and exit
  -c count      number of times to send each arp request (default: 1)
  -i interface  the network device to send/sniff packets (default: first available)
  -n node       last ip octet to be used to send packets (default: 43)
  -p            enable passive mode, do not send any packets
  -s sleep      time to sleep between each arp request in ms (default: 3)
  -v            show program version and exit

required arguments:
  -r range      scan a given range, e.g. 192.168.2.1/24 (valid: /8, /16, /24)

Use at your own risk!
```

---

# Examples

```shell script
# harpy -r 192.168.2.1/24
```
```
|_  _  _ _      | TOTAL HOST: 3
| |(_|| |_)\/   | TOTAL REQ.: 2
        |  /    | TOTAL REP.: 2
-----------------------------------------------------------------------------------------------------
IP ADDRESS      | ETH MAC ADDRESS   | ARP MAC ADDRESS   | REQ.   | REP.   | VENDOR
-----------------------------------------------------------------------------------------------------
192.168.2.1     | 18:28:61:xx:xx:xx | 18:28:61:xx:xx:xx | 0      | 1      | airties wireless networks
192.168.2.80    | 18:28:61:xx:xx:xx | 18:28:61:xx:xx:xx | 1      | 1      | airties wireless networks
192.168.2.240   | c8:60:00:xx:xx:xx | 18:28:61:xx:xx:xx | 1      | 0      | asustek computer inc.
```

---

# Uninstallation

```shell script
# pip3 uninstall harpy-prjct
```

---

# Contact

If you find a bug or have a suggestion, please consider [creating an issue](https://github.com/serhatcelik/hARPy/issues) to contact with me.
