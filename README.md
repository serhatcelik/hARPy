```
|_  _  _ _      | Fast   : False     | Hosts   : 0
| |(_|| |_)\/   | Filter : False     | Replies : 0
        |  /    | Passive: True      | Requests: 0
------------------------------------------------------------------------
Exit with ^C    |
------------------------------------------------------------------------
IP Address      | MAC Address        | Reply   | Request | Vendor
------------------------------------------------------------------------

```

# Features

- Suspicious packet detection.
- Active (fast or normal) or passive scanning option.
- Ability to send packets from a fake IP address.
- Ability to filter the results using the given scanning range.
- Ability to show number of hosts and ARP reply/request count.
- Option to determine the amount of ARP requests to be sent.
- Option to determine the sleep time between each ARP request.

# Supported OSs

- GNU/Linux

# Tested Distributions

- Kali Linux 2020.3
- Linux Mint 20 Ulyana
- openSUSE Leap 15.2
- Pardus 19.4
- Ubuntu 20.04.1 LTS

# Preparation

> apt (Ubuntu, Debian)
```
# apt update
# apt install python3 python3-pip
```

> zypper (openSUSE)
```
# zypper refresh
# zypper install python3 python3-pip
```

# Installation

```
# pip3 install harpy-prjct
```

# Upgrade

```
# pip3 install harpy-prjct --upgrade
```

# Usage

```
# harpy -h
```
```
usage: harpy [-h] [-a] [-c count] [-f] [-F] [-i interface] [-l] [-n node] [-p]
             [-r range [range ...]] [-s time] [-t time] [-v]

- Active/passive ARP discovery tool -

optional arguments:
  -h, --help            show this help message and exit
  -a                    show program author information and exit
  -c count              number of times to send each request (def:1|min:1)
  -f                    fast mode, only scan for specific hosts
  -F                    filter the sniff results using the given scanning range
  -i interface          network device to send/sniff packets
  -l                    show logs and exit
  -n node               last ip octet to be used to send packets (def:43|min:2|max:253)
  -p                    passive mode, do not send any packets
  -r range [range ...]  scanning range
  -s time               time to sleep between each request in ms (def:3|min:3|max:1000)
  -t time               timeout to stop scanning in sec (def:inf|min:10)
  -v                    show program version and exit

Written by Serhat Çelik ( https://github.com/serhatcelik/harpy )
```

# Examples

> Active scanning for common IP addresses in fast mode
```
# harpy -f
```

> Passive scanning on eth0
```
# harpy -i eth0 -p
```

> Scan a fixed range with a count value of 2
```
# harpy -r 192.168.0.1/24 -c 2
```

> Scan some fixed ranges with filtering
```
# harpy -r 172.16.0.1/16 10.0.0.1/8 -F
```

# Contact

If you find a bug or have a suggestion, please consider to mail me at <prjctsrht@gmail.com>
