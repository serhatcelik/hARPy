# hARPy

Active/passive ARP discovery tool.

## How It Works

Sends ARP (Address Resolution Protocol) requests (active mode only) for discovering the link layer addresses and sniffs for ARP replies.

## Features

- Supports...
    - ...Python version 3 (3.4, 3.5, 3.6, 3.7, 3.8, 3.9),
    - ...Python version 2 (2.7).
- Ability to...
    - ...detect suspicious packets during scanning,
    - ...scan active (normal or fast) or passive,
    - ...scan more than one range at the same time,
    - ...filter the results using the given scanning range,
    - ...send packets from a fake IP address,
    - ...show number of hosts and ARP reply/request counts.
- Option to determine...
    - ...the amount of ARP requests to be sent,
    - ...the sleep time between each ARP request.

## Tested OSs

- GNU/Linux
    - Kali Linux
        - 2020.4
        - 2020.3
    - Linux Mint
        - 20 "Ulyana"
    - openSUSE
        - Leap
            - 15.2
    - Pardus
        - 19.4
    - Ubuntu
        - 20.04.1 LTS

## Preparation and Installation

> For Python version 3 (recommended)

```
# pip3 install --upgrade pip
# pip3 install --upgrade setuptools
# pip3 install --upgrade harpy-prjct
```

> For Python version 2

```
# curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
# python2 get-pip.py
# pip2 install --upgrade pip
# pip2 install --upgrade setuptools
# pip2 install --upgrade harpy-prjct
```

If you want to use the program by downloading directly from GitHub without installing it from PyPI, do the following:

```
# git clone https://github.com/serhatcelik/harpy.git
# cd harpy
# python3 -m harpy --help
```

## Usage

```
# harpy --help
```

```
usage: harpy [-h] [-c count] [-f] [-F] [-i interface] [-l] [-L] [-n node] [-p]
             [-r range [range ...]] [-R] [-s time] [-t timeout] [-v]

hARPy - Active/passive ARP discovery tool
Written by Serhat Çelik <prjctsrht@gmail.com>

optional arguments:
  -h, --help            show this help message and exit
  -c count              number of times to send each request (def:1|min:1)
  -f, --fast            enable fast mode, only scan for specific hosts
  -F, --filter          filter the sniff results using the given scanning range
  -i interface          network device to send/sniff packets
  -l, --log             show log and exit
  -L, --license         show license and exit
  -n node               last ip octet to be used to send packets (def:43|min:2|max:253)
  -p, --passive         enable passive mode, do not send any packets
  -r range [range ...]  scanning range
  -R, --repeat          enable repeat mode, never stop sending packets
  -s time               time to sleep between each request in ms (def:3|min:2|max:1000)
  -t timeout            timeout to stop scanning in sec (def:inf|min:10)
  -v, --version         show program version and exit

It is recommended that you enable passive mode on networks with heavy packet flow.
See https://github.com/serhatcelik/harpy for more information.
```

## Examples

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

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Feedback

If you have found a bug or have a suggestion, please consider mailing me at <prjctsrht@gmail.com>
