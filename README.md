# Features

- Suspicious packet detection.
- Active or passive scan option.
- Ability to send packets from a fake IP address.
- Ability to show number of hosts and ARP request/reply count.
- Option to determine the amount of ARP requests to be sent.
- Option to determine the sleep time between each ARP request.

---

# Supported Platforms

Linux only.

---

# Tested Platforms

- Kali Linux 2020.3
- Ubuntu 20.04.1 LTS

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
# pip3 install -U harpy-prjct
```

---

# Usage

```shell script
# harpy -h
```
```
usage: harpy [-h] [-a] [-c count] [-f] [-i interface] [-l] [-n node] [-p]
             [-r range] [-s sleep] [-t timeout] [-v]

By Serhat Çelik <prjctsrht@gmail.com> ( https://github.com/serhatcelik )

optional arguments:
  -h, --help     show this help message and exit
  -a, --author   show program author information and exit
  -c count       number of times to send each request (def|min: 1|1)
  -f, --filter   filter sniff results using the given scan range
  -i interface   network interface to send/sniff packets
  -l, --log      show where log files are stored and exit
  -n node        last ip octet to be used to send packets (def|min|max: 43|2|253)
  -p, --passive  enable passive mode, do not send any packets
  -r range       scan range, e.g. 192.168.2.1/24 (valid: /8, /16, /24)
  -s sleep       time to sleep between each request in ms (def|min|max: 3|3|1000)
  -t timeout     timeout to stop scanning in sec (def|min: 1800|5)
  -v, --version  show program version and exit

Use at your own risk!
```

---

# Example

```shell script
# harpy -r 192.168.2.1/24
```
```
|_  _  _ _        | TOTAL HOST: 3
| |(_|| |_)\/     | TOTAL REQ.: 2
        |  /      | TOTAL REP.: 1
--------------------------------------------------------------------------------------
PRESS ^C TO EXIT  | SENDING 192.168.2.134
--------------------------------------------------------------------------------------
IP ADDRESS        | MAC ADDRESS        | REQ.   | REP.   | VENDOR
--------------------------------------------------------------------------------------
192.168.2.1       | 18:28:61:xx:xx:xx  | 1      | 0      | airties wireless networks
192.168.2.80      | e4:58:e7:xx:xx:xx? | 0      | 1      | samsung electronics co.,ltd
192.168.2.133     | 4c:dd:31:xx:xx:xx  | 1      | 0      | samsung electronics co.,ltd
```

---

# Contact

If you find a bug or have a suggestion, please consider to mail me at <prjctsrht@gmail.com>
