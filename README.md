# CodeAlpha_BasicNetworkSniffer

Task 1 of the CodeAlpha Cyber Security Internship: a basic network sniffer in Python using Scapy.

## What it does
- Captures live packets from a network interface
- Shows source/destination IP and port, protocol (TCP, UDP, ICMP, ARP), TTL, size and TCP flags
- Detects DNS queries and flags HTTP vs HTTPS traffic
- Prints a payload preview and a protocol summary at the end
- Optionally saves captures to a `.pcap` file for Wireshark

## Setup
```
pip install scapy
```
Windows: install [Npcap](https://npcap.com) and run the terminal as Administrator.
Linux/macOS: run with `sudo`.

## Usage
```
sudo python3 sniffer.py                       # until Ctrl+C
sudo python3 sniffer.py -c 20                 # 20 packets
sudo python3 sniffer.py -f "tcp port 80"      # BPF filter
sudo python3 sniffer.py -c 50 -o capture.pcap # save to file
```

## Sample output
```
[1] 12:45:10 --------------------------------------------------
Protocol : TCP
Source   : 192.168.1.5:51544
Dest     : 142.250.195.46:443
TTL      : 64   Size: 66 bytes
Flags    : A
App      : HTTPS (encrypted payload)
Payload  : -
```

## How data flows (what I learned)
Ethernet frame -> IP header (addresses, TTL) -> TCP/UDP header (ports, flags) -> application data (HTTP, DNS...).
HTTPS payloads are encrypted, so only plain protocols like HTTP/DNS reveal readable content.

## Disclaimer
For learning only. Capture traffic only on networks you own or have permission to monitor.
