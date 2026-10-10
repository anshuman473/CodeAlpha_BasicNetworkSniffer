#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures live network packets with Scapy and prints useful details:
source/destination IP, protocol, ports, TCP flags and a payload preview.

Usage (needs administrator/root rights to capture packets):
    sudo python3 sniffer.py                    # capture until Ctrl+C
    sudo python3 sniffer.py -c 20              # capture 20 packets
    sudo python3 sniffer.py -i eth0 -f "tcp port 80"
    sudo python3 sniffer.py -c 50 -o capture.pcap

Install dependency:
    pip install scapy
(On Windows also install Npcap from https://npcap.com and run as Administrator.)

Use ONLY on networks you own or have permission to monitor.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw

packet_count = 0
protocol_stats = {}


def count(proto):
    protocol_stats[proto] = protocol_stats.get(proto, 0) + 1


def payload_preview(packet, max_len=60):
    """Return a printable preview of the packet payload."""
    if Raw in packet:
        data = bytes(packet[Raw].load)[:max_len]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return f"{text}  (len={len(packet[Raw].load)} bytes)"
    return "-"


def process_packet(packet):
    global packet_count
    packet_count += 1
    time = datetime.now().strftime("%H:%M:%S")

    print(f"\n[{packet_count}] {time} " + "-" * 50)

    # ARP (layer 2/3, no IP header)
    if ARP in packet:
        op = "request" if packet[ARP].op == 1 else "reply"
        print(f"Protocol : ARP ({op})")
        print(f"Source   : {packet[ARP].psrc}  ({packet[ARP].hwsrc})")
        print(f"Dest     : {packet[ARP].pdst}")
        count("ARP")
        return

    # IP layer
    if IP in packet:
        src, dst, ttl = packet[IP].src, packet[IP].dst, packet[IP].ttl
    elif IPv6 in packet:
        src, dst, ttl = packet[IPv6].src, packet[IPv6].dst, packet[IPv6].hlim
    else:
        print("Non-IP packet:", packet.summary())
        count("Other")
        return

    # Transport layer
    if TCP in packet:
        proto = "TCP"
        sport, dport = packet[TCP].sport, packet[TCP].dport
        extra = f"Flags    : {packet[TCP].flags}"
    elif UDP in packet:
        proto = "UDP"
        sport, dport = packet[UDP].sport, packet[UDP].dport
        extra = ""
    elif ICMP in packet:
        proto = "ICMP"
        sport = dport = None
        extra = f"Type     : {packet[ICMP].type}  Code: {packet[ICMP].code}"
    else:
        proto = "Other"
        sport = dport = None
        extra = ""

    count(proto)
    print(f"Protocol : {proto}")
    print(f"Source   : {src}" + (f":{sport}" if sport else ""))
    print(f"Dest     : {dst}" + (f":{dport}" if dport else ""))
    print(f"TTL      : {ttl}   Size: {len(packet)} bytes")
    if extra:
        print(extra)

    # Application hints
    if DNS in packet and packet.haslayer(DNSQR):
        print(f"DNS Query: {packet[DNSQR].qname.decode(errors='ignore')}")
    elif TCP in packet and 80 in (sport, dport):
        print("App      : HTTP (unencrypted)")
    elif TCP in packet and 443 in (sport, dport):
        print("App      : HTTPS (encrypted payload)")

    print(f"Payload  : {payload_preview(packet)}")


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (Scapy)")
    parser.add_argument("-i", "--interface", help="Interface to sniff on (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    parser.add_argument("-o", "--output", help="Save captured packets to a .pcap file")
    args = parser.parse_args()

    print("Starting sniffer... press Ctrl+C to stop.")
    try:
        packets = sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=process_packet,
            count=args.count,
            store=bool(args.output),
        )
    except PermissionError:
        print("Permission denied: run as root/Administrator.")
        return
    except KeyboardInterrupt:
        packets = []

    print("\n" + "=" * 60)
    print(f"Captured {packet_count} packets")
    for proto, n in sorted(protocol_stats.items(), key=lambda x: -x[1]):
        print(f"  {proto:<6}: {n}")

    if args.output and packets:
        wrpcap(args.output, packets)
        print(f"Saved to {args.output} (open it in Wireshark)")


if __name__ == "__main__":
    main()
