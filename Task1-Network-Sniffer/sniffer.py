#!/usr/bin/env python3
"""
Advanced Network Sniffer
Cybersecurity Internship - Task 1 (Upgraded Version)
Author: Umer Zafar
Description: Captures live network packets, analyzes structure,
saves to PCAP file, and shows protocol statistics.
"""

import argparse
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Global counters and storage
packet_count = 0
captured_packets = []
protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other/Non-IP": 0}


def process_packet(packet):
    global packet_count
    packet_count += 1
    captured_packets.append(packet)

    print(f"\n{'='*60}")
    print(f"Packet #{packet_count} | Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"[+] Source IP      : {ip_layer.src}")
        print(f"[+] Destination IP : {ip_layer.dst}")
        print(f"[+] TTL            : {ip_layer.ttl}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            protocol_stats["TCP"] += 1
            print(f"[+] Protocol       : TCP")
            print(f"[+] Source Port    : {tcp_layer.sport}")
            print(f"[+] Destination Port: {tcp_layer.dport}")
            print(f"[+] Flags          : {tcp_layer.flags}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            protocol_stats["UDP"] += 1
            print(f"[+] Protocol       : UDP")
            print(f"[+] Source Port    : {udp_layer.sport}")
            print(f"[+] Destination Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            protocol_stats["ICMP"] += 1
            print(f"[+] Protocol       : ICMP")

        else:
            protocol_stats["Other/Non-IP"] += 1
            print(f"[+] Protocol       : Other (proto num: {ip_layer.proto})")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded = payload.decode('utf-8', errors='replace')
                print(f"[+] Payload (first 100 chars): {decoded[:100]}")
            except Exception:
                print(f"[+] Payload (raw bytes): {payload[:50]}")
    else:
        protocol_stats["Other/Non-IP"] += 1
        print("[!] Non-IP packet captured (e.g., ARP/IPv6 Discovery)")


def print_summary():
    print(f"\n{'#'*60}")
    print("#  CAPTURE SUMMARY")
    print(f"{'#'*60}")
    print(f"Total Packets Captured : {packet_count}")
    for proto, count in protocol_stats.items():
        percentage = (count / packet_count * 100) if packet_count > 0 else 0
        print(f"  {proto:15s}: {count:5d}  ({percentage:.1f}%)")
    print(f"{'#'*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer - Cybersecurity Internship Task")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite until Ctrl+C)")
    parser.add_argument("-f", "--filter", type=str, default="",
                         help="BPF filter, e.g. 'tcp', 'udp', 'icmp', 'port 80'")
    parser.add_argument("-o", "--output", type=str, default="capture.pcap",
                         help="Output PCAP filename (default: capture.pcap)")
    args = parser.parse_args()

    print("="*60)
    print("   ADVANCED NETWORK SNIFFER - Starting Capture")
    print(f"   Filter: {args.filter if args.filter else 'None (all traffic)'}")
    print(f"   Packet limit: {args.count if args.count > 0 else 'Unlimited (Ctrl+C to stop)'}")
    print("="*60)

    sniff(prn=process_packet, store=False, count=args.count,
          filter=args.filter if args.filter else None)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()
        if captured_packets:
            filename = "capture.pcap"
            wrpcap(filename, captured_packets)
            print(f"[+] Packets saved to: {filename}")
            print(f"[+] Open this file in Wireshark to analyze visually.")
