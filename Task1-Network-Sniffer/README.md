# Task 1: Basic Network Sniffer

## 📌 Project Overview
This project is part of a Cybersecurity Internship. It is a Python-based network sniffer built using the **Scapy** library. The tool captures live network traffic in real-time, analyzes packet structure, and displays key information such as source/destination IP addresses, protocols, ports, and payload data.

## 🎯 Objectives
- Capture live network packets using Python
- Analyze packet structure (Ethernet, IP, TCP/UDP/ICMP layers)
- Understand how data flows through a network
- Learn the basics of networking protocols
- Save captured traffic for further analysis in Wireshark

## 🛠️ Tools & Technologies Used
- **Python 3** — Programming language
- **Scapy** — Python library for packet manipulation and sniffing
- **Kali Linux** — Operating system (built for cybersecurity tasks)
- **Wireshark** — Used to visually inspect the saved PCAP file

## ⚙️ Features
- Captures live packets from the network interface
- Identifies protocol type: TCP, UDP, ICMP, or Non-IP (ARP/IPv6)
- Displays Source IP, Destination IP, Ports, TTL, and TCP flags
- Displays payload data (when unencrypted)
- Saves all captured packets into a `.pcap` file for Wireshark analysis
- Supports command-line arguments:
  - `-c` / `--count` → limit number of packets captured
  - `-f` / `--filter` → filter by protocol (e.g., tcp, udp, icmp)
  - `-o` / `--output` → custom output filename
- Displays a protocol-wise statistics summary at the end of capture

## 📂 Files in This Folder
| File | Description |
|------|-------------|
| `sniffer.py` | Main Python script for the network sniffer |
| `capture.pcap` | Sample captured traffic (open in Wireshark) |
| `README.md` | Project documentation (this file) |
| `Report.pdf` | Detailed report with explanation and screenshots |

## ▶️ How to Run

### 1. Install dependencies
```bash
sudo apt update
sudo apt install python3-scapy -y
```

### 2. Run the sniffer (requires root privileges)
```bash
sudo python3 sniffer.py
```

### 3. Run with options
```bash
# Capture only 20 packets
sudo python3 sniffer.py -c 20

# Capture only TCP traffic
sudo python3 sniffer.py -f "tcp"

# Capture 15 TCP packets and save to custom file
sudo python3 sniffer.py -c 15 -f "tcp" -o mycapture.pcap
```

### 4. Stop the sniffer
Press `Ctrl + C` — a summary of captured protocols will be displayed automatically.

### 5. View the results in Wireshark
```bash
wireshark capture.pcap
```

## 📊 Sample Output Summary
############################################################
#  CAPTURE SUMMARY
############################################################
Total Packets Captured : 693
  TCP            :   516  (74.5%)
  UDP            :    47  (6.8%)
  ICMP           :   129  (18.6%)
  Other/Non-IP   :     1  (0.1%)
############################################################
