#!/usr/bin/env python3
"""
IDS Alert Visualizer
Cybersecurity Internship - Task 4
Author: Umer Zafar

Reads Suricata's eve.json log and generates visual charts
showing alert statistics (by signature, by source IP, over time).
"""

import json
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"


def load_alerts():
    alerts = []
    with open(EVE_LOG, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alerts.append(data)
            except json.JSONDecodeError:
                continue
    return alerts


def plot_alerts_by_signature(alerts):
    signatures = [a.get("alert", {}).get("signature", "unknown") for a in alerts]
    counts = Counter(signatures)

    plt.figure(figsize=(10, 6))
    plt.barh(list(counts.keys()), list(counts.values()), color="crimson")
    plt.xlabel("Number of Alerts")
    plt.title("IDS Alerts by Signature Type")
    plt.tight_layout()
    plt.savefig("alerts_by_signature.png")
    print("[+] Saved: alerts_by_signature.png")
    plt.close()


def plot_alerts_by_source_ip(alerts):
    src_ips = [a.get("src_ip", "unknown") for a in alerts]
    counts = Counter(src_ips)
    top = counts.most_common(10)

    if not top:
        print("[!] No source IP data to plot.")
        return

    labels, values = zip(*top)
    plt.figure(figsize=(10, 6))
    plt.bar(labels, values, color="steelblue")
    plt.xlabel("Source IP")
    plt.ylabel("Number of Alerts")
    plt.title("Top Source IPs Triggering Alerts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("alerts_by_source_ip.png")
    print("[+] Saved: alerts_by_source_ip.png")
    plt.close()


def plot_alerts_timeline(alerts):
    timestamps = []
    for a in alerts:
        ts = a.get("timestamp", "")
        try:
            dt = datetime.strptime(ts.split(".")[0], "%Y-%m-%dT%H:%M:%S")
            timestamps.append(dt)
        except (ValueError, IndexError):
            continue

    if not timestamps:
        print("[!] No timestamp data to plot.")
        return

    timestamps.sort()
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, range(1, len(timestamps) + 1), marker="o", color="darkorange")
    plt.xlabel("Time")
    plt.ylabel("Cumulative Alert Count")
    plt.title("IDS Alerts Over Time")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("alerts_timeline.png")
    print("[+] Saved: alerts_timeline.png")
    plt.close()


def main():
    alerts = load_alerts()
    print(f"[+] Loaded {len(alerts)} alert(s) from {EVE_LOG}")

    if not alerts:
        print("[!] No alerts found. Generate some traffic first (e.g., ping).")
        return

    plot_alerts_by_signature(alerts)
    plot_alerts_by_source_ip(alerts)
    plot_alerts_timeline(alerts)
    print("\n[+] All charts generated successfully!")


if __name__ == "__main__":
    main()
