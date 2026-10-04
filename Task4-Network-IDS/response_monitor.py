#!/usr/bin/env python3
"""
IDS Response Monitor
Cybersecurity Internship - Task 4
Author: Umer Zafar

Monitors Suricata's eve.json log in real-time and triggers
response actions when an intrusion alert is detected.
"""

import json
import time
import os
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"
INCIDENT_LOG = "incidents.log"
BLOCKED_IPS_FILE = "blocked_ips.txt"

# Keep track of IPs we've already "responded" to (avoid duplicate spam)
responded_ips = set()


def log_incident(alert_data):
    """Write a structured incident record to our incident log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = alert_data.get("src_ip", "unknown")
    dest_ip = alert_data.get("dest_ip", "unknown")
    signature = alert_data.get("alert", {}).get("signature", "unknown")
    severity = alert_data.get("alert", {}).get("severity", "unknown")

    entry = (f"[{timestamp}] INCIDENT DETECTED\n"
             f"  Signature : {signature}\n"
             f"  Source IP : {src_ip}\n"
             f"  Dest IP   : {dest_ip}\n"
             f"  Severity  : {severity}\n"
             f"  Action    : Logged + Flagged for review\n"
             f"{'-'*60}\n")

    with open(INCIDENT_LOG, "a") as f:
        f.write(entry)

    print(f"\n🚨 ALERT DETECTED [{timestamp}]")
    print(f"   Signature: {signature}")
    print(f"   {src_ip} -> {dest_ip}")
    print(f"   Response: Incident logged to {INCIDENT_LOG}")

    return src_ip


def flag_repeat_offender(src_ip):
    """
    Response mechanism: if the same source IP triggers multiple
    alerts, flag it as a repeat offender and record it as
    'recommended for blocking' (simulated response action).
    """
    if src_ip in responded_ips:
        return  # already handled

    responded_ips.add(src_ip)

    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(f"{src_ip} - flagged {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    print(f"   ⚠️  {src_ip} added to watchlist (blocked_ips.txt)")


def monitor():
    print("="*60)
    print("   IDS RESPONSE MONITOR - Watching for alerts")
    print(f"   Reading from: {EVE_LOG}")
    print("   Press Ctrl+C to stop")
    print("="*60)

    # Open the file and seek to the end (only watch NEW alerts)
    with open(EVE_LOG, "r") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # We only care about "alert" type events
            if data.get("event_type") == "alert":
                src_ip = log_incident(data)
                flag_repeat_offender(src_ip)


if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n\n[!] Monitor stopped by user.")
        print(f"[!] Total unique source IPs flagged: {len(responded_ips)}")
    except FileNotFoundError:
        print(f"[!] ERROR: {EVE_LOG} not found. Is Suricata running?")
    except PermissionError:
        print("[!] ERROR: Permission denied. Run this script with sudo.")
