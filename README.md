🛡️ DoS Detection System (Python + Scapy + GUI)

A real-time Denial-of-Service (DoS) Detection System built using Python, Scapy, and Tkinter, designed to monitor network traffic and identify suspicious packet floods in a Linux environment.

This project follows a safe IDS (Intrusion Detection System) architecture: it detects abnormal behavior and logs it, rather than directly manipulating the firewall.

📌 Features

Real-time packet capture using Scapy

Detects DoS attacks based on packet rate per IP

Uses a sliding time window to avoid false positives

Supports IPv4 and IPv6

GUI Dashboard 
Logs detected attackers into a blocklist file

Designed for Kali Linux in VMware

🖥️ GUI Preview

The interface shows:

Live traffic rates per IP

Detected attacks

Blocked IP addresses

🧰 Technologies Used

    Python 3
    Shell Scripting
    Scapy
    Time 
    Tkinter
    Collections
    Linux (Kali)
    Threading
    VMware
    OS
Networking & Cybersecurity

⚙️  How It Works

The system captures packets on the network interface (eth0)

Each source IP is tracked in a time window

Packet rate (packets/sec) is calculated

If the rate exceeds a defined threshold, the IP is marked as an attacker

The IP is added to a blocklist file and displayed in the GUI

This simulates how professional Intrusion Detection Systems identify DoS behavior.

▶️ How to Run
1. Install dependencies: 
sudo apt update
sudo apt install python3-scapy python3-tk

2. Run the detector: 
sudo python3 dos_detector_gui.py

3. Run the shell script: 
sudo watch -n 5 ./firewall_sync.sh

Root privileges are required to capture packets.

🧪 Testing (Lab Setup)

This project is tested in a VMware lab:

Kali Linux runs the detector

Host machine sends traffic to the Kali VM’s IP

Scapy monitors packets arriving on eth0

Traffic from outside the VM crosses the virtual network and is detected.

📁 Output

Detected IPs are written to:

/var/run/dos_blocklist.txt


This file can be used by an external firewall or security tool.

🔐 Security Note

This project is designed for educational and defensive purposes only.
It does not block network traffic directly — it only detects and logs suspicious behavior.

📚 Learning Outcomes

Through this project, you gain hands-on experience with:

Network packet analysis

DoS attack detection techniques

Linux networking

IDS design principles

Python-based security tools
