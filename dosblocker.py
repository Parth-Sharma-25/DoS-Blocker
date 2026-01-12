from scapy.all import sniff, IP, IPv6
from collections import defaultdict, deque
import time
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import os

THRESHOLD = 1500
WINDOW = 3
INTERFACE = "eth0"
BLOCK_FILE = "/var/run/dos_blocklist.txt"

traffic = defaultdict(deque)
blocked = set()

if not os.path.exists(BLOCK_FILE):
    open(BLOCK_FILE, "w").close()

root = tk.Tk()
root.title("DoS Detector")
root.geometry("1980x980")
root.configure(bg="#556B2F")   

frame = tk.Frame(root, bg="#556B2F")
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

l_box = ScrolledText(
    frame,
    bg="#90EE90",        
    fg="#00008B",       
    font=("Consolas", 10),
    wrap=tk.WORD
)
l_box.pack(fill=tk.BOTH, expand=True)

def i_log(msg):
    l_box.insert(tk.END, msg + "\n")
    l_box.see(tk.END)

def mark_block(ip):
    blocked.add(ip)
    with open(BLOCK_FILE, "a") as f:
        f.write(ip + "\n")
    i_log(f"[BLOCKED] {ip}")

def on_packet(pkt):
    now = time.time()

    if IP in pkt:
        src = pkt[IP].src
    elif IPv6 in pkt:
        src = pkt[IPv6].src
    else:
        return

    traffic[src].append(now)

    while traffic[src] and now - traffic[src][0] > WINDOW:
        traffic[src].popleft()

    rate = len(traffic[src]) / WINDOW

    if rate > 50:
        i_log(f"{src} → {int(rate)} pps")

    if rate > THRESHOLD and src not in blocked:
        i_log(f"[ATTACK] {src} → {int(rate)} pps")
        mark_block(src)

def start_sniffer():
    i_log(f"Listening on {INTERFACE} ...")
    sniff(iface=INTERFACE, filter="ip or ip6", prn=on_packet, store=False)

threading.Thread(target=start_sniffer, daemon=True).start()

i_log("DoS Detection System Started")
root.mainloop()
