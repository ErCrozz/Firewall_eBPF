#!/usr/bin/env python3
from scapy.all import *
import threading
import time

DEST_IP = "192.168.2.2"
DEST_PORT = 9999
NUM_SENDERS = 1000
INTERVAL = 1  # 1 packet per second

def sender_thread(id):
    pkt = IP(dst=DEST_IP)/UDP(dport=DEST_PORT)/Raw(load=f"sender{id}")
    while True:
        send(pkt, verbose=False)
        time.sleep(INTERVAL)

print(f"Lancio {NUM_SENDERS} sender con 1 pps ciascuno...")

threads = []
for i in range(NUM_SENDERS):
    t = threading.Thread(target=sender_thread, args=(i,), daemon=True)
    t.start()
    threads.append(t)

# Mantiene vivo il processo principale
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Terminazione manuale.")
