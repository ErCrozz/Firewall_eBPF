#!/usr/bin/env python3
from scapy.all import *
import time

DEST_IP = "192.168.2.2"
DEST_PORT = 9999
INTERVAL = 1 / 1000  # 1000 pps → 1ms tra pacchetti

pkt = IP(dst=DEST_IP)/UDP(dport=DEST_PORT)/Raw(load="ping")

print("Invio UDP a 1000 pps...")

while True:
    send(pkt, verbose=False)
    time.sleep(INTERVAL)
