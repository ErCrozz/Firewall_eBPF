#!/usr/bin/env python3

from scapy.all import *
import threading
import time

# Parametri da personalizzare
DEST_IP = "192.168.2.4"    # IP di destinazione dove è in ascolto l'eBPF
DEST_PORT = 8888           # Porta di destinazione arbitraria
SRC_PORT = 3333            # Porta sorgente arbitraria
PACKETS_PER_SECOND = 200   # Numero totale di pacchetti da inviare al secondo
NUM_THREADS = 4            # Numero di thread da utilizzare

def send_packets(thread_id, packets_per_second_per_thread):
    """Funzione per inviare pacchetti in un ciclo infinito."""
    pkt = IP(dst=DEST_IP) / UDP(sport=SRC_PORT, dport=DEST_PORT) / Raw(f"Thread {thread_id} data")
    interval = 1 / packets_per_second_per_thread  # Intervallo tra pacchetti

    print(f"[Thread {thread_id}] Invio di ~{packets_per_second_per_thread} pacchetti al secondo.")
    
    while True:
        send(pkt, verbose=False)
        time.sleep(interval)

def main():
    # Calcola quanti pacchetti per secondo deve inviare ciascun thread
    packets_per_second_per_thread = PACKETS_PER_SECOND // NUM_THREADS

    # Creazione e avvio dei thread
    threads = []
    for i in range(NUM_THREADS):
        thread = threading.Thread(target=send_packets, args=(i, packets_per_second_per_thread))
        thread.daemon = True  # Permette di terminare i thread con il programma principale
        threads.append(thread)
        thread.start()

    print(f"Avviati {NUM_THREADS} thread per inviare un totale di ~{PACKETS_PER_SECOND} pacchetti al secondo.")

    # Mantieni il programma in esecuzione
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente.")

if __name__ == "__main__":
    main()