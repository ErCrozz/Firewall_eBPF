#!/usr/bin/env python3

import subprocess
import json
import socket
import struct
import time
import sys

#
# Soglie di esempio (User Space). 
# Se vuoi replicare *esattamente* la logica del kernel (count_udp_flows),
# imposta: 
#   PPS_THRESHOLD    = 35   (perché in eBPF hai 35000 => 35 pps reali)
#   BPS_THRESHOLD    = 150  (perché hai 150000 => 150 B/s reali)
#   PACKET_THRESHOLD = 100
#
PPS_THRESHOLD = 35
BPS_THRESHOLD = 150
PACKET_THRESHOLD = 100

def format_ip(ip_int):
    """
    Converte un indirizzo IP (in formato intero little-endian) 
    in una stringa dotted-decimal (es. "192.168.0.1").
    """
    return socket.inet_ntoa(struct.pack('<I', ip_int))

def parse_key_list(key_list):
    """
    Parsa la chiave flow_key da un array di stringhe esadecimali.
    Struttura in eBPF:
    
      struct flow_key {
         __u32 saddr; 
         __u32 daddr; 
         __u16 sport; 
         __u16 dport;
      };
    
    => Dimensione: 4 + 4 + 2 + 2 = 12 byte
    => Layout in little-endian: "<I I H H"
    """
    all_bytes = []
    for segment in key_list:
        for hex_byte in segment.split():
            all_bytes.append(int(hex_byte, 16))
    raw = bytes(all_bytes)

    saddr, daddr, sport, dport = struct.unpack("<I I H H", raw[:12])
    return saddr, daddr, sport, dport

def parse_value_list(value_list):
    """
    Parsa la struct flow_stats dalla mappa eBPF.
    Nel tuo programma la struct è (senza padding extra):
    
      struct flow_stats {
          __u64 packet_count; // offset 0
          __u64 byte_count;   // offset 8
          __u64 first_ts;     // offset 16
          __u64 last_ts;      // offset 24
          __u64 avg_pps;      // offset 32
          __u64 avg_bps;      // offset 40
          __u8  is_blocked;   // offset 48
      };
      // Totale 49 byte
    """
    all_bytes = []
    for segment in value_list:
        for hex_byte in segment.split():
            all_bytes.append(int(hex_byte, 16))
    raw = bytes(all_bytes)

    # unpack dei 49 byte (6 campi a 64 bit + 1 byte)
    packet_count, byte_count, first_ts, last_ts, avg_pps, avg_bps, blocked = \
        struct.unpack("<Q Q Q Q Q Q B", raw[:49])

    return {
        "packet_count": packet_count,
        "byte_count":   byte_count,
        "first_ts":     first_ts,
        "last_ts":      last_ts,
        "avg_pps":      avg_pps,   # in eBPF: pps * 1000
        "avg_bps":      avg_bps,   # in eBPF: B/s * 1000
        "blocked":      blocked
    }

def pack_key_value(saddr, daddr, sport, dport, stats):
    """
    Ricostruisce i byte di chiave e valore pronti per:
        bpftool map update id <map_id> key hex ... value hex ...
    """
    # Chiave
    key_bytes = struct.pack("<I I H H", saddr, daddr, sport, dport)
    key_hex   = " ".join(f"{b:02x}" for b in key_bytes)

    # Valore
    # Ricordati di rispettare l'ordine e i tipi
    packet_count = stats["packet_count"]
    byte_count   = stats["byte_count"]
    first_ts     = stats["first_ts"]
    last_ts      = stats["last_ts"]
    avg_pps      = stats["avg_pps"]
    avg_bps      = stats["avg_bps"]
    blocked      = stats["blocked"]

    value_bytes = struct.pack("<Q Q Q Q Q Q B", 
                              packet_count, 
                              byte_count, 
                              first_ts, 
                              last_ts, 
                              avg_pps, 
                              avg_bps,
                              blocked)
    value_hex   = " ".join(f"{b:02x}" for b in value_bytes)

    return key_hex, value_hex

def update_block_flag(map_id, saddr, daddr, sport, dport, stats):
    """
    Imposta blocked = 1 nella struct flow_stats e aggiorna la mappa eBPF.
    """
    stats["blocked"] = 1  # settiamo il flag
    key_hex, value_hex = pack_key_value(saddr, daddr, sport, dport, stats)

    cmd_update = [
        "bpftool", "map", "update", "id", str(map_id),
        "key", "hex", *key_hex.split(),
        "value", "hex", *value_hex.split()
    ]
    result = subprocess.run(cmd_update, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Errore in 'bpftool map update': {result.stderr}")

def get_ebpf_map_data(map_id):
    """
    Ritorna l'output JSON di 'bpftool map dump id <map_id> -j'.
    """
    try:
        result = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id), "-j"],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Errore nell'esecuzione di bpftool: {e}")
    except json.JSONDecodeError:
        print("Errore nella decodifica JSON della risposta di bpftool.")
    return None

def clear_console():
    """Pulisce la console."""
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()

def main():
    map_id = input("Inserisci l'ID della mappa eBPF: ")
    print(f"Leggendo la mappa con ID {map_id}... (Ctrl+C per uscire)")

    try:
        while True:
            data = get_ebpf_map_data(map_id)
            if data:
                clear_console()
                print("\n--- Tabella eBPF ---")
                for idx, entry in enumerate(data, start=1):
                    # Chiave
                    saddr, daddr, sport, dport = parse_key_list(entry["key"])
                    # Valore (flow_stats)
                    stats = parse_value_list(entry["value"])

                    src_ip = format_ip(saddr)
                    dst_ip = format_ip(daddr)

                    # Converto sport/dport da little-endian a "host order" (big-endian) per la stampa
                    sport_host = struct.unpack('!H', struct.pack('<H', sport))[0]
                    dport_host = struct.unpack('!H', struct.pack('<H', dport))[0]

                    # Calcolo di supporto
                    duration_ns  = stats["last_ts"] - stats["first_ts"]
                    duration_sec = duration_ns / 1e9 if duration_ns > 0 else 0.0

                    # In eBPF, avg_pps e avg_bps sono scalati di *1000
                    real_pps = stats["avg_pps"] / 1000.0
                    real_bps = stats["avg_bps"] / 1000.0

                    # Eventuale "logica di blocco" in user space (facoltativa)
                    # Se vuoi replicare EXACT la logica del kernel, controlliamo:
                    #   (packet_count > 5) AND (real_pps > 35) => poi bps o count ...
                    #   Qui, semplifichiamo: se superiamo una di queste soglie, blocchiamo.
                    is_blocked_user = (
                        (real_pps > PPS_THRESHOLD) or
                        (real_bps > BPS_THRESHOLD) or
                        (stats["packet_count"] > PACKET_THRESHOLD)
                    )

                    # Se nel kernel non è ancora bloccato, ma lo "vorremmo" bloccare da user space:
                    if is_blocked_user and stats["blocked"] == 0:
                        update_block_flag(map_id, saddr, daddr, sport, dport, stats)

                    # Ricarichiamo il flag dopo l'eventuale update
                    blocked_kernel = (stats["blocked"] == 1)
                    status_str = "BLOCCATO" if blocked_kernel else "CONSENTITO"

                    print(f"Flusso #{idx}:")
                    print(f"  IP Sorgente:       {src_ip}, Porta Sorg: {sport_host}")
                    print(f"  IP Destinazione:   {dst_ip}, Porta Dest: {dport_host}")
                    print(f"  Pacchetti totali:  {stats['packet_count']}")
                    print(f"  Byte totali:       {stats['byte_count']}")
                    print(f"  Durata flusso:     {duration_sec:.2f} sec")
                    print(f"  PPS medio (kernel): {real_pps:.2f} p/s")
                    print(f"  BPS medio (kernel): {real_bps:.2f} B/s")
                    print(f"  blocked (kernel):  {blocked_kernel}")
                    print(f"  Stato:             {status_str}")
                    print("-------------------------")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nChiusura dello script.")

if __name__ == "__main__":
    main()
