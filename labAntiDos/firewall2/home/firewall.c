//Questo programma blocca i pacchetti dei flussi superiori a 35pps, avendo funzione di rate limiter.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Definizione delle soglie, definite considerando che:
// - avg_pps è calcolato come (pps * 1000)
// - avg_bps è calcolato come (bps * 1000)

#define PPS_THRESHOLD 35000ULL   // 35 pps (scalato)
#define BPS_THRESHOLD 150000ULL  // 150 byte/s (scalato)
#define COUNT_THRESHOLD 100ULL   // 100 pacchetti totali

// Strutture
struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct flow_stats {
    __u64 packet_count; // numero di pacchetti del flusso
    __u64 byte_count;   // numero di byte del flusso
    __u64 first_ts;     // timestamp primo pacchetto del flusso
    __u64 last_ts;      // timestamp ultimo pacchetto del flusso
    __u64 avg_pps;      // media pacchetti al secondo
    __u64 avg_bps;      // media byte al secondo
    __u8 is_blocked;    // flusso bloccato
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, 1024);
} flow_map SEC(".maps");

SEC("xdp")
int count_udp_flows(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)((void*)iph + ip_hdr_len);
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    struct flow_key key = {};
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;
    key.sport = udph->source;
    key.dport = udph->dest;

    __u64 ip_len = bpf_ntohs(iph->tot_len);
    __u64 now = bpf_ktime_get_ns();

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_map, &key);
    if (stats) {

        stats->packet_count += 1;
        stats->byte_count += ip_len;
        stats->last_ts = now;

        if (stats->packet_count > 1) {
            // calcolo duration
            __u64 duration_ns = stats->last_ts - stats->first_ts;
            if (duration_ns > 0) {
                // calcolo avg pps e avg bps
                stats->avg_pps = (stats->packet_count * 1000000000ULL * 1000) / duration_ns; // multiply by 1000 to have more precision
                stats->avg_bps = (stats->byte_count * 1000000000ULL * 1000) / duration_ns;
            }
        }
        // albero decisionale anti-DDoS
        // le medie sono cumulative quindi saranno precise dopo almeno 5 pacchetti
        if (stats->packet_count > 5){
            // se la media pacchetti al secondo è maggiore della soglia
            if (stats->avg_pps > PPS_THRESHOLD) {
                // se la media byte al secondo è maggiore della soglia
                if (stats->avg_bps > BPS_THRESHOLD) {
                    // il traffico in byte è elevato: possibile attacco DDoS
                    return XDP_DROP;
                } else if (stats->packet_count > COUNT_THRESHOLD) {
                    // anche se i bps non sono altissimi, il packet_count supera una soglia critica
                    return XDP_DROP;
                } else {
                    // traffico elevato in pps ma non abbastanza "pesante" in bps o count
                    return XDP_PASS;
                }
            } else {
                // flusso considerato benigno
                return XDP_PASS;
            }
        }
    } else {
        // primo pacchetto
        struct flow_stats new_stats = {};
        new_stats.packet_count = 1;
        new_stats.byte_count = ip_len;
        new_stats.first_ts = now;
        new_stats.last_ts = now;
        new_stats.avg_pps = 0;
        new_stats.avg_bps = 0;
        new_stats.is_blocked = 0;
        bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";