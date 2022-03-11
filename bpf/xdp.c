// +build ignore

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "headers/common.h"
#include "headers/bpf_helpers.h"

#include "types.h"

int port_is_in_ip_metric(ip_metric *metric, u16 port) {
    int i;
    // eBPF VM doesn't support loops, this asks the compiler to replace the "for" by all its individual iterations
    #pragma clang loop unroll(full)
    for (i = 0; i < PORT_HISTORY_SIZE ; ++i) {
        if (metric->ports[i] == port) {
            return 1;
        }
    }
    return 0;
}
// Insert a port into the ip_metric.ports ring buffer
void add_port_to_ip_metric(ip_metric *metric, u16 port) {
    int i;
    // eBPF VM doesn't support loops, this asks the compiler to replace the "for" by all its individual iterations
    #pragma clang loop unroll(full)
    for (i = PORT_HISTORY_SIZE; i > 0 ; --i) {
       metric->ports[i] = metric->ports[i-1];
    }
    metric->ports[0] = port;
}

SEC("xdp_metrics")
int xdp_prog_main(struct xdp_md *ctx) {

    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Scan ethernet header.
    struct ethhdr *ethernet_header = data;

    // We have to make sure we won't try to read memory out of the packet
    // Without this check the BPF validator is angry
    if (ethernet_header + 1 > (struct ethhdr *)data_end) {
        return XDP_DROP;
    }

    // Bail out if protocol is not IP
    if (ethernet_header->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Scan IP header
    struct iphdr *ip_header = NULL;

    ip_header = (data + sizeof(struct ethhdr));

    // Same than for the ethernet header, we have to make sure we won't attempt to read memory out of the packet
    if (ip_header + 1 > (struct iphdr *)data_end) {
        return XDP_DROP;
    }

    // Bail out if protocol is not TCP
    if (ip_header->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Scan TCP header.
    struct tcphdr *tcp_header = NULL;
    tcp_header = (data + sizeof(struct ethhdr) + (ip_header->ihl * 4));

    // Same situation than for ethernet and ip headers
    if (tcp_header + 1 > (struct tcphdr *)data_end) {
        return XDP_DROP;
    }

    // We retrieve source and dest IP/port
    u32 source_ip = ip_header->saddr;
    u32 dest_ip = ip_header->daddr;
    u16 source_port = tcp_header->source;
    u16 dest_port = tcp_header->dest;

    // Drop the packet is the IP is blocked
    u64 *blocked_time;
    blocked_time = bpf_map_lookup_elem(&ip_blocked_map, &source_ip);
    if (blocked_time) {
        return XDP_DROP;
    }

    // We want to catch only the first packet of the three-way handshake: SYN, SYN+ACK, ACK.
    if (!tcp_header->syn || tcp_header->ack){
        return XDP_PASS;
    }

    ip_metric *metric = NULL;
    metric = bpf_map_lookup_elem(&ip_metric_map, &source_ip);

    // If a map elem already exist for this IP we increment and eventually add port.
    // Else we have to initialize a new ip_metric
    if (metric) {
        metric->syn_received += 1;
        // We check if the port was already seen
        // If this is a new port we register it
        // Please note that ip_metric.ports is not exactly a LRU buffer: if a port was already seen it won't be moved
        // back to the first position
        if (! port_is_in_ip_metric(metric, dest_port)) {
            add_port_to_ip_metric(metric, dest_port);
        }
        bpf_map_update_elem(&ip_metric_map, &ip_header->saddr, metric, BPF_ANY);
    }
    else {
        ip_metric initval = {};
        initval.syn_received = 1;
        initval.ports[0] = dest_port;
        bpf_map_update_elem(&ip_metric_map, &ip_header->saddr, &initval, BPF_ANY);
    }

    tcp_connection connection = {};
    connection.source_ip = source_ip;
    connection.dest_ip = dest_ip;
    connection.source_port = source_port;
    connection.dest_port = dest_port;

    bpf_map_push_elem(&tcp_connection_tracking_map, &connection, 0);

    return XDP_PASS;
}