#define METRICS_SIZE 65536
#define BLOCKLIST_SIZE 65536
#define CONNTRACK_SIZE 65536
#define PORT_HISTORY_SIZE 10

#include "headers/common.h"
#include "headers/bpf_helpers.h"

// ip_metric represents what we know about an IP:
// * how much SYN packet have we received
// * X ports it contacted us recently on
// Ideally the `ports` field would be a LRU but I took a shortcut did not implement
struct ip_metric {
    __u64 syn_received;
    __u16 ports[PORT_HISTORY_SIZE];
};

typedef struct ip_metric ip_metric;

// ip_metric_map contains the history of which IP address tried to connect to which port.
// This is a least-recently-used hashmap, keys are the IP addresses and values are ip_metric.
// This map is filled by a XDP program when a SYN packet is received and flushed by the go program in userspace.
struct bpf_map_def SEC("maps") ip_metric_map =
{
    // per-cpu maps avoid cross-cpu locks, which is especially important as we're in the critical path
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(ip_metric),
    .max_entries = METRICS_SIZE
};

// ip_blocked_map contains the blocked IPs. Keys are the IP, values are the epoch timestamp when the IP was blocked.
// This map is read by the XDP firewall program and filled by the go program in userspace when a scan is detected.
struct bpf_map_def SEC("maps") ip_blocked_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = BLOCKLIST_SIZE
};

// tcp_connection is a struct representing the log record of a connection
struct tcp_connection {
    __u32 source_ip;
    __u32 dest_ip;
    __u16 source_port;
    __u16 dest_port;
};

typedef struct tcp_connection tcp_connection;

// tcp_connection_tracking_map is a queue keeping track of individual TCP connection attempts
// It is populated by the XDP program and consumed by userspace.
struct bpf_map_def SEC("maps") tcp_connection_tracking_map =
{
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(tcp_connection),
    .max_entries = CONNTRACK_SIZE
};