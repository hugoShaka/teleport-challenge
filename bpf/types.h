#define METRICS_SIZE 65536
#define BLOCKLIST_SIZE 65536
#define PORT_HISTORY_SIZE 10

#include "headers/common.h"
#include "headers/bpf_helpers.h"

struct ip_metric {
    __u64 syn_received;
    __u16 ports[PORT_HISTORY_SIZE];
};

typedef struct ip_metric ip_metric;

struct bpf_map_def SEC("maps") ip_metric_map =
{
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(ip_metric),
    .max_entries = METRICS_SIZE
};

struct bpf_map_def SEC("maps") ip_blocked_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = BLOCKLIST_SIZE
};
