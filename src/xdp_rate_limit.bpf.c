// SPDX-License-Identifier: GPL-2.0
// XDP IPv4 rate-limit helper: counts ingress bytes/packets by source IP and globally,
// drops source IPs listed in blacklist_map, and bypasses whitelist_lpm_map.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// linux/if_vlan.h keeps struct vlan_hdr behind __KERNEL__, so it is not visible
// to BPF programs. Define it locally to match the on-wire 802.1Q tag layout.
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct traffic_stats {
    __u64 bytes;
    __u64 packets;
};

struct ban_value {
    // 0 = permanent while present in map; otherwise monotonic time in ns.
    __u64 expires_ns;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct {
    // Per-CPU + LRU: no cross-CPU cache-line contention, no atomics needed,
    // and memory stays bounded under source-IP floods (oldest entries evicted).
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);              // raw IPv4 address bytes, network order
    __type(value, struct traffic_stats);
} stats_map SEC(".maps");

struct {
    // Per-CPU array: each core bumps its own counter; userspace sums across CPUs.
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} global_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);              // raw IPv4 address bytes, network order
    __type(value, struct ban_value);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key); // prefixlen + raw network-order address
    __type(value, __u8);
} whitelist_lpm_map SEC(".maps");

static __always_inline int parse_eth_proto(void *data, void *data_end, __u64 *offset, __be16 *proto)
{
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    *proto = eth->h_proto;
    *offset = sizeof(*eth);

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (*proto == bpf_htons(ETH_P_8021Q) || *proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vh = data + *offset;
            if ((void *)(vh + 1) > data_end)
                return -1;
            *proto = vh->h_vlan_encapsulated_proto;
            *offset += sizeof(*vh);
        }
    }

    return 0;
}

SEC("xdp")
int xdp_rate_limiter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 offset = 0;
    __be16 proto = 0;

    if (parse_eth_proto(data, data_end, &offset, &proto) < 0)
        return XDP_PASS;

    if (proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + offset;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src = iph->saddr;

    // Whitelist bypasses accounting and blacklist. Useful for SSH/admin IPs.
    struct ipv4_lpm_key wl_key = {
        .prefixlen = 32,
        .addr = src,
    };
    __u8 *wl = bpf_map_lookup_elem(&whitelist_lpm_map, &wl_key);
    if (wl)
        return XDP_PASS;

    // Important: active bans are checked BEFORE accounting.
    // This way already-dropped attack traffic does not keep the smart global
    // threshold above the limit and does not pollute the top-IP list.
    struct ban_value *ban = bpf_map_lookup_elem(&blacklist_map, &src);
    if (ban) {
        __u64 now = bpf_ktime_get_ns();
        if (ban->expires_ns == 0 || ban->expires_ns > now)
            return XDP_DROP;
    }

    __u64 pkt_len = data_end - data;

    // Per-CPU maps: the pointer refers to this CPU's private slot, so plain
    // increments are safe and cheaper than atomics.
    __u32 zero = 0;
    struct traffic_stats *gst = bpf_map_lookup_elem(&global_stats_map, &zero);
    if (gst) {
        gst->bytes += pkt_len;
        gst->packets += 1;
    }

    struct traffic_stats *st = bpf_map_lookup_elem(&stats_map, &src);
    if (!st) {
        struct traffic_stats init = {};
        bpf_map_update_elem(&stats_map, &src, &init, BPF_ANY);
        st = bpf_map_lookup_elem(&stats_map, &src);
    }
    if (st) {
        st->bytes += pkt_len;
        st->packets += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
