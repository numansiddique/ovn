/* SPDX-License-Identifier: GPL-2.0 */
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_ALEN 6
#define VIF_ADDR_FLAG_ETH_SET 0x01
#define VIF_ADDR_FLAG_IP_SET  0x02

#define ETH_P_IP 0x0800

#define OVN_CHECK_PORT_SEC_MAC      0x00000001
#define OVN_CHECK_PORT_SEC_MAC_IP   0x00000002


struct bpf_map_def SEC("maps") ovn_vif_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

/* Map for mac port security table*/
struct bpf_map_def SEC("maps") port_sec_mac_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u8),
    .max_entries = 4,
};

struct lpm_mac_ip_key {
    struct bpf_lpm_trie_key trie_key;
    __u8 data[10]; /* 6 bytes for mac, 4 bytes for ip */
};

/* Map for mac + ip4 port security table*/
struct bpf_map_def SEC("maps") port_sec_mac_ip_table = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_mac_ip_key),
    .value_size = sizeof(__u8),
    .max_entries = 4,
    .map_flags = BPF_F_NO_PREALLOC,
};

static inline __u64
eth_addr_to_uint64(unsigned char ethaddr[ETH_ALEN]) {
    return ((uint64_t) ethaddr[0] << 40) |
           ((uint64_t) ethaddr[1] << 32) |
           ((uint64_t) ethaddr[2] << 24) |
           ((uint64_t) ethaddr[3] << 16) |
           ((uint64_t) ethaddr[4] << 8) |
           ((uint64_t) ethaddr[5] << 0);
}

SEC("xdp")
int  xdp_ovn_vif(struct xdp_md *xdp)
{
    __u32 key = 0;

    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;

    int ret = XDP_PASS;

    if (data + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }

    __u32 *vif_flags = bpf_map_lookup_elem(&ovn_vif_map, &key);
    if (!vif_flags || !(*vif_flags)) {
        /* No checks to be done. */
        return XDP_PASS;
    }

    if (eth->h_source[0] & 0x01) {
        /* Multicast eth src. Drop it. */
        return XDP_DROP;
    }

    if (eth->h_proto == htons(ETH_P_ARP)) {
        __u8 ps_check_pass = 0;
        __u64 src_mac;

        src_mac = eth_addr_to_uint64(eth->h_source);
        if (bpf_map_lookup_elem(&port_sec_mac_table, &src_mac)) {
            ps_check_pass = 1;
        }

        if (!ps_check_pass) {
            return XDP_DROP;
        }

        /* TODO.  Inspect the arp header and check if arp.sha is allowed or not. */
        return XDP_PASS;
    } else if (eth->h_proto == htons(ETH_P_IP)) {
        __u8 ps_check_pass = 0;
        if (*vif_flags & OVN_CHECK_PORT_SEC_MAC_IP) {
            struct iphdr *iph;
            struct lpm_mac_ip_key key = {
                .trie_key = {
                    .prefixlen = 80,
                },
            };

            iph = (struct iphdr *)(eth + 1);
            if ((void *)(iph + 1) > data_end) {
                return XDP_DROP;
            }

            key.data[0] = eth->h_source[0];
            key.data[1] = eth->h_source[1];
            key.data[2] = eth->h_source[2];
            key.data[3] = eth->h_source[3];
            key.data[4] = eth->h_source[4];
            key.data[5] = eth->h_source[5];

            key.data[6] = iph->saddr & 0xff;
            key.data[7] = (iph->saddr >> 8) & 0xff;
            key.data[8] = (iph->saddr >> 16) & 0xff;
            key.data[9] = (iph->saddr >> 24) & 0xff;

            __u8 *v;
            v = bpf_map_lookup_elem(&port_sec_mac_ip_table, &key);
            if (v && *v) {
                ps_check_pass = 1;
            }
        }

        if (!ps_check_pass && (*vif_flags & OVN_CHECK_PORT_SEC_MAC)) {
            __u64 src_mac;
            __u8 *v;

            src_mac = eth_addr_to_uint64(eth->h_source);
            v = bpf_map_lookup_elem(&port_sec_mac_table, &src_mac);
            if (v && *v) {
                ps_check_pass = 1;
            }
        }

        if (!ps_check_pass) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
