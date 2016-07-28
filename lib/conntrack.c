/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "conntrack.h"

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "bitmap.h"
#include "conntrack-private.h"
#include "coverage.h"
#include "csum.h"
#include "dp-packet.h"
#include "flow.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "random.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(conntrack);

COVERAGE_DEFINE(conntrack_full);

struct conn_lookup_ctx {
    struct conn_key key;
    struct conn *conn;
    uint32_t hash;
    bool reply;
    bool related;
};

static bool conn_key_extract(struct conntrack *, struct dp_packet *,
                             struct conn_lookup_ctx *, uint16_t zone);
static uint32_t conn_key_hash(const struct conn_key *, uint32_t basis);
static void conn_key_reverse(struct conn_key *);
static void conn_key_lookup(struct conntrack_bucket *ctb,
                            struct conn_lookup_ctx *ctx,
                            long long now);
static bool valid_new(struct dp_packet *pkt, struct conn_key *);
static struct conn *new_conn(struct dp_packet *pkt, struct conn_key *,
                             long long now);
static void delete_conn(struct conn *);
static enum ct_update_res conn_update(struct conn *, struct dp_packet*,
                                      bool reply, long long now);
static bool conn_expired(struct conn *, long long now);
static void set_mark(struct dp_packet *, struct conn *,
                     uint32_t val, uint32_t mask);
static void set_label(struct dp_packet *, struct conn *,
                      const struct ovs_key_ct_labels *val,
                      const struct ovs_key_ct_labels *mask);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
    [IPPROTO_ICMP] = &ct_proto_other,
    [IPPROTO_ICMPV6] = &ct_proto_other,
};

long long ct_timeout_val[] = {
#define CT_TIMEOUT(NAME, VAL) [CT_TM_##NAME] = VAL,
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

/* If the total number of connections goes above this value, no new connections
 * are accepted */
#define DEFAULT_N_CONN_LIMIT 3000000

/* Initializes the connection tracker 'ct'.  The caller is responsible for
 * calling 'conntrack_destroy()', when the instance is not needed anymore */
void
conntrack_init(struct conntrack *ct)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];

        ct_lock_init(&ctb->lock);
        ct_lock_lock(&ctb->lock);
        hmap_init(&ctb->connections);
        ct_lock_unlock(&ctb->lock);
    }
    ct->hash_basis = random_uint32();
    atomic_count_init(&ct->n_conn, 0);
    atomic_init(&ct->n_conn_limit, DEFAULT_N_CONN_LIMIT);
}

/* Destroys the connection tracker 'ct' and frees all the allocated memory. */
void
conntrack_destroy(struct conntrack *ct)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];
        struct conn *conn;

        ct_lock_lock(&ctb->lock);
        HMAP_FOR_EACH_POP(conn, node, &ctb->connections) {
            atomic_count_dec(&ct->n_conn);
            delete_conn(conn);
        }
        hmap_destroy(&ctb->connections);
        ct_lock_unlock(&ctb->lock);
        ct_lock_destroy(&ctb->lock);
    }
}

static unsigned hash_to_bucket(uint32_t hash)
{
    /* Extracts the most significant bits in hash. The least significant bits
     * are already used internally by the hmap implementation. */
    BUILD_ASSERT(CONNTRACK_BUCKETS_SHIFT < 32 && CONNTRACK_BUCKETS_SHIFT >= 1);

    return (hash >> (32 - CONNTRACK_BUCKETS_SHIFT)) % CONNTRACK_BUCKETS;
}

static void
write_ct_md(struct dp_packet *pkt, uint16_t state, uint16_t zone,
            uint32_t mark, ovs_u128 label)
{
    pkt->md.ct_state = state | CS_TRACKED;
    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = mark;
    pkt->md.ct_label = label;
}

static struct conn *
conn_not_found(struct conntrack *ct, struct dp_packet *pkt,
               struct conn_lookup_ctx *ctx, uint16_t *state, bool commit,
               long long now)
{
    unsigned bucket = hash_to_bucket(ctx->hash);
    struct conn *nc = NULL;

    if (!valid_new(pkt, &ctx->key)) {
        *state |= CS_INVALID;
        return nc;
    }

    *state |= CS_NEW;

    if (commit) {
        unsigned int n_conn_limit;

        atomic_read_relaxed(&ct->n_conn_limit, &n_conn_limit);

        if (atomic_count_get(&ct->n_conn) >= n_conn_limit) {
            COVERAGE_INC(conntrack_full);
            return nc;
        }

        nc = new_conn(pkt, &ctx->key, now);

        memcpy(&nc->rev_key, &ctx->key, sizeof nc->rev_key);

        conn_key_reverse(&nc->rev_key);
        hmap_insert(&ct->buckets[bucket].connections, &nc->node, ctx->hash);
        atomic_count_inc(&ct->n_conn);
    }

    return nc;
}

static struct conn *
process_one(struct conntrack *ct, struct dp_packet *pkt,
            struct conn_lookup_ctx *ctx, uint16_t zone,
            bool commit, long long now)
{
    unsigned bucket = hash_to_bucket(ctx->hash);
    struct conn *conn = ctx->conn;
    uint16_t state = 0;

    if (conn) {
        if (ctx->related) {
            state |= CS_RELATED;
            if (ctx->reply) {
                state |= CS_REPLY_DIR;
            }
        } else {
            enum ct_update_res res;

            res = conn_update(conn, pkt, ctx->reply, now);

            switch (res) {
            case CT_UPDATE_VALID:
                state |= CS_ESTABLISHED;
                if (ctx->reply) {
                    state |= CS_REPLY_DIR;
                }
                break;
            case CT_UPDATE_INVALID:
                state |= CS_INVALID;
                break;
            case CT_UPDATE_NEW:
                hmap_remove(&ct->buckets[bucket].connections, &conn->node);
                atomic_count_dec(&ct->n_conn);
                delete_conn(conn);
                conn = conn_not_found(ct, pkt, ctx, &state, commit, now);
                break;
            default:
                OVS_NOT_REACHED();
            }
        }
    } else {
        conn = conn_not_found(ct, pkt, ctx, &state, commit, now);
    }

    write_ct_md(pkt, state, zone, conn ? conn->mark : 0,
                conn ? conn->label : OVS_U128_ZERO);

    return conn;
}

/* Sends the packets in '*pkt_batch' through the connection tracker 'ct'.  All
 * the packets should have the same 'dl_type' (IPv4 or IPv6) and should have
 * the l3 and and l4 offset properly set.
 *
 * If 'commit' is true, the packets are allowed to create new entries in the
 * connection tables.  'setmark', if not NULL, should point to a two
 * elements array containing a value and a mask to set the connection mark.
 * 'setlabel' behaves similarly for the connection label.*/
int
conntrack_execute(struct conntrack *ct, struct dp_packet_batch *pkt_batch,
                  bool commit, uint16_t zone, const uint32_t *setmark,
                  const struct ovs_key_ct_labels *setlabel,
                  const char *helper)
{
    struct dp_packet **pkts = pkt_batch->packets;
    size_t cnt = pkt_batch->count;
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t KEY_ARRAY_SIZE = cnt;
#else
    enum { KEY_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct conn_lookup_ctx ctxs[KEY_ARRAY_SIZE];
    int8_t bucket_list[CONNTRACK_BUCKETS];
    struct {
        unsigned bucket;
        unsigned long maps;
    } arr[KEY_ARRAY_SIZE];
    long long now = time_msec();
    size_t i = 0;
    uint8_t arrcnt = 0;

    BUILD_ASSERT_DECL(sizeof arr[0].maps * CHAR_BIT >= NETDEV_MAX_BURST);

    if (helper) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

        VLOG_WARN_RL(&rl, "ALG helper \"%s\" not supported", helper);
        /* Continue without the helper */
    }

    memset(bucket_list, INT8_C(-1), sizeof bucket_list);
    for (i = 0; i < cnt; i++) {
        unsigned bucket;

        if (!conn_key_extract(ct, pkts[i], &ctxs[i], zone)) {
            write_ct_md(pkts[i], CS_INVALID, zone, 0, OVS_U128_ZERO);
            continue;
        }

        bucket = hash_to_bucket(ctxs[i].hash);
        if (bucket_list[bucket] == INT8_C(-1)) {
            bucket_list[bucket] = arrcnt;

            arr[arrcnt].maps = 0;
            ULLONG_SET1(arr[arrcnt].maps, i);
            arr[arrcnt++].bucket = bucket;
        } else {
            ULLONG_SET1(arr[bucket_list[bucket]].maps, i);
            arr[bucket_list[bucket]].maps |= 1UL << i;
        }
    }

    for (i = 0; i < arrcnt; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[arr[i].bucket];
        size_t j;

        ct_lock_lock(&ctb->lock);

        ULLONG_FOR_EACH_1(j, arr[i].maps) {
            struct conn *conn;

            conn_key_lookup(ctb, &ctxs[j], now);

            conn = process_one(ct, pkts[j], &ctxs[j], zone, commit, now);

            if (conn && setmark) {
                set_mark(pkts[j], conn, setmark[0], setmark[1]);
            }

            if (conn && setlabel) {
                set_label(pkts[j], conn, &setlabel[0], &setlabel[1]);
            }
        }
        ct_lock_unlock(&ctb->lock);
    }

    return 0;
}

static void
set_mark(struct dp_packet *pkt, struct conn *conn, uint32_t val, uint32_t mask)
{
    pkt->md.ct_mark = val | (pkt->md.ct_mark & ~(mask));
    conn->mark = pkt->md.ct_mark;
}

static void
set_label(struct dp_packet *pkt, struct conn *conn,
          const struct ovs_key_ct_labels *val,
          const struct ovs_key_ct_labels *mask)
{
    ovs_u128 v, m;

    memcpy(&v, val, sizeof v);
    memcpy(&m, mask, sizeof m);

    pkt->md.ct_label.u64.lo = v.u64.lo
                              | (pkt->md.ct_label.u64.lo & ~(m.u64.lo));
    pkt->md.ct_label.u64.hi = v.u64.hi
                              | (pkt->md.ct_label.u64.hi & ~(m.u64.hi));
    conn->label = pkt->md.ct_label;
}

/* Key extraction */

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks.  If 'validate_checksum' is true, the function returns
 * false if the IPv4 checksum is invalid. */
static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data, bool validate_checksum)
{
    const struct ip_header *ip = data;
    size_t ip_len;

    if (new_data) {
        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            return false;
        }
    }

    ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

    if (new_data) {
        if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
            return false;
        }
        if (OVS_UNLIKELY(size < ip_len)) {
            return false;
        }

        *new_data = (char *) data + ip_len;
    }

    if (IP_IS_FRAGMENT(ip->ip_frag_off)) {
        return false;
    }

    if (validate_checksum && csum(data, ip_len) != 0) {
        return false;
    }

    key->src.addr.ipv4 = ip->ip_src;
    key->dst.addr.ipv4 = ip->ip_dst;
    key->nw_proto = ip->ip_proto;

    return true;
}

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks. */
static inline bool
extract_l3_ipv6(struct conn_key *key, const void *data, size_t size,
                const char **new_data)
{
    const struct ovs_16aligned_ip6_hdr *ip6 = data;
    uint8_t nw_proto = ip6->ip6_nxt;
    uint8_t nw_frag = 0;

    if (new_data) {
        if (OVS_UNLIKELY(size < sizeof *ip6)) {
            return false;
        }
    }

    data = ip6 + 1;
    size -=  sizeof *ip6;

    if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag)) {
        return false;
    }

    if (new_data) {
        *new_data = data;
    }

    if (nw_frag) {
        return false;
    }

    key->src.addr.ipv6 = ip6->ip6_src;
    key->dst.addr.ipv6 = ip6->ip6_dst;
    key->nw_proto = nw_proto;

    return true;
}

static inline bool
checksum_valid(const struct conn_key *key, const void *data, size_t size,
               const void *l3)
{
    uint32_t csum = 0;

    if (key->dl_type == htons(ETH_TYPE_IP)) {
        csum = packet_csum_pseudoheader(l3);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)) {
        csum = packet_csum_pseudoheader6(l3);
    } else {
        return false;
    }

    csum = csum_continue(csum, data, size);

    return csum_finish(csum) == 0;
}

static inline bool
check_l4_tcp(const struct conn_key *key, const void *data, size_t size,
             const void *l3)
{
    const struct tcp_header *tcp = data;
    size_t tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

    if (OVS_UNLIKELY(tcp_len < TCP_HEADER_LEN || tcp_len > size)) {
        return false;
    }

    return checksum_valid(key, data, size, l3);
}

static inline bool
check_l4_udp(const struct conn_key *key, const void *data, size_t size,
             const void *l3)
{
    const struct udp_header *udp = data;
    size_t udp_len = ntohs(udp->udp_len);

    if (OVS_UNLIKELY(udp_len < UDP_HEADER_LEN || udp_len > size)) {
        return false;
    }

    /* Validation must be skipped if checksum is 0 on IPv4 packets */
    return (udp->udp_csum == 0 && key->dl_type == htons(ETH_TYPE_IP))
           || checksum_valid(key, data, size, l3);
}

static inline bool
check_l4_icmp(const void *data, size_t size)
{
    return csum(data, size) == 0;
}

static inline bool
check_l4_icmp6(const struct conn_key *key, const void *data, size_t size,
               const void *l3)
{
    return checksum_valid(key, data, size, l3);
}

static inline bool
extract_l4_tcp(struct conn_key *key, const void *data, size_t size)
{
    const struct tcp_header *tcp = data;

    if (OVS_UNLIKELY(size < TCP_HEADER_LEN)) {
        return false;
    }

    key->src.port = tcp->tcp_src;
    key->dst.port = tcp->tcp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool
extract_l4_udp(struct conn_key *key, const void *data, size_t size)
{
    const struct udp_header *udp = data;

    if (OVS_UNLIKELY(size < UDP_HEADER_LEN)) {
        return false;
    }

    key->src.port = udp->udp_src;
    key->dst.port = udp->udp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool extract_l4(struct conn_key *key, const void *data,
                              size_t size, bool *related, const void *l3);

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
static inline int
extract_l4_icmp(struct conn_key *key, const void *data, size_t size,
                bool *related)
{
    const struct icmp_header *icmp = data;

    if (OVS_UNLIKELY(size < ICMP_HEADER_LEN)) {
        return false;
    }

    switch (icmp->icmp_type) {
    case ICMP4_ECHO_REQUEST:
    case ICMP4_ECHO_REPLY:
    case ICMP4_TIMESTAMP:
    case ICMP4_TIMESTAMPREPLY:
    case ICMP4_INFOREQUEST:
    case ICMP4_INFOREPLY:
        /* Separate ICMP connection: identified using id */
        key->src.port = key->dst.port = icmp->icmp_fields.echo.id;
        break;
    case ICMP4_DST_UNREACH:
    case ICMP4_TIME_EXCEEDED:
    case ICMP4_PARAM_PROB:
    case ICMP4_SOURCEQUENCH:
    case ICMP4_REDIRECT: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key;
        const char *l3 = (const char *) (icmp + 1);
        const char *tail = (const char *) data + size;
        const char *l4;
        bool ok;

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IP);
        ok = extract_l3_ipv4(&inner_key, l3, tail - l3, &l4, false);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (inner_key.src.addr.ipv4_aligned != key->dst.addr.ipv4_aligned
            || inner_key.dst.addr.ipv4_aligned != key->src.addr.ipv4_aligned) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3);
        if (ok) {
            conn_key_reverse(key);
            *related = true;
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
static inline bool
extract_l4_icmp6(struct conn_key *key, const void *data, size_t size,
                 bool *related)
{
    const struct icmp6_header *icmp6 = data;

    /* All the messages that we support need at least 4 bytes after
     * the header */
    if (size < sizeof *icmp6 + 4) {
        return false;
    }

    switch (icmp6->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        /* Separate ICMP connection: identified using id */
        key->src.port = key->dst.port = *(ovs_be16 *) (icmp6 + 1);
        break;
    case ICMP6_DST_UNREACH:
    case ICMP6_PACKET_TOO_BIG:
    case ICMP6_TIME_EXCEEDED:
    case ICMP6_PARAM_PROB: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key;
        const char *l3 = (const char *) icmp6 + 8;
        const char *tail = (const char *) data + size;
        const char *l4 = NULL;
        bool ok;

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IPV6);
        ok = extract_l3_ipv6(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (!ipv6_addr_equals(&inner_key.src.addr.ipv6_aligned,
                              &key->dst.addr.ipv6_aligned)
            || !ipv6_addr_equals(&inner_key.dst.addr.ipv6_aligned,
                                 &key->src.addr.ipv6_aligned)) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3);
        if (ok) {
            conn_key_reverse(key);
            *related = true;
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

/* Extract l4 fields into 'key', which must already contain valid l3
 * members.
 *
 * If 'related' is not NULL and an ICMP error packet is being
 * processed, the function will extract the key from the packet nested
 * in the ICMP paylod and set '*related' to true.
 *
 * If 'related' is NULL, it means that we're already parsing a header nested
 * in an ICMP error.  In this case, we skip checksum and length validation. */
static inline bool
extract_l4(struct conn_key *key, const void *data, size_t size, bool *related,
           const void *l3)
{
    if (key->nw_proto == IPPROTO_TCP) {
        return (!related || check_l4_tcp(key, data, size, l3))
               && extract_l4_tcp(key, data, size);
    } else if (key->nw_proto == IPPROTO_UDP) {
        return (!related || check_l4_udp(key, data, size, l3))
               && extract_l4_udp(key, data, size);
    } else if (key->dl_type == htons(ETH_TYPE_IP)
               && key->nw_proto == IPPROTO_ICMP) {
        return (!related || check_l4_icmp(data, size))
               && extract_l4_icmp(key, data, size, related);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)
               && key->nw_proto == IPPROTO_ICMPV6) {
        return (!related || check_l4_icmp6(key, data, size, l3))
               && extract_l4_icmp6(key, data, size, related);
    } else {
        return false;
    }
}

static bool
conn_key_extract(struct conntrack *ct, struct dp_packet *pkt,
                 struct conn_lookup_ctx *ctx, uint16_t zone)
{
    const struct eth_header *l2 = dp_packet_l2(pkt);
    const struct ip_header *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);
    const char *tail = dp_packet_tail(pkt);
    bool ok;

    memset(ctx, 0, sizeof *ctx);

    if (!l2 || !l3 || !l4) {
        return false;
    }

    ctx->key.zone = zone;

    /* XXX In this function we parse the packet (again, it has already
     * gone through miniflow_extract()) for two reasons:
     *
     * 1) To extract the l3 addresses and l4 ports.
     *    We already have the l3 and l4 headers' pointers.  Extracting
     *    the l3 addresses and the l4 ports is really cheap, since they
     *    can be found at fixed locations.
     * 2) To extract the l3 and l4 types.
     *    Extracting the l3 and l4 types (especially the l3[1]) on the
     *    other hand is quite expensive, because they're not at a
     *    fixed location.
     *
     * Here's a way to avoid (2) with the help of the datapath.
     * The datapath doesn't keep the packet's extracted flow[2], so
     * using that is not an option.  We could use the packet's matching
     * megaflow for l3 type (it's always unwildcarded), and for l4 type
     * (we have to unwildcard it first).  This means either:
     *
     * a) dpif-netdev passes the matching megaflow to dp_execute_cb(), which
     *    is used to extract the l3 type.  Unfortunately, dp_execute_cb() is
     *    used also in dpif_netdev_execute(), which doesn't have a matching
     *    megaflow.
     *
     * b) We define an alternative OVS_ACTION_ATTR_CT, used only by the
     *    userspace datapath, which includes l3 (and l4) type.  The
     *    alternative action could be generated by ofproto-dpif specifically
     *    for the userspace datapath. Having a different interface for
     *    userspace and kernel doesn't seem very clean, though.
     *
     * ---
     * [1] A simple benchmark (running only the connection tracker
     *     over and over on the same packets) shows that if the
     *     l3 type is already provided we are 15% faster (running the
     *     connection tracker over a couple of DPDK devices with a
     *     stream of UDP 64-bytes packets shows that we are 4% faster).
     *
     * [2] The reasons for this are that keeping the flow increases
     *     (slightly) the cache footprint and increases computation
     *     time as we move the packet around. Most importantly, the flow
     *     should be updated by the actions and this can be slow, as
     *     we use a sparse representation (miniflow).
     *
     */
    ctx->key.dl_type = parse_dl_type(l2, (char *) l3 - (char *) l2);
    if (ctx->key.dl_type == htons(ETH_TYPE_IP)) {
        ok = extract_l3_ipv4(&ctx->key, l3, tail - (char *) l3, NULL, true);
    } else if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        ok = extract_l3_ipv6(&ctx->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        if (extract_l4(&ctx->key, l4, tail - l4, &ctx->related, l3)) {
            ctx->hash = conn_key_hash(&ctx->key, ct->hash_basis);
            return true;
        }
    }

    return false;
}

/* Symmetric */
static uint32_t
conn_key_hash(const struct conn_key *key, uint32_t basis)
{
    uint32_t hsrc, hdst, hash;
    int i;

    hsrc = hdst = basis;

    /* Hash the source and destination tuple */
    for (i = 0; i < sizeof(key->src) / sizeof(uint32_t); i++) {
        hsrc = hash_add(hsrc, ((uint32_t *) &key->src)[i]);
        hdst = hash_add(hdst, ((uint32_t *) &key->dst)[i]);
    }

    /* Even if source and destination are swapped the hash will be the same. */
    hash = hsrc ^ hdst;

    /* Hash the rest of the key(L3 and L4 types and zone). */
    hash = hash_words((uint32_t *) &key->dst + 1,
                      (uint32_t *) (key + 1) - (uint32_t *) (&key->dst + 1),
                      hash);

    return hash;
}

static void
conn_key_reverse(struct conn_key *key)
{
    struct ct_endpoint tmp;
    tmp = key->src;
    key->src = key->dst;
    key->dst = tmp;
}

static void
conn_key_lookup(struct conntrack_bucket *ctb,
                struct conn_lookup_ctx *ctx,
                long long now)
{
    uint32_t hash = ctx->hash;
    struct conn *conn;

    ctx->conn = NULL;

    HMAP_FOR_EACH_WITH_HASH (conn, node, hash, &ctb->connections) {
        if (!memcmp(&conn->key, &ctx->key, sizeof(conn->key))
                && !conn_expired(conn, now)) {
            ctx->conn = conn;
            ctx->reply = false;
            break;
        }
        if (!memcmp(&conn->rev_key, &ctx->key, sizeof(conn->rev_key))
                && !conn_expired(conn, now)) {
            ctx->conn = conn;
            ctx->reply = true;
            break;
        }
    }
}

static enum ct_update_res
conn_update(struct conn *conn, struct dp_packet *pkt, bool reply,
            long long now)
{
    return l4_protos[conn->key.nw_proto]->conn_update(conn, pkt, reply, now);
}

static bool
conn_expired(struct conn *conn, long long now)
{
    return now >= conn->expiration;
}

static bool
valid_new(struct dp_packet *pkt, struct conn_key *key)
{
    return l4_protos[key->nw_proto]->valid_new(pkt);
}

static struct conn *
new_conn(struct dp_packet *pkt, struct conn_key *key, long long now)
{
    struct conn *newconn;

    newconn = l4_protos[key->nw_proto]->new_conn(pkt, now);

    if (newconn) {
        newconn->key = *key;
    }

    return newconn;
}

static void
delete_conn(struct conn *conn)
{
    free(conn);
}
