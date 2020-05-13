/* Copyright (c) 2015, 2016 Nicira, Inc.
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


#ifndef OVN_CONTROLLER_H
#define OVN_CONTROLLER_H 1

#include "simap.h"
#include "lib/ovn-sb-idl.h"

struct ovsrec_bridge_table;

/* Linux supports a maximum of 64K zones, which seems like a fine default. */
#define MAX_CT_ZONES 65535

/* States to move through when a new conntrack zone has been allocated. */
enum ct_zone_pending_state {
    CT_ZONE_OF_QUEUED,    /* Waiting to send conntrack flush command. */
    CT_ZONE_OF_SENT,      /* Sent and waiting for confirmation on flush. */
    CT_ZONE_DB_QUEUED,    /* Waiting for DB transaction to open. */
    CT_ZONE_DB_SENT,      /* Sent and waiting for confirmation from DB. */
};

struct ct_zone_pending_entry {
    int zone;
    bool add;             /* Is the entry being added? */
    ovs_be32 of_xid;      /* Transaction id for barrier. */
    enum ct_zone_pending_state state;
};

/* A logical datapath that has some relevance to this hypervisor.  A logical
 * datapath D is relevant to hypervisor H if:
 *
 *     - Some VIF or l2gateway or l3gateway port in D is located on H.
 *
 *     - D is reachable over a series of hops across patch ports, starting from
 *       a datapath relevant to H.
 *
 * The 'hmap_node''s hash value is 'datapath->tunnel_key'. */
struct local_datapath {
    struct hmap_node hmap_node;
    const struct sbrec_datapath_binding *datapath;

    /* The localnet port in this datapath, if any (at most one is allowed). */
    const struct sbrec_port_binding *localnet_port;

    /* True if this datapath contains an l3gateway port located on this
     * hypervisor. */
    bool has_local_l3gateway;

    struct {
        const struct sbrec_port_binding *local;
        const struct sbrec_port_binding *remote;
    } *peer_ports;

    size_t n_peer_ports;
    size_t n_allocated_peer_ports;
};

struct local_datapath *get_local_datapath(const struct hmap *,
                                          uint32_t tunnel_key);

enum local_binding_type {
    BT_VIF,
    BT_CHILD,
    BT_VIRTUAL
};

struct local_binding {
    struct ovs_list node;       /* In parent if any. */
    char *name;
    enum local_binding_type type;
    const struct ovsrec_interface *iface;
    const struct sbrec_port_binding *pb;
    struct ovs_list children;
};

static inline struct local_binding *
local_binding_find(struct shash *local_bindings, const char *name)
{
    return shash_find_data(local_bindings, name);
}

/* Represents a tracked binding logical port. */
struct tracked_binding_lport {
    const struct sbrec_port_binding *pb;
    struct ovs_list list_node;
    bool deleted;
};

/* Represent a tracked binding datapath. */
struct tracked_binding_datapath {
    struct hmap_node node;
    const struct sbrec_datapath_binding *dp;
    bool is_new;
    struct ovs_list lports_head; /* List of struct tracked_binding_lport. */
};

const struct ovsrec_bridge *get_bridge(const struct ovsrec_bridge_table *,
                                       const char *br_name);

struct sbrec_encap *preferred_encap(const struct sbrec_chassis *);

/* Must be a bit-field ordered from most-preferred (higher number) to
 * least-preferred (lower number). */
enum chassis_tunnel_type {
    GENEVE = 1 << 2,
    STT    = 1 << 1,
    VXLAN  = 1 << 0
};

uint32_t get_tunnel_type(const char *name);

#endif /* controller/ovn-controller.h */
