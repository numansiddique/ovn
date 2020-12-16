/* Copyright (c) 2021, Red Hat, Inc.
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

#ifndef LDATA_H
#define LDATA_H 1

/* OVS includes. */
#include "include/openvswitch/shash.h"
#include "lib/smap.h"

/* OVN includes. */
#include "lib/ovn-util.h"

struct sbrec_datapath_binding;
struct sbrec_port_binding;
struct ovsdb_idl_index;
struct sbrec_load_balancer;

struct local_lport {
    const struct sbrec_port_binding *pb;
    enum en_lport_type type;

    /* cached data. */
    char **addresses;
    size_t n_addresses;
    char **port_security;
    size_t n_port_security;
    struct smap options;
    bool claimed;

    union {
        struct {
            /* Logical switch port data. */
            struct lport_addresses *addrs;  /* Logical switch port
                                             * addresses. */
            unsigned int n_addrs;

            struct lport_addresses *ps_addrs;  /* Port security addresses. */
            unsigned int n_ps_addrs;

            bool has_unknown;
            bool check_lport_is_up;
        } lsp;

        struct {
            struct lport_addresses networks;
            bool has_bfd;
            bool is_l3dgw_port;
            char *chassis_redirect_json_key; /* Initialized only if
                                              * 'is_l3dgw_port'. */
            bool dp_has_l3dgw_port; /* True if the router datapath has a
                                     * gw port. */
            bool peer_dp_has_localnet_ports; /* True if the peer datapath has
                                      * localnet ports. */
        } lrp;
    };
    char *json_key;

    /* The port's peer:
     *
     *     - A switch port S of type "router" has a router port R as a peer,
     *       and R in turn has S has its peer.
     *
     *     - Two connected logical router ports have each other as peer.
     *
     *     - Other kinds of ports have no peer. */
    struct local_lport *peer;

    /* Logical port multicast data. */
    /*struct mcast_port_info mcast_info; */

    struct local_datapath *ldp;

    struct hmap ctrl_lflows[2];
    struct hmap *active_lflows;
    struct hmap *cleared_lflows;

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
    bool is_switch;

    /* The localnet port in this datapath, if any (at most one is allowed). */
    const struct sbrec_port_binding *localnet_port;

    /* True if this datapath contains an l3gateway port located on this
     * hypervisor. */
    bool has_local_l3gateway;

    struct {
        struct local_lport *local;
        struct local_lport *remote;
    } *peer_ports;

    size_t n_peer_ports;
    size_t n_allocated_peer_ports;

    /* Multicast data. */
    /*struct mcast_info mcast_info; */

    /* Data related to lflow generation. */
    struct smap dp_options;
    struct hmap ctrl_lflows[2];
    struct hmap *active_lflows;
    struct hmap *cleared_lflows;

    /* shash of 'struct local_lport'. */
    struct shash lports;
};

struct local_datapath *local_datapath_alloc(
    const struct sbrec_datapath_binding *);
struct local_datapath *get_local_datapath(const struct hmap *,
                                          uint32_t tunnel_key);
void local_datapath_add(struct hmap *local_datapaths,
                        const struct sbrec_datapath_binding *,
                        struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                        struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                        struct ovsdb_idl_index *sbrec_port_binding_by_name,
                        void (*datapath_added)(struct local_datapath *,
                                               void *aux),
                        void *aux);

void local_datapaths_destroy(struct hmap *local_datapaths);
void local_datapath_destroy(struct local_datapath *ld);
void local_datapath_switch_lflow_map(struct local_datapath *);

struct local_lport *local_datapath_get_lport(struct local_datapath *ld,
                                             const char *lport_name);

struct local_lport *local_datapath_add_lport(
    struct local_datapath *ld, const char *lport_name,
    const struct sbrec_port_binding *);

void local_datapath_remove_lport(struct local_datapath *ld,
                                 const char *lport_name);

void local_datapath_add_or_update_peer_port(
    const struct sbrec_port_binding *pb,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    struct local_datapath *ld,
    struct hmap *local_datapaths,
    void (*datapath_added_cb)(
                         struct local_datapath *ld,
                         void *aux),
    void *aux);

void local_datapath_remove_peer_port(const struct sbrec_port_binding *pb,
                                     struct local_datapath *ld,
                                     struct hmap *local_datapaths);
struct local_lport *local_datapath_unlink_lport(struct local_datapath *ld,
                                                const char *lport_name);

void local_lport_destroy(struct local_lport *);

bool local_lport_update_cache(struct local_lport *);
void local_lport_clear_cache(struct local_lport *);
bool local_lport_is_cache_old(struct local_lport *);
void local_lport_switch_lflow_map(struct local_lport *);

/* Represents a tracked logical port. */
enum en_tracked_resource_type {
    TRACKED_RESOURCE_NEW,
    TRACKED_RESOURCE_REMOVED,
    TRACKED_RESOURCE_UPDATED
};

struct tracked_lport {
    const struct sbrec_port_binding *pb;
    enum en_tracked_resource_type tracked_type;
};

/* Represent a tracked datapath. */
struct tracked_datapath {
    struct hmap_node node;
    const struct sbrec_datapath_binding *dp;
    enum en_tracked_resource_type tracked_type;
    struct shash lports; /* shash of struct tracked_binding_lport. */
};

struct tracked_datapath * tracked_datapath_add(
    const struct sbrec_datapath_binding *, enum en_tracked_resource_type,
    struct hmap *tracked_datapaths);
struct tracked_datapath *tracked_datapath_find(
    struct hmap *tracked_datapaths, const struct sbrec_datapath_binding *);
void tracked_datapath_lport_add(const struct sbrec_port_binding *,
                                enum en_tracked_resource_type,
                                struct hmap *tracked_datapaths);
void tracked_datapaths_destroy(struct hmap *tracked_datapaths);

/* Load balancer. */
struct local_load_balancer {
    struct hmap_node hmap_node;

    struct ovn_controller_lb *ovn_lb;
    struct hmap lswitch_lflows[2];
    struct hmap lrouter_lflows[2];
    struct hmap *active_lswitch_lflows;
    struct hmap *cleared_lswitch_lflows;
    struct hmap *active_lrouter_lflows;
    struct hmap *cleared_lrouter_lflows;
};

struct local_load_balancer *local_load_balancer_add(
    struct hmap *local_lbs, struct hmap *local_datapaths,
    const struct sbrec_load_balancer *);
void local_load_balancer_remove(struct hmap *local_lbs,
                                struct local_load_balancer *);
void local_load_balancers_destroy(struct hmap *local_lbs);
struct local_load_balancer *local_load_balancer_get(struct hmap *local_lbs,
                                                    const struct uuid *);
void local_load_balancer_update(struct local_load_balancer *);
void local_load_balancer_switch_lflow_map(struct local_load_balancer *);

struct tracked_lb {
    struct hmap_node node;
    struct local_load_balancer *local_lb;
    enum en_tracked_resource_type tracked_type;
};

void tracked_lb_add(struct local_load_balancer *,
                    enum en_tracked_resource_type,
                    struct hmap *tracked_lbs);
void tracked_lbs_destroy(struct hmap *tracked_lbs);

#endif /* controller/ldata.h */
