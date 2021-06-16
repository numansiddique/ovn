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

#include <config.h>

/* OVS includes. */
#include "include/openvswitch/json.h"
#include "lib/hmapx.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "ldata.h"
#include "lib/ovn-util.h"
#include "lib/ovn-sb-idl.h"
#include "lib/lflow.h"

VLOG_DEFINE_THIS_MODULE(ldata);

static struct local_datapath *local_datapath_add__(
    struct hmap *local_datapaths,
    const struct sbrec_datapath_binding *,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    int depth,
    void (*datapath_added)(struct local_datapath *,
                           void *aux),
    void *aux);

static void local_lport_init_cache(struct local_lport *);
static void local_lport_update_lsp_data(struct local_lport *);
static void local_lport_update_lrp_data(struct local_lport *);
static void local_lport_destroy_lsp_data(struct local_lport *);
static void local_lport_destroy_lrp_data(struct local_lport *);
static void local_lport_init_lflow_gen_data(struct local_lport *);
static void local_lport_destroy_lflow_gen_data(struct local_lport *);

static struct tracked_datapath *tracked_datapath_create(
    const struct sbrec_datapath_binding *dp,
    enum en_tracked_resource_type tracked_type,
    struct hmap *tracked_datapaths);

struct local_datapath *
get_local_datapath(const struct hmap *local_datapaths, uint32_t tunnel_key)
{
    struct hmap_node *node = hmap_first_with_hash(local_datapaths, tunnel_key);
    return (node
            ? CONTAINER_OF(node, struct local_datapath, hmap_node)
            : NULL);
}

struct local_datapath *
local_datapath_alloc(const struct sbrec_datapath_binding *dp)
{
    struct local_datapath *ld = xzalloc(sizeof *ld);
    ld->datapath = dp;
    ld->is_switch = datapath_is_switch(dp);
    hmap_init(&ld->ctrl_lflows[0]);
    hmap_init(&ld->ctrl_lflows[1]);
    ld->active_lflows = &ld->ctrl_lflows[0];
    ld->cleared_lflows = &ld->ctrl_lflows[1];
    shash_init(&ld->lports);
    smap_clone(&ld->dp_options, &dp->options);
    return ld;
}

void
local_datapaths_destroy(struct hmap *local_datapaths)
{
    struct local_datapath *ld;
    HMAP_FOR_EACH_POP (ld, hmap_node, local_datapaths) {
        local_datapath_destroy(ld);
    }

    hmap_destroy(local_datapaths);
}

void
local_datapath_destroy(struct local_datapath *ld)
{
    ovn_ctrl_lflows_destroy(&ld->ctrl_lflows[0]);
    ovn_ctrl_lflows_destroy(&ld->ctrl_lflows[1]);

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &ld->lports) {
        hmap_remove(&ld->lports.map, &node->node);
        local_lport_destroy(node->data);
        free(node->name);
        free(node);
    }

    hmap_destroy(&ld->lports.map);
    free(ld->peer_ports);
    smap_destroy(&ld->dp_options);
    free(ld);
}

void
local_datapath_add(struct hmap *local_datapaths,
                   const struct sbrec_datapath_binding *dp,
                   struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                   struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   void (*datapath_added_cb)(
                         struct local_datapath *ld,
                         void *aux),
                   void *aux)
{
    local_datapath_add__(local_datapaths, dp, sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_datapath,
                         sbrec_port_binding_by_name, 0,
                         datapath_added_cb, aux);
}

void
local_datapath_switch_lflow_map(struct local_datapath *ldp)
{
    struct hmap *temp = ldp->active_lflows;
    ldp->active_lflows = ldp->cleared_lflows;
    ldp->cleared_lflows = temp;

    /* Make sure that the active_lflows is empty. */
    ovs_assert(hmap_is_empty(ldp->active_lflows));
}

void
local_datapath_add_peer_port(
    const struct sbrec_port_binding *pb,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    struct local_datapath *ld,
    struct hmap *local_datapaths,
    void (*datapath_added_cb)(
                         struct local_datapath *ld,
                         void *aux),
    void *aux)
{
    const struct sbrec_port_binding *peer;
    peer = lport_get_peer(pb, sbrec_port_binding_by_name);

    if (!peer) {
        return;
    }

    struct local_datapath *peer_ld =
        get_local_datapath(local_datapaths, peer->datapath->tunnel_key);
    if (!peer_ld){
        peer_ld = local_datapath_add__(local_datapaths, peer->datapath,
                                       sbrec_datapath_binding_by_key,
                                       sbrec_port_binding_by_datapath,
                                       sbrec_port_binding_by_name, 1,
                                       datapath_added_cb, aux);
    }

    struct local_lport *peer_lport =
        local_datapath_get_lport(peer_ld, peer->logical_port);

    if (!peer_lport) {
        return;
    }

    struct local_lport *lport = local_datapath_get_lport(ld, pb->logical_port);
    ovs_assert(lport);

    bool present = false;
    for (size_t i = 0; i < ld->n_peer_ports; i++) {
        if (ld->peer_ports[i].local == lport) {
            present = true;
            break;
        }
    }

    if (!present) {
        ld->n_peer_ports++;
        if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
            ld->peer_ports =
                x2nrealloc(ld->peer_ports,
                           &ld->n_allocated_peer_ports,
                           sizeof *ld->peer_ports);
        }
        ld->peer_ports[ld->n_peer_ports - 1].local = lport;
        ld->peer_ports[ld->n_peer_ports - 1].remote = peer_lport;
    }

    lport->peer = peer_lport;
    peer_lport->peer = lport;

    for (size_t i = 0; i < peer_ld->n_peer_ports; i++) {
        if (peer_ld->peer_ports[i].local == peer_lport) {
            return;
        }
    }

    peer_ld->n_peer_ports++;
    if (peer_ld->n_peer_ports > peer_ld->n_allocated_peer_ports) {
        peer_ld->peer_ports =
            x2nrealloc(peer_ld->peer_ports,
                        &peer_ld->n_allocated_peer_ports,
                        sizeof *peer_ld->peer_ports);
    }
    peer_ld->peer_ports[peer_ld->n_peer_ports - 1].local = peer_lport;
    peer_ld->peer_ports[peer_ld->n_peer_ports - 1].remote = lport;
}

void
local_datapath_remove_peer_port(const struct sbrec_port_binding *pb,
                                struct local_datapath *ld,
                                struct hmap *local_datapaths)
{
    struct local_lport *lport = local_datapath_get_lport(ld, pb->logical_port);
    if (!lport) {
        return;
    }

    size_t i = 0;
    for (i = 0; i < ld->n_peer_ports; i++) {
        if (ld->peer_ports[i].local == lport) {
            break;
        }
    }

    if (i == ld->n_peer_ports) {
        return;
    }

    struct local_lport *peer = ld->peer_ports[i].remote;

    /* Possible improvement: We can shrink the allocated peer ports
     * if (ld->n_peer_ports < ld->n_allocated_peer_ports / 2).
     */
    ld->peer_ports[i].local = ld->peer_ports[ld->n_peer_ports - 1].local;
    ld->peer_ports[i].remote = ld->peer_ports[ld->n_peer_ports - 1].remote;
    ld->n_peer_ports--;

    struct local_datapath *peer_ld = peer->ldp;
    if (peer_ld) {
        /* Remove the peer port from the peer datapath. The peer
         * datapath also tries to remove its peer lport, but that would
         * be no-op. */
        local_datapath_remove_peer_port(peer->pb, peer_ld, local_datapaths);
    }

    if (lport->peer) {
        lport->peer->peer = NULL;
    }
    lport->peer = NULL;
}

struct local_lport *
local_datapath_add_lport(struct local_datapath *ld,
                         const char *lport_name,
                         const struct sbrec_port_binding *pb)
{
    struct local_lport *dp_lport = local_datapath_get_lport(ld, lport_name);
    if (!dp_lport) {
        dp_lport = xzalloc(sizeof *dp_lport);
        dp_lport->pb = pb;

        hmap_init(&dp_lport->ctrl_lflows[0]);
        hmap_init(&dp_lport->ctrl_lflows[1]);
        dp_lport->active_lflows = &dp_lport->ctrl_lflows[0];
        dp_lport->cleared_lflows = &dp_lport->ctrl_lflows[1];

        shash_add(&ld->lports, lport_name, dp_lport);
        dp_lport->ldp = ld;
        dp_lport->type = get_lport_type(pb);
        local_lport_init_cache(dp_lport);
    } else {
        local_lport_update_cache(dp_lport);
    }

    dp_lport->ldp = ld;
    dp_lport->type = get_lport_type(pb);

    return dp_lport;
}

struct local_lport *
local_datapath_get_lport(struct local_datapath *ld, const char *lport_name)
{
    struct shash_node *node = shash_find(&ld->lports, lport_name);
    return node ? node->data : NULL;
}

void
local_datapath_remove_lport(struct local_datapath *ld, const char *lport_name)
{
    struct local_lport *dp_lport = shash_find_and_delete(&ld->lports,
                                                         lport_name);
    if (dp_lport) {
        local_lport_destroy(dp_lport);
    }
}

void
local_lport_update_cache(struct local_lport *lport)
{
    if (local_lport_is_cache_old(lport)) {
        local_lport_clear_cache(lport);
        local_lport_init_cache(lport);
    }
}


void
local_lport_clear_cache(struct local_lport *lport)
{
    for (size_t i = 0; i < lport->n_addresses; i++) {
        free(lport->addresses[i]);
    }
    free(lport->addresses);
    lport->n_addresses = 0;
    for (size_t i = 0; i < lport->n_port_security; i++) {
        free(lport->port_security[i]);
    }
    free(lport->port_security);
    lport->n_port_security = 0;

    smap_destroy(&lport->options);

    local_lport_destroy_lflow_gen_data(lport);
}

bool
local_lport_is_cache_old(struct local_lport *lport)
{
    const struct sbrec_port_binding *pb = lport->pb;

    if (lport->n_addresses != pb->n_mac) {
        return true;
    }

    if (lport->n_port_security != pb->n_port_security) {
        return true;
    }

    if (!smap_equal(&lport->options, &pb->options)) {
        return true;
    }

    for (size_t i = 0; i < lport->n_addresses; i++) {
        if (strcmp(lport->addresses[i], pb->mac[i])) {
            return true;
        }
    }

    for (size_t i = 0; i < lport->n_port_security; i++) {
        if (strcmp(lport->port_security[i], pb->port_security[i])) {
            return true;
        }
    }

    bool claimed_ = !!pb->chassis;

    return (lport->claimed != claimed_);
}

static void
local_lport_init_lflow_gen_data(struct local_lport *lport)
{
    struct ds json_key = DS_EMPTY_INITIALIZER;
    json_string_escape(lport->pb->logical_port, &json_key);
    lport->json_key = ds_steal_cstr(&json_key);

    if (lport->ldp->is_switch) {
        local_lport_update_lsp_data(lport);
    } else {
        local_lport_update_lrp_data(lport);
    }
}

static void
local_lport_destroy_lflow_gen_data(struct local_lport *lport)
{
    free(lport->json_key);
    lport->json_key = NULL;
    if (lport->ldp->is_switch) {
        local_lport_destroy_lsp_data(lport);
    } else {
        local_lport_destroy_lrp_data(lport);
    }
}

void
local_lport_switch_lflow_map(struct local_lport *lport)
{
    struct hmap *temp = lport->active_lflows;
    lport->active_lflows = lport->cleared_lflows;
    lport->cleared_lflows = temp;

    /* Make sure that the active_lflows is empty. */
    ovs_assert(hmap_is_empty(lport->active_lflows));
}

struct local_lport *
local_datapath_unlink_lport(struct local_datapath *ld,
                                                const char *lport_name)
{
    return shash_find_and_delete(&ld->lports, lport_name);
}

void
local_lport_destroy(struct local_lport *dp_lport)
{
    ovn_ctrl_lflows_destroy(&dp_lport->ctrl_lflows[0]);
    ovn_ctrl_lflows_destroy(&dp_lport->ctrl_lflows[1]);
    local_lport_clear_cache(dp_lport);
    free(dp_lport);
}

struct tracked_datapath *
tracked_datapath_add(const struct sbrec_datapath_binding *dp,
                     enum en_tracked_resource_type tracked_type,
                     struct hmap *tracked_datapaths)
{
    struct tracked_datapath *t_dp =
        tracked_datapath_find(tracked_datapaths, dp);
    if (!t_dp) {
        t_dp = tracked_datapath_create(dp, tracked_type, tracked_datapaths);
    } else {
        t_dp->tracked_type = tracked_type;
    }

    return t_dp;
}

struct tracked_datapath *
tracked_datapath_find(struct hmap *tracked_datapaths,
                      const struct sbrec_datapath_binding *dp)
{
    struct tracked_datapath *t_dp;
    size_t hash = uuid_hash(&dp->header_.uuid);
    HMAP_FOR_EACH_WITH_HASH (t_dp, node, hash, tracked_datapaths) {
        if (uuid_equals(&t_dp->dp->header_.uuid, &dp->header_.uuid)) {
            return t_dp;
        }
    }

    return NULL;
}

void
tracked_datapath_lport_add(const struct sbrec_port_binding *pb,
                           enum en_tracked_resource_type tracked_type,
                           struct hmap *tracked_datapaths)
{
    struct tracked_datapath *tracked_dp =
        tracked_datapath_find(tracked_datapaths, pb->datapath);
    if (!tracked_dp) {
        tracked_dp = tracked_datapath_create(pb->datapath,
                                             TRACKED_RESOURCE_UPDATED,
                                             tracked_datapaths);
    }

    /* Check if the lport is already present or not.
     * If it is already present, then just update the 'pb' field. */
    struct tracked_lport *lport =
        shash_find_data(&tracked_dp->lports, pb->logical_port);

    if (!lport) {
        lport = xmalloc(sizeof *lport);
        shash_add(&tracked_dp->lports, pb->logical_port, lport);
    }

    lport->pb = pb;
    lport->tracked_type = tracked_type;
}

void
tracked_datapaths_destroy(struct hmap *tracked_datapaths)
{
    struct tracked_datapath *t_dp;
    HMAP_FOR_EACH_POP (t_dp, node, tracked_datapaths) {
        shash_destroy_free_data(&t_dp->lports);
        free(t_dp);
    }

    hmap_destroy(tracked_datapaths);
}

/* static functions. */
static void
local_lport_init_cache(struct local_lport *lport)
{
    const struct sbrec_port_binding *pb = lport->pb;
    smap_clone(&lport->options, &pb->options);

    lport->addresses =
        pb->n_mac ? xmalloc(pb->n_mac * sizeof *lport->addresses) :
        NULL;

    lport->n_addresses = pb->n_mac;
    for (size_t i = 0; i < pb->n_mac; i++) {
        lport->addresses[i] = xstrdup(pb->mac[i]);
    }

    lport->port_security =
        pb->n_port_security ?
        xmalloc(pb->n_port_security * sizeof *lport->port_security) :
        NULL;

    lport->n_port_security = pb->n_port_security;
    for (size_t i = 0; i < pb->n_port_security; i++) {
        lport->port_security[i] = xstrdup(pb->port_security[i]);
    }

    lport->claimed = !!pb->chassis;

    local_lport_init_lflow_gen_data(lport);
}

static struct local_datapath *
local_datapath_add__(struct hmap *local_datapaths,
                     const struct sbrec_datapath_binding *dp,
                     struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     int depth,
                     void (*datapath_added_cb)(
                           struct local_datapath *ld,
                           void *aux),
                     void *aux)
{
    uint32_t dp_key = dp->tunnel_key;
    struct local_datapath *ld = get_local_datapath(local_datapaths, dp_key);
    if (ld) {
        return ld;
    }

    ld = local_datapath_alloc(dp);
    hmap_insert(local_datapaths, &ld->hmap_node, dp_key);
    ld->datapath = dp;

    if (datapath_added_cb) {
        datapath_added_cb(ld, aux);
    }

    if (depth >= 100) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "datapaths nested too deep");
        return ld;
    }

    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_datapath);
    sbrec_port_binding_index_set_datapath(target, dp);

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                       sbrec_port_binding_by_datapath) {
        struct local_lport *lport =
            local_datapath_add_lport(ld, pb->logical_port, pb);

        if (!strcmp(pb->type, "patch") || !strcmp(pb->type, "l3gateway")) {
            const char *peer_name = smap_get(&pb->options, "peer");
            if (peer_name) {
                const struct sbrec_port_binding *peer;

                peer = lport_lookup_by_name(sbrec_port_binding_by_name,
                                            peer_name);

                if (peer && peer->datapath) {
                    if (!strcmp(pb->type, "patch")) {
                        /* Add the datapath to local datapath only for patch
                         * ports. For l3gateway ports, since gateway router
                         * resides on one chassis, we don't need to add.
                         * Otherwise, all other chassis might create patch
                         * ports between br-int and the provider bridge. */
                        local_datapath_add__(local_datapaths, peer->datapath,
                                             sbrec_datapath_binding_by_key,
                                             sbrec_port_binding_by_datapath,
                                             sbrec_port_binding_by_name,
                                             depth + 1, datapath_added_cb,
                                             aux);
                    }
                    struct local_datapath *peer_ld =
                        get_local_datapath(local_datapaths, peer->datapath->tunnel_key);
                    if (peer_ld){
                        struct local_lport *peer_lport =
                            local_datapath_get_lport(peer_ld, peer->logical_port);

                        if (peer_lport) {
                            ld->n_peer_ports++;
                            if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
                                ld->peer_ports =
                                    x2nrealloc(ld->peer_ports,
                                            &ld->n_allocated_peer_ports,
                                            sizeof *ld->peer_ports);
                            }

                            ld->peer_ports[ld->n_peer_ports - 1].local = lport;
                            ld->peer_ports[ld->n_peer_ports - 1].remote = peer_lport;

                            lport->peer = peer_lport;
                            peer_lport->peer = lport;
                        }
                    }
                }
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
    return ld;
}

static struct tracked_datapath *
tracked_datapath_create(const struct sbrec_datapath_binding *dp,
                        enum en_tracked_resource_type tracked_type,
                        struct hmap *tracked_datapaths)
{
    struct tracked_datapath *t_dp = xzalloc(sizeof *t_dp);
    t_dp->dp = dp;
    t_dp->tracked_type = tracked_type;
    shash_init(&t_dp->lports);
    hmap_insert(tracked_datapaths, &t_dp->node, uuid_hash(&dp->header_.uuid));
    return t_dp;
}

static void
local_lport_destroy_lsp_data(struct local_lport *lport)
{
    if (lport->lsp.n_addrs) {
        destroy_lport_addresses(lport->lsp.addrs);
    }

    if (lport->lsp.n_ps_addrs){
        destroy_lport_addresses(lport->lsp.ps_addrs);
    }

    free(lport->lsp.addrs);
    free(lport->lsp.ps_addrs);
    lport->lsp.addrs = NULL;
    lport->lsp.ps_addrs = NULL;
    lport->lsp.n_addrs = 0;
    lport->lsp.n_ps_addrs = 0;
}

static void
local_lport_destroy_lrp_data(struct local_lport *lport)
{
    destroy_lport_addresses(&lport->lrp.networks);
    if (lport->lrp.is_l3dgw_port) {
        free(lport->lrp.chassis_redirect_json_key);
    }
}

static void
local_lport_update_lsp_data(struct local_lport *lport)
{
    lport->lsp.addrs = xmalloc(sizeof *lport->lsp.addrs * lport->pb->n_mac);
    lport->lsp.ps_addrs =
        xmalloc(sizeof *lport->lsp.ps_addrs * lport->pb->n_mac);
    for (size_t i = 0; i < lport->pb->n_mac; i++) {
        if (!strcmp(lport->pb->mac[i], "unknown")) {
            lport->lsp.has_unknown = true;
            continue;
        }
        if (!strcmp(lport->pb->mac[i], "router")) {
            continue;
        }

        if (!extract_lsp_addresses(lport->pb->mac[i],
                                   &lport->lsp.addrs[lport->lsp.n_addrs])) {
            continue;
        }

        lport->lsp.n_addrs++;
    }

    for (size_t i = 0; i < lport->pb->n_port_security; i++) {
        if (!extract_lsp_addresses(
            lport->pb->port_security[i],
            &lport->lsp.ps_addrs[lport->lsp.n_ps_addrs])) {
            continue;
        }
        lport->lsp.n_ps_addrs++;
    }

    lport->lsp.check_lport_is_up =
        !smap_get_bool(&lport->pb->datapath->options,
        "ignore_lport_down", false);
}

static void
local_lport_update_lrp_data(struct local_lport *lport)
{
    if (!extract_lsp_addresses(lport->pb->mac[0], &lport->lrp.networks)) {
        return;
    }

    /* Always add the IPv6 link local address. */
    struct in6_addr lla;
    in6_generate_lla(lport->lrp.networks.ea, &lla);
    lport_addr_add_ip6ddr(&lport->lrp.networks, lla, 64);

    struct ds json_key = DS_EMPTY_INITIALIZER;
    json_string_escape(lport->pb->logical_port, &json_key);
    lport->json_key = ds_steal_cstr(&json_key);

    lport->lrp.is_l3dgw_port = smap_get_bool(&lport->pb->options,
                                             "is-l3dgw-port", false);
    if (lport->lrp.is_l3dgw_port) {
        char *chassis_redirect_name =
            ovn_chassis_redirect_name(lport->pb->logical_port);
        json_string_escape(chassis_redirect_name, &json_key);
        lport->lrp.chassis_redirect_json_key = ds_steal_cstr(&json_key);
        free(chassis_redirect_name);
    }

    lport->lrp.dp_has_l3dgw_port = smap_get_bool(&lport->pb->datapath->options,
                                          "has-l3dgw-port", false);

    lport->lrp.peer_dp_has_localnet_ports =
        smap_get_bool(&lport->pb->options,
                      "peer-dp-has-localnet-ports", false);
}
