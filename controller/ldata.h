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
#include "ofctrl.h"

struct sbrec_datapath_binding;
struct sbrec_port_binding;

struct local_lport {
    const struct sbrec_port_binding *pb;

    char **addresses;
    size_t n_addresses;
    char **port_security;
    size_t n_port_security;
    struct smap options;

    struct hmap ctrl_lflows;
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
        const struct sbrec_port_binding *local;
        const struct sbrec_port_binding *remote;
    } *peer_ports;

    size_t n_peer_ports;
    size_t n_allocated_peer_ports;

    struct hmap ctrl_lflows;
    struct ovn_desired_flow_table flow_table; /* Flow table per datapath. */

    /* shash of 'struct local_lport'. */
    struct shash lports;
};

struct local_datapath *local_datapath_alloc(
    const struct sbrec_datapath_binding *);
struct local_datapath *get_local_datapath(const struct hmap *,
                                          uint32_t tunnel_key);
void local_datapath_destroy(struct local_datapath *ld);
struct local_lport *local_datapath_get_lport(struct local_datapath *ld,
                                             const char *lport_name);

struct local_lport *local_datapath_add_lport(
    struct local_datapath *ld, const char *lport_name,
    const struct sbrec_port_binding *);

void local_datapath_remove_lport(struct local_datapath *ld,
                                 const char *lport_name);

struct local_lport *local_datapath_unlink_lport(struct local_datapath *ld,
                                                const char *lport_name);

void local_lport_destroy(struct local_lport *local_lport);

#endif /* controller/ldata.h */
