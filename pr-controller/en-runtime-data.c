/*
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "openvswitch/vlog.h"
#include "include/openvswitch/hmap.h"
#include "include/openvswitch/shash.h"
#include "lib/dirs.h"
#include "lib/vswitch-idl.h"

/* OVN includes. */
#include "en-runtime-data.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-pr-idl.h"

VLOG_DEFINE_THIS_MODULE(en_runtime_data);

static void pr_bridges_init(struct shash *);
static void pr_bridges_cleanup(struct shash *);
static void pr_bridges_run(const struct prrec_pr_bridge_table *,
                           struct shash *bridges,
                           struct ovsdb_idl_index *);
static void pr_bridge_destroy(struct pr_bridge *);
static const struct ovsrec_bridge *ovsbridge_lookup_by_name(
    struct ovsdb_idl_index *ovsrec_bridge_by_name,
    const char *name);
static void build_pr_bridge_iface_simap(struct pr_bridge *);
static void update_pr_br_remote(struct pr_bridge *);

void *
en_runtime_data_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_runtime_data *data = xzalloc(sizeof *data);
    pr_bridges_init(&data->bridges);

    return data;
}

void
en_runtime_data_cleanup(void *data_)
{
    struct ed_type_runtime_data *data = data_;
    pr_bridges_cleanup(&data->bridges);
    free(data);
}

enum engine_node_state
en_runtime_data_run(struct engine_node *node, void *data_)
{
    const struct prrec_pr_bridge_table *prrec_br_table =
        EN_OVSDB_GET(engine_get_input("PR_pr_bridge", node));

    
    struct ovsdb_idl_index *ovsrec_bridge_by_name =
        engine_ovsdb_node_get_index(engine_get_input("OVS_bridge", node),
                                    "name");
    struct ed_type_runtime_data *data = data_;

    pr_bridges_cleanup(&data->bridges);
    pr_bridges_init(&data->bridges);
    pr_bridges_run(prrec_br_table, &data->bridges, ovsrec_bridge_by_name);

    return EN_UPDATED;
}

/* Static functions. */
static void
pr_bridges_init(struct shash *bridges)
{
    shash_init(bridges);
}

static void
pr_bridges_cleanup(struct shash *bridges)
{
    struct shash_node *shash_node;
    SHASH_FOR_EACH_SAFE (shash_node, bridges) {
        pr_bridge_destroy(shash_node->data);
    }
    shash_destroy(bridges);
}

static void
pr_bridges_run(const struct prrec_pr_bridge_table *prrec_br_table,
               struct shash *bridges,
               struct ovsdb_idl_index *ovsrec_bridge_by_name)
{
    const struct prrec_pr_bridge *prrec_br;
    PRREC_PR_BRIDGE_TABLE_FOR_EACH (prrec_br, prrec_br_table) {
        struct pr_bridge *br = xzalloc(sizeof *br);
        br->db_br = prrec_br;
        br->key = prrec_br->header_.uuid;
        simap_init(&br->ovs_ifaces);
        shash_add(bridges, prrec_br->name, br);

        const struct ovsrec_bridge *ovs_br =
            ovsbridge_lookup_by_name(ovsrec_bridge_by_name, prrec_br->name);
        
        if (!ovs_br) {
            continue;
        }

        br->ovs_br = ovs_br;
        build_pr_bridge_iface_simap(br);
        update_pr_br_remote(br);
    }
}

static void
pr_bridge_destroy(struct pr_bridge *br)
{
    simap_destroy(&br->ovs_ifaces);
    free(br->conn_target);
    free(br);
}

static const struct ovsrec_bridge *
ovsbridge_lookup_by_name(struct ovsdb_idl_index *ovsrec_bridge_by_name,
                         const char *name)
{
    struct ovsrec_bridge *target =
        ovsrec_bridge_index_init_row(ovsrec_bridge_by_name);
    ovsrec_bridge_index_set_name(target, name);

    const struct ovsrec_bridge *retval =
        ovsrec_bridge_index_find(ovsrec_bridge_by_name, target);
    ovsrec_bridge_index_destroy_row(target);

    return retval;
}

static void
build_pr_bridge_iface_simap(struct pr_bridge *pr_br)
{
    ovs_assert(pr_br->ovs_br);
    for (size_t i = 0; i < pr_br->ovs_br->n_ports; i++) {
        const struct ovsrec_port *port_rec = pr_br->ovs_br->ports[i];

        for (size_t j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
            if (ofport) {
                simap_put(&pr_br->ovs_ifaces, iface_rec->name, ofport);
            }
        }
    }
}

static void
update_pr_br_remote(struct pr_bridge *br)
{
    ovs_assert(br->ovs_br);

    const char *ext_target = smap_get(&br->ovs_br->external_ids,
                                      "ovn-bridge-remote");
    char *target = ext_target
        ? xstrdup(ext_target)
        : xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br->ovs_br->name);

    if (!br->conn_target || strcmp(br->conn_target, target)) {
        free(br->conn_target);
        br->conn_target = target;
    } else {
        free(target);
    }

    unsigned long long probe_interval =
        smap_get_ullong(&br->ovs_br->external_ids,
                        "ovn-openflow-remote-probe-interval", 0);
    br->probe_interval = MIN(probe_interval / 1000, INT_MAX);

    unsigned int _wait_before_clear_time =
        smap_get_uint(&br->ovs_br->external_ids, "ovn-ofctrl-wait-before-clear", 0);

    if (_wait_before_clear_time != br->wait_before_clear_time) {
        VLOG_INFO("ofctrl-wait-before-clear is now %u ms (was %u ms) "
                  "for bridge %s",
                  _wait_before_clear_time, br->wait_before_clear_time,
                  br->ovs_br->name);
        br->wait_before_clear_time = _wait_before_clear_time;
    }
}
