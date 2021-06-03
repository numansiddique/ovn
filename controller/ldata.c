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
#include "lib/hmapx.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "ldata.h"
#include "lib/ovn-util.h"
#include "lib/lflow.h"
#include "ofctrl.h"

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
    hmap_init(&ld->ctrl_lflows);
    ovn_desired_flow_table_init(&ld->flow_table);
    shash_init(&ld->lports);
    return ld;
}

void
local_datapath_destroy(struct local_datapath *ld)
{
    ovn_ctrl_lflows_destroy(&ld->ctrl_lflows);
    ovn_desired_flow_table_destroy(&ld->flow_table);
    free(ld->peer_ports);
    free(ld);

    struct local_lport *dp_lport;
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &ld->lports) {
        hmap_remove(&ld->lports.map, &node->node);
        dp_lport = node->data;
        ovn_ctrl_lflows_destroy(&dp_lport->ctrl_lflows);
        free(dp_lport);
        free(node->name);
        free(node);
    }

    hmap_destroy(&ld->lports.map);
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
        hmap_init(&dp_lport->ctrl_lflows);
        shash_add(&ld->lports, lport_name, dp_lport);
    }

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
        ovn_ctrl_lflows_destroy(&dp_lport->ctrl_lflows);
        free(dp_lport);
    }
}
