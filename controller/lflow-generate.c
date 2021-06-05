/*
 * Copyright (c) 2021 Red Hat, Inc.
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
#include "lflow-generate.h"
#include "lib/lflow.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

static void generate_lflows_for_lport(const struct sbrec_port_binding *,
                                      struct hmap *local_datapaths);

void
lflow_generate_run(struct hmap *local_datapaths,
                   const struct sbrec_port_binding_table *pb_table)
{
    struct local_datapath *ldp;
    HMAP_FOR_EACH (ldp, hmap_node, local_datapaths) {
        ovn_ctrl_lflows_build_dp_lflows(&ldp->ctrl_lflows, ldp->datapath);
    }

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (pb, pb_table) {
        generate_lflows_for_lport(pb, local_datapaths);
    }
}

bool
lflow_generate_handle_port_binding_changes(
    struct hmap *local_datapaths,
    const struct sbrec_port_binding_table *pb_table)
{
    return false;

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb, pb_table) {
        generate_lflows_for_lport(pb, local_datapaths);
    }

    return true;
}

void
lflow_generate_delete_lflows(struct hmap *local_datapaths)
{
    struct local_datapath *ldp;
    HMAP_FOR_EACH (ldp, hmap_node, local_datapaths) {
        ovn_ctrl_lflows_clear(&ldp->ctrl_lflows);

        struct local_lport *lport;
        struct shash_node *node, *next;
        SHASH_FOR_EACH_SAFE (node, next, &ldp->lports) {
            lport = node->data;
            shash_delete(&ldp->lports, node);
            local_lport_destroy(lport);
        }
    }
}

static void
generate_lflows_for_lport(const struct sbrec_port_binding *pb,
                          struct hmap *local_datapaths)
{
    struct local_datapath *ldp =
        get_local_datapath(local_datapaths, pb->datapath->tunnel_key);
    if (!ldp) {
        return;
    }

    struct local_lport *dp_lport =
        local_datapath_add_lport(ldp, pb->logical_port, pb);
    ovn_ctrl_build_lport_lflows(&dp_lport->ctrl_lflows, pb);
}
