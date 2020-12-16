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
#include "lib/lb.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

VLOG_DEFINE_THIS_MODULE(lflow_gen);

static void generate_lflows_for_lport__(struct local_lport *dp_lport);

void
lflow_generate_run(struct hmap *local_datapaths, struct hmap *local_lbs)
{
    struct local_datapath *ldp;
    HMAP_FOR_EACH (ldp, hmap_node, local_datapaths) {
        ovn_ctrl_lflows_build_dp_lflows(ldp->active_lflows, ldp);

        struct shash_node *node;
        SHASH_FOR_EACH (node, &ldp->lports) {
            generate_lflows_for_lport__(node->data);
        }
    }

    struct local_load_balancer *local_lb;
    HMAP_FOR_EACH (local_lb, hmap_node, local_lbs) {
        lflow_generate_load_balancer_lflows(local_lb);
    }
}

void
lflow_generate_datapath_flows(struct local_datapath *ldp,
                              bool build_lport_flows)
{
    local_datapath_switch_lflow_map(ldp);
    ovn_ctrl_lflows_build_dp_lflows(ldp->active_lflows, ldp);

    if (build_lport_flows) {
        struct shash_node *node;
        SHASH_FOR_EACH (node, &ldp->lports) {
            generate_lflows_for_lport__(node->data);
        }
    }
}

void
lflow_generate_lport_flows(const struct sbrec_port_binding *pb,
                           struct local_datapath *ldp)
{
    struct local_lport *lport =
        local_datapath_get_lport(ldp, pb->logical_port);
    if (lport) {
        generate_lflows_for_lport__(lport);
    } else {
        lport = local_datapath_add_lport(ldp, pb->logical_port, pb);
        local_lport_update_cache(lport);
        ovn_ctrl_build_lport_lflows(lport->active_lflows, lport);
    }
}

void
lflow_delete_generated_lport_lflows(const struct sbrec_port_binding *pb,
                                    struct local_datapath *ldp)
{
    struct local_lport *lport =
        local_datapath_get_lport(ldp, pb->logical_port);
    if (lport) {
        local_lport_switch_lflow_map(lport);
    }
}

void
lflow_delete_generated_lflows(struct hmap *local_datapaths,
                              struct hmap *local_lbs)
{
    struct local_datapath *ldp;
    HMAP_FOR_EACH (ldp, hmap_node, local_datapaths) {
        ovn_ctrl_lflows_clear(&ldp->ctrl_lflows[0]);
        ovn_ctrl_lflows_clear(&ldp->ctrl_lflows[1]);

        struct local_lport *lport;
        struct shash_node *node;
        SHASH_FOR_EACH (node, &ldp->lports) {
            lport = node->data;
            ovn_ctrl_lflows_clear(&lport->ctrl_lflows[0]);
            ovn_ctrl_lflows_clear(&lport->ctrl_lflows[1]);
        }
    }

    struct local_load_balancer *local_lb;
    HMAP_FOR_EACH (local_lb, hmap_node, local_lbs) {
        ovn_ctrl_lflows_clear(&local_lb->lswitch_lflows[0]);
        ovn_ctrl_lflows_clear(&local_lb->lswitch_lflows[1]);
        ovn_ctrl_lflows_clear(&local_lb->lrouter_lflows[0]);
        ovn_ctrl_lflows_clear(&local_lb->lrouter_lflows[1]);
    }
}


/* Returns true if the local datapath 'ldp' needs logical flow
 * generation.  False otherwise.
 */
bool
lflow_datapath_needs_generation(struct local_datapath *ldp)
{
    ovs_assert(ldp->datapath);

    /* Right now we check if the datapath options have changed
     * from the locally stored value. */
    return !smap_equal(&ldp->dp_options, &ldp->datapath->options);
}

bool
lflow_lport_needs_generation(struct local_datapath *ldp,
                             const struct sbrec_port_binding *pb)
{
    struct local_lport *dp_lport = local_datapath_get_lport(
        ldp, pb->logical_port);

    if (!dp_lport) {
        return true;
    }

    return local_lport_update_cache(dp_lport);
}

void
lflow_generate_load_balancer_lflows(struct local_load_balancer *local_lb)
{
    ovn_ctrl_build_lb_lflows(local_lb->active_lswitch_lflows,
                             local_lb->active_lrouter_lflows,
                             local_lb->ovn_lb);
}

bool
lflow_load_balancer_needs_gen(struct local_load_balancer *local_lb)
{
    local_load_balancer_update(local_lb);
    return true;
}


void
lflow_clear_generated_lb_lflows(struct local_load_balancer *local_lb)
{
    local_load_balancer_switch_lflow_map(local_lb);
}

static void
generate_lflows_for_lport__(struct local_lport *dp_lport)
{
    local_lport_switch_lflow_map(dp_lport);
    local_lport_update_cache(dp_lport);
    ovn_ctrl_build_lport_lflows(dp_lport->active_lflows, dp_lport);
}
