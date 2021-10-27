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

#include "en-northd.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/list.h" /* TODO This is needed for ovn-parallel-hmap.h.
                               * lib/ovn-parallel-hmap.h should be updated
                               * to include this dependency itself */
#include "lib/ovn-parallel-hmap.h"
#include "northd.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_northd);

void en_northd_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();

    northd_destroy(data);
    northd_init(data);

    struct northd_data *northd_data = data;
    northd_data->input.sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_chassis", node),
            "sbrec_chassis_by_name");
    northd_data->input.sbrec_chassis_by_hostname =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_chassis", node),
            "sbrec_chassis_by_hostname");
    northd_data->input.sbrec_ha_chassis_grp_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_ha_chassis_group", node),
            "sbrec_ha_chassis_grp_by_name");
    northd_data->input.sbrec_mcast_group_by_name_dp =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_multicast_group", node),
            "sbrec_mcast_group_by_name");
    northd_data->input.sbrec_ip_mcast_by_dp =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_ip_multicast", node),
            "sbrec_ip_mcast_by_dp");

    northd_data->input.nbrec_nb_global_table =
        EN_OVSDB_GET(engine_get_input("NB_nb_global", node));
    northd_data->input.nbrec_logical_switch =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    northd_data->input.nbrec_logical_router =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    northd_data->input.nbrec_load_balancer_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));
    northd_data->input.nbrec_port_group_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    northd_data->input.nbrec_bfd_table =
        EN_OVSDB_GET(engine_get_input("NB_bfd", node));
    northd_data->input.nbrec_address_set_table =
        EN_OVSDB_GET(engine_get_input("NB_address_set", node));
    northd_data->input.nbrec_meter_table =
        EN_OVSDB_GET(engine_get_input("NB_meter", node));
    northd_data->input.nbrec_acl_table =
        EN_OVSDB_GET(engine_get_input("NB_acl", node));

    northd_data->input.sbrec_sb_global_table =
        EN_OVSDB_GET(engine_get_input("SB_sb_global", node));
    northd_data->input.sbrec_datapath_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_datapath_binding", node));
    northd_data->input.sbrec_port_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    northd_data->input.sbrec_mac_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_mac_binding", node));
    northd_data->input.sbrec_ha_chassis_group_table =
        EN_OVSDB_GET(engine_get_input("SB_ha_chassis_group", node));
    northd_data->input.sbrec_chassis =
        EN_OVSDB_GET(engine_get_input("SB_chassis", node));
    northd_data->input.sbrec_fdb_table =
        EN_OVSDB_GET(engine_get_input("SB_fdb", node));
    northd_data->input.sbrec_load_balancer_table =
        EN_OVSDB_GET(engine_get_input("SB_load_balancer", node));
    northd_data->input.sbrec_service_monitor_table =
        EN_OVSDB_GET(engine_get_input("SB_service_monitor", node));
    northd_data->input.sbrec_bfd_table =
        EN_OVSDB_GET(engine_get_input("SB_bfd", node));
    northd_data->input.sbrec_logical_flow_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_flow", node));
    northd_data->input.sbrec_multicast_group_table =
        EN_OVSDB_GET(engine_get_input("SB_multicast_group", node));
    northd_data->input.sbrec_address_set_table =
        EN_OVSDB_GET(engine_get_input("SB_address_set", node));
    northd_data->input.sbrec_port_group_table =
        EN_OVSDB_GET(engine_get_input("SB_port_group", node));
    northd_data->input.sbrec_meter_table =
        EN_OVSDB_GET(engine_get_input("SB_meter", node));
    northd_data->input.sbrec_dns_table =
        EN_OVSDB_GET(engine_get_input("SB_dns", node));
    northd_data->input.sbrec_ip_multicast_table =
        EN_OVSDB_GET(engine_get_input("SB_ip_multicast", node));
    northd_data->input.sbrec_igmp_group_table =
        EN_OVSDB_GET(engine_get_input("SB_igmp_group", node));
    northd_data->input.sbrec_chassis_private_table =
        EN_OVSDB_GET(engine_get_input("SB_chassis_private", node));

    northd_run(data,
               eng_ctx->ovnnb_idl_txn,
               eng_ctx->ovnsb_idl_txn,
               eng_ctx->ovnsb_idl_loop);
    engine_set_node_state(node, EN_UPDATED);

}
void *en_northd_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct northd_data *data = xmalloc(sizeof *data);

    northd_init(data);

    return data;
}

void en_northd_cleanup(void *data)
{
    northd_destroy(data);
    free(data);
}
