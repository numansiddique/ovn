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
#ifndef NORTHD_H
#define NORTHD_H 1

#include "ovsdb-idl.h"
#include "lib/ovn-parallel-hmap.h"

struct northd_context {
    const char *ovnnb_db;
    const char *ovnsb_db;
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_loop *ovnnb_idl_loop;
    struct ovsdb_idl_loop *ovnsb_idl_loop;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name;
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp;
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp;

    bool use_parallel_build;
    struct hashrow_locks *lflow_locks;

    const char *ovn_internal_version;
};

struct common_lflows_data {
    struct hmap lswitch_lflows;
    struct hmap lrouter_lflows;
    struct sbrec_logical_dp_group *lswitch_dp_group;
    struct sbrec_logical_dp_group *lrouter_dp_group;
    struct uuid lswitch_dp_group_uuid;
    struct uuid lrouter_dp_group_uuid;
};

void ovn_db_run(struct northd_context *ctx, struct ovs_list *,
                struct hmap *, struct hmap *, struct common_lflows_data *);
void destroy_datapaths_and_ports(struct hmap *datapaths, struct hmap *ports,
                                 struct ovs_list *lr_list);

void common_lflows_init(struct common_lflows_data *common_lflows_data);
void common_lflows_build(struct common_lflows_data *common_lflows_data);
void common_lflows_destroy(struct common_lflows_data *common_lflows_data);

#endif /* NORTHD_H */
