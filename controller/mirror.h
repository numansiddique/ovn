/* Copyright (c) 2022 Red Hat, Inc.
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

#ifndef OVN_MIRROR_H
#define OVN_MIRROR_H 1

struct ovsdb_idl_txn;
struct ovsrec_port_table;
struct ovsrec_bridge;
struct ovsrec_bridge_table;
struct ovsrec_open_vswitch_table;
struct sbrec_chassis;
struct ovsrec_interface_table;
struct ovsrec_mirror_table;
struct sbrec_mirror_table;
struct sbrec_port_binding_table;

struct port_mirror_ctx {
    struct shash *ovs_mirrors;
    struct ovsdb_idl_txn *ovs_idl_txn;
    const struct ovsrec_port_table *port_table;
    const struct ovsrec_bridge *br_int;
    const struct sbrec_chassis *chassis_rec;
    const struct ovsrec_bridge_table *bridge_table;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_interface_table *iface_table;
    const struct ovsrec_mirror_table *mirror_table;
    const struct sbrec_mirror_table *sb_mirror_table;
    const struct sbrec_port_binding_table *port_binding_table;
    struct shash *local_bindings;
};

void mirror_register_ovs_idl(struct ovsdb_idl *);
void ovn_port_mirror_init(struct shash *);
void ovn_port_mirror_destroy(struct shash *);
void ovn_port_mirror_run(struct port_mirror_ctx *pm_ctx);
bool ovn_port_mirror_handle_lport(const struct sbrec_port_binding *pb,
                                  bool removed,
                                  struct port_mirror_ctx *pm_ctx);
bool ovn_port_mirror_handle_update(struct port_mirror_ctx *pm_ctx);
#endif
