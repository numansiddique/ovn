/*
 * Copyright (c) 2021 Canonical
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

#ifndef PLUG_H
#define PLUG_H 1

/*
 * Plug, the controller internal interface to the plug provider infrastructure.
 */

#include "openvswitch/shash.h"
#include "smap.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct plug_ctx_in {
    struct ovsdb_idl_txn *ovs_idl_txn;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *ovsrec_port_by_interfaces;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_bridge *br_int;
    const struct ovsrec_interface_table *iface_table;
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding_table *port_binding_table;
    const struct shash *local_bindings;
    bool pb_handler_has_run;
};

struct plug_ctx_out {
    struct shash *deleted_iface_ids;
    struct shash *changed_iface_ids;
};

struct plug_class;
struct plug_port_ctx_out;
struct plug_port_ctx_in;

const struct sset * plug_get_maintained_iface_options(
    const struct plug_class *plug_class);

bool plug_port_prepare(const struct plug_class *,
                       const struct plug_port_ctx_in *,
                       struct plug_port_ctx_out *);
void plug_port_finish(const struct plug_class *,
                      const struct plug_port_ctx_in *,
                      struct plug_port_ctx_out *);
void plug_port_ctx_destroy(const struct plug_class *,
                           const struct plug_port_ctx_in *,
                           struct plug_port_ctx_out *);

struct ovsdb_idl;

void plug_register_ovs_idl(struct ovsdb_idl *ovs_idl);
void plug_run(struct plug_ctx_in *, struct plug_ctx_out *);
bool plug_handle_port_binding_changes(struct plug_ctx_in *,
                                      struct plug_ctx_out *);
bool plug_handle_ovs_interface_changes(struct plug_ctx_in *,
                                       struct plug_ctx_out *);
void plug_clear_changed(struct shash *deleted_iface_ids);
void plug_finish_changed(struct shash *changed_iface_ids);
void plug_clear_deleted(struct shash *deleted_iface_ids);
void plug_finish_deleted(struct shash *changed_iface_ids);

#ifdef  __cplusplus
}
#endif

#endif /* plug.h */
