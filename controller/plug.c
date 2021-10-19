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

#include <config.h>

/* OVS includes */
#include "lib/vswitch-idl.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

/* OVN includes */
#include "binding.h"
#include "lib/ovn-sb-idl.h"
#include "lport.h"
#include "ovsport.h"
#include "plug.h"
#include "plug-provider.h"

VLOG_DEFINE_THIS_MODULE(plug);

#define OVN_PLUGGED_EXT_ID "ovn-plugged"

void
plug_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_mtu_request);
}

/* Get the class level 'maintained_iface_options' set. */
const struct sset *
plug_get_maintained_iface_options(const struct plug_class *plug_class)
{
    return plug_class->plug_get_maintained_iface_options ?
           plug_class->plug_get_maintained_iface_options() : NULL;
}

/* Prepare the logical port as identified by 'ctx_in' for port creation, update
 * or removal as specified by 'ctx_in->op_type'.
 *
 * When 'ctx_in->op_type' is PLUG_OP_CREATE the plug implementation must fill
 * 'ctx_out' with data to apply to the interface record maintained by OVN on
 * its behalf.
 *
 * When 'ctx_in_op_type' is PLUG_OP_REMOVE 'ctx_out' should be set to NULL and
 * the plug implementation must not attempt to use 'ctx_out'.
 *
 * The data in 'ctx_out' is owned by the plug implementation, and a call must
 * be made to plug_port_ctx_destroy when done with it. */
bool
plug_port_prepare(const struct plug_class *plug_class,
                  const struct plug_port_ctx_in *ctx_in,
                  struct plug_port_ctx_out *ctx_out)
{
    return plug_class->plug_port_prepare(ctx_in, ctx_out);
}

/* Notify the plug implementation that a port creation, update or removal has
 * been completed */
void
plug_port_finish(const struct plug_class *plug_class,
                 const struct plug_port_ctx_in *ctx_in,
                 struct plug_port_ctx_out *ctx_out)
{
    plug_class->plug_port_finish(ctx_in, ctx_out);
}

/* Free any data allocated to 'ctx_out' in a prevous call to
 * plug_port_prepare. */
void
plug_port_ctx_destroy(const struct plug_class *plug_class,
                      const struct plug_port_ctx_in *ctx_in,
                      struct plug_port_ctx_out *ctx_out)
{
    plug_class->plug_port_ctx_destroy(ctx_in, ctx_out);
}

static struct plug_port_ctx *
build_port_ctx(const struct plug_class *plug,
                  const enum plug_op_type op_type,
                  const struct plug_ctx_in *plug_ctx_in,
                  const struct sbrec_port_binding *pb,
                  const struct ovsrec_interface *iface,
                  const char *iface_id)
{
    struct plug_port_ctx *new_ctx = xzalloc(
        sizeof *new_ctx);

    new_ctx->plug = plug;
    new_ctx->plug_port_ctx_in.op_type = op_type;
    new_ctx->plug_port_ctx_in.ovs_table = plug_ctx_in->ovs_table;
    new_ctx->plug_port_ctx_in.br_int = plug_ctx_in->br_int;
    new_ctx->plug_port_ctx_in.lport_name = pb ?
        xstrdup(pb->logical_port) : iface_id ? xstrdup(iface_id) : NULL;
    /* Prepare plug_port_ctx_in smaps for use.
     *
     * Note that smap_init does not allocate memory.  Any memory allocated by
     * putting data into the plug_port_ctx_in smaps will be destroyed by calls
     * to smap_destroy in destroy_port_ctx */
    smap_init(&new_ctx->plug_port_ctx_in.lport_options);
    smap_init(&new_ctx->plug_port_ctx_in.iface_options);

    if (pb) {
        smap_clone(&new_ctx->plug_port_ctx_in.lport_options,
                   &pb->options);
    }

    if (iface) {
        new_ctx->plug_port_ctx_in.iface_name = xstrdup(iface->name);
        new_ctx->plug_port_ctx_in.iface_type = xstrdup(iface->type);
        smap_clone(&new_ctx->plug_port_ctx_in.iface_options,
                   &iface->options);
    }

    /* Prepare plug_port_ctx_out smaps for use.
     *
     * Note that smap_init does not allocate memory.  Any memory allocated by
     * putting data into the plug_port_ctx_out smaps is the responsibility of
     * the plug provider through a call to plug_port_ctx_destroy. */
    smap_init(&new_ctx->plug_port_ctx_out.iface_options);

    return new_ctx;
}

static void
destroy_port_ctx(struct plug_port_ctx *ctx)
{
    smap_destroy(&ctx->plug_port_ctx_in.lport_options);
    smap_destroy(&ctx->plug_port_ctx_in.iface_options);
    if (ctx->plug_port_ctx_in.lport_name) {
        free((char *)ctx->plug_port_ctx_in.lport_name);
    }
    if (ctx->plug_port_ctx_in.iface_name) {
        free((char *)ctx->plug_port_ctx_in.iface_name);
    }
    if (ctx->plug_port_ctx_in.iface_type) {
        free((char *)ctx->plug_port_ctx_in.iface_type);
    }
    /* Note that data associated with ctx->plug_port_ctx_out must be destroyed
     * by the plug provider implementation with a call to plug_port_ctx_destroy
     * prior to calling this function */
    free(ctx);
}

/* When we add deletion of rows to the transaction, the data structures
 * associated with the rows will immediately be freed from the IDL, and as
 * such we can no longer access them.
 *
 * Since IDL commits are handled asynchronously we can have a few engine
 * iterations where the deleted data shows up when iterating over table
 * contents, but the IDL *_is_deleted() call will not reliably categorize the
 * data as deleted.  This is in contrast to the IDL behaviour when some other
 * process deletes data from the database, so this may be an OVS IDL bug, or it
 * could be it's just expected that the program consuming the IDL will know not
 * to access rows it has deleted.
 *
 * To deal with this, we keep a reference for ourself to avoid attempting to
 * remove the same data multiple times while waiting for the transaction to
 * commit.  The tracking data will be cleared after commit at the end of the
 * ovn-controller main loop.
 */
static void
transact_delete_port(const struct plug_ctx_in *plug_ctx_in,
                     const struct plug_ctx_out *plug_ctx_out,
                     const struct plug_port_ctx *plug_port_ctx,
                     const struct ovsrec_port *port)
{
    shash_add(plug_ctx_out->deleted_iface_ids,
              plug_port_ctx->plug_port_ctx_in.lport_name,
              plug_port_ctx);
    ovsport_remove(plug_ctx_in->br_int, port);
}

static void
transact_create_port(const struct plug_ctx_in *plug_ctx_in,
                     const struct plug_ctx_out *plug_ctx_out,
                     const struct plug_port_ctx *plug_port_ctx,
                     const struct smap *iface_external_ids,
                     const int64_t mtu_request)
{
    shash_add(plug_ctx_out->changed_iface_ids,
              plug_port_ctx->plug_port_ctx_in.lport_name,
              plug_port_ctx);
    ovsport_create(plug_ctx_in->ovs_idl_txn, plug_ctx_in->br_int,
                   plug_port_ctx->plug_port_ctx_out.name,
                   plug_port_ctx->plug_port_ctx_out.type,
                   NULL, iface_external_ids,
                   &plug_port_ctx->plug_port_ctx_out.iface_options,
                   mtu_request);
}

static void
transact_update_port(const struct ovsrec_interface *iface_rec,
                     const struct plug_ctx_in *plug_ctx_in OVS_UNUSED,
                     const struct plug_ctx_out *plug_ctx_out,
                     const struct plug_port_ctx *plug_port_ctx,
                     const struct smap *iface_external_ids,
                     const int64_t mtu_request)
{
    shash_add(plug_ctx_out->changed_iface_ids,
              plug_port_ctx->plug_port_ctx_in.lport_name,
              plug_port_ctx);
    ovsport_update_iface(iface_rec,
                         plug_port_ctx->plug_port_ctx_out.type,
                         iface_external_ids,
                         NULL,
                         &plug_port_ctx->plug_port_ctx_out.iface_options,
                         plug_get_maintained_iface_options(
                            plug_port_ctx->plug),
                         mtu_request);
}


static bool
consider_unplug_iface(const struct ovsrec_interface *iface,
                      const struct sbrec_port_binding *pb,
                      struct plug_ctx_in *plug_ctx_in,
                      struct plug_ctx_out *plug_ctx_out)
{
    const char *plug_type = smap_get(&iface->external_ids, OVN_PLUGGED_EXT_ID);
    const char *iface_id = smap_get(&iface->external_ids, "iface-id");
    const struct ovsrec_port *port = ovsport_lookup_by_interface(
        plug_ctx_in->ovsrec_port_by_interfaces,
        (struct ovsrec_interface *) iface);

    if (plug_type && iface_id && port) {
        const struct plug_class *plug;
        if (!(plug = plug_provider_get(plug_type))) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl,
                         "Unable to open plug provider for "
                         "plug-type %s iface-id %s",
                         plug_type, iface_id);
            /* While we are unable to handle this, asking for a recompute
             * will not change that fact. */
            return true;
        }
        if (!plug_ctx_in->chassis_rec || !plug_ctx_in->br_int
            || !plug_ctx_in->ovs_idl_txn)
        {
            /* Some of our prerequisites are not available, ask for a
             * recompute. */
            return false;
        }

        /* Our contract with the plug provider is that plug_port_finish
         * will be called with a plug_port_ctx_in object once the data
         * is actually deleted.
         *
         * Since this happens asynchronously we need to allocate memory for
         * and duplicate any database references so that they stay valid.
         *
         * The data is freed with a call to destroy_port_ctx after the
         * transaction completes at the end of the ovn-controller main
         * loop. */
        struct plug_port_ctx *plug_port_ctx = build_port_ctx(
            plug, PLUG_OP_REMOVE, plug_ctx_in, pb, iface, iface_id);

        if (!plug_port_prepare(plug, &plug_port_ctx->plug_port_ctx_in, NULL)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl,
                         "Not unplugging iface %s (iface-id %s) on direction "
                         "from plugging library.",
                         iface->name, iface_id);
            destroy_port_ctx(plug_port_ctx);
            return false;
        }
        VLOG_INFO("Unplugging port %s from %s for iface-id %s on this "
                  "chassis.",
                  port->name,
                  plug_ctx_in->br_int->name,
                  iface_id);

        /* Add and track delete operation to the transaction */
        transact_delete_port(plug_ctx_in, plug_ctx_out,
                             plug_port_ctx, port);
        return true;
    }
    return true;
}

static int64_t
get_plug_mtu_request(const struct smap *lport_options)
{
    return smap_get_int(lport_options, "plug-mtu-request", 0);
}

static bool
consider_plug_lport_create__(const struct plug_class *plug,
                             const struct smap *iface_external_ids,
                             const struct sbrec_port_binding *pb,
                             struct plug_ctx_in *plug_ctx_in,
                             struct plug_ctx_out *plug_ctx_out)
{
    if (!plug_ctx_in->chassis_rec || !plug_ctx_in->br_int
        || !plug_ctx_in->ovs_idl_txn) {
        /* Some of our prerequisites are not available, ask for a recompute. */
        return false;
    }

    /* Our contract with the plug provider is that plug_port_finish
     * will be called with plug_port_ctx_in and plug_port_ctx_out objects
     * once the port is actually created.
     *
     * Since this happens asynchronously we need to allocate memory for
     * and duplicate any database references so that they stay valid.
     *
     * The data is freed with a call to destroy_port_ctx after the
     * transaction completes at the end of the ovn-controller main
     * loop. */
    struct plug_port_ctx *plug_port_ctx = build_port_ctx(
        plug, PLUG_OP_CREATE, plug_ctx_in, pb, NULL, NULL);

    if (!plug_port_prepare(plug,
                           &plug_port_ctx->plug_port_ctx_in,
                           &plug_port_ctx->plug_port_ctx_out)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_INFO_RL(&rl,
                     "Not plugging lport %s on direction from plugging "
                     "library.",
                     pb->logical_port);
        plug_port_ctx_destroy(plug,
                              &plug_port_ctx->plug_port_ctx_in,
                              &plug_port_ctx->plug_port_ctx_out);
        destroy_port_ctx(plug_port_ctx);
        return false;
    }

    VLOG_INFO("Plugging port %s into %s for lport %s on this "
              "chassis.",
              plug_port_ctx->plug_port_ctx_out.name, plug_ctx_in->br_int->name,
              pb->logical_port);
    transact_create_port(plug_ctx_in, plug_ctx_out,
                         plug_port_ctx,
                         iface_external_ids,
                         get_plug_mtu_request(&pb->options));
    return true;
}

static bool
consider_plug_lport_update__(const struct plug_class *plug,
                             const struct smap *iface_external_ids,
                             const struct sbrec_port_binding *pb,
                             struct local_binding *lbinding,
                             struct plug_ctx_in *plug_ctx_in,
                             struct plug_ctx_out *plug_ctx_out)
{
    if (!plug_ctx_in->chassis_rec || !plug_ctx_in->br_int
        || !plug_ctx_in->ovs_idl_txn) {
        /* Some of our prerequisites are not available, ask for a recompute. */
        return false;
    }
    /* Our contract with the plug provider is that plug_port_finish
     * will be called with plug_port_ctx_in and plug_port_ctx_out objects
     * once the port is actually updated.
     *
     * Since this happens asynchronously we need to allocate memory for
     * and duplicate any database references so that they stay valid.
     *
     * The data is freed with a call to destroy_port_ctx after the
     * transaction completes at the end of the ovn-controller main
     * loop. */
    struct plug_port_ctx *plug_port_ctx = build_port_ctx(
        plug, PLUG_OP_CREATE, plug_ctx_in, pb, NULL, NULL);

    if (!plug_port_prepare(plug,
                           &plug_port_ctx->plug_port_ctx_in,
                           &plug_port_ctx->plug_port_ctx_out)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_INFO_RL(&rl,
                     "Not updating lport %s on direction from plugging "
                     "library.",
                     pb->logical_port);
        plug_port_ctx_destroy(plug,
                              &plug_port_ctx->plug_port_ctx_in,
                              &plug_port_ctx->plug_port_ctx_out);
        destroy_port_ctx(plug_port_ctx);
        return false;
    }

    if (strcmp(lbinding->iface->name, plug_port_ctx->plug_port_ctx_out.name)) {
        VLOG_WARN("Attempt of incompatible change to existing "
                  "port detected, please recreate port: %s",
                   pb->logical_port);
        plug_port_ctx_destroy(plug,
                              &plug_port_ctx->plug_port_ctx_in,
                              &plug_port_ctx->plug_port_ctx_out);
        destroy_port_ctx(plug_port_ctx);
        return false;
    }
    VLOG_DBG("updating iface for: %s", pb->logical_port);
    transact_update_port(lbinding->iface, plug_ctx_in, plug_ctx_out,
                         plug_port_ctx, iface_external_ids,
                         get_plug_mtu_request(&pb->options));

    return true;
}

static bool
consider_plug_lport(const struct sbrec_port_binding *pb,
                    struct local_binding *lbinding,
                    struct plug_ctx_in *plug_ctx_in,
                    struct plug_ctx_out *plug_ctx_out)
{
    bool ret = true;
    if (lport_can_bind_on_this_chassis(plug_ctx_in->chassis_rec, pb)
        && pb->requested_chassis == plug_ctx_in->chassis_rec) {
        const char *plug_type = smap_get(&pb->options, "plug-type");
        if (!plug_type) {
            /* Nothing for us to do and we don't need a recompute. */
            return true;
        }

        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        const struct plug_class *plug;
        if (!(plug = plug_provider_get(plug_type))) {
            VLOG_WARN_RL(&rl,
                         "Unable to open plug provider for plug-type: '%s' "
                         "lport %s",
                         plug_type, pb->logical_port);
            /* While we are unable to handle this, asking for a recompute will
             * not change that fact. */
            return true;
        }
        const struct smap iface_external_ids = SMAP_CONST2(
                &iface_external_ids,
                OVN_PLUGGED_EXT_ID, plug_type,
                "iface-id", pb->logical_port);
        if (lbinding && lbinding->iface) {
            if (!smap_get(&lbinding->iface->external_ids,
                          OVN_PLUGGED_EXT_ID))
            {
                VLOG_WARN_RL(&rl,
                             "CMS requested plugging of lport %s, but a port "
                             "that is not maintained by OVN already exsist "
                             "in local vSwitch: "UUID_FMT,
                             pb->logical_port,
                             UUID_ARGS(&lbinding->iface->header_.uuid));
                return false;
            }
            ret = consider_plug_lport_update__(plug, &iface_external_ids, pb,
                                               lbinding, plug_ctx_in,
                                               plug_ctx_out);
        } else {
            ret = consider_plug_lport_create__(plug, &iface_external_ids, pb,
                                               plug_ctx_in, plug_ctx_out);
        }
    }

    return ret;
}

static bool
plug_iface_touched_this_txn(const struct plug_ctx_out *plug_ctx_out,
                            const char *iface_id)
{
    return shash_find(plug_ctx_out->changed_iface_ids, iface_id)
           || shash_find(plug_ctx_out->deleted_iface_ids, iface_id);
}

static bool
plug_handle_lport_vif(const struct sbrec_port_binding *pb,
                      struct plug_ctx_in *plug_ctx_in,
                      struct plug_ctx_out *plug_ctx_out)
{
    if (plug_iface_touched_this_txn(plug_ctx_out, pb->logical_port)) {
        return true;
    }
    bool handled = true;
    struct local_binding *lbinding = local_binding_find(
        plug_ctx_in->local_bindings, pb->logical_port);

    if (lport_can_bind_on_this_chassis(plug_ctx_in->chassis_rec, pb)) {
        handled &= consider_plug_lport(pb, lbinding,
                                       plug_ctx_in, plug_ctx_out);
    } else if (lbinding && lbinding->iface) {
        handled &= consider_unplug_iface(lbinding->iface, pb,
                                         plug_ctx_in, plug_ctx_out);
    }
    return handled;
}

static bool
plug_handle_iface(const struct ovsrec_interface *iface_rec,
                  struct plug_ctx_in *plug_ctx_in,
                  struct plug_ctx_out *plug_ctx_out)
{
    bool handled = true;
    const char *plug_type = smap_get(&iface_rec->external_ids,
                                     OVN_PLUGGED_EXT_ID);
    const char *iface_id = smap_get(&iface_rec->external_ids, "iface-id");
    if (!plug_type || !iface_id
        || plug_iface_touched_this_txn(plug_ctx_out, iface_id)) {
        return true;
    }
    struct local_binding *lbinding = local_binding_find(
        plug_ctx_in->local_bindings, iface_id);
    const struct sbrec_port_binding *pb = lport_lookup_by_name(
        plug_ctx_in->sbrec_port_binding_by_name, iface_id);
    if (pb && lbinding
        && lport_can_bind_on_this_chassis(plug_ctx_in->chassis_rec, pb)) {
        /* Something changed on a interface we have previously plugged,
         * consider updating it */
        handled &= consider_plug_lport(pb, lbinding,
                                       plug_ctx_in, plug_ctx_out);
    } else if (!pb
               || !lport_can_bind_on_this_chassis(
                       plug_ctx_in->chassis_rec, pb)) {
        /* No lport for this interface or it is destined for different chassis,
         * consuder unplugging it */
        handled &= consider_unplug_iface(iface_rec, pb,
                                         plug_ctx_in, plug_ctx_out);
    }
    return handled;
}

void
plug_run(struct plug_ctx_in *plug_ctx_in,
         struct plug_ctx_out *plug_ctx_out)
{
    if (!plug_ctx_in->pb_handler_has_run) {
        /* Avoid uneccessary unplug/plug thrashing.  If we are starting up
         * after having done a normal exit (unregistered our chassis record),
         * we have to wait until northd has reinstated the requested_chassis
         * pointer before table iterators and index lookups provide the
         * expected data */
        return;
    }
    const struct ovsrec_interface *iface_rec;
    OVSREC_INTERFACE_TABLE_FOR_EACH (iface_rec,
                                     plug_ctx_in->iface_table) {
        plug_handle_iface(iface_rec, plug_ctx_in, plug_ctx_out);
    }
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (pb,
                                       plug_ctx_in->port_binding_table) {
        enum en_lport_type lport_type = get_lport_type(pb);
        if (lport_type == LP_VIF) {
            plug_handle_lport_vif(pb, plug_ctx_in, plug_ctx_out);
        }
    }
}

bool
plug_handle_port_binding_changes(struct plug_ctx_in *plug_ctx_in,
                                 struct plug_ctx_out *plug_ctx_out)
{
    const struct sbrec_port_binding *pb;
    bool handled = true;

    /* handle deleted lports */
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (
            pb,
            plug_ctx_in->port_binding_table) {
        if (!sbrec_port_binding_is_deleted(pb)) {
            continue;
        }

        enum en_lport_type lport_type = get_lport_type(pb);
        if (lport_type == LP_VIF) {
            struct local_binding *lbinding = local_binding_find(
                plug_ctx_in->local_bindings, pb->logical_port);
            if (lbinding && lbinding->iface
                && !plug_iface_touched_this_txn(plug_ctx_out,
                                                pb->logical_port)) {
                handled &= consider_unplug_iface(lbinding->iface, pb,
                                                 plug_ctx_in, plug_ctx_out);
            }
        }
    }

    /* handle any new or updated lports */
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (
            pb,
            plug_ctx_in->port_binding_table) {
        if (sbrec_port_binding_is_deleted(pb)) {
            continue;
        }
        enum en_lport_type lport_type = get_lport_type(pb);
        if (lport_type == LP_VIF) {
            handled &= plug_handle_lport_vif(pb, plug_ctx_in, plug_ctx_out);
        }
    }

    return handled;
}

bool
plug_handle_ovs_interface_changes(struct plug_ctx_in *plug_ctx_in,
                                  struct plug_ctx_out *plug_ctx_out)
{
    bool handled = true;
    const struct ovsrec_interface *iface_rec;

    OVSREC_INTERFACE_TABLE_FOR_EACH_TRACKED (iface_rec,
                                             plug_ctx_in->iface_table) {
        if (ovsrec_interface_is_deleted(iface_rec)) {
            continue;
        }
        handled &= plug_handle_iface(iface_rec, plug_ctx_in, plug_ctx_out);
    }
    return handled;
}

static void
plug_finish_deleted__(struct shash *deleted_iface_ids, bool txn_success)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, deleted_iface_ids) {
        struct plug_port_ctx *plug_port_ctx = node->data;
        if (txn_success) {
            plug_port_finish(plug_port_ctx->plug,
                             &plug_port_ctx->plug_port_ctx_in,
                             NULL);
        }
        shash_delete(deleted_iface_ids, node);
        destroy_port_ctx(plug_port_ctx);
    }
}

void
plug_clear_deleted(struct shash *deleted_iface_ids) {
    plug_finish_deleted__(deleted_iface_ids, false);
}

void
plug_finish_deleted(struct shash *deleted_iface_ids) {
    plug_finish_deleted__(deleted_iface_ids, true);
}

static void
plug_finish_changed__(struct shash *changed_iface_ids, bool txn_success)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, changed_iface_ids) {
        struct plug_port_ctx *plug_port_ctx = node->data;
        if (txn_success) {
            plug_port_finish(plug_port_ctx->plug,
                             &plug_port_ctx->plug_port_ctx_in,
                             &plug_port_ctx->plug_port_ctx_out);
        }
        plug_port_ctx_destroy(plug_port_ctx->plug,
                              &plug_port_ctx->plug_port_ctx_in,
                              &plug_port_ctx->plug_port_ctx_out);
        shash_delete(changed_iface_ids, node);
        destroy_port_ctx(plug_port_ctx);
    }
}

void
plug_clear_changed(struct shash *deleted_iface_ids) {
    plug_finish_changed__(deleted_iface_ids, false);
}

void
plug_finish_changed(struct shash *deleted_iface_ids) {
    plug_finish_changed__(deleted_iface_ids, true);
}
