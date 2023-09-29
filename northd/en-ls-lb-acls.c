/*
 * Copyright (c) 2023, Red Hat, Inc.
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes */
#include "include/openvswitch/hmap.h"
#include "lib/bitmap.h"
#include "lib/socket-util.h"
#include "lib/uuidset.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "stopwatch.h"

/* OVN includes */
#include "en-lb-data.h"
#include "en-ls-lb-acls.h"
#include "en-port-group.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_ls_lbacls);

/* Static function declarations. */
static void ls_lbacls_table_init(struct ls_lbacls_table *);
static void ls_lbacls_table_clear(struct ls_lbacls_table *);
static void ls_lbacls_table_destroy(struct ls_lbacls_table *);
static struct ls_lbacls_record *ls_lbacls_table_find_(
    const struct ls_lbacls_table *, const struct nbrec_logical_switch *);
static void ls_lbacls_table_build(struct ls_lbacls_table *,
                                  const struct ovn_datapaths *ls_datapaths,
                                  const struct ls_port_group_table *);

static struct ls_lbacls_input ls_lbacls_get_input_data(
    struct engine_node *);

static struct ls_lbacls_record *ls_lbacls_record_create(
    struct ls_lbacls_table *,
    const struct ovn_datapath *,
    const struct ls_port_group_table *);
static void ls_lbacls_record_destroy(struct ls_lbacls_record *);
static void ls_lbacls_record_init(
    struct ls_lbacls_record *,
    const struct ovn_datapath *,
    const struct ls_port_group *,
    const struct ls_port_group_table *);
static void ls_lbacls_record_reinit(
    struct ls_lbacls_record *,
    const struct ls_port_group *,
    const struct ls_port_group_table *);
static bool ls_has_lb_vip(const struct ovn_datapath *);
static void ls_lbacls_record_set_acl_flags(struct ls_lbacls_record *,
                                           const struct ovn_datapath *,
                                           const struct ls_port_group *,
                                           const struct ls_port_group_table *);
static bool ls_lbacls_record_set_acl_flags_(struct ls_lbacls_record *,
                                            struct nbrec_acl **,
                                            size_t n_acls);
static struct ls_lbacls_input ls_lbacls_get_input_data(struct engine_node *);
static bool is_ls_acls_changed(const struct nbrec_logical_switch *);
static bool is_acls_seqno_changed(struct nbrec_acl **, size_t n_nb_acls);


/* public functions. */
const struct ls_lbacls_record *
ls_lbacls_table_find(
    const struct ls_lbacls_table *table,
    const struct nbrec_logical_switch *nbs)
{
    return ls_lbacls_table_find_(table, nbs);
}

void *
en_ls_lbacls_init(struct engine_node *node OVS_UNUSED,
                  struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_ls_lbacls *data = xzalloc(sizeof *data);
    ls_lbacls_table_init(&data->ls_lbacls);
    hmapx_init(&data->tracked_data.crupdated);
    hmapx_init(&data->tracked_data.deleted);
    return data;
}

void
en_ls_lbacls_cleanup(void *data_)
{
    struct ed_type_ls_lbacls *data =
        (struct ed_type_ls_lbacls *) data_;
    ls_lbacls_table_destroy(&data->ls_lbacls);
    hmapx_destroy(&data->tracked_data.crupdated);
    hmapx_destroy(&data->tracked_data.deleted);
}

void
en_ls_lbacls_clear_tracked_data(void *data_)
{
    struct ed_type_ls_lbacls *data =
        (struct ed_type_ls_lbacls *) data_;

    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH_SAFE (hmapx_node, &data->tracked_data.deleted) {
        ls_lbacls_record_destroy(hmapx_node->data);
        hmapx_delete(&data->tracked_data.deleted, hmapx_node);
    }

    hmapx_clear(&data->tracked_data.crupdated);
    data->tracked = false;
}

void
en_ls_lbacls_run(struct engine_node *node, void *data_)
{
    struct ls_lbacls_input input_data = ls_lbacls_get_input_data(node);
    struct ed_type_ls_lbacls *data = data_;

    stopwatch_start(LS_LBACLS_RUN_STOPWATCH_NAME, time_msec());

    ls_lbacls_table_clear(&data->ls_lbacls);
    ls_lbacls_table_build(&data->ls_lbacls, input_data.ls_datapaths,
                          input_data.ls_port_groups);

    data->tracked = false;
    stopwatch_stop(LS_LBACLS_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

/* Handler functions. */
bool
ls_lbacls_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_data->change_tracked) {
        return false;
    }

    struct northd_tracked_data *nd_changes = &northd_data->trk_northd_changes;
    struct ls_lbacls_input input_data = ls_lbacls_get_input_data(node);
    struct ls_lbacls_record *ls_lbacls_rec;
    struct ed_type_ls_lbacls *data = data_;
    const struct ovn_datapath *od;
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->ls_with_changed_lbs.crupdated) {
        od = hmapx_node->data;

        ls_lbacls_rec = ls_lbacls_table_find_(&data->ls_lbacls, od->nbs);
        if (!ls_lbacls_rec) {
            ls_lbacls_rec = ls_lbacls_record_create(&data->ls_lbacls, od,
                                                    input_data.ls_port_groups);
        } else {
            ls_lbacls_record_reinit(ls_lbacls_rec, NULL,
                                    input_data.ls_port_groups);
        }

        /* Add the ls_lbacls_rec to the tracking data. */
        hmapx_add(&data->tracked_data.crupdated, ls_lbacls_rec);
    }

    if (!hmapx_is_empty(&data->tracked_data.crupdated)) {
        data->tracked = true;
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
}

bool
ls_lbacls_port_group_handler(struct engine_node *node, void *data_)
{
    struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);

    if (pg_data->ls_port_groups_sets_changed) {
        return false;
    }

    /* port_group engine node doesn't provide the tracking data yet.
     * Loop through all the ls port groups and update the ls_lbacls_rec.
     * This is still better than returning false. */
    struct ls_lbacls_input input_data = ls_lbacls_get_input_data(node);
    struct ed_type_ls_lbacls *data = data_;
    const struct ls_port_group *ls_pg;

    LS_PORT_GROUP_TABLE_FOR_EACH (ls_pg, input_data.ls_port_groups) {
        struct ls_lbacls_record *ls_lbacls_rec =
            ls_lbacls_table_find_(&data->ls_lbacls, ls_pg->nbs);

        bool modified = false;
        if (!ls_lbacls_rec) {
            const struct ovn_datapath *od;
            od = ovn_datapath_find(&input_data.ls_datapaths->datapaths,
                                    &ls_pg->nbs->header_.uuid);
            ovs_assert(od);
            ls_lbacls_rec = ls_lbacls_record_create(&data->ls_lbacls, od,
                                                input_data.ls_port_groups);
            modified = true;
        } else {
            bool had_stateful_acl = ls_lbacls_rec->has_stateful_acl;
            uint64_t max_acl_tier = ls_lbacls_rec->max_acl_tier;
            bool had_acls = ls_lbacls_rec->has_acls;

            ls_lbacls_record_reinit(ls_lbacls_rec, ls_pg,
                                    input_data.ls_port_groups);

            if ((had_stateful_acl != ls_lbacls_rec->has_stateful_acl)
                || (had_acls != ls_lbacls_rec->has_acls)
                || max_acl_tier != ls_lbacls_rec->max_acl_tier) {
                modified = true;
            }
        }

        if (modified) {
            /* Add the ls_lbacls_rec to the tracking data. */
            hmapx_add(&data->tracked_data.crupdated, ls_lbacls_rec);
        }
    }

    if (!hmapx_is_empty(&data->tracked_data.crupdated)) {
        data->tracked = true;
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
}

bool
ls_lbacls_logical_switch_handler(struct engine_node *node, void *data_)
{
    struct ls_lbacls_input input_data = ls_lbacls_get_input_data(node);
    const struct nbrec_logical_switch *nbs;
    struct ed_type_ls_lbacls *data = data_;

    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (nbs,
                                    input_data.nbrec_logical_switch_table) {
        if (!is_ls_acls_changed(nbs)) {
            continue;
        }

        struct ls_lbacls_record *ls_lbacls_rec =
            ls_lbacls_table_find_(&data->ls_lbacls, nbs);

        if (nbrec_logical_switch_is_deleted(nbs)) {
            if (ls_lbacls_rec) {
                /* Remove the record from the entries. */
                hmap_remove(&data->ls_lbacls.entries,
                            &ls_lbacls_rec->key_node);

                /* Add the ls_lbacls_rec to the tracking data. */
                hmapx_add(&data->tracked_data.deleted, ls_lbacls_rec);
            }
        } else {
            if (!ls_lbacls_rec) {
                const struct ovn_datapath *od;
                od = ovn_datapath_find(&input_data.ls_datapaths->datapaths,
                                       &nbs->header_.uuid);
                ovs_assert(od);
                ls_lbacls_rec = ls_lbacls_record_create(&data->ls_lbacls, od,
                                                    input_data.ls_port_groups);
            } else {
                ls_lbacls_record_reinit(ls_lbacls_rec, NULL,
                                        input_data.ls_port_groups);
            }

            /* Add the ls_lbacls_rec to the tracking data. */
            hmapx_add(&data->tracked_data.crupdated, ls_lbacls_rec);
        }
    }

    if (!hmapx_is_empty(&data->tracked_data.crupdated)
        || !hmapx_is_empty(&data->tracked_data.deleted)) {
        data->tracked = true;
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
}

/* static functions. */
static void
ls_lbacls_table_init(struct ls_lbacls_table *table)
{
    *table = (struct ls_lbacls_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

static void
ls_lbacls_table_destroy(struct ls_lbacls_table *table)
{
    ls_lbacls_table_clear(table);
    hmap_destroy(&table->entries);
}

static void
ls_lbacls_table_clear(struct ls_lbacls_table *table)
{
    struct ls_lbacls_record *ls_lbacls_rec;
    HMAP_FOR_EACH_POP (ls_lbacls_rec, key_node, &table->entries) {
        ls_lbacls_record_destroy(ls_lbacls_rec);
    }
}

static void
ls_lbacls_table_build(struct ls_lbacls_table *table,
                      const struct ovn_datapaths *ls_datapaths,
                      const struct ls_port_group_table *ls_pgs)
{
    const struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &ls_datapaths->datapaths) {
        ls_lbacls_record_create(table, od, ls_pgs);
    }
}

struct ls_lbacls_record *
ls_lbacls_table_find_(const struct ls_lbacls_table *table,
                      const struct nbrec_logical_switch *nbs)
{
    struct ls_lbacls_record *rec;

    HMAP_FOR_EACH_WITH_HASH (rec, key_node,
                             uuid_hash(&nbs->header_.uuid), &table->entries) {
        if (nbs == rec->od->nbs) {
            return rec;
        }
    }
    return NULL;
}

static struct ls_lbacls_record *
ls_lbacls_record_create(struct ls_lbacls_table *table,
                        const struct ovn_datapath *od,
                        const struct ls_port_group_table *ls_pgs)
{
    struct ls_lbacls_record *ls_lbacls_rec = xzalloc(sizeof *ls_lbacls_rec);
    ls_lbacls_rec->od = od;
    ls_lbacls_record_init(ls_lbacls_rec, od, NULL, ls_pgs);

    hmap_insert(&table->entries, &ls_lbacls_rec->key_node,
                uuid_hash(&ls_lbacls_rec->od->nbs->header_.uuid));

    return ls_lbacls_rec;
}

static void
ls_lbacls_record_destroy(struct ls_lbacls_record *ls_lbacls_rec)
{
    free(ls_lbacls_rec);
}

static void
ls_lbacls_record_init(struct ls_lbacls_record *ls_lbacls_rec,
                      const struct ovn_datapath *od,
                      const struct ls_port_group *ls_pg,
                      const struct ls_port_group_table *ls_pgs)
{
    ls_lbacls_rec->has_lb_vip = ls_has_lb_vip(od);
    ls_lbacls_record_set_acl_flags(ls_lbacls_rec, od, ls_pg, ls_pgs);
}

static void
ls_lbacls_record_reinit(struct ls_lbacls_record *ls_lbacls_rec,
                        const struct ls_port_group *ls_pg,
                        const struct ls_port_group_table *ls_pgs)
{
    ls_lbacls_record_init(ls_lbacls_rec, ls_lbacls_rec->od, ls_pg, ls_pgs);
}

static bool
lb_has_vip(const struct nbrec_load_balancer *lb)
{
    return !smap_is_empty(&lb->vips);
}

static bool
lb_group_has_vip(const struct nbrec_load_balancer_group *lb_group)
{
    for (size_t i = 0; i < lb_group->n_load_balancer; i++) {
        if (lb_has_vip(lb_group->load_balancer[i])) {
            return true;
        }
    }
    return false;
}

static bool
ls_has_lb_vip(const struct ovn_datapath *od)
{
    for (size_t i = 0; i < od->nbs->n_load_balancer; i++) {
        if (lb_has_vip(od->nbs->load_balancer[i])) {
            return true;
        }
    }

    for (size_t i = 0; i < od->nbs->n_load_balancer_group; i++) {
        if (lb_group_has_vip(od->nbs->load_balancer_group[i])) {
            return true;
        }
    }
    return false;
}

static void
ls_lbacls_record_set_acl_flags(struct ls_lbacls_record *ls_lbacls_rec,
                               const struct ovn_datapath *od,
                               const struct ls_port_group *ls_pg,
                               const struct ls_port_group_table *ls_pgs)
{
    ls_lbacls_rec->has_stateful_acl = false;
    ls_lbacls_rec->max_acl_tier = 0;
    ls_lbacls_rec->has_acls = false;

    if (ls_lbacls_record_set_acl_flags_(ls_lbacls_rec, od->nbs->acls,
                                        od->nbs->n_acls)) {
        return;
    }

    if (!ls_pg) {
        ls_pg = ls_port_group_table_find(ls_pgs, od->nbs);
    }

    if (!ls_pg) {
        return;
    }

    const struct ls_port_group_record *ls_pg_rec;
    HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
        if (ls_lbacls_record_set_acl_flags_(ls_lbacls_rec,
                                            ls_pg_rec->nb_pg->acls,
                                            ls_pg_rec->nb_pg->n_acls)) {
            return;
        }
    }
}

static bool
ls_lbacls_record_set_acl_flags_(struct ls_lbacls_record *ls_lbacls_rec,
                                struct nbrec_acl **acls,
                                size_t n_acls)
{
    /* A true return indicates that there are no possible ACL flags
     * left to set on ls_lbacls record. A false return indicates that
     * further ACLs should be explored in case more flags need to be
     * set on ls_lbacls record.
     */
    if (!n_acls) {
        return false;
    }

    ls_lbacls_rec->has_acls = true;
    for (size_t i = 0; i < n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        if (acl->tier > ls_lbacls_rec->max_acl_tier) {
            ls_lbacls_rec->max_acl_tier = acl->tier;
        }
        if (!ls_lbacls_rec->has_stateful_acl
                && !strcmp(acl->action, "allow-related")) {
            ls_lbacls_rec->has_stateful_acl = true;
        }
        if (ls_lbacls_rec->has_stateful_acl &&
            ls_lbacls_rec->max_acl_tier ==
                nbrec_acl_col_tier.type.value.integer.max) {
            return true;
        }
    }

    return false;
}

static struct ls_lbacls_input
ls_lbacls_get_input_data(struct engine_node *node)
{
    const struct northd_data *northd_data =
        engine_get_input_data("northd", node);
    const struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);

    return (struct ls_lbacls_input) {
        .nbrec_logical_switch_table =
            EN_OVSDB_GET(engine_get_input("NB_logical_switch", node)),
        .ls_port_groups = &pg_data->ls_port_groups,
        .ls_datapaths = &northd_data->ls_datapaths,
    };
}

static bool
is_acls_seqno_changed(struct nbrec_acl **nb_acls, size_t n_nb_acls)
{
    for (size_t i = 0; i < n_nb_acls; i++) {
        if (nbrec_acl_row_get_seqno(nb_acls[i],
                                    OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return true;
        }
    }

    return false;
}

static bool
is_ls_acls_changed(const struct nbrec_logical_switch *nbs) {
    return (nbrec_logical_switch_is_new(nbs)
            || nbrec_logical_switch_is_deleted(nbs)
            || nbrec_logical_switch_is_updated(nbs,
                                               NBREC_LOGICAL_SWITCH_COL_ACLS)
            || is_acls_seqno_changed(nbs->acls, nbs->n_acls));
}
