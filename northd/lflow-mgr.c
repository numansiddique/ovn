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
#include "include/openvswitch/thread.h"
#include "lib/bitmap.h"
#include "lib/uuidset.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "stopwatch.h"

/* OVN includes */
#include "debug.h"
#include "lflow-mgr.h"
#include "lib/ovn-parallel-hmap.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(lflow_mgr);

/* Static function declarations. */
struct ovn_lflow;

static void ovn_lflow_init(struct ovn_lflow *, struct ovn_datapath *od,
                           size_t dp_bitmap_len, enum ovn_stage stage,
                           uint16_t priority, char *match,
                           char *actions, char *io_port,
                           char *ctrl_meter, char *stage_hint,
                           const char *where, uint32_t hash);
static struct ovn_lflow *ovn_lflow_find(const struct hmap *lflows,
                                        enum ovn_stage stage,
                                        uint16_t priority, const char *match,
                                        const char *actions,
                                        const char *ctrl_meter, uint32_t hash);
static void ovn_lflow_destroy(struct lflow_table *lflow_table,
                              struct ovn_lflow *lflow);
static void inc_ovn_lflow_ref(struct ovn_lflow *);
static void dec_ovn_lflow_ref(struct lflow_table *, struct ovn_lflow *);
static char *ovn_lflow_hint(const struct ovsdb_idl_row *row);

static struct ovn_lflow *do_ovn_lflow_add(
    struct lflow_table *, const struct ovn_datapath *,
    const unsigned long *dp_bitmap, size_t dp_bitmap_len, uint32_t hash,
    enum ovn_stage stage, uint16_t priority, const char *match,
    const char *actions, const char *io_port,
    const char *ctrl_meter,
    const struct ovsdb_idl_row *stage_hint,
    const char *where);


static struct ovs_mutex *lflow_hash_lock(const struct hmap *lflow_table,
                                         uint32_t hash);
static void lflow_hash_unlock(struct ovs_mutex *hash_lock);

static struct sbrec_logical_dp_group *ovn_sb_insert_or_update_logical_dp_group(
    struct ovsdb_idl_txn *ovnsb_txn,
    struct sbrec_logical_dp_group *,
    const unsigned long *dpg_bitmap,
    const struct ovn_datapaths *);
static struct ovn_dp_group *ovn_dp_group_find(const struct hmap *dp_groups,
                                              const unsigned long *dpg_bitmap,
                                              size_t bitmap_len,
                                              uint32_t hash);
static void inc_ovn_dp_group_ref(struct ovn_dp_group *);
static void dec_ovn_dp_group_ref(struct hmap *dp_groups,
                                 struct ovn_dp_group *);
static void ovn_dp_group_add_with_reference(struct ovn_lflow *,
                                            const struct ovn_datapath *od,
                                            const unsigned long *dp_bitmap,
                                            size_t bitmap_len);

static void unlink_lflows_from_datapath(struct lflow_ref *);
static void unlink_lflows_from_all_datapaths(struct lflow_ref *,
                                             size_t n_ls_datapaths,
                                             size_t n_lr_datapaths);

static void lflow_ref_sync_lflows_to_sb__(struct lflow_ref  *,
                            struct lflow_table *,
                            struct ovsdb_idl_txn *ovnsb_txn,
                            const struct ovn_datapaths *ls_datapaths,
                            const struct ovn_datapaths *lr_datapaths,
                            bool ovn_internal_version_changed,
                            const struct sbrec_logical_flow_table *,
                            const struct sbrec_logical_dp_group_table *);
static void sync_lflow_to_sb(struct ovn_lflow *,
                             struct ovsdb_idl_txn *ovnsb_txn,
                             struct lflow_table *,
                             const struct ovn_datapaths *ls_datapaths,
                             const struct ovn_datapaths *lr_datapaths,
                             bool ovn_internal_version_changed,
                             const struct sbrec_logical_flow *sbflow,
                             const struct sbrec_logical_dp_group_table *);

extern int parallelization_state;
extern thread_local size_t thread_lflow_counter;

static bool lflow_hash_lock_initialized = false;
/* The lflow_hash_lock is a mutex array that protects updates to the shared
 * lflow table across threads when parallel lflow build and dp-group are both
 * enabled. To avoid high contention between threads, a big array of mutexes
 * are used instead of just one. This is possible because when parallel build
 * is used we only use hmap_insert_fast() to update the hmap, which would not
 * touch the bucket array but only the list in a single bucket. We only need to
 * make sure that when adding lflows to the same hash bucket, the same lock is
 * used, so that no two threads can add to the bucket at the same time.  It is
 * ok that the same lock is used to protect multiple buckets, so a fixed sized
 * mutex array is used instead of 1-1 mapping to the hash buckets. This
 * simplies the implementation while effectively reduces lock contention
 * because the chance that different threads contending the same lock amongst
 * the big number of locks is very low. */
#define LFLOW_HASH_LOCK_MASK 0xFFFF
static struct ovs_mutex lflow_hash_locks[LFLOW_HASH_LOCK_MASK + 1];

/* Full thread safety analysis is not possible with hash locks, because
 * they are taken conditionally based on the 'parallelization_state' and
 * a flow hash.  Also, the order in which two hash locks are taken is not
 * predictable during the static analysis.
 *
 * Since the order of taking two locks depends on a random hash, to avoid
 * ABBA deadlocks, no two hash locks can be nested.  In that sense an array
 * of hash locks is similar to a single mutex.
 *
 * Using a fake mutex to partially simulate thread safety restrictions, as
 * if it were actually a single mutex.
 *
 * OVS_NO_THREAD_SAFETY_ANALYSIS below allows us to ignore conditional
 * nature of the lock.  Unlike other attributes, it applies to the
 * implementation and not to the interface.  So, we can define a function
 * that acquires the lock without analysing the way it does that.
 */
extern struct ovs_mutex fake_hash_mutex;

struct ovn_lflow {
    struct hmap_node hmap_node;

    struct ovn_datapath *od;     /* 'logical_datapath' in SB schema.  */
    unsigned long *dpg_bitmap;   /* Bitmap of all datapaths by their 'index'.*/
    enum ovn_stage stage;
    uint16_t priority;
    char *match;
    char *actions;
    char *io_port;
    char *stage_hint;
    char *ctrl_meter;
    size_t n_ods;                /* Number of datapaths referenced by 'od' and
                                  * 'dpg_bitmap'. */
    struct ovn_dp_group *dpg;    /* Link to unique Sb datapath group. */

    const char *where;

    struct uuid sb_uuid;         /* SB DB row uuid, specified by northd. */
    struct uuid lflow_uuid;

    size_t refcnt;
};

struct lflow_table {
    struct hmap entries;
    struct hmap ls_dp_groups;
    struct hmap lr_dp_groups;
    ssize_t max_seen_lflow_size;
};

struct lflow_table *
lflow_table_alloc(void)
{
    struct lflow_table *lflow_table = xzalloc(sizeof *lflow_table);
    lflow_table->max_seen_lflow_size = 128;

    return lflow_table;
}

void
lflow_table_init(struct lflow_table *lflow_table)
{
    fast_hmap_size_for(&lflow_table->entries,
                       lflow_table->max_seen_lflow_size);
    ovn_dp_groups_init(&lflow_table->ls_dp_groups);
    ovn_dp_groups_init(&lflow_table->lr_dp_groups);
}

void
lflow_table_clear(struct lflow_table *lflow_table)
{
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_SAFE (lflow, hmap_node, &lflow_table->entries) {
        ovn_lflow_destroy(lflow_table, lflow);
    }
    hmap_destroy(&lflow_table->entries);

    ovn_dp_groups_destroy(&lflow_table->ls_dp_groups);
    ovn_dp_groups_destroy(&lflow_table->lr_dp_groups);
}

void
lflow_table_destroy(struct lflow_table *lflow_table)
{
    lflow_table_clear(lflow_table);
    free(lflow_table);
}

void
lflow_table_expand(struct lflow_table *lflow_table)
{
    hmap_expand(&lflow_table->entries);

    if (hmap_count(&lflow_table->entries) >
            lflow_table->max_seen_lflow_size) {
        lflow_table->max_seen_lflow_size = hmap_count(&lflow_table->entries);
    }
}

void
lflow_table_set_size(struct lflow_table *lflow_table, size_t size)
{
    lflow_table->entries.n = size;
}

void
lflow_table_sync_to_sb(struct lflow_table *lflow_table,
                       struct ovsdb_idl_txn *ovnsb_txn,
                       const struct ovn_datapaths *ls_datapaths,
                       const struct ovn_datapaths *lr_datapaths,
                       bool ovn_internal_version_changed,
                       const struct sbrec_logical_flow_table *sb_flow_table,
                       const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    struct hmap lflows_temp = HMAP_INITIALIZER(&lflows_temp);
    struct hmap *lflows = &lflow_table->entries;
    struct ovn_lflow *lflow;

    /* Push changes to the Logical_Flow table to database. */
    const struct sbrec_logical_flow *sbflow;
    SBREC_LOGICAL_FLOW_TABLE_FOR_EACH_SAFE (sbflow, sb_flow_table) {
        struct sbrec_logical_dp_group *dp_group = sbflow->logical_dp_group;
        struct ovn_datapath *logical_datapath_od = NULL;
        size_t i;

        /* Find one valid datapath to get the datapath type. */
        struct sbrec_datapath_binding *dp = sbflow->logical_datapath;
        if (dp) {
            logical_datapath_od = ovn_datapath_from_sbrec(
                                        &ls_datapaths->datapaths,
                                        &lr_datapaths->datapaths,
                                        dp);
            if (logical_datapath_od
                && ovn_datapath_is_stale(logical_datapath_od)) {
                logical_datapath_od = NULL;
            }
        }
        for (i = 0; dp_group && i < dp_group->n_datapaths; i++) {
            logical_datapath_od = ovn_datapath_from_sbrec(
                                        &ls_datapaths->datapaths,
                                        &lr_datapaths->datapaths,
                                        dp_group->datapaths[i]);
            if (logical_datapath_od
                && !ovn_datapath_is_stale(logical_datapath_od)) {
                break;
            }
            logical_datapath_od = NULL;
        }

        if (!logical_datapath_od) {
            /* This lflow has no valid logical datapaths. */
            sbrec_logical_flow_delete(sbflow);
            continue;
        }

        enum ovn_pipeline pipeline
            = !strcmp(sbflow->pipeline, "ingress") ? P_IN : P_OUT;

        lflow = ovn_lflow_find(
            lflows,
            ovn_stage_build(ovn_datapath_get_type(logical_datapath_od),
                            pipeline, sbflow->table_id),
            sbflow->priority, sbflow->match, sbflow->actions,
            sbflow->controller_meter, sbflow->hash);
        if (lflow) {
            sync_lflow_to_sb(lflow, ovnsb_txn, lflow_table, ls_datapaths,
                             lr_datapaths, ovn_internal_version_changed,
                             sbflow, dpgrp_table);

            hmap_remove(lflows, &lflow->hmap_node);
            hmap_insert(&lflows_temp, &lflow->hmap_node,
                        hmap_node_hash(&lflow->hmap_node));
        } else {
            sbrec_logical_flow_delete(sbflow);
        }
    }

    HMAP_FOR_EACH_SAFE (lflow, hmap_node, lflows) {
        sync_lflow_to_sb(lflow, ovnsb_txn, lflow_table, ls_datapaths,
                         lr_datapaths, ovn_internal_version_changed,
                         NULL, dpgrp_table);

        hmap_remove(lflows, &lflow->hmap_node);
        hmap_insert(&lflows_temp, &lflow->hmap_node,
                    hmap_node_hash(&lflow->hmap_node));
    }
    hmap_swap(lflows, &lflows_temp);
    hmap_destroy(&lflows_temp);
}

/* lflow ref mgr */
struct lflow_ref {
    char *res_name;

    /* head of the list 'struct lflow_ref_node'. */
    struct ovs_list lflows_ref_list;

    /* hmapx_node is 'struct lflow *'.  This is used to ensure
     * that there are no duplicates in 'lflow_ref_list' above. */
    struct hmapx lflows;
};

struct lflow_ref_node {
    struct ovs_list ref_list_node;

    struct ovn_lflow *lflow;
    size_t dp_index;
};

struct lflow_ref *
lflow_ref_alloc(const char *res_name)
{
    struct lflow_ref *lflow_ref = xzalloc(sizeof *lflow_ref);
    lflow_ref->res_name = xstrdup(res_name);
    ovs_list_init(&lflow_ref->lflows_ref_list);
    hmapx_init(&lflow_ref->lflows);
    return lflow_ref;
}

void
lflow_ref_destroy(struct lflow_ref *lflow_ref)
{
    free(lflow_ref->res_name);

    struct lflow_ref_node *l;
    LIST_FOR_EACH_SAFE (l, ref_list_node, &lflow_ref->lflows_ref_list) {
        ovs_list_remove(&l->ref_list_node);
        free(l);
    }

    hmapx_destroy(&lflow_ref->lflows);
    free(lflow_ref);
}

void
lflow_ref_reset(struct lflow_ref *lflow_ref)
{
    struct lflow_ref_node *l;
    LIST_FOR_EACH_SAFE (l, ref_list_node, &lflow_ref->lflows_ref_list) {
        ovs_list_remove(&l->ref_list_node);
        free(l);
    }

    hmapx_clear(&lflow_ref->lflows);
}

void
lflow_ref_clear_lflows(struct lflow_ref *lflow_ref)
{
    unlink_lflows_from_datapath(lflow_ref);
}

void
lflow_ref_clear_lflows_for_all_dps(struct lflow_ref *lflow_ref,
                                   size_t n_ls_datapaths,
                                   size_t n_lr_datapaths)
{
    unlink_lflows_from_all_datapaths(lflow_ref, n_ls_datapaths,
                                     n_lr_datapaths);
}

void
lflow_ref_clear_and_sync_lflows(struct lflow_ref *lflow_ref,
                    struct lflow_table *lflow_table,
                    struct ovsdb_idl_txn *ovnsb_txn,
                    const struct ovn_datapaths *ls_datapaths,
                    const struct ovn_datapaths *lr_datapaths,
                    bool ovn_internal_version_changed,
                    const struct sbrec_logical_flow_table *sbflow_table,
                    const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    unlink_lflows_from_datapath(lflow_ref);
    lflow_ref_sync_lflows_to_sb__(lflow_ref, lflow_table, ovnsb_txn,
                                  ls_datapaths, lr_datapaths,
                                  ovn_internal_version_changed, sbflow_table,
                                  dpgrp_table);
}

void
lflow_ref_sync_lflows_to_sb(struct lflow_ref *lflow_ref,
                     struct lflow_table *lflow_table,
                     struct ovsdb_idl_txn *ovnsb_txn,
                     const struct ovn_datapaths *ls_datapaths,
                     const struct ovn_datapaths *lr_datapaths,
                     bool ovn_internal_version_changed,
                     const struct sbrec_logical_flow_table *sbflow_table,
                     const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    lflow_ref_sync_lflows_to_sb__(lflow_ref, lflow_table, ovnsb_txn,
                                  ls_datapaths, lr_datapaths,
                                  ovn_internal_version_changed, sbflow_table,
                                  dpgrp_table);
}

void
lflow_table_add_lflow(struct lflow_table *lflow_table,
                      const struct ovn_datapath *od,
                      const unsigned long *dp_bitmap, size_t dp_bitmap_len,
                      enum ovn_stage stage, uint16_t priority,
                      const char *match, const char *actions,
                      const char *io_port, const char *ctrl_meter,
                      const struct ovsdb_idl_row *stage_hint,
                      const char *where,
                      struct lflow_ref *lflow_ref)
    OVS_EXCLUDED(fake_hash_mutex)
{
    struct ovs_mutex *hash_lock;
    uint32_t hash;

    ovs_assert(!od ||
               ovn_stage_to_datapath_type(stage) == ovn_datapath_get_type(od));

    hash = ovn_logical_flow_hash(ovn_stage_get_table(stage),
                                 ovn_stage_get_pipeline(stage),
                                 priority, match,
                                 actions);

    hash_lock = lflow_hash_lock(&lflow_table->entries, hash);
    struct ovn_lflow *lflow =
        do_ovn_lflow_add(lflow_table, od, dp_bitmap,
                         dp_bitmap_len, hash, stage,
                         priority, match, actions,
                         io_port, ctrl_meter, stage_hint, where);

    if (lflow_ref) {
        if (hmapx_add(&lflow_ref->lflows, lflow)) {
            /*  lflow_ref_node for this lflow doesn't exist yet.  Add it. */
            struct lflow_ref_node *ref_node = xzalloc(sizeof *ref_node);
            ref_node->lflow = lflow;
            if (od) {
                ref_node->dp_index = od->index;
            }
            ovs_list_insert(&lflow_ref->lflows_ref_list,
                            &ref_node->ref_list_node);

            inc_ovn_lflow_ref(lflow);
        }
    }

    lflow_hash_unlock(hash_lock);

}

void
lflow_table_add_lflow_default_drop(struct lflow_table *lflow_table,
                                   const struct ovn_datapath *od,
                                   enum ovn_stage stage,
                                   const char *where,
                                   struct lflow_ref *lflow_ref)
{
    lflow_table_add_lflow(lflow_table, od, NULL, 0, stage, 0, "1",
                          debug_drop_action(), NULL, NULL, NULL,
                          where, lflow_ref);
}

struct ovn_dp_group *
ovn_dp_group_get(struct hmap *dp_groups, size_t desired_n,
                 const unsigned long *desired_bitmap,
                 size_t bitmap_len)
{
    uint32_t hash;

    hash = hash_int(desired_n, 0);
    return ovn_dp_group_find(dp_groups, desired_bitmap, bitmap_len, hash);
}

/* Creates a new datapath group and adds it to 'dp_groups'.
 * If 'sb_group' is provided, function will try to re-use this group by
 * either taking it directly, or by modifying, if it's not already in use.
 * Caller should first call ovn_dp_group_get() before calling this function. */
struct ovn_dp_group *
ovn_dp_group_create(struct ovsdb_idl_txn *ovnsb_txn,
                    struct hmap *dp_groups,
                    struct sbrec_logical_dp_group *sb_group,
                    size_t desired_n,
                    const unsigned long *desired_bitmap,
                    size_t bitmap_len,
                    bool is_switch,
                    const struct ovn_datapaths *ls_datapaths,
                    const struct ovn_datapaths *lr_datapaths)
{
    struct ovn_dp_group *dpg;

    bool update_dp_group = false, can_modify = false;
    unsigned long *dpg_bitmap;
    size_t i, n = 0;

    dpg_bitmap = sb_group ? bitmap_allocate(bitmap_len) : NULL;
    for (i = 0; sb_group && i < sb_group->n_datapaths; i++) {
        struct ovn_datapath *datapath_od;

        datapath_od = ovn_datapath_from_sbrec(
                        ls_datapaths ? &ls_datapaths->datapaths : NULL,
                        lr_datapaths ? &lr_datapaths->datapaths : NULL,
                        sb_group->datapaths[i]);
        if (!datapath_od || ovn_datapath_is_stale(datapath_od)) {
            break;
        }
        bitmap_set1(dpg_bitmap, datapath_od->index);
        n++;
    }
    if (!sb_group || i != sb_group->n_datapaths) {
        /* No group or stale group.  Not going to be used. */
        update_dp_group = true;
        can_modify = true;
    } else if (!bitmap_equal(dpg_bitmap, desired_bitmap, bitmap_len)) {
        /* The group in Sb is different. */
        update_dp_group = true;
        /* We can modify existing group if it's not already in use. */
        can_modify = !ovn_dp_group_find(dp_groups, dpg_bitmap,
                                        bitmap_len, hash_int(n, 0));
    }

    bitmap_free(dpg_bitmap);

    dpg = xzalloc(sizeof *dpg);
    dpg->bitmap = bitmap_clone(desired_bitmap, bitmap_len);
    if (!update_dp_group) {
        dpg->dp_group = sb_group;
    } else {
        dpg->dp_group = ovn_sb_insert_or_update_logical_dp_group(
                            ovnsb_txn,
                            can_modify ? sb_group : NULL,
                            desired_bitmap,
                            is_switch ? ls_datapaths : lr_datapaths);
    }
    dpg->dpg_uuid = dpg->dp_group->header_.uuid;
    hmap_insert(dp_groups, &dpg->node, hash_int(desired_n, 0));

    return dpg;
}

void
ovn_dp_groups_destroy(struct hmap *dp_groups)
{
    struct ovn_dp_group *dpg;
    HMAP_FOR_EACH_POP (dpg, node, dp_groups) {
        bitmap_free(dpg->bitmap);
        free(dpg);
    }
    hmap_destroy(dp_groups);
}


void
lflow_hash_lock_init(void)
{
    if (!lflow_hash_lock_initialized) {
        for (size_t i = 0; i < LFLOW_HASH_LOCK_MASK + 1; i++) {
            ovs_mutex_init(&lflow_hash_locks[i]);
        }
        lflow_hash_lock_initialized = true;
    }
}

void
lflow_hash_lock_destroy(void)
{
    if (lflow_hash_lock_initialized) {
        for (size_t i = 0; i < LFLOW_HASH_LOCK_MASK + 1; i++) {
            ovs_mutex_destroy(&lflow_hash_locks[i]);
        }
    }
    lflow_hash_lock_initialized = false;
}

/* static functions. */
static void
ovn_lflow_init(struct ovn_lflow *lflow, struct ovn_datapath *od,
               size_t dp_bitmap_len, enum ovn_stage stage, uint16_t priority,
               char *match, char *actions, char *io_port, char *ctrl_meter,
               char *stage_hint, const char *where, uint32_t hash)
{
    lflow->dpg_bitmap = bitmap_allocate(dp_bitmap_len);
    lflow->od = od;
    lflow->stage = stage;
    lflow->priority = priority;
    lflow->match = match;
    lflow->actions = actions;
    lflow->io_port = io_port;
    lflow->stage_hint = stage_hint;
    lflow->ctrl_meter = ctrl_meter;
    lflow->dpg = NULL;
    lflow->where = where;
    lflow->sb_uuid = UUID_ZERO;
    lflow->lflow_uuid = uuid_random();
    lflow->lflow_uuid.parts[0] = hash;
}

static struct ovs_mutex *
lflow_hash_lock(const struct hmap *lflow_table, uint32_t hash)
    OVS_ACQUIRES(fake_hash_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct ovs_mutex *hash_lock = NULL;

    if (parallelization_state == STATE_USE_PARALLELIZATION) {
        hash_lock =
            &lflow_hash_locks[hash & lflow_table->mask & LFLOW_HASH_LOCK_MASK];
        ovs_mutex_lock(hash_lock);
    }
    return hash_lock;
}

static void
lflow_hash_unlock(struct ovs_mutex *hash_lock)
    OVS_RELEASES(fake_hash_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (hash_lock) {
        ovs_mutex_unlock(hash_lock);
    }
}

static bool
ovn_lflow_equal(const struct ovn_lflow *a, enum ovn_stage stage,
                uint16_t priority, const char *match,
                const char *actions, const char *ctrl_meter)
{
    return (a->stage == stage
            && a->priority == priority
            && !strcmp(a->match, match)
            && !strcmp(a->actions, actions)
            && nullable_string_is_equal(a->ctrl_meter, ctrl_meter));
}

static struct ovn_lflow *
ovn_lflow_find(const struct hmap *lflows,
               enum ovn_stage stage, uint16_t priority,
               const char *match, const char *actions,
               const char *ctrl_meter, uint32_t hash)
{
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_WITH_HASH (lflow, hmap_node, hash, lflows) {
        if (ovn_lflow_equal(lflow, stage, priority, match, actions,
                            ctrl_meter)) {
            return lflow;
        }
    }
    return NULL;
}

static char *
ovn_lflow_hint(const struct ovsdb_idl_row *row)
{
    if (!row) {
        return NULL;
    }
    return xasprintf("%08x", row->uuid.parts[0]);
}

static void
ovn_lflow_destroy(struct lflow_table *lflow_table, struct ovn_lflow *lflow)
{
    if (lflow) {
        if (lflow_table) {
            hmap_remove(&lflow_table->entries, &lflow->hmap_node);
        }
        bitmap_free(lflow->dpg_bitmap);
        free(lflow->match);
        free(lflow->actions);
        free(lflow->io_port);
        free(lflow->stage_hint);
        free(lflow->ctrl_meter);
        free(lflow);
    }
}

static
void inc_ovn_lflow_ref(struct ovn_lflow *lflow)
{
    lflow->refcnt++;
}

static
void dec_ovn_lflow_ref(struct lflow_table *lflow_table,
                       struct ovn_lflow *lflow)
{
    lflow->refcnt--;

    if (!lflow->refcnt) {
        ovn_lflow_destroy(lflow_table, lflow);
    }
}

static struct ovn_lflow *
do_ovn_lflow_add(struct lflow_table *lflow_table,
                 const struct ovn_datapath *od,
                 const unsigned long *dp_bitmap, size_t dp_bitmap_len,
                 uint32_t hash, enum ovn_stage stage, uint16_t priority,
                 const char *match, const char *actions,
                 const char *io_port, const char *ctrl_meter,
                 const struct ovsdb_idl_row *stage_hint,
                 const char *where)
    OVS_REQUIRES(fake_hash_mutex)
{
    struct ovn_lflow *old_lflow;
    struct ovn_lflow *lflow;

    size_t bitmap_len = od ? ods_size(od->datapaths) : dp_bitmap_len;
    ovs_assert(bitmap_len);

    old_lflow = ovn_lflow_find(&lflow_table->entries, stage,
                               priority, match, actions, ctrl_meter, hash);
    if (old_lflow) {
        ovn_dp_group_add_with_reference(old_lflow, od, dp_bitmap,
                                        bitmap_len);
        return old_lflow;
    }

    lflow = xmalloc(sizeof *lflow);
    /* While adding new logical flows we're not setting single datapath, but
     * collecting a group.  'od' will be updated later for all flows with only
     * one datapath in a group, so it could be hashed correctly. */
    ovn_lflow_init(lflow, NULL, bitmap_len, stage, priority,
                   xstrdup(match), xstrdup(actions),
                   io_port ? xstrdup(io_port) : NULL,
                   nullable_xstrdup(ctrl_meter),
                   ovn_lflow_hint(stage_hint), where, hash);

    ovn_dp_group_add_with_reference(lflow, od, dp_bitmap, bitmap_len);

    if (parallelization_state != STATE_USE_PARALLELIZATION) {
        hmap_insert(&lflow_table->entries, &lflow->hmap_node, hash);
    } else {
        hmap_insert_fast(&lflow_table->entries, &lflow->hmap_node,
                         hash);
        thread_lflow_counter++;
    }

    return lflow;
}

static void
sync_lflow_to_sb(struct ovn_lflow *lflow,
                 struct ovsdb_idl_txn *ovnsb_txn,
                 struct lflow_table *lflow_table,
                 const struct ovn_datapaths *ls_datapaths,
                 const struct ovn_datapaths *lr_datapaths,
                 bool ovn_internal_version_changed,
                 const struct sbrec_logical_flow *sbflow,
                 const struct sbrec_logical_dp_group_table *sb_dpgrp_table)
{
    struct sbrec_logical_dp_group *sbrec_dp_group = NULL;
    struct ovn_dp_group *pre_sync_dpg = lflow->dpg;
    struct ovn_datapath **datapaths_array;
    struct hmap *dp_groups;
    size_t n_datapaths;
    bool is_switch;

    if (ovn_stage_to_datapath_type(lflow->stage) == DP_SWITCH) {
        n_datapaths = ods_size(ls_datapaths);
        datapaths_array = ls_datapaths->array;
        dp_groups = &lflow_table->ls_dp_groups;
        is_switch = true;
    } else {
        n_datapaths = ods_size(lr_datapaths);
        datapaths_array = lr_datapaths->array;
        dp_groups = &lflow_table->lr_dp_groups;
        is_switch = false;
    }

    lflow->n_ods = bitmap_count1(lflow->dpg_bitmap, n_datapaths);
    ovs_assert(lflow->n_ods);

    if (lflow->n_ods == 1) {
        /* There is only one datapath, so it should be moved out of the
         * group to a single 'od'. */
        size_t index = bitmap_scan(lflow->dpg_bitmap, true, 0,
                                    n_datapaths);

        lflow->od = datapaths_array[index];
        lflow->dpg = NULL;
    } else {
        lflow->od = NULL;
    }

    if (!sbflow) {
        lflow->sb_uuid = uuid_random();
        sbflow = sbrec_logical_flow_insert_persist_uuid(ovnsb_txn,
                                                        &lflow->sb_uuid);
        const char *pipeline = ovn_stage_get_pipeline_name(lflow->stage);
        uint8_t table = ovn_stage_get_table(lflow->stage);
        sbrec_logical_flow_set_pipeline(sbflow, pipeline);
        sbrec_logical_flow_set_table_id(sbflow, table);
        sbrec_logical_flow_set_priority(sbflow, lflow->priority);
        sbrec_logical_flow_set_match(sbflow, lflow->match);
        sbrec_logical_flow_set_actions(sbflow, lflow->actions);
        if (lflow->io_port) {
            struct smap tags = SMAP_INITIALIZER(&tags);
            smap_add(&tags, "in_out_port", lflow->io_port);
            sbrec_logical_flow_set_tags(sbflow, &tags);
            smap_destroy(&tags);
        }
        sbrec_logical_flow_set_controller_meter(sbflow, lflow->ctrl_meter);

        /* Trim the source locator lflow->where, which looks something like
         * "ovn/northd/northd.c:1234", down to just the part following the
         * last slash, e.g. "northd.c:1234". */
        const char *slash = strrchr(lflow->where, '/');
#if _WIN32
        const char *backslash = strrchr(lflow->where, '\\');
        if (!slash || backslash > slash) {
            slash = backslash;
        }
#endif
        const char *where = slash ? slash + 1 : lflow->where;

        struct smap ids = SMAP_INITIALIZER(&ids);
        smap_add(&ids, "stage-name", ovn_stage_to_str(lflow->stage));
        smap_add(&ids, "source", where);
        if (lflow->stage_hint) {
            smap_add(&ids, "stage-hint", lflow->stage_hint);
        }
        sbrec_logical_flow_set_external_ids(sbflow, &ids);
        smap_destroy(&ids);

    } else {
        lflow->sb_uuid = sbflow->header_.uuid;
        sbrec_dp_group = sbflow->logical_dp_group;

        if (ovn_internal_version_changed) {
            const char *stage_name = smap_get_def(&sbflow->external_ids,
                                                  "stage-name", "");
            const char *stage_hint = smap_get_def(&sbflow->external_ids,
                                                  "stage-hint", "");
            const char *source = smap_get_def(&sbflow->external_ids,
                                              "source", "");

            if (strcmp(stage_name, ovn_stage_to_str(lflow->stage))) {
                sbrec_logical_flow_update_external_ids_setkey(
                    sbflow, "stage-name", ovn_stage_to_str(lflow->stage));
            }
            if (lflow->stage_hint) {
                if (strcmp(stage_hint, lflow->stage_hint)) {
                    sbrec_logical_flow_update_external_ids_setkey(
                        sbflow, "stage-hint", lflow->stage_hint);
                }
            }
            if (lflow->where) {

                /* Trim the source locator lflow->where, which looks something
                 * like "ovn/northd/northd.c:1234", down to just the part
                 * following the last slash, e.g. "northd.c:1234". */
                const char *slash = strrchr(lflow->where, '/');
#if _WIN32
                const char *backslash = strrchr(lflow->where, '\\');
                if (!slash || backslash > slash) {
                    slash = backslash;
                }
#endif
                const char *where = slash ? slash + 1 : lflow->where;

                if (strcmp(source, where)) {
                    sbrec_logical_flow_update_external_ids_setkey(
                        sbflow, "source", where);
                }
            }
        }
    }

    if (lflow->od) {
        sbrec_logical_flow_set_logical_datapath(sbflow, lflow->od->sb);
        sbrec_logical_flow_set_logical_dp_group(sbflow, NULL);
    } else {
        sbrec_logical_flow_set_logical_datapath(sbflow, NULL);
        lflow->dpg = ovn_dp_group_get(dp_groups, lflow->n_ods,
                                      lflow->dpg_bitmap,
                                      n_datapaths);
        if (lflow->dpg) {
            /* Update the dpg's sb dp_group. */
            lflow->dpg->dp_group = sbrec_logical_dp_group_table_get_for_uuid(
                sb_dpgrp_table,
                &lflow->dpg->dpg_uuid);
            ovs_assert(lflow->dpg->dp_group);
        } else {
            lflow->dpg = ovn_dp_group_create(
                                ovnsb_txn, dp_groups, sbrec_dp_group,
                                lflow->n_ods, lflow->dpg_bitmap,
                                n_datapaths, is_switch,
                                ls_datapaths,
                                lr_datapaths);
        }
        sbrec_logical_flow_set_logical_dp_group(sbflow,
                                                lflow->dpg->dp_group);
    }

    if (pre_sync_dpg != lflow->dpg) {
        if (lflow->dpg) {
            inc_ovn_dp_group_ref(lflow->dpg);
        }
        if (pre_sync_dpg) {
           dec_ovn_dp_group_ref(dp_groups, pre_sync_dpg);
        }
    }
}

static struct ovn_dp_group *
ovn_dp_group_find(const struct hmap *dp_groups,
                  const unsigned long *dpg_bitmap, size_t bitmap_len,
                  uint32_t hash)
{
    struct ovn_dp_group *dpg;

    HMAP_FOR_EACH_WITH_HASH (dpg, node, hash, dp_groups) {
        if (bitmap_equal(dpg->bitmap, dpg_bitmap, bitmap_len)) {
            return dpg;
        }
    }
    return NULL;
}

static struct sbrec_logical_dp_group *
ovn_sb_insert_or_update_logical_dp_group(
                            struct ovsdb_idl_txn *ovnsb_txn,
                            struct sbrec_logical_dp_group *dp_group,
                            const unsigned long *dpg_bitmap,
                            const struct ovn_datapaths *datapaths)
{
    const struct sbrec_datapath_binding **sb;
    size_t n = 0, index;

    sb = xmalloc(bitmap_count1(dpg_bitmap, ods_size(datapaths)) * sizeof *sb);
    BITMAP_FOR_EACH_1 (index, ods_size(datapaths), dpg_bitmap) {
        sb[n++] = datapaths->array[index]->sb;
    }
    if (!dp_group) {
        struct uuid dpg_uuid = uuid_random();
        dp_group = sbrec_logical_dp_group_insert_persist_uuid(
            ovnsb_txn, &dpg_uuid);
    }
    sbrec_logical_dp_group_set_datapaths(
        dp_group, (struct sbrec_datapath_binding **) sb, n);
    free(sb);

    return dp_group;
}

/* Adds an OVN datapath to a datapath group of existing logical flow.
 * Version to use when hash bucket locking is NOT required or the corresponding
 * hash lock is already taken. */
static void
ovn_dp_group_add_with_reference(struct ovn_lflow *lflow_ref,
                                const struct ovn_datapath *od,
                                const unsigned long *dp_bitmap,
                                size_t bitmap_len)
    OVS_REQUIRES(fake_hash_mutex)
{
    if (od) {
        bitmap_set1(lflow_ref->dpg_bitmap, od->index);
    }
    if (dp_bitmap) {
        bitmap_or(lflow_ref->dpg_bitmap, dp_bitmap, bitmap_len);
    }
}

/* Unlinks the lflows stored in the resource to object nodes for the
 * datapath 'od' from the lflow dependecy manager.
 * It basically clears the datapath id of the 'od' for the lflows
 * in the 'res_node'.
 */
static void
unlink_lflows_from_datapath(struct lflow_ref *lflow_ref)
{
    struct lflow_ref_node *ref_node;

    LIST_FOR_EACH (ref_node, ref_list_node, &lflow_ref->lflows_ref_list) {
        bitmap_set0(ref_node->lflow->dpg_bitmap, ref_node->dp_index);
    }
}

static void
unlink_lflows_from_all_datapaths(struct lflow_ref *lflow_ref,
                                 size_t n_ls_datapaths,
                                 size_t n_lr_datapaths)
{
    struct lflow_ref_node *ref_node;
    struct ovn_lflow *lflow;
    LIST_FOR_EACH (ref_node, ref_list_node, &lflow_ref->lflows_ref_list) {
        size_t n_datapaths;
        size_t index;

        lflow = ref_node->lflow;
        if (ovn_stage_to_datapath_type(lflow->stage) == DP_SWITCH) {
            n_datapaths = n_ls_datapaths;
        } else {
            n_datapaths = n_lr_datapaths;
        }

        BITMAP_FOR_EACH_1 (index, n_datapaths, lflow->dpg_bitmap) {
            bitmap_set0(lflow->dpg_bitmap, index);
        }
    }
}

static void
lflow_ref_sync_lflows_to_sb__(struct lflow_ref  *lflow_ref,
                        struct lflow_table *lflow_table,
                        struct ovsdb_idl_txn *ovnsb_txn,
                        const struct ovn_datapaths *ls_datapaths,
                        const struct ovn_datapaths *lr_datapaths,
                        bool ovn_internal_version_changed,
                        const struct sbrec_logical_flow_table *sbflow_table,
                        const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    struct lflow_ref_node *lrn;
    struct ovn_lflow *lflow;
    LIST_FOR_EACH (lrn, ref_list_node, &lflow_ref->lflows_ref_list) {
        lflow = lrn->lflow;

        const struct sbrec_logical_flow *sblflow =
            sbrec_logical_flow_table_get_for_uuid(sbflow_table,
                                                  &lflow->sb_uuid);

        size_t n_datapaths;
        if (ovn_stage_to_datapath_type(lflow->stage) == DP_SWITCH) {
            n_datapaths = ods_size(ls_datapaths);
        } else {
            n_datapaths = ods_size(lr_datapaths);
        }

        size_t n_ods = bitmap_count1(lflow->dpg_bitmap, n_datapaths);

        if (n_ods) {
            sync_lflow_to_sb(lflow, ovnsb_txn, lflow_table, ls_datapaths,
                             lr_datapaths, ovn_internal_version_changed,
                             sblflow, dpgrp_table);
        } else {
            if (sblflow) {
                sbrec_logical_flow_delete(sblflow);
                dec_ovn_lflow_ref(lflow_table, lflow);
            }

            lrn->lflow = NULL;
            hmapx_find_and_delete(&lflow_ref->lflows, lflow);
        }
    }

    LIST_FOR_EACH_SAFE (lrn, ref_list_node, &lflow_ref->lflows_ref_list) {
        if (!lrn->lflow) {
            ovs_list_remove(&lrn->ref_list_node);
            free(lrn);
        }
    }
}
