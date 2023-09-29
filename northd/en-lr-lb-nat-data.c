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
#include "en-lr-lb-nat-data.h"
#include "en-lr-nat.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_lr_lb_nat_data);

/* Static function declarations. */
static void lr_lb_nat_data_table_init(struct lr_lb_nat_data_table *);
static void lr_lb_nat_data_table_clear(struct lr_lb_nat_data_table *);
static void lr_lb_nat_data_table_destroy(struct lr_lb_nat_data_table *);
static struct lr_lb_nat_data_record *lr_lb_nat_data_table_find_(
    const struct lr_lb_nat_data_table *, const struct nbrec_logical_router *);
static struct lr_lb_nat_data_record *lr_lb_nat_data_table_find_by_index_(
    const struct lr_lb_nat_data_table *table, size_t od_index);

static void lr_lb_nat_data_table_build(struct lr_lb_nat_data_table *,
                                   const struct lr_nat_table *,
                                   const struct ovn_datapaths *lr_datapaths,
                                   const struct hmap *lb_datapaths_map,
                                   const struct hmap *lbgrp_datapaths_map);

static struct lr_lb_nat_data_input lr_lb_nat_data_get_input_data(
    struct engine_node *);

static struct lr_lb_nat_data_record *lr_lb_nat_data_record_create(
    struct lr_lb_nat_data_table *, const struct lr_nat_record *,
    const struct hmap *lb_datapaths_map,
    const struct hmap *lbgrp_datapaths_map);
static void lr_lb_nat_data_record_destroy(struct lr_lb_nat_data_record *);
static void lr_lb_nat_data_record_init(
    struct lr_lb_nat_data_record *,
    const struct hmap *lb_datapaths_map,
    const struct hmap *lbgrp_datapaths_map);

static void build_lrouter_lb_reachable_ips(struct lr_lb_nat_data_record *,
                                           const struct ovn_northd_lb *);
static void add_neigh_ips_to_lrouter(struct lr_lb_nat_data_record *,
                                     enum lb_neighbor_responder_mode,
                                     const struct sset *lb_ips_v4,
                                     const struct sset *lb_ips_v6);
static void remove_lrouter_lb_reachable_ips(struct lr_lb_nat_data_record *,
                                            enum lb_neighbor_responder_mode,
                                            const struct sset *lb_ips_v4,
                                            const struct sset *lb_ips_v6);
static void lr_lb_nat_data_build_vip_nats(struct lr_lb_nat_data_record *);

/* 'lr_lb_nat_data' engine node manages the NB logical router LB data.
 */
void *
en_lr_lb_nat_data_init(struct engine_node *node OVS_UNUSED,
               struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_lr_lb_nat_data *data = xzalloc(sizeof *data);
    lr_lb_nat_data_table_init(&data->lr_lbnats);
    hmapx_init(&data->tracked_data.crupdated);
    hmapx_init(&data->tracked_data.deleted);
    return data;
}

void
en_lr_lb_nat_data_cleanup(void *data_)
{
    struct ed_type_lr_lb_nat_data *data =
        (struct ed_type_lr_lb_nat_data *) data_;
    lr_lb_nat_data_table_destroy(&data->lr_lbnats);
    hmapx_destroy(&data->tracked_data.crupdated);
    hmapx_destroy(&data->tracked_data.deleted);
}

void
en_lr_lb_nat_data_clear_tracked_data(void *data_)
{
    struct ed_type_lr_lb_nat_data *data =
        (struct ed_type_lr_lb_nat_data *) data_;

    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH_SAFE (hmapx_node, &data->tracked_data.deleted) {
        lr_lb_nat_data_record_destroy(hmapx_node->data);
        hmapx_delete(&data->tracked_data.deleted, hmapx_node);
    }

    hmapx_clear(&data->tracked_data.crupdated);
    data->tracked = false;
}

void
en_lr_lb_nat_data_run(struct engine_node *node, void *data_)
{
    struct lr_lb_nat_data_input input_data =
        lr_lb_nat_data_get_input_data(node);
    struct ed_type_lr_lb_nat_data *data = data_;

    stopwatch_start(LR_LB_NAT_DATA_RUN_STOPWATCH_NAME, time_msec());

    lr_lb_nat_data_table_clear(&data->lr_lbnats);
    lr_lb_nat_data_table_build(&data->lr_lbnats, input_data.lr_nats,
                               input_data.lr_datapaths,
                               input_data.lb_datapaths_map,
                               input_data.lbgrp_datapaths_map);

    stopwatch_stop(LR_LB_NAT_DATA_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

bool
lr_lb_nat_data_northd_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_data->change_tracked) {
        return false;
    }

    return true;
}

bool
lr_lb_nat_data_lb_data_handler(struct engine_node *node, void *data_)
{
    struct ed_type_lb_data *lb_data = engine_get_input_data("lb_data", node);
    if (!lb_data->tracked) {
        return false;
    }

    struct ed_type_lr_lb_nat_data *data =
        (struct ed_type_lr_lb_nat_data *) data_;
    struct lr_lb_nat_data_input input_data =
        lr_lb_nat_data_get_input_data(node);
    struct lr_lb_nat_data_record *lr_lbnat_rec;
    size_t index;

    const struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    const struct ovn_lb_group_datapaths *lbgrp_dps;
    const struct crupdated_lbgrp *crupdated_lbgrp;
    const struct crupdated_od_lb_data *codlb;
    const struct ovn_lb_datapaths *lb_dps;
    const struct crupdated_lb *clb;
    const struct ovn_northd_lb *lb;
    const struct ovn_datapath *od;

    LIST_FOR_EACH (codlb, list_node, &trk_lb_data->crupdated_lr_lbs) {
        od = ovn_datapath_find(&input_data.lr_datapaths->datapaths,
                               &codlb->od_uuid);
        ovs_assert(od);

        lr_lbnat_rec = lr_lb_nat_data_table_find_(&data->lr_lbnats, od->nbr);
        if (!lr_lbnat_rec) {
            const struct lr_nat_record *lrnat_rec = lr_nat_table_find_by_index(
                input_data.lr_nats, od->index);
            ovs_assert(lrnat_rec);

            lr_lbnat_rec = lr_lb_nat_data_record_create(&data->lr_lbnats,
                                            lrnat_rec,
                                            input_data.lb_datapaths_map,
                                            input_data.lbgrp_datapaths_map);

            /* Add the lr_lbnat_rec rec to the tracking data. */
            hmapx_add(&data->tracked_data.crupdated, lr_lbnat_rec);
            continue;
        }

        struct uuidset_node *uuidnode;
        UUIDSET_FOR_EACH (uuidnode, &codlb->assoc_lbs) {
            lb_dps = ovn_lb_datapaths_find(
                input_data.lb_datapaths_map, &uuidnode->uuid);
            ovs_assert(lb_dps);

            /* Add the lb_ips of lb_dps to the od. */
            build_lrouter_lb_ips(lr_lbnat_rec->lb_ips, lb_dps->lb);
            build_lrouter_lb_reachable_ips(lr_lbnat_rec, lb_dps->lb);
        }

        UUIDSET_FOR_EACH (uuidnode, &codlb->assoc_lbgrps) {
            lbgrp_dps = ovn_lb_group_datapaths_find(
                input_data.lbgrp_datapaths_map, &uuidnode->uuid);
            ovs_assert(lbgrp_dps);

            for (size_t j = 0; j < lbgrp_dps->lb_group->n_lbs; j++) {
                const struct uuid *lb_uuid
                    = &lbgrp_dps->lb_group->lbs[j]->nlb->header_.uuid;
                lb_dps = ovn_lb_datapaths_find(input_data.lb_datapaths_map,
                                               lb_uuid);
                ovs_assert(lb_dps);

                /* Add the lb_ips of lb_dps to the od. */
                build_lrouter_lb_ips(lr_lbnat_rec->lb_ips, lb_dps->lb);
                build_lrouter_lb_reachable_ips(lr_lbnat_rec, lb_dps->lb);
            }
        }

        /* Add the lr_lbnat_rec rec to the tracking data. */
        hmapx_add(&data->tracked_data.crupdated, lr_lbnat_rec);
    }

    HMAP_FOR_EACH (clb, hmap_node, &trk_lb_data->crupdated_lbs) {
        lb = clb->lb;
        const struct uuid *lb_uuid = &lb->nlb->header_.uuid;

        lb_dps = ovn_lb_datapaths_find(input_data.lb_datapaths_map, lb_uuid);
        ovs_assert(lb_dps);

        BITMAP_FOR_EACH_1 (index, ods_size(input_data.lr_datapaths),
                           lb_dps->nb_lr_map) {
            od = input_data.lr_datapaths->array[index];

            lr_lbnat_rec = lr_lb_nat_data_table_find_(&data->lr_lbnats,
                                                      od->nbr);
            ovs_assert(lr_lbnat_rec);

            /* Update the od->lb_ips with the deleted and inserted
             * vips (if any). */
            remove_ips_from_lb_ip_set(lr_lbnat_rec->lb_ips, lb->routable,
                                      &clb->deleted_vips_v4,
                                      &clb->deleted_vips_v6);
            add_ips_to_lb_ip_set(lr_lbnat_rec->lb_ips, lb->routable,
                                 &clb->inserted_vips_v4,
                                 &clb->inserted_vips_v6);

            remove_lrouter_lb_reachable_ips(lr_lbnat_rec, lb->neigh_mode,
                                            &clb->deleted_vips_v4,
                                            &clb->deleted_vips_v6);
            add_neigh_ips_to_lrouter(lr_lbnat_rec, lb->neigh_mode,
                                     &clb->inserted_vips_v4,
                                     &clb->inserted_vips_v6);

            /* Add the lr_lbnat_rec rec to the tracking data. */
            hmapx_add(&data->tracked_data.crupdated, lr_lbnat_rec);
        }
    }

    HMAP_FOR_EACH (crupdated_lbgrp, hmap_node,
                   &trk_lb_data->crupdated_lbgrps) {
        const struct uuid *lb_uuid = &crupdated_lbgrp->lbgrp->uuid;

        lbgrp_dps = ovn_lb_group_datapaths_find(input_data.lbgrp_datapaths_map,
                                                lb_uuid);
        ovs_assert(lbgrp_dps);

        struct hmapx_node *hnode;
        HMAPX_FOR_EACH (hnode, &crupdated_lbgrp->assoc_lbs) {
            lb = hnode->data;
            lb_uuid = &lb->nlb->header_.uuid;
            lb_dps = ovn_lb_datapaths_find(input_data.lb_datapaths_map,
                                           lb_uuid);
            ovs_assert(lb_dps);
            for (size_t i = 0; i < lbgrp_dps->n_lr; i++) {
                od = lbgrp_dps->lr[i];
                lr_lbnat_rec = lr_lb_nat_data_table_find_(&data->lr_lbnats,
                                                          od->nbr);
                ovs_assert(lr_lbnat_rec);
                /* Add the lb_ips of lb_dps to the lr lb data. */
                build_lrouter_lb_ips(lr_lbnat_rec->lb_ips, lb_dps->lb);
                build_lrouter_lb_reachable_ips(lr_lbnat_rec, lb_dps->lb);

                /* Add the lr_lbnat_rec rec to the tracking data. */
                hmapx_add(&data->tracked_data.crupdated, lr_lbnat_rec);
            }
        }
    }

    if (!hmapx_is_empty(&data->tracked_data.crupdated)) {
        struct hmapx_node *hmapx_node;
        /* For all the modified lr_lb_nat_data records (re)build the
         * vip nats and re-evaluate 'has_lb_vip'. */
        HMAPX_FOR_EACH (hmapx_node, &data->tracked_data.crupdated) {
            lr_lbnat_rec = hmapx_node->data;
            lr_lb_nat_data_build_vip_nats(lr_lbnat_rec);
            lr_lbnat_rec->has_lb_vip = od_has_lb_vip(lr_lbnat_rec->od);
        }

        data->tracked = true;
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
}

bool
lr_lb_nat_data_lr_nat_handler(struct engine_node *node, void *data_)
{
    struct ed_type_lr_nat_data *lr_nat_data =
        engine_get_input_data("lr_nat", node);

    if (!lr_nat_data->tracked
        || !hmapx_is_empty(&lr_nat_data->tracked_data.deleted)) {
        return false;
    }

    struct ed_type_lr_lb_nat_data *data =
        (struct ed_type_lr_lb_nat_data *) data_;
    struct lr_lb_nat_data_input input_data =
        lr_lb_nat_data_get_input_data(node);
    const struct lr_nat_record *lrnat_rec;
    struct lr_lb_nat_data_record *lr_lbnat_rec;
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &lr_nat_data->tracked_data.crupdated) {
        lrnat_rec = hmapx_node->data;
        lr_lbnat_rec = lr_lb_nat_data_table_find_(&data->lr_lbnats,
                                                  lrnat_rec->od->nbr);
        if (!lr_lbnat_rec) {
            lr_lbnat_rec = lr_lb_nat_data_record_create(&data->lr_lbnats,
                                            lrnat_rec,
                                            input_data.lb_datapaths_map,
                                            input_data.lbgrp_datapaths_map);
        } else {
            lr_lb_nat_data_build_vip_nats(lr_lbnat_rec);
        }

        /* Add the lr_lbnat_rec rec to the tracking data. */
        hmapx_add(&data->tracked_data.crupdated, lr_lbnat_rec);
    }

    if (!hmapx_is_empty(&data->tracked_data.crupdated)) {
        data->tracked = true;
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
}

const struct lr_lb_nat_data_record *
lr_lb_nat_data_table_find_by_index(const struct lr_lb_nat_data_table *table,
                                   size_t od_index)
{
    return lr_lb_nat_data_table_find_by_index_(table, od_index);
}

/* static functions. */
static void
lr_lb_nat_data_table_init(struct lr_lb_nat_data_table *table)
{
    *table = (struct lr_lb_nat_data_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

static void
lr_lb_nat_data_table_destroy(struct lr_lb_nat_data_table *table)
{
    lr_lb_nat_data_table_clear(table);
    hmap_destroy(&table->entries);
}

static void
lr_lb_nat_data_table_clear(struct lr_lb_nat_data_table *table)
{
    struct lr_lb_nat_data_record *lr_lbnat_rec;
    HMAP_FOR_EACH_POP (lr_lbnat_rec, key_node, &table->entries) {
        lr_lb_nat_data_record_destroy(lr_lbnat_rec);
    }

    free(table->array);
    table->array = NULL;
}

static void
lr_lb_nat_data_table_build(struct lr_lb_nat_data_table *table,
                       const struct lr_nat_table *lr_nats,
                       const struct ovn_datapaths *lr_datapaths,
                       const struct hmap *lb_datapaths_map,
                       const struct hmap *lbgrp_datapaths_map)
{
    table->array = xrealloc(table->array,
                            ods_size(lr_datapaths) * sizeof *table->array);
    const struct lr_nat_record *lrnat_rec;
    LR_NAT_TABLE_FOR_EACH (lrnat_rec, lr_nats) {
        lr_lb_nat_data_record_create(table, lrnat_rec, lb_datapaths_map,
                                     lbgrp_datapaths_map);
    }
}

static struct lr_lb_nat_data_record *
lr_lb_nat_data_table_find_(const struct lr_lb_nat_data_table *table,
                  const struct nbrec_logical_router *nbr)
{
    struct lr_lb_nat_data_record *lr_lbnat_rec;

    HMAP_FOR_EACH_WITH_HASH (lr_lbnat_rec, key_node,
                             uuid_hash(&nbr->header_.uuid), &table->entries) {
        if (nbr == lr_lbnat_rec->od->nbr) {
            return lr_lbnat_rec;
        }
    }
    return NULL;
}

static struct lr_lb_nat_data_record *
lr_lb_nat_data_table_find_by_index_(const struct lr_lb_nat_data_table *table,
                                   size_t od_index)
{
    ovs_assert(od_index <= hmap_count(&table->entries));
    return table->array[od_index];
}

static struct lr_lb_nat_data_record *
lr_lb_nat_data_record_create(struct lr_lb_nat_data_table *table,
                         const struct lr_nat_record *lrnat_rec,
                         const struct hmap *lb_datapaths_map,
                         const struct hmap *lbgrp_datapaths_map)
{
    struct lr_lb_nat_data_record *lr_lbnat_rec = xzalloc(sizeof *lr_lbnat_rec);
    lr_lbnat_rec->lrnat_rec = lrnat_rec;
    lr_lbnat_rec->od = lrnat_rec->od;
    lr_lb_nat_data_record_init(lr_lbnat_rec, lb_datapaths_map,
                               lbgrp_datapaths_map);

    hmap_insert(&table->entries, &lr_lbnat_rec->key_node,
                uuid_hash(&lr_lbnat_rec->od->nbr->header_.uuid));

    table->array[lr_lbnat_rec->od->index] = lr_lbnat_rec;
    return lr_lbnat_rec;
}

static void
lr_lb_nat_data_record_destroy(struct lr_lb_nat_data_record *lr_lbnat_rec)
{
    ovn_lb_ip_set_destroy(lr_lbnat_rec->lb_ips);
    lr_lbnat_rec->lb_ips = NULL;
    sset_destroy(&lr_lbnat_rec->vip_nats);
    free(lr_lbnat_rec);
}

static void
lr_lb_nat_data_record_init(struct lr_lb_nat_data_record *lr_lbnat_rec,
                           const struct hmap *lb_datapaths_map,
                           const struct hmap *lbgrp_datapaths_map)
{
    const struct nbrec_load_balancer_group *nbrec_lb_group;
    const struct ovn_lb_group_datapaths *lb_group_dps;
    const struct ovn_lb_datapaths *lb_dps;

    /* Checking load balancer groups first, starting from the largest one,
     * to more efficiently copy IP sets. */
    size_t largest_group = 0;

    const struct nbrec_logical_router *nbr = lr_lbnat_rec->od->nbr;
    for (size_t i = 1; i < nbr->n_load_balancer_group; i++) {
        if (nbr->load_balancer_group[i]->n_load_balancer >
                nbr->load_balancer_group[largest_group]->n_load_balancer) {
            largest_group = i;
        }
    }

    for (size_t i = 0; i < nbr->n_load_balancer_group; i++) {
        size_t idx = (i + largest_group) % nbr->n_load_balancer_group;

        nbrec_lb_group = nbr->load_balancer_group[idx];
        const struct uuid *lbgrp_uuid = &nbrec_lb_group->header_.uuid;

        lb_group_dps =
            ovn_lb_group_datapaths_find(lbgrp_datapaths_map,
                                        lbgrp_uuid);
        ovs_assert(lb_group_dps);

        if (!lr_lbnat_rec->lb_ips) {
            lr_lbnat_rec->lb_ips =
                ovn_lb_ip_set_clone(lb_group_dps->lb_group->lb_ips);
        } else {
            for (size_t j = 0; j < lb_group_dps->lb_group->n_lbs; j++) {
                build_lrouter_lb_ips(lr_lbnat_rec->lb_ips,
                                     lb_group_dps->lb_group->lbs[j]);
            }
        }

        for (size_t j = 0; j < lb_group_dps->lb_group->n_lbs; j++) {
            build_lrouter_lb_reachable_ips(lr_lbnat_rec,
                                           lb_group_dps->lb_group->lbs[j]);
        }
    }

    if (!lr_lbnat_rec->lb_ips) {
        lr_lbnat_rec->lb_ips = ovn_lb_ip_set_create();
    }

    for (size_t i = 0; i < nbr->n_load_balancer; i++) {
        const struct uuid *lb_uuid =
            &nbr->load_balancer[i]->header_.uuid;
        lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
        ovs_assert(lb_dps);
        build_lrouter_lb_ips(lr_lbnat_rec->lb_ips, lb_dps->lb);
        build_lrouter_lb_reachable_ips(lr_lbnat_rec, lb_dps->lb);
    }

    sset_init(&lr_lbnat_rec->vip_nats);

    if (!nbr->n_nat) {
        lr_lb_nat_data_build_vip_nats(lr_lbnat_rec);
    }

    lr_lbnat_rec->has_lb_vip = od_has_lb_vip(lr_lbnat_rec->od);
}

static struct lr_lb_nat_data_input
lr_lb_nat_data_get_input_data(struct engine_node *node)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_lr_nat_data *lr_nat_data =
        engine_get_input_data("lr_nat", node);

    return (struct lr_lb_nat_data_input) {
        .lr_datapaths = &northd_data->lr_datapaths,
        .lb_datapaths_map = &northd_data->lb_datapaths_map,
        .lbgrp_datapaths_map = &northd_data->lb_group_datapaths_map,
        .lr_nats = &lr_nat_data->lr_nats,
    };
}

static void
build_lrouter_lb_reachable_ips(struct lr_lb_nat_data_record *lr_lbnat_rec,
                               const struct ovn_northd_lb *lb)
{
    add_neigh_ips_to_lrouter(lr_lbnat_rec, lb->neigh_mode, &lb->ips_v4,
                             &lb->ips_v6);
}

static void
add_neigh_ips_to_lrouter(struct lr_lb_nat_data_record *lr_lbnat_rec,
                         enum lb_neighbor_responder_mode neigh_mode,
                         const struct sset *lb_ips_v4,
                         const struct sset *lb_ips_v6)
{
    /* If configured to not reply to any neighbor requests for all VIPs
     * return early.
     */
    if (neigh_mode == LB_NEIGH_RESPOND_NONE) {
        return;
    }

    const char *ip_address;

    /* If configured to reply to neighbor requests for all VIPs force them
     * all to be considered "reachable".
     */
    if (neigh_mode == LB_NEIGH_RESPOND_ALL) {
        SSET_FOR_EACH (ip_address, lb_ips_v4) {
            sset_add(&lr_lbnat_rec->lb_ips->ips_v4_reachable, ip_address);
        }
        SSET_FOR_EACH (ip_address, lb_ips_v6) {
            sset_add(&lr_lbnat_rec->lb_ips->ips_v6_reachable, ip_address);
        }

        return;
    }

    /* Otherwise, a VIP is reachable if there's at least one router
     * subnet that includes it.
     */
    ovs_assert(neigh_mode == LB_NEIGH_RESPOND_REACHABLE);

    SSET_FOR_EACH (ip_address, lb_ips_v4) {
        struct ovn_port *op;
        ovs_be32 vip_ip4;
        if (ip_parse(ip_address, &vip_ip4)) {
            HMAP_FOR_EACH (op, dp_node, &lr_lbnat_rec->od->ports) {
                if (lrouter_port_ipv4_reachable(op, vip_ip4)) {
                    sset_add(&lr_lbnat_rec->lb_ips->ips_v4_reachable,
                             ip_address);
                    break;
                }
            }
        }
    }

    SSET_FOR_EACH (ip_address, lb_ips_v6) {
        struct ovn_port *op;
        struct in6_addr vip;
        if (ipv6_parse(ip_address, &vip)) {
            HMAP_FOR_EACH (op, dp_node, &lr_lbnat_rec->od->ports) {
                if (lrouter_port_ipv6_reachable(op, &vip)) {
                    sset_add(&lr_lbnat_rec->lb_ips->ips_v6_reachable,
                             ip_address);
                    break;
                }
            }
        }
    }
}

static void
remove_lrouter_lb_reachable_ips(struct lr_lb_nat_data_record *lr_lbnat_rec,
                                enum lb_neighbor_responder_mode neigh_mode,
                                const struct sset *lb_ips_v4,
                                const struct sset *lb_ips_v6)
{
    if (neigh_mode == LB_NEIGH_RESPOND_NONE) {
        return;
    }

    const char *ip_address;
    SSET_FOR_EACH (ip_address, lb_ips_v4) {
        sset_find_and_delete(&lr_lbnat_rec->lb_ips->ips_v4_reachable,
                             ip_address);
    }
    SSET_FOR_EACH (ip_address, lb_ips_v6) {
        sset_find_and_delete(&lr_lbnat_rec->lb_ips->ips_v6_reachable,
                             ip_address);
    }
}

static void
lr_lb_nat_data_build_vip_nats(struct lr_lb_nat_data_record *lr_lbnat_rec)
{
    sset_clear(&lr_lbnat_rec->vip_nats);
    const char *external_ip;
    SSET_FOR_EACH (external_ip, &lr_lbnat_rec->lrnat_rec->external_ips) {
        bool is_vip_nat = false;
        if (addr_is_ipv6(external_ip)) {
            is_vip_nat = sset_contains(&lr_lbnat_rec->lb_ips->ips_v6,
                                       external_ip);
        } else {
            is_vip_nat = sset_contains(&lr_lbnat_rec->lb_ips->ips_v4,
                                       external_ip);
        }

        if (is_vip_nat) {
            sset_add(&lr_lbnat_rec->vip_nats, external_ip);
        }
    }
}
