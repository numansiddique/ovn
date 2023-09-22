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
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "stopwatch.h"

/* OVN includes */
#include "en-lr-nat.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_lr_nat);

/* Static function declarations. */
static void lr_nat_table_init(struct lr_nat_table *);
static void lr_nat_table_clear(struct lr_nat_table *);
static void lr_nat_table_destroy(struct lr_nat_table *);
static void lr_nat_table_build(struct lr_nat_table *,
                               const struct nbrec_logical_router_table *);
struct lr_nat_record *lr_nat_table_find_(const struct lr_nat_table *,
                                         const struct nbrec_logical_router *);

static struct lr_nat_record *lr_nat_record_create(
    struct lr_nat_table *, const struct nbrec_logical_router *);
static void lr_nat_record_init(struct lr_nat_record *);
static void lr_nat_record_reinit(struct lr_nat_record *);
static void lr_nat_record_destroy(struct lr_nat_record *);

static void lr_nat_entries_init(struct lr_nat_record *);
static void lr_nat_entries_destroy(struct lr_nat_record *);
static void lr_nat_external_ips_init(struct lr_nat_record *);
static void lr_nat_external_ips_destroy(struct lr_nat_record *);
static bool get_force_snat_ip(struct lr_nat_record *, const char *key_type,
                              struct lport_addresses *);
static struct lr_nat_input lr_nat_get_input_data(struct engine_node *);
static bool is_lr_nats_changed(const struct nbrec_logical_router *);


const struct lr_nat_record *
lr_nat_table_find(const struct lr_nat_table *table,
                  const struct nbrec_logical_router *nbr)
{
    return lr_nat_table_find_(table, nbr);
}

/* 'lr_nat' engine node manages the NB logical router NAT data.
 */
void *
en_lr_nat_init(struct engine_node *node OVS_UNUSED,
               struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_lr_nat_data *data = xzalloc(sizeof *data);
    lr_nat_table_init(&data->lr_nats);
    hmapx_init(&data->tracked_data.crupdated);
    hmapx_init(&data->tracked_data.deleted);
    return data;
}

void
en_lr_nat_cleanup(void *data_)
{
    struct ed_type_lr_nat_data *data = (struct ed_type_lr_nat_data *) data_;
    lr_nat_table_destroy(&data->lr_nats);
    hmapx_destroy(&data->tracked_data.crupdated);
    hmapx_destroy(&data->tracked_data.deleted);
}

void
en_lr_nat_clear_tracked_data(void *data_)
{
    struct ed_type_lr_nat_data *data = (struct ed_type_lr_nat_data *) data_;

    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH_SAFE (hmapx_node, &data->tracked_data.deleted) {
        lr_nat_record_destroy(hmapx_node->data);
        hmapx_delete(&data->tracked_data.deleted, hmapx_node);
    }

    hmapx_clear(&data->tracked_data.crupdated);
    data->tracked = false;
}

void
en_lr_nat_run(struct engine_node *node, void *data_)
{
    struct lr_nat_input input_data = lr_nat_get_input_data(node);
    struct ed_type_lr_nat_data *data = data_;

    stopwatch_start(LR_NAT_RUN_STOPWATCH_NAME, time_msec());

    lr_nat_table_clear(&data->lr_nats);
    lr_nat_table_build(&data->lr_nats, input_data.nbrec_logical_router_table);

    stopwatch_stop(LR_NAT_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}


/* Handler functions. */
bool
lr_nat_logical_router_handler(struct engine_node *node, void *data_)
{
    struct lr_nat_input input_data = lr_nat_get_input_data(node);
    struct ed_type_lr_nat_data *data = data_;
    const struct nbrec_logical_router *nbr;

    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH_TRACKED (
            nbr, input_data.nbrec_logical_router_table) {
        if (!is_lr_nats_changed(nbr)) {
            continue;
        }

        struct lr_nat_record *lrnat_rec = lr_nat_table_find_(&data->lr_nats,
                                                             nbr);

        if (nbrec_logical_router_is_deleted(nbr)) {
            if (lrnat_rec) {
                /* Remove the record from the entries. */
                hmap_remove(&data->lr_nats.entries, &lrnat_rec->key_node);

                /* Add the lrnet rec to the tracking data. */
                hmapx_add(&data->tracked_data.deleted, lrnat_rec);
            }
        } else {
            if (!lrnat_rec) {
                lrnat_rec = lr_nat_record_create(&data->lr_nats, nbr);
            } else {
                lr_nat_record_reinit(lrnat_rec);
            }

            /* Add the lrnet rec to the tracking data. */
            hmapx_add(&data->tracked_data.crupdated, lrnat_rec);
        }
    }

    if (!hmapx_is_empty(&data->tracked_data.deleted)
            || !hmapx_is_empty(&data->tracked_data.crupdated)) {
        data->tracked = true;
        engine_set_node_state(node, EN_UPDATED);
    }
    return true;
}

/* static functions. */
static void
lr_nat_table_init(struct lr_nat_table *table)
{
    *table = (struct lr_nat_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

static void
lr_nat_table_clear(struct lr_nat_table *table)
{
    struct lr_nat_record *lrnat_rec;
    HMAP_FOR_EACH_POP (lrnat_rec, key_node, &table->entries) {
        lr_nat_record_destroy(lrnat_rec);
    }
}

static void
lr_nat_table_build(struct lr_nat_table *table,
                   const struct nbrec_logical_router_table *nbr_table)
{
    const struct nbrec_logical_router *nbr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH (nbr, nbr_table) {
        lr_nat_record_create(table, nbr);
    }
}

static void
lr_nat_table_destroy(struct lr_nat_table *table)
{
    lr_nat_table_clear(table);
    hmap_destroy(&table->entries);
}

struct lr_nat_record *
lr_nat_table_find_(const struct lr_nat_table *table,
                  const struct nbrec_logical_router *nbr)
{
    struct lr_nat_record *lrnat_rec;

    HMAP_FOR_EACH_WITH_HASH (lrnat_rec, key_node,
                             uuid_hash(&nbr->header_.uuid), &table->entries) {
        if (nbr == lrnat_rec->nbr) {
            return lrnat_rec;
        }
    }
    return NULL;
}

static struct lr_nat_record *
lr_nat_record_create(struct lr_nat_table *table,
                     const struct nbrec_logical_router *nbr)
{
    struct lr_nat_record *lrnat_rec = xzalloc(sizeof *lrnat_rec);
    lrnat_rec->nbr = nbr;
    lr_nat_record_init(lrnat_rec);

    hmap_insert(&table->entries, &lrnat_rec->key_node,
                uuid_hash(&nbr->header_.uuid));

    return lrnat_rec;
}

static void
lr_nat_record_init(struct lr_nat_record *lrnat_rec)
{
    lr_nat_entries_init(lrnat_rec);
    lr_nat_external_ips_init(lrnat_rec);
}

static void
lr_nat_record_reinit(struct lr_nat_record *lrnat_rec)
{
    lr_nat_entries_destroy(lrnat_rec);
    lr_nat_external_ips_destroy(lrnat_rec);
    lr_nat_record_init(lrnat_rec);
}

static void
lr_nat_record_destroy(struct lr_nat_record *lrnat_rec)
{
    lr_nat_entries_destroy(lrnat_rec);
    lr_nat_external_ips_destroy(lrnat_rec);
    free(lrnat_rec);
}

static void
lr_nat_external_ips_init(struct lr_nat_record *lrnat_rec)
{
    sset_init(&lrnat_rec->external_ips);
    for (size_t i = 0; i < lrnat_rec->nbr->n_nat; i++) {
        sset_add(&lrnat_rec->external_ips,
                 lrnat_rec->nbr->nat[i]->external_ip);
    }
}

static void
lr_nat_external_ips_destroy(struct lr_nat_record *lrnat)
{
    sset_destroy(&lrnat->external_ips);
}

static void
snat_ip_add(struct lr_nat_record *lrnat_rec, const char *ip,
            struct ovn_nat *nat_entry)
{
    struct ovn_snat_ip *snat_ip = shash_find_data(&lrnat_rec->snat_ips, ip);

    if (!snat_ip) {
        snat_ip = xzalloc(sizeof *snat_ip);
        ovs_list_init(&snat_ip->snat_entries);
        shash_add(&lrnat_rec->snat_ips, ip, snat_ip);
    }

    if (nat_entry) {
        ovs_list_push_back(&snat_ip->snat_entries,
                           &nat_entry->ext_addr_list_node);
    }
}

static void
lr_nat_entries_init(struct lr_nat_record *lrnat)
{
    shash_init(&lrnat->snat_ips);
    sset_init(&lrnat->external_macs);

    if (get_force_snat_ip(lrnat, "dnat", &lrnat->dnat_force_snat_addrs)) {
        if (lrnat->dnat_force_snat_addrs.n_ipv4_addrs) {
            snat_ip_add(lrnat,
                        lrnat->dnat_force_snat_addrs.ipv4_addrs[0].addr_s,
                        NULL);
        }
        if (lrnat->dnat_force_snat_addrs.n_ipv6_addrs) {
            snat_ip_add(lrnat,
                        lrnat->dnat_force_snat_addrs.ipv6_addrs[0].addr_s,
                        NULL);
        }
    }

    /* Check if 'lb_force_snat_ip' is configured with 'router_ip'. */
    const char *lb_force_snat =
        smap_get(&lrnat->nbr->options, "lb_force_snat_ip");
    if (lb_force_snat && !strcmp(lb_force_snat, "router_ip")
            && smap_get(&lrnat->nbr->options, "chassis")) {
        /* Set it to true only if its gateway router and
         * options:lb_force_snat_ip=router_ip. */
        lrnat->lb_force_snat_router_ip = true;
    } else {
        lrnat->lb_force_snat_router_ip = false;

        /* Check if 'lb_force_snat_ip' is configured with a set of
         * IP address(es). */
        if (get_force_snat_ip(lrnat, "lb", &lrnat->lb_force_snat_addrs)) {
            if (lrnat->lb_force_snat_addrs.n_ipv4_addrs) {
                snat_ip_add(lrnat,
                            lrnat->lb_force_snat_addrs.ipv4_addrs[0].addr_s,
                            NULL);
            }
            if (lrnat->lb_force_snat_addrs.n_ipv6_addrs) {
                snat_ip_add(lrnat,
                            lrnat->lb_force_snat_addrs.ipv6_addrs[0].addr_s,
                            NULL);
            }
        }
    }

    if (!lrnat->nbr->n_nat) {
        return;
    }

    lrnat->nat_entries =
        xmalloc(lrnat->nbr->n_nat * sizeof *lrnat->nat_entries);

    for (size_t i = 0; i < lrnat->nbr->n_nat; i++) {
        const struct nbrec_nat *nat = lrnat->nbr->nat[i];
        struct ovn_nat *nat_entry = &lrnat->nat_entries[i];

        nat_entry->nb = nat;
        if (!extract_ip_addresses(nat->external_ip,
                                  &nat_entry->ext_addrs) ||
                !nat_entry_is_valid(nat_entry)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

            VLOG_WARN_RL(&rl,
                         "Bad ip address %s in nat configuration "
                         "for router %s", nat->external_ip, lrnat->nbr->name);
            continue;
        }

        /* If this is a SNAT rule add the IP to the set of unique SNAT IPs. */
        if (!strcmp(nat->type, "snat")) {
            if (!nat_entry_is_v6(nat_entry)) {
                snat_ip_add(lrnat, nat_entry->ext_addrs.ipv4_addrs[0].addr_s,
                            nat_entry);
            } else {
                snat_ip_add(lrnat, nat_entry->ext_addrs.ipv6_addrs[0].addr_s,
                            nat_entry);
            }
        } else {
            if (!strcmp(nat->type, "dnat_and_snat")
                    && nat->logical_port && nat->external_mac) {
                lrnat->has_distributed_nat = true;
            }

            if (nat->external_mac) {
                sset_add(&lrnat->external_macs, nat->external_mac);
            }
        }
    }
    lrnat->n_nat_entries = lrnat->nbr->n_nat;
}

static bool
get_force_snat_ip(struct lr_nat_record *lrnat, const char *key_type,
                  struct lport_addresses *laddrs)
{
    char *key = xasprintf("%s_force_snat_ip", key_type);
    const char *addresses = smap_get(&lrnat->nbr->options, key);
    free(key);

    if (!addresses) {
        return false;
    }

    if (!extract_ip_address(addresses, laddrs)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad ip %s in options of router "UUID_FMT"",
                     addresses, UUID_ARGS(&lrnat->nbr->header_.uuid));
        return false;
    }

    return true;
}

static void
lr_nat_entries_destroy(struct lr_nat_record *lrnat)
{
    shash_destroy_free_data(&lrnat->snat_ips);
    destroy_lport_addresses(&lrnat->dnat_force_snat_addrs);
    destroy_lport_addresses(&lrnat->lb_force_snat_addrs);

    for (size_t i = 0; i < lrnat->n_nat_entries; i++) {
        destroy_lport_addresses(&lrnat->nat_entries[i].ext_addrs);
    }

    free(lrnat->nat_entries);
    lrnat->nat_entries = NULL;
    lrnat->n_nat_entries = 0;
    sset_destroy(&lrnat->external_macs);
}

static struct lr_nat_input
lr_nat_get_input_data(struct engine_node *node)
{
    return (struct lr_nat_input) {
        .nbrec_logical_router_table =
            EN_OVSDB_GET(engine_get_input("NB_logical_router", node)),
    };
}

static bool
is_lr_nats_changed(const struct nbrec_logical_router *nbr) {
    return (nbrec_logical_router_is_new(nbr)
            || nbrec_logical_router_is_deleted(nbr)
            || nbrec_logical_router_is_updated(nbr,
                                               NBREC_LOGICAL_ROUTER_COL_NAT)
            || nbrec_logical_router_is_updated(
                nbr, NBREC_LOGICAL_ROUTER_COL_OPTIONS));
}
