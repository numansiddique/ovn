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

#include "openvswitch/util.h"

#include "en-northd-lb-data.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "northd.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_northd_lb_data);

static void northd_lb_data_init(struct northd_lb_data *);
static void northd_lb_data_destroy(struct northd_lb_data *);
static void build_lbs(const struct nbrec_load_balancer_table *,
                      const struct nbrec_load_balancer_group_table *,
                      struct hmap *lbs, struct hmap *lb_groups);
static struct ovn_lb_group *create_lb_group(
    const struct nbrec_load_balancer_group *, struct hmap *lbs,
    struct hmap *lb_groups);
static void destroy_tracked_data(struct northd_lb_data *);
static void add_lb_to_tracked_data(struct ovn_northd_lb *,
                                   struct ovs_list *tracked_list,
                                   bool health_checks);
static void add_lb_group_to_tracked_data(struct ovn_lb_group *,
                                         struct ovs_list *tracked_list);

void *
en_northd_lb_data_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED)
{
    struct northd_lb_data *data = xzalloc(sizeof *data);

    northd_lb_data_init(data);

    return data;
}

void
en_northd_lb_data_run(struct engine_node *node, void *data)
{
    struct northd_lb_data *lb_data = (struct northd_lb_data *) data;
    northd_lb_data_destroy(lb_data);
    northd_lb_data_init(lb_data);

    const struct nbrec_load_balancer_table *nb_lb_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));
    const struct nbrec_load_balancer_group_table *nb_lbg_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer_group", node));

    lb_data->tracked = false;
    build_lbs(nb_lb_table, nb_lbg_table, &lb_data->lbs, &lb_data->lb_groups);
    engine_set_node_state(node, EN_UPDATED);
}

void
en_northd_lb_data_cleanup(void *data)
{
    struct northd_lb_data *lb_data = (struct northd_lb_data *) data;
    northd_lb_data_destroy(lb_data);
}

void
en_northd_lb_data_clear_tracked_data(void *data)
{
    struct northd_lb_data *lb_data = (struct northd_lb_data *) data;
    destroy_tracked_data(lb_data);
}


/* Handler functions. */
bool
northd_lb_data_load_balancer_handler(struct engine_node *node,
                                     void *data OVS_UNUSED)
{
    const struct nbrec_load_balancer_table *nb_lb_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));

    struct northd_lb_data *lb_data = (struct northd_lb_data *) data;

    lb_data->tracked = true;
    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;

    const struct nbrec_load_balancer *tracked_lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH_TRACKED (tracked_lb, nb_lb_table) {
        struct ovn_northd_lb *lb;
        if (nbrec_load_balancer_is_new(tracked_lb)) {
            /* New load balancer. */
            lb = ovn_northd_lb_create(tracked_lb);
            hmap_insert(&lb_data->lbs, &lb->hmap_node,
                        uuid_hash(&tracked_lb->header_.uuid));
            add_lb_to_tracked_data(
                lb, &trk_lb_data->tracked_updated_lbs.updated,
                lb->health_checks);
        } else if (nbrec_load_balancer_is_deleted(tracked_lb)) {
            lb = ovn_northd_lb_find(&lb_data->lbs,
                                    &tracked_lb->header_.uuid);
            ovs_assert(lb);
            hmap_remove(&lb_data->lbs, &lb->hmap_node);
            add_lb_to_tracked_data(
                lb, &trk_lb_data->tracked_deleted_lbs.updated,
                lb->health_checks);
        } else {
            /* Load balancer updated. */
            lb = ovn_northd_lb_find(&lb_data->lbs,
                                    &tracked_lb->header_.uuid);
            ovs_assert(lb);
            bool health_checks = lb->health_checks;
            ovn_northd_lb_reinit(lb, tracked_lb);
            health_checks |= lb->health_checks;
            add_lb_to_tracked_data(
                lb, &trk_lb_data->tracked_updated_lbs.updated, health_checks);
        }
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

bool
northd_lb_data_load_balancer_group_handler(struct engine_node *node,
                                           void *data OVS_UNUSED)
{
    struct northd_lb_data *lb_data = (struct northd_lb_data *) data;
    const struct nbrec_load_balancer_group_table *nb_lbg_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer_group", node));

    lb_data->tracked = true;
    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    const struct nbrec_load_balancer_group *tracked_lb_group;
    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH_TRACKED (tracked_lb_group,
                                                      nb_lbg_table) {
        if (nbrec_load_balancer_group_is_new(tracked_lb_group)) {
            struct ovn_lb_group *lb_group =
                create_lb_group(tracked_lb_group, &lb_data->lbs,
                                &lb_data->lb_groups);
            add_lb_group_to_tracked_data(
                lb_group, &trk_lb_data->tracked_updated_lb_groups.updated);
        } else if (nbrec_load_balancer_group_is_deleted(tracked_lb_group)) {
            struct ovn_lb_group *lb_group;
            lb_group = ovn_lb_group_find(&lb_data->lb_groups,
                                         &tracked_lb_group->header_.uuid);
            ovs_assert(lb_group);
            hmap_remove(&lb_data->lb_groups, &lb_group->hmap_node);
            add_lb_group_to_tracked_data(
                lb_group, &trk_lb_data->tracked_deleted_lb_groups.updated);
        } else if (nbrec_load_balancer_group_is_updated(tracked_lb_group,
                                NBREC_LOAD_BALANCER_GROUP_COL_LOAD_BALANCER)) {

            struct ovn_lb_group *lb_group;
            lb_group = ovn_lb_group_find(&lb_data->lb_groups,
                                         &tracked_lb_group->header_.uuid);
            ovs_assert(lb_group);
            ovn_lb_group_reinit(lb_group, tracked_lb_group, &lb_data->lbs);
            for (size_t i = 0; i < lb_group->n_lbs; i++) {
                build_lrouter_lb_ips(lb_group->lb_ips, lb_group->lbs[i]);
            }
            add_lb_group_to_tracked_data(
                lb_group, &trk_lb_data->tracked_updated_lb_groups.updated);
        }
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

/* static functions. */
static void
northd_lb_data_init(struct northd_lb_data *lb_data)
{
    hmap_init(&lb_data->lbs);
    hmap_init(&lb_data->lb_groups);

    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    ovs_list_init(&trk_lb_data->tracked_updated_lbs.updated);
    ovs_list_init(&trk_lb_data->tracked_deleted_lbs.updated);
    ovs_list_init(&trk_lb_data->tracked_updated_lb_groups.updated);
    ovs_list_init(&trk_lb_data->tracked_deleted_lb_groups.updated);
}

static void
northd_lb_data_destroy(struct northd_lb_data *lb_data)
{
    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH_POP (lb, hmap_node, &lb_data->lbs) {
        ovn_northd_lb_destroy(lb);
    }
    hmap_destroy(&lb_data->lbs);

    struct ovn_lb_group *lb_group;
    HMAP_FOR_EACH_POP (lb_group, hmap_node, &lb_data->lb_groups) {
        ovn_lb_group_destroy(lb_group);
    }
    hmap_destroy(&lb_data->lb_groups);

    destroy_tracked_data(lb_data);
}

static void
build_lbs(const struct nbrec_load_balancer_table *nbrec_load_balancer_table,
          const struct nbrec_load_balancer_group_table *nbrec_lb_group_table,
          struct hmap *lbs, struct hmap *lb_groups)
{
    const struct nbrec_load_balancer *nbrec_lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH (nbrec_lb, nbrec_load_balancer_table) {
        struct ovn_northd_lb *lb_nb = ovn_northd_lb_create(nbrec_lb);
        hmap_insert(lbs, &lb_nb->hmap_node,
                    uuid_hash(&nbrec_lb->header_.uuid));
    }

    const struct nbrec_load_balancer_group *nbrec_lb_group;
    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH (nbrec_lb_group,
                                              nbrec_lb_group_table) {
        create_lb_group(nbrec_lb_group, lbs, lb_groups);
    }
}

static struct ovn_lb_group *
create_lb_group(const struct nbrec_load_balancer_group *nbrec_lb_group,
                struct hmap *lbs, struct hmap *lb_groups)
{
    struct ovn_lb_group *lb_group = ovn_lb_group_create(nbrec_lb_group, lbs);

    for (size_t i = 0; i < lb_group->n_lbs; i++) {
        build_lrouter_lb_ips(lb_group->lb_ips, lb_group->lbs[i]);
    }

    hmap_insert(lb_groups, &lb_group->hmap_node,
                uuid_hash(&lb_group->uuid));

    return lb_group;
}

static void
destroy_tracked_data(struct northd_lb_data *lb_data)
{
    lb_data->tracked = false;

    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    struct tracked_lb *tracked_lb;
    LIST_FOR_EACH_SAFE (tracked_lb, list_node,
                        &trk_lb_data->tracked_updated_lbs.updated) {
        ovs_list_remove(&tracked_lb->list_node);
        free(tracked_lb);
    }

    LIST_FOR_EACH_SAFE (tracked_lb, list_node,
                        &trk_lb_data->tracked_deleted_lbs.updated) {
        ovs_list_remove(&tracked_lb->list_node);
        ovn_northd_lb_destroy(tracked_lb->lb);
        free(tracked_lb);
    }

    struct tracked_lb_group *tracked_lb_group;
    LIST_FOR_EACH_SAFE (tracked_lb_group, list_node,
                        &trk_lb_data->tracked_updated_lb_groups.updated) {
        ovs_list_remove(&tracked_lb_group->list_node);
        free(tracked_lb_group);
    }

    LIST_FOR_EACH_SAFE (tracked_lb_group, list_node,
                        &trk_lb_data->tracked_deleted_lb_groups.updated) {
        ovs_list_remove(&tracked_lb_group->list_node);
        ovn_lb_group_destroy(tracked_lb_group->lb_group);
        free(tracked_lb_group);
    }
}

static void
add_lb_to_tracked_data(struct ovn_northd_lb *lb, struct ovs_list *tracked_list,
                       bool health_checks)
{
    struct tracked_lb *t_lb = xzalloc(sizeof *t_lb);
    t_lb->lb = lb;
    t_lb->health_checks = health_checks;
    ovs_list_push_back(tracked_list, &t_lb->list_node);
}

static void
add_lb_group_to_tracked_data(struct ovn_lb_group *lb_group,
                             struct ovs_list *tracked_list)
{
    struct tracked_lb_group *t_lb_group = xzalloc(sizeof *t_lb_group);
    t_lb_group->lb_group = lb_group;
    ovs_list_push_back(tracked_list, &t_lb_group->list_node);
}
