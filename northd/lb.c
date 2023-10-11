/*
 * Copyright (c) 2024, Red Hat, Inc.
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
#include "lib/bitmap.h"

/* OVN includes */
#include "lb.h"
#include "lib/lb.h"
#include "northd.h"

/* lb datapaths functions */
struct  ovn_lb_datapaths *
ovn_lb_datapaths_create(const struct ovn_northd_lb *lb, size_t n_ls_datapaths,
                        size_t n_lr_datapaths)
{
    struct ovn_lb_datapaths *lb_dps = xzalloc(sizeof *lb_dps);
    lb_dps->lb = lb;
    lb_dps->nb_ls_map = bitmap_allocate(n_ls_datapaths);
    lb_dps->nb_lr_map = bitmap_allocate(n_lr_datapaths);

    return lb_dps;
}

void
ovn_lb_datapaths_destroy(struct ovn_lb_datapaths *lb_dps)
{
    bitmap_free(lb_dps->nb_lr_map);
    bitmap_free(lb_dps->nb_ls_map);
    free(lb_dps);
}

void
ovn_lb_datapaths_add_lr(struct ovn_lb_datapaths *lb_dps, size_t n,
                        struct ovn_datapath **ods)
{
    for (size_t i = 0; i < n; i++) {
        if (!bitmap_is_set(lb_dps->nb_lr_map, ods[i]->index)) {
            bitmap_set1(lb_dps->nb_lr_map, ods[i]->index);
            lb_dps->n_nb_lr++;
        }
    }
}

void
ovn_lb_datapaths_add_ls(struct ovn_lb_datapaths *lb_dps, size_t n,
                        struct ovn_datapath **ods)
{
    for (size_t i = 0; i < n; i++) {
        if (!bitmap_is_set(lb_dps->nb_ls_map, ods[i]->index)) {
            bitmap_set1(lb_dps->nb_ls_map, ods[i]->index);
            lb_dps->n_nb_ls++;
        }
    }
}

struct ovn_lb_datapaths *
ovn_lb_datapaths_find(const struct hmap *lb_dps_map,
                      const struct uuid *lb_uuid)
{
    struct ovn_lb_datapaths *lb_dps;
    size_t hash = uuid_hash(lb_uuid);
    HMAP_FOR_EACH_WITH_HASH (lb_dps, hmap_node, hash, lb_dps_map) {
        if (uuid_equals(&lb_dps->lb->nlb->header_.uuid, lb_uuid)) {
            return lb_dps;
        }
    }
    return NULL;
}

struct ovn_lb_group_datapaths *
ovn_lb_group_datapaths_create(const struct ovn_lb_group *lb_group,
                              size_t max_ls_datapaths,
                              size_t max_lr_datapaths)
{
    struct ovn_lb_group_datapaths *lb_group_dps =
        xzalloc(sizeof *lb_group_dps);
    lb_group_dps->lb_group = lb_group;
    lb_group_dps->ls = xmalloc(max_ls_datapaths * sizeof *lb_group_dps->ls);
    lb_group_dps->lr = xmalloc(max_lr_datapaths * sizeof *lb_group_dps->lr);

    return lb_group_dps;
}

void
ovn_lb_group_datapaths_destroy(struct ovn_lb_group_datapaths *lb_group_dps)
{
    free(lb_group_dps->ls);
    free(lb_group_dps->lr);
    free(lb_group_dps);
}

struct ovn_lb_group_datapaths *
ovn_lb_group_datapaths_find(const struct hmap *lb_group_dps_map,
                            const struct uuid *lb_group_uuid)
{
    struct ovn_lb_group_datapaths *lb_group_dps;
    size_t hash = uuid_hash(lb_group_uuid);

    HMAP_FOR_EACH_WITH_HASH (lb_group_dps, hmap_node, hash, lb_group_dps_map) {
        if (uuid_equals(&lb_group_dps->lb_group->uuid, lb_group_uuid)) {
            return lb_group_dps;
        }
    }
    return NULL;
}
