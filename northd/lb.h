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

#ifndef OVN_NORTHD_LB_H
#define OVN_NORTHD_LB_H 1

#include "openvswitch/hmap.h"
#include "uuid.h"

struct ovn_lb_datapaths {
    struct hmap_node hmap_node;

    const struct ovn_northd_lb *lb;
    size_t n_nb_ls;
    unsigned long *nb_ls_map;

    size_t n_nb_lr;
    unsigned long *nb_lr_map;
};

struct ovn_lb_datapaths *ovn_lb_datapaths_create(const struct ovn_northd_lb *,
                                                 size_t n_ls_datapaths,
                                                 size_t n_lr_datapaths);
struct ovn_lb_datapaths *ovn_lb_datapaths_find(const struct hmap *,
                                               const struct uuid *);
void ovn_lb_datapaths_destroy(struct ovn_lb_datapaths *);

struct ovn_datapath;
void ovn_lb_datapaths_add_lr(struct ovn_lb_datapaths *, size_t n,
                             struct ovn_datapath **);
void ovn_lb_datapaths_add_ls(struct ovn_lb_datapaths *, size_t n,
                             struct ovn_datapath **);

struct ovn_lb_group_datapaths {
    struct hmap_node hmap_node;

    const struct ovn_lb_group *lb_group;

    /* Datapaths to which 'lb_group' is applied. */
    size_t n_ls;
    struct ovn_datapath **ls;
    size_t n_lr;
    struct ovn_datapath **lr;
};

struct ovn_lb_group_datapaths *ovn_lb_group_datapaths_create(
    const struct ovn_lb_group *, size_t max_ls_datapaths,
    size_t max_lr_datapaths);

void ovn_lb_group_datapaths_destroy(struct ovn_lb_group_datapaths *);
struct ovn_lb_group_datapaths *ovn_lb_group_datapaths_find(
    const struct hmap *lb_group_dps, const struct uuid *);

static inline void
ovn_lb_group_datapaths_add_ls(struct ovn_lb_group_datapaths *lbg_dps, size_t n,
                               struct ovn_datapath **ods)
{
    memcpy(&lbg_dps->ls[lbg_dps->n_ls], ods, n * sizeof *ods);
    lbg_dps->n_ls += n;
}

static inline void
ovn_lb_group_datapaths_add_lr(struct ovn_lb_group_datapaths *lbg_dps,
                               struct ovn_datapath *lr)
{
    lbg_dps->lr[lbg_dps->n_lr++] = lr;
}

#endif /* OVN_NORTHD_LB_H */