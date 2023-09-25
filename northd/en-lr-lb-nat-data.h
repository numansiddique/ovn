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
#ifndef EN_LR_LB_NAT_DATA_H
#define EN_LR_LB_NAT_DATA_H 1

#include <stdint.h>

/* OVS includes. */
#include "lib/hmapx.h"
#include "openvswitch/hmap.h"
#include "sset.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

struct ovn_datapath;
struct lr_nat_record;

struct lr_lb_nat_data_record {
    struct hmap_node key_node; /* Index on 'nbr->header_.uuid'. */

    const struct ovn_datapath *od;
    const struct lr_nat_record *lrnat_rec;

    /* Load Balancer vIPs relevant for this datapath. */
    struct ovn_lb_ip_set *lb_ips;

    /* sset of vips which are also part of lr nats. */
    struct sset vip_nats;
};

struct lr_lb_nat_data_table {
    struct hmap entries;

    /* The array index of each element in 'entries'. */
    struct lr_lb_nat_data_record **array;
};

#define LR_LB_NAT_DATA_TABLE_FOR_EACH(LR_LB_NAT_REC, TABLE) \
    HMAP_FOR_EACH (LR_LB_NAT_REC, key_node, &(TABLE)->entries)

struct lr_lb_nat_data_tracked_data {
    /* Created or updated logical router with LB data. */
    struct hmapx crupdated; /* Stores 'struct lr_lb_nat_data_record'. */

    /* Deleted logical router with LB data. */
    struct hmapx deleted; /* Stores 'struct lr_lb_nat_data_record'. */
};

struct ed_type_lr_lb_nat_data {
    struct lr_lb_nat_data_table lr_lbnats;

    bool tracked;
    struct lr_lb_nat_data_tracked_data tracked_data;
};

struct lr_lb_nat_data_input {
    const struct ovn_datapaths *lr_datapaths;
    const struct hmap *lb_datapaths_map;
    const struct hmap *lbgrp_datapaths_map;
    const struct lr_nat_table *lr_nats;
};

void *en_lr_lb_nat_data_init(struct engine_node *, struct engine_arg *);
void en_lr_lb_nat_data_cleanup(void *data);
void en_lr_lb_nat_data_clear_tracked_data(void *data);
void en_lr_lb_nat_data_run(struct engine_node *, void *data);

bool lr_lb_nat_data_northd_handler(struct engine_node *, void *data);
bool lr_lb_nat_data_lr_nat_handler(struct engine_node *, void *data);
bool lr_lb_nat_data_lb_data_handler(struct engine_node *, void *data);

const struct lr_lb_nat_data_record *lr_lb_nat_data_table_find_by_index(
    const struct lr_lb_nat_data_table *, size_t od_index);

#endif /* EN_LR_LB_NAT_DATA_H */