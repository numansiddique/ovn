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
#ifndef EN_LS_LB_ACL_H
#define EN_LS_LB_ACL_H 1

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
#include "lib/stopwatch-names.h"

struct ls_lbacls_record {
    struct hmap_node key_node;

    const struct ovn_datapath *od;
    bool has_stateful_acl;
    bool has_lb_vip;
    bool has_acls;
    uint64_t max_acl_tier;
};

struct ls_lbacls_table {
    struct hmap entries;
};

#define LS_LBACLS_TABLE_FOR_EACH(LS_LBACLS_REC, TABLE) \
    HMAP_FOR_EACH (LS_LBACLS_REC, key_node, &(TABLE)->entries)

#define LS_LBACLS_TABLE_FOR_EACH_IN_P(LS_LBACLS_REC, JOBID, TABLE) \
    HMAP_FOR_EACH_IN_PARALLEL (LS_LBACLS_REC, key_node, JOBID, \
                               &(TABLE)->entries)

struct ls_lbacls_tracked_data {
    /* Created or updated logical switch with LB and ACL data. */
    struct hmapx crupdated; /* Stores 'struct ls_lbacls_record'. */

    /* Deleted logical switch with LB and ACL data. */
    struct hmapx deleted; /* Stores 'struct ls_lbacls_record'. */
};

struct ed_type_ls_lbacls {
    struct ls_lbacls_table ls_lbacls;

    bool tracked;
    struct ls_lbacls_tracked_data tracked_data;
};

struct ls_lbacls_input {
    const struct nbrec_logical_switch_table *nbrec_logical_switch_table;
    const struct ls_port_group_table *ls_port_groups;
    const struct ovn_datapaths *ls_datapaths;
};

void *en_ls_lbacls_init(struct engine_node *, struct engine_arg *);
void en_ls_lbacls_cleanup(void *data);
void en_ls_lbacls_clear_tracked_data(void *data);
void en_ls_lbacls_run(struct engine_node *, void *data);

bool ls_lbacls_northd_handler(struct engine_node *, void *data);
bool ls_lbacls_port_group_handler(struct engine_node *, void *data);
bool ls_lbacls_logical_switch_handler(struct engine_node *, void *data);

const struct ls_lbacls_record *ls_lbacls_table_find(
    const struct ls_lbacls_table *, const struct nbrec_logical_switch *);

#endif /* EN_LS_LB_ACL_H */
