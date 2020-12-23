/* Copyright (c) 2021 Red Hat, Inc.
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


#ifndef OVN_DATAPATH_H
#define OVN_DATAPATH_H 1

#include <stdio.h>

/* ovn includes. */

/* ovs includes. */
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

struct match;
struct ofpbuf;
struct uuid;

#define DP_FLOW_TABLE_GLOBAL_KEY 0

void dp_flow_tables_init(void);
void dp_flow_tables_destroy(void);

struct dp_flow_table *dp_flow_table_alloc(uint32_t dp_key);
struct dp_flow_table * dp_flow_table_get(uint32_t dp_key);
void dp_flow_table_destroy(uint32_t dp_key);

void dp_flow_switch_logical_oflow_tables(void);
void dp_flow_switch_logical_oflow_table(uint32_t dp_key);
void dp_flow_switch_physical_oflow_tables(void);
void dp_flow_switch_physical_oflow_table(uint32_t dp_key);

void dp_flow_add_logical_oflow(uint32_t dp_key, uint8_t table_id,
                               uint16_t priority, uint64_t cookie,
                               const struct match *match,
                               const struct ofpbuf *actions,
                               const struct uuid *flow_uuid);
void dp_flow_add_physical_oflow(uint32_t dp_key, uint8_t table_id,
                                uint16_t priority, uint64_t cookie,
                                const struct match *match,
                                const struct ofpbuf *actions,
                                const struct uuid *flow_uuid);
void dp_flow_remove_logical_oflows_all(const struct uuid *flow_uuid);
void dp_flow_remove_logical_oflows(uint32_t dp_key,
                                   const struct uuid *flow_uuid);
void dp_flow_remove_physical_oflows(uint32_t dp_key,
                                    const struct uuid *flow_uuid);
void dp_flow_flush_all_oflows(void);

void dp_flow_populate_oflow_msgs(struct ovs_list *msgs);
#endif /* OVN_DATAPATH_H */
