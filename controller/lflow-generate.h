/*
 * Copyright (c) 2021 Red Hat, Inc.
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

#ifndef OVN_LFLOW_GENERATE_H
#define OVN_LFLOW_GENERATE_H 1

struct hmap;
struct sbrec_port_binding_table;
struct sbrec_datapath_binding_table;
struct sbrec_port_binding;

void lflow_generate_run(struct hmap *local_datapaths, struct hmap *local_lbs);
void lflow_generate_datapath_flows(struct local_datapath *ldp,
                                   bool build_lport_flows);
void lflow_generate_lport_flows(const struct sbrec_port_binding *pb,
                                struct local_datapath *ldp);

void lflow_delete_generated_lport_lflows(const struct sbrec_port_binding *,
                                         struct local_datapath *);

void lflow_delete_generated_lflows(struct hmap *local_datapaths,
                                   struct hmap *local_lbs);

bool lflow_datapath_needs_generation(struct local_datapath *ldp);
bool lflow_lport_needs_generation(struct local_datapath *ldp,
                                  const struct sbrec_port_binding *);

void lflow_delete_generated_lport_lflows(const struct sbrec_port_binding *,
                                         struct local_datapath *);

void lflow_generate_load_balancer_lflows(struct local_load_balancer *local_lb);
bool lflow_load_balancer_needs_gen(struct local_load_balancer *local_lb);
void lflow_clear_generated_lb_lflows(struct local_load_balancer *local_lb);


#endif /* controller/lflow-generate.h */
