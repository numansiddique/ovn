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

#include "en-runtime.h"
#include "openvswitch/hmap.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/list.h"
#include "northd.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_runtime);

void en_runtime_run(struct engine_node *node, void *data OVS_UNUSED)
{
    struct ed_type_runtime *runtime_data = data;

    struct ovs_list *lr_list = &runtime_data->lr_list;
    struct hmap *datapaths = &runtime_data->datapaths;
    struct hmap *ports = &runtime_data->ports;

    destroy_datapaths_and_ports(datapaths, ports, lr_list);

    ovs_list_init(lr_list);
    hmap_init(datapaths);
    hmap_init(ports);

    engine_set_node_state(node, EN_UPDATED);
}
void *en_runtime_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_runtime *data = xzalloc(sizeof *data);
    ovs_list_init(&data->lr_list);
    hmap_init(&data->datapaths);
    hmap_init(&data->ports);

    return data;
}

void en_runtime_cleanup(void *data)
{
    struct ed_type_runtime *runtime_data = data;

    struct ovs_list *lr_list = &runtime_data->lr_list;
    struct hmap *datapaths = &runtime_data->datapaths;
    struct hmap *ports = &runtime_data->ports;

    destroy_datapaths_and_ports(datapaths, ports, lr_list);
}
