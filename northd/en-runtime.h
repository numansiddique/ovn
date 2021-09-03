#ifndef EN_RUNTIME_H
#define EN_RUNTIME_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "openvswitch/hmap.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/list.h"

struct ed_type_runtime {
    struct ovs_list lr_list;
    struct hmap datapaths;
    struct hmap ports;
};

void en_runtime_run(struct engine_node *node, void *data);
void *en_runtime_init(struct engine_node *node,
                      struct engine_arg *arg);
void en_runtime_cleanup(void *data);

#endif /* EN_RUNTIME_H */
