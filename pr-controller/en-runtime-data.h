#ifndef EN_RUNTIME_DATA_H
#define EN_RUNTIME_DATA_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "lib/simap.h"
#include "lib/uuid.h"
#include "openvswitch/shash.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct prrec_pr_bridge;
struct ovsrec_bridge;

struct pr_bridge {
    struct uuid key; /* prrec_bridge->header_.uuid */

    const struct prrec_pr_bridge *db_br;
    const struct ovsrec_bridge *ovs_br;

    /* simap of ovs interface names to ofport numbers. */
    struct simap ovs_ifaces;

    int probe_interval;
    char *conn_target;
    unsigned int wait_before_clear_time;
};

struct ed_type_runtime_data {
    struct shash bridges;
};

enum engine_node_state en_runtime_data_run(struct engine_node *node, void *data);
void *en_runtime_data_init(struct engine_node *node, struct engine_arg *arg);
void en_runtime_data_cleanup(void *data);

#endif /* EN_RUNTIME_DATA_H */
