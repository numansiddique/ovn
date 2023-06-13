#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"

#include "lib/inc-proc-eng.h"

struct northd_lb_data {
    struct hmap lbs;
    struct hmap lb_groups;
};

void *en_northd_lb_data_init(struct engine_node *, struct engine_arg *);
void en_northd_lb_data_run(struct engine_node *, void *data);
void en_northd_lb_data_cleanup(void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
