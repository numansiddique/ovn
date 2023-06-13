#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"
#include "include/openvswitch/list.h"

#include "lib/inc-proc-eng.h"

struct ovn_northd_lb;
struct ovn_lb_group;

struct tracked_lb {
    struct ovs_list list_node;
    struct ovn_northd_lb *lb;
    bool health_checks;
};

struct tracked_lb_group {
    struct ovs_list list_node;
    struct ovn_lb_group *lb_group;
};

struct tracked_lb_changes {
    struct ovs_list updated; /* contains list of 'struct tracked_lb ' or
                                list of 'struct tracked_lb_group' */
};

struct tracked_lb_data {
    struct tracked_lb_changes tracked_updated_lbs;
    struct tracked_lb_changes tracked_deleted_lbs;
    struct tracked_lb_changes tracked_updated_lb_groups;
    struct tracked_lb_changes tracked_deleted_lb_groups;
};

struct northd_lb_data {
    struct hmap lbs;
    struct hmap lb_groups;

    /* tracked data*/
    bool tracked;
    struct tracked_lb_data tracked_lb_data;
};

void *en_northd_lb_data_init(struct engine_node *, struct engine_arg *);
void en_northd_lb_data_run(struct engine_node *, void *data);
void en_northd_lb_data_cleanup(void *data);
void en_northd_lb_data_clear_tracked_data(void *data);

bool northd_lb_data_load_balancer_handler(struct engine_node *,
                                          void *data);
bool northd_lb_data_load_balancer_group_handler(struct engine_node *,
                                                void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
