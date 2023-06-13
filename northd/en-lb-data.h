#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"
#include "include/openvswitch/list.h"
#include "lib/hmapx.h"

#include "lib/inc-proc-eng.h"

struct ovn_northd_lb;
struct ovn_lb_group;

struct tracked_lb_data {
    /* Both created and updated lbs. hmapx node is 'struct ovn_northd_lb *'. */
    struct hmapx crupdated_lbs;
    struct hmapx deleted_lbs;

    /* Both created and updated lb_groups. hmapx node is
     * 'struct ovn_lb_group *'. */
    struct hmapx crupdated_lb_groups;
    struct hmapx deleted_lb_groups;

    bool has_health_checks;
};

struct lb_data {
    struct hmap lbs;
    struct hmap lb_groups;

    /* tracked data*/
    bool tracked;
    struct tracked_lb_data tracked_lb_data;
};

void *en_lb_data_init(struct engine_node *, struct engine_arg *);
void en_lb_data_run(struct engine_node *, void *data);
void en_lb_data_cleanup(void *data);
void en_lb_data_clear_tracked_data(void *data);

bool lb_data_load_balancer_handler(struct engine_node *,
                                          void *data);
bool lb_data_load_balancer_group_handler(struct engine_node *,
                                                void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
