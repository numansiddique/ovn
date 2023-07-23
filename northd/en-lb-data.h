#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"
#include "include/openvswitch/list.h"
#include "lib/hmapx.h"
#include "lib/uuidset.h"

#include "lib/inc-proc-eng.h"

struct ovn_northd_lb;
struct ovn_lb_group;

struct crupdated_lb_group {
    struct ovn_lb_group *lbg;

    /* hmapx of newly associated lbs to this lb group.
     * hmapx node is 'struct ovn_northd_lb *' */
    struct hmapx assoc_lbs;
};

struct crupdated_od_lb_data {
    struct ovs_list list_node;

    struct uuid od_uuid;
    struct uuidset assoc_lbs;
    struct uuidset assoc_lbgrps;
};

struct tracked_lb_data {
    /* Both created and updated lbs. hmapx node is 'struct ovn_northd_lb *'. */
    struct hmapx crupdated_lbs;
    struct hmapx deleted_lbs;

    /* Both created and updated lb_groups. hmapx node is
     * 'struct crupdated_lb_group'. */
    struct hmapx crupdated_lb_groups;

    /* Deleted lb_groups. hmapx node is  'struct ovn_lb_group *'. */
    struct hmapx deleted_lb_groups;

    /* List of logical switch <-> lb changes. List node is
     * 'struct crupdated_od_lb_data' */
    struct ovs_list crupdated_ls_lbs;

    /* List of logical router <-> lb changes. List node is
     * 'struct crupdated_od_lb_data' */
    struct ovs_list crupdated_lr_lbs;

    /* Indicates if any of the tracked lb has health checks enabled. */
    bool has_health_checks;

    /* Indicates if any lb got disassociated from a lb group
     * but not deleted. */
    bool has_dissassoc_lbs_from_lb_grops;

    /* Indicates if a lb was disassociated from a logical switch. */
    bool has_dissassoc_lbs_from_od;

    /* Indicates if a lb group was disassociated from a logical switch. */
    bool has_dissassoc_lbgrps_from_od;

    /* Indicates if any lb (in the tracked data) has 'routable' flag set. */
    bool has_routable_lb;
};

/* struct which maintains the data of the engine node lb_data. */
struct ed_type_lb_data {
    /* hmap of load balancers.  hmap node is 'struct ovn_northd_lb *' */
    struct hmap lbs;

    /* hmap of load balancer groups.  hmap node is 'struct ovn_lb_group *' */
    struct hmap lb_groups;
    struct hmap ls_lb_map;
    struct hmap lr_lb_map;

    /* tracked data*/
    bool tracked;
    struct tracked_lb_data tracked_lb_data;
};

void *en_lb_data_init(struct engine_node *, struct engine_arg *);
void en_lb_data_run(struct engine_node *, void *data);
void en_lb_data_cleanup(void *data);
void en_lb_data_clear_tracked_data(void *data);

bool lb_data_load_balancer_handler(struct engine_node *, void *data);
bool lb_data_load_balancer_group_handler(struct engine_node *, void *data);
bool lb_data_logical_switch_handler(struct engine_node *, void *data);
bool lb_data_logical_router_handler(struct engine_node *, void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
