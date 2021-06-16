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

#ifndef OVN_LIB_LFLOW_H
#define OVN_LIB_LFLOW_H 1

#include "lib/util.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"

struct sbrec_datapath_binding;
struct sbrec_port_binding;
struct hmap;
struct ofpbuf;
struct local_lport;

/* Pipeline stages. */

/* The two pipelines in an OVN logical flow table. */
enum ovn_pipeline {
    P_IN,                       /* Ingress pipeline. */
    P_OUT                       /* Egress pipeline. */
};

/* The two purposes for which ovn-northd uses OVN logical datapaths. */
enum ovn_datapath_type {
    DP_SWITCH,                  /* OVN logical switch. */
    DP_ROUTER                   /* OVN logical router. */
};

/* Returns an "enum ovn_stage" built from the arguments.
 *
 * (It's better to use ovn_stage_build() for type-safety reasons, but inline
 * functions can't be used in enums or switch cases.) */
#define OVN_STAGE_BUILD(DP_TYPE, PIPELINE, TABLE) \
    (((DP_TYPE) << 9) | ((PIPELINE) << 8) | (TABLE))

/* A stage within an OVN logical switch or router.
 *
 * An "enum ovn_stage" indicates whether the stage is part of a logical switch
 * or router, whether the stage is part of the ingress or egress pipeline, and
 * the table within that pipeline.  The first three components are combined to
 * form the stage's full name, e.g. S_SWITCH_IN_PORT_SEC_L2,
 * S_ROUTER_OUT_DELIVERY. */
enum ovn_stage {
#define PIPELINE_STAGES                                                   \
    /* Logical switch ingress stages. */                                  \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_L2,    0, "ls_in_port_sec_l2")   \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_IP,    1, "ls_in_port_sec_ip")   \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_ND,    2, "ls_in_port_sec_nd")   \
    PIPELINE_STAGE(SWITCH, IN,  LOOKUP_FDB ,    3, "ls_in_lookup_fdb")    \
    PIPELINE_STAGE(SWITCH, IN,  PUT_FDB,        4, "ls_in_put_fdb")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_ACL,        5, "ls_in_pre_acl")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_LB,         6, "ls_in_pre_lb")        \
    PIPELINE_STAGE(SWITCH, IN,  PRE_STATEFUL,   7, "ls_in_pre_stateful")  \
    PIPELINE_STAGE(SWITCH, IN,  ACL_HINT,       8, "ls_in_acl_hint")      \
    PIPELINE_STAGE(SWITCH, IN,  ACL,            9, "ls_in_acl")           \
    PIPELINE_STAGE(SWITCH, IN,  QOS_MARK,      10, "ls_in_qos_mark")      \
    PIPELINE_STAGE(SWITCH, IN,  QOS_METER,     11, "ls_in_qos_meter")     \
    PIPELINE_STAGE(SWITCH, IN,  STATEFUL,      12, "ls_in_stateful")      \
    PIPELINE_STAGE(SWITCH, IN,  PRE_HAIRPIN,   13, "ls_in_pre_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  NAT_HAIRPIN,   14, "ls_in_nat_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  HAIRPIN,       15, "ls_in_hairpin")       \
    PIPELINE_STAGE(SWITCH, IN,  ARP_ND_RSP,    16, "ls_in_arp_rsp")       \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_OPTIONS,  17, "ls_in_dhcp_options")  \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_RESPONSE, 18, "ls_in_dhcp_response") \
    PIPELINE_STAGE(SWITCH, IN,  DNS_LOOKUP,    19, "ls_in_dns_lookup")    \
    PIPELINE_STAGE(SWITCH, IN,  DNS_RESPONSE,  20, "ls_in_dns_response")  \
    PIPELINE_STAGE(SWITCH, IN,  EXTERNAL_PORT, 21, "ls_in_external_port") \
    PIPELINE_STAGE(SWITCH, IN,  L2_LKUP,       22, "ls_in_l2_lkup")       \
    PIPELINE_STAGE(SWITCH, IN,  L2_UNKNOWN,    23, "ls_in_l2_unknown")    \
                                                                          \
    /* Logical switch egress stages. */                                   \
    PIPELINE_STAGE(SWITCH, OUT, PRE_LB,       0, "ls_out_pre_lb")         \
    PIPELINE_STAGE(SWITCH, OUT, PRE_ACL,      1, "ls_out_pre_acl")        \
    PIPELINE_STAGE(SWITCH, OUT, PRE_STATEFUL, 2, "ls_out_pre_stateful")   \
    PIPELINE_STAGE(SWITCH, OUT, ACL_HINT,     3, "ls_out_acl_hint")       \
    PIPELINE_STAGE(SWITCH, OUT, ACL,          4, "ls_out_acl")            \
    PIPELINE_STAGE(SWITCH, OUT, QOS_MARK,     5, "ls_out_qos_mark")       \
    PIPELINE_STAGE(SWITCH, OUT, QOS_METER,    6, "ls_out_qos_meter")      \
    PIPELINE_STAGE(SWITCH, OUT, STATEFUL,     7, "ls_out_stateful")       \
    PIPELINE_STAGE(SWITCH, OUT, PORT_SEC_IP,  8, "ls_out_port_sec_ip")    \
    PIPELINE_STAGE(SWITCH, OUT, PORT_SEC_L2,  9, "ls_out_port_sec_l2")    \
                                                                      \
    /* Logical router ingress stages. */                              \
    PIPELINE_STAGE(ROUTER, IN,  ADMISSION,       0, "lr_in_admission")    \
    PIPELINE_STAGE(ROUTER, IN,  LOOKUP_NEIGHBOR, 1, "lr_in_lookup_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  LEARN_NEIGHBOR,  2, "lr_in_learn_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  IP_INPUT,        3, "lr_in_ip_input")     \
    PIPELINE_STAGE(ROUTER, IN,  UNSNAT,          4, "lr_in_unsnat")       \
    PIPELINE_STAGE(ROUTER, IN,  DEFRAG,          5, "lr_in_defrag")       \
    PIPELINE_STAGE(ROUTER, IN,  DNAT,            6, "lr_in_dnat")         \
    PIPELINE_STAGE(ROUTER, IN,  ECMP_STATEFUL,   7, "lr_in_ecmp_stateful") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_OPTIONS,   8, "lr_in_nd_ra_options") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_RESPONSE,  9, "lr_in_nd_ra_response") \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING,      10, "lr_in_ip_routing")   \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING_ECMP, 11, "lr_in_ip_routing_ecmp") \
    PIPELINE_STAGE(ROUTER, IN,  POLICY,          12, "lr_in_policy")       \
    PIPELINE_STAGE(ROUTER, IN,  POLICY_ECMP,     13, "lr_in_policy_ecmp")  \
    PIPELINE_STAGE(ROUTER, IN,  ARP_RESOLVE,     14, "lr_in_arp_resolve")  \
    PIPELINE_STAGE(ROUTER, IN,  CHK_PKT_LEN   ,  15, "lr_in_chk_pkt_len")  \
    PIPELINE_STAGE(ROUTER, IN,  LARGER_PKTS,     16, "lr_in_larger_pkts")  \
    PIPELINE_STAGE(ROUTER, IN,  GW_REDIRECT,     17, "lr_in_gw_redirect")  \
    PIPELINE_STAGE(ROUTER, IN,  ARP_REQUEST,     18, "lr_in_arp_request")  \
                                                                      \
    /* Logical router egress stages. */                               \
    PIPELINE_STAGE(ROUTER, OUT, UNDNAT,    0, "lr_out_undnat")        \
    PIPELINE_STAGE(ROUTER, OUT, SNAT,      1, "lr_out_snat")          \
    PIPELINE_STAGE(ROUTER, OUT, EGR_LOOP,  2, "lr_out_egr_loop")      \
    PIPELINE_STAGE(ROUTER, OUT, DELIVERY,  3, "lr_out_delivery")

#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)   \
    S_##DP_TYPE##_##PIPELINE##_##STAGE                          \
        = OVN_STAGE_BUILD(DP_##DP_TYPE, P_##PIPELINE, TABLE),
    PIPELINE_STAGES
#undef PIPELINE_STAGE
};


/* Due to various hard-coded priorities need to implement ACLs, the
 * northbound database supports a smaller range of ACL priorities than
 * are available to logical flows.  This value is added to an ACL
 * priority to determine the ACL's logical flow priority. */
#define OVN_ACL_PRI_OFFSET 1000

/* Register definitions specific to switches. */
#define REGBIT_CONNTRACK_DEFRAG   "reg0[0]"
#define REGBIT_CONNTRACK_COMMIT   "reg0[1]"
#define REGBIT_CONNTRACK_NAT      "reg0[2]"
#define REGBIT_DHCP_OPTS_RESULT   "reg0[3]"
#define REGBIT_DNS_LOOKUP_RESULT  "reg0[4]"
#define REGBIT_ND_RA_OPTS_RESULT  "reg0[5]"
#define REGBIT_HAIRPIN            "reg0[6]"
#define REGBIT_ACL_HINT_ALLOW_NEW "reg0[7]"
#define REGBIT_ACL_HINT_ALLOW     "reg0[8]"
#define REGBIT_ACL_HINT_DROP      "reg0[9]"
#define REGBIT_ACL_HINT_BLOCK     "reg0[10]"
#define REGBIT_LKUP_FDB           "reg0[11]"
#define REGBIT_HAIRPIN_REPLY      "reg0[12]"

#define REG_ORIG_DIP_IPV4         "reg1"
#define REG_ORIG_DIP_IPV6         "xxreg1"
#define REG_ORIG_TP_DPORT         "reg2[0..15]"

/* Register definitions for switches and routers. */

/* Indicate that this packet has been recirculated using egress
 * loopback.  This allows certain checks to be bypassed, such as a
 * logical router dropping packets with source IP address equals
 * one of the logical router's own IP addresses. */
#define REGBIT_EGRESS_LOOPBACK  "reg9[0]"
/* Register to store the result of check_pkt_larger action. */
#define REGBIT_PKT_LARGER        "reg9[1]"
#define REGBIT_LOOKUP_NEIGHBOR_RESULT "reg9[2]"
#define REGBIT_LOOKUP_NEIGHBOR_IP_RESULT "reg9[3]"

/* Register to store the eth address associated to a router port for packets
 * received in S_ROUTER_IN_ADMISSION.
 */
#define REG_INPORT_ETH_ADDR "xreg0[0..47]"

/* Register for ECMP bucket selection. */
#define REG_ECMP_GROUP_ID       "reg8[0..15]"
#define REG_ECMP_MEMBER_ID      "reg8[16..31]"

/* Registers used for routing. */
#define REG_NEXT_HOP_IPV4 "reg0"
#define REG_NEXT_HOP_IPV6 "xxreg0"
#define REG_SRC_IPV4 "reg1"
#define REG_SRC_IPV6 "xxreg1"

#define FLAGBIT_NOT_VXLAN "flags[1] == 0"

/*
 * OVS register usage:
 *
 * Logical Switch pipeline:
 * +---------+----------------------------------------------+
 * | R0      |     REGBIT_{CONNTRACK/DHCP/DNS/HAIRPIN}      |
 * |         | REGBIT_ACL_HINT_{ALLOW_NEW/ALLOW/DROP/BLOCK} |
 * +---------+----------------------------------------------+
 * | R1 - R9 |                   UNUSED                     |
 * +---------+----------------------------------------------+
 *
 * Logical Router pipeline:
 * +-----+--------------------------+---+-----------------+---+---------------+
 * | R0  | REGBIT_ND_RA_OPTS_RESULT |   |                 |   |               |
 * |     |   (= IN_ND_RA_OPTIONS)   | X |                 |   |               |
 * |     |      NEXT_HOP_IPV4       | R |                 |   |               |
 * |     |      (>= IP_INPUT)       | E | INPORT_ETH_ADDR | X |               |
 * +-----+--------------------------+ G |   (< IP_INPUT)  | X |               |
 * | R1  |   SRC_IPV4 for ARP-REQ   | 0 |                 | R |               |
 * |     |      (>= IP_INPUT)       |   |                 | E | NEXT_HOP_IPV6 |
 * +-----+--------------------------+---+-----------------+ G | (>= IP_INPUT) |
 * | R2  |        UNUSED            | X |                 | 0 |               |
 * |     |                          | R |                 |   |               |
 * +-----+--------------------------+ E |     UNUSED      |   |               |
 * | R3  |        UNUSED            | G |                 |   |               |
 * |     |                          | 1 |                 |   |               |
 * +-----+--------------------------+---+-----------------+---+---------------+
 * | R4  |        UNUSED            | X |                 |   |               |
 * |     |                          | R |                 |   |               |
 * +-----+--------------------------+ E |     UNUSED      | X |               |
 * | R5  |        UNUSED            | G |                 | X |               |
 * |     |                          | 2 |                 | R |SRC_IPV6 for NS|
 * +-----+--------------------------+---+-----------------+ E | (>= IP_INPUT) |
 * | R6  |        UNUSED            | X |                 | G |               |
 * |     |                          | R |                 | 1 |               |
 * +-----+--------------------------+ E |     UNUSED      |   |               |
 * | R7  |        UNUSED            | G |                 |   |               |
 * |     |                          | 3 |                 |   |               |
 * +-----+--------------------------+---+-----------------+---+---------------+
 * | R8  |     ECMP_GROUP_ID        |   |                 |
 * |     |     ECMP_MEMBER_ID       | X |                 |
 * +-----+--------------------------+ R |                 |
 * |     | REGBIT_{                 | E |                 |
 * |     |   EGRESS_LOOPBACK/       | G |     UNUSED      |
 * | R9  |   PKT_LARGER/            | 4 |                 |
 * |     |   LOOKUP_NEIGHBOR_RESULT/|   |                 |
 * |     |   SKIP_LOOKUP_NEIGHBOR}  |   |                 |
 * +-----+--------------------------+---+-----------------+
 *
 */

/* Returns an "enum ovn_stage" built from the arguments. */
static inline enum ovn_stage
ovn_stage_build(enum ovn_datapath_type dp_type, enum ovn_pipeline pipeline,
                uint8_t table)
{
    return OVN_STAGE_BUILD(dp_type, pipeline, table);
}

/* Returns the pipeline to which 'stage' belongs. */
static inline enum ovn_pipeline
ovn_stage_get_pipeline(enum ovn_stage stage)
{
    return (stage >> 8) & 1;
}

/* Returns the pipeline name to which 'stage' belongs. */
static inline const char *
ovn_stage_get_pipeline_name(enum ovn_stage stage)
{
    return ovn_stage_get_pipeline(stage) == P_IN ? "ingress" : "egress";
}

/* Returns the table to which 'stage' belongs. */
static inline uint8_t
ovn_stage_get_table(enum ovn_stage stage)
{
    return stage & 0xff;
}

/* Returns a string name for 'stage'. */
static inline const char *
ovn_stage_to_str(enum ovn_stage stage)
{
    switch (stage) {
#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)       \
        case S_##DP_TYPE##_##PIPELINE##_##STAGE: return NAME;
    PIPELINE_STAGES
#undef PIPELINE_STAGE
        default: return "<unknown>";
    }
}

/* Returns the type of the datapath to which a flow with the given 'stage' may
 * be added. */
static inline enum ovn_datapath_type
ovn_stage_to_datapath_type(enum ovn_stage stage)
{
    switch (stage) {
#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)       \
        case S_##DP_TYPE##_##PIPELINE##_##STAGE: return DP_##DP_TYPE;
    PIPELINE_STAGES
#undef PIPELINE_STAGE
    default: OVS_NOT_REACHED();
    }
}

#define MC_FLOOD "_MC_flood"
#define MC_MROUTER_FLOOD "_MC_mrouter_flood"
#define MC_MROUTER_STATIC "_MC_mrouter_static"
#define MC_STATIC "_MC_static"
#define MC_UNKNOWN "_MC_unknown"
#define MC_FLOOD_L2 "_MC_flood_l2"

struct ovn_ctrl_lflow {
    struct hmap_node hmap_node;
    struct uuid uuid_;

    uint32_t dp_key; /* Datapath tunnel key. */
    enum ovn_stage stage;
    uint16_t priority;
    char *match;
    char *actions;
    char *stage_hint;
    const char *where;
};

size_t ovn_ctrl_lflow_hash(const struct ovn_ctrl_lflow *);
void build_lswitch_generic_lflows(struct hmap *lflows);
void build_lrouter_generic_lflows(struct hmap *lflows);

void ovn_ctrl_lflows_build_dp_lflows(
    struct hmap *lflows, const struct sbrec_datapath_binding *dp);

void ovn_ctrl_lflows_clear(struct hmap *lflows);
void ovn_ctrl_lflows_destroy(struct hmap *lflows);

void ovn_ctrl_build_lport_lflows(
    struct hmap *lflows, struct local_lport *);

#endif /* OVN_LIB_LFLOW_H */
