/*
 * Copyright (c) 2021 Red Hat.
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

#include <config.h>

#include "ovn/expr.h"

#include "lflow.h"
#include "lib/ldata.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-util.h"

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "openvswitch/hmap.h"
#include "include/openvswitch/json.h"
#include "lib/smap.h"

VLOG_DEFINE_THIS_MODULE(lib_lflow);

static size_t ovn_ctrl_lflow_hash(const struct ovn_ctrl_lflow *lflow);
static char *ovn_ctrl_lflow_hint(const struct ovsdb_idl_row *row);
static void ovn_ctrl_lflow_init(struct ovn_ctrl_lflow *lflow,
                                enum ovn_stage stage, uint16_t priority,
                                char *match, char *actions,
                                const struct uuid *lflow_uuid,
                                uint8_t lflow_idx,
                                char *stage_hint, const char *where);
static void ovn_ctrl_lflow_add_at(struct hmap *lflow_map, enum ovn_stage stage,
                                  uint16_t priority, const char *match,
                                  const char *actions,
                                  const struct uuid *lflow_uuid,
                                  uint8_t lflow_idx,
                                  const struct ovsdb_idl_row *stage_hint,
                                  const char *where);
static void ovn_ctrl_lflow_destroy(struct ovn_ctrl_lflow *lflow);


#define ovn_ctrl_lflow_add(LFLOW_MAP, STAGE, PRIORITY, MATCH, ACTIONS) \
    ovn_ctrl_lflow_add_at(LFLOW_MAP, STAGE, PRIORITY, MATCH, ACTIONS, \
                          NULL, 0, NULL, OVS_SOURCE_LOCATOR)

#define ovn_ctrl_lflow_add_uuid(LFLOW_MAP, STAGE, PRIORITY, MATCH, ACTIONS, UUID, LFLOW_IDX) \
    ovn_ctrl_lflow_add_at(LFLOW_MAP, STAGE, PRIORITY, MATCH, ACTIONS, \
                          UUID, *LFLOW_IDX, NULL, OVS_SOURCE_LOCATOR); \
    (*LFLOW_IDX)++

static void build_generic_port_security(struct hmap *lflows);
static void build_generic_pre_acl(struct hmap *lflows);
static void build_generic_pre_lb(struct hmap *lflows);
static void build_generic_pre_stateful(struct hmap *lflows);
static void build_generic_acls(struct hmap *lflows);
static void build_generic_qos(struct hmap *lflows);
static void build_generic_stateful(struct hmap *lflows);
static void build_generic_lb_hairpin(struct hmap *lflows);
static void build_generic_l2_lkup(struct hmap *lflows);

static void build_lswitch_dp_lflows(struct hmap *lflows,
                                    const struct sbrec_datapath_binding *dp,
                                    bool use_ct_inv_match);
static void build_lrouter_dp_lflows(struct hmap *lflows,
                                    const struct sbrec_datapath_binding *dp);

static void build_lswitch_port_lflows(struct hmap *lflows,
                                      struct local_lport *);
static void build_lrouter_port_lflows(struct hmap *lflows,
                                      struct local_lport *);

void
ovn_ctrl_lflows_clear(struct hmap *lflows)
{
    struct ovn_ctrl_lflow *lflow;
    HMAP_FOR_EACH_POP (lflow, hmap_node, lflows) {
        ovn_ctrl_lflow_destroy(lflow);
    }
}

void
ovn_ctrl_lflows_destroy(struct hmap *lflows)
{
    ovn_ctrl_lflows_clear(lflows);
    hmap_destroy(lflows);
}

void
build_lswitch_generic_lflows(struct hmap *lflows)
{
    /* Port security stages. */
    build_generic_port_security(lflows);

    /* Lookup and learn FDB. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_LOOKUP_FDB, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PUT_FDB, 0, "1", "next;");

    build_generic_pre_acl(lflows);
    build_generic_pre_lb(lflows);
    build_generic_pre_stateful(lflows);
    build_generic_acls(lflows);
    build_generic_qos(lflows);
    build_generic_stateful(lflows);
    build_generic_lb_hairpin(lflows);

    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_ARP_ND_RSP, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_DHCP_OPTIONS, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_DHCP_RESPONSE, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_DNS_LOOKUP, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_DNS_RESPONSE, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_EXTERNAL_PORT, 0, "1", "next;");

    build_generic_l2_lkup(lflows);
}

void
ovn_ctrl_lflows_build_dp_lflows(struct hmap *lflows,
                                const struct sbrec_datapath_binding *dp)
{
    if (datapath_is_switch(dp)) {
        build_lswitch_dp_lflows(lflows, dp, true);
    } else {
        build_lrouter_dp_lflows(lflows, dp);
    }
}

void
ovn_ctrl_build_lport_lflows(struct hmap *lflows, struct local_lport *op)
{
    /* Initialize the data required for lflow generation. */
    local_lport_init_lflow_gen_data(op);
    if (op->peer) {
        local_lport_init_lflow_gen_data(op->peer);
    }

    if (op->ldp->is_switch) {
            build_lswitch_port_lflows(lflows, op);
    } else {
        build_lrouter_port_lflows(lflows, op);
    }

    local_lport_destroy_lflow_gen_data(op);
    if (op->peer) {
        local_lport_destroy_lflow_gen_data(op->peer);
    }
}

/* static functions. */
static size_t
ovn_ctrl_lflow_hash(const struct ovn_ctrl_lflow *lflow)
{
    return ovn_logical_flow_hash(ovn_stage_get_table(lflow->stage),
                                 ovn_stage_get_pipeline_name(lflow->stage),
                                 lflow->priority, lflow->match,
                                 lflow->actions);
}

static char *
ovn_ctrl_lflow_hint(const struct ovsdb_idl_row *row)
{
    if (!row) {
        return NULL;
    }
    return xasprintf("%08x", row->uuid.parts[0]);
}

static void
ovn_ctrl_lflow_init(struct ovn_ctrl_lflow *lflow,
                    enum ovn_stage stage, uint16_t priority,
                    char *match, char *actions,
                    const struct uuid *lflow_uuid, uint8_t lflow_idx OVS_UNUSED,
                    char *stage_hint,
                    const char *where)
{
    lflow->stage = stage;
    lflow->priority = priority;
    lflow->match = match;
    lflow->actions = actions;
    lflow->stage_hint = stage_hint;
    lflow->where = where;
    lflow_uuid = NULL; /* TODO. */
    if (lflow_uuid) {
        lflow->uuid_ = *lflow_uuid;
        uint32_t part0;
        part0 = ((lflow->uuid_.parts[0] & 0x00ffffff) | lflow_idx << 24);
        lflow->uuid_.parts[0] = part0;
    } else {
        uuid_generate(&lflow->uuid_);
    }
}

/* Adds a row with the specified contents to the Logical_Flow table. */
static void
ovn_ctrl_lflow_add_at(struct hmap *lflow_map, enum ovn_stage stage,
                      uint16_t priority, const char *match,
                      const char *actions,
                      const struct uuid *lflow_uuid,
                      uint8_t lflow_idx,
                      const struct ovsdb_idl_row *stage_hint,
                      const char *where)
{
    struct ovn_ctrl_lflow *lflow;
    size_t hash;

    lflow = xzalloc(sizeof *lflow);
    ovn_ctrl_lflow_init(lflow, stage, priority,
                        xstrdup(match), xstrdup(actions),
                        lflow_uuid, lflow_idx,
                        ovn_ctrl_lflow_hint(stage_hint), where);

    hash = ovn_ctrl_lflow_hash(lflow);
    hmap_insert(lflow_map, &lflow->hmap_node, hash);
}

static void
ovn_ctrl_lflow_destroy(struct ovn_ctrl_lflow *lflow)
{
    if (lflow) {
        free(lflow->match);
        free(lflow->actions);
        free(lflow->stage_hint);
        free(lflow);
    }
}

static void
build_generic_port_security(struct hmap *lflows)
{
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PORT_SEC_L2, 100, "eth.src[40]",
                       "drop;");

    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PORT_SEC_ND, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PORT_SEC_IP, 0, "1", "next;");

    /* Egress tables 8: Egress port security - IP (priority 0)
     * Egress table 9: Egress port security L2 - multicast/broadcast
     *                 (priority 100). */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PORT_SEC_IP, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PORT_SEC_L2, 100, "eth.mcast",
                          "output;");
}

static void
build_generic_pre_acl(struct hmap *lflows)
{
    /* Ingress and Egress Pre-ACL Table (Priority 0): Packets are
     * allowed by default. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_ACL, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_ACL, 0, "1", "next;");

#if 0
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_ACL, 110,
                          "eth.dst == $svc_monitor_mac", "next;");

    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_ACL, 110,
                          "eth.src == $svc_monitor_mac", "next;");
#endif
}

static void
build_generic_pre_lb(struct hmap *lflows)
{
    /* Do not send ND packets to conntrack */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_LB, 110,
                  "nd || nd_rs || nd_ra || mldv1 || mldv2",
                  "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_LB, 110,
                  "nd || nd_rs || nd_ra || mldv1 || mldv2",
                  "next;");

    /* Do not send service monitor packets to conntrack. */
#if 0
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_LB, 110,
                       "eth.dst == $svc_monitor_mac", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_LB, 110,
                      "eth.src == $svc_monitor_mac", "next;");
#endif

    /* Allow all packets to go to next tables by default. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_LB, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_LB, 0, "1", "next;");
}

static void
build_generic_pre_stateful(struct hmap *lflows)
{
    /* Ingress and Egress pre-stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_STATEFUL, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_STATEFUL, 0, "1", "next;");

    const char *lb_protocols[] = {"tcp", "udp", "sctp"};
    struct ds actions = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < ARRAY_SIZE(lb_protocols); i++) {
        ds_clear(&match);
        ds_clear(&actions);
        ds_put_format(&match, REGBIT_CONNTRACK_NAT" == 1 && ip4 && %s",
                      lb_protocols[i]);
        ds_put_format(&actions, REG_ORIG_DIP_IPV4 " = ip4.dst; "
                                REG_ORIG_TP_DPORT " = %s.dst; ct_lb;",
                      lb_protocols[i]);
        ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_STATEFUL, 120,
                      ds_cstr(&match), ds_cstr(&actions));

        ds_clear(&match);
        ds_clear(&actions);
        ds_put_format(&match, REGBIT_CONNTRACK_NAT" == 1 && ip6 && %s",
                      lb_protocols[i]);
        ds_put_format(&actions, REG_ORIG_DIP_IPV6 " = ip6.dst; "
                                REG_ORIG_TP_DPORT " = %s.dst; ct_lb;",
                      lb_protocols[i]);
        ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_STATEFUL, 120,
                      ds_cstr(&match), ds_cstr(&actions));
    }

    ds_destroy(&actions);
    ds_destroy(&match);

    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_STATEFUL, 110,
                       REGBIT_CONNTRACK_NAT" == 1", "ct_lb;");

    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_STATEFUL, 110,
                       REGBIT_CONNTRACK_NAT" == 1", "ct_lb;");

    /* If REGBIT_CONNTRACK_DEFRAG is set as 1, then the packets should be
     * sent to conntrack for tracking and defragmentation. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_STATEFUL, 100,
                       REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;");

    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_PRE_STATEFUL, 100,
                       REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;");
}

static void
build_generic_acls(struct hmap *lflows)
{
    /* Ingress and Egress ACL Table (Priority 0): Packets are allowed by
     * default.  A related rule at priority 1 is added below if there
     * are any stateful ACLs in this datapath. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_ACL, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_ACL, 0, "1", "next;");

#if 0
    /* Add a 34000 priority flow to advance the service monitor reply
     * packets to skip applying ingress ACLs. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_ACL, 34000,
                          "eth.dst == $svc_monitor_mac", "next;");

    /* Add a 34000 priority flow to advance the service monitor packets
     * generated by ovn-controller to skip applying egress ACLs. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_ACL, 34000,
                          "eth.src == $svc_monitor_mac", "next;");
#endif
}

static void
build_generic_qos(struct hmap *lflows)
{
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_QOS_MARK, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_QOS_MARK, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_QOS_METER, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_QOS_METER, 0, "1", "next;");
}

static void
build_generic_stateful(struct hmap *lflows)
{
    /* Ingress and Egress stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_STATEFUL, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_STATEFUL, 0, "1", "next;");

    /* If REGBIT_CONNTRACK_COMMIT is set as 1, then the packets should be
     * committed to conntrack. We always set ct_label.blocked to 0 here as
     * any packet that makes it this far is part of a connection we
     * want to allow to continue. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_STATEFUL, 100,
                       REGBIT_CONNTRACK_COMMIT" == 1",
                       "ct_commit { ct_label.blocked = 0; }; next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_STATEFUL, 100,
                       REGBIT_CONNTRACK_COMMIT" == 1",
                       "ct_commit { ct_label.blocked = 0; }; next;");
}

static void
build_generic_lb_hairpin(struct hmap *lflows)
{
    /* Ingress Pre-Hairpin/Nat-Hairpin/Hairpin tabled (Priority 0).
     * Packets that don't need hairpinning should continue processing.
     */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_PRE_HAIRPIN, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_NAT_HAIRPIN, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_HAIRPIN, 0, "1", "next;");
}

static void
build_generic_l2_lkup(struct hmap *lflows)
{
#if 0
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_L2_LKUP, 110,
                          "eth.dst == $svc_monitor_mac",
                          "handle_svc_check(inport);");
#endif
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_L2_LKUP, 0, "1",
                          "outport = get_fdb(eth.dst); next;");

    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_L2_UNKNOWN, 0, "1", "output;");
}

static bool
is_dp_vlan_transparent(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "vlan-passthru", false);
}

static bool
has_dp_lb_vip(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "has-lb-vips", false);
}

static bool
has_dp_stateful_acls(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "has-stateful-acls", false);
}

static bool
has_dp_acls(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "has-acls", false);
}

static bool
has_dp_unknown_lports(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "has-unknown", false);
}

static bool
has_dp_dns_records(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "has-dns-records", false);
}

static void
build_lswitch_pre_acls(struct hmap *lflows, bool has_stateful_acls,
                       const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx)
{
    /* If there are any stateful ACL rules in this datapath, we may
     * send IP packets for some (allow) filters through the conntrack action,
     * which handles defragmentation, in order to match L4 headers. */
    if (has_stateful_acls) {
        /* Ingress and Egress Pre-ACL Table (Priority 110).
         *
         * Not to do conntrack on ND and ICMP destination
         * unreachable packets. */
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_IN_PRE_ACL, 110,
            "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
            "(udp && udp.src == 546 && udp.dst == 547)", "next;",
            lflow_uuid, lflow_uuid_idx);

        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_OUT_PRE_ACL, 110,
            "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
            "(udp && udp.src == 546 && udp.dst == 547)", "next;",
            lflow_uuid, lflow_uuid_idx);

        /* Ingress and Egress Pre-ACL Table (Priority 100).
         *
         * Regardless of whether the ACL is "from-lport" or "to-lport",
         * we need rules in both the ingress and egress table, because
         * the return traffic needs to be followed.
         *
         * 'REGBIT_CONNTRACK_DEFRAG' is set to let the pre-stateful table send
         * it to conntrack for tracking and defragmentation. */
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PRE_ACL, 100, "ip",
                                REGBIT_CONNTRACK_DEFRAG" = 1; next;",
                                lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_PRE_ACL, 100, "ip",
                                REGBIT_CONNTRACK_DEFRAG" = 1; next;",
                                lflow_uuid, lflow_uuid_idx);
    }
}

static void
build_lswitch_pre_lb(struct hmap *lflows, bool vip_configured,
                     const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx)
{
    /* 'REGBIT_CONNTRACK_NAT' is set to let the pre-stateful table send
     * packet to conntrack for defragmentation and possibly for unNATting.
     *
     * Send all the packets to conntrack in the ingress pipeline if the
     * logical switch has a load balancer with VIP configured. Earlier
     * we used to set the REGBIT_CONNTRACK_DEFRAG flag in the ingress pipeline
     * if the IP destination matches the VIP. But this causes few issues when
     * a logical switch has no ACLs configured with allow-related.
     * To understand the issue, lets a take a TCP load balancer -
     * 10.0.0.10:80=10.0.0.3:80.
     * If a logical port - p1 with IP - 10.0.0.5 opens a TCP connection with
     * the VIP - 10.0.0.10, then the packet in the ingress pipeline of 'p1'
     * is sent to the p1's conntrack zone id and the packet is load balanced
     * to the backend - 10.0.0.3. For the reply packet from the backend lport,
     * it is not sent to the conntrack of backend lport's zone id. This is fine
     * as long as the packet is valid. Suppose the backend lport sends an
     *  invalid TCP packet (like incorrect sequence number), the packet gets
     * delivered to the lport 'p1' without unDNATing the packet to the
     * VIP - 10.0.0.10. And this causes the connection to be reset by the
     * lport p1's VIF.
     *
     * We can't fix this issue by adding a logical flow to drop ct.inv packets
     * in the egress pipeline since it will drop all other connections not
     * destined to the load balancers.
     *
     * To fix this issue, we send all the packets to the conntrack in the
     * ingress pipeline if a load balancer is configured. We can now
     * add a lflow to drop ct.inv packets.
     */
    if (vip_configured) {
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PRE_LB,
                                100, "ip", REGBIT_CONNTRACK_NAT" = 1; next;",
                                lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_PRE_LB,
                                100, "ip", REGBIT_CONNTRACK_NAT" = 1; next;",
                                lflow_uuid, lflow_uuid_idx);
    }
}

static void
build_lswitch_acl_hints(struct hmap *lflows, bool has_acls_or_lbs,
                        const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx)
{
    /* This stage builds hints for the IN/OUT_ACL stage. Based on various
     * combinations of ct flags packets may hit only a subset of the logical
     * flows in the IN/OUT_ACL stage.
     *
     * Populating ACL hints first and storing them in registers simplifies
     * the logical flow match expressions in the IN/OUT_ACL stage and
     * generates less openflows.
     *
     * Certain combinations of ct flags might be valid matches for multiple
     * types of ACL logical flows (e.g., allow/drop). In such cases hints
     * corresponding to all potential matches are set.
     */

    enum ovn_stage stages[] = {
        S_SWITCH_IN_ACL_HINT,
        S_SWITCH_OUT_ACL_HINT,
    };

    for (size_t i = 0; i < ARRAY_SIZE(stages); i++) {
        enum ovn_stage stage = stages[i];

        /* In any case, advance to the next stage. */
        if (!has_acls_or_lbs) {
            ovn_ctrl_lflow_add_uuid(lflows, stage, UINT16_MAX, "1", "next;",
                                    lflow_uuid, lflow_uuid_idx);
        } else {
            ovn_ctrl_lflow_add_uuid(lflows, stage, 0, "1", "next;",
                                    lflow_uuid, lflow_uuid_idx);
        }

        if (!has_acls_or_lbs) {
            continue;
        }

        /* New, not already established connections, may hit either allow
         * or drop ACLs. For allow ACLs, the connection must also be committed
         * to conntrack so we set REGBIT_ACL_HINT_ALLOW_NEW.
         */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 7, "ct.new && !ct.est",
                                REGBIT_ACL_HINT_ALLOW_NEW " = 1; "
                                REGBIT_ACL_HINT_DROP " = 1; "
                                "next;", lflow_uuid, lflow_uuid_idx);

        /* Already established connections in the "request" direction that
         * are already marked as "blocked" may hit either:
         * - allow ACLs for connections that were previously allowed by a
         *   policy that was deleted and is being readded now. In this case
         *   the connection should be recommitted so we set
         *   REGBIT_ACL_HINT_ALLOW_NEW.
         * - drop ACLs.
         */
        ovn_ctrl_lflow_add_uuid(
            lflows, stage, 6,
            "!ct.new && ct.est && !ct.rpl && ct_label.blocked == 1",
            REGBIT_ACL_HINT_ALLOW_NEW " = 1; "REGBIT_ACL_HINT_DROP " = 1; "
            "next;", lflow_uuid, lflow_uuid_idx);

        /* Not tracked traffic can either be allowed or dropped. */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 5, "!ct.trk",
                                REGBIT_ACL_HINT_ALLOW " = 1; "
                                REGBIT_ACL_HINT_DROP " = 1; "
                                "next;", lflow_uuid, lflow_uuid_idx);

        /* Already established connections in the "request" direction may hit
         * either:
         * - allow ACLs in which case the traffic should be allowed so we set
         *   REGBIT_ACL_HINT_ALLOW.
         * - drop ACLs in which case the traffic should be blocked and the
         *   connection must be committed with ct_label.blocked set so we set
         *   REGBIT_ACL_HINT_BLOCK.
         */
        ovn_ctrl_lflow_add_uuid(
            lflows, stage, 4,
            "!ct.new && ct.est && !ct.rpl && ct_label.blocked == 0",
            REGBIT_ACL_HINT_ALLOW " = 1; "REGBIT_ACL_HINT_BLOCK " = 1; "
            "next;", lflow_uuid, lflow_uuid_idx);

        /* Not established or established and already blocked connections may
         * hit drop ACLs.
         */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 3, "!ct.est",
                                REGBIT_ACL_HINT_DROP " = 1; "
                                "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, stage, 2,
                                "ct.est && ct_label.blocked == 1",
                                REGBIT_ACL_HINT_DROP " = 1; next;",
                                lflow_uuid, lflow_uuid_idx);

        /* Established connections that were previously allowed might hit
         * drop ACLs in which case the connection must be committed with
         * ct_label.blocked set.
         */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 1,
                                "ct.est && ct_label.blocked == 0",
                                REGBIT_ACL_HINT_BLOCK " = 1; next;",
                                lflow_uuid, lflow_uuid_idx);
    }
}

static void
build_lswitch_acls(struct hmap *lflows, bool has_acls_or_lbs,
                   bool has_stateful, bool use_ct_inv_match,
                   const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx)
{
    /* Ingress and Egress ACL Table (Priority 0): Packets are allowed by
     * default.  If the logical switch has no ACLs or no load balancers,
     * then add 65535-priority flow to advance the packet to next
     * stage.
     *
     * A related rule at priority 1 is added below if there
     * are any stateful ACLs in this datapath. */
    if (!has_acls_or_lbs) {
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, UINT16_MAX, "1",
                                "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, UINT16_MAX, "1",
                                "next;", lflow_uuid, lflow_uuid_idx);
    } else {
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, 0, "1",
                                "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, 0, "1",
                                "next;", lflow_uuid, lflow_uuid_idx);
    }

    if (has_stateful) {
        /* Ingress and Egress ACL Table (Priority 1).
         *
         * By default, traffic is allowed.  This is partially handled by
         * the Priority 0 ACL flows added earlier, but we also need to
         * commit IP flows.  This is because, while the initiater's
         * direction may not have any stateful rules, the server's may
         * and then its return traffic would not have an associated
         * conntrack entry and would return "+invalid".
         *
         * We use "ct_commit" for a connection that is not already known
         * by the connection tracker.  Once a connection is committed,
         * subsequent packets will hit the flow at priority 0 that just
         * uses "next;"
         *
         * We also check for established connections that have ct_label.blocked
         * set on them.  That's a connection that was disallowed, but is
         * now allowed by policy again since it hit this default-allow flow.
         * We need to set ct_label.blocked=0 to let the connection continue,
         * which will be done by ct_commit() in the "stateful" stage.
         * Subsequent packets will hit the flow at priority 0 that just
         * uses "next;". */
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, 1,
                            "ip && (!ct.est || "
                            "(ct.est && ct_label.blocked == 1))",
                            REGBIT_CONNTRACK_COMMIT" = 1; next;",
                            lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_OUT_ACL, 1,
            "ip && (!ct.est || (ct.est && ct_label.blocked == 1))",
            REGBIT_CONNTRACK_COMMIT" = 1; next;",
            lflow_uuid, lflow_uuid_idx);

        /* Ingress and Egress ACL Table (Priority 65532).
         *
         * Always drop traffic that's in an invalid state.  Also drop
         * reply direction packets for connections that have been marked
         * for deletion (bit 0 of ct_label is set).
         *
         * This is enforced at a higher priority than ACLs can be defined. */
        char *match = xasprintf("%s(ct.est && ct.rpl && ct_label.blocked == 1)",
                                use_ct_inv_match ? "ct.inv || " : "");
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, UINT16_MAX - 3, match,
                            "drop;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, UINT16_MAX - 3, match,
                            "drop;", lflow_uuid, lflow_uuid_idx);
        free(match);

        /* Ingress and Egress ACL Table (Priority 65535 - 3).
         *
         * Allow reply traffic that is part of an established
         * conntrack entry that has not been marked for deletion
         * (bit 0 of ct_label).  We only match traffic in the
         * reply direction because we want traffic in the request
         * direction to hit the currently defined policy from ACLs.
         *
         * This is enforced at a higher priority than ACLs can be defined. */
        match = xasprintf("ct.est && !ct.rel && !ct.new%s && "
                          "ct.rpl && ct_label.blocked == 0",
                          use_ct_inv_match ? " && !ct.inv" : "");

        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                                match, "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                                match, "next;", lflow_uuid, lflow_uuid_idx);
        free(match);

        /* Ingress and Egress ACL Table (Priority 65535).
         *
         * Allow traffic that is related to an existing conntrack entry that
         * has not been marked for deletion (bit 0 of ct_label).
         *
         * This is enforced at a higher priority than ACLs can be defined.
         *
         * NOTE: This does not support related data sessions (eg,
         * a dynamically negotiated FTP data channel), but will allow
         * related traffic such as an ICMP Port Unreachable through
         * that's generated from a non-listening UDP port.  */
        match = xasprintf("!ct.est && ct.rel && !ct.new%s && "
                          "ct_label.blocked == 0",
                          use_ct_inv_match ? " && !ct.inv" : "");
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                                match, "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                                match, "next;", lflow_uuid, lflow_uuid_idx);
        free(match);

        /* Ingress and Egress ACL Table (Priority 65532).
         *
         * Not to do conntrack on ND packets. */
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_IN_ACL, UINT16_MAX - 3,
            "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;",
            lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
            "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;",
            lflow_uuid, lflow_uuid_idx);
    }
}

static void
build_lswitch_lb_hairpin(struct hmap *lflows, bool has_lb_vips,
                         const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx)
{
    if (has_lb_vips) {
        /* Check if the packet needs to be hairpinned.
         * Set REGBIT_HAIRPIN in the original direction and
         * REGBIT_HAIRPIN_REPLY in the reply direction.
         */
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_IN_PRE_HAIRPIN, 100, "ip && ct.trk",
            REGBIT_HAIRPIN " = chk_lb_hairpin(); "
            REGBIT_HAIRPIN_REPLY " = chk_lb_hairpin_reply(); "
            "next;", lflow_uuid, lflow_uuid_idx);

        /* If packet needs to be hairpinned, snat the src ip with the VIP
         * for new sessions. */
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && ct.new && ct.trk"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat_to_vip; next;",
                                lflow_uuid, lflow_uuid_idx);

        /* If packet needs to be hairpinned, for established sessions there
         * should already be an SNAT conntrack entry.
         */
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && ct.est && ct.trk"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat;",
                                lflow_uuid, lflow_uuid_idx);

        /* For the reply of hairpinned traffic, snat the src ip to the VIP. */
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_NAT_HAIRPIN, 90,
                                "ip && "REGBIT_HAIRPIN_REPLY " == 1",
                                "ct_snat;",
                                lflow_uuid, lflow_uuid_idx);

        /* Ingress Hairpin table.
        * - Priority 1: Packets that were SNAT-ed for hairpinning should be
        *   looped back (i.e., swap ETH addresses and send back on inport).
        */
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_IN_HAIRPIN, 1,
            "("REGBIT_HAIRPIN " == 1 || " REGBIT_HAIRPIN_REPLY " == 1)",
            "eth.dst <-> eth.src; outport = inport; flags.loopback = 1; "
            "output;", lflow_uuid, lflow_uuid_idx);
    }
}

static void
build_lswitch_pre_acls_and_acls(struct hmap *lflows,
                                const struct sbrec_datapath_binding *dp,
                                bool use_ct_inv_match,
                                const struct uuid *lflow_uuid,
                                uint8_t *lflow_uuid_idx)
{
    bool has_stateful_acls = has_dp_stateful_acls(dp);
    bool has_lb_vips = has_dp_lb_vip(dp);
    bool has_stateful = (has_stateful_acls || has_lb_vips);
    bool has_acls_or_lbs = has_dp_acls(dp) || has_lb_vips;

    build_lswitch_pre_acls(lflows, has_stateful_acls, lflow_uuid,
                           lflow_uuid_idx);
    build_lswitch_pre_lb(lflows, has_lb_vips, lflow_uuid, lflow_uuid_idx);
    build_lswitch_acl_hints(lflows, has_acls_or_lbs, lflow_uuid,
                            lflow_uuid_idx);
    build_lswitch_acls(lflows, has_acls_or_lbs, has_stateful,
                       use_ct_inv_match, lflow_uuid, lflow_uuid_idx);
    build_lswitch_lb_hairpin(lflows, has_lb_vips, lflow_uuid, lflow_uuid_idx);

    /* Add a 34000 priority flow to advance the DNS reply from ovn-controller,
     * if the CMS has configured DNS records for the datapath.
     */
    if (has_dp_dns_records(dp)) {
        const char *actions = has_stateful ? "ct_commit; next;" : "next;";
        ovn_ctrl_lflow_add_uuid(
            lflows, S_SWITCH_OUT_ACL, 34000, "udp.src == 53",
            actions, lflow_uuid, lflow_uuid_idx);
    }

#if 0
    /* Add a 34000 priority flow to advance the service monitor reply
     * packets to skip applying ingress ACLs. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_IN_ACL, 34000,
                  "eth.dst == $svc_monitor_mac", "next;");

    /* Add a 34000 priority flow to advance the service monitor packets
     * generated by ovn-controller to skip applying egress ACLs. */
    ovn_ctrl_lflow_add(lflows, S_SWITCH_OUT_ACL, 34000,
                       "eth.src == $svc_monitor_mac", "next;");
#endif
}

static void
build_lswitch_dns_lkup(struct hmap *lflows,
                       const struct uuid *lflow_uuid,
                       uint8_t *lflow_uuid_idx)
{
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_DNS_LOOKUP, 100,
                            "udp.dst == 53",
                            REGBIT_DNS_LOOKUP_RESULT" = dns_lookup(); next;",
                            lflow_uuid, lflow_uuid_idx);
    const char *dns_action =
        "eth.dst <-> eth.src; ip4.src <-> ip4.dst; "
        "udp.dst = udp.src; udp.src = 53; outport = inport; "
        "flags.loopback = 1; output;";
    const char *dns_match = "udp.dst == 53 && "REGBIT_DNS_LOOKUP_RESULT;
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_DNS_RESPONSE, 100,
                            dns_match, dns_action,
                            lflow_uuid, lflow_uuid_idx);
    dns_action = "eth.dst <-> eth.src; ip6.src <-> ip6.dst; "
                 "udp.dst = udp.src; udp.src = 53; outport = inport; "
                 "flags.loopback = 1; output;";
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_DNS_RESPONSE, 100,
                            dns_match, dns_action,
                            lflow_uuid, lflow_uuid_idx);
}

static void
build_lswitch_dp_lflows(struct hmap *lflows,
                        const struct sbrec_datapath_binding *dp,
                        bool use_ct_inv_match)
{
    uint8_t lflow_uuid_idx = 1;

    /* Logical VLANs not supported. */
    if (!is_dp_vlan_transparent(dp)) {
        /* Block logical VLANs. */
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PORT_SEC_L2, 100,
                                "vlan.present", "drop;", &dp->header_.uuid,
                                &lflow_uuid_idx);
    }

    build_lswitch_pre_acls_and_acls(lflows, dp, use_ct_inv_match,
                                    &dp->header_.uuid, &lflow_uuid_idx);

    if (has_dp_dns_records(dp)) {
        build_lswitch_dns_lkup(lflows, &dp->header_.uuid, &lflow_uuid_idx);
    }

    if (has_dp_unknown_lports(dp)) {
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_L2_LKUP, 0, "1",
                                "outport = \""MC_UNKNOWN"\"; output;",
                                 &dp->header_.uuid, &lflow_uuid_idx);
    }
}

static void
build_generic_lr_lookup(struct hmap *lflows)
{
    /* For other packet types, we can skip neighbor learning.
         * So set REGBIT_LOOKUP_NEIGHBOR_RESULT to 1. */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 0, "1",
                          REGBIT_LOOKUP_NEIGHBOR_RESULT" = 1; next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                          "arp", "put_arp(inport, arp.spa, arp.sha); next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                          "nd_na", "put_nd(inport, nd.target, nd.tll); next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                          "nd_ns", "put_nd(inport, ip6.src, nd.sll); next;");
}

static void
build_generic_lr_ip_input(struct hmap *lflows)
{
    /* L3 admission control: drop multicast and broadcast source, localhost
        * source or destination, and zero network source or destination
        * (priority 100). */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 100,
                          "ip4.src_mcast ||"
                          "ip4.src == 255.255.255.255 || "
                          "ip4.src == 127.0.0.0/8 || "
                          "ip4.dst == 127.0.0.0/8 || "
                          "ip4.src == 0.0.0.0/8 || "
                          "ip4.dst == 0.0.0.0/8",
                          "drop;");

    /* Drop ARP packets (priority 85). ARP request packets for router's own
        * IPs are handled with priority-90 flows.
        * Drop IPv6 ND packets (priority 85). ND NA packets for router's own
        * IPs are handled with priority-90 flows.
        */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 85,
                          "arp || nd", "drop;");

    /* Allow IPv6 multicast traffic that's supposed to reach the
        * router pipeline (e.g., router solicitations).
        */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 84, "nd_rs || nd_ra",
                          "next;");

    /* Drop other reserved multicast. */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 83,
                          "ip6.mcast_rsvd", "drop;");

    /* Drop Ethernet local broadcast.  By definition this traffic should
        * not be forwarded.*/
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 50,
                       "eth.bcast", "drop;");

    /* TTL discard */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 30,
                       "ip4 && ip.ttl == {0, 1}", "drop;");

    /* Pass other traffic not already handled to the next table for
        * routing. */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 0, "1", "next;");
}

static void
build_generic_lr_arp_resolve(struct hmap *lflows)
{
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_RESOLVE, 500,
                          "ip4.mcast || ip6.mcast", "next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_RESOLVE, 0, "ip4",
                          "get_arp(outport, " REG_NEXT_HOP_IPV4 "); next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_RESOLVE, 0, "ip6",
                          "get_nd(outport, " REG_NEXT_HOP_IPV6 "); next;");
}

static void
build_generic_lr_arp_request(struct hmap *lflows)
{
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_REQUEST, 100,
                          "eth.dst == 00:00:00:00:00:00 && ip4",
                          "arp { "
                          "eth.dst = ff:ff:ff:ff:ff:ff; "
                          "arp.spa = " REG_SRC_IPV4 "; "
                          "arp.tpa = " REG_NEXT_HOP_IPV4 "; "
                          "arp.op = 1; " /* ARP request */
                          "output; "
                          "};");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_REQUEST, 100,
                          "eth.dst == 00:00:00:00:00:00 && ip6",
                          "nd_ns { "
                          "nd.target = " REG_NEXT_HOP_IPV6 "; "
                          "output; "
                          "};");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_REQUEST, 0, "1", "output;");
}

void
build_lrouter_generic_lflows(struct hmap *lflows)
{
    /* Logical VLANs not supported.
         * Broadcast/multicast source address is invalid. */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ADMISSION, 100,
                          "vlan.present || eth.src[40]", "drop;");

    build_generic_lr_lookup(lflows);
    build_generic_lr_ip_input(lflows);

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_DEFRAG, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_UNSNAT, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_DNAT, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ECMP_STATEFUL, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ND_RA_OPTIONS, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ND_RA_RESPONSE, 0, "1", "next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_ROUTING, 550,
                       "nd_rs || nd_ra", "drop;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_ROUTING_ECMP, 150,
                       REG_ECMP_GROUP_ID" == 0", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_POLICY, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_POLICY_ECMP, 150,
                       REG_ECMP_GROUP_ID" == 0", "next;");

    build_generic_lr_arp_resolve(lflows);

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_CHK_PKT_LEN, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LARGER_PKTS, 0, "1", "next;");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_GW_REDIRECT, 0, "1", "next;");

    build_generic_lr_arp_request(lflows);

    ovn_ctrl_lflow_add(lflows, S_ROUTER_OUT_UNDNAT, 0, "1", "next;");

    /* Send the IPv6 NS packets to next table. When ovn-controller
     * generates IPv6 NS (for the action - nd_ns{}), the injected
     * packet would go through conntrack - which is not required. */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_OUT_SNAT, 120, "nd_ns", "next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_OUT_SNAT, 0, "1", "next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_OUT_EGR_LOOP, 0, "1", "next;");
}

static bool
is_learn_from_arp_request(const struct sbrec_datapath_binding *dp)
{
    return (!datapath_is_switch(dp) &&
            smap_get_bool(&dp->options,
                          "always-learn-from-arp-request", true));

}

static void build_lrouter_neigh_learning_flows(
    struct hmap *lflows, const struct sbrec_datapath_binding *dp);
static void build_misc_local_traffic_drop_flows_for_lrouter(
    struct hmap *lflows, const struct sbrec_datapath_binding *dp);

static void
build_lrouter_dp_lflows(struct hmap *lflows,
                        const struct sbrec_datapath_binding *dp)
{
    build_lrouter_neigh_learning_flows(lflows, dp);
    build_misc_local_traffic_drop_flows_for_lrouter(lflows, dp);
}

static void
build_lrouter_neigh_learning_flows(struct hmap *lflows,
                                   const struct sbrec_datapath_binding *dp)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    bool learn_from_arp_request = is_learn_from_arp_request(dp);

    ds_clear(&actions);
    ds_put_format(&actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                  " = lookup_arp(inport, arp.spa, arp.sha); %snext;",
                  learn_from_arp_request ? "" :
                  REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1; ");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100,
                       "arp.op == 2", ds_cstr(&actions));

    ds_clear(&actions);
    ds_put_format(&actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                  " = lookup_nd(inport, nd.target, nd.tll); %snext;",
                  learn_from_arp_request ? "" :
                  REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1; ");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100, "nd_na",
                       ds_cstr(&actions));

    ds_clear(&actions);
    ds_put_format(&actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                  " = lookup_nd(inport, ip6.src, nd.sll); %snext;",
                  learn_from_arp_request ? "" :
                  REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
                  " = lookup_nd_ip(inport, ip6.src); ");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100, "nd_ns",
                    ds_cstr(&actions));

    /* For other packet types, we can skip neighbor learning.
        * So set REGBIT_LOOKUP_NEIGHBOR_RESULT to 1. */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 0, "1",
                    REGBIT_LOOKUP_NEIGHBOR_RESULT" = 1; next;");

    /* Flows for LEARN_NEIGHBOR. */
    /* Skip Neighbor learning if not required. */
    ds_clear(&match);
    ds_put_format(&match, REGBIT_LOOKUP_NEIGHBOR_RESULT" == 1%s",
                  learn_from_arp_request ? "" :
                  " || "REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" == 0");
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 100,
                       ds_cstr(&match), "next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                       "arp", "put_arp(inport, arp.spa, arp.sha); next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                       "nd_na", "put_nd(inport, nd.target, nd.tll); next;");

    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                       "nd_ns", "put_nd(inport, ip6.src, nd.sll); next;");

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_misc_local_traffic_drop_flows_for_lrouter(
    struct hmap *lflows,
    const struct sbrec_datapath_binding *dp)
{
    bool mcast_relay = smap_get_bool(&dp->options, "mcast-relay", false);
    /* Allow other multicast if relay enabled (priority 82). */
    ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_IP_INPUT, 82,
                      "ip4.mcast || ip6.mcast",
                       mcast_relay ? "next;" : "drop;");
}

static bool
lsp_is_enabled(const struct sbrec_port_binding *pb)
{
    return smap_get_bool(&pb->options, "enabled", true);
}

static bool
lsp_is_up(const struct sbrec_port_binding *pb)
{
    return pb->n_up && *pb->up;
}

static void build_lswitch_input_port_sec_op(struct hmap *lflows,
                                            struct local_lport *,
                                            uint8_t *lflow_uuid_idx);
static void build_lswitch_output_port_sec_op(struct hmap *lflows,
                                             struct local_lport *,
                                             uint8_t *lflow_uuid_idx);
static void build_lswitch_learn_fdb_op(struct hmap *lflows,
                                       struct local_lport *,
                                       uint8_t *lflow_uuid_idx,
                                       struct ds *match,
                                       struct ds *actions);
static void build_lswitch_arp_nd_responder_skip_local(struct hmap *lflows,
                                                      struct local_lport *,
                                                      uint8_t *lflow_uuid_idx,
                                                      struct ds *match);
static void build_lswitch_arp_nd_responder_known_ips(struct hmap *lflows,
                                                     struct local_lport *,
                                                     uint8_t *lflow_uuid_idx,
                                                     struct ds *match,
                                                     struct ds *actions);
static void build_lswitch_ip_unicast_lookup(struct hmap *lflows,
                                            struct local_lport *,
                                            uint8_t *lflow_uuid_idx,
                                            struct ds *match,
                                            struct ds *actions);

static void
build_lswitch_port_lflows(struct hmap *lflows, struct local_lport *op)
{
    uint8_t lflow_uuid_idx = 1;
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    build_lswitch_input_port_sec_op(lflows, op, &lflow_uuid_idx);
    build_lswitch_output_port_sec_op(lflows, op, &lflow_uuid_idx);

    build_lswitch_learn_fdb_op(lflows, op, &lflow_uuid_idx,
                               &match, &actions);
    build_lswitch_arp_nd_responder_skip_local(lflows, op,
                                              &lflow_uuid_idx, &match);
    build_lswitch_arp_nd_responder_known_ips(lflows, op,
                                             &lflow_uuid_idx, &match,
                                             &actions);
    build_lswitch_ip_unicast_lookup(lflows, op, &lflow_uuid_idx,
                                    &match, &actions);

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Appends port security constraints on L2 address field 'eth_addr_field'
 * (e.g. "eth.src" or "eth.dst") to 'match'.  'ps_addrs', with 'n_ps_addrs'
 * elements, is the collection of port_security constraints from an
 * OVN_NB Logical_Switch_Port row generated by extract_lsp_addresses(). */
static void
build_port_security_l2(const char *eth_addr_field,
                       struct lport_addresses *ps_addrs,
                       unsigned int n_ps_addrs,
                       struct ds *match)
{
    if (!n_ps_addrs) {
        return;
    }

    ds_put_format(match, " && %s == {", eth_addr_field);

    for (size_t i = 0; i < n_ps_addrs; i++) {
        ds_put_format(match, "%s ", ps_addrs[i].ea_s);
    }
    ds_chomp(match, ' ');
    ds_put_cstr(match, "}");
}

static void
build_port_security_ipv6_flow(
    enum ovn_pipeline pipeline, struct ds *match, struct eth_addr ea,
    struct ipv6_netaddr *ipv6_addrs, int n_ipv6_addrs)
{
    char ip6_str[INET6_ADDRSTRLEN + 1];

    ds_put_format(match, " && %s == {",
                  pipeline == P_IN ? "ip6.src" : "ip6.dst");

    /* Allow link-local address. */
    struct in6_addr lla;
    in6_generate_lla(ea, &lla);
    ipv6_string_mapped(ip6_str, &lla);
    ds_put_format(match, "%s, ", ip6_str);

    /* Allow ip6.dst=ff00::/8 for multicast packets */
    if (pipeline == P_OUT) {
        ds_put_cstr(match, "ff00::/8, ");
    }
    for (size_t i = 0; i < n_ipv6_addrs; i++) {
        /* When the netmask is applied, if the host portion is
         * non-zero, the host can only use the specified
         * address.  If zero, the host is allowed to use any
         * address in the subnet.
         */
        if (ipv6_addrs[i].plen == 128
            || !ipv6_addr_is_host_zero(&ipv6_addrs[i].addr,
                                       &ipv6_addrs[i].mask)) {
            ds_put_format(match, "%s, ", ipv6_addrs[i].addr_s);
        } else {
            ds_put_format(match, "%s/%d, ", ipv6_addrs[i].network_s,
                          ipv6_addrs[i].plen);
        }
    }
    /* Replace ", " by "}". */
    ds_chomp(match, ' ');
    ds_chomp(match, ',');
    ds_put_cstr(match, "}");
}

static void
build_port_security_ipv6_nd_flow(
    struct ds *match, struct eth_addr ea, struct ipv6_netaddr *ipv6_addrs,
    int n_ipv6_addrs)
{
    ds_put_format(match, " && ip6 && nd && ((nd.sll == "ETH_ADDR_FMT" || "
                  "nd.sll == "ETH_ADDR_FMT") || ((nd.tll == "ETH_ADDR_FMT" || "
                  "nd.tll == "ETH_ADDR_FMT")", ETH_ADDR_ARGS(eth_addr_zero),
                  ETH_ADDR_ARGS(ea), ETH_ADDR_ARGS(eth_addr_zero),
                  ETH_ADDR_ARGS(ea));
    if (!n_ipv6_addrs) {
        ds_put_cstr(match, "))");
        return;
    }

    char ip6_str[INET6_ADDRSTRLEN + 1];
    struct in6_addr lla;
    in6_generate_lla(ea, &lla);
    memset(ip6_str, 0, sizeof(ip6_str));
    ipv6_string_mapped(ip6_str, &lla);
    ds_put_format(match, " && (nd.target == %s", ip6_str);

    for (size_t i = 0; i < n_ipv6_addrs; i++) {
        /* When the netmask is applied, if the host portion is
         * non-zero, the host can only use the specified
         * address in the nd.target.  If zero, the host is allowed
         * to use any address in the subnet.
         */
        if (ipv6_addrs[i].plen == 128
            || !ipv6_addr_is_host_zero(&ipv6_addrs[i].addr,
                                       &ipv6_addrs[i].mask)) {
            ds_put_format(match, " || nd.target == %s", ipv6_addrs[i].addr_s);
        } else {
            ds_put_format(match, " || nd.target == %s/%d",
                          ipv6_addrs[i].network_s, ipv6_addrs[i].plen);
        }
    }

    ds_put_format(match, ")))");
}

/**
 * Build port security constraints on IPv4 and IPv6 src and dst fields
 * and add logical flows to S_SWITCH_(IN/OUT)_PORT_SEC_IP stage.
 *
 * For each port security of the logical port, following
 * logical flows are added
 *   - If the port security has IPv4 addresses,
 *     - Priority 90 flow to allow IPv4 packets for known IPv4 addresses
 *
 *   - If the port security has IPv6 addresses,
 *     - Priority 90 flow to allow IPv6 packets for known IPv6 addresses
 *
 *   - If the port security has IPv4 addresses or IPv6 addresses or both
 *     - Priority 80 flow to drop all IPv4 and IPv6 traffic
 */
static void
build_port_security_ip(enum ovn_pipeline pipeline, struct local_lport *op,
                       struct hmap *lflows, uint8_t *lflow_uuid_idx)
{
    char *port_direction;
    enum ovn_stage stage;
    if (pipeline == P_IN) {
        port_direction = "inport";
        stage = S_SWITCH_IN_PORT_SEC_IP;
    } else {
        port_direction = "outport";
        stage = S_SWITCH_OUT_PORT_SEC_IP;
    }

    for (size_t i = 0; i < op->lsp.n_ps_addrs; i++) {
        struct lport_addresses *ps = &op->lsp.ps_addrs[i];

        if (!(ps->n_ipv4_addrs || ps->n_ipv6_addrs)) {
            continue;
        }

        if (ps->n_ipv4_addrs) {
            struct ds match = DS_EMPTY_INITIALIZER;
            if (pipeline == P_IN) {
                /* Permit use of the unspecified address for DHCP discovery */
                struct ds dhcp_match = DS_EMPTY_INITIALIZER;
                ds_put_format(&dhcp_match, "inport == %s"
                              " && eth.src == %s"
                              " && ip4.src == 0.0.0.0"
                              " && ip4.dst == 255.255.255.255"
                              " && udp.src == 68 && udp.dst == 67",
                              op->json_key, ps->ea_s);
                ovn_ctrl_lflow_add_uuid(lflows, stage, 90,
                                        ds_cstr(&dhcp_match), "next;",
                                        &op->pb->header_.uuid, lflow_uuid_idx);
                ds_destroy(&dhcp_match);
                ds_put_format(&match, "inport == %s && eth.src == %s"
                              " && ip4.src == {", op->json_key,
                              ps->ea_s);
            } else {
                ds_put_format(&match, "outport == %s && eth.dst == %s"
                              " && ip4.dst == {255.255.255.255, 224.0.0.0/4, ",
                              op->json_key, ps->ea_s);
            }

            for (int j = 0; j < ps->n_ipv4_addrs; j++) {
                ovs_be32 mask = ps->ipv4_addrs[j].mask;
                /* When the netmask is applied, if the host portion is
                 * non-zero, the host can only use the specified
                 * address.  If zero, the host is allowed to use any
                 * address in the subnet.
                 */
                if (ps->ipv4_addrs[j].plen == 32
                    || ps->ipv4_addrs[j].addr & ~mask) {
                    ds_put_format(&match, "%s", ps->ipv4_addrs[j].addr_s);
                    if (pipeline == P_OUT && ps->ipv4_addrs[j].plen != 32) {
                        /* Host is also allowed to receive packets to the
                         * broadcast address in the specified subnet. */
                        ds_put_format(&match, ", %s",
                                      ps->ipv4_addrs[j].bcast_s);
                    }
                } else {
                    /* host portion is zero */
                    ds_put_format(&match, "%s/%d", ps->ipv4_addrs[j].network_s,
                                  ps->ipv4_addrs[j].plen);
                }
                ds_put_cstr(&match, ", ");
            }

            /* Replace ", " by "}". */
            ds_chomp(&match, ' ');
            ds_chomp(&match, ',');
            ds_put_cstr(&match, "}");
            ovn_ctrl_lflow_add_uuid(lflows, stage, 90, ds_cstr(&match),
                                    "next;", &op->pb->header_.uuid,
                                    lflow_uuid_idx);
            ds_destroy(&match);
        }

        if (ps->n_ipv6_addrs) {
            struct ds match = DS_EMPTY_INITIALIZER;
            if (pipeline == P_IN) {
                /* Permit use of unspecified address for duplicate address
                 * detection */
                struct ds dad_match = DS_EMPTY_INITIALIZER;
                ds_put_format(&dad_match, "inport == %s"
                              " && eth.src == %s"
                              " && ip6.src == ::"
                              " && ip6.dst == ff02::/16"
                              " && icmp6.type == {131, 135, 143}",
                              op->json_key,
                              ps->ea_s);
                ovn_ctrl_lflow_add_uuid(lflows, stage, 90, ds_cstr(&dad_match),
                                   "next;", &op->pb->header_.uuid,
                                   lflow_uuid_idx);
                ds_destroy(&dad_match);
            }
            ds_put_format(&match, "%s == %s && %s == %s",
                          port_direction, op->json_key,
                          pipeline == P_IN ? "eth.src" : "eth.dst", ps->ea_s);
            build_port_security_ipv6_flow(pipeline, &match, ps->ea,
                                          ps->ipv6_addrs, ps->n_ipv6_addrs);
            ovn_ctrl_lflow_add_uuid(lflows, stage, 90, ds_cstr(&match),
                                    "next;", &op->pb->header_.uuid,
                                    lflow_uuid_idx);
            ds_destroy(&match);
        }

        char *match = xasprintf("%s == %s && %s == %s && ip",
                                port_direction, op->json_key,
                                pipeline == P_IN ? "eth.src" : "eth.dst",
                                ps->ea_s);
        ovn_ctrl_lflow_add_uuid(lflows, stage, 80, match, "drop;",
                                &op->pb->header_.uuid, lflow_uuid_idx);
        free(match);
    }

}

/**
 * Build port security constraints on ARP and IPv6 ND fields
 * and add logical flows to S_SWITCH_IN_PORT_SEC_ND stage.
 *
 * For each port security of the logical port, following
 * logical flows are added
 *   - If the port security has no IP (both IPv4 and IPv6) or
 *     if it has IPv4 address(es)
 *      - Priority 90 flow to allow ARP packets for known MAC addresses
 *        in the eth.src and arp.spa fields. If the port security
 *        has IPv4 addresses, allow known IPv4 addresses in the arp.tpa field.
 *
 *   - If the port security has no IP (both IPv4 and IPv6) or
 *     if it has IPv6 address(es)
 *     - Priority 90 flow to allow IPv6 ND packets for known MAC addresses
 *       in the eth.src and nd.sll/nd.tll fields. If the port security
 *       has IPv6 addresses, allow known IPv6 addresses in the nd.target field
 *       for IPv6 Neighbor Advertisement packet.
 *
 *   - Priority 80 flow to drop ARP and IPv6 ND packets.
 */
static void
build_port_security_nd(struct local_lport *op, struct hmap *lflows,
                       uint8_t *lflow_uuid_idx)
{
    struct ds match = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < op->lsp.n_ps_addrs; i++) {
        struct lport_addresses *ps = &op->lsp.ps_addrs[i];

        bool no_ip = !(ps->n_ipv4_addrs || ps->n_ipv6_addrs);

        ds_clear(&match);
        if (ps->n_ipv4_addrs || no_ip) {
            ds_put_format(&match,
                          "inport == %s && eth.src == %s && arp.sha == %s",
                          op->json_key, ps->ea_s, ps->ea_s);

            if (ps->n_ipv4_addrs) {
                ds_put_cstr(&match, " && arp.spa == {");
                for (size_t j = 0; j < ps->n_ipv4_addrs; j++) {
                    /* When the netmask is applied, if the host portion is
                     * non-zero, the host can only use the specified
                     * address in the arp.spa.  If zero, the host is allowed
                     * to use any address in the subnet. */
                    if (ps->ipv4_addrs[j].plen == 32
                        || ps->ipv4_addrs[j].addr & ~ps->ipv4_addrs[j].mask) {
                        ds_put_cstr(&match, ps->ipv4_addrs[j].addr_s);
                    } else {
                        ds_put_format(&match, "%s/%d",
                                      ps->ipv4_addrs[j].network_s,
                                      ps->ipv4_addrs[j].plen);
                    }
                    ds_put_cstr(&match, ", ");
                }
                ds_chomp(&match, ' ');
                ds_chomp(&match, ',');
                ds_put_cstr(&match, "}");
            }
            ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PORT_SEC_ND,
                                    90, ds_cstr(&match), "next;",
                                    &op->pb->header_.uuid, lflow_uuid_idx);
        }

        if (ps->n_ipv6_addrs || no_ip) {
            ds_clear(&match);
            ds_put_format(&match, "inport == %s && eth.src == %s",
                          op->json_key, ps->ea_s);
            build_port_security_ipv6_nd_flow(&match, ps->ea, ps->ipv6_addrs,
                                             ps->n_ipv6_addrs);
            ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PORT_SEC_ND, 90,
                                    ds_cstr(&match), "next;",
                                    &op->pb->header_.uuid, lflow_uuid_idx);
        }
    }

    ds_clear(&match);
    ds_put_format(&match, "inport == %s && (arp || nd)", op->json_key);
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PORT_SEC_ND, 80,
                            ds_cstr(&match), "drop;", &op->pb->header_.uuid,
                            lflow_uuid_idx);
    ds_destroy(&match);
}

/* Logical switch ingress table 0: Ingress port security - L2
 *  (priority 50).
 *  Ingress table 1: Ingress port security - IP (priority 90 and 80)
 *  Ingress table 2: Ingress port security - ND (priority 90 and 80)
 */
static void
build_lswitch_input_port_sec_op(struct hmap *lflows, struct local_lport *op,
                                uint8_t *lflow_uuid_idx)
{
    if (op->type == LP_EXTERNAL) {
        return;
    }

    if (!lsp_is_enabled(op->pb)) {
        /* Drop packets from disabled logical ports (since logical flow
         * tables are default-drop). */
        return;
    }

    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    ds_put_format(&match, "inport == %s", op->json_key);
    build_port_security_l2("eth.src", op->lsp.ps_addrs, op->lsp.n_ps_addrs,
                            &match);

    const char *queue_id = smap_get(&op->pb->options, "qdisc_queue_id");
    if (queue_id) {
        ds_put_format(&actions, "set_queue(%s); ", queue_id);
    }
    ds_put_cstr(&actions, "next;");
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PORT_SEC_L2, 50,
                            ds_cstr(&match), ds_cstr(&actions),
                            &op->pb->header_.uuid, lflow_uuid_idx);

    ds_destroy(&match);
    ds_destroy(&actions);

    if (op->lsp.n_ps_addrs) {
        build_port_security_ip(P_IN, op, lflows, lflow_uuid_idx);
        build_port_security_nd(op, lflows, lflow_uuid_idx);
    }
}

/* Egress table 8: Egress port security - IP (priorities 90 and 80)
 * if port security enabled.
 *
 * Egress table 9: Egress port security - L2 (priorities 50 and 150).
 *
 * Priority 50 rules implement port security for enabled logical port.
 *
 * Priority 150 rules drop packets to disabled logical ports, so that
 * they don't even receive multicast or broadcast packets.
 */
static void
build_lswitch_output_port_sec_op(struct hmap *lflows, struct local_lport *op,
                                 uint8_t *lflow_uuid_idx)
{
    if (op->type == LP_EXTERNAL) {
        return;
    }

    struct ds match = DS_EMPTY_INITIALIZER;

    ds_put_format(&match, "outport == %s", op->json_key);
    if (lsp_is_enabled(op->pb)) {
        struct ds actions = DS_EMPTY_INITIALIZER;
        build_port_security_l2("eth.dst", op->lsp.ps_addrs, op->lsp.n_ps_addrs,
                                &match);

        if (op->type == LP_LOCALNET) {
            const char *queue_id = smap_get(&op->pb->options,
                                            "qdisc_queue_id");
            if (queue_id) {
                ds_put_format(&actions, "set_queue(%s); ", queue_id);
            }
        }
        ds_put_cstr(&actions, "output;");
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_PORT_SEC_L2,
                                50, ds_cstr(&match), ds_cstr(&actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
        ds_destroy(&actions);
    } else {
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_PORT_SEC_L2,
                                150, ds_cstr(&match), "drop;",
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    ds_destroy(&match);

    if (op->lsp.n_ps_addrs) {
        build_port_security_ip(P_OUT, op, lflows, lflow_uuid_idx);
    }
}

static void
build_lswitch_learn_fdb_op(struct hmap *lflows, struct local_lport *op,
                           uint8_t *lflow_uuid_idx, struct ds *match,
                           struct ds *actions)
{
    if (!op->lsp.n_ps_addrs && op->type == LP_VIF &&
            op->lsp.has_unknown) {
        ds_clear(match);
        ds_clear(actions);
        ds_put_format(match, "inport == %s", op->json_key);
        ds_put_format(actions, REGBIT_LKUP_FDB
                      " = lookup_fdb(inport, eth.src); next;");
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_LOOKUP_FDB, 100,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);

        ds_put_cstr(match, " && "REGBIT_LKUP_FDB" == 0");
        ds_clear(actions);
        ds_put_cstr(actions, "put_fdb(inport, eth.src); next;");
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PUT_FDB, 100,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }
}

/* Ingress table 13: ARP/ND responder, skip requests coming from localnet
 * and vtep ports. (priority 100); see ovn-northd.8.xml for the
 * rationale. */

static void
build_lswitch_arp_nd_responder_skip_local(struct hmap *lflows,
                                          struct local_lport *op,
                                          uint8_t *lflow_uuid_idx,
                                          struct ds *match)
{
    if (op->type == LP_LOCALNET || op->type == LP_VTEP) {
        ds_clear(match);
        ds_put_format(match, "inport == %s", op->json_key);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ARP_ND_RSP, 100,
                                ds_cstr(match), "next;",
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }
}

/* Ingress table 13: ARP/ND responder, reply for known IPs.
 * (priority 50). */
static void
build_lswitch_arp_nd_responder_known_ips(struct hmap *lflows,
                                         struct local_lport *op,
                                         uint8_t *lflow_uuid_idx,
                                         struct ds *match,
                                         struct ds *actions)
{
    if (op->type == LP_VIRTUAL) {
        /* Handle
            *  - GARPs for virtual ip which belongs to a logical port
            *    of type 'virtual' and bind that port.
            *
            *  - ARP reply from the virtual ip which belongs to a logical
            *    port of type 'virtual' and bind that port.
            * */
        ovs_be32 ip;
        const char *virtual_ip = smap_get(&op->pb->options,
                                          "virtual-ip");
        const char *virtual_parents = smap_get(&op->pb->options,
                                               "virtual-parents");
        if (!virtual_ip || !virtual_parents ||
            !ip_parse(virtual_ip, &ip)) {
            return;
        }

        char *tokstr = xstrdup(virtual_parents);
        char *save_ptr = NULL;
        char *vparent;
        for (vparent = strtok_r(tokstr, ",", &save_ptr); vparent != NULL;
                vparent = strtok_r(NULL, ",", &save_ptr)) {
            ds_clear(match);
            ds_put_format(match, "inport == \"%s\" && "
                          "((arp.op == 1 && arp.spa == %s && "
                          "arp.tpa == %s) || (arp.op == 2 && "
                          "arp.spa == %s))",
                          vparent, virtual_ip, virtual_ip,
                          virtual_ip);
            ds_clear(actions);
            ds_put_format(actions,
                "bind_vport(%s, inport); "
                "next;",
                op->json_key);
            ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ARP_ND_RSP, 100,
                                    ds_cstr(match), ds_cstr(actions),
                                    &op->pb->header_.uuid, lflow_uuid_idx);
        }

        free(tokstr);
    } else {
        /*
         * Add ARP/ND reply flows if either the
         *  - port is up and it doesn't have 'unknown' address defined or
         *  - port type is router or
         *  - port type is localport
         */
        if (op->lsp.check_lport_is_up &&
            !lsp_is_up(op->pb) && op->type != LP_PATCH &&
            op->type != LP_LOCALPORT) {
            return;
        }

        if (op->type == LP_EXTERNAL || op->lsp.has_unknown) {
            return;
        }

        for (size_t i = 0; i < op->lsp.n_addrs; i++) {
            for (size_t j = 0; j < op->lsp.addrs[i].n_ipv4_addrs; j++) {
                ds_clear(match);
                ds_put_format(match, "arp.tpa == %s && arp.op == 1",
                              op->lsp.addrs[i].ipv4_addrs[j].addr_s);
                ds_clear(actions);
                ds_put_format(actions,
                    "eth.dst = eth.src; "
                    "eth.src = %s; "
                    "arp.op = 2; /* ARP reply */ "
                    "arp.tha = arp.sha; "
                    "arp.sha = %s; "
                    "arp.tpa = arp.spa; "
                    "arp.spa = %s; "
                    "outport = inport; "
                    "flags.loopback = 1; "
                    "output;",
                    op->lsp.addrs[i].ea_s, op->lsp.addrs[i].ea_s,
                    op->lsp.addrs[i].ipv4_addrs[j].addr_s);
                ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ARP_ND_RSP, 50,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->pb->header_.uuid, lflow_uuid_idx);

                /* Do not reply to an ARP request from the port that owns
                    * the address (otherwise a DHCP client that ARPs to check
                    * for a duplicate address will fail).  Instead, forward
                    * it the usual way.
                    *
                    * (Another alternative would be to simply drop the packet.
                    * If everything is working as it is configured, then this
                    * would produce equivalent results, since no one should
                    * reply to the request.  But ARPing for one's own IP
                    * address is intended to detect situations where the
                    * network is not working as configured, so dropping the
                    * request would frustrate that intent.) */
                ds_put_format(match, " && inport == %s", op->json_key);
                ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ARP_ND_RSP, 100,
                                        ds_cstr(match), "next;",
                                        &op->pb->header_.uuid, lflow_uuid_idx);
            }

            /* For ND solicitations, we need to listen for both the
                * unicast IPv6 address and its all-nodes multicast address,
                * but always respond with the unicast IPv6 address. */
            for (size_t j = 0; j < op->lsp.addrs[i].n_ipv6_addrs; j++) {
                ds_clear(match);
                ds_put_format(
                    match,
                    "nd_ns && ip6.dst == {%s, %s} && nd.target == %s",
                    op->lsp.addrs[i].ipv6_addrs[j].addr_s,
                    op->lsp.addrs[i].ipv6_addrs[j].sn_addr_s,
                    op->lsp.addrs[i].ipv6_addrs[j].addr_s);

                ds_clear(actions);
                ds_put_format(actions,
                        "%s { "
                        "eth.src = %s; "
                        "ip6.src = %s; "
                        "nd.target = %s; "
                        "nd.tll = %s; "
                        "outport = inport; "
                        "flags.loopback = 1; "
                        "output; "
                        "};",
                        op->type == LP_PATCH ? "nd_na_router" : "nd_na",
                        op->lsp.addrs[i].ea_s,
                        op->lsp.addrs[i].ipv6_addrs[j].addr_s,
                        op->lsp.addrs[i].ipv6_addrs[j].addr_s,
                        op->lsp.addrs[i].ea_s);
                ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ARP_ND_RSP, 50,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->pb->header_.uuid, lflow_uuid_idx);

                /* Do not reply to a solicitation from the port that owns
                    * the address (otherwise DAD detection will fail). */
                ds_put_format(match, " && inport == %s", op->json_key);
                ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ARP_ND_RSP, 100,
                                        ds_cstr(match), "next;",
                                        &op->pb->header_.uuid, lflow_uuid_idx);
            }
        }
    }
}

/* Ingress table 19: Destination lookup, unicast handling (priority 50), */
static void
build_lswitch_ip_unicast_lookup(struct hmap *lflows, struct local_lport *op,
                                uint8_t *lflow_uuid_idx,
                                struct ds *match, struct ds *actions)
{
    if (op->type == LP_EXTERNAL) {
        return;
    }

    /* For ports connected to logical routers add flows to bypass the
     * broadcast flooding of ARP/ND requests in table 19. We direct the
     * requests only to the router port that owns the IP address.
     */
#if 0
    if (lsp_is_router(op->nbsp)) {
        build_lswitch_rport_arp_req_flows(op->peer, op->od, op, lflows,
                                            &op->nbsp->header_);
    }
#endif

    for (size_t i = 0; i < op->lsp.n_addrs; i++) {
        ds_clear(match);
        ds_put_format(match, "eth.dst == %s", op->lsp.addrs[i].ea_s);
        ds_clear(actions);
        ds_put_format(actions, "outport = %s; output;", op->json_key);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_L2_LKUP, 50,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }
}

static void build_adm_ctrl_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);
static void build_neigh_learning_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);
static void build_ip_routing_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);
static void build_ND_RA_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);
static void build_dhcpv6_reply_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match);
static void build_ipv6_input_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);
static void build_lrouter_nd_flow(struct hmap *lflows, struct local_lport *op,
                                  const struct uuid *flow_uuid,
                                  uint8_t *lflow_uuid_idx, const char *action,
                                  const char *ip_address,
                                  const char *sn_ip_address,
                                  const char *eth_addr,
                                  struct ds *extra_match, bool drop,
                                  uint16_t priority);
static void build_lrouter_bfd_flows(struct hmap *lflows,
                                    struct local_lport *op,
                                    uint8_t *lflow_uuid_idx);
static void build_lrouter_arp_flow(
    struct hmap *lflows, struct local_lport *,
    const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx,
    const char *ip_address, const char *eth_addr,
    struct ds *extra_match, bool drop, uint16_t priority);
static void build_lrouter_ipv4_ip_input(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);
static void build_lrouter_force_snat_flows_op(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx,
    struct ds *match, struct ds *actions);
static void build_arp_resolve_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    struct ds *match, struct ds *actions);
static void build_egress_delivery_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions);

static void op_put_v4_networks(struct ds *ds, const struct local_lport *op,
                               bool add_bcast);

static void op_put_v6_networks(struct ds *ds, const struct local_lport *op);
static void add_route(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions,
    const char *lrp_addr_s, const char *network_s, int plen,
    const char *gateway, bool is_src_route, bool is_discard_route);

/* Router port lflows. */
static void
build_lrouter_port_lflows(struct hmap *lflows, struct local_lport *op)
{
    uint8_t lflow_uuid_idx = 1;
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    build_adm_ctrl_flows_for_lrouter_port(lflows, op,
                                          &lflow_uuid_idx, &match, &actions);
    build_neigh_learning_flows_for_lrouter_port(lflows, op,
                                                &lflow_uuid_idx, &match,
                                                &actions);
    build_ip_routing_flows_for_lrouter_port(lflows, op,
                                            &lflow_uuid_idx, &match, &actions);
    build_ND_RA_flows_for_lrouter_port(lflows, op,
                                       &lflow_uuid_idx, &match, &actions);
    build_dhcpv6_reply_flows_for_lrouter_port(lflows, op,
                                              &lflow_uuid_idx, &match);
    build_ipv6_input_flows_for_lrouter_port(lflows, op,
                                            &lflow_uuid_idx, &match, &actions);
    build_lrouter_ipv4_ip_input(lflows, op, &lflow_uuid_idx,
                                &match, &actions);
    build_lrouter_force_snat_flows_op(lflows, op, &lflow_uuid_idx,
                                      &match, &actions);
    build_arp_resolve_flows_for_lrouter_port(lflows, op, &match, &actions);
    build_egress_delivery_flows_for_lrouter_port(lflows, op,
                                                 &lflow_uuid_idx,
                                                 &match, &actions);

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Logical router ingress Table 0: L2 Admission Control
 * This table drops packets that the router shouldn’t see at all based
 * on their Ethernet headers.
 */
static void
build_adm_ctrl_flows_for_lrouter_port(struct hmap *lflows,
                                      struct local_lport *op,
                                      uint8_t *lflow_uuid_idx,
                                      struct ds *match, struct ds *actions)
{
#if 0
TODO:
    if (!lrport_is_enabled(op->nbrp)) {
        /* Drop packets from disabled logical ports (since logical flow
            * tables are default-drop). */
        return;
    }
#endif

    if (op->type == LP_CHASSISREDIRECT) {
        /* No ingress packets should be received on a chassisredirect port. */
        return;
    }

    /* Store the ethernet address of the port receiving the packet.
     * This will save us from having to match on inport further down in
     * the pipeline.
     */
    ds_clear(actions);
    ds_put_format(actions, REG_INPORT_ETH_ADDR " = %s; next;",
                  op->lrp.networks.ea_s);

    ds_clear(match);
    ds_put_format(match, "eth.mcast && inport == %s", op->json_key);
    ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_ADMISSION, 50, ds_cstr(match),
                            ds_cstr(actions), &op->pb->header_.uuid,
                            lflow_uuid_idx);

    ds_clear(match);
    ds_put_format(match, "eth.dst == %s && inport == %s",
                  op->lrp.networks.ea_s, op->json_key);
    if (op->lrp.is_l3dgw_port) {
        /* Traffic with eth.dst = l3dgw_port->lrp_networks.ea_s
         * should only be received on the gateway chassis. */
        ds_put_format(match, " && is_chassis_resident(%s)",
                      op->lrp.chassis_redirect_json_key);
    }
    ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_ADMISSION, 50, ds_cstr(match),
                            ds_cstr(actions), &op->pb->header_.uuid,
                            lflow_uuid_idx);
}

/* Logical router ingress Table 1: Neighbor lookup lflows
 * for logical router ports. */
static void
build_neigh_learning_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx,
    struct ds *match, struct ds *actions)
{
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    bool learn_from_arp_request = is_learn_from_arp_request(op->pb->datapath);

    /* Check if we need to learn mac-binding from ARP requests. */
    for (int i = 0; i < op->lrp.networks.n_ipv4_addrs; i++) {
        if (!learn_from_arp_request) {
            /* ARP request to this address should always get learned,
                * so add a priority-110 flow to set
                * REGBIT_LOOKUP_NEIGHBOR_IP_RESULT to 1. */
            ds_clear(match);
            ds_put_format(match,
                          "inport == %s && arp.spa == %s/%u && "
                          "arp.tpa == %s && arp.op == 1",
                          op->json_key,
                          op->lrp.networks.ipv4_addrs[i].network_s,
                          op->lrp.networks.ipv4_addrs[i].plen,
                          op->lrp.networks.ipv4_addrs[i].addr_s);
            if (op->lrp.is_l3dgw_port) {
                ds_put_format(match, " && is_chassis_resident(%s)",
                              op->lrp.chassis_redirect_json_key);
            }
            const char *actions_s = REGBIT_LOOKUP_NEIGHBOR_RESULT
                                    " = lookup_arp(inport, arp.spa, arp.sha); "
                                    REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1;"
                                    " next;";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 110,
                                    ds_cstr(match), actions_s,
                                    &op->pb->header_.uuid, lflow_uuid_idx);
        }
        ds_clear(match);
        ds_put_format(match,
                      "inport == %s && arp.spa == %s/%u && arp.op == 1",
                      op->json_key,
                      op->lrp.networks.ipv4_addrs[i].network_s,
                      op->lrp.networks.ipv4_addrs[i].plen);
        if (op->lrp.is_l3dgw_port) {
            ds_put_format(match, " && is_chassis_resident(%s)",
                          op->lrp.chassis_redirect_json_key);
        }
        ds_clear(actions);
        ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                        " = lookup_arp(inport, arp.spa, arp.sha); %snext;",
                        learn_from_arp_request ? "" :
                        REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
                        " = lookup_arp_ip(inport, arp.spa); ");
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }
}

/* Logical router ingress table IP_ROUTING : IP Routing.
 *
 * A packet that arrives at this table is an IP packet that should be
 * routed to the address in 'ip[46].dst'.
 *
 * For regular routes without ECMP, table IP_ROUTING sets outport to the
 * correct output port, eth.src to the output port's MAC address, and
 * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 to the next-hop IP address
 * (leaving 'ip[46].dst', the packet’s final destination, unchanged), and
 * advances to the next table.
 *
 * For ECMP routes, i.e. multiple routes with same policy and prefix, table
 * IP_ROUTING remembers ECMP group id and selects a member id, and advances
 * to table IP_ROUTING_ECMP, which sets outport, eth.src and
 * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 for the selected ECMP member.
 */
static void
build_ip_routing_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions)
{
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    for (int i = 0; i < op->lrp.networks.n_ipv4_addrs; i++) {
        add_route(lflows, op, lflow_uuid_idx, match, actions,
                  op->lrp.networks.ipv4_addrs[i].addr_s,
                  op->lrp.networks.ipv4_addrs[i].network_s,
                  op->lrp.networks.ipv4_addrs[i].plen, NULL, false, false);
    }

    for (int i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
        add_route(lflows, op, lflow_uuid_idx, match, actions,
                  op->lrp.networks.ipv6_addrs[i].addr_s,
                  op->lrp.networks.ipv6_addrs[i].network_s,
                  op->lrp.networks.ipv6_addrs[i].plen, NULL, false, false);
    }
}

/* Logical router ingress table ND_RA_OPTIONS & ND_RA_RESPONSE: IPv6 Router
 * Adv (RA) options and response. */
static void
build_ND_RA_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions)
{
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    if (!op->lrp.networks.n_ipv6_addrs) {
        return;
    }

    const char *address_mode = smap_get(&op->pb->options,
                                        "ipv6_ra_address_mode");
    if (!address_mode) {
        return;
    }

    if (strcmp(address_mode, "slaac") &&
        strcmp(address_mode, "dhcpv6_stateful") &&
        strcmp(address_mode, "dhcpv6_stateless")) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid address mode [%s] defined",
                     address_mode);
        return;
    }

    ds_clear(match);
    ds_put_format(match, "inport == %s && ip6.dst == ff02::2 && nd_rs",
                  op->json_key);
    ds_clear(actions);

    const char *mtu_s = smap_get(&op->pb->options, "ipv6_ra_mtu");

    /* As per RFC 2460, 1280 is minimum IPv6 MTU. */
    uint32_t mtu = (mtu_s && atoi(mtu_s) >= 1280) ? atoi(mtu_s) : 0;

    ds_put_format(actions, REGBIT_ND_RA_OPTS_RESULT" = put_nd_ra_opts("
                  "addr_mode = \"%s\", slla = %s",
                  address_mode, op->lrp.networks.ea_s);
    if (mtu > 0) {
        ds_put_format(actions, ", mtu = %u", mtu);
    }

    const char *prf = smap_get_def(&op->pb->options, "ipv6_ra_prf", "MEDIUM");
    if (strcmp(prf, "MEDIUM")) {
        ds_put_format(actions, ", router_preference = \"%s\"", prf);
    }

    bool add_rs_response_flow = false;

    for (size_t i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
        if (in6_is_lla(&op->lrp.networks.ipv6_addrs[i].network)) {
            continue;
        }

        ds_put_format(actions, ", prefix = %s/%u",
                      op->lrp.networks.ipv6_addrs[i].network_s,
                      op->lrp.networks.ipv6_addrs[i].plen);

        add_rs_response_flow = true;
    }

    if (add_rs_response_flow) {
        ds_put_cstr(actions, "); next;");
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_ND_RA_OPTIONS,
                                50, ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
        ds_clear(actions);
        ds_clear(match);
        ds_put_format(match, "inport == %s && ip6.dst == ff02::2 && "
                      "nd_ra && "REGBIT_ND_RA_OPTS_RESULT, op->json_key);

        char ip6_str[INET6_ADDRSTRLEN + 1];
        struct in6_addr lla;
        in6_generate_lla(op->lrp.networks.ea, &lla);
        memset(ip6_str, 0, sizeof(ip6_str));
        ipv6_string_mapped(ip6_str, &lla);
        ds_put_format(actions, "eth.dst = eth.src; eth.src = %s; "
                      "ip6.dst = ip6.src; ip6.src = %s; "
                      "outport = inport; flags.loopback = 1; "
                      "output;",
                      op->lrp.networks.ea_s, ip6_str);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_ND_RA_RESPONSE, 50,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }
}

static void
build_dhcpv6_reply_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match)
{
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    for (size_t i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
        ds_clear(match);
        ds_put_format(match, "ip6.dst == %s && udp.src == 547 &&"
                      " udp.dst == 546",
                      op->lrp.networks.ipv6_addrs[i].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 100,
                                ds_cstr(match),
                                "reg0 = 0; handle_dhcpv6_reply;",
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }
}

static void
build_ipv6_input_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions)
{
    /* No ingress packets are accepted on a chassisredirect
     * port, so no need to program flows for that port. */
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    if (op->lrp.networks.n_ipv6_addrs) {
        /* ICMPv6 echo reply.  These flows reply to echo requests
            * received for the router's IP address. */
        ds_clear(match);
        ds_put_cstr(match, "ip6.dst == ");
        op_put_v6_networks(match, op);
        ds_put_cstr(match, " && icmp6.type == 128 && icmp6.code == 0");

        const char *lrp_actions =
                    "ip6.dst <-> ip6.src; "
                    "ip.ttl = 255; "
                    "icmp6.type = 129; "
                    "flags.loopback = 1; "
                    "next; ";
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 90,
                                ds_cstr(match), lrp_actions,
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    /* ND reply.  These flows reply to ND solicitations for the
     * router's own IP address. */
    for (size_t i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
        ds_clear(match);
        if (op->lrp.is_l3dgw_port && op->lrp.chassis_redirect_json_key) {
            /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
                * should only be sent from the gateway chassi, so that
                * upstream MAC learning points to the gateway chassis.
                * Also need to avoid generation of multiple ND replies
                * from different chassis. */
            ds_put_format(match, "is_chassis_resident(%s)",
                          op->lrp.chassis_redirect_json_key);
        }

        build_lrouter_nd_flow(lflows, op, &op->pb->header_.uuid,
                              lflow_uuid_idx, "nd_na_router",
                              op->lrp.networks.ipv6_addrs[i].addr_s,
                              op->lrp.networks.ipv6_addrs[i].sn_addr_s,
                              REG_INPORT_ETH_ADDR, match, false, 90);
    }

    /* UDP/TCP/SCTP port unreachable */
    if (op->type != LP_L3GATEWAY && !op->lrp.dp_has_l3dgw_port) {
        for (int i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
            ds_clear(match);
            ds_put_format(match,
                          "ip6 && ip6.dst == %s && !ip.later_frag && tcp",
                          op->lrp.networks.ipv6_addrs[i].addr_s);
            const char *action = "tcp_reset {"
                                 "eth.dst <-> eth.src; "
                                 "ip6.dst <-> ip6.src; "
                                 "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    80, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);

            ds_clear(match);
            ds_put_format(match,
                            "ip6 && ip6.dst == %s && !ip.later_frag && sctp",
                            op->lrp.networks.ipv6_addrs[i].addr_s);
            action = "sctp_abort {"
                        "eth.dst <-> eth.src; "
                        "ip6.dst <-> ip6.src; "
                        "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    80, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);

            ds_clear(match);
            ds_put_format(match,
                            "ip6 && ip6.dst == %s && !ip.later_frag && udp",
                            op->lrp.networks.ipv6_addrs[i].addr_s);
            action = "icmp6 {"
                        "eth.dst <-> eth.src; "
                        "ip6.dst <-> ip6.src; "
                        "ip.ttl = 255; "
                        "icmp6.type = 1; "
                        "icmp6.code = 4; "
                        "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    80, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);

            ds_clear(match);
            ds_put_format(match,
                            "ip6 && ip6.dst == %s && !ip.later_frag",
                            op->lrp.networks.ipv6_addrs[i].addr_s);
            action = "icmp6 {"
                        "eth.dst <-> eth.src; "
                        "ip6.dst <-> ip6.src; "
                        "ip.ttl = 255; "
                        "icmp6.type = 1; "
                        "icmp6.code = 3; "
                        "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    70, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);
        }
    }

    /* ICMPv6 time exceeded */
    for (int i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
        /* skip link-local address */
        if (in6_is_lla(&op->lrp.networks.ipv6_addrs[i].network)) {
            continue;
        }

        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match,
                      "inport == %s && ip6 && "
                      "ip6.src == %s/%d && "
                      "ip.ttl == {0, 1} && !ip.later_frag",
                      op->json_key,
                      op->lrp.networks.ipv6_addrs[i].network_s,
                      op->lrp.networks.ipv6_addrs[i].plen);
        ds_put_format(actions,
                      "icmp6 {"
                      "eth.dst <-> eth.src; "
                      "ip6.dst = ip6.src; "
                      "ip6.src = %s; "
                      "ip.ttl = 255; "
                      "icmp6.type = 3; /* Time exceeded */ "
                      "icmp6.code = 0; /* TTL exceeded in transit */ "
                      "next; };",
                      op->lrp.networks.ipv6_addrs[i].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 40,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

}

/* Builds the logical flow that replies to NS requests for an 'ip_address'
 * owned by the router. The flow is inserted in table S_ROUTER_IN_IP_INPUT
 * with the given priority. If 'sn_ip_address' is non-NULL, requests are
 * restricted only to packets with IP destination 'ip_address' or
 * 'sn_ip_address'.
 */
static void
build_lrouter_nd_flow(struct hmap *lflows, struct local_lport *op,
                      const struct uuid *flow_uuid, uint8_t *lflow_uuid_idx,
                      const char *action, const char *ip_address,
                      const char *sn_ip_address, const char *eth_addr,
                      struct ds *extra_match, bool drop, uint16_t priority)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    if (op) {
        ds_put_format(&match, "inport == %s && ", op->json_key);
    }

    if (sn_ip_address) {
        ds_put_format(&match, "ip6.dst == {%s, %s} && ",
                      ip_address, sn_ip_address);
    }

    ds_put_format(&match, "nd_ns && nd.target == %s", ip_address);

    if (extra_match && ds_last(extra_match) != EOF) {
        ds_put_format(&match, " && %s", ds_cstr(extra_match));
    }

    if (drop) {
        ds_put_format(&actions, "drop;");
    } else {
        ds_put_format(&actions,
                      "%s { "
                        "eth.src = %s; "
                        "ip6.src = %s; "
                        "nd.target = %s; "
                        "nd.tll = %s; "
                        "outport = inport; "
                        "flags.loopback = 1; "
                        "output; "
                      "};",
                      action,
                      eth_addr,
                      ip_address,
                      ip_address,
                      eth_addr);
    }

    ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, priority,
                            ds_cstr(&match), ds_cstr(&actions),
                            flow_uuid, lflow_uuid_idx);

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Logical router ingress table 3: IP Input for IPv4. */
static void
build_lrouter_ipv4_ip_input(struct hmap *lflows, struct local_lport *op,
                            uint8_t *lflow_uuid_idx, struct ds *match,
                            struct ds *actions)
{
    /* No ingress packets are accepted on a chassisredirect
     * port, so no need to program flows for that port. */
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    if (op->lrp.networks.n_ipv4_addrs) {
        /* L3 admission control: drop packets that originate from an
         * IPv4 address owned by the router or a broadcast address
         * known to the router (priority 100). */
        ds_clear(match);
        ds_put_cstr(match, "ip4.src == ");
        op_put_v4_networks(match, op, true);
        ds_put_cstr(match, " && "REGBIT_EGRESS_LOOPBACK" == 0");
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 100,
                                ds_cstr(match), "drop;",
                                &op->pb->header_.uuid, lflow_uuid_idx);

        /* ICMP echo reply.  These flows reply to ICMP echo requests
         * received for the router's IP address. Since packets only
         * get here as part of the logical router datapath, the inport
         * (i.e. the incoming locally attached net) does not matter.
         * The ip.ttl also does not matter (RFC1812 section 4.2.2.9) */
        ds_clear(match);
        ds_put_cstr(match, "ip4.dst == ");
        op_put_v4_networks(match, op, false);
        ds_put_cstr(match, " && icmp4.type == 8 && icmp4.code == 0");

        const char * icmp_actions = "ip4.dst <-> ip4.src; "
                        "ip.ttl = 255; "
                        "icmp4.type = 0; "
                        "flags.loopback = 1; "
                        "next; ";
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 90,
                                ds_cstr(match), icmp_actions,
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    /* BFD msg handling */
    build_lrouter_bfd_flows(lflows, op, lflow_uuid_idx);

    /* ICMP time exceeded */
    for (int i = 0; i < op->lrp.networks.n_ipv4_addrs; i++) {
        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match,
                      "inport == %s && ip4 && "
                      "ip.ttl == {0, 1} && !ip.later_frag", op->json_key);
        ds_put_format(actions,
                      "icmp4 {"
                      "eth.dst <-> eth.src; "
                      "icmp4.type = 11; /* Time exceeded */ "
                      "icmp4.code = 0; /* TTL exceeded in transit */ "
                      "ip4.dst = ip4.src; "
                      "ip4.src = %s; "
                      "ip.ttl = 255; "
                      "next; };",
                      op->lrp.networks.ipv4_addrs[i].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 40,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    /* ARP reply.  These flows reply to ARP requests for the router's own
     * IP address. */
    for (int i = 0; i < op->lrp.networks.n_ipv4_addrs; i++) {
        ds_clear(match);
        ds_put_format(match, "arp.spa == %s/%u",
                      op->lrp.networks.ipv4_addrs[i].network_s,
                      op->lrp.networks.ipv4_addrs[i].plen);

        if (op->lrp.dp_has_l3dgw_port && op->peer
                && op->lrp.peer_dp_has_localnet_ports) {
            bool add_chassis_resident_check = false;
            if (op->lrp.is_l3dgw_port) {
                /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
                 * should only be sent from the gateway chassis, so that
                 * upstream MAC learning points to the gateway chassis.
                 * Also need to avoid generation of multiple ARP responses
                 * from different chassis. */
                add_chassis_resident_check = true;
            } else {
                /* Check if the option 'reside-on-redirect-chassis'
                    * is set to true on the router port. If set to true
                    * and if peer's logical switch has a localnet port, it
                    * means the router pipeline for the packets from
                    * peer's logical switch is be run on the chassis
                    * hosting the gateway port and it should reply to the
                    * ARP requests for the router port IPs.
                    */
                add_chassis_resident_check = smap_get_bool(
                    &op->pb->options,
                    "reside-on-redirect-chassis", false);
            }

            if (add_chassis_resident_check) {
                ds_put_format(match, " && is_chassis_resident(%s)",
                              op->lrp.chassis_redirect_json_key);
            }
        }

        build_lrouter_arp_flow(lflows, op, &op->pb->header_.uuid,
                               lflow_uuid_idx,
                               op->lrp.networks.ipv4_addrs[i].addr_s,
                               REG_INPORT_ETH_ADDR, match, false, 90);
    }

    if (op->type != LP_L3GATEWAY && !op->lrp.dp_has_l3dgw_port) {
        /* UDP/TCP/SCTP port unreachable. */
        for (int i = 0; i < op->lrp.networks.n_ipv4_addrs; i++) {
            ds_clear(match);
            ds_put_format(match,
                          "ip4 && ip4.dst == %s && !ip.later_frag && udp",
                          op->lrp.networks.ipv4_addrs[i].addr_s);
            const char *action = "icmp4 {"
                                    "eth.dst <-> eth.src; "
                                    "ip4.dst <-> ip4.src; "
                                    "ip.ttl = 255; "
                                    "icmp4.type = 3; "
                                    "icmp4.code = 3; "
                                    "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    80, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);

            ds_clear(match);
            ds_put_format(match,
                            "ip4 && ip4.dst == %s && !ip.later_frag && tcp",
                            op->lrp.networks.ipv4_addrs[i].addr_s);
            action = "tcp_reset {"
                        "eth.dst <-> eth.src; "
                        "ip4.dst <-> ip4.src; "
                        "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    80, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);

            ds_clear(match);
            ds_put_format(match,
                            "ip4 && ip4.dst == %s && !ip.later_frag && sctp",
                            op->lrp.networks.ipv4_addrs[i].addr_s);
            action = "sctp_abort {"
                        "eth.dst <-> eth.src; "
                        "ip4.dst <-> ip4.src; "
                        "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    80, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);

            ds_clear(match);
            ds_put_format(match,
                            "ip4 && ip4.dst == %s && !ip.later_frag",
                            op->lrp.networks.ipv4_addrs[i].addr_s);
            action = "icmp4 {"
                        "eth.dst <-> eth.src; "
                        "ip4.dst <-> ip4.src; "
                        "ip.ttl = 255; "
                        "icmp4.type = 3; "
                        "icmp4.code = 2; "
                        "next; };";
            ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT,
                                    70, ds_cstr(match), action,
                                    &op->pb->header_.uuid, lflow_uuid_idx);
        }
    }
}

static void
build_lrouter_bfd_flows(struct hmap *lflows, struct local_lport *op,
                        uint8_t *lflow_uuid_idx)
{
    if (!op->lrp.has_bfd) {
        return;
    }

    struct ds ip_list = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;

    if (op->lrp.networks.n_ipv4_addrs) {
        op_put_v4_networks(&ip_list, op, false);
        ds_put_format(&match, "ip4.src == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "next; ",
                                &op->pb->header_.uuid, lflow_uuid_idx);
        ds_clear(&match);
        ds_put_format(&match, "ip4.dst == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "handle_bfd_msg(); ",
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    if (op->lrp.networks.n_ipv6_addrs) {
        ds_clear(&ip_list);
        ds_clear(&match);

        op_put_v6_networks(&ip_list, op);
        ds_put_format(&match, "ip6.src == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "next; ",
                                &op->pb->header_.uuid, lflow_uuid_idx);
        ds_clear(&match);
        ds_put_format(&match, "ip6.dst == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "handle_bfd_msg(); ",
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    ds_destroy(&ip_list);
    ds_destroy(&match);
}

/* Builds the logical flow that replies to ARP requests for an 'ip_address'
 * owned by the router. The flow is inserted in table S_ROUTER_IN_IP_INPUT
 * with the given priority.
 */
static void
build_lrouter_arp_flow(struct hmap *lflows, struct local_lport *op,
                       const struct uuid *lflow_uuid, uint8_t *lflow_uuid_idx,
                       const char *ip_address, const char *eth_addr,
                       struct ds *extra_match, bool drop, uint16_t priority)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    if (op) {
        ds_put_format(&match, "inport == %s && ", op->json_key);
    }

    ds_put_format(&match, "arp.op == 1 && arp.tpa == %s", ip_address);

    if (extra_match && ds_last(extra_match) != EOF) {
        ds_put_format(&match, " && %s", ds_cstr(extra_match));
    }
    if (drop) {
        ds_put_format(&actions, "drop;");
    } else {
        ds_put_format(&actions,
                      "eth.dst = eth.src; "
                      "eth.src = %s; "
                      "arp.op = 2; /* ARP reply */ "
                      "arp.tha = arp.sha; "
                      "arp.sha = %s; "
                      "arp.tpa <-> arp.spa; "
                      "outport = inport; "
                      "flags.loopback = 1; "
                      "output;",
                      eth_addr,
                      eth_addr);
    }

    ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_INPUT, priority,
                            ds_cstr(&match), ds_cstr(&actions),
                            lflow_uuid, lflow_uuid_idx);

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_lrouter_force_snat_flows_op(struct hmap *lflows, struct local_lport *op,
                                  uint8_t *lflow_uuid_idx, struct ds *match,
                                  struct ds *actions)
{
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

    if (!op->peer || !smap_get_bool(&op->pb->datapath->options,
                                    "lb-force-snat-router-ip", false)) {
        return;
    }

    if (op->lrp.networks.n_ipv4_addrs) {
        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match, "inport == %s && ip4.dst == %s",
                      op->json_key, op->lrp.networks.ipv4_addrs[0].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_UNSNAT, 110,
                                ds_cstr(match), "ct_snat;",
                                &op->pb->header_.uuid, lflow_uuid_idx);

        ds_clear(match);

        /* Higher priority rules to force SNAT with the router port ip.
         * This only takes effect when the packet has already been
         * load balanced once. */
        ds_put_format(match, "flags.force_snat_for_lb == 1 && ip4 && "
                      "outport == %s", op->json_key);
        ds_put_format(actions, "ct_snat(%s);",
                      op->lrp.networks.ipv4_addrs[0].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_OUT_SNAT, 110,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
        if (op->lrp.networks.n_ipv4_addrs > 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Logical router port %s is configured with "
                              "multiple IPv4 addresses.  Only the first "
                              "IP [%s] is considered as SNAT for load "
                              "balancer", op->json_key,
                              op->lrp.networks.ipv4_addrs[0].addr_s);
        }
    }

    /* op->lrp.networks.ipv6_addrs will always have LLA and that will be
     * last in the list. So add the flows only if n_ipv6_addrs > 1. */
    if (op->lrp.networks.n_ipv6_addrs > 1) {
        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match, "inport == %s && ip6.dst == %s",
                      op->json_key, op->lrp.networks.ipv6_addrs[0].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_UNSNAT, 110,
                                ds_cstr(match), "ct_snat;",
                                &op->pb->header_.uuid, lflow_uuid_idx);

        ds_clear(match);

        /* Higher priority rules to force SNAT with the router port ip.
         * This only takes effect when the packet has already been
         * load balanced once. */
        ds_put_format(match, "flags.force_snat_for_lb == 1 && ip6 && "
                      "outport == %s", op->json_key);
        ds_put_format(actions, "ct_snat(%s);",
                      op->lrp.networks.ipv6_addrs[0].addr_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_OUT_SNAT, 110,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
        if (op->lrp.networks.n_ipv6_addrs > 2) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Logical router port %s is configured with "
                              "multiple IPv6 addresses.  Only the first "
                              "IP [%s] is considered as SNAT for load "
                              "balancer", op->json_key,
                              op->lrp.networks.ipv6_addrs[0].addr_s);
        }
    }
}

/* Local router ingress table ARP_RESOLVE: ARP Resolution.
 *
 * Any unicast packet that reaches this table is an IP packet whose
 * next-hop IP address is in REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6
 * (ip4.dst/ipv6.dst is the final destination).
 * This table resolves the IP address in
 * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 into an output port in outport and
 * an Ethernet address in eth.dst.
 */
static void
build_arp_resolve_flows_for_lrouter_port(
        struct hmap *lflows, struct local_lport *op,
        struct ds *match, struct ds *actions)
{
    if (!op->peer) {
        return;
    }

    /* This is a logical router port. If next-hop IP address in
        * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 matches IP address of this
        * router port, then the packet is intended to eventually be sent
        * to this logical port. Set the destination mac address using
        * this port's mac address.
        *
        * The packet is still in peer's logical pipeline. So the match
        * should be on peer's outport. */
    if (op->peer && !op->peer->ldp->is_switch) {
        /* Both the peer's are router ports. */
        if (op->peer->lrp.networks.n_ipv4_addrs) {
            ds_clear(match);
            ds_put_format(match, "outport == %s && "
                          REG_NEXT_HOP_IPV4 " == ",
                          op->json_key);
            op_put_v4_networks(match, op->peer, false);

            ds_clear(actions);
            ds_put_format(actions, "eth.dst = %s; next;",
                          op->peer->lrp.networks.ea_s);
            ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_RESOLVE, 100,
                               ds_cstr(match), ds_cstr(actions));
        }

        if (op->peer->lrp.networks.n_ipv6_addrs) {
            ds_clear(match);
            ds_put_format(match, "outport == %s && "
                          REG_NEXT_HOP_IPV4 " == ",
                          op->json_key);
            op_put_v6_networks(match, op->peer);

            ds_clear(actions);
            ds_put_format(actions, "eth.dst = %s; next;",
                          op->peer->lrp.networks.ea_s);
            ovn_ctrl_lflow_add(lflows, S_ROUTER_IN_ARP_RESOLVE, 100,
                               ds_cstr(match), ds_cstr(actions));
        }
    }
}

/* Logical router egress table DELIVERY: Delivery (priority 100-110).
 *
 * Priority 100 rules deliver packets to enabled logical ports.
 * Priority 110 rules match multicast packets and update the source
 * mac before delivering to enabled logical ports. IP multicast traffic
 * bypasses S_ROUTER_IN_IP_ROUTING route lookups.
 */
static void
build_egress_delivery_flows_for_lrouter_port(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions)
{
    if (op->type == LP_CHASSISREDIRECT) {
        return;
    }

#if 0
TODO
    if (!lrport_is_enabled(op->nbrp)) {
        /* Drop packets to disabled logical ports (since logical flow
            * tables are default-drop). */
        return;
    }
#endif

    /* If multicast relay is enabled then also adjust source mac for IP
        * multicast traffic.
        */
    if (smap_get_bool(&op->pb->datapath->options, "mcast-relay", false)) {
        ds_clear(match);
        ds_clear(actions);
        ds_put_format(match, "(ip4.mcast || ip6.mcast) && outport == %s",
                      op->json_key);
        ds_put_format(actions, "eth.src = %s; output;", op->lrp.networks.ea_s);
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_OUT_DELIVERY, 110,
                                ds_cstr(match), ds_cstr(actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    ds_clear(match);
    ds_put_format(match, "outport == %s", op->json_key);
    ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_OUT_DELIVERY, 100,
                            ds_cstr(match), "output;",
                            &op->pb->header_.uuid, lflow_uuid_idx);
}

/* lrouter util functions. */
static void
op_put_v4_networks(struct ds *ds, const struct local_lport *op,
                   bool add_bcast)
{
    if (!add_bcast && op->lrp.networks.n_ipv4_addrs == 1) {
        ds_put_format(ds, "%s", op->lrp.networks.ipv4_addrs[0].addr_s);
        return;
    }

    ds_put_cstr(ds, "{");
    for (int i = 0; i < op->lrp.networks.n_ipv4_addrs; i++) {
        ds_put_format(ds, "%s, ", op->lrp.networks.ipv4_addrs[i].addr_s);
        if (add_bcast) {
            ds_put_format(ds, "%s, ", op->lrp.networks.ipv4_addrs[i].bcast_s);
        }
    }
    ds_chomp(ds, ' ');
    ds_chomp(ds, ',');
    ds_put_cstr(ds, "}");
}

static void
op_put_v6_networks(struct ds *ds, const struct local_lport *op)
{
    if (op->lrp.networks.n_ipv6_addrs == 1) {
        ds_put_format(ds, "%s", op->lrp.networks.ipv6_addrs[0].addr_s);
        return;
    }

    ds_put_cstr(ds, "{");
    for (int i = 0; i < op->lrp.networks.n_ipv6_addrs; i++) {
        ds_put_format(ds, "%s, ", op->lrp.networks.ipv6_addrs[i].addr_s);
    }
    ds_chomp(ds, ' ');
    ds_chomp(ds, ',');
    ds_put_cstr(ds, "}");
}

static void
build_route_match(const struct local_lport *op_inport, const char *network_s,
                  int plen, bool is_src_route, bool is_ipv4, struct ds *match,
                  uint16_t *priority)
{
    const char *dir;
    /* The priority here is calculated to implement longest-prefix-match
     * routing. */
    if (is_src_route) {
        dir = "src";
        *priority = plen * 2;
    } else {
        dir = "dst";
        *priority = (plen * 2) + 1;
    }

    if (op_inport) {
        ds_put_format(match, "inport == %s && ", op_inport->json_key);
    }
    ds_put_format(match, "ip%s.%s == %s/%d", is_ipv4 ? "4" : "6", dir,
                  network_s, plen);
}

static void
add_route(
    struct hmap *lflows, struct local_lport *op,
    uint8_t *lflow_uuid_idx, struct ds *match, struct ds *actions,
    const char *lrp_addr_s, const char *network_s, int plen,
    const char *gateway, bool is_src_route, bool is_discard_route)
{
    bool is_ipv4 = strchr(network_s, '.') ? true : false;
    uint16_t priority;
    const struct local_lport *op_inport = NULL;

    /* IPv6 link-local addresses must be scoped to the local router port. */
    if (!is_ipv4) {
        struct in6_addr network;
        ovs_assert(ipv6_parse(network_s, &network));
        if (in6_is_lla(&network)) {
            op_inport = op;
        }
    }

    ds_clear(match);
    ds_clear(actions);

    build_route_match(op_inport, network_s, plen, is_src_route, is_ipv4,
                      match, &priority);

    struct ds common_actions = DS_EMPTY_INITIALIZER;

    if (is_discard_route) {
        ds_put_format(actions, "drop;");
    } else {
        ds_put_format(&common_actions, REG_ECMP_GROUP_ID" = 0; %s = ",
                      is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6);
        if (gateway) {
            ds_put_cstr(&common_actions, gateway);
        } else {
            ds_put_format(&common_actions, "ip%s.dst", is_ipv4 ? "4" : "6");
        }
        ds_put_format(&common_actions, "; "
                      "%s = %s; "
                      "eth.src = %s; "
                      "outport = %s; "
                      "flags.loopback = 1; "
                      "next;",
                      is_ipv4 ? REG_SRC_IPV4 : REG_SRC_IPV6,
                      lrp_addr_s,
                      op->lrp.networks.ea_s,
                      op->json_key);
        ds_put_format(actions, "ip.ttl--; %s", ds_cstr(&common_actions));
    }

    ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_ROUTING, priority,
                            ds_cstr(match), ds_cstr(actions),
                            &op->pb->header_.uuid, lflow_uuid_idx);
    if (op && op->lrp.has_bfd) {
        ds_put_format(match, " && udp.dst == 3784");
        ovn_ctrl_lflow_add_uuid(lflows, S_ROUTER_IN_IP_ROUTING,
                                priority + 1, ds_cstr(match),
                                ds_cstr(&common_actions),
                                &op->pb->header_.uuid, lflow_uuid_idx);
    }

    ds_destroy(&common_actions);
}
