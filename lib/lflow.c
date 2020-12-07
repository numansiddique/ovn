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
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "openvswitch/hmap.h"
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

void
ovn_ctrl_lflows_clear(struct hmap *lflows)
{
    struct ovn_ctrl_lflow *lflow;
    HMAP_FOR_EACH_POP (lflow, hmap_node, lflows) {
        ovn_ctrl_lflow_destroy(lflow);
    }
}

void
ovn_ctrl_reinit_lflows_matches(struct hmap *lflows)
{
    struct ovn_ctrl_lflow *lflow;
    HMAP_FOR_EACH (lflow, hmap_node, lflows) {
        expr_matches_destroy(&lflow->expr_matches);
        ofpbuf_delete(lflow->ofpacts);
        hmap_init(&lflow->expr_matches);
        lflow->ofpacts = ofpbuf_new(0);
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
    if (lflow_uuid) {
        lflow->uuid_ = *lflow_uuid;
        uint32_t part0;
        part0 = ((lflow->uuid_.parts[0] & 0x00ffffff) | lflow_idx << 24);
        lflow->uuid_.parts[0] = part0;
    } else {
        uuid_generate(&lflow->uuid_);
    }

    hmap_init(&lflow->expr_matches);
    lflow->ofpacts = ofpbuf_new(0);
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

    lflow = xmalloc(sizeof *lflow);
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
        expr_matches_destroy(&lflow->expr_matches);
        ofpbuf_delete(lflow->ofpacts);
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
    for (size_t i = 0; i < dp->n_load_balancers; i++) {
        struct sbrec_load_balancer *sb_lb = dp->load_balancers[i];
        if (!smap_is_empty(&sb_lb->vips)) {
            return true;
        }
    }

    return false;
}

static bool
has_dp_stateful_acls(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "stateful-acl", false);
}

static bool
has_dp_unknown_lports(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "has-unknown", false);
}

static void
build_lswitch_lb_flows(struct hmap *lflows, const struct uuid *lflow_uuid,
                       uint8_t *lflow_uuid_idx)
{
    /* 'REGBIT_CONNTRACK_DEFRAG' is set to let the pre-stateful table send
     * packet to conntrack for defragmentation.
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
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PRE_LB,
                            100, "ip", REGBIT_CONNTRACK_DEFRAG" = 1; next;",
                            lflow_uuid, lflow_uuid_idx);
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_PRE_LB,
                            100, "ip", REGBIT_CONNTRACK_DEFRAG" = 1; next;",
                            lflow_uuid, lflow_uuid_idx);

    /* Ingress and Egress LB Table (Priority 65534).
     *
     * Send established traffic through conntrack for just NAT. */
    /* Check if the packet needs to be hairpinned. */
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PRE_HAIRPIN, 100,
                            "ip && ct.trk",
                            REGBIT_HAIRPIN " = chk_lb_hairpin(); "
                            REGBIT_HAIRPIN_REPLY " = chk_lb_hairpin_reply(); "
                            "next;", lflow_uuid, lflow_uuid_idx);

    /* If packet needs to be hairpinned, snat the src ip with the VIP
     * for new sessions. */
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_NAT_HAIRPIN, 100,
                            "ip && ct.new && ct.trk && "REGBIT_HAIRPIN " == 1",
                            "ct_snat_to_vip; next;", lflow_uuid,
                            lflow_uuid_idx);

    /* If packet needs to be hairpinned, for established sessions there
     * should already be an SNAT conntrack entry.
     */
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_NAT_HAIRPIN, 100,
                            "ip && ct.est && ct.trk && "REGBIT_HAIRPIN " == 1",
                            "ct_snat;", lflow_uuid, lflow_uuid_idx);

    /* For the reply of hairpinned traffic, snat the src ip to the VIP. */
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_NAT_HAIRPIN, 90,
                            "ip && "REGBIT_HAIRPIN_REPLY " == 1", "ct_snat;",
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

static void
build_lswitch_stateful_acl_hints(struct hmap *lflows,
                                 const struct uuid *lflow_uuid,
                                 uint8_t *lflow_uuid_idx)
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
        ovn_ctrl_lflow_add_uuid(lflows, stage, 6,
                                "!ct.new && ct.est && !ct.rpl && "
                                "ct_label.blocked == 1",
                                REGBIT_ACL_HINT_ALLOW_NEW " = 1; "
                                REGBIT_ACL_HINT_DROP " = 1; "
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
            REGBIT_ACL_HINT_ALLOW " = 1; "
            REGBIT_ACL_HINT_BLOCK " = 1; "
            "next;", lflow_uuid, lflow_uuid_idx);

        /* Not established or established and already blocked connections may
         * hit drop ACLs.
         */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 3, "!ct.est",
                                REGBIT_ACL_HINT_DROP " = 1; "
                                "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, stage, 2,
                                "ct.est && ct_label.blocked == 1",
                                REGBIT_ACL_HINT_DROP " = 1; "
                                "next;", lflow_uuid, lflow_uuid_idx);

        /* Established connections that were previously allowed might hit
         * drop ACLs in which case the connection must be committed with
         * ct_label.blocked set.
         */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 1,
                                "ct.est && ct_label.blocked == 0",
                                REGBIT_ACL_HINT_BLOCK " = 1; "
                                "next;", lflow_uuid, lflow_uuid_idx);

        /* In any case, advance to the next stage. */
        ovn_ctrl_lflow_add_uuid(lflows, stage, 0, "1", "next;",
                                lflow_uuid, lflow_uuid_idx);
    }
}

static void
build_lswitch_stateful_acls(struct hmap *lflows, bool use_ct_inv_match,
                            const struct uuid *lflow_uuid,
                            uint8_t *lflow_uuid_idx)
{
    /* Ingress and Egress Pre-ACL Table (Priority 110).
     *
     * Not to do conntrack on ND and ICMP destination
     * unreachable packets. */
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_PRE_ACL, 110,
                            "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
                            "(udp && udp.src == 546 && udp.dst == 547)",
                            "next;", lflow_uuid, lflow_uuid_idx);
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_PRE_ACL, 110,
                            "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
                            "(udp && udp.src == 546 && udp.dst == 547)",
                            "next;", lflow_uuid, lflow_uuid_idx);

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
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, 1,
                            "ip && (!ct.est || (ct.est && ct_label.blocked == 1))",
                            REGBIT_CONNTRACK_COMMIT" = 1; next;",
                            lflow_uuid, lflow_uuid_idx);

    /* Ingress and Egress ACL Table (Priority 65535 - 3).
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

    /* Ingress and Egress ACL Table (Priority 65535 - 3).
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

    /* Ingress and Egress ACL Table (Priority 65535).
     *
     * Not to do conntrack on ND packets. */
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                            "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;",
                            lflow_uuid, lflow_uuid_idx);
    ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                            "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;",
                            lflow_uuid, lflow_uuid_idx);
}

static bool
has_dp_dns_records(const struct sbrec_datapath_binding *dp)
{
    return smap_get_bool(&dp->options, "dns-records", false);
}

static void
build_lswitch_acls(struct hmap *lflows,
                   const struct sbrec_datapath_binding *dp,
                   bool use_ct_inv_match,
                   const struct uuid *lflow_uuid,
                   uint8_t *lflow_uuid_idx)
{
    bool has_stateful = (has_dp_stateful_acls(dp) || has_dp_lb_vip(dp));

    if (has_stateful) {
        build_lswitch_stateful_acl_hints(lflows, lflow_uuid, lflow_uuid_idx);
        build_lswitch_stateful_acls(lflows, use_ct_inv_match,
                                    lflow_uuid, lflow_uuid_idx);
    } else {
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL_HINT, UINT16_MAX,
                                "1", "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL_HINT, UINT16_MAX,
                                "1", "next;", lflow_uuid, lflow_uuid_idx);

        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_IN_ACL, UINT16_MAX,
                                "1", "next;", lflow_uuid, lflow_uuid_idx);
        ovn_ctrl_lflow_add_uuid(lflows, S_SWITCH_OUT_ACL, UINT16_MAX,
                                "1", "next;", lflow_uuid, lflow_uuid_idx);
    }

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

    if (has_dp_lb_vip(dp)) {
        build_lswitch_lb_flows(lflows, &dp->header_.uuid, &lflow_uuid_idx);
    }

    build_lswitch_acls(lflows, dp, use_ct_inv_match, &dp->header_.uuid,
                       &lflow_uuid_idx);

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
build_lrouter_dp_lflows(struct hmap *lflows,
                        const struct sbrec_datapath_binding *dp)
{
    build_lrouter_neigh_learning_flows(lflows, dp);
}
