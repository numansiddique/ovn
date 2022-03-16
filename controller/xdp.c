/* Copyright (c) 2022 Red Hat, Inc.
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
#include <unistd.h>

/* library headers */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* OVS includes. */
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "binding.h"
#include "lib/ovn-dirs.h"
#include "lib/ovn-util.h"
#include "lib/ovn-sb-idl.h"
#include "xdp.h"

VLOG_DEFINE_THIS_MODULE(xdp);

#define MAX_ERRNO       4095
#define STRERR_BUFSIZE 1024

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

struct lpm_mac_ip_key {
    struct bpf_lpm_trie_key trie_key;
    __u8 data[10]; /* 6 bytes for mac, 4 bytes for ip */
};

struct xdp_lport {
    int ifindex;
    bool bpf_attached;
    bool bpf_attach_failed;

    struct xdp_program *prog;
    int vif_map_fd;
    int port_sec_mac_map_fd;
    int port_sec_mac_ip_map_fd;

    struct lport_addresses *ps_addrs;   /* Port security addresses. */
    unsigned int n_ps_addrs;
};

static void xdp_handle_lport(const char *lport, struct shash *local_bindings,
                             struct shash *xdp_lports);
static struct xdp_lport *xdp_lport_find(struct shash *xdp_lports,
                                        const char *lport);
static void xdp_lport_attach_prog(struct xdp_lport *);
static void xdp_lport_update_maps(struct xdp_lport *);
static void xdp_lport_detach_prog(struct xdp_lport *);
static void xdp_lport_update_sb_bpf(struct xdp_lport *,
                                    const struct sbrec_bpf *);
static struct xdp_lport *xdp_lport_create(
    struct shash *xdp_lports, const struct binding_lport *);
static void xdp_lport_destroy(struct xdp_lport *);


void
ovn_xdp_init(struct shash *xdp_lports)
{
    shash_init(xdp_lports);
}

void
ovn_xdp_run(struct shash *local_bindings, struct sset *local_lports,
            struct shash *xdp_lports)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, xdp_lports) {
        if (!sset_contains(local_lports, node->name)) {
            struct xdp_lport *xdp_lport = node->data;
            shash_delete(xdp_lports, node);
            xdp_lport_destroy(xdp_lport);
        }
    }

    const char *lport;
    SSET_FOR_EACH (lport, local_lports) {
        xdp_handle_lport(lport, local_bindings, xdp_lports);
    }
}

bool
ovn_xdp_handle_lport(const struct sbrec_port_binding *pb, bool removed,
                     struct shash *local_bindings, struct shash *xdp_lports)
{
    if (removed) {
        struct xdp_lport *xdp_lport =
            shash_find_and_delete(xdp_lports, pb->logical_port);
        if (xdp_lport) {
            xdp_lport_destroy(xdp_lport);
        }
    } else {
        xdp_handle_lport(pb->logical_port, local_bindings, xdp_lports);
    }

    return true;
}

void
ovn_xdp_destroy(struct shash *xdp_lports)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, xdp_lports) {
        struct xdp_lport *xdp_lport = node->data;
        shash_delete(xdp_lports, node);
        xdp_lport_destroy(xdp_lport);
    }
}

/* static functions. */

static void
xdp_handle_lport(const char *lport, struct shash *local_bindings,
                 struct shash *xdp_lports)
{
    struct local_binding *lbinding = local_binding_find(local_bindings, lport);
    if (!lbinding) {
        return;
    }

    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);
    if (!b_lport) {
        return;
    }

    int ifindex = lbinding->iface->n_ifindex ? lbinding->iface->ifindex[0]
                                                : -1;
    struct xdp_lport *xdp_lport = xdp_lport_find(xdp_lports, lport);
    if (xdp_lport && ifindex < 1) {
        /* The interface has been deleted. */
        shash_find_and_delete(xdp_lports, lport);
        xdp_lport_destroy(xdp_lport);
        return;
    }

    if (ifindex < 1) {
        return;
    }

    if (!xdp_lport) {
        xdp_lport = xdp_lport_create(xdp_lports, b_lport);
        if (!xdp_lport) {
            return;
        }
    }

    xdp_lport_attach_prog(xdp_lport);
    if (xdp_lport->bpf_attached) {
        xdp_lport_update_maps(xdp_lport);
    }
}

static void
xdp_lport_attach_prog(struct xdp_lport *xdp_lport)
{
    if (xdp_lport->bpf_attached || xdp_lport->bpf_attach_failed) {
        return;
    }

    /* Detach any xdp program if it is already attached. */
    xdp_lport_detach_prog(xdp_lport);

    char *ovn_xdp_file = xasprintf("%s/ovn_xdp.o", ovn_pkgdatadir());
    struct xdp_program *prog =
        xdp_program__open_file(ovn_xdp_file, "xdp", NULL);
    free(ovn_xdp_file);

    int err = libxdp_get_error(prog);
    char errmsg[STRERR_BUFSIZE];
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        VLOG_ERR("ovn_xdp_attach: failed to open xdp program: %s", errmsg);
        return;
    }

    err = xdp_program__attach(prog, xdp_lport->ifindex, XDP_MODE_NATIVE, 0);

    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        VLOG_ERR("ovn_xdp_attach: failed to attach xdp program: %s", errmsg);
        xdp_lport->bpf_attach_failed = true;
        return;
    }

    struct bpf_object *obj = xdp_program__bpf_obj(prog);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ovn_vif_map");

    xdp_lport->vif_map_fd = map ? bpf_map__fd(map) : -1;

    map = bpf_object__find_map_by_name(obj, "port_sec_mac_table");
    xdp_lport->port_sec_mac_map_fd = map ? bpf_map__fd(map) : -1;

    map = bpf_object__find_map_by_name(obj, "port_sec_mac_ip_table");
    xdp_lport->port_sec_mac_ip_map_fd = map ? bpf_map__fd(map) : -1;

    xdp_lport->bpf_attached = true;
    xdp_lport->bpf_attach_failed = false;
    xdp_lport->prog = prog;
}


static void
xdp_lport_update_maps(struct xdp_lport *xdp_lport)
{
    if (!xdp_lport->bpf_attached || xdp_lport->vif_map_fd < 1 ||
        xdp_lport->port_sec_mac_map_fd < 1 ||
        xdp_lport->port_sec_mac_ip_map_fd < 1) {
        return;
    }

    uint32_t ovn_xdp_checks = 0;
    for (size_t i = 0 ; i < xdp_lport->n_ps_addrs; i++) {
        uint8_t ps_only_l2 = 1;
        struct lport_addresses *ps = &xdp_lport->ps_addrs[i];

        if (ps->n_ipv4_addrs) {
            struct lpm_mac_ip_key key;
            key.data[0] = ps->ea.ea[0];
            key.data[1] = ps->ea.ea[1];
            key.data[2] = ps->ea.ea[2];
            key.data[3] = ps->ea.ea[3];
            key.data[4] = ps->ea.ea[4];
            key.data[5] = ps->ea.ea[5];

            for (size_t j = 0; j < ps->n_ipv4_addrs; j++) {
                key.trie_key.prefixlen = ps->ipv4_addrs[j].plen + 48;

                uint32_t addr = (OVS_FORCE uint32_t)ps->ipv4_addrs[j].addr;
                key.data[6] = addr & 0xff;
                key.data[7] = (addr >> 8) & 0xff;
                key.data[8] = (addr >> 16) & 0xff;
                key.data[9] = (addr >> 24) & 0xff;
                
                uint8_t v = 1;
                if (bpf_map_update_elem(xdp_lport->port_sec_mac_ip_map_fd,
                                        &key, &v, 0) < 0) {
                    VLOG_ERR("ovn_xdp_attach: failed to update port_sec_mac_ip_table");
                    return;
                }
                ovn_xdp_checks |= OVN_CHECK_PORT_SEC_MAC_IP;
            }
            ps_only_l2 = 0;
        }

        ovn_xdp_checks |= OVN_CHECK_PORT_SEC_MAC;
        uint64_t mac = eth_addr_to_uint64(ps->ea);

        if (bpf_map_update_elem(xdp_lport->port_sec_mac_map_fd, &mac,
                                &ps_only_l2, 0) < 0) {
            VLOG_ERR("ovn_xdp_attach: failed to update port_sec_mac_table");
            return;
        }
    }

    int key = 0;
    if (bpf_map_update_elem(xdp_lport->vif_map_fd, &key,
                            &ovn_xdp_checks, 0) < 0) {
        VLOG_ERR("ovn_xdp_attach: failed to update ovn_check_map");
    }
}

static void
xdp_lport_detach_prog(struct xdp_lport *xdp_lport)
{
    if (xdp_lport->bpf_attached && xdp_lport->prog) {
        if (xdp_lport->vif_map_fd > 0) {
            close(xdp_lport->vif_map_fd);
            xdp_lport->vif_map_fd = -1;
        }

        if (xdp_lport->port_sec_mac_map_fd > 0) {
            close(xdp_lport->port_sec_mac_map_fd);
            xdp_lport->port_sec_mac_map_fd = -1;
        }

        if (xdp_lport->port_sec_mac_ip_map_fd > 0) {
            close(xdp_lport->port_sec_mac_ip_map_fd);
            xdp_lport->port_sec_mac_ip_map_fd = -1;
        }

        xdp_program__detach(xdp_lport->prog, xdp_lport->ifindex, XDP_MODE_NATIVE, 0);
        xdp_program__close(xdp_lport->prog);
        xdp_lport->bpf_attached = false;
        xdp_lport->bpf_attach_failed = false;
        xdp_lport->prog = NULL;
    } else {
        struct xdp_multiprog *mp = NULL;
        mp = xdp_multiprog__get_from_ifindex(xdp_lport->ifindex);

        if (!mp || IS_ERR_VALUE((unsigned long) mp)) {
            return;
        }

        if (xdp_multiprog__detach(mp)) {
            VLOG_ERR("ovn_xdp_detach: failed to detach xdp program");
            return;
        }

        xdp_multiprog__close(mp);
    }
}

static struct xdp_lport *
xdp_lport_find(struct shash *xdp_lports, const char *lport)
{
    return shash_find_data(xdp_lports, lport);
}

static void
xdp_lport_update_sb_bpf(struct xdp_lport *xdp_lp,
                        const struct sbrec_bpf *sb_bpf)
{
    bool update_ps = false;
    if (!xdp_lp->n_ps_addrs) {
        update_ps = true;
    }

    if (update_ps) {
        xdp_lp->ps_addrs =
            xmalloc(sizeof *xdp_lp->ps_addrs * sb_bpf->n_port_security);
        for (size_t i = 0; i < sb_bpf->n_port_security; i++) {
            if (!extract_lsp_addresses(
                sb_bpf->port_security[i],
                &xdp_lp->ps_addrs[xdp_lp->n_ps_addrs])) {
                static struct vlog_rate_limit rl
                    = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_INFO_RL(&rl, "invalid syntax '%s' in bpf port security. "
                             "No MAC address found", sb_bpf->port_security[i]);
                continue;
            }
            xdp_lp->n_ps_addrs++;
        }
    }
}

static struct xdp_lport *
xdp_lport_create(struct shash *xdp_lports, const struct binding_lport *b_lport)
{
    struct xdp_lport *xdp_lport = xzalloc(sizeof(*xdp_lport));
    ovs_assert(b_lport->lbinding->iface->n_ifindex);
    xdp_lport->ifindex = b_lport->lbinding->iface->ifindex[0];
    shash_add(xdp_lports, b_lport->lbinding->name, xdp_lport);

    const struct sbrec_bpf *sb_bpf = b_lport->pb->bpf;
    if (sb_bpf && sb_bpf->n_port_security) {
        xdp_lport_update_sb_bpf(xdp_lport, sb_bpf);
    }

    xdp_lport->vif_map_fd = -1;
    xdp_lport->port_sec_mac_map_fd = -1;
    xdp_lport->port_sec_mac_ip_map_fd = -1;

    return xdp_lport;
}

static void
xdp_lport_destroy(struct xdp_lport *xdp_lport)
{
    xdp_lport_detach_prog(xdp_lport);
    for (size_t i = 0; i < xdp_lport->n_ps_addrs; i++) {
        destroy_lport_addresses(&xdp_lport->ps_addrs[i]);
    }
    free(xdp_lport->ps_addrs);
    free(xdp_lport);
}
