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

#ifndef OVN_XDP_H
#define OVN_XDP_H 1

#define ETH_ALEN 6

struct vif_addr {
    uint8_t flags;
    uint8_t eth_addr[ETH_ALEN];
    ovs_be32 ip_addr;
};

#define OVN_CHECK_PORT_SEC_MAC      0x00000001
#define OVN_CHECK_PORT_SEC_MAC_IP   0x00000002

struct sbrec_port_binding;
struct local_binding;
struct shash;

void ovn_xdp_init(struct shash *);
void ovn_xdp_destroy(struct shash *);
void ovn_xdp_run(struct shash *local_bindings, struct sset *local_lports,
                 struct shash *xdp_lports);
bool ovn_xdp_handle_lport(const struct sbrec_port_binding *pb, bool removed,
                          struct shash *local_bindings,
                          struct shash *xdp_lports);
#endif
