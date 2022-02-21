/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_ovn_vif(struct xdp_md *xdp)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
