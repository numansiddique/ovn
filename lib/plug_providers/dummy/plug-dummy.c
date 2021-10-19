/*
 * Copyright (c) 2021 Canonical
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
#include "lib/plug-provider.h"

#include <stdint.h>

#include "openvswitch/vlog.h"
#include "smap.h"
#include "sset.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

VLOG_DEFINE_THIS_MODULE(plug_dummy);

static struct sset plug_dummy_maintained_iface_options;

static int
plug_dummy_init(void)
{
    sset_init(&plug_dummy_maintained_iface_options);
    sset_add(&plug_dummy_maintained_iface_options, "plug-dummy-option");

    return 0;
}

static int
plug_dummy_destroy(void)
{
    sset_destroy(&plug_dummy_maintained_iface_options);

    return 0;
}

static const struct sset*
plug_dummy_get_maintained_iface_options(void)
{
    return &plug_dummy_maintained_iface_options;
}

static bool
plug_dummy_run(struct plug_class *plug)
{
    VLOG_DBG("plug_dummy_run(%p)", plug);

    return false;
}

static bool
plug_dummy_port_prepare(const struct plug_port_ctx_in *ctx_in,
                        struct plug_port_ctx_out *ctx_out)
{
    VLOG_DBG("plug_dummy_port_prepare: %s", ctx_in->lport_name);

    if (ctx_in->op_type == PLUG_OP_CREATE) {
        size_t lport_name_len = strlen(ctx_in->lport_name);
        ctx_out->name = xzalloc(IFNAMSIZ);
        memcpy(ctx_out->name, ctx_in->lport_name,
               (lport_name_len < IFNAMSIZ) ? lport_name_len : IFNAMSIZ - 1);
        ctx_out->type = xstrdup("internal");
        smap_init(&ctx_out->iface_options);
        smap_add(&ctx_out->iface_options, "plug-dummy-option", "value");
    }

    return true;
}

static void
plug_dummy_port_finish(const struct plug_port_ctx_in *ctx_in,
                      struct plug_port_ctx_out *ctx_out OVS_UNUSED)
{
    VLOG_DBG("plug_dummy_port_finish: %s", ctx_in->lport_name);
}

static void
plug_dummy_port_ctx_destroy(const struct plug_port_ctx_in *ctx_in,
                           struct plug_port_ctx_out *ctx_out)
{
    VLOG_DBG("plug_dummy_port_ctx_destroy: %s", ctx_in->lport_name);
    ovs_assert(ctx_in->op_type == PLUG_OP_CREATE);
    free(ctx_out->name);
    free(ctx_out->type);
    smap_destroy(&ctx_out->iface_options);
}

const struct plug_class plug_dummy_class = {
    .type = "dummy",
    .init = plug_dummy_init,
    .destroy = plug_dummy_destroy,
    .plug_get_maintained_iface_options =
        plug_dummy_get_maintained_iface_options,
    .run = plug_dummy_run,
    .plug_port_prepare = plug_dummy_port_prepare,
    .plug_port_finish = plug_dummy_port_finish,
    .plug_port_ctx_destroy = plug_dummy_port_ctx_destroy,
};

void
plug_dummy_enable(void)
{
    plug_provider_register(&plug_dummy_class);
}

