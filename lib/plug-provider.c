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
#include "plug-provider.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "openvswitch/vlog.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "sset.h"
#include "lib/inc-proc-eng.h"

VLOG_DEFINE_THIS_MODULE(plug_provider);

#ifdef ENABLE_PLUG
static const struct plug_class *base_plug_classes[] = {
};
#endif

static struct shash plug_classes = SHASH_INITIALIZER(&plug_classes);

/* Protects the 'plug_classes' shash. */
static struct ovs_mutex plug_classes_mutex = OVS_MUTEX_INITIALIZER;

/* Initialize the the plug infrastructure by registering known plug classes */
void
plug_provider_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
#ifdef ENABLE_PLUG
        /* Register built-in plug provider classes */
        for (int i = 0; i < ARRAY_SIZE(base_plug_classes); i++) {
            plug_provider_register(base_plug_classes[i]);
        }
#endif
#ifdef HAVE_PLUG_PROVIDER
        /* Register external plug provider classes.
         *
         * Note that we cannot use the ARRAY_SIZE macro here as
         * plug_provider_classes is defined in external code which is not
         * available at compile time.  The convention is to use a
         * NULL-terminated array instead. */
        for (const struct plug_class **pp = plug_provider_classes;
             pp && *pp;
             pp++)
        {
            plug_provider_register(*pp);
        }
#endif
        ovsthread_once_done(&once);
    }
}

static int
plug_provider_register__(const struct plug_class *new_class)
{
    struct plug_class *plug_class;
    int error;

    if (shash_find(&plug_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate plug provider: %s",
                  new_class->type);
        return EEXIST;
    }

    error = new_class->init ? new_class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s plug class: %s",
                  new_class->type, ovs_strerror(error));
        return error;
    }

    plug_class = xmalloc(sizeof *plug_class);
    memcpy(plug_class, new_class, sizeof *plug_class);

    shash_add(&plug_classes, new_class->type, plug_class);

    return 0;
}

/* Register the new plug provider referred to in 'new_class' and perform any
 * class level initialization as specified in its plug_class. */
int
plug_provider_register(const struct plug_class *new_class)
{
    int error;

    ovs_mutex_lock(&plug_classes_mutex);
    error = plug_provider_register__(new_class);
    ovs_mutex_unlock(&plug_classes_mutex);

    return error;
}

static int
plug_provider_unregister__(const char *type)
{
    int error;
    struct shash_node *node;
    struct plug_class *plug_class;

    node = shash_find(&plug_classes, type);
    if (!node) {
        return EINVAL;
    }

    plug_class = node->data;
    error = plug_class->destroy ? plug_class->destroy() : 0;
    if (error) {
        VLOG_WARN("failed to destroy %s plug class: %s",
                  plug_class->type, ovs_strerror(error));
        return error;
    }

    shash_delete(&plug_classes, node);
    free(plug_class);

    return 0;
}

/* Unregister the plug provider identified by 'type' and perform any class
 * level de-initialization as specified in its plug_class. */
int
plug_provider_unregister(const char *type)
{
    int error;

    ovs_mutex_lock(&plug_classes_mutex);
    error = plug_provider_unregister__(type);
    ovs_mutex_unlock(&plug_classes_mutex);

    return error;
}

/* Check whether there are any plug providers registered */
bool
plug_provider_has_providers(void)
{
    return !shash_is_empty(&plug_classes);
}

const struct plug_class *
plug_provider_get(const char *type)
{
    struct plug_class *plug_class;

    ovs_mutex_lock(&plug_classes_mutex);
    plug_class = shash_find_data(&plug_classes, type);
    ovs_mutex_unlock(&plug_classes_mutex);

    return plug_class;
}

/* Iterate over plug providers and call their run function.
 *
 * Returns 'true' if any of the providers run functions return 'true', 'false'
 * otherwise.
 *
 * A return value of 'true' means that data has changed. */
bool
plug_provider_run_all(void)
{
    struct shash_node *node, *next;
    bool changed = false;

    SHASH_FOR_EACH_SAFE (node, next, &plug_classes) {
        struct plug_class *plug_class = node->data;
        if (plug_class->run && plug_class->run(plug_class)) {
            changed = true;
        }
    }
    return changed;
}

/* De-initialize and unregister the plug provider classes. */
void
plug_provider_destroy_all(void)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, &plug_classes) {
        struct plug_class *plug_class = node->data;
        plug_provider_unregister(plug_class->type);
    }
}
