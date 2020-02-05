/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Milan Platisa
 * 
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 *
 * PicoTCP-NG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) version 3.
 *
 * PicoTCP-NG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 *
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_tree.h"
#include "pico_ipv6.h"
#include "pico_ipv6_pmtu.h"

#define PICO_PMTU_CACHE_NEW (0)
#define PICO_PMTU_CACHE_UPDATED (1)
#define PICO_PMTU_CACHE_OLD (2)

#ifdef PICO_SUPPORT_IPV6PMTU


int pico_ipv6_path_compare(void *ka, void *kb)
{
    struct pico_ipv6_path_mtu *a = ka, *b = kb;
    return pico_ipv6_compare(&((a->path).dst), &((b->path).dst));
}

uint32_t pico_ipv6_pmtu_get(struct pico_stack *S, const struct pico_ipv6_path_id *path)
{
    struct pico_ipv6_path_mtu test;
    struct pico_ipv6_path_mtu *found = NULL;
    uint32_t mtu = 0;
    if (path != NULL) {
        test.path = *path;
        found = pico_tree_findKey(&S->IPV6PathCache, &test);
        if (found) {
            mtu = found->mtu;
        }
    }

    return mtu;
}

int pico_ipv6_path_add(struct pico_stack *S, const struct pico_ipv6_path_id *path, uint32_t mtu)
{
    int status = PICO_PMTU_ERROR;
    if (path != NULL && mtu >= PICO_IPV6_MIN_MTU) {
        struct pico_ipv6_path_mtu test;
        struct pico_ipv6_path_mtu *new = NULL;

        test.path = *path;
        new = pico_tree_findKey(&S->IPV6PathCache, &test);
        if (new == NULL) {
            new = PICO_ZALLOC(sizeof(struct pico_ipv6_path_mtu));
            if (new != NULL) {
                new->path = *path;
                new->mtu = mtu;
                new->cache_status = PICO_PMTU_CACHE_NEW;
                pico_tree_insert(&S->IPV6PathCache, new);
                status = PICO_PMTU_OK;
            }
        }
        else {
            new->mtu = mtu;
            new->cache_status = PICO_PMTU_CACHE_NEW;
            status = PICO_PMTU_OK;
        }
    }

    return status;
}

int pico_ipv6_path_update(struct pico_stack *S, const struct pico_ipv6_path_id *path, uint32_t mtu)
{
    int status = PICO_PMTU_ERROR;
    if (path != NULL) {
        struct pico_ipv6_path_mtu test;
        struct pico_ipv6_path_mtu *found = NULL;
        test.path = *path;
        found = pico_tree_findKey(&S->IPV6PathCache, &test);
        if (found) {
            if (found->mtu > mtu) {
                if (mtu < PICO_IPV6_MIN_MTU) {
                    mtu = PICO_IPV6_MIN_MTU;
                }
                found->mtu = mtu;
                found->cache_status = PICO_PMTU_CACHE_UPDATED;
                status = PICO_PMTU_OK;
            }
        }
    }

    return status;
}

int pico_ipv6_path_del(struct pico_stack *S, const struct pico_ipv6_path_id *path)
{
    int status = PICO_PMTU_ERROR;
    if (path != NULL) {
        struct pico_ipv6_path_mtu test;
        struct pico_ipv6_path_mtu *found = NULL;
        test.path = *path;
        found = pico_tree_findKey(&S->IPV6PathCache, &test);
        if (found) {
            pico_tree_delete(&S->IPV6PathCache, found);
            PICO_FREE(found);
            status = PICO_PMTU_OK;
        }
    }

    return status;
}

static void pico_ipv6_path_gc(pico_time now, void *arg)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_stack *S = (struct pico_stack *)arg;
    IGNORE_PARAMETER(now);
    if(!pico_tree_empty(&S->IPV6PathCache)) {
        pico_tree_foreach_safe(index, &S->IPV6PathCache, _tmp)
        {
            if(((struct pico_ipv6_path_mtu *)index->keyValue)->cache_status == PICO_PMTU_CACHE_OLD) {
                pico_tree_delete(&S->IPV6PathCache, index->keyValue);
            } else {
                ((struct pico_ipv6_path_mtu *)index->keyValue)->cache_status = PICO_PMTU_CACHE_OLD;
            }
        }
    }
    S->ipv6_path_cache_gc_timer.id = pico_timer_add(S, S->ipv6_path_cache_gc_timer.interval, &pico_ipv6_path_gc, S);
}

void pico_ipv6_path_init(struct pico_stack *S, pico_time interval)
{
    S->ipv6_path_cache_gc_timer.interval = interval;
    if (S->ipv6_path_cache_gc_timer.id != 0) {
        pico_timer_cancel(S, S->ipv6_path_cache_gc_timer.id);
    }

    S->ipv6_path_cache_gc_timer.id = pico_timer_add(S, S->ipv6_path_cache_gc_timer.interval, &pico_ipv6_path_gc, S);
}

#endif
