/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Frederik Van Slycken
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
#include "pico_protocol.h"
#include "pico_hotplug_detection.h"
#include "pico_tree.h"
#include "pico_device.h"

struct pico_hotplug_device {
    struct pico_device *dev;
    int prev_state;
    struct pico_tree callbacks;
    struct pico_tree init_callbacks; /* functions we still need to call for initialization */
};


int pico_hotplug_dev_cmp(void *ka, void *kb)
{
    struct pico_hotplug_device *a = ka, *b = kb;
    if (a->dev->hash < b->dev->hash)
        return -1;

    if (a->dev->hash > b->dev->hash)
        return 1;

    return 0;
}

static int callback_compare(void *ka, void *kb)
{
    if (ka < kb)
        return -1;

    if (ka > kb)
        return 1;

    return 0;
}

static void hotplug_timer_cb(__attribute__((unused)) pico_time t, void *v)
{
    struct pico_tree_node *node = NULL, *safe = NULL, *cb_node = NULL, *cb_safe = NULL;
    int new_state, event;
    struct pico_hotplug_device *hpdev = NULL;
    void (*cb)(struct pico_device *dev, int event);
    struct pico_stack *S = (struct pico_stack *)v;

    /* we don't know if one of the callbacks might deregister, so be safe */
    pico_tree_foreach_safe(node, &S->Hotplug_device_tree, safe)
    {
        hpdev = node->keyValue;
        new_state = hpdev->dev->link_state(hpdev->dev);

        if (new_state == 1) {
            event = PICO_HOTPLUG_EVENT_UP;
        } else {
            event = PICO_HOTPLUG_EVENT_DOWN;
        }

        pico_tree_foreach_safe(cb_node, &(hpdev->init_callbacks), cb_safe)
        {
            cb = cb_node->keyValue;
            cb(hpdev->dev, event);
            pico_tree_delete(&hpdev->init_callbacks, cb);
        }
        if (new_state != hpdev->prev_state)
        {
            /* we don't know if one of the callbacks might deregister, so be safe */
            pico_tree_foreach_safe(cb_node, &(hpdev->callbacks), cb_safe)
            {
                cb = cb_node->keyValue;
                cb(hpdev->dev, event);
            }
            hpdev->prev_state = new_state;
        }
    }

    S->hotplug_timer_id = pico_timer_add(S, PICO_HOTPLUG_INTERVAL, &hotplug_timer_cb, S);
    if (S->hotplug_timer_id == 0) {
        dbg("HOTPLUG: Failed to start timer\n");
    }
}

static int ensure_hotplug_timer(struct pico_stack *S)
{
    if (S->hotplug_timer_id == 0)
    {
        S->hotplug_timer_id = pico_timer_add(S, PICO_HOTPLUG_INTERVAL, &hotplug_timer_cb, S);
        if (S->hotplug_timer_id == 0) {
            dbg("HOTPLUG: Failed to start timer\n");
            return -1;
        }
    }

    return 0;
}

int pico_hotplug_register(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event))
{
    struct pico_hotplug_device *hotplug_dev;
    struct pico_hotplug_device search = {
        .dev = dev
    };

    /* If it does not have a link_state, */
    /* the device does not support hotplug detection */
    if (dev->link_state == NULL) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }

    hotplug_dev = (struct pico_hotplug_device*)pico_tree_findKey(&dev->stack->Hotplug_device_tree, &search);
    if (!hotplug_dev )
    {
        hotplug_dev = PICO_ZALLOC(sizeof(struct pico_hotplug_device));
        if (!hotplug_dev)
        {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        hotplug_dev->dev = dev;
        hotplug_dev->prev_state = dev->link_state(hotplug_dev->dev);
        hotplug_dev->callbacks.root = &LEAF;
        hotplug_dev->callbacks.compare = &callback_compare;
        hotplug_dev->init_callbacks.root = &LEAF;
        hotplug_dev->init_callbacks.compare = &callback_compare;
        if (pico_tree_insert(&dev->stack->Hotplug_device_tree, hotplug_dev)) {
            PICO_FREE(hotplug_dev);
        	return -1;
		}
    }

    if (pico_tree_insert(&(hotplug_dev->callbacks), cb) == &LEAF) {
        PICO_FREE(hotplug_dev);
        return -1;
	}

    if (pico_tree_insert(&(hotplug_dev->init_callbacks), cb) == &LEAF) {
        pico_tree_delete(&(hotplug_dev->callbacks), cb);
        PICO_FREE(hotplug_dev);
		return -1;
	}

    if (ensure_hotplug_timer(dev->stack) < 0) {
        pico_hotplug_deregister((struct pico_device *)hotplug_dev, cb);
        return -1;
    }

    return 0;
}

int pico_hotplug_deregister(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event))
{
    struct pico_hotplug_device*hotplug_dev;
    struct pico_hotplug_device search = {
        .dev = dev
    };

    hotplug_dev = (struct pico_hotplug_device*)pico_tree_findKey(&dev->stack->Hotplug_device_tree, &search);
    if (!hotplug_dev)
        /* wasn't registered */
        return 0;

    pico_tree_delete(&hotplug_dev->callbacks, cb);
    pico_tree_delete(&hotplug_dev->init_callbacks, cb);
    if (pico_tree_empty(&hotplug_dev->callbacks))
    {
        pico_tree_delete(&dev->stack->Hotplug_device_tree, hotplug_dev);
        PICO_FREE(hotplug_dev);
    }

    if (pico_tree_empty(&dev->stack->Hotplug_device_tree) && dev->stack->hotplug_timer_id != 0)
    {
        pico_timer_cancel(dev->stack, dev->stack->hotplug_timer_id);
        dev->stack->hotplug_timer_id = 0;
    }

    return 0;
}

