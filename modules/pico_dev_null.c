/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Daniele Lacamera
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
#include "pico_device.h"
#include "pico_dev_null.h"
#include "pico_stack.h"

struct pico_device_null {
    struct pico_device dev;
    int statistics_frames_out;
};

#define NULL_MTU 0

static int pico_null_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_null *null = (struct pico_device_null *) dev;
    IGNORE_PARAMETER(buf);

    /* Increase the statistic count */
    null->statistics_frames_out++;

    /* Discard the frame content silently. */
    return len;
}

static int pico_null_poll(struct pico_device *dev, int loop_score)
{
    /* We never have packet to receive, no score is used. */
    IGNORE_PARAMETER(dev);
    return loop_score;
}

/* Public interface: create/destroy. */


struct pico_device *pico_null_create(struct pico_stack *S, const char *name)
{
    struct pico_device_null *null = PICO_ZALLOC(sizeof(struct pico_device_null));

    if (!null)
        return NULL;

    if( 0 != pico_device_init(S, (struct pico_device *)null, name, NULL)) {
        return NULL;
    }

    null->dev.overhead = 0;
    null->statistics_frames_out = 0;
    null->dev.send = pico_null_send;
    null->dev.poll = pico_null_poll;
    dbg("Device %s created.\n", null->dev.name);
    return (struct pico_device *)null;
}

