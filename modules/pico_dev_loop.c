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
#include "pico_dev_loop.h"
#include "pico_stack.h"


#define LOOP_MTU 1500
static uint8_t l_buf[LOOP_MTU];
static int l_bufsize = 0;


static int pico_loop_send(struct pico_device *dev, void *buf, int len)
{
    IGNORE_PARAMETER(dev);
    if (len > LOOP_MTU)
        return 0;

    if (l_bufsize == 0) {
        memcpy(l_buf, buf, (size_t)len);
        l_bufsize += len;
        return len;
    }

    return 0;
}

static int pico_loop_poll(struct pico_device *dev, int loop_score)
{
    if (loop_score <= 0)
        return 0;

    if (l_bufsize > 0) {
        pico_stack_recv(dev, l_buf, (uint32_t)l_bufsize);
        l_bufsize = 0;
        loop_score--;
    }

    return loop_score;
}


struct pico_device *pico_loop_create(struct pico_stack *S)
{
    struct pico_device *loop = PICO_ZALLOC(sizeof(struct pico_device));
    if (!loop)
        return NULL;

    if( 0 != pico_device_init(S, loop, "loop", NULL)) {
        dbg ("Loop init failed.\n");
        pico_device_destroy(loop);
        return NULL;
    }

    loop->send = pico_loop_send;
    loop->poll = pico_loop_poll;
    dbg("Device %s created.\n", loop->name);
    return loop;
}

