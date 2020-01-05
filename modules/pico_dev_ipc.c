/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Michiel Kustermans
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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "pico_device.h"
#include "pico_dev_ipc.h"
#include "pico_stack.h"

struct pico_device_ipc {
    struct pico_device dev;
    int fd;
};

#define IPC_MTU 2048

static int pico_ipc_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_ipc *ipc = (struct pico_device_ipc *) dev;
    return (int)write(ipc->fd, buf, (uint32_t)len);
}

static int pico_ipc_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_ipc *ipc = (struct pico_device_ipc *) dev;
    struct pollfd pfd;
    unsigned char buf[IPC_MTU];
    int len;
    pfd.fd = ipc->fd;
    pfd.events = POLLIN;
    do  {
        if (poll(&pfd, 1, 0) <= 0)
            return loop_score;

        len = (int)read(ipc->fd, buf, IPC_MTU);
        if (len > 0) {
            loop_score--;
            pico_stack_recv(dev, buf, (uint32_t)len);
        }
    } while(loop_score > 0);
    return 0;
}

/* Public interface: create/destroy. */

void pico_ipc_destroy(struct pico_device *dev)
{
    struct pico_device_ipc *ipc = (struct pico_device_ipc *) dev;
    if(ipc->fd > 0) {
        close(ipc->fd);
    }
}

static int ipc_connect(const char *sock_path)
{
    struct sockaddr_un addr;
    int ipc_fd;

    if((ipc_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
        return(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if(connect(ipc_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) < 0) {
        return(-1);
    }

    return ipc_fd;
}

struct pico_device *pico_ipc_create(struct pico_stack *S, const char *sock_path, const char *name, const uint8_t *mac)
{
    struct pico_device_ipc *ipc = PICO_ZALLOC(sizeof(struct pico_device_ipc));

    if (!ipc)
        return NULL;

    ipc->dev.mtu = IPC_MTU;

    if( 0 != pico_device_init(S, (struct pico_device *)ipc, name, mac)) {
        dbg("Ipc init failed.\n");
        pico_ipc_destroy((struct pico_device *)ipc);
        return NULL;
    }

    ipc->dev.overhead = 0;
    ipc->fd = ipc_connect(sock_path);
    if (ipc->fd < 0) {
        dbg("Ipc creation failed.\n");
        pico_ipc_destroy((struct pico_device *)ipc);
        return NULL;
    }

    ipc->dev.send = pico_ipc_send;
    ipc->dev.poll = pico_ipc_poll;
    ipc->dev.destroy = pico_ipc_destroy;
    dbg("Device %s created.\n", ipc->dev.name);
    return (struct pico_device *)ipc;
}
