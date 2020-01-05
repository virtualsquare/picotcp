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
#include <pcap.h>
#include "pico_device.h"
#include "pico_dev_pcap.h"
#include "pico_stack.h"

#include <sys/poll.h>

struct pico_device_pcap {
    struct pico_device dev;
    pcap_t *conn;
};

#define VDE_MTU 2048

static int pico_pcap_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_pcap *pcap = (struct pico_device_pcap *) dev;
    /* dbg("[%s] send %d bytes.\n", dev->name, len); */
    return pcap_inject(pcap->conn, buf, (uint32_t)len);
}

static void pico_dev_pcap_cb(u_char *u, const struct pcap_pkthdr *h, const u_char *data)
{
    struct pico_device *dev = (struct pico_device *)u;
    const uint8_t *buf = (const uint8_t *)data;
    pico_stack_recv(dev, buf, (uint32_t)h->len);
}


static int pico_pcap_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_pcap *pcap = (struct pico_device_pcap *) dev;
    loop_score -= pcap_dispatch(pcap->conn, loop_score, pico_dev_pcap_cb, (u_char *) pcap);
    return loop_score;
}

/* Public interface: create/destroy. */

void pico_pcap_destroy(struct pico_device *dev)
{
    struct pico_device_pcap *pcap = (struct pico_device_pcap *) dev;
    pcap_close(pcap->conn);
}

#define PICO_PCAP_MODE_LIVE 0
#define PICO_PCAP_MODE_STORED 1

static struct pico_device *pico_pcap_create(struct pico_stack *S, char *if_file_name, char *name, uint8_t *mac, int mode)
{
    struct pico_device_pcap *pcap = PICO_ZALLOC(sizeof(struct pico_device_pcap));
    char errbuf[2000];
    if (!pcap)
        return NULL;

    if( 0 != pico_device_init(S, (struct pico_device *)pcap, name, mac)) {
        dbg ("Pcap init failed.\n");
        pico_pcap_destroy((struct pico_device *)pcap);
        return NULL;
    }

    pcap->dev.overhead = 0;

    if (mode == PICO_PCAP_MODE_LIVE)
        pcap->conn = pcap_open_live(if_file_name, 2000, 100, 10, errbuf);
    else
        pcap->conn = pcap_open_offline(if_file_name, errbuf);

    if (!pcap->conn) {
        pico_pcap_destroy((struct pico_device *)pcap);
        return NULL;
    }

    pcap->dev.send = pico_pcap_send;
    pcap->dev.poll = pico_pcap_poll;
    pcap->dev.destroy = pico_pcap_destroy;
    dbg("Device %s created.\n", pcap->dev.name);
    return (struct pico_device *)pcap;
}

struct pico_device *pico_pcap_create_fromfile(char *filename, char *name, uint8_t *mac)
{
    return pico_pcap_create(filename, name, mac, PICO_PCAP_MODE_STORED);
}

struct pico_device *pico_pcap_create_live(char *ifname, char *name, uint8_t *mac)
{
    return pico_pcap_create(ifname, name, mac, PICO_PCAP_MODE_LIVE);
}
