/*********************************************************************
 * PicoTCP-NG
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
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
#include "pico_queue.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_stack.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_nat.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket_multicast.h"
#include "pico_ipv6_pmtu.h"
#include "pico_socket_ll.h"

int pico_socket_ll_compare(void *ka, void *kb)
{
    struct pico_ll_socket *a = ka, *b = kb;
    if (a->id < b->id)
        return -1;
    if (a->id > b->id)
        return 1;
    return (0);
}

void pico_socket_set_raw(struct pico_socket *s)
{
    struct pico_ll_socket *lls = (struct pico_ll_socket *)s;
    lls->type = PICO_PACKET_TYPE_RAW;
}

struct pico_socket *pico_socket_ll_open(struct pico_stack *S, uint16_t proto) {
    struct pico_ll_socket *s;
    s = PICO_ZALLOC(sizeof(struct pico_ll_socket));
    if (!s) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    s->id = S->PSocket_id++;
    s->type = PICO_PACKET_TYPE_DGRAM;
    s->sock.local_addr.ll.proto = proto;
    s->sock.proto = &pico_proto_ll;
    s->sock.net = &pico_proto_ll;
    s->sock.stack = S;
    pico_tree_insert(&S->PSockets, s);
    return (struct pico_socket *)s;
}

struct pico_frame *pico_ll_frame_alloc(struct pico_stack *S, struct pico_protocol *self, struct pico_device *dev, uint16_t size)
{
    uint32_t overhead;
    struct pico_frame *f;
    (void)S;
    (void)self;
    if (dev)
        overhead = dev->overhead;

    f = pico_frame_alloc((uint32_t)(overhead + size + PICO_SIZE_ETHHDR));
    if (!f)
        return NULL;

    f->dev = dev;
    f->datalink_hdr = f->buffer + overhead;
    return f;
}

int pico_socket_ll_process_in(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_tree_node *node;
    struct pico_eth_hdr *ehdr = (struct pico_eth_hdr *)f->datalink_hdr;
    (void)S;
    (void)self;

    pico_tree_foreach(node, &f->dev->stack->PSockets) {
        struct pico_ll_socket *s;
        struct pico_frame *cp;
        s = (struct pico_ll_socket *) node->keyValue;
        if (((s->sock.state & PICO_SOCKET_STATE_BOUND) == 0) && (s->sock.local_addr.ll.proto == 0))
            continue;
        if ((s->sock.dev != f->dev) && (s->sock.local_addr.ll.proto != PICO_IDETH_ALL))
            continue;
        if ((s->sock.local_addr.ll.proto != ehdr->proto) && (s->sock.local_addr.ll.proto != PICO_IDETH_ALL))
            continue;
        if ( ((s->sock.state & PICO_SOCKET_STATE_BOUND) == 0)  ||
                (memcmp(s->sock.local_addr.ll.hwaddr.addr, ehdr->daddr, 6) == 0)  )
        {
            cp = pico_frame_copy(f);
            if (cp) {
                pico_enqueue(&s->sock.q_in, cp);
                if (s->sock.wakeup)
                    s->sock.wakeup(PICO_SOCK_EV_RD, &s->sock);
            }
        }
    }
    return 0;
}

static int pico_ll_process_out(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    (void)S;
    (void)self;
    (void)f;
    /* Should not be used. */
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

static int pico_ll_frame_sock_push(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    (void)S;
    (void)self;
    return pico_sendto_dev(f);
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_ll = {
    .name = "socket_ll",
    .proto_number = PICO_AF_PACKET,
    .layer = PICO_LAYER_DATALINK,
    .alloc = pico_ll_frame_alloc,
    .process_in = pico_socket_ll_process_in,
    .process_out = pico_ll_process_out,
    .push = pico_ll_frame_sock_push,
};


int pico_socket_ll_recvfrom(struct pico_socket *s, void *buf, uint32_t len, void *orig)
{
    struct pico_ll_socket *lls = (struct pico_ll_socket *)s;
    struct pico_frame *f;
    uint8_t *data;
    uint32_t offset = 0;
    if (!buf) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    f = pico_dequeue(&s->q_in);
    if (!f)
        return 0;
    if (f->dev->eth || (lls->type == PICO_PACKET_TYPE_RAW)) {
        data = f->datalink_hdr + sizeof(struct pico_eth_hdr);
        offset = sizeof(struct pico_eth_hdr);
    } else {
        data = f->datalink_hdr;
    }

    if ((f->buffer_len - (offset + f->dev->overhead)) > len) {
        pico_err = PICO_ERR_EMSGSIZE;
        pico_frame_discard(f);
        return -1;
    }
    len = ((f->buffer_len - (offset + f->dev->overhead)));

    if (f->dev->eth && orig && (lls->type == PICO_PACKET_TYPE_DGRAM)) {
        struct pico_eth_hdr *ehdr = (struct pico_eth_hdr *)f->datalink_hdr;
        struct pico_ll *ll = (struct pico_ll *)orig;
        ll->proto = ehdr->proto;
        memcpy(ll->hwaddr.addr, ehdr->daddr, 6);
        ll->halen = 6;
        ll->dev = f->dev;
    }
    memcpy(buf, data, len);
    pico_frame_discard(f);
    return (int)len;
}

int pico_socket_ll_sendto(struct pico_socket *s, void *buf, uint32_t len, void *_dst)
{
    struct pico_frame *f;
    struct pico_ll *dst = (struct pico_ll *)_dst;
    uint32_t overhead = 0;
    struct pico_ll_socket *lls = (struct pico_ll_socket *)s;

    if (!dst || !dst->dev || (!dst->proto && !s->local_addr.ll.proto)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if ((dst->halen != 6) && ((dst->halen != 0) && dst->dev->eth)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (len > pico_socket_get_mss(s)) {
        pico_err = PICO_ERR_EMSGSIZE;
        return -1;
    }
    f = pico_ll_frame_alloc(s->stack, &pico_proto_ll, dst->dev, (uint16_t)(len));
    if (!f) {
        return -1;
    }
    f->dev = dst->dev;
    if (dst->proto == 0)
        dst->proto = s->local_addr.ll.proto;
    if (dst->dev->eth && (lls->type == PICO_PACKET_TYPE_DGRAM)) {
        struct pico_eth_hdr *ehdr;
        ehdr = (struct pico_eth_hdr *)f->datalink_hdr;
        memcpy(ehdr->daddr, dst->hwaddr.addr, 6);
        memcpy(ehdr->saddr, dst->dev->eth->mac.addr, 6);
        ehdr->proto = dst->proto;
        f->payload = f->datalink_hdr + (sizeof (struct pico_eth_hdr));
        overhead += (uint32_t)sizeof(struct pico_eth_hdr);
    } else {
        f->payload = f->datalink_hdr;
    }
    memcpy(f->payload, (const uint8_t *)buf, len);
    f->start = f->datalink_hdr;
    f->len = len + overhead;
    pico_sendto_dev(f);
    s->dev = f->dev;
    return (int)len;
}

int pico_setsockopt_ll(struct pico_socket *s, int option, void *value)
{
    (void)s;
    (void)option;
    (void)value;
    pico_err = PICO_ERR_EOPNOTSUPP;
    return -1;
}

int pico_getsockopt_ll(struct pico_socket *s, int option, void *value)
{
    (void)s;
    (void)option;
    (void)value;
    pico_err = PICO_ERR_EOPNOTSUPP;
    return -1;
}

int pico_socket_ll_close(struct pico_socket *arg)
{
    struct pico_ll_socket *s = (struct pico_ll_socket *)arg;
    if (s) {
        pico_tree_delete(&s->sock.stack->PSockets, s);
        return 0;
    }
    pico_err = PICO_ERR_ENOENT;
    return -1;
}
