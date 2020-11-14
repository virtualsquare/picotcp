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
#include "pico_config.h"
#include "pico_frame.h"
#include "pico_device.h"
#include "pico_protocol.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_dns_client.h"
#include "pico_mdns.h"
#include "pico_fragments.h"
#include "pico_ipfilter.h"

#include "pico_6lowpan_ll.h"
#include "pico_ethernet.h"
#include "pico_6lowpan.h"
#include "pico_olsr.h"
#include "pico_aodv.h"
#include "pico_eth.h"
#include "pico_arp.h"
#include "pico_ipv4.h"
#include "pico_nat.h"
#include "pico_ipv6.h"
#include "pico_ipv6_pmtu.h"
#include "pico_icmp4.h"
#include "pico_icmp6.h"
#include "pico_igmp.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_socket_multicast.h"
#include "pico_ethernet.h"
#include "pico_dhcp_server.h"
#include "pico_hotplug_detection.h"
#include "heap.h"
#include "pico_jobs.h"

/* Globals (common to all instances) */
volatile pico_time pico_tick;
volatile pico_err_t pico_err;

/* Mockables */
#if defined UNIT_TEST
#   define MOCKABLE __attribute__((weak))
#else
#   define MOCKABLE
#endif


void pico_to_lowercase(char *str)
{
    int i = 0;
    if (!str)
        return;

    while(str[i]) {
        if ((str[i] <= 'Z') && (str[i] >= 'A'))
            str[i] = (char) (str[i] - (char)('A' - 'a'));

        i++;
    }
}

/* NOTIFICATIONS: distributed notifications for stack internal errors.
 */

int pico_notify_socket_unreachable(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_port_unreachable(S, f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_port_unreachable(S, f);
    }
#endif

    return 0;
}

int pico_notify_proto_unreachable(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_proto_unreachable(S, f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_proto_unreachable(S, f);
    }
#endif
    return 0;
}

int pico_notify_dest_unreachable(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_dest_unreachable(S, f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_dest_unreachable(S, f);
    }
#endif
    return 0;
}

int pico_notify_ttl_expired(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_ttl_expired(S, f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_ttl_expired(S, f);
    }
#endif
    return 0;
}

int pico_notify_frag_expired(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_frag_expired(S, f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_frag_expired(S, f);
    }
#endif
    return 0;
}

int pico_notify_pkt_too_big(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_ICMP4
    else if (IS_IPV4(f)) {
        pico_icmp4_mtu_exceeded(S, f);
    }
#endif
#ifdef PICO_SUPPORT_ICMP6
    else if (IS_IPV6(f)) {
        pico_icmp6_pkt_too_big(S, f);
    }
#endif
    return 0;
}

/*******************************************************************************
 *  TRANSPORT LAYER
 ******************************************************************************/

/* Transport layer */
MOCKABLE int32_t pico_transport_receive(struct pico_frame *f, uint8_t proto)
{
    int32_t ret = -1;
    switch (proto) {

#ifdef PICO_SUPPORT_ICMP4
    case PICO_PROTO_ICMP4:
        ret = pico_enqueue(pico_proto_icmp4.q_in, f);
        break;
#endif

#ifdef PICO_SUPPORT_ICMP6
    case PICO_PROTO_ICMP6:
        ret = pico_enqueue(pico_proto_icmp6.q_in, f);
        break;
#endif


#if defined(PICO_SUPPORT_IGMP) && defined(PICO_SUPPORT_MCAST)
    case PICO_PROTO_IGMP:
        ret = pico_enqueue(pico_proto_igmp.q_in, f);
        break;
#endif

#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
        ret = pico_enqueue(pico_proto_udp.q_in, f);
        break;
#endif

#ifdef PICO_SUPPORT_TCP
    case PICO_PROTO_TCP:
        ret = pico_enqueue(pico_proto_tcp.q_in, f);
        break;
#endif

    default:
        /* Protocol not available */
        dbg("pkt: no such protocol (%d)\n", proto);
        pico_notify_proto_unreachable(f->dev->stack, f);
        pico_frame_discard(f);
        ret = -1;
    }
    return ret;
}

/*******************************************************************************
 *  NETWORK LAYER
 ******************************************************************************/

MOCKABLE int32_t pico_network_receive(struct pico_frame *f)
{
    if (0) {}

#ifdef PICO_SUPPORT_IPV4
    else if (IS_IPV4(f)) {
        pico_enqueue(pico_proto_ipv4.q_in, f);
    }
#endif
#ifdef PICO_SUPPORT_IPV6
    else if (IS_IPV6(f)) {
        pico_enqueue(pico_proto_ipv6.q_in, f);
    }
#endif
    else {
        dbg("Network not found.\n");
        pico_frame_discard(f);
        return -1;
    }
    return (int32_t)f->buffer_len;
}

/// Interface towards socket for frame sending
int32_t pico_network_send(struct pico_frame *f)
{
    if (!f || !f->sock || !f->sock->net) {
        pico_frame_discard(f);
        return -1;
    }

    return f->sock->net->push(f->sock->stack, f->sock->net, f);
}

int pico_source_is_local(struct pico_stack *S, struct pico_frame *f)
{
    if (0) { }

#ifdef PICO_SUPPORT_IPV4
    else if (IS_IPV4(f)) {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
        if (hdr->src.addr == PICO_IPV4_INADDR_ANY)
            return 1;

        if (pico_ipv4_link_find(S, &hdr->src))
            return 1;
    }
#endif
#ifdef PICO_SUPPORT_IPV6
    else if (IS_IPV6(f)) {
        struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        if (pico_ipv6_is_unspecified(hdr->src.addr) || pico_ipv6_link_find(S, &hdr->src))
            return 1;
    }
#endif
    return 0;
}


void pico_store_network_origin(void *src, struct pico_frame *f)
{
  #ifdef PICO_SUPPORT_IPV4
    struct pico_ip4 *ip4;
  #endif

  #ifdef PICO_SUPPORT_IPV6
    struct pico_ip6 *ip6;
  #endif

  #ifdef PICO_SUPPORT_IPV4
    if (IS_IPV4(f)) {
        struct pico_ipv4_hdr *hdr;
        hdr = (struct pico_ipv4_hdr *) f->net_hdr;
        ip4 = (struct pico_ip4 *) src;
        ip4->addr = hdr->src.addr;
    }

  #endif
  #ifdef PICO_SUPPORT_IPV6
    if (IS_IPV6(f)) {
        struct pico_ipv6_hdr *hdr;
        hdr = (struct pico_ipv6_hdr *) f->net_hdr;
        ip6 = (struct pico_ip6 *) src;
        memcpy(ip6->addr, hdr->src.addr, PICO_SIZE_IP6);
    }

  #endif
}

int pico_address_compare(union pico_address *a, union pico_address *b, uint16_t proto)
{
    #ifdef PICO_SUPPORT_IPV6
    if (proto == PICO_PROTO_IPV6) {
        return pico_ipv6_compare(&a->ip6, &b->ip6);
    }

    #endif
    #ifdef PICO_SUPPORT_IPV4
    if (proto == PICO_PROTO_IPV4) {
        return pico_ipv4_compare(&a->ip4, &b->ip4);
    }

    #endif
    return 0;

}

int pico_frame_dst_is_unicast(struct pico_stack *S, struct pico_frame *f)
{
    if (0) {
        return 0;
    }

#ifdef PICO_SUPPORT_IPV4
    if (IS_IPV4(f)) {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
        if (pico_ipv4_is_multicast(hdr->dst.addr) || pico_ipv4_is_broadcast(S, hdr->dst.addr))
            return 0;

        return 1;
    }

#endif

#ifdef PICO_SUPPORT_IPV6
    if (IS_IPV6(f)) {
        struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
        if (pico_ipv6_is_multicast(hdr->dst.addr) || pico_ipv6_is_unspecified(hdr->dst.addr))
            return 0;

        return 1;
    }

#endif
    else return 0;
}

/*******************************************************************************
 *  DATALINK LAYER
 ******************************************************************************/

int pico_datalink_receive(struct pico_frame *f)
{
#ifdef PICO_SUPPORT_PACKET_SOCKETS
    pico_socket_ll_process_in(f->dev->stack, &pico_proto_ll, f);
#endif
    if (f->dev->eth) {
        /* If device has stack with datalink-layer pass frame through it */
        switch (f->dev->mode) {
            #ifdef PICO_SUPPORT_802154
            case LL_MODE_IEEE802154:
                f->datalink_hdr = f->buffer;
                return pico_enqueue(pico_proto_6lowpan_ll.q_in, f);
            #endif
            default:
                #ifdef PICO_SUPPORT_ETH
                f->datalink_hdr = f->buffer;
                return pico_enqueue(pico_proto_ethernet.q_in,f);
                #else
                return -1;
                #endif
        }
    } else {
        /* If device handles raw IP-frames send it straight to network-layer */
        f->net_hdr = f->buffer;
        pico_network_receive(f);
    }

    return 0;
}

MOCKABLE int pico_datalink_send(struct pico_frame *f)
{
    if (f->dev->eth) {
        switch (f->dev->mode) {
            #ifdef PICO_SUPPORT_802154
            case LL_MODE_IEEE802154:
                return pico_enqueue(pico_proto_6lowpan.q_out, f);
            #endif
            default:
                #ifdef PICO_SUPPORT_ETH
                return pico_enqueue(pico_proto_ethernet.q_out, f);
                #else
                return -1;
                #endif
        }
    } else {
        /* non-ethernet: no post-processing needed */
        return pico_sendto_dev(f);
    }
}

/*******************************************************************************
 *  PHYSICAL LAYER
 ******************************************************************************/

struct pico_frame *pico_stack_recv_new_frame(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    struct pico_frame *f;
    if (len == 0)
        return NULL;

    f = pico_frame_alloc(len);
    if (!f)
    {
        dbg("Cannot alloc incoming frame!\n");
        return NULL;
    }

    /* Association to the device that just received the frame. */
    f->dev = dev;

    /* Setup the start pointer, length. */
    f->start = f->buffer;
    f->len = f->buffer_len;
    if (f->len > 8) {
        uint32_t rand, mid_frame = (f->buffer_len >> 2) << 1;
        mid_frame -= (mid_frame % 4);
        memcpy(&rand, f->buffer + mid_frame, sizeof(uint32_t));
    }

    memcpy(f->buffer, buffer, len);
    return f;
}

/* LOWEST LEVEL: interface towards devices. */
/* Device driver will call this function which returns immediately.
 * Incoming packet will be processed later on in the dev loop.
 */
int32_t pico_stack_recv(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    struct pico_frame *f = pico_stack_recv_new_frame (dev, buffer, len);
    int32_t ret;

    if (!f)
        return -1;

    ret = pico_enqueue(dev->q_in, f);
    if (ret <= 0) {
        pico_frame_discard(f);
    }
    return ret;
}

static int32_t _pico_stack_recv_zerocopy(struct pico_device *dev, uint8_t *buffer, uint32_t len, int ext_buffer, void (*notify_free)(uint8_t *))
{
    struct pico_frame *f;
    int ret;
    if (len == 0)
        return -1;

    f = pico_frame_alloc_skeleton(len, ext_buffer);
    if (!f)
    {
        dbg("Cannot alloc incoming frame!\n");
        return -1;
    }

    if (pico_frame_skeleton_set_buffer(f, buffer) < 0)
    {
        dbg("Invalid zero-copy buffer!\n");
        PICO_FREE(f->usage_count);
        PICO_FREE(f);
        return -1;
    }

    if (notify_free) {
        f->notify_free = notify_free;
    }

    f->dev = dev;
    ret = pico_enqueue(dev->q_in, f);
    if (ret <= 0) {
        pico_frame_discard(f);
    }

    return ret;
}

int32_t pico_stack_recv_zerocopy(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    return _pico_stack_recv_zerocopy(dev, buffer, len, 0, NULL);
}

int32_t pico_stack_recv_zerocopy_ext_buffer(struct pico_device *dev, uint8_t *buffer, uint32_t len)
{
    return _pico_stack_recv_zerocopy(dev, buffer, len, 1, NULL);
}

int32_t pico_stack_recv_zerocopy_ext_buffer_notify(struct pico_device *dev, uint8_t *buffer, uint32_t len, void (*notify_free)(uint8_t *buffer))
{
    return _pico_stack_recv_zerocopy(dev, buffer, len, 1, notify_free);
}

int32_t pico_sendto_dev(struct pico_frame *f)
{
    if (!f->dev) {
        pico_frame_discard(f);
        return -1;
    } else {
        if (f->len > 8) {
            uint32_t rand, mid_frame = (f->buffer_len >> 2) << 1;
            mid_frame -= (mid_frame % 4);
            memcpy(&rand, f->buffer + mid_frame, sizeof(uint32_t));
        }

        return pico_enqueue(f->dev->q_out, f);
    }
}

int32_t pico_seq_compare(uint32_t a, uint32_t b)
{
    uint32_t thresh = ((uint32_t)(-1)) >> 1;

    if (a > b) /* return positive number, if not wrapped */
    {
        if ((a - b) > thresh) /* b wrapped */
            return -(int32_t)(b - a); /* b = very small,     a = very big      */
        else
            return (int32_t)(a - b); /* a = biggest,        b = a bit smaller */

    }

    if (a < b) /* return negative number, if not wrapped */
    {
        if ((b - a) > thresh) /* a wrapped */
            return (int32_t)(a - b); /* a = very small,     b = very big      */
        else
            return -(int32_t)(b - a); /* b = biggest,        a = a bit smaller */

    }

    return 0;
}

static void pico_check_timers(struct pico_stack *S)
{
    struct pico_timer *t;
    struct pico_timer_ref tref_unused, *tref = heap_first(S->Timers);
    pico_tick = PICO_TIME_MS();
    while((tref) && (tref->expire <= pico_tick)) {
        t = tref->tmr;
        if (t && t->timer)
            t->timer(pico_tick, t->arg);

        if (t)
        {
            PICO_FREE(t);
        }

        heap_peek(S->Timers, &tref_unused);
        tref = heap_first(S->Timers);
    }
}

#ifdef PICO_SUPPORT_TICKLESS
long long int pico_stack_go(struct pico_stack *S)
{
    struct pico_timer_ref *tref;
    pico_execute_pending_jobs(S);
    pico_check_timers(S);
    tref = heap_first(S->Timers);
    if (!tref)
        return -1;
    /* Execute jobs again, in case they were scheduled in timer execution */
    pico_execute_pending_jobs(S);
    return(long long int)((tref->expire - pico_tick) + 1);
}
#endif

void MOCKABLE pico_timer_cancel(struct pico_stack *S, uint32_t id)
{
    uint32_t i;
    struct pico_timer_ref *tref;
    if (id == 0u)
        return;

    for (i = 1; i <= S->Timers->n; i++) {
        tref = heap_get_element(S->Timers, i);
        if (tref->id == id) {
            if (tref->tmr)
            {
                PICO_FREE(tref->tmr);
                tref->tmr = NULL;
                tref->id = 0;
            }
            break;
        }
    }
}

void pico_timer_cancel_hashed(struct pico_stack *S, uint32_t hash)
{
    uint32_t i;
    struct pico_timer_ref *tref;
    if (hash == 0u)
        return;

    for (i = 1; i <= S->Timers->n; i++) {
        tref = heap_get_element(S->Timers, i);
        if (tref->hash == hash) {
            if (tref->tmr)
            {
                PICO_FREE(tref->tmr);
                tref->tmr = NULL;
                tref[i].id = 0;
            }
        }
    }
}

#ifndef PICO_SUPPORT_TICKLESS
static int calc_score(struct pico_stack *S)
{
    int temp, i, j, sum;
    int max_total = PROTO_MAX_LOOP, total = 0;

    /* dbg("USED SCORES> "); */

    for (i = 0; i < PROTO_DEF_NR; i++) {

        /* if used looped S->score */
        if (S->ret[i] < S->score[i]) {
            temp = S->score[i] - S->ret[i]; /* remaining loop S->score */

            /* dbg("%3d - ",temp); */

            if (S->index[i] >= PROTO_DEF_AVG_NR)
                S->index[i] = 0;   /* reset S->index */

            j = S->index[i];
            S->avg[i][j] = temp;

            S->index[i]++;

            if (S->ret[i] == 0 && ((S->score[i] * 2) <= PROTO_MAX_SCORE) && ((total + (S->score[i] * 2)) < max_total)) { /* used all loop S->score -> increase next S->score directly */
                S->score[i] *= 2;
                total += S->score[i];
                continue;
            }

            sum = 0;
            for (j = 0; j < PROTO_DEF_AVG_NR; j++)
                sum += S->avg[i][j]; /* calculate sum */

            sum /= 4;           /* divide by 4 to get average used S->score */

            /* criterion to increase next loop S->score */
            if (sum > (S->score[i] - (S->score[i] / 4))  && ((S->score[i] * 2) <= PROTO_MAX_SCORE) && ((total + (S->score[i] / 2)) < max_total)) { /* > 3/4 */
                S->score[i] *= 2; /* double loop S->score */
                total += S->score[i];
                continue;
            }

            /* criterion to decrease next loop S->score */
            if ((sum < (S->score[i] / 4)) && ((S->score[i] / 2) >= PROTO_MIN_SCORE)) { /* < 1/4 */
                S->score[i] /= 2; /* half loop S->score */
                total += S->score[i];
                continue;
            }

            /* also add non-changed S->scores */
            total += S->score[i];
        }
        else if (S->ret[i] == S->score[i]) {
            /* no used loop S->score - gradually decrease */

            /*  dbg("%3d - ",0); */

            if (S->index[i] >= PROTO_DEF_AVG_NR)
                S->index[i] = 0;   /* reset S->index */

            j = S->index[i];
            S->avg[i][j] = 0;

            S->index[i]++;

            sum = 0;
            for (j = 0; j < PROTO_DEF_AVG_NR; j++)
                sum += S->avg[i][j]; /* calculate sum */

            sum /= 2;          /* divide by 4 to get average used S->score */

            if ((sum == 0) && ((S->score[i] / 2) >= PROTO_MIN_SCORE)) {
                S->score[i] /= 2; /* half loop S->score */
                total += S->score[i];
                for (j = 0; j < PROTO_DEF_AVG_NR; j++)
                    S->avg[i][j] = S->score[i];
            }

        }
    }
    /* dbg("\n"); */

    return 0;
}
#endif


static uint32_t
pico_timer_ref_add(struct pico_stack *S, pico_time expire, struct pico_timer *t, uint32_t id, uint32_t hash)
{
    struct pico_timer_ref tref;

    tref.expire = PICO_TIME_MS() + expire;
    tref.tmr = t;
    tref.id = id;
    tref.hash = hash;

    if (heap_insert(S->Timers, &tref) < 0) {
        dbg("Error: failed to insert timer(ID %u) into heap\n", id);
        PICO_FREE(t);
        pico_err = PICO_ERR_ENOMEM;
        return 0;
    }
    if (S->Timers->n > PICO_MAX_TIMERS) {
        dbg("Warning: I have %d timers\n", (int)S->Timers->n);
    }

    return tref.id;
}

static struct pico_timer *
pico_timer_create(void (*timer)(pico_time, void *), void *arg)
{
    struct pico_timer *t = PICO_ZALLOC(sizeof(struct pico_timer));

    if (!t) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    t->arg = arg;
    t->timer = timer;

    return t;
}

MOCKABLE uint32_t pico_timer_add(struct pico_stack *S, pico_time expire, void (*timer)(pico_time, void *), void *arg)
{
    struct pico_timer *t = pico_timer_create(timer, arg);

    /* zero is guard for timers */
    if (S->timer_id == 0u) {
        S->timer_id++;
    }

    if (!t)
        return 0;

    return pico_timer_ref_add(S, expire, t, S->timer_id++, 0);
}

uint32_t pico_timer_add_hashed(struct pico_stack *S, pico_time expire, void (*timer)(pico_time, void *), void *arg, uint32_t hash)
{
    struct pico_timer *t = pico_timer_create(timer, arg);

    /* zero is guard for timers */
    if (S->timer_id == 0u) {
        S->timer_id++;
    }

    if (!t)
        return 0;

    return pico_timer_ref_add(S, expire, t, S->timer_id++, hash);
} /* Static path count: 4 */



int MOCKABLE pico_stack_init(struct pico_stack **S)
{
    int i;
    if (!S) {
        return PICO_ERR_EINVAL;
    } else {
        *S = PICO_ZALLOC(sizeof(struct pico_stack));
        if (!*S)
            return PICO_ERR_ENOMEM;
    }

    /* Initialize stack scheduler */
    pico_protocol_scheduler_init(*S);

    EMPTY_TREE((*S)->Device_tree, pico_dev_cmp);

#ifdef PICO_SUPPORT_ETH
    pico_protocol_init(*S, &pico_proto_ethernet);
    ATTACH_QUEUES(*S, ethernet, pico_proto_ethernet);
#endif

#ifdef PICO_SUPPORT_6LOWPAN
    pico_protocol_init(*S, &pico_proto_6lowpan);
    pico_protocol_init(*S, &pico_proto_6lowpan_ll);
    ATTACH_QUEUES(*S, sixlowpan, pico_proto_6lowpan);
    ATTACH_QUEUES(*S, sixlowpan_ll, pico_proto_6lowpan_ll);
    EMPTY_TREE((*S)->SixLowPanCTXTree, compare_6lowpan_ctx);
    EMPTY_TREE((*S)->LPFragTree, lp_frag_ctx_cmp);
    EMPTY_TREE((*S)->LPReassemblyTree, lp_frag_cmp);
#endif

#ifdef PICO_SUPPORT_PACKET_SOCKETS
    pico_protocol_init(*S, &pico_proto_ll);
    ATTACH_QUEUES(*S, proto_ll, pico_proto_ll);
    EMPTY_TREE((*S)->PSockets, pico_socket_ll_compare);
#endif

#ifdef PICO_SUPPORT_IPV4
    pico_protocol_init(*S, &pico_proto_ipv4);
    ATTACH_QUEUES(*S, ipv4, pico_proto_ipv4);
    /* Initialize "link" tree */
    EMPTY_TREE((*S)->Tree_dev_link, ipv4_link_compare);
    EMPTY_TREE((*S)->Routes, ipv4_route_compare);
    /* Set default broadcast route */
    (*S)->default_bcast_route = &initial_default_bcast_route;
#   ifdef PICO_SUPPORT_RAWSOCKETS
    EMPTY_TREE((*S)->IP4Sockets, pico_ipv4_rawsocket_cmp);
#   endif
#   ifdef PICO_SUPPORT_NAT
    EMPTY_TREE((*S)->NATOutbound, nat_cmp_outbound);
    EMPTY_TREE((*S)->NATInbound, nat_cmp_inbound);
#   endif
#   ifdef PICO_SUPPORT_IPV4FRAG
    EMPTY_TREE((*S)->ipv4_fragments, pico_ipv4_frag_compare);
#   endif
#   ifdef PICO_SUPPORT_SLAACV4
    EMPTY_TREE((*S)->Hotplug_device_tree, pico_hotplug_dev_cmp);
#endif
#endif

#ifdef PICO_SUPPORT_IPV6
    pico_protocol_init(*S, &pico_proto_ipv6);
    ATTACH_QUEUES(*S, ipv6, pico_proto_ipv6);
	EMPTY_TREE((*S)->Tree_dev_ip6_link, ipv6_link_compare);
	EMPTY_TREE((*S)->IPV6Routes, ipv6_route_compare);
	EMPTY_TREE((*S)->IPV6Links, ipv6_link_compare);
	EMPTY_TREE((*S)->IPV6NQueue, pico_ipv6_nd_qcompare);
	EMPTY_TREE((*S)->IPV6NCache, pico_ipv6_neighbor_compare);
	EMPTY_TREE((*S)->IPV6RCache, pico_ipv6_router_compare);
#   ifdef PICO_SUPPORT_IPV6FRAG
    EMPTY_TREE((*S)->ipv6_fragments, pico_ipv6_frag_compare);
#   endif
#endif

#ifdef PICO_SUPPORT_IPFILTER
    EMPTY_TREE((*S)->ipfilter_tree, filter_compare);
#endif

#ifdef PICO_SUPPORT_ICMP4
    pico_protocol_init(*S, &pico_proto_icmp4);
    ATTACH_QUEUES(*S, icmp4, pico_proto_icmp4);
    EMPTY_TREE((*S)->Pings, pico_icmp4_cookie_compare);
    EMPTY_TREE((*S)->ICMP4Sockets, icmp4_socket_cmp);
#endif

#ifdef PICO_SUPPORT_ICMP6
    pico_protocol_init(*S, &pico_proto_icmp6);
    ATTACH_QUEUES(*S, icmp6, pico_proto_icmp6);
    EMPTY_TREE((*S)->IPV6Pings, icmp6_cookie_compare); 
#endif

#if defined(PICO_SUPPORT_IGMP) && defined(PICO_SUPPORT_MCAST)
    pico_protocol_init(*S, &pico_proto_igmp);
    ATTACH_QUEUES(*S, igmp, pico_proto_igmp);
    EMPTY_TREE((*S)->IGMPParameters, igmp_parameters_cmp);
    EMPTY_TREE((*S)->IGMPTimers, igmp_timer_cmp);
    EMPTY_TREE((*S)->IGMPAllow, igmp_sources_cmp);
    EMPTY_TREE((*S)->IGMPBlock, igmp_sources_cmp);
    EMPTY_TREE((*S)->MCASTSockets, mcast_socket_cmp);
    EMPTY_TREE((*S)->MCASTFilter, mcast_filter_cmp);
    EMPTY_TREE((*S)->MCASTFilter_ipv6, mcast_filter_cmp_ipv6);
#endif

#ifdef PICO_SUPPORT_UDP
    pico_protocol_init(*S, &pico_proto_udp);
    ATTACH_QUEUES(*S, udp, pico_proto_udp);
    EMPTY_TREE((*S)->UDPTable, pico_socket_table_compare);
#endif

#ifdef PICO_SUPPORT_TCP
    pico_protocol_init(*S, &pico_proto_tcp);
    ATTACH_QUEUES(*S, tcp, pico_proto_tcp);
    EMPTY_TREE((*S)->TCPTable, pico_socket_table_compare);
#endif

#ifdef PICO_SUPPORT_DHCPC
    EMPTY_TREE((*S)->DHCPCookies, dhcp_cookies_cmp);
#endif

#ifdef PICO_SUPPORT_DHCPD
    EMPTY_TREE((*S)->DHCPSettings, dhcp_settings_cmp);
    EMPTY_TREE((*S)->DHCPNegotiations, dhcp_negotiations_cmp);
#endif

#ifdef PICO_SUPPORT_DNS_CLIENT
    EMPTY_TREE((*S)->DNSTable, dns_query_cmp);
    EMPTY_TREE((*S)->NSTable, dns_nameserver_cmp);
    pico_dns_client_init((*S));
#endif
    

#ifdef PICO_SUPPORT_MDNS
#   if PICO_MDNS_ALLOW_CACHING == 1
    EMPTY_TREE((*S)->MDNSCache, &pico_mdns_record_cmp);
#   endif
    EMPTY_TREE((*S)->MDNSOwnRecords, &pico_mdns_record_cmp_name_type);
    EMPTY_TREE((*S)->MDNSCookies, &pico_mdns_cookie_cmp);
#endif

    /* Initialize timer heap */
    (*S)->Timers = heap_init();
    if (!(*S)->Timers)
        return -1;

#if ((defined PICO_SUPPORT_IPV4) && (defined PICO_SUPPORT_ETH))
    /* Initialize ARP module */
    pico_arp_init(*S);
    EMPTY_TREE((*S)->arp_tree, arp_compare);
#endif

#ifdef PICO_SUPPORT_IPV6
    /* Initialize Neighbor discovery module */
    pico_ipv6_nd_init(*S);
#endif

#ifdef PICO_SUPPORT_IPV6PMTU
    pico_ipv6_path_init((*S), PICO_PMTU_CACHE_CLEANUP_INTERVAL);
    EMPTY_TREE((*S)->IPV6PathCache, pico_ipv6_path_compare); 
    (*S)->ipv6_path_cache_gc_timer.interval = PICO_PMTU_CACHE_CLEANUP_INTERVAL;
#endif

#ifdef PICO_SUPPORT_MLD
    EMPTY_TREE((*S)->MLDTimers, mld_timer_cmp);
    EMPTY_TREE((*S)->MLDParameters, mcast_parameters_cmp);
    EMPTY_TREE((*S)->MLDAllow, mld_sources_cmp);
    EMPTY_TREE((*S)->MLDBlock, mld_sources_cmp);
#endif


#ifdef PICO_SUPPORT_OLSR
    pico_olsr_init(*S);
#endif
#ifdef PICO_SUPPORT_AODV
    pico_aodv_init(*S);
    EMPTY_TREE((*S)->aodv_nodes, aodv_node_compare);
    EMPTY_TREE((*S)->aodv_nodes, aodv_dev_cmp);
#endif
#ifdef PICO_SUPPORT_6LOWPAN
    if (pico_6lowpan_init(*S))
       return -1;
#endif
#ifdef PICO_SUPPORT_SNTP_CLIENT
    (*S)->sntp_port = 123u;
#endif
    for (i = 0; i < PROTO_DEF_NR; i++)
        (*S)->score[i] = PROTO_DEF_SCORE;
    pico_stack_tick((*S));
    pico_stack_tick((*S));
    pico_stack_tick((*S));
    return 0;
}

#ifndef PICO_SUPPORT_TICKLESS
static void legacy_pico_stack_tick(struct pico_stack *S)
{
    pico_check_timers(S);
    S->ret[0] = pico_devices_loop(S, S->score[0], PICO_LOOP_DIR_IN);

    S->ret[1] = pico_protocol_datalink_loop(S, S->score[1], PICO_LOOP_DIR_IN);

    S->ret[2] = pico_protocol_network_loop(S, S->score[2], PICO_LOOP_DIR_IN);

    S->ret[3] = pico_protocol_transport_loop(S, S->score[3], PICO_LOOP_DIR_IN);


    S->ret[5] = S->score[5];
#if defined (PICO_SUPPORT_IPV4) || defined (PICO_SUPPORT_IPV6)
#if defined (PICO_SUPPORT_TCP) || defined (PICO_SUPPORT_UDP)
    S->ret[5] = pico_sockets_loop(S, S->score[5]); /* swapped */
#endif
#endif

    S->ret[4] = pico_protocol_socket_loop(S, S->score[4], PICO_LOOP_DIR_IN);

    S->ret[6] = pico_protocol_socket_loop(S, S->score[6], PICO_LOOP_DIR_OUT);

    S->ret[7] = pico_protocol_transport_loop(S, S->score[7], PICO_LOOP_DIR_OUT);

    S->ret[8] = pico_protocol_network_loop(S, S->score[8], PICO_LOOP_DIR_OUT);

    S->ret[9] = pico_protocol_datalink_loop(S, S->score[9], PICO_LOOP_DIR_OUT);

    S->ret[10] = pico_devices_loop(S, S->score[10], PICO_LOOP_DIR_OUT);

    /* calculate new loop S->scores for next iteration */
    calc_score(S);
}
#endif

void pico_stack_tick(struct pico_stack *S)
{
#ifdef PICO_SUPPORT_TICKLESS
    long long int interval;
    interval = pico_stack_go(S);
    (void)interval;
#else
    legacy_pico_stack_tick(S);
#endif
}

static void pico_terminate_timers(struct pico_stack *S)
{
    struct pico_timer *t;
    struct pico_timer_ref tref_unused, *tref = heap_first(S->Timers);
    pico_tick = PICO_TIME_MS();
    while(tref) {
        t = tref->tmr;
        if (t)
        {
            PICO_FREE(t);
        }

        heap_peek(S->Timers, &tref_unused);
        tref = heap_first(S->Timers);
    }
}

static void cleanup_queue(struct pico_queue *q)
{
    struct pico_frame *f = pico_dequeue(q);
    while (f) {
        pico_frame_discard(f);
        f = pico_dequeue(q);
    }
}


#define DETACH_QUEUES(St, pname) \
    do { \
       cleanup_queue(&(St)->q_ ## pname.in); \
       cleanup_queue(&(St)->q_ ## pname.out); \
    } while(0)


void pico_stack_deinit(struct pico_stack *S)
{
    struct pico_tree_node *node, *safe;
    struct pico_device *dev;
    /* Cleanup: timers */
    pico_terminate_timers(S);
    /* Cleanup: devices */
    pico_tree_foreach_safe(node, &S->Device_tree, safe) {
        dev = node->keyValue;
        pico_device_destroy(dev);
    }
    /* Cleanup: sockets */
    pico_socket_destroy_all(S);

    /* Cleanup: queues */
    
#ifdef PICO_SUPPORT_ETH
    DETACH_QUEUES(S, ethernet);
#endif

#ifdef PICO_SUPPORT_6LOWPAN
    DETACH_QUEUES(S, sixlowpan);
    DETACH_QUEUES(S, sixlowpan_ll);
#endif

#ifdef PICO_SUPPORT_IPV4
    DETACH_QUEUES(S, ipv4);
#endif

#ifdef PICO_SUPPORT_IPV6
    DETACH_QUEUES(S, ipv6);
#endif

#ifdef PICO_SUPPORT_ICMP4
    DETACH_QUEUES(S, icmp4);
#endif

#ifdef PICO_SUPPORT_ICMP6
    DETACH_QUEUES(S, icmp6);
#endif

#if defined(PICO_SUPPORT_IGMP) && defined(PICO_SUPPORT_MCAST)
    DETACH_QUEUES(S, igmp);
#endif

#ifdef PICO_SUPPORT_UDP
    DETACH_QUEUES(S, udp);
#endif

#ifdef PICO_SUPPORT_TCP
    DETACH_QUEUES(S, tcp);
#endif

}
