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
#include "pico_arp.h"
#include "pico_tree.h"
#include "pico_ipv4.h"
#include "pico_device.h"
#include "pico_stack.h"

extern const uint8_t PICO_ETHADDR_ALL[6];
#define PICO_ARP_TIMEOUT 600000llu
#define PICO_ARP_RETRY 300lu
#define PICO_ARP_MAX_PENDING 5

#ifdef DEBUG_ARP
    #define arp_dbg dbg
#else
    #define arp_dbg(...) do {} while(0)
#endif

static int max_arp_reqs = PICO_ARP_MAX_RATE;
static uint32_t arp_rate_timer = 0u;
static struct pico_frame *frames_queued[PICO_ARP_MAX_PENDING] = {
    0
};

static void pico_arp_queued_trigger(void)
{
    int i;
    struct pico_frame *f;
    for (i = 0; i < PICO_ARP_MAX_PENDING; i++)
    {
        f = frames_queued[i];
        if (f) {
            if (pico_datalink_send(f) <= 0)
                pico_frame_discard(f);
            frames_queued[i] = NULL;
        }
    }
}

static void update_max_arp_reqs(pico_time now, void *arg)
{
    struct pico_stack *S = (struct pico_stack *)arg;
    IGNORE_PARAMETER(now);
    if (max_arp_reqs < PICO_ARP_MAX_RATE) {
        arp_rate_timer = pico_timer_add(S, PICO_ARP_INTERVAL / PICO_ARP_MAX_RATE, &update_max_arp_reqs, S);
        max_arp_reqs++;
    } else {
        arp_rate_timer = 0u;
    }
}

void pico_arp_init(struct pico_stack *S)
{
    (void)S;
    if (!pico_timer_add(S, PICO_ARP_INTERVAL / PICO_ARP_MAX_RATE, &update_max_arp_reqs, S)) {
        arp_dbg("ARP: Failed to start update_max_arps timer\n");
    }
}

PACKED_STRUCT_DEF pico_arp_hdr
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t opcode;
    uint8_t s_mac[PICO_SIZE_ETH];
    struct pico_ip4 src;
    uint8_t d_mac[PICO_SIZE_ETH];
    struct pico_ip4 dst;
};


#define PICO_SIZE_ARPHDR ((sizeof(struct pico_arp_hdr)))

/* Arp Entries for the tables. */
struct pico_arp {
/* CAREFUL MAN! ARP entry MUST begin with a pico_eth structure,
 * due to in-place casting!!! */
    struct pico_eth eth;
    struct pico_ip4 ipv4;
    int arp_status;
    pico_time timestamp;
    struct pico_device *dev;
    uint32_t timer;
};



/*****************/
/**  ARP TREE **/
/*****************/

/* Routing destination */

int arp_compare(void *ka, void *kb)
{
    struct pico_arp *a = ka, *b = kb;
    return pico_ipv4_compare(&a->ipv4, &b->ipv4);
}


/*********************/
/**  END ARP TREE **/
/*********************/

struct pico_eth *pico_arp_lookup(struct pico_stack *S, struct pico_ip4 *dst)
{
    struct pico_arp search, *found;
    search.ipv4.addr = dst->addr;
    found = pico_tree_findKey(&S->arp_tree, &search);
    if (found && (found->arp_status != PICO_ARP_STATUS_STALE))
        return &found->eth;

    return NULL;
}

struct pico_ip4 *pico_arp_reverse_lookup(struct pico_stack *S, struct pico_eth *dst)
{
    struct pico_arp*search;
    struct pico_tree_node *index;
    pico_tree_foreach(index, &S->arp_tree){
        search = index->keyValue;
        if(memcmp(&(search->eth.addr), &dst->addr, 6) == 0)
            return &search->ipv4;
    }
    return NULL;
}

static void pico_arp_unreachable(struct pico_stack *S, struct pico_ip4 *a)
{
    int i;
    struct pico_frame *f;
    struct pico_ipv4_hdr *hdr;
    struct pico_ip4 dst;
    for (i = 0; i < PICO_ARP_MAX_PENDING; i++)
    {
        f = frames_queued[i];
        if (f) {
            hdr = (struct pico_ipv4_hdr *) f->net_hdr;
            dst = pico_ipv4_route_get_gateway(S, &hdr->dst);
            if (!dst.addr)
                dst.addr = hdr->dst.addr;

            if (dst.addr ==  a->addr) {
                if (!pico_source_is_local(S, f)) {
                    pico_notify_dest_unreachable(S, f);
                }

            }
        }
    }
}

static void pico_arp_retry(struct pico_stack *S, struct pico_frame *f, struct pico_ip4 *where)
{
    if (++f->failure_count < 4) {
        arp_dbg ("================= ARP REQUIRED: %d =============\n\n", f->failure_count);
        /* check if dst is local (gateway = 0), or if to use gateway */
        pico_arp_request(f->dev, where, PICO_ARP_QUERY);
    } else {
        pico_arp_unreachable(S, where);
    }
}

struct pico_eth *pico_arp_get(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_eth *a4;
    struct pico_ip4 gateway;
    struct pico_ip4 *where;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_ipv4_link *l;
    if (!hdr)
        return NULL;

    l = pico_ipv4_link_get(S, &hdr->dst);
    if(l) {
        /* address belongs to ourself */
        return &l->dev->eth->mac;
    }

    gateway = pico_ipv4_route_get_gateway(S, &hdr->dst);
    /* check if dst is local (gateway = 0), or if to use gateway */
    if (gateway.addr != 0)
        where = &gateway;
    else
        where = &hdr->dst;

    a4 = pico_arp_lookup(S, where);      /* check if dst ip mac in cache */

    if (!a4)
        pico_arp_retry(S, f, where);

    return a4;
}


void pico_arp_postpone(struct pico_frame *f)
{
    int i;
    for (i = 0; i < PICO_ARP_MAX_PENDING; i++)
    {
        if (!frames_queued[i]) {
            if (f->failure_count < 4)
                frames_queued[i] = f;

            return;
        }
    }
    /* Not possible to enqueue: caller will discard packet */
}


#ifdef DEBUG_ARP
static void dbg_arp(void)
{
    struct pico_arp *a;
    struct pico_tree_node *index;

    pico_tree_foreach(index, &S->arp_tree) {
        a = index->keyValue;
        arp_dbg("ARP to  %08x, mac: %02x:%02x:%02x:%02x:%02x:%02x\n", a->ipv4.addr, a->eth.addr[0], a->eth.addr[1], a->eth.addr[2], a->eth.addr[3], a->eth.addr[4], a->eth.addr[5] );
    }
}
#endif

static void arp_expire(pico_time now, void *_stale)
{
    struct pico_arp *stale = (struct pico_arp *) _stale;
    if (now >= (stale->timestamp + PICO_ARP_TIMEOUT)) {
        stale->arp_status = PICO_ARP_STATUS_STALE;
        arp_dbg("ARP: Setting arp_status to STALE\n");
        pico_arp_request(stale->dev, &stale->ipv4, PICO_ARP_QUERY);
    } else {
        /* Timer must be rescheduled, ARP entry has been renewed lately.
         * No action required to refresh the entry, will check on the next timeout */
        if (!pico_timer_add(stale->dev->stack, PICO_ARP_TIMEOUT + stale->timestamp - now, arp_expire, stale)) {
            arp_dbg("ARP: Failed to start expiration timer, destroying arp entry\n");
            pico_tree_delete(&stale->dev->stack->arp_tree, stale);
            PICO_FREE(stale);
        }
    }
}

static int pico_arp_add_entry(struct pico_arp *entry)
{
    entry->arp_status = PICO_ARP_STATUS_REACHABLE;
    entry->timestamp  = PICO_TIME();

    if (pico_tree_insert(&entry->dev->stack->arp_tree, entry)) {
        arp_dbg("ARP: Failed to insert new entry in tree\n");
        return -1;
    }

    arp_dbg("ARP ## reachable.\n");
    pico_arp_queued_trigger();
    if (!pico_timer_add(entry->dev->stack, PICO_ARP_TIMEOUT, arp_expire, entry)) {
        arp_dbg("ARP: Failed to start expiration timer\n");
        pico_tree_delete(&entry->dev->stack->arp_tree, entry);
        return -1;
    }

    return 0;
}

int pico_arp_create_entry(uint8_t *hwaddr, struct pico_ip4 ipv4, struct pico_device *dev)
{
    struct pico_arp*arp = PICO_ZALLOC(sizeof(struct pico_arp));
    if(!arp) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    memcpy(arp->eth.addr, hwaddr, 6);
    arp->ipv4.addr = ipv4.addr;
    arp->dev = dev;

    if (pico_arp_add_entry(arp) < 0) {
        PICO_FREE(arp);
        return -1;
    }

    return 0;
}

static void pico_arp_check_conflict(struct pico_stack *S, struct pico_arp_hdr *hdr)
{
    if (S->conflict_ipv4.conflict)
    {
        if((S->conflict_ipv4.ip.addr == hdr->src.addr) &&
           (memcmp(hdr->s_mac, S->conflict_ipv4.mac.addr, PICO_SIZE_ETH) != 0))
            S->conflict_ipv4.conflict(S, PICO_ARP_CONFLICT_REASON_CONFLICT );

        if((hdr->src.addr == 0) && (hdr->dst.addr == S->conflict_ipv4.ip.addr))
            S->conflict_ipv4.conflict(S, PICO_ARP_CONFLICT_REASON_PROBE );
    }
}

static struct pico_arp *pico_arp_lookup_entry(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_arp search;
    struct pico_arp *found = NULL;
    struct pico_arp_hdr *hdr = (struct pico_arp_hdr *) f->net_hdr;
    /* Populate a new arp entry */
    search.ipv4.addr = hdr->src.addr;
    /* Search for already existing entry */
    found = pico_tree_findKey(&S->arp_tree, &search);
    if (found) {
        if (found->arp_status == PICO_ARP_STATUS_STALE) {
            /* Replace if stale */
            pico_tree_delete(&S->arp_tree, found);
            if (pico_arp_add_entry(found) < 0) {
                arp_dbg("ARP: Failed to re-insert stale arp entry\n");
                PICO_FREE(found);
                found = NULL;
            }
        } else {
            /* Update mac address */
            memcpy(found->eth.addr, hdr->s_mac, PICO_SIZE_ETH);
            arp_dbg("ARP entry updated!\n");

            /* Refresh timestamp, this will force a reschedule on the next timeout*/
            found->timestamp = PICO_TIME();
        }
    }

    return found;
}


static int pico_arp_check_incoming_hdr_type(struct pico_arp_hdr *h)
{
    /* Check the hardware type and protocol */
    if ((h->htype != PICO_ARP_HTYPE_ETH) || (h->ptype != PICO_IDETH_IPV4))
        return -1;

    return 0;
}

static int pico_arp_check_incoming_hdr(struct pico_frame *f, struct pico_ip4 *dst_addr)
{
    struct pico_arp_hdr *hdr = (struct pico_arp_hdr *) f->net_hdr;
    if (!hdr)
        return -1;

    dst_addr->addr = hdr->dst.addr;
    if (pico_arp_check_incoming_hdr_type(hdr) < 0)
        return -1;

    /* The source mac address must not be a multicast or broadcast address */
    if (hdr->s_mac[0] & 0x01)
        return -1;

    return 0;
}

static void pico_arp_reply_on_request(struct pico_frame *f, struct pico_ip4 me)
{
    struct pico_arp_hdr *hdr;
    struct pico_eth_hdr *eh;

    hdr = (struct pico_arp_hdr *) f->net_hdr;
    eh = (struct pico_eth_hdr *)f->datalink_hdr;
    if (hdr->opcode != PICO_ARP_REQUEST)
        return;

    hdr->opcode = PICO_ARP_REPLY;
    memcpy(hdr->d_mac, hdr->s_mac, PICO_SIZE_ETH);
    memcpy(hdr->s_mac, f->dev->eth->mac.addr, PICO_SIZE_ETH);
    hdr->dst.addr = hdr->src.addr;
    hdr->src.addr = me.addr;

    /* Prepare eth header for arp reply */
    memcpy(eh->daddr, eh->saddr, PICO_SIZE_ETH);
    memcpy(eh->saddr, f->dev->eth->mac.addr, PICO_SIZE_ETH);
    f->start = f->datalink_hdr;
    f->len = PICO_SIZE_ETHHDR + PICO_SIZE_ARPHDR;
    f->dev->send(f->dev, f->start, (int)f->len);
}

static int pico_arp_check_flooding(struct pico_frame *f, struct pico_ip4 me)
{
    struct pico_device *link_dev;
    struct pico_arp_hdr *hdr;
    hdr = (struct pico_arp_hdr *) f->net_hdr;

    /* Prevent ARP flooding */
    link_dev = pico_ipv4_link_find(f->dev->stack, &me);
    if ((link_dev == f->dev) && (hdr->opcode == PICO_ARP_REQUEST)) {
        if (max_arp_reqs == 0)
            return -1;
        else
            max_arp_reqs--;
    }

    /* Check if we are the target IP address */
    if (link_dev != f->dev)
        return -1;

    /* Check if rate timer is running, or reschedule */
    if (!arp_rate_timer)
        arp_rate_timer = pico_timer_add(f->dev->stack, PICO_ARP_INTERVAL / PICO_ARP_MAX_RATE, &update_max_arp_reqs, f->dev->stack);

    return 0;
}

static int pico_arp_process_in(struct pico_frame *f, struct pico_arp_hdr *hdr, struct pico_arp *found)
{
    struct pico_ip4 me;
    if (pico_arp_check_incoming_hdr(f, &me) < 0) {
        pico_frame_discard(f);
        return -1;
    }

    if (pico_arp_check_flooding(f, me) < 0) {
        pico_frame_discard(f);
        return -1;
    }

    /* If no existing entry was found, create a new entry, or fail trying. */
    if ((!found) && (pico_arp_create_entry(hdr->s_mac, hdr->src, f->dev) < 0)) {
        pico_frame_discard(f);
        return -1;
    }

    /* If the packet is a request, send a reply */
    pico_arp_reply_on_request(f, me);

#ifdef DEBUG_ARP
    dbg_arp();
#endif
    pico_frame_discard(f);
    return 0;
}

int pico_arp_receive(struct pico_frame *f)
{
    struct pico_arp_hdr *hdr;
    struct pico_arp *found = NULL;

    hdr = (struct pico_arp_hdr *) f->net_hdr;
    if (!hdr) {
        pico_frame_discard(f);
        return -1;
    }

    pico_arp_check_conflict(f->dev->stack, hdr);
    found = pico_arp_lookup_entry(f->dev->stack, f);
    return pico_arp_process_in(f, hdr, found);

}

static int32_t pico_arp_request_xmit(struct pico_device *dev, struct pico_frame *f, struct pico_ip4 *src, struct pico_ip4 *dst, uint8_t type)
{
    struct pico_arp_hdr *ah = (struct pico_arp_hdr *) (f->start + PICO_SIZE_ETHHDR);
    int ret;

    /* Fill arp header */
    ah->htype  = PICO_ARP_HTYPE_ETH;
    ah->ptype  = PICO_IDETH_IPV4;
    ah->hsize  = PICO_SIZE_ETH;
    ah->psize  = PICO_SIZE_IP4;
    ah->opcode = PICO_ARP_REQUEST;
    memcpy(ah->s_mac, dev->eth->mac.addr, PICO_SIZE_ETH);

    switch (type) {
    case PICO_ARP_ANNOUNCE:
        ah->src.addr = dst->addr;
        ah->dst.addr = dst->addr;
        break;
    case PICO_ARP_PROBE:
        ah->src.addr = 0;
        ah->dst.addr = dst->addr;
        break;
    case PICO_ARP_QUERY:
        ah->src.addr = src->addr;
        ah->dst.addr = dst->addr;
        break;
    default:
        pico_frame_discard(f);
        return -1;
    }
    arp_dbg("Sending arp request.\n");
    ret = dev->send(dev, f->start, (int) f->len);
    pico_frame_discard(f);
    return ret;
}

int32_t pico_arp_request(struct pico_device *dev, struct pico_ip4 *dst, uint8_t type)
{
    struct pico_frame *q = pico_frame_alloc(PICO_SIZE_ETHHDR + PICO_SIZE_ARPHDR);
    struct pico_eth_hdr *eh;
    struct pico_ip4 *src = NULL;

    if (!q)
        return -1;

    if (type == PICO_ARP_QUERY)
    {
        src = pico_ipv4_source_find(dev->stack, dst);
        if (!src) {
            pico_frame_discard(q);
            return -1;
        }
    }

    arp_dbg("QUERY: %08x\n", dst->addr);

    eh = (struct pico_eth_hdr *)q->start;

    /* Fill eth header */
    memcpy(eh->saddr, dev->eth->mac.addr, PICO_SIZE_ETH);
    memcpy(eh->daddr, PICO_ETHADDR_ALL, PICO_SIZE_ETH);
    eh->proto = PICO_IDETH_ARP;

    return pico_arp_request_xmit(dev, q, src, dst, type);
}

void pico_arp_register_ipconflict(struct pico_stack *S, struct pico_ip4 *ip, struct pico_eth *mac, void (*cb)(struct pico_stack *S, int reason))
{
    S->conflict_ipv4.conflict = cb;
    S->conflict_ipv4.ip.addr = ip->addr;
    if (mac != NULL)
        memcpy(S->conflict_ipv4.mac.addr, mac, 6);
}

