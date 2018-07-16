/*********************************************************************
  PicoTCP. Copyright (c) 2018 Daniele Lacamera. Some rights reserved.
  See LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

  This module is GPLv2/GPLv3 only.

  Authors: Daniele Lacamera
 ********************************************************************/

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv4.h"
#include "pico_arp.h"
#include "pico_socket.h"
#include "pico_olsr.h"
#include "pico_defines.h"
#ifdef PICO_SUPPORT_OLSR
#define TC_DGRAM_MAX_SIZE (100 - 28)
#define HELLO_DGRAM_MAX_SIZE (100 - 28)
#define MAX_OLSR_MEM (4 * TC_DGRAM_MAX_SIZE)

#ifdef DEBUG_OLSR
#define olsr_dbg dbg
#else
#define olsr_dbg(...) do {} while(0)
#endif

int OOM(void);

#define OLSR_HELLO_INTERVAL   ((uint32_t)5000)
#define OLSR_TC_INTERVAL      ((uint32_t)9000)
#define OLSR_MAXJITTER        ((uint32_t)(OLSR_HELLO_INTERVAL >> 2))

#define OLSR_HELLO_INTERVAL_SECONDS (uint32_t)(OLSR_HELLO_INTERVAL/1000)
#define OLSR_TC_INTERVAL_SECONDS	(uint32_t)(OLSR_TC_INTERVAL/1000)

static const struct pico_ip4 HOST_NETMASK = {
    0xffffffff
};
#ifndef MIN
# define MIN(a, b) (a < b ? a : b)
#endif

#ifndef AVG
# define AVG(a,b) ((uint8_t)(((int)a + (int)b) >> 1u))
#endif

#define fresher(a, b) ((a > b) || ((b - a) > 32768))


static uint16_t msg_counter; /* Global message sequence number */

/* Objects */
struct olsr_dev_entry
{
    struct olsr_dev_entry *next;
    struct pico_device *dev;
    uint16_t pkt_counter;
};


/* OLSR Protocol */
#define OLSRMSG_HELLO   0xc9
#define OLSRMSG_MID    0x03
#define OLSRMSG_TC    0xca

#define OLSRLINK_SYMMETRIC 0x06
#define OLSRLINK_ASYMMETRIC 0x01
#define OLSRLINK_LOST 0x03
#define OLSRLINK_UNKNOWN 0x08
#define OLSRLINK_MPR  0x0a



#define OLSR_PORT (short_be((uint16_t)698))


/* Headers */

PACKED_STRUCT_DEF olsr_link
{
    uint8_t link_code;
    uint8_t reserved;
    uint16_t link_msg_size;
};

PACKED_STRUCT_DEF olsr_neighbor
{
    uint32_t addr;
    uint8_t lq;
    uint8_t nlq;
    uint16_t reserved;
};

PACKED_STRUCT_DEF olsr_hmsg_hello
{
    uint16_t reserved;
    uint8_t htime;
    uint8_t willingness;
};

PACKED_STRUCT_DEF olsr_hmsg_tc
{
    uint16_t ansn;
    uint16_t reserved;
};


PACKED_STRUCT_DEF olsrmsg
{
    uint8_t type;
    uint8_t vtime;
    uint16_t size;
    struct pico_ip4 orig;
    uint8_t ttl;
    uint8_t hop;
    uint16_t seq;
};

PACKED_STRUCT_DEF olsrhdr
{
    uint16_t len;
    uint16_t seq;
};



/* Globals */
static struct pico_socket *udpsock = NULL;
uint16_t my_ansn = 0;
static struct olsr_route_entry  *Local_interfaces = NULL;
static struct olsr_dev_entry    *Local_devices    = NULL;

static struct olsr_dev_entry *olsr_get_deventry(struct pico_device *dev)
{
    struct olsr_dev_entry *cur = Local_devices;
    while(cur) {
        if (cur->dev == dev)
            return cur;

        cur = cur->next;
    }
    return NULL;
}

static inline void olsr_route_del(struct olsr_route_entry *r, uint8_t call, int force_del_neighbor);

struct olsr_route_entry *olsr_get_ethentry(struct pico_device *vif)
{
    struct olsr_route_entry *cur = Local_interfaces;
    while(cur) {
        if (cur->iface == vif)
            return cur;

        cur = cur->next;
    }
    return NULL;
}

static struct olsr_route_entry *get_next_hop(struct olsr_route_entry *dst)
{
    struct olsr_route_entry *hop = dst;
    while(hop) {
        /* olsr_dbg("Finding next hop to %08x m=%d", hop->destination.addr, hop->metric); */
        if(hop->metric <= 1)
            return hop;

        hop = hop->gateway;
    }
    return NULL;
}

static inline void olsr_route_add(struct olsr_route_entry *el, uint8_t call)
{
    struct olsr_route_entry *nexthop;

    if(!el)
        return;

    my_ansn++;

    nexthop = get_next_hop(el);
    if (el->gateway && nexthop && (nexthop->destination.addr != el->destination.addr)) {
        /* 2-hops route or more */
        el->next = el->gateway->children;
        el->gateway->children = el;
        el->link_type = OLSRLINK_MPR;
        pico_ipv4_route_add(el->destination, HOST_NETMASK, nexthop->destination, (int) el->metric, NULL);
    } else if (el->iface) {
        /* neighbor */
        struct olsr_route_entry *ei = olsr_get_ethentry(el->iface);
        struct pico_ip4 no_gw = {
            0U
        };
        if (el->link_type == OLSRLINK_UNKNOWN)
            el->link_type = OLSRLINK_SYMMETRIC;
        if (!ei) {
            ei = Local_interfaces;

        }
        if (ei) {
            el->next = ei->children;
            ei->children = el;
        }

        olsr_dbg("[OLSR]  ----------Adding neighbor %08x iface %s\n", el->destination.addr, el->iface->name);

        pico_ipv4_route_add(el->destination, HOST_NETMASK, no_gw, 1, pico_ipv4_link_by_dev(el->iface));
    }
}


static struct olsr_route_entry *olsr_destroy_entry(struct olsr_route_entry *lst, struct olsr_route_entry *r)
{
    if (lst == r) {
        struct olsr_route_entry *nxt = r->next;
        my_ansn++;
        while (r->children) {
            r->children = olsr_destroy_entry(r->children, r->children);
        }
        pico_ipv4_route_del(r->destination, HOST_NETMASK, r->metric);
        PICO_FREE(r);
        return nxt;
    }
    lst->next = olsr_destroy_entry(lst->next, r);
    return lst;
}

static inline void olsr_route_del(struct olsr_route_entry *r, uint8_t call, int force_del_neighbor)
{
    if (!r || !r->gateway || !r->gateway->children)
        return;
    r->gateway->children = olsr_destroy_entry(r->gateway->children, r);
}

static struct olsr_route_entry *get_route_by_address(struct olsr_route_entry *lst, uint32_t ip)
{
    struct olsr_route_entry *found;
    while(lst) {
        if (lst->destination.addr == ip) {
            return lst;
        }

        /* recursive function, could be dangerous for stack overflow if a lot of routes are available... */
        if (lst->children) {
            found = get_route_by_address(lst->children, ip);
            if (found)
                return found;
        }
        lst = lst->next;
    }
    return NULL;
}

#define OLSR_C_SHIFT (uint32_t)4 /* 1/16 */
#define DEFAULT_DEC 2u
#define DEFAULT_VTIME 288UL

static uint8_t seconds2olsr(uint32_t seconds)
{
    uint16_t a, b;
    if (seconds > 32767)
        seconds = 32767;

    /* find largest b such as seconds/C >= 2^b */
    for (b = 1; b <= 0x0fu; b++) {
        if ((uint16_t)(seconds * 16u) < (1u << b)) {
            b--;
            break;
        }
    }
    /* olsr_dbg("b=%u", b); */
    /* compute the expression 16*(T/(C*(2^b))-1), which may not be a
       integer, and round it up.  This results in the value for 'a' */
    /* a = (T / ( C * (1u << b) ) ) - 1u; */
    {
        uint16_t den = ((uint16_t)(1u << b) >> 4u);
        /* olsr_dbg(" den=%u ", den); */
        if (den == 0)
        {
            /* olsr_dbg("div by 0!\n"); */
            den = 1u;
        }

        a = (uint16_t)(((uint16_t)seconds / den) - (uint16_t)1);
    }
    /* if 'a' is equal to 16: increment 'b' by one, and set 'a' to 0 */
    if (16u == a) {
        b++;
        a = 0u;
    }

    return (uint8_t)((a << 4u) + b);
}

static void olsr_garbage_collector(struct olsr_route_entry *sublist)
{
    if(!sublist)
        return;
    olsr_garbage_collector(sublist->next);
    olsr_garbage_collector(sublist->children);

    if (sublist != Local_interfaces) {
        if (sublist->time_left <= 0) {
            olsr_dbg("Node %08x expired\r\n\n", sublist->destination.addr);
            olsr_route_del(sublist, 0xda, 0);
            return;
        } else {
            sublist->time_left -= DEFAULT_DEC;
        }
    }
}

struct olsr_fwd_pkt
{
    void *buf;
    uint16_t len;
    struct pico_device *pdev;
};

static uint32_t buffer_mem_used = 0U;

static void olsr_process_out(pico_time now, void *arg)
{
    struct olsr_fwd_pkt *p = (struct olsr_fwd_pkt *)arg;
    struct pico_ip4 bcast;
    struct pico_ipv4_link *addr;
    struct olsr_dev_entry *pdev = Local_devices;
    struct olsrhdr *ohdr;
    (void)now;

    /* Send the thing out */
    ohdr = (struct olsrhdr *)p->buf;
    ohdr->len = short_be((uint16_t)p->len);

    if (p->pdev) {
        struct olsr_dev_entry *odev = olsr_get_deventry(p->pdev);
        if (!odev) {
            goto out_free;
        }

        addr = pico_ipv4_link_by_dev(p->pdev);
        if (!addr)
            goto out_free;

        ohdr->seq = short_be((uint16_t)(odev->pkt_counter)++);
        if (addr->address.addr)
            bcast.addr = (addr->netmask.addr & addr->address.addr) | (~addr->netmask.addr);
        else
            bcast.addr = 0xFFFFFFFFu;

        if ( 0 > pico_socket_sendto(udpsock, p->buf, p->len, &bcast, OLSR_PORT)) {
            olsr_dbg("olsr send\n");
        }
    } else {
        while(pdev) {
            ohdr->seq = short_be((uint16_t)(pdev->pkt_counter++));
            addr = pico_ipv4_link_by_dev(pdev->dev);
            if (!addr)
                continue;

            if (addr->address.addr)
                bcast.addr = (addr->netmask.addr & addr->address.addr) | (~addr->netmask.addr);
            else
                bcast.addr = 0xFFFFFFFFu;

            if ( 0 > pico_socket_sendto(udpsock, p->buf, p->len, &bcast, OLSR_PORT)) {
                olsr_dbg("olsr send\n");
            }

            pdev = pdev->next;
        }
    }

out_free:
    PICO_FREE(p->buf);
    buffer_mem_used -= TC_DGRAM_MAX_SIZE;
    PICO_FREE(p);
}

static void olsr_scheduled_output(uint32_t when, void *buffer, uint16_t size, struct pico_device *pdev)
{
    struct olsr_fwd_pkt *p;
    /* olsr_dbg("Scheduling olsr packet, type:%s, size: %x\n", when == OLSR_HELLO_INTERVAL?"HELLO":"TC", size); */
    if ((buffer_mem_used + TC_DGRAM_MAX_SIZE) > MAX_OLSR_MEM) {
        PICO_FREE(buffer);
        return;
    }

    p = PICO_ZALLOC(sizeof(struct olsr_fwd_pkt));
    if (!p) {
        OOM();
        PICO_FREE(buffer);
        return;
    }

    p->buf = buffer;
    p->len = size;
    p->pdev = pdev;
    buffer_mem_used += TC_DGRAM_MAX_SIZE;
    if (!pico_timer_add(1 + when - ((pico_rand() % OLSR_MAXJITTER)), &olsr_process_out, p)) {
        olsr_dbg("OLSR: Failed to start process timer\n");
        OOM();
        PICO_FREE(p);
        PICO_FREE(buffer);
    }
}




static uint32_t olsr_build_hello_neighbors(uint8_t *buf, uint32_t size, struct olsr_route_entry **bookmark)
{
    uint32_t ret = 0;
    struct olsr_route_entry *local, *neighbor, *tmp;
    struct olsr_neighbor *dst = (struct olsr_neighbor *) buf;
    uint32_t total_link_size = sizeof(struct olsr_neighbor) + sizeof(struct olsr_link);
    local = Local_interfaces;
    while (local) {
        neighbor = local->children;
        if (*bookmark) {
            while ((neighbor) && *bookmark != neighbor)
                neighbor = neighbor->next;
        }

        while (neighbor) {
            struct olsr_link *li = (struct olsr_link *) (buf + ret);

            if ((size - ret) < total_link_size) {
                /* Incomplete list, new datagram needed. */
                *bookmark = neighbor;
                return ret;
            }

            li->link_code = neighbor->link_type;
            li->reserved = 0;
            li->link_msg_size = short_be((uint16_t)total_link_size);
            ret += (uint32_t)sizeof(struct olsr_link);
            dst = (struct olsr_neighbor *) (buf + ret);
            dst->addr = neighbor->destination.addr;
            dst->nlq = neighbor->nlq;
            dst->lq = neighbor->nlq;
            dst->reserved = 0;
            ret += (uint32_t)sizeof(struct olsr_neighbor);
            tmp = neighbor;
            neighbor = neighbor->next;
            if (tmp->link_type == OLSRLINK_LOST) {
                olsr_dbg("HELLO-LOST: force delete expired node\r\n");
                olsr_route_del(tmp, 2, 1);
            }
        }
        local = local->next;
    }
    *bookmark = NULL; /* All the list was visited, no more dgrams needed */
    return ret;
}

static uint32_t olsr_build_tc_neighbors(uint8_t *buf, uint32_t size, struct olsr_route_entry **bookmark)
{
    uint32_t ret = 0;
    struct olsr_route_entry *local, *neighbor;
    struct olsr_neighbor *dst = (struct olsr_neighbor *) buf;
    local = Local_interfaces;
    while (local) {
        neighbor = local->children;
        if (*bookmark) {
            while ((neighbor) && *bookmark != neighbor)
                neighbor = neighbor->next;
        }

        while (neighbor) {
            if (size - ret < sizeof(struct olsr_neighbor)) {
                /* Incomplete list, new datagram needed. */
                *bookmark = neighbor;
                return ret;
            }
            if (neighbor->link_type != OLSRLINK_LOST) {
                dst->addr = neighbor->destination.addr;
                dst->nlq = neighbor->nlq;
                dst->lq = neighbor->lq;
                dst->reserved = 0;
                ret += (uint32_t)sizeof(struct olsr_neighbor);
                dst = (struct olsr_neighbor *) (buf + ret);
            }
            neighbor = neighbor->next;
        }
        local = local->next;
    }
    *bookmark = NULL; /* All the list was visited, no more dgrams needed */
    return ret;
}

static uint32_t olsr_build_mid(uint8_t *buf, uint32_t size, struct pico_device *excluded)
{
    uint32_t ret = 0;
    struct olsr_route_entry *local;
    struct pico_ip4 *dst = (struct pico_ip4 *) buf;
    local = Local_interfaces;
    while (local) {
        if (local->iface != excluded) {
            dst->addr = local->destination.addr;
            ret += (uint32_t)sizeof(uint32_t);
            dst = (struct pico_ip4 *) (buf + ret);
            if (ret >= size)
                return (uint32_t)(ret - sizeof(uint32_t));
        }

        local = local->next;
    }
    return ret;
}


static void olsr_compose_tc_dgram(struct pico_device *pdev, struct pico_ipv4_link *ep)
{
    struct olsrmsg *msg_tc, *msg_mid;
    uint32_t size = 0, r;
    static struct olsr_route_entry *last_neighbor = NULL;
    uint8_t *dgram;
    struct olsr_hmsg_tc *tc;
    do {
        dgram = PICO_ZALLOC(TC_DGRAM_MAX_SIZE);
        if (!dgram) {
            OOM();
            return;
        }

        size = (uint32_t)sizeof(struct olsrhdr);
        ep = pico_ipv4_link_by_dev(pdev);
        if (!ep) {
            PICO_FREE(dgram);
            return;
        }


        if (!last_neighbor) {
            /* MID Message */
            msg_mid = (struct olsrmsg *)(dgram + size);
            size += (uint32_t)sizeof(struct olsrmsg);
            msg_mid->type = OLSRMSG_MID;
            msg_mid->vtime = seconds2olsr(DEFAULT_VTIME);
            msg_mid->orig.addr = ep->address.addr;
            msg_mid->ttl = 0xFF;
            msg_mid->hop = 0;
            msg_mid->seq = short_be(msg_counter++);
            r = olsr_build_mid(dgram + size, TC_DGRAM_MAX_SIZE - size, pdev);
            if (r == 0) {
                size -= (uint32_t)sizeof(struct olsrmsg);
            } else {
                if ((size + r) > TC_DGRAM_MAX_SIZE)
                    return;

                size += r;
                msg_mid->size = short_be((uint16_t)(sizeof(struct olsrmsg) + r));
            }
        }

        if (size + sizeof(struct olsrmsg) > TC_DGRAM_MAX_SIZE)
            return;

        msg_tc = (struct olsrmsg *) (dgram + size);
        size += (uint32_t)sizeof(struct olsrmsg);
        msg_tc->type = OLSRMSG_TC;
        msg_tc->vtime = seconds2olsr(DEFAULT_VTIME);
        msg_tc->orig.addr = ep->address.addr;
        msg_tc->ttl = 0xFF;
        msg_tc->hop = 0;
        msg_tc->seq = short_be(msg_counter++);
        tc = (struct olsr_hmsg_tc *)(dgram + size);
        size += (uint32_t)sizeof(struct olsr_hmsg_tc);
        if (size > TC_DGRAM_MAX_SIZE)
            return;

        tc->ansn = short_be(my_ansn);
        r = olsr_build_tc_neighbors(dgram + size, TC_DGRAM_MAX_SIZE  - size, &last_neighbor);
        size += r;
        msg_tc->size = short_be((uint16_t)(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_tc) + r));
        olsr_scheduled_output(OLSR_TC_INTERVAL, dgram, (uint16_t)size, pdev );
    } while(last_neighbor);
}

static void olsr_compose_hello_dgram(struct pico_device *pdev, struct pico_ipv4_link *ep)
{
    struct olsrmsg *msg_hello;
    uint32_t size = 0, r;
    static struct olsr_route_entry *last_neighbor = NULL;
    uint8_t *dgram;
    struct olsr_hmsg_hello *hello;
    /* HELLO Message */
    do {
        dgram = PICO_ZALLOC(HELLO_DGRAM_MAX_SIZE);
        if (!dgram) {
            OOM();
            return;
        }

        size = (uint32_t)sizeof(struct olsrhdr);
        msg_hello = (struct olsrmsg *) (dgram + size);
        size += (uint32_t)sizeof(struct olsrmsg);
        msg_hello->type = OLSRMSG_HELLO;
        msg_hello->vtime = seconds2olsr(DEFAULT_VTIME);
        msg_hello->orig.addr = ep->address.addr;
        msg_hello->ttl = 1;
        msg_hello->hop = 0;
        msg_hello->seq = short_be(msg_counter++);
        hello = (struct olsr_hmsg_hello *)(dgram + size);
        size += (uint32_t)sizeof(struct olsr_hmsg_hello);
        hello->reserved = 0;
        hello->htime = seconds2olsr(OLSR_HELLO_INTERVAL);
        hello->htime = 0x05; /* Todo: find and define values */
        hello->willingness = 0x07;
        if (HELLO_DGRAM_MAX_SIZE > size) {
            r = olsr_build_hello_neighbors(dgram + size, HELLO_DGRAM_MAX_SIZE - size, &last_neighbor);
            if (r == 0) {
                /* olsr_dbg("Building hello message\n"); */
                PICO_FREE(dgram);
                return;
            }
        }

        size += r;
        msg_hello->size = short_be((uint16_t)(sizeof(struct olsrmsg) + sizeof(struct olsr_hmsg_hello) + r));
        olsr_scheduled_output(OLSR_HELLO_INTERVAL, dgram, (uint16_t)size, pdev );
    } while(last_neighbor);
}

static void olsr_make_dgram(struct pico_device *pdev, int full)
{
    struct pico_ipv4_link *ep;
    ep = pico_ipv4_link_by_dev(pdev);
    if (!ep) {
        return;
    }

    if (!full) {
        olsr_compose_hello_dgram(pdev, ep);
    } else {
        olsr_compose_tc_dgram(pdev, ep);
    } /*if full */

}

static int olsr_route_replace(struct olsr_route_entry*r, struct olsr_route_entry*new_orig, uint8_t new_metric, uint8_t new_lq)
{
    if (new_metric == 1) {
        new_orig = olsr_get_ethentry(r->iface);
    }

    if ((r->gateway == new_orig) && (r->metric == new_metric)) {
        r->time_left = (DEFAULT_VTIME);
        return 0;
    }

    /* Sort by metric first, then lq on same hops */
    if ( (new_metric < r->metric) || ((new_metric == r->metric) && (new_lq > r->lq +10 )) ) {
        struct olsr_route_entry *new = PICO_ZALLOC(sizeof (struct olsr_route_entry));
        if (new) {
            memcpy(new, r, sizeof(struct olsr_dev_entry));
            new->gateway = new_orig;
            new->lq = new_lq;
            new->metric = new_metric;
            new->time_left = (DEFAULT_VTIME);
            olsr_route_del(r, 0, 0);
            olsr_route_add(new, 0);
            return 1;
        }
    }
    return 0;
}

static void recv_mid(uint8_t *buffer, uint32_t len, struct olsr_route_entry *origin)
{
    uint32_t parsed = 0;
    struct pico_ip4 *address;
    struct olsr_route_entry *e;
    uint8_t lq = (origin->nlq == 0) ? origin->lq : origin->nlq;

    if (len % sizeof(uint32_t)) /*drop*/
        return;

    while (len > parsed) {
        address = (struct pico_ip4 *)(buffer + parsed);

        if (pico_ipv4_link_get(address))
            return;

        e = get_route_by_address(Local_interfaces, address->addr);
        if (!e) {
            e = PICO_ZALLOC(sizeof(struct olsr_route_entry));
            if (!e) {
                OOM();
                return;
            }
            e->time_left = (DEFAULT_VTIME);
            e->destination.addr = address->addr;
            e->gateway = origin;
            e->iface = NULL;
            e->metric = (uint16_t)(origin->metric + 1u);
            e->lq = lq;
            e->nlq = lq;
            olsr_route_add(e, 1);
        } else {
            olsr_route_replace(e, origin, origin->metric + 1u, lq);
        }
        parsed += (uint32_t)sizeof(uint32_t);
    }
}

#define HELLO_PROCESS 1

extern uint8_t local_net;

#define THRESH_HI 0xFF - 70
#define THRESH_LO 0xFF - 60

uint8_t olsr_set_nlq(struct pico_ip4 addr, uint8_t nlq)
{
    struct olsr_route_entry *e = get_route_by_address(Local_interfaces, addr.addr);
    if (!e) {
        if (nlq < THRESH_HI)
            return 0;
        return nlq;
    }
    if (nlq == 0) {
        if (e && (e->nlq > THRESH_LO))
            return e->nlq;
        else
            return 0;
    }
    if ((e->nlq == 0xFF) || (e->nlq == 0)) {
        e->lq = e->nlq = nlq;
    } else {
        e->lq = e->nlq = (e->nlq - (e->nlq >> 3)) + (nlq >> 3); /* 1/8 new nlq + 7/8 old */
        if (e->nlq < THRESH_LO) {
            e->lq = e->nlq = 0;
            return 0;
        }
    }
    return e->nlq;
}

static void recv_hello(uint8_t *buffer, uint32_t len, struct olsr_route_entry *origin, uint16_t hops)
{
    struct olsr_link *li;
    struct olsr_route_entry *e;
    uint32_t parsed = 0;
    struct olsr_neighbor *neigh;

    if (!origin)
        return;
    /* Don't parse hello messages that were forwarded */
    if (hops > 0 || origin->metric > 1)
        return;
    /* Ignore self messages */
    if (pico_ipv4_link_get(&origin->destination))
        return;
    while (len > parsed) {
        uint8_t lq;
        int metric = 1;
        li = (struct olsr_link *) buffer;
        neigh = (struct olsr_neighbor *)(buffer + parsed + sizeof(struct olsr_link));
        parsed += short_be(li->link_msg_size);
        if (pico_ipv4_link_find((struct pico_ip4 *)&neigh->addr)) {
            origin->link_type = OLSRLINK_SYMMETRIC;
            continue;
        }
        e = get_route_by_address(Local_interfaces, neigh->addr);
        lq = AVG(origin->nlq, neigh->nlq);
        if (li->link_code != OLSRLINK_LOST) {
            if (e) {
                if (e == origin) {
                    metric = 1;
                } else {
                    metric = 2;
                }
                olsr_route_replace(e, origin, metric, lq);
            } else {
                e = PICO_ZALLOC(sizeof(struct olsr_route_entry));
                if (!e) {
                    OOM();
                    return;
                }
                e->time_left = (DEFAULT_VTIME);
                e->destination.addr = neigh->addr;
                e->gateway = origin;
                e->iface = origin->iface;
                e->metric = (uint16_t)(origin->metric + 1);
                e->link_type = OLSRLINK_SYMMETRIC;
                e->lq = lq;
                e->nlq = lq;
                olsr_route_add(e, 3);
            }
        } else { /* Lost */
            if (e && (e->gateway == origin)) {
                olsr_route_del(e, 7, 0);
            }
        }
    }
}



static int reconsider_topology(uint8_t *buf, uint32_t size, struct olsr_route_entry *e)
{
    struct olsr_hmsg_tc *tc = (struct olsr_hmsg_tc *) buf;
    uint16_t new_ansn = short_be(tc->ansn);
    uint32_t parsed = sizeof(struct olsr_hmsg_tc);
    struct olsr_route_entry *rt;
    struct olsr_neighbor *n;

    /* If the TC has never been received from this origin,
     * or the last one had an invalid ansn, restart the ansn counter
     * for this node.
     */
    if (!e->advertised_tc) {
        e->advertised_tc = 1;
        e->ansn = new_ansn;
    }

    /* if TC is invalid (old), reset the counter.
     * The next TC from this node will be parsed again.
     */
    if (fresher(e->ansn, new_ansn)) {
        e->advertised_tc = 0;
        return 0;
    }
    e->ansn = new_ansn;
    while (parsed < size) {
        n = (struct olsr_neighbor *) (buf + parsed);
        parsed += (uint32_t)sizeof(struct olsr_neighbor);
        rt = get_route_by_address(Local_interfaces, n->addr);
        if (rt) {
            olsr_route_replace(rt, e, e->metric + 1, AVG(e->lq, n->lq));
        } else {
            rt = PICO_ZALLOC(sizeof (struct olsr_route_entry));
            if (!rt) {
                return 0;
            }
            rt->destination.addr = n->addr;
            rt->link_type = OLSRLINK_UNKNOWN;
            rt->iface = e->iface;
            rt->gateway = e;
            rt->metric = (uint16_t)(e->metric + 1);
            rt->lq = n->lq;
            rt->nlq = n->lq;
            rt->time_left =(DEFAULT_VTIME);
            olsr_route_add(rt, 5);
        }
    }
    /* Allow forward of this TC */
    return 1;
}
uint32_t n_tc = 0;
static void olsr_recv(uint8_t *buffer, uint32_t len)
{
    struct olsrmsg *msg;
    struct olsrhdr *oh = (struct olsrhdr *) buffer;
    uint32_t parsed = 0;
    uint16_t outsize = 0;
    uint8_t *datagram;

    /* if Local_Interfaces is not initialized, don't parse. */
    if (!Local_interfaces)
        return;

    if (len != short_be(oh->len)) {
        return;
    }

    /* RFC 3626, section 3.4, if a packet is too small, it is silently discarded */
    if (len < 16) {
        return;
    }

    parsed += (uint32_t)sizeof(struct olsrhdr);

    datagram = PICO_ZALLOC(TC_DGRAM_MAX_SIZE);
    if (!datagram) {
        OOM();
        return;
    }

    if (buffer[4] == OLSRMSG_TC)
        n_tc++;

    outsize = (uint16_t) (outsize + (sizeof(struct olsrhdr)));
    /* Section 1: parsing received messages. */
    while (len > parsed) {
        struct olsr_route_entry *origin;
        msg = (struct olsrmsg *) (buffer + parsed);

        if(pico_ipv4_link_find(&msg->orig) != NULL) {
            parsed += short_be(msg->size);
            continue;
        }

        origin = get_route_by_address(Local_interfaces, msg->orig.addr);

        /* OLSR's TTL expired. */
        if (msg->ttl < 1u) {
            parsed += short_be(msg->size);
            continue;
        }

        if ((msg->type == OLSRMSG_HELLO) && origin && origin->gateway != olsr_get_ethentry(Local_devices->dev)) {
            olsr_route_del(origin, 0x60, 0);
            origin = NULL;
        }

        if (!origin) {
            if (msg->hop == 0) {
                struct olsr_route_entry *e = PICO_ZALLOC(sizeof (struct olsr_route_entry));
                if (!e) {
                    parsed += short_be(msg->size);
                    OOM();
                    break;
                }

                e->destination.addr = msg->orig.addr;
                e->link_type = OLSRLINK_ASYMMETRIC;
                e->time_left = (DEFAULT_VTIME);
                e->iface = Local_devices->dev;
                e->gateway = olsr_get_ethentry(e->iface);
                e->metric = 1;
                e->lq = 0xFF;
                e->nlq = 0xFF;
                olsr_route_add(e, 6);
                origin = e;
            } else {
                PICO_FREE(datagram);
                return;
            }
        }

        /* We know this is a Master host and a neighbor */
        if (origin->link_type == OLSRLINK_SYMMETRIC)
            origin->link_type = OLSRLINK_MPR;


        switch(msg->type) {
            case OLSRMSG_HELLO: {
                                    uint32_t size = (uint32_t)short_be(msg->size);
                                    uint8_t *pay = (uint8_t *) buffer + (uint32_t)parsed + (uint32_t)sizeof(struct olsrmsg) + (uint32_t)sizeof(struct olsr_hmsg_hello);
                                    origin->time_left = (DEFAULT_VTIME);
                                    recv_hello(pay, ((uint32_t) (size - (sizeof(struct olsrmsg)))) - (uint32_t)sizeof(struct olsr_hmsg_hello), origin, msg->hop);
                                    msg->ttl = 0;
                                }
                                break;
            case OLSRMSG_MID:
                                if ((origin->seq != 0) && (!fresher(short_be(msg->seq), origin->seq))) {
                                    msg->ttl = 0;
                                } else {
                                    recv_mid(buffer + parsed + sizeof(struct olsrmsg), (uint32_t)(short_be(msg->size) - (sizeof(struct olsrmsg))), origin);
                                    /* olsr_dbg("MID forwarded from origin %08x (seq: %u)\n", long_be(msg->orig.addr), short_be(msg->seq)); */
                                    origin->seq = short_be(msg->seq);
                                }

                                break;
            case OLSRMSG_TC:
                                if(!pico_ipv4_link_find(&origin->destination)) {
                                    if ((origin->seq != 0) && (!fresher(short_be(msg->seq), origin->seq))) {
                                        msg->ttl = 0;
                                        origin->seq = short_be(msg->seq);
                                        PICO_FREE(datagram);
                                        return;
                                    } else {
                                        /* Only parse valid messages */
                                        int ret = reconsider_topology(buffer + parsed + sizeof(struct olsrmsg),
                                                (uint32_t)(short_be(msg->size) - (sizeof(struct olsrmsg))),
                                                origin);
                                        if (ret == 0) {
                                            msg->ttl = 0;
                                        }
                                        origin->seq = short_be(msg->seq);
                                    }
                                } else {
                                    /* We originated this TC. */
                                    msg->ttl = 0;
                                }


                                break;
            default:
                                PICO_FREE(datagram);
                                return;
        }

        if (msg->ttl > 1) {
            uint16_t msize = short_be(msg->size);
            msg->hop++;
            msg->ttl--;
            if (outsize + msize < TC_DGRAM_MAX_SIZE) {
                memcpy(datagram + outsize, msg, short_be(msg->size));
                outsize = (uint16_t)(outsize + short_be(msg->size));
            }
        }

        parsed += short_be(msg->size);
        if (parsed != len) {
            olsr_dbg("Short parse: %d out of %d, loop again.\r\n", parsed, len);
        }
    }
    /* Section 2: forwarding parsed messages that got past the filter. */
    if ((outsize > sizeof(struct olsrhdr))) {
        /* Finalize FWD packet */
        olsr_scheduled_output(OLSR_MAXJITTER, datagram, outsize, NULL);
    } else {
        /* Nothing to forward. */
        PICO_FREE(datagram);
    }
}

static void wakeup(uint16_t ev, struct pico_socket *s)
{
    unsigned char *recvbuf;
    int r = 0;
    struct pico_ip4 ANY = {
        0
    };
    uint16_t port = OLSR_PORT;
    recvbuf = PICO_ZALLOC(TC_DGRAM_MAX_SIZE);
    if (!recvbuf) {
        OOM();
        return;
    }

    if (ev & PICO_SOCK_EV_RD) {
        r = pico_socket_recv(s, recvbuf, TC_DGRAM_MAX_SIZE);
        if (r > 0)
            olsr_recv(recvbuf, (uint32_t)r);
    }

    if (ev == PICO_SOCK_EV_ERR) {
        pico_socket_close(udpsock);
        udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
        if (udpsock)
            pico_socket_bind(udpsock, &ANY, &port);
    }

    PICO_FREE(recvbuf);
}

static void olsr_hello_tick(pico_time when, void *unused)
{
    struct olsr_dev_entry *d;
    (void)when;
    (void)unused;
    d = Local_devices;
    while(d) {
        olsr_make_dgram(d->dev, 0);
        d = d->next;
    }
    pico_timer_add(OLSR_HELLO_INTERVAL, &olsr_hello_tick, NULL);
}

static void olsr_tc_tick(pico_time when, void *unused)
{
    struct olsr_dev_entry *d;
    (void)when;
    (void)unused;
    d = Local_devices;
    while(d) {
        olsr_make_dgram(d->dev, 1);
        d = d->next;
    }
    pico_timer_add(OLSR_TC_INTERVAL, &olsr_tc_tick, NULL);
}

uint32_t garbage_tick = 0;
static void olsr_garbage_tick(pico_time when, void *unused)
{
    (void)when;
    (void)unused;
    garbage_tick++;
    olsr_garbage_collector(Local_interfaces);
    pico_timer_add(2000, &olsr_garbage_tick, NULL);
}

void pico_olsr_init(void)
{
    struct pico_ip4 ANY = {
        0
    };
    uint16_t port = OLSR_PORT;
    olsr_dbg("OLSR initialized.\n");
    if (!udpsock) {
        udpsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
        if (udpsock)
            pico_socket_bind(udpsock, &ANY, &port);
    }

    pico_timer_add(pico_rand() % 100, &olsr_hello_tick, NULL);
    pico_timer_add(pico_rand() % 900, &olsr_tc_tick, NULL);
    pico_timer_add(2000, &olsr_garbage_tick, NULL);
}


int OOM(void)
{
    volatile int c = 3600;
    c++;
    c++;
    c++;
    return -1;
}

int pico_olsr_add(struct pico_device *dev)
{
    struct pico_ipv4_link *lnk = NULL;
    struct olsr_dev_entry *od;
    if (!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    /* olsr_dbg("OLSR: Adding device %s\n", dev->name); */
    od = PICO_ZALLOC(sizeof(struct olsr_dev_entry));
    if (!od) {
        pico_err = PICO_ERR_ENOMEM;
        /* OOM(); */
        return -1;
    }
    od->dev = dev;
    od->next = Local_devices;
    Local_devices = od;
    do {
        char ipaddr[20];
        lnk = pico_ipv4_link_by_dev_next(dev, lnk);
        if (lnk) {
            struct olsr_route_entry *e = PICO_ZALLOC(sizeof(struct olsr_route_entry));
            /* olsr_dbg("OLSR: Found IP address %08x\n", long_be(lnk->address.addr)); */
            pico_ipv4_to_string(ipaddr, (lnk->address.addr));
            /* olsr_dbg("OLSR: Found IP address %s\n", ipaddr); */
            if (!e) {
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }

            e->destination.addr = lnk->address.addr;
            e->link_type = OLSRLINK_SYMMETRIC;
            e->time_left = (OLSR_HELLO_INTERVAL << 2);
            e->gateway = NULL;
            e->children = NULL;
            e->iface = dev;
            e->metric = 0;
            e->lq = 0xFF;
            e->nlq = 0xFF;
            e->next = Local_interfaces;
            Local_interfaces = e;

        }
    } while(lnk);
    return 0;
}


struct olsr_route_entry kill_neighbour(uint32_t loc_add, uint32_t rem_add)
{
    struct olsr_route_entry *origin;
    origin = get_route_by_address(Local_interfaces, rem_add);
    if (origin){
        if (origin->gateway){
            if (origin->gateway->destination.addr == loc_add)
                origin->time_left = 0;
        }
    }
    return *origin;
}

#endif
