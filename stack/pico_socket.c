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
#include "pico_socket_tcp.h"
#include "pico_socket_udp.h"
#include "pico_ipv6_pmtu.h"
#include "pico_socket_ll.h"

#if defined (PICO_SUPPORT_IPV4) || defined (PICO_SUPPORT_IPV6) || defined(PICO_SUPPORT_PACKET_SOCKETS)
#if defined (PICO_SUPPORT_TCP) || defined (PICO_SUPPORT_UDP) || defined(PICO_SUPPORT_PACKET_SOCKETS)


#define PROTO(s) ((s)->proto->proto_number)
#define PICO_MIN_MSS (1280)
#define TCP_STATE(s) (s->state & PICO_SOCKET_STATE_TCP)


/* Mockables */
#if defined UNIT_TEST
#   define MOCKABLE __attribute__((weak))
#else
#   define MOCKABLE
#endif

#define PROTO(s) ((s)->proto->proto_number)

#define PICO_SOCKET_MTU 1480 /* Ethernet MTU(1500) - IP header size(20) */

#ifdef PICO_SUPPORT_IPV4FRAG

#ifdef DEBUG_FRAG
#define frag_dbg      dbg
#else
#define frag_dbg(...) do {} while(0)
#endif

#endif


struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, struct pico_device *dev, uint16_t len);

static int socket_cmp_family(struct pico_socket *a, struct pico_socket *b)
{
    uint32_t a_is_ip6 = is_sock_ipv6(a);
    uint32_t b_is_ip6 = is_sock_ipv6(b);
    (void)a;
    (void)b;
    if (a_is_ip6 < b_is_ip6)
        return -1;

    if (a_is_ip6 > b_is_ip6)
        return 1;

    return 0;
}


static int socket_cmp_ipv6(struct pico_socket *a, struct pico_socket *b)
{
    int ret = 0;
    (void)a;
    (void)b;
#ifdef PICO_SUPPORT_IPV6
    if (!is_sock_ipv6(a) || !is_sock_ipv6(b))
        return 0;

    if ((memcmp(a->local_addr.ip6.addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0) || (memcmp(b->local_addr.ip6.addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0))
        ret = 0;
    else
        ret = memcmp(a->local_addr.ip6.addr, b->local_addr.ip6.addr, PICO_SIZE_IP6);

#endif
    return ret;
}

static int socket_cmp_ipv4(struct pico_socket *a, struct pico_socket *b)
{
    int ret = 0;
    (void)a;
    (void)b;
    if (!is_sock_ipv4(a) || !is_sock_ipv4(b))
        return 0;

#ifdef PICO_SUPPORT_IPV4
    if ((a->local_addr.ip4.addr == PICO_IP4_ANY) || (b->local_addr.ip4.addr == PICO_IP4_ANY))
        ret = 0;
    else
        ret = (int)(a->local_addr.ip4.addr - b->local_addr.ip4.addr);

#endif
    return ret;
}

static int socket_cmp_remotehost(struct pico_socket *a, struct pico_socket *b)
{
    int ret = 0;
    if (is_sock_ipv6(a))
        ret = memcmp(a->remote_addr.ip6.addr, b->remote_addr.ip6.addr, PICO_SIZE_IP6);
    else
        ret = (int)(a->remote_addr.ip4.addr - b->remote_addr.ip4.addr);

    return ret;
}

static int socket_cmp_addresses(struct pico_socket *a, struct pico_socket *b)
{
    int ret = 0;
    /* At this point, sort by local host */
    ret = socket_cmp_ipv6(a, b);

    if (ret == 0)
        ret = socket_cmp_ipv4(a, b);

    /* Sort by remote host */
    if (ret == 0)
        ret = socket_cmp_remotehost(a, b);

    return ret;
}

static int socket_cmp(void *ka, void *kb)
{
    struct pico_socket *a = ka, *b = kb;
    int ret = 0;

    /* First, order by network family */
    ret = socket_cmp_family(a, b);

    /* Then, compare by source/destination addresses */
    if (ret == 0)
        ret = socket_cmp_addresses(a, b);

    /* And finally by remote port. The two sockets are coincident if the quad is the same. */
    if (ret == 0)
        ret = b->remote_port - a->remote_port;

    return ret;
}


#define INIT_SOCKPORT { {&LEAF, pico_socket_table_compare}, 0, 0, NULL }

int pico_socket_table_compare(void *ka, void *kb)
{
    struct pico_sockport *a = ka, *b = kb;
    if (a->number < b->number)
        return -1;

    if (a->number > b->number)
        return 1;

    return 0;
}

struct pico_sockport *pico_get_sockport(struct pico_stack *S, uint16_t proto, uint16_t port)
{
    struct pico_sockport test = INIT_SOCKPORT;
    test.number = port;

#ifdef PICO_SUPPORT_UDP
    if (proto == PICO_PROTO_UDP)
        return pico_tree_findKey(&S->UDPTable, &test);
#endif
#ifdef PICO_SUPPORT_TCP
    if (proto == PICO_PROTO_TCP)
        return pico_tree_findKey(&S->TCPTable, &test);
#endif
    return NULL;
}

#ifdef PICO_SUPPORT_IPV4

static int pico_port_in_use_by_nat(struct pico_stack *S, uint16_t proto, uint16_t port)
{
    int ret = 0;
    (void) proto;
    (void) port;
#ifdef PICO_SUPPORT_NAT
    if (pico_ipv4_nat_find(S, port, NULL, 0, (uint8_t)proto)) {
        dbg("In use by nat....\n");
        ret = 1;
    }

#endif
    return ret;
}

static int pico_port_in_use_with_this_ipv4_address(struct pico_sockport *sp, struct pico_ip4 ip)
{
    if (sp) {
        struct pico_ip4 *s_local;
        struct pico_tree_node *idx;
        struct pico_socket *s;
        pico_tree_foreach(idx, &sp->socks) {
            s = idx->keyValue;
            if (s->net == &pico_proto_ipv4) {
                s_local = (struct pico_ip4*) &s->local_addr;
                if ((s_local->addr == PICO_IPV4_INADDR_ANY) || (s_local->addr == ip.addr)) {
                    return 1;
                }
            }
        }
    }

    return 0;
}


static int pico_port_in_use_ipv4(struct pico_sockport *sp, void *addr)
{
    struct pico_ip4 ip;
    /* IPv4 */
    if (addr)
        ip.addr = ((struct pico_ip4 *)addr)->addr;
    else
        ip.addr = PICO_IPV4_INADDR_ANY;

    if (ip.addr == PICO_IPV4_INADDR_ANY) {
        if (!sp)
            return 0;
        else {
            dbg("In use, and asked for ANY\n");
            return 1;
        }
    }

    return pico_port_in_use_with_this_ipv4_address(sp, ip);
}
#endif

#ifdef PICO_SUPPORT_IPV6
static int pico_port_in_use_with_this_ipv6_address(struct pico_sockport *sp, struct pico_ip6 ip)
{
    if (sp) {
        struct pico_ip6 *s_local;
        struct pico_tree_node *idx;
        struct pico_socket *s;
        pico_tree_foreach(idx, &sp->socks) {
            s = idx->keyValue;
            if (s->net == &pico_proto_ipv6) {
                s_local = (struct pico_ip6*) &s->local_addr;
                if ((pico_ipv6_is_unspecified(s_local->addr)) || (!memcmp(s_local->addr, ip.addr, PICO_SIZE_IP6))) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

static int pico_port_in_use_ipv6(struct pico_sockport *sp, void *addr)
{
    struct pico_ip6 ip;
    /* IPv6 */
    if (addr)
        memcpy(ip.addr, ((struct pico_ip6 *)addr)->addr, sizeof(struct pico_ip6));
    else
        memcpy(ip.addr, PICO_IP6_ANY, sizeof(struct pico_ip6));

    if (memcmp(ip.addr, PICO_IP6_ANY, sizeof(struct pico_ip6)) ==  0) {
        if (!sp)
            return 0;
        else {
            dbg("In use, and asked for ANY\n");
            return 1;
        }
    }

    return pico_port_in_use_with_this_ipv6_address(sp, ip);
}
#endif



static int pico_generic_port_in_use(uint16_t proto, uint16_t port, struct pico_sockport *sp, void *addr, void *net)
{
#ifdef PICO_SUPPORT_IPV4
    if (net == &pico_proto_ipv4)
    {
        if (sp && pico_port_in_use_by_nat(sp->stack, proto, port)) {
            return 1;
        }

        if (sp && pico_port_in_use_ipv4(sp, addr)) {
            return 1;
        }
    }

#endif

#ifdef PICO_SUPPORT_IPV6
    if (net == &pico_proto_ipv6)
    {
        if (sp && pico_port_in_use_ipv6(sp, addr)) {
            return 1;
        }
    }

#endif

    return 0;
}

int pico_is_port_free(struct pico_stack *S, uint16_t proto, uint16_t port, void *addr, void *net)
{
    struct pico_sockport *sp;
    sp = pico_get_sockport(S, proto, port);

    if (pico_generic_port_in_use(proto, port, sp, addr, net))
        return 0;

    return 1;
}

static int pico_check_socket(struct pico_socket *s)
{
    struct pico_sockport *test;
    struct pico_socket *found;
    struct pico_tree_node *index;

    test = pico_get_sockport(s->stack, PROTO(s), s->local_port);

    if (!test) {
        return -1;
    }

    pico_tree_foreach(index, &test->socks){
        found = index->keyValue;
        if (s == found) {
            return 0;
        }
    }

    return -1;
}

struct pico_socket *pico_sockets_find(struct pico_stack *S, uint16_t local, uint16_t remote)
{
    struct pico_socket *sock = NULL;
    struct pico_tree_node *index = NULL;
    struct pico_sockport *sp = NULL;

    sp = pico_get_sockport(S, PICO_PROTO_TCP, local);
    if(sp)
    {
        pico_tree_foreach(index, &sp->socks)
        {
            if(((struct pico_socket *)index->keyValue)->remote_port == remote)
            {
                sock = (struct pico_socket *)index->keyValue;
                break;
            }
        }
    }

    return sock;
}


int8_t pico_socket_add(struct pico_socket *s)
{
    struct pico_sockport *sp = pico_get_sockport(s->stack, PROTO(s), s->local_port);
    PICOTCP_MUTEX_LOCK(s->stack->SockMutex);
    if (!sp) {
        /* dbg("Creating sockport..%04x\n", s->local_port); / * In comment due to spam during test * / */
        sp = PICO_ZALLOC(sizeof(struct pico_sockport));

        if (!sp) {
            pico_err = PICO_ERR_ENOMEM;
            PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
            return -1;
        }
        sp->stack = s->stack;
        sp->proto = PROTO(s);
        sp->number = s->local_port;
        sp->socks.root = &LEAF;
        sp->socks.compare = socket_cmp;

#ifdef PICO_SUPPORT_UDP
        if (PROTO(s) == PICO_PROTO_UDP)
        {
            if (pico_tree_insert(&s->stack->UDPTable, sp)) {
				PICO_FREE(sp);
				PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
				return -1;
			}

        }

#endif
#ifdef PICO_SUPPORT_TCP
        if (PROTO(s) == PICO_PROTO_TCP)
        {
            if (pico_tree_insert(&s->stack->TCPTable, sp)) {
				PICO_FREE(sp);
				PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
				return -1;
			}
        }
#endif
    }

    if (pico_tree_insert(&sp->socks, s)) {
		PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
		return -1;
	}
    s->state |= PICO_SOCKET_STATE_BOUND;
    PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
#ifdef DEBUG_SOCKET_TREE
    {
        struct pico_tree_node *index;
        /* RB_FOREACH(s, socket_tree, &sp->socks) { */
        pico_tree_foreach(index, &sp->socks){
            s = index->keyValue;
            dbg(">>>> List Socket lc=%hu rm=%hu\n", short_be(s->local_port), short_be(s->remote_port));
        }

    }
#endif
    return 0;
}

static void socket_clean_queues(struct pico_socket *sock)
{
    struct pico_frame *f_in = pico_dequeue(&sock->q_in);
    struct pico_frame *f_out = pico_dequeue(&sock->q_out);
    while(f_in || f_out)
    {
        if(f_in)
        {
            pico_frame_discard(f_in);
            f_in = pico_dequeue(&sock->q_in);
        }

        if(f_out)
        {
            pico_frame_discard(f_out);
            f_out = pico_dequeue(&sock->q_out);
        }
    }
    pico_queue_deinit(&sock->q_in);
    pico_queue_deinit(&sock->q_out);
    pico_socket_tcp_cleanup(sock);
}

static void socket_garbage_collect(pico_time now, void *arg)
{
    struct pico_socket *s = (struct pico_socket *) arg;
    IGNORE_PARAMETER(now);

    socket_clean_queues(s);
    PICO_FREE(s);
}


static void pico_socket_check_empty_sockport(struct pico_socket *s, struct pico_sockport *sp)
{
    if(pico_tree_empty(&sp->socks)) {
#ifdef PICO_SUPPORT_UDP
        if (PROTO(s) == PICO_PROTO_UDP)
        {
            pico_tree_delete(&s->stack->UDPTable, sp);
        }
#endif
#ifdef PICO_SUPPORT_TCP
        if (PROTO(s) == PICO_PROTO_TCP)
        {
            pico_tree_delete(&s->stack->TCPTable, sp);
        }
#endif

        if(s->stack->sp_tcp == sp)
            s->stack->sp_tcp = NULL;

        if(s->stack->sp_udp == sp)
            s->stack->sp_udp = NULL;

        PICO_FREE(sp);
    }
}

int8_t pico_socket_del(struct pico_socket *s)
{
    struct pico_sockport *sp = pico_get_sockport(s->stack, PROTO(s), s->local_port);
    if (!sp) {
        pico_err = PICO_ERR_ENXIO;
        return -1;
    }

    PICOTCP_MUTEX_LOCK(s->stack->SockMutex);
    pico_tree_delete(&sp->socks, s);
    pico_socket_check_empty_sockport(s, sp);
#ifdef PICO_SUPPORT_MCAST
    pico_multicast_delete(s);
#endif
    pico_socket_tcp_delete(s);
    s->state = PICO_SOCKET_STATE_CLOSED;
    if (!pico_timer_add(s->stack, (pico_time)10, socket_garbage_collect, s)) {
        dbg("SOCKET: Failed to start garbage collect timer, doing garbage collection now\n");
        PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
        socket_garbage_collect((pico_time)0, s);
        return -1;
    }
    PICOTCP_MUTEX_UNLOCK(s->stack->SockMutex);
    return 0;
}

static void pico_socket_update_tcp_state(struct pico_socket *s, uint16_t tcp_state)
{
    if (tcp_state) {
        s->state &= 0x00FF;
        s->state |= tcp_state;
    }
}

static int8_t pico_socket_alter_state(struct pico_socket *s, uint16_t more_states, uint16_t less_states, uint16_t tcp_state)
{
    struct pico_sockport *sp;
    if (more_states & PICO_SOCKET_STATE_BOUND)
        return pico_socket_add(s);

    if (less_states & PICO_SOCKET_STATE_BOUND)
        return pico_socket_del(s);

    sp = pico_get_sockport(s->stack, PROTO(s), s->local_port);
    if (!sp) {
        pico_err = PICO_ERR_ENXIO;
        return -1;
    }

    s->state |= more_states;
    s->state = (uint16_t)(s->state & (~less_states));
    pico_socket_update_tcp_state(s, tcp_state);
    return 0;
}


static int pico_socket_transport_deliver(struct pico_protocol *p, struct pico_sockport *sp, struct pico_frame *f)
{
#ifdef PICO_SUPPORT_TCP
    if (p->proto_number == PICO_PROTO_TCP)
        return pico_socket_tcp_deliver(sp, f);

#endif

#ifdef PICO_SUPPORT_UDP
    if (p->proto_number == PICO_PROTO_UDP)
        return pico_socket_udp_deliver(sp, f);

#endif

    return -1;
}


static int pico_socket_deliver(struct pico_stack *S, struct pico_protocol *p, struct pico_frame *f, uint16_t localport)
{
    struct pico_sockport *sp = NULL;
    struct pico_trans *tr = (struct pico_trans *) f->transport_hdr;

    if (!tr)
        return -1;

    sp = pico_get_sockport(S, p->proto_number, localport);
    if (!sp) {
        dbg("No such port %d\n", short_be(localport));
        return -1;
    }

    return pico_socket_transport_deliver(p, sp, f);
}

int pico_socket_set_family(struct pico_socket *s, uint16_t family)
{
    (void) family;

  #ifdef PICO_SUPPORT_IPV4
    if (family == PICO_PROTO_IPV4)
        s->net = &pico_proto_ipv4;

  #endif

  #ifdef PICO_SUPPORT_IPV6
    if (family == PICO_PROTO_IPV6)
        s->net = &pico_proto_ipv6;

  #endif

    if (s->net == NULL)
        return -1;

    return 0;
}

static struct pico_socket *pico_socket_transport_open(struct pico_stack *S, uint16_t proto, uint16_t family)
{
    struct pico_socket *s = NULL;
    (void)family;
#ifdef PICO_SUPPORT_UDP
    if (proto == PICO_PROTO_UDP)
        s = pico_socket_udp_open(S);
#endif

#ifdef PICO_SUPPORT_TCP
    if (proto == PICO_PROTO_TCP)
        s = pico_socket_tcp_open(S, family);
#endif

#ifdef PICO_SUPPORT_ICMP4
    if (proto == PICO_PROTO_ICMP4) {
        if (family == PICO_PROTO_IPV4)
            s = pico_socket_icmp4_open(S);
        else
            pico_err = PICO_ERR_EPROTONOSUPPORT;
    }
#endif

#ifdef PICO_SUPPORT_RAWSOCKETS
#   ifdef PICO_SUPPORT_IPV4
    if ((family == PICO_PROTO_IPV4) && ((proto & PICO_PROTO_RAWSOCKET) != 0)) {
        s = pico_socket_ipv4_open(S, proto);
    }
#   endif
#   ifdef  PICO_SUPPORT_IPV6_RAWSOCKETS /* TODO */
    if (family == PICO_PROTO_IPV6 && ((proto & PICO_PROTO_RAWSOCKET) != 0)) {
        s = pico_socket_ipv6_open(S, proto);
    }
#   endif
#endif

#ifdef PICO_SUPPORT_PACKET_SOCKETS
    if (family == PICO_AF_PACKET) {
        s = pico_socket_ll_open(S, proto);
    }
#endif
    return s;
}

struct pico_socket *pico_socket_open(struct pico_stack *S, uint16_t net, uint16_t proto, void (*wakeup)(uint16_t ev, struct pico_socket *))
{

    struct pico_socket *s = NULL;

    if (!S) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    s = pico_socket_transport_open(S, proto, net);
    if (!s) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return NULL;
    }
    if (pico_socket_set_family(s, net) != 0) {
        PICO_FREE(s);
        pico_err = PICO_ERR_ENETUNREACH;
        return NULL;
    }
    s->stack = S;
    s->q_in.max_size = PICO_DEFAULT_SOCKETQ;
    s->q_out.max_size = PICO_DEFAULT_SOCKETQ;
    s->wakeup = wakeup;
    return s;
}

static void pico_socket_clone_assign_address(struct pico_socket *s, struct pico_socket *facsimile)
{

#ifdef PICO_SUPPORT_IPV4
    if (facsimile->net == &pico_proto_ipv4) {
        s->net = &pico_proto_ipv4;
        memcpy(&s->local_addr, &facsimile->local_addr, sizeof(struct pico_ip4));
        memcpy(&s->remote_addr, &facsimile->remote_addr, sizeof(struct pico_ip4));
    }

#endif

#ifdef PICO_SUPPORT_IPV6
    if (facsimile->net == &pico_proto_ipv6) {
        s->net = &pico_proto_ipv6;
        memcpy(&s->local_addr, &facsimile->local_addr, sizeof(struct pico_ip6));
        memcpy(&s->remote_addr, &facsimile->remote_addr, sizeof(struct pico_ip6));
    }

#endif

}

struct pico_socket *pico_socket_clone(struct pico_socket *facsimile)
{
    struct pico_socket *s = NULL;

    s = pico_socket_transport_open(facsimile->stack, facsimile->proto->proto_number, facsimile->net->proto_number);
    if (!s) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return NULL;
    }

    s->local_port = facsimile->local_port;
    s->remote_port = facsimile->remote_port;
    s->state = facsimile->state;
    pico_socket_clone_assign_address(s, facsimile);
    if (!s->net) {
        PICO_FREE(s);
        pico_err = PICO_ERR_ENETUNREACH;
        return NULL;
    }

    s->q_in.max_size = PICO_DEFAULT_SOCKETQ;
    s->q_out.max_size = PICO_DEFAULT_SOCKETQ;
    s->wakeup = NULL;
    return s;
}

static int pico_socket_transport_read(struct pico_socket *s, void *buf, int len)
{
    if (PROTO(s) == PICO_PROTO_UDP)
    {
        /* make sure cast to uint16_t doesn't give unexpected results */
        if(len > 0xFFFF) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        return pico_socket_udp_recv(s, buf, (uint16_t)len, NULL, NULL);
    }
    else if (PROTO(s) == PICO_PROTO_TCP)
        return pico_socket_tcp_read(s, buf, (uint32_t)len);
#ifdef PICO_SUPPORT_RAWSOCKETS
    else if (PROTO(s) == PICO_PROTO_IPV4)
        return pico_socket_ipv4_recvfrom(s, buf, (uint32_t)len, NULL, NULL);
#endif
    else return 0;
}

int pico_socket_read(struct pico_socket *s, void *buf, int len)
{
    if (!s || buf == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        /* check if exists in tree */
        /* See task #178 */
        if (pico_check_socket(s) != 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }

    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        pico_err = PICO_ERR_EIO;
        return -1;
    }

    return pico_socket_transport_read(s, buf, len);
}

static int pico_socket_write_check_state(struct pico_socket *s)
{
    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        pico_err = PICO_ERR_EIO;
        return -1;
    }

    if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
        pico_err = PICO_ERR_ENOTCONN;
        return -1;
    }

    if (s->state & PICO_SOCKET_STATE_SHUT_LOCAL) { /* check if in shutdown state */
        pico_err = PICO_ERR_ESHUTDOWN;
        return -1;
    }

    return 0;
}

static int pico_socket_write_attempt(struct pico_socket *s, const void *buf, int len)
{
    if (pico_socket_write_check_state(s) < 0) {
        return -1;
    } else {
        return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
    }
}

int pico_socket_write(struct pico_socket *s, const void *buf, int len)
{
    if (!s || buf == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        /* check if exists in tree */
        /* See task #178 */
        if (pico_check_socket(s) != 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }

    return pico_socket_write_attempt(s, buf, len);
}

static uint16_t pico_socket_high_port(struct pico_stack *S, uint16_t proto)
{
    uint16_t port;
    if (0 ||
#ifdef PICO_SUPPORT_TCP
        (proto == PICO_PROTO_TCP) ||
#endif
#ifdef PICO_SUPPORT_UDP
        (proto == PICO_PROTO_UDP) ||
#endif
        0) {
        do {
            uint32_t rand = pico_rand();
            port = (uint16_t) (rand & 0xFFFFU);
            port = (uint16_t)((port % (65535 - 1024)) + 1024U);
            if (pico_is_port_free(S, proto, port, NULL, NULL)) {
                return short_be(port);
            }
        } while(1);
    }
    else return 0U;
}

static void *pico_socket_sendto_get_ip4_src(struct pico_socket *s, struct pico_ip4 *dst)
{
    struct pico_ip4 *src4 = NULL;

#ifdef PICO_SUPPORT_IPV4
    /* Check if socket is connected: destination address MUST match the
     * current connected endpoint
     */
    if ((s->state & PICO_SOCKET_STATE_CONNECTED)) {
        src4 = &s->local_addr.ip4;
        if  (s->remote_addr.ip4.addr != ((struct pico_ip4 *)dst)->addr ) {
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return NULL;
        }
    } else {

        src4 = pico_ipv4_source_find(s->stack, dst);
        if (!src4) {
            pico_err = PICO_ERR_EHOSTUNREACH;
            return NULL;
        }

    }

    if (src4->addr != PICO_IPV4_INADDR_ANY)
        s->local_addr.ip4.addr = src4->addr;

#else
    pico_err = PICO_ERR_EPROTONOSUPPORT;
#endif
    return src4;
}

static void *pico_socket_sendto_get_ip6_src(struct pico_socket *s, struct pico_ip6 *dst)
{
    struct pico_ip6 *src6 = NULL;
    (void)s;
    (void)dst;

#ifdef PICO_SUPPORT_IPV6

    /* Check if socket is connected: destination address MUST match the
     * current connected endpoint
     */
    if ((s->state & PICO_SOCKET_STATE_CONNECTED)) {
        src6 = &s->local_addr.ip6;
        if (memcmp(&s->remote_addr, dst, PICO_SIZE_IP6)) {
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return NULL;
        }
    } else {
        src6 = pico_ipv6_source_find(s->stack, dst);
        if (!src6) {
            pico_err = PICO_ERR_EHOSTUNREACH;
            return NULL;
        }

        if (!pico_ipv6_is_unspecified(src6->addr))
            s->local_addr.ip6 = *src6;
    }

#else
    pico_err = PICO_ERR_EPROTONOSUPPORT;
#endif
    return src6;
}


static int pico_socket_sendto_dest_check(struct pico_socket *s, void *dst, uint16_t port)
{

    /* Don't execute port/connection state for RAW sockets */
    if ((PROTO(s) != PICO_PROTO_TCP) && (PROTO(s) != PICO_PROTO_UDP))
        return 0;

    /* For the sendto call to be valid,
     * dst and remote_port should be always populated.
     */
    if (!dst || !port) {
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
    }

    /* When coming from pico_socket_send (or _write),
     * the destination is automatically assigned to the currently connected endpoint.
     * This check will ensure that there is no mismatch when sendto() is called directly
     * on a connected socket
     */
    if ((s->state & PICO_SOCKET_STATE_CONNECTED) != 0) {
        if (port != s->remote_port) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }

    return 0;
}

static int pico_socket_sendto_initial_checks(struct pico_socket *s, const void *buf, const int len, void *dst, uint16_t remote_port)
{
    if (len < 0) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (buf == NULL || s == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return pico_socket_sendto_dest_check(s, dst, remote_port);
}

static void *pico_socket_sendto_get_src(struct pico_socket *s, void *dst)
{
    void *src = NULL;
    if (is_sock_ipv4(s))
        src = pico_socket_sendto_get_ip4_src(s, (struct pico_ip4 *)dst);

    if (is_sock_ipv6(s))
        src = pico_socket_sendto_get_ip6_src(s, (struct pico_ip6 *)dst);

    return src;
}

static struct pico_remote_endpoint *pico_socket_sendto_destination_ipv4(struct pico_socket *s, struct pico_ip4 *dst, uint16_t port)
{
    struct pico_remote_endpoint *ep = NULL;
    (void)s;
    ep = PICO_ZALLOC(sizeof(struct pico_remote_endpoint));
    if (!ep) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    ep->remote_addr.ip4.addr = ((struct pico_ip4 *)dst)->addr;
    ep->remote_port = port;
    return ep;
}

static void pico_endpoint_free(struct pico_remote_endpoint *ep)
{
    if (ep)
        PICO_FREE(ep);
}

static struct pico_remote_endpoint *pico_socket_sendto_destination_ipv6(struct pico_socket *s, struct pico_ip6 *dst, uint16_t port)
{
    struct pico_remote_endpoint *ep = NULL;
    (void)s;
    (void)dst;
    (void)port;
#ifdef PICO_SUPPORT_IPV6
    ep = PICO_ZALLOC(sizeof(struct pico_remote_endpoint));
    if (!ep) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    memcpy(&ep->remote_addr.ip6, dst, sizeof(struct pico_ip6));
    ep->remote_port = port;
#endif
    return ep;
}


static struct pico_remote_endpoint *pico_socket_sendto_destination(struct pico_socket *s, void *dst, uint16_t port)
{
    struct pico_remote_endpoint *ep = NULL;
    (void)pico_socket_sendto_destination_ipv6;
    /* socket remote info could change in a consecutive call, make persistent */
    if (PROTO(s) != PICO_PROTO_TCP) {
#       ifdef PICO_SUPPORT_IPV6
        if (is_sock_ipv6(s))
            ep = pico_socket_sendto_destination_ipv6(s, (struct pico_ip6 *)dst, port);

#       endif
#       ifdef PICO_SUPPORT_IPV4
        if (is_sock_ipv4(s))
            ep = pico_socket_sendto_destination_ipv4(s, (struct pico_ip4 *)dst, port);

#       endif
    }
    return ep;
}

static int32_t pico_socket_sendto_set_localport(struct pico_socket *s)
{

    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        s->local_port = pico_socket_high_port(s->stack, s->proto->proto_number);
        if (s->local_port == 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
    }

    return s->local_port;
}

static int pico_socket_sendto_transport_offset(struct pico_socket *s)
{
    int header_offset = 0;
    #ifdef PICO_SUPPORT_TCP
    if (PROTO(s) == PICO_PROTO_TCP)
        header_offset = pico_tcp_overhead(s);
    #endif
    #ifdef PICO_SUPPORT_UDP
    if (PROTO(s) == PICO_PROTO_UDP)
        header_offset = sizeof(struct pico_udp_hdr);
    #endif
    return header_offset;
}


static struct pico_remote_endpoint *pico_socket_set_info(struct pico_remote_endpoint *ep)
{
    struct pico_remote_endpoint *info;
    info = PICO_ZALLOC(sizeof(struct pico_remote_endpoint));
    if (!info) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    memcpy(info, ep, sizeof(struct pico_remote_endpoint));
    return info;
}

static void pico_xmit_frame_set_nofrag(struct pico_frame *f)
{
#ifdef PICO_SUPPORT_IPV4FRAG
    f->frag = PICO_IPV4_DONTFRAG;
#else
    (void)f;
#endif
}

static int pico_socket_final_xmit(struct pico_socket *s, struct pico_frame *f)
{
    if (s->proto->push(s->stack, s->proto, f) > 0) {
        return f->payload_len;
    } else {
        pico_frame_discard(f);
        return 0;
    }
}

static int pico_socket_xmit_one(struct pico_socket *s, const void *buf, const int len, void *src,
                                struct pico_remote_endpoint *ep, struct pico_msginfo *msginfo)
{
    struct pico_frame *f;
    struct pico_device *dev = NULL;
    uint16_t hdr_offset = (uint16_t)pico_socket_sendto_transport_offset(s);
    int ret = 0;
    (void)src;

    if (msginfo) {
        dev = msginfo->dev;
    }
#ifdef PICO_SUPPORT_IPV6
    else if (IS_SOCK_IPV6(s) && ep && pico_ipv6_is_multicast(&ep->remote_addr.ip6.addr[0])) {
        dev = pico_ipv6_link_find(s->stack, src);
    } else if (IS_SOCK_IPV6(s) && ep) {
        dev = pico_ipv6_source_dev_find(s->stack, &ep->remote_addr.ip6);
    }
#endif
    else if (IS_SOCK_IPV4(s) && ep) {
        dev = pico_ipv4_source_dev_find(s->stack, &ep->remote_addr.ip4);
    } else {
        dev = get_sock_dev(s);
    }

    if (!dev) {
        return -1;
    }

    f = pico_socket_frame_alloc(s, dev, (uint16_t)(len + hdr_offset));
    if (!f) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    if (PROTO(s) == PICO_PROTO_ICMP4)
        f->payload = f->transport_hdr;
    else
        f->payload += hdr_offset;
    f->payload_len = (uint16_t)(len);
    f->sock = s;
    transport_flags_update(f, s);
    pico_xmit_frame_set_nofrag(f);
    if (ep && !f->info) {
        f->info = pico_socket_set_info(ep);
        if (!f->info) {
            pico_frame_discard(f);
            return -1;
        }
    }

    if (msginfo) {
        f->send_ttl = (uint8_t)msginfo->ttl;
        f->send_tos = (uint8_t)msginfo->tos;
    }

    memcpy(f->payload, (const uint8_t *)buf, f->payload_len);
    /* dbg("Pushing segment, hdr len: %d, payload_len: %d\n", header_offset, f->payload_len); */
    ret = pico_socket_final_xmit(s, f);
    return ret;
}

static int pico_socket_xmit_avail_space(struct pico_socket *s);

#ifdef PICO_SUPPORT_IPV4FRAG
static void pico_socket_xmit_first_fragment_setup(struct pico_frame *f, int space, int hdr_offset)
{
    frag_dbg("FRAG: first fragmented frame %p | len = %u offset = 0\n", f, f->payload_len);
    /* transport header length field contains total length + header length */
    f->transport_len = (uint16_t)(space);
    f->frag = PICO_IPV4_MOREFRAG;
    f->payload += hdr_offset;
}

static void pico_socket_xmit_next_fragment_setup(struct pico_frame *f, int hdr_offset, int total_payload_written, int len)
{
    /* no transport header in fragmented IP */
    f->payload = f->transport_hdr;
    /* set offset in octets */
    f->frag = (uint16_t)((total_payload_written + (uint16_t)hdr_offset) >> 3u); /* first fragment had a header offset */
    if (total_payload_written + f->payload_len < len) {
        frag_dbg("FRAG: intermediate fragmented frame %p | len = %u offset = %u\n", f, f->payload_len, short_be(f->frag));
        f->frag |= PICO_IPV4_MOREFRAG;
    } else {
        frag_dbg("FRAG: last fragmented frame %p | len = %u offset = %u\n", f, f->payload_len, short_be(f->frag));
        f->frag &= PICO_IPV4_FRAG_MASK;
    }
}
#endif

/* Implies ep discarding! */
static int pico_socket_xmit_fragments(struct pico_socket *s, const void *buf, const int len,
                                      void *src, struct pico_remote_endpoint *ep, struct pico_msginfo *msginfo)
{
    int space = pico_socket_xmit_avail_space(s);
    int hdr_offset = pico_socket_sendto_transport_offset(s);
    int total_payload_written = 0;
    int retval = 0;
    struct pico_frame *f = NULL;

    if (space < 0) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        pico_endpoint_free(ep);
        return -1;
    }

    if (space > len) {
        retval = pico_socket_xmit_one(s, buf, len, src, ep, msginfo);
        pico_endpoint_free(ep);
        return retval;
    }

#ifdef PICO_SUPPORT_IPV6
    /* Can't fragment IPv6 */
    if (is_sock_ipv6(s)) {
        retval =  pico_socket_xmit_one(s, buf, space, src, ep, msginfo);
        pico_endpoint_free(ep);
        return retval;
    }

#endif

#ifdef PICO_SUPPORT_IPV4FRAG
    while(total_payload_written < len) {
        /* Always allocate the max space available: space + offset */
        if (len < space)
            space = len;

        if (space > len - total_payload_written) /* update space for last fragment */
            space = len - total_payload_written;

        f = pico_socket_frame_alloc(s, get_sock_dev(s), (uint16_t)(space + hdr_offset));
        if (!f) {
            pico_err = PICO_ERR_ENOMEM;
            pico_endpoint_free(ep);
            return -1;
        }

        f->sock = s;
        if (ep) {
            f->info = pico_socket_set_info(ep);
            if (!f->info) {
                pico_frame_discard(f);
                pico_endpoint_free(ep);
                return -1;
            }
        }

        f->payload_len = (uint16_t) space;
        if (total_payload_written == 0) {
            /* First fragment: no payload written yet! */
            pico_socket_xmit_first_fragment_setup(f, space, hdr_offset);
            space += hdr_offset; /* only first fragments contains transport header */
            hdr_offset = 0;
        } else {
            /* Next fragment */
            pico_socket_xmit_next_fragment_setup(f, pico_socket_sendto_transport_offset(s), total_payload_written, len);
        }

        memcpy(f->payload, (const uint8_t *)buf + total_payload_written, f->payload_len);
        transport_flags_update(f, s);
        if (s->proto->push(s->stack, s->proto, f) > 0) {
            total_payload_written += f->payload_len;
        } else {
            pico_frame_discard(f);
            break;
        }
    } /* while() */
    pico_endpoint_free(ep);
    return total_payload_written;

#else
    /* Careful with that axe, Eugene!
     *
     * cropping down datagrams to the MTU value.
     */
    (void) f;
    (void) hdr_offset;
    (void) total_payload_written;
    retval = pico_socket_xmit_one(s, buf, space, src, ep, msginfo);
    pico_endpoint_free(ep);
    return retval;

#endif
}

struct pico_device *get_sock_dev(struct pico_socket *s)
{
    if (0) {}

#ifdef PICO_SUPPORT_IPV6
    else if (is_sock_ipv6(s))
        s->dev = pico_ipv6_source_dev_find(s->stack, &s->remote_addr.ip6);
#endif
#ifdef PICO_SUPPORT_IPV4
    else if (is_sock_ipv4(s))
        s->dev = pico_ipv4_source_dev_find(s->stack, &s->remote_addr.ip4);
#endif

    return s->dev;
}


static uint32_t pico_socket_adapt_mss_to_proto(struct pico_socket *s, uint32_t mss)
{
#ifdef PICO_SUPPORT_RAWSOCKETS
    struct pico_socket_ipv4 *s4;
    if (s && is_sock_ipv4(s) && s->proto && (PROTO(s) == PICO_PROTO_IPV4)) {
        s4 = (struct pico_socket_ipv4 *)s;
        if (s4->hdr_included)
            return mss;
    }
#endif
#ifdef PICO_SUPPORT_IPV6
    if (s && is_sock_ipv6(s))
        return mss - PICO_SIZE_IP6HDR;
#endif
    return mss - PICO_SIZE_IP4HDR;
}
static uint32_t pico_socket_pmtu_check(struct pico_socket *s, uint32_t mss)
{

#if defined(PICO_SUPPORT_IPV6) && defined(PICO_SUPPORT_IPV6PMTU)
    if (is_sock_ipv6(s)) {
    	uint32_t pmtu = 0;
    	const struct pico_ipv6_path_id destination = {s->remote_addr.ip6};
    	pmtu = pico_ipv6_pmtu_get(s->stack, &destination);
    	if (pmtu == 0) {
    		pico_ipv6_path_add(s->stack, &destination, mss);
    	} else {
    		if (pmtu < mss) {
    			mss = pmtu;
    		}
    	}
	}
#else
    IGNORE_PARAMETER(s);
#endif
    return mss;
}

uint32_t pico_socket_get_mss(struct pico_socket *s)
{
    uint32_t mss = PICO_MIN_MSS;
    if (!s) {
        return mss;
    }
    if (!s->dev) {
        get_sock_dev(s);
    }
    if (s->dev) {
    	mss = pico_socket_pmtu_check(s, s->dev->mtu);
    }
    return pico_socket_adapt_mss_to_proto(s, mss);
}

static int pico_socket_xmit_avail_space(struct pico_socket *s)
{
    int transport_len;

#ifdef PICO_SUPPORT_TCP
    if (PROTO(s) == PICO_PROTO_TCP) {
        transport_len = (uint16_t)pico_tcp_get_socket_mss(s);
    } else
#endif
    transport_len = (uint16_t)pico_socket_get_mss(s);
    transport_len -= pico_socket_sendto_transport_offset(s);
    return transport_len;
}


static int pico_socket_xmit(struct pico_socket *s, const void *buf, const int len, void *src,
                            struct pico_remote_endpoint *ep, struct pico_msginfo *msginfo)
{
    int space = pico_socket_xmit_avail_space(s);
    int total_payload_written = 0;

    if (space < 0) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        pico_endpoint_free(ep);
        return -1;
    }


    if ((PROTO(s) != PICO_PROTO_TCP) && (len > space)) {
        total_payload_written = pico_socket_xmit_fragments(s, buf, len, src, ep, msginfo);
        /* Implies ep discarding */
        return total_payload_written;
    }

    while (total_payload_written < len) {
        int w, chunk_len = len - total_payload_written;
        if (chunk_len > space)
            chunk_len = space;

        w = pico_socket_xmit_one(s, (const void *)((const uint8_t *)buf + total_payload_written), chunk_len, src, ep, msginfo);
        if (w <= 0) {
            break;
        }

        total_payload_written += w;
        if (PROTO(s) != PICO_PROTO_TCP) {
            /* Break after the first datagram sent with at most MTU bytes. */
            break;
        }
    }
    pico_endpoint_free(ep);
    return total_payload_written;
}

static void pico_socket_sendto_set_dport(struct pico_socket *s, uint16_t port)
{
    if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
        s->remote_port = port;
    }
}


int MOCKABLE pico_socket_sendto_extended(struct pico_socket *s, const void *buf, const int len,
                                         void *dst, uint16_t remote_port, struct pico_msginfo *msginfo)
{
    struct pico_remote_endpoint *remote_endpoint = NULL;
    void *src = NULL;

    if(len == 0)
        return 0;

#ifdef PICO_SUPPORT_PACKET_SOCKETS
    if (PROTO(s) == PICO_AF_PACKET)
        return pico_socket_ll_sendto(s, buf, (uint32_t)len, dst);
#endif

    if (pico_socket_sendto_initial_checks(s, buf, len, dst, remote_port) < 0)
        return -1;

#ifdef PICO_SUPPORT_RAWSOCKETS
    /* Skip src assignment for raw sockets */
    if (PROTO(s) == PICO_PROTO_IPV4) {
        return pico_socket_ipv4_sendto(s, buf, (uint32_t)len, dst);
    }
#endif

    src = pico_socket_sendto_get_src(s, dst);
    if (!src) {
#ifdef PICO_SUPPORT_IPV6
        if((s->net->proto_number == PICO_PROTO_IPV6)
           && msginfo && msginfo->dev
           && pico_ipv6_is_multicast(((struct pico_ip6 *)dst)->addr))
        {
            src = &(pico_ipv6_linklocal_get(msginfo->dev)->address);
        }
        else
#endif
        return -1;
    }

    remote_endpoint = pico_socket_sendto_destination(s, dst, remote_port);

    if (PROTO(s) == PICO_PROTO_ICMP4) {
        if (pico_socket_icmp4_sendto_check(s, buf, len, dst, remote_port) < 0)
            return -1;
    }
    if ((PROTO(s) == PICO_PROTO_UDP) || (PROTO(s) == PICO_PROTO_TCP)) {
        if (pico_socket_sendto_set_localport(s) < 0) {
            pico_endpoint_free(remote_endpoint);
            return -1;
        }
    }
    pico_socket_sendto_set_dport(s, remote_port);
    return pico_socket_xmit(s, buf, len, src, remote_endpoint, msginfo); /* Implies discarding the endpoint */
}

int MOCKABLE pico_socket_sendto(struct pico_socket *s, const void *buf, const int len, void *dst, uint16_t remote_port)
{
    return pico_socket_sendto_extended(s, buf, len, dst, remote_port, NULL);
}

int pico_socket_send(struct pico_socket *s, const void *buf, int len)
{
    if (!s || buf == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        /* check if exists in tree */
        /* See task #178 */
        if (pico_check_socket(s) != 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }

    if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
        pico_err = PICO_ERR_ENOTCONN;
        return -1;
    }

    return pico_socket_sendto(s, buf, len, &s->remote_addr, s->remote_port);
}

int pico_socket_recvfrom_extended(struct pico_socket *s, void *buf, int len, void *orig,
                                  uint16_t *remote_port, struct pico_msginfo *msginfo)
{
    if (!s || buf == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
#ifdef PICO_SUPPORT_PACKET_SOCKETS
    if (PROTO(s) == PICO_AF_PACKET)
        return pico_socket_ll_recvfrom(s, buf, (uint16_t)len, orig);
#endif

#ifdef PICO_SUPPORT_RAWSOCKETS
    if ((PROTO(s) == PICO_PROTO_IPV4)) {
        return pico_socket_ipv4_recvfrom(s, buf, (uint16_t)len, orig, remote_port);
    }
#endif

#ifdef PICO_SUPPORT_ICMP4
    /* forward request to icmp layer */
    if (PROTO(s) == PICO_PROTO_ICMP4) {
        if(len > 0xFFFF) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        return pico_socket_icmp4_recvfrom(s, buf, (uint16_t)len, orig, remote_port);
    }
#endif

    /* check if exists in tree */
    if ((PROTO(s) != PICO_PROTO_ICMP4) && pico_check_socket(s) != 0) {
        pico_err = PICO_ERR_EINVAL;
        /* See task #178 */
        return -1;
    }

    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
    }

#ifdef PICO_SUPPORT_UDP
    if (PROTO(s) == PICO_PROTO_UDP) {
        /* make sure cast to uint16_t doesn't give unexpected results */
        if(len > 0xFFFF) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        return pico_udp_recv(s, buf, (uint16_t)len, orig, remote_port, msginfo);
    }

#endif
#ifdef PICO_SUPPORT_TCP
    if (PROTO(s) == PICO_PROTO_TCP) {
        /* check if in shutdown state and if tcpq_in empty */
        if ((s->state & PICO_SOCKET_STATE_SHUT_REMOTE) && pico_tcp_queue_in_is_empty(s)) {
            pico_err = PICO_ERR_ESHUTDOWN;
            return -1;
        } else {
            /* dbg("socket tcp recv\n"); */
            return (int)pico_tcp_read(s, buf, (uint32_t)len);
        }
    }

#endif
    /* dbg("socket return 0\n"); */
    return 0;
}

int MOCKABLE pico_socket_recvfrom(struct pico_socket *s, void *buf, int len, void *orig,
                                  uint16_t *remote_port)
{
    return pico_socket_recvfrom_extended(s, buf, len, orig, remote_port, NULL);

}

int pico_socket_recv(struct pico_socket *s, void *buf, int len)
{
    return pico_socket_recvfrom(s, buf, len, NULL, NULL);
}

int pico_socket_fionread(struct pico_socket *s)
{

    struct pico_frame *f;
    if (s == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (pico_check_socket(s) != 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }
    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        pico_err = PICO_ERR_EIO;
        return -1;
    }
    if (PROTO(s) == PICO_PROTO_UDP)
    {
        f = pico_queue_peek(&s->q_in);
        if (!f)
            return 0;
        if(!f->payload_len) {
            f->payload = f->transport_hdr + sizeof(struct pico_udp_hdr);
            f->payload_len =
                (f->transport_len > sizeof(struct pico_udp_hdr)) ?
                (uint16_t)(f->transport_len - sizeof(struct pico_udp_hdr)):
                0;
        }
        return f->payload_len;
    }
#ifdef PICO_SUPPORT_RAWSOCKETS
    else if (PROTO(s) == PICO_PROTO_IPV4) {
        struct pico_socket_ipv4 *s4 = (struct pico_socket_ipv4 *)s;
        f = pico_queue_peek(&s->q_in);
        if (!f)
            return 0;
        if(!f->payload_len) {
            f->payload = f->net_hdr + f->net_len;
            f->payload_len = (uint16_t)(f->len);
            if (!s4->hdr_included)
                f->payload_len =
                    f->payload_len > PICO_SIZE_IP4HDR ?
                    (uint16_t)(f->payload_len - PICO_SIZE_IP4HDR) :
                    0;
        }
        return f->payload_len;
    }
#endif
    else if (PROTO(s) == PICO_PROTO_TCP) {
        return pico_tcp_queue_in_size(s);
    }
    return 0;
}

int pico_socket_getname(struct pico_socket *s, void *local_addr, uint16_t *port, uint16_t *proto)
{

    if (!s || !local_addr || !port || !proto) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (is_sock_ipv4(s)) {
    #ifdef PICO_SUPPORT_IPV4
        struct pico_ip4 *ip = (struct pico_ip4 *)local_addr;
        ip->addr = s->local_addr.ip4.addr;
        *proto = PICO_PROTO_IPV4;
    #endif
    } else if (is_sock_ipv6(s)) {
    #ifdef PICO_SUPPORT_IPV6
        struct pico_ip6 *ip = (struct pico_ip6 *)local_addr;
        memcpy(ip->addr, s->local_addr.ip6.addr, PICO_SIZE_IP6);
        *proto = PICO_PROTO_IPV6;
    #endif
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    *port = s->local_port;
    return 0;
}

int pico_socket_getpeername(struct pico_socket *s, void *remote_addr, uint16_t *port, uint16_t *proto)
{
    if (!s || !remote_addr || !port || !proto) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if ((s->state & PICO_SOCKET_STATE_CONNECTED) == 0) {
        pico_err = PICO_ERR_ENOTCONN;
        return -1;
    }

    if (is_sock_ipv4(s)) {
    #ifdef PICO_SUPPORT_IPV4
        struct pico_ip4 *ip = (struct pico_ip4 *)remote_addr;
        ip->addr = s->remote_addr.ip4.addr;
        *proto = PICO_PROTO_IPV4;
    #endif
    } else if (is_sock_ipv6(s)) {
    #ifdef PICO_SUPPORT_IPV6
        struct pico_ip6 *ip = (struct pico_ip6 *)remote_addr;
        memcpy(ip->addr, s->remote_addr.ip6.addr, PICO_SIZE_IP6);
        *proto = PICO_PROTO_IPV6;
    #endif
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    *port = s->remote_port;
    return 0;

}

int MOCKABLE pico_socket_bind(struct pico_socket *s, void *local_addr, uint16_t *port)
{
    struct pico_device *dev;

    if (!s || !local_addr || !port) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (is_sock_ipv4(s)) {
    #ifdef PICO_SUPPORT_IPV4
        struct pico_ip4 *ip = (struct pico_ip4 *)local_addr;
        if (ip->addr != PICO_IPV4_INADDR_ANY) {
            dev = pico_ipv4_link_find(s->stack, local_addr);
            if (!dev) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            s->dev = dev;
        }
    #endif
    } else if (is_sock_ipv6(s)) {
    #ifdef PICO_SUPPORT_IPV6
        struct pico_ip6 *ip = (struct pico_ip6 *)local_addr;
        if (!pico_ipv6_is_unspecified(ip->addr)) {
            dev = pico_ipv6_link_find(s->stack, local_addr);
            if (!dev) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            s->dev = dev;
        }
    #endif
    } else if (is_sock_ll(s)) {
#ifdef PICO_SUPPORT_PACKET_SOCKETS
        struct pico_ll *ll = (struct pico_ll *)local_addr;
        if ((!ll->dev) || (ll->dev != pico_get_device(s->stack, ll->dev->name))) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
#endif
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    #ifdef PICO_SUPPORT_ICMP4
    if (PROTO(s) == PICO_PROTO_ICMP4) {
        if (pico_socket_icmp4_bind(s, local_addr, *port) < 0)
            return -1;
    }
    #endif

    /* Manage ports for transport protocols */
    if ((PROTO(s) == PICO_PROTO_TCP) || (PROTO(s) == PICO_PROTO_UDP)) {
        /* When given port = 0, get a random high port to bind to. */
        if (*port == 0) {
            *port = pico_socket_high_port(s->stack, PROTO(s));
            if (*port == 0) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
        }

        if (pico_is_port_free(s->stack, PROTO(s), *port, local_addr, s->net) == 0) {
            pico_err = PICO_ERR_EADDRINUSE;
            return -1;
        }
        s->local_port = *port;
    }

    if (is_sock_ipv4(s)) {
    #ifdef PICO_SUPPORT_IPV4
        struct pico_ip4 *ip = (struct pico_ip4 *)local_addr;
        s->local_addr.ip4 = *ip;
    #endif
    } else if (is_sock_ipv6(s)) {
    #ifdef PICO_SUPPORT_IPV6
        struct pico_ip6 *ip = (struct pico_ip6 *)local_addr;
        s->local_addr.ip6 = *ip;
    #endif
    } else if (is_sock_ll(s)) {
    #ifdef PICO_SUPPORT_PACKET_SOCKETS
        struct pico_ll *ll = (struct pico_ll *)local_addr;
        s->local_addr.ll = *ll;
    #endif
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);
}


int pico_socket_connect(struct pico_socket *s, const void *remote_addr, uint16_t remote_port)
{
    int ret = -1;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    if (!s || remote_addr == NULL || remote_port == 0) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (PROTO(s) == PICO_PROTO_IPV4)
    {
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;
    }

    s->remote_port = remote_port;

    if (s->local_port == 0) {
        s->local_port = pico_socket_high_port(s->stack, PROTO(s));
        if (!s->local_port) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }

    if (is_sock_ipv4(s)) {
    #ifdef PICO_SUPPORT_IPV4
        struct pico_ip4 *local = NULL;
        const struct pico_ip4 *ip = (const struct pico_ip4 *)remote_addr;
        s->remote_addr.ip4 = *ip;
        local = pico_ipv4_source_find(s->stack, ip);
        if (local) {
            get_sock_dev(s);
            s->local_addr.ip4 = *local;
        } else {
            pico_err = PICO_ERR_EHOSTUNREACH;
            return -1;
        }

    #endif
    } else if (is_sock_ipv6(s)) {
    #ifdef PICO_SUPPORT_IPV6
        struct pico_ip6 *local = NULL;
        const struct pico_ip6 *ip = (const struct pico_ip6 *)remote_addr;
        s->remote_addr.ip6 = *ip;
        local = pico_ipv6_source_find(s->stack, ip);
        if (local) {
            get_sock_dev(s);
            s->local_addr.ip6 = *local;
        } else {
            pico_err = PICO_ERR_EHOSTUNREACH;
            return -1;
        }

    #endif
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    pico_socket_alter_state(s, PICO_SOCKET_STATE_BOUND, 0, 0);

#ifdef PICO_SUPPORT_UDP
    if (PROTO(s) == PICO_PROTO_UDP) {
        pico_socket_alter_state(s, PICO_SOCKET_STATE_CONNECTED, 0, 0);
        pico_err = PICO_ERR_NOERR;
        ret = 0;
    }

#endif

#ifdef PICO_SUPPORT_TCP
    if (PROTO(s) == PICO_PROTO_TCP) {
        if (pico_tcp_initconn(s) == 0) {
            pico_socket_alter_state(s, PICO_SOCKET_STATE_CONNECTED | PICO_SOCKET_STATE_TCP_SYN_SENT, PICO_SOCKET_STATE_CLOSED, 0);
            pico_err = PICO_ERR_NOERR;
            ret = 0;
        } else {
            pico_err = PICO_ERR_EHOSTUNREACH;
        }
    }

#endif

    return ret;
}


#ifdef PICO_SUPPORT_TCP

int pico_socket_listen(struct pico_socket *s, int backlog)
{
    if (!s || backlog < 1) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        /* check if exists in tree */
        /* See task #178 */
        if (pico_check_socket(s) != 0) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    }
    if (PROTO(s) == PICO_PROTO_IPV4) {
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;
    }
    if (PROTO(s) == PICO_PROTO_UDP) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        pico_err = PICO_ERR_EISCONN;
        return -1;
    }
    if (PROTO(s) == PICO_PROTO_TCP)
        pico_socket_alter_state(s, PICO_SOCKET_STATE_TCP_SYN_SENT, 0, PICO_SOCKET_STATE_TCP_LISTEN);

    s->max_backlog = (uint16_t)backlog;

    return 0;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *port)
{
    if (!s || !orig || !port) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    pico_err = PICO_ERR_EINVAL;

    if ((s->state & PICO_SOCKET_STATE_BOUND) == 0) {
        return NULL;
    }

    if (PROTO(s) == PICO_PROTO_UDP) {
        return NULL;
    }
    if (PROTO(s) == PICO_PROTO_IPV4) {
        pico_err = PICO_ERR_EOPNOTSUPP;
        return NULL;
    }

    if (TCPSTATE(s) == PICO_SOCKET_STATE_TCP_LISTEN) {
        struct pico_sockport *sp = pico_get_sockport(s->stack, PICO_PROTO_TCP, s->local_port);
        struct pico_socket *found;
        uint32_t socklen = sizeof(struct pico_ip4);
        /* If at this point no incoming connection socket is found,
         * the accept call is valid, but no connection is established yet.
         */
        pico_err = PICO_ERR_EAGAIN;
        if (sp) {
            struct pico_tree_node *index;
            /* RB_FOREACH(found, socket_tree, &sp->socks) { */
            pico_tree_foreach(index, &sp->socks){
                found = index->keyValue;
                if ((s == found->parent) && ((found->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED)) {
                    found->parent = NULL;
                    pico_err = PICO_ERR_NOERR;
                    #ifdef PICO_SUPPORT_IPV6
                    if (is_sock_ipv6(s))
                        socklen = sizeof(struct pico_ip6);

                    #endif
                    memcpy(orig, &found->remote_addr, socklen);
                    *port = found->remote_port;
                    s->number_of_pending_conn--;
                    return found;
                }
            }
        }
    }

    return NULL;
}

#else

int pico_socket_listen(struct pico_socket *s, int backlog)
{
    IGNORE_PARAMETER(s);
    IGNORE_PARAMETER(backlog);
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

struct pico_socket *pico_socket_accept(struct pico_socket *s, void *orig, uint16_t *local_port)
{
    IGNORE_PARAMETER(s);
    IGNORE_PARAMETER(orig);
    IGNORE_PARAMETER(local_port);
    pico_err = PICO_ERR_EINVAL;
    return NULL;
}

#endif


int MOCKABLE pico_socket_setoption(struct pico_socket *s, int option, void *value)
{

    if (s == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

#ifdef PICO_SUPPORT_RAWSOCKETS
    if (PROTO(s) == PICO_PROTO_IPV4)
        return pico_setsockopt_ipv4(s, option, value);
#endif

    if (PROTO(s) == PICO_PROTO_TCP)
        return pico_setsockopt_tcp(s, option, value);

    if (PROTO(s) == PICO_PROTO_UDP)
        return pico_setsockopt_udp(s, option, value);


    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}


int pico_socket_getoption(struct pico_socket *s, int option, void *value)
{
    if (s == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

#ifdef PICO_SUPPORT_RAWSOCKETS
    if (PROTO(s) == PICO_PROTO_IPV4)
        return pico_getsockopt_ipv4(s, option, value);
#endif

    if (PROTO(s) == PICO_PROTO_TCP)
        return pico_getsockopt_tcp(s, option, value);

    if (PROTO(s) == PICO_PROTO_UDP)
        return pico_getsockopt_udp(s, option, value);

    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}


int pico_socket_shutdown(struct pico_socket *s, int mode)
{
    if (!s) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Check if the socket has already been closed */
    if (s->state & PICO_SOCKET_STATE_CLOSED) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* unbound sockets can be deleted immediately */
    if (!(s->state & PICO_SOCKET_STATE_BOUND))
    {
        socket_garbage_collect((pico_time)10, s);
        return 0;
    }

#ifdef PICO_SUPPORT_UDP
    if (PROTO(s) == PICO_PROTO_UDP) {
        if ((mode & PICO_SHUT_RDWR) == PICO_SHUT_RDWR)
            pico_socket_alter_state(s, PICO_SOCKET_STATE_CLOSED, PICO_SOCKET_STATE_CLOSING | PICO_SOCKET_STATE_BOUND | PICO_SOCKET_STATE_CONNECTED, 0);
        else if (mode & PICO_SHUT_RD)
            pico_socket_alter_state(s, 0, PICO_SOCKET_STATE_BOUND, 0);
    }

#endif
#ifdef PICO_SUPPORT_TCP
    if (PROTO(s) == PICO_PROTO_TCP) {
        if ((mode & PICO_SHUT_RDWR) == PICO_SHUT_RDWR)
        {
            pico_socket_alter_state(s, PICO_SOCKET_STATE_SHUT_LOCAL | PICO_SOCKET_STATE_SHUT_REMOTE, 0, 0);
            pico_tcp_notify_closing(s);
        }
        else if (mode & PICO_SHUT_WR) {
            pico_socket_alter_state(s, PICO_SOCKET_STATE_SHUT_LOCAL, 0, 0);
            pico_tcp_notify_closing(s);
        } else if (mode & PICO_SHUT_RD)
            pico_socket_alter_state(s, PICO_SOCKET_STATE_SHUT_REMOTE, 0, 0);

    }

#endif
    return 0;
}

int MOCKABLE pico_socket_close(struct pico_socket *s)
{
    if (!s)
        return -1;

#ifdef PICO_SUPPORT_ICMP4
    if (PROTO(s) == PICO_PROTO_ICMP4) {
        pico_socket_icmp4_close(s);
        socket_clean_queues(s);
        PICO_FREE(s);
        return 0;
    }
#endif

#ifdef PICO_SUPPORT_TCP
    if (PROTO(s) == PICO_PROTO_TCP) {
        if (pico_tcp_check_listen_close(s) == 0)
            return 0;
    }

#endif
    return pico_socket_shutdown(s, PICO_SHUT_RDWR);
}

void pico_socket_destroy_all(struct pico_stack *S)
{
    struct pico_sockport *start = NULL;
    struct pico_socket *s;
    struct pico_tree_node *sp_node, *sp_safe;
    struct pico_tree_node *index, *safe;
    PICOTCP_MUTEX_LOCK(S->SockMutex);

    if (S->sp_udp) {
        pico_tree_foreach_safe(sp_node, &S->sp_udp->socks, sp_safe) {
            start = sp_node->keyValue;
            pico_tree_foreach_safe(index, &start->socks, safe){
                s = index->keyValue;
                socket_clean_queues(s);
                pico_tree_delete(&S->sp_udp->socks, s);
                pico_socket_check_empty_sockport(s, S->sp_udp);
#ifdef PICO_SUPPORT_MCAST
                pico_multicast_delete(s);
#endif
                socket_clean_queues(s);
                PICO_FREE(s);
            }
        }
    }
    if (S->sp_tcp) {
        pico_tree_foreach_safe(sp_node, &S->sp_tcp->socks, sp_safe) {
            start = sp_node->keyValue;
            pico_tree_foreach_safe(index, &start->socks, safe){
                s = index->keyValue;
                socket_clean_queues(s);
                pico_tree_delete(&S->sp_tcp->socks, s);
                pico_socket_check_empty_sockport(s, S->sp_tcp);
                pico_socket_tcp_delete(s);
                socket_clean_queues(s);
                PICO_FREE(s);
            }
        }
    }
#ifdef PICO_SUPPORT_ICMP4
    pico_tree_foreach_safe(index, &S->ICMP4Sockets, safe){
        s = index->keyValue;
        pico_socket_icmp4_close(s);
        socket_clean_queues(s);
        PICO_FREE(s);
    }
#endif
#ifdef PICO_SUPPORT_RAWSOCKETS
    pico_tree_foreach_safe(index, &S->IP4Sockets, safe){
        s = index->keyValue;
        pico_socket_ipv4_close(s);
        socket_clean_queues(s);
        PICO_FREE(s);
    }
#endif
    PICOTCP_MUTEX_UNLOCK(S->SockMutex);
}

#ifdef PICO_SUPPORT_CRC
static inline int pico_transport_crc_check(struct pico_frame *f)
{
    struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_udp_hdr *udp_hdr = NULL;
    uint16_t checksum_invalid = 1;

    switch (net_hdr->proto)
    {
#ifdef PICO_SUPPORT_TCP
    case PICO_PROTO_TCP:
        checksum_invalid = short_be(pico_tcp_checksum(f));
        /* dbg("TCP CRC validation == %u\n", checksum_invalid); */
        if (checksum_invalid) {
            dbg("TCP CRC: validation failed!\n");
            pico_frame_discard(f);
            return 0;
        }

        break;
#endif /* PICO_SUPPORT_TCP */

#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
        udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
        if (short_be(udp_hdr->crc)) {
#ifdef PICO_SUPPORT_IPV4
            if (IS_IPV4(f))
                checksum_invalid = short_be(pico_udp_checksum_ipv4(f));

#endif
#ifdef PICO_SUPPORT_IPV6
            if (IS_IPV6(f))
                checksum_invalid = short_be(pico_udp_checksum_ipv6(f));

#endif
            /* dbg("UDP CRC validation == %u\n", checksum_invalid); */
            if (checksum_invalid) {
                /* dbg("UDP CRC: validation failed!\n"); */
                pico_frame_discard(f);
                return 0;
            }
        }

        break;
#endif /* PICO_SUPPORT_UDP */

    default:
        /* Do nothing */
        break;
    }
    return 1;
}
#else
static inline int pico_transport_crc_check(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 1;
}
#endif /* PICO_SUPPORT_CRC */

int pico_transport_process_in(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_trans *hdr = (struct pico_trans *) f->transport_hdr;
    int ret = 0;

    if (!hdr) {
        pico_err = PICO_ERR_EFAULT;
        return -1;
    }

    ret = pico_transport_crc_check(f);
    if (ret < 1)
        return ret;
    else
        ret = 0;

    if ((hdr) && (pico_socket_deliver(S, self, f, hdr->dport) == 0))
        return ret;

    if (!IS_BCAST(f)) {
        dbg("Socket not found... \n");
        pico_notify_socket_unreachable(S, f);
        ret = -1;
        pico_err = PICO_ERR_ENOENT;
    }

    pico_frame_discard(f);
    return ret;
}

#define SL_LOOP_MIN 1

#ifdef PICO_SUPPORT_TCP
int pico_socket_sanity_check(struct pico_socket *s)
{

    /* checking for pending connections */
    if(TCP_STATE(s) == PICO_SOCKET_STATE_TCP_SYN_RECV) {
        if((PICO_TIME_MS() - s->timestamp) >= PICO_SOCKET_BOUND_TIMEOUT)
            return -1;
    }

    return 0;
}
#endif


static int pico_sockets_loop_udp(struct pico_stack *S, int loop_score)
{

#ifdef PICO_SUPPORT_UDP
    struct pico_sockport *start;
    struct pico_socket *s;
    struct pico_frame *f;

    if (S->sp_udp == NULL)
    {
        S->udp_loop_index = pico_tree_firstNode(S->UDPTable.root);
        S->sp_udp = S->udp_loop_index->keyValue;
    }

    /* init start node */
    start = S->sp_udp;

    /* round-robin all transport protocols, break if traversed all protocols */
    while (loop_score > SL_LOOP_MIN && S->sp_udp != NULL) {
        struct pico_tree_node *index;

        pico_tree_foreach(index, &S->sp_udp->socks){
            s = index->keyValue;
            f = pico_dequeue(&s->q_out);
            while (f && (loop_score > 0)) {
                pico_proto_udp.push(S, &pico_proto_udp, f);
                loop_score -= 1;
                if (loop_score > 0) /* only dequeue if there is still loop_score, otherwise f might get lost */
                    f = pico_dequeue(&s->q_out);
            }
        }

        S->udp_loop_index = pico_tree_next(S->udp_loop_index);
        S->sp_udp = S->udp_loop_index->keyValue;

        if (S->sp_udp == NULL)
        {
            S->udp_loop_index = pico_tree_firstNode(S->UDPTable.root);
            S->sp_udp = S->udp_loop_index->keyValue;
        }

        if (S->sp_udp == start)
            break;
    }
#endif
    return loop_score;
}

static int pico_sockets_loop_tcp(struct pico_stack *S, int loop_score)
{
#ifdef PICO_SUPPORT_TCP
    struct pico_sockport *start;
    struct pico_socket *s;
    if (S->sp_tcp == NULL)
    {
        S->tcp_loop_index = pico_tree_firstNode(S->TCPTable.root);
        S->sp_tcp = S->tcp_loop_index->keyValue;
    }

    /* init start node */
    start = S->sp_tcp;

    while (loop_score > SL_LOOP_MIN && S->sp_tcp != NULL) {
        struct pico_tree_node *index = NULL, *safe_index = NULL;
        pico_tree_foreach_safe(index, &S->sp_tcp->socks, safe_index){
            s = index->keyValue;
            loop_score = pico_tcp_output(s, loop_score);
            if ((s->ev_pending) && s->wakeup) {
                s->wakeup(s->ev_pending, s);
                if(!s->parent)
                    s->ev_pending = 0;
            }

            if (loop_score <= 0) {
                loop_score = 0;
                break;
            }

            if(pico_socket_sanity_check(s) < 0)
            {
                pico_socket_del(s);
                S->tcp_loop_index = NULL; /* forcing the restart of loop */
                S->sp_tcp = NULL;
                break;
            }
        }

        /* check if RB_FOREACH ended, if not, break to keep the cur S->sp_tcp */
        if (!S->tcp_loop_index || (index && index->keyValue))
            break;

        S->tcp_loop_index = pico_tree_next(S->tcp_loop_index);
        S->sp_tcp = S->tcp_loop_index->keyValue;

        if (S->sp_tcp == NULL)
        {
            S->tcp_loop_index = pico_tree_firstNode(S->TCPTable.root);
            S->sp_tcp = S->tcp_loop_index->keyValue;
        }

        if (S->sp_tcp == start)
            break;
    }
#endif
    return loop_score;


}

int pico_sockets_loop(struct pico_stack *S, int loop_score)
{
    loop_score = pico_sockets_loop_udp(S, loop_score);
    loop_score = pico_sockets_loop_tcp(S, loop_score);
    return loop_score;
}

int pico_count_sockets(struct pico_stack *S, uint8_t proto)
{
    struct pico_sockport *sp;
    struct pico_tree_node *idx_sp, *idx_s;
    int count = 0;

#ifdef PICO_SUPPORT_TCP
    if ((proto == 0) || (proto == PICO_PROTO_TCP)) {
        pico_tree_foreach(idx_sp, &S->TCPTable) {
            sp = idx_sp->keyValue;
            if (sp) {
                pico_tree_foreach(idx_s, &sp->socks)
                count++;
            }
        }
    }
#endif

#ifdef PICO_SUPPORT_UDP
    if ((proto == 0) || (proto == PICO_PROTO_UDP)) {
        pico_tree_foreach(idx_sp, &S->UDPTable) {
            sp = idx_sp->keyValue;
            if (sp) {
                pico_tree_foreach(idx_s, &sp->socks)
                count++;
            }
        }
    }
#endif

    return count;
}


struct pico_frame *pico_socket_frame_alloc(struct pico_socket *s, struct pico_device *dev, uint16_t len)
{
    struct pico_frame *f = NULL;

#ifdef PICO_SUPPORT_IPV6
    if (is_sock_ipv6(s))
        f = pico_proto_ipv6.alloc(s->stack, &pico_proto_ipv6, dev, len);

#endif

#ifdef PICO_SUPPORT_IPV4
    if (is_sock_ipv4(s))
        f = pico_proto_ipv4.alloc(s->stack, &pico_proto_ipv4, dev, len);

#endif
    if (!f) {
        pico_err = PICO_ERR_ENOMEM;
        return f;
    }

    f->payload = f->transport_hdr;
    f->payload_len = len;
    f->sock = s;
    return f;
}

static void pico_transport_error_set_picoerr(int code)
{
    /* dbg("SOCKET ERROR FROM ICMP NOTIFICATION. (icmp code= %d)\n\n", code); */
    switch(code) {
    case PICO_ICMP_UNREACH_NET:
        pico_err = PICO_ERR_ENETUNREACH;
        break;

    case PICO_ICMP_UNREACH_HOST:
        pico_err = PICO_ERR_EHOSTUNREACH;
        break;

    case PICO_ICMP_UNREACH_PROTOCOL:
        pico_err = PICO_ERR_ENOPROTOOPT;
        break;

    case PICO_ICMP_UNREACH_PORT:
        pico_err = PICO_ERR_ECONNREFUSED;
        break;

    case PICO_ICMP_UNREACH_NET_UNKNOWN:
        pico_err = PICO_ERR_ENETUNREACH;
        break;

    case PICO_ICMP_UNREACH_HOST_UNKNOWN:
        pico_err = PICO_ERR_EHOSTDOWN;
        break;

    case PICO_ICMP_UNREACH_ISOLATED:
        pico_err = PICO_ERR_ENONET;
        break;

    case PICO_ICMP_UNREACH_NET_PROHIB:
    case PICO_ICMP_UNREACH_HOST_PROHIB:
        pico_err = PICO_ERR_EHOSTUNREACH;
        break;

    case PICO_ICMP6_ERR_PKT_TOO_BIG:
        pico_err = PICO_ERR_EMSGSIZE;
        break;

    default:
        pico_err = PICO_ERR_EOPNOTSUPP;
    }
}

int pico_transport_error(struct pico_stack *S, struct pico_frame *f, uint8_t proto, int code)
{
    int ret = -1;
    struct pico_trans *trans = (struct pico_trans*) f->transport_hdr;
    struct pico_sockport *port = NULL;
    struct pico_socket *s = NULL;
    switch (proto) {


#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
        port = pico_get_sockport(S, proto, trans->sport);
        break;
#endif

#ifdef PICO_SUPPORT_TCP
    case PICO_PROTO_TCP:
        port = pico_get_sockport(S, proto, trans->sport);
        break;
#endif

    default:
        /* Protocol not available */
        ret = -1;
    }
    if (port) {
        struct pico_tree_node *index;
        ret = 0;

        pico_tree_foreach(index, &port->socks) {
            s = index->keyValue;
            if (trans->dport == s->remote_port) {
                if (s->wakeup) {
                    pico_transport_error_set_picoerr(code);
                    s->state |= PICO_SOCKET_STATE_SHUT_REMOTE;
                    s->wakeup(PICO_SOCK_EV_ERR, s);
                }

                break;
            }
        }
    }

    pico_frame_discard(f);
    return ret;
}
#endif
#endif
