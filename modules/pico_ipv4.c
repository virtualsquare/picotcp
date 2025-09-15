/*********************************************************************
 * PicoTCP-NG
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Daniele Lacamera, Markian Yskout
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
#include "pico_ipfilter.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_nat.h"
#include "pico_igmp.h"
#include "pico_tree.h"
#include "pico_aodv.h"
#include "pico_socket_multicast.h"
#include "pico_fragments.h"
#include "pico_ethernet.h"
#include "pico_mcast.h"

#ifdef PICO_SUPPORT_IPV4

#ifdef PICO_SUPPORT_MCAST

#ifdef DEBUG_MCAST
#define ip_mcast_dbg dbg
#else
#define ip_mcast_dbg(...) do {} while(0)
#endif

# define PICO_MCAST_ALL_HOSTS long_be(0xE0000001) /* 224.0.0.1 */
#endif

#ifdef PICO_SUPPORT_RAWSOCKETS
int pico_ipv4_rawsocket_cmp(void *ka, void *kb)
{
    struct pico_socket_ipv4 *a = ka, *b = kb;
    if (a->id < b->id)
        return -1;
    if (a->id > b->id)
        return 1;
    return (0);
}
#endif

/* Functions */
int ipv4_route_compare(void *ka, void *kb);
struct pico_frame *pico_ipv4_alloc(struct pico_stack *S, struct pico_protocol *self, struct pico_device *dev, uint16_t size);
static struct pico_ipv4_route *route_find(struct pico_stack *S, const struct pico_ip4 *addr);
static int pico_ipv4_frame_sock_push(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f);
static int pico_ipv4_frame_sock_push_ex(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f, uint8_t ip_proto_n);


int pico_ipv4_compare(struct pico_ip4 *a, struct pico_ip4 *b)
{
    if (a->addr < b->addr)
        return -1;

    if (a->addr > b->addr)
        return 1;

    return 0;
}

int pico_ipv4_to_string(char *ipbuf, const uint32_t ip)
{
    const unsigned char *addr = (const unsigned char *) &ip;
    int i;

    if (!ipbuf) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    for(i = 0; i < 4; i++)
    {
        if (addr[i] > 99) {
            *ipbuf++ = (char)('0' + (addr[i] / 100));
            *ipbuf++ = (char)('0' + ((addr[i] % 100) / 10));
            *ipbuf++ = (char)('0' + ((addr[i] % 100) % 10));
        } else if (addr[i] > 9) {
            *ipbuf++ = (char)('0' + (addr[i] / 10));
            *ipbuf++ = (char)('0' + (addr[i] % 10));
        } else {
            *ipbuf++ = (char)('0' + addr[i]);
        }

        if (i < 3)
            *ipbuf++ = '.';
    }
    *ipbuf = '\0';

    return 0;
}

static int pico_string_check_null_args(const char *ipstr, uint32_t *ip)
{

    if (!ipstr || !ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;

}

int pico_string_to_ipv4(const char *ipstr, uint32_t *ip)
{
    unsigned char buf[PICO_SIZE_IP4] = {
        0
    };
    int cnt = 0;
    char p;
    uint16_t overflow = 0;

    if (pico_string_check_null_args(ipstr, ip) < 0)
        return -1;

    while((p = *ipstr++) != 0 && cnt < PICO_SIZE_IP4)
    {
        if (pico_is_digit(p)) {
            overflow = (uint16_t) ((10 * buf[cnt]) + (p - '0'));
            if(overflow > UINT8_MAX) {
              return -1;
            }
            buf[cnt] = (uint8_t) overflow;
        } else if (p == '.') {
            cnt++;
        } else {
            return -1;
        }
    }
    /* Handle short notation */
    if (cnt == 1) {
        buf[3] = buf[1];
        buf[1] = 0;
        buf[2] = 0;
    } else if (cnt == 2) {
        buf[3] = buf[2];
        buf[2] = 0;
    } else if (cnt != 3) {
        /* String could not be parsed, return error */
        return -1;
    }

    *ip = long_from(buf);

    return 0;
}

int pico_ipv4_valid_netmask(uint32_t mask)
{
    int cnt = 0;
    int end = 0;
    int i;
    uint32_t mask_swap = long_be(mask);

    /*
     * Swap bytes for convenient parsing
     * e.g. 0x..f8ff will become 0xfff8..
     * Then, we count the consecutive bits
     *
     * */

    for(i = 0; i < 32; i++) {
        if ((mask_swap << i) & 0x80000000) {
            if (end) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }

            cnt++;
        } else {
            end = 1;
        }
    }
    return cnt;
}

int pico_ipv4_is_unicast(uint32_t address)
{
    const unsigned char *addr = (unsigned char *) &address;
    if ((addr[0] & 0xe0) == 0xe0)
        return 0; /* multicast */

    return 1;
}

int pico_ipv4_is_multicast(uint32_t address)
{
    const unsigned char *addr = (unsigned char *) &address;
    if ((addr[0] != 0xff) && ((addr[0] & 0xe0) == 0xe0))
        return 1; /* multicast */

    return 0;
}

int pico_ipv4_is_loopback(uint32_t address)
{
    const unsigned char *addr = (unsigned char *) &address;
    if (addr[0] == 0x7f)
        return 1;

    return 0;
}

static int pico_ipv4_is_invalid_loopback(uint32_t address, struct pico_device *dev)
{
    return pico_ipv4_is_loopback(address) && ((!dev) || strcmp(dev->name, "loop"));
}

int pico_ipv4_is_valid_src(struct pico_stack *S, uint32_t address, struct pico_device *dev)
{
    if (pico_ipv4_is_broadcast(S, address)) {
        dbg("Source is a broadcast address, discard packet\n");
        return 0;
    } else if ( pico_ipv4_is_multicast(address)) {
        dbg("Source is a multicast address, discard packet\n");
        return 0;
    } else if (pico_ipv4_is_invalid_loopback(address, dev)) {
        dbg("Source is a loopback address, discard packet\n");
        return 0;
    } else {
#ifdef PICO_SUPPORT_AODV
        union pico_address src;
        src.ip4.addr = address;
        pico_aodv_refresh(dev->stack, &src);
#endif
        return 1;
    }
}

static int pico_ipv4_checksum(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (!hdr)
        return -1;

    hdr->crc = 0;
    hdr->crc = short_be(pico_checksum(hdr, f->net_len));
    return 0;
}


#ifdef PICO_SUPPORT_CRC
static inline int pico_ipv4_crc_check(struct pico_frame *f)
{
    uint16_t checksum_invalid = 1;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

    checksum_invalid = short_be(pico_checksum(hdr, f->net_len));
    if (checksum_invalid) {
        dbg("IP: checksum failed!\n");
        pico_frame_discard(f);
        return 0;
    }

    return 1;
}
#else
static inline int pico_ipv4_crc_check(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 1;
}
#endif /* PICO_SUPPORT_CRC */

static int pico_ipv4_forward(struct pico_stack *S, struct pico_frame *f);
#ifdef PICO_SUPPORT_MCAST
static int pico_ipv4_mcast_filter(struct pico_stack *S, struct pico_frame *f);
#endif

int ipv4_link_compare(void *ka, void *kb)
{
    struct pico_ipv4_link *a = ka, *b = kb;
    int cmp = pico_ipv4_compare(&a->address, &b->address);
    if (cmp)
        return cmp;

    /* zero can be assigned multiple times (e.g. for DHCP) */
    if (a->dev != NULL && b->dev != NULL && a->address.addr == PICO_IP4_ANY && b->address.addr == PICO_IP4_ANY) {
        if (a->dev < b->dev)
            return -1;

        if (a->dev > b->dev)
            return 1;
    }

    return 0;
}


static int pico_ipv4_process_bcast_in(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
#ifdef PICO_SUPPORT_UDP
    if (pico_ipv4_is_broadcast(S, hdr->dst.addr) && (hdr->proto == PICO_PROTO_UDP)) {
        /* Receiving UDP broadcast datagram */
        f->flags |= PICO_FRAME_FLAG_BCAST;
        pico_enqueue(pico_proto_udp.q_in, f);
        return 1;
    }

#endif

#ifdef PICO_SUPPORT_ICMP4
    if (pico_ipv4_is_broadcast(S, hdr->dst.addr) && (hdr->proto == PICO_PROTO_ICMP4)) {
        /* Receiving ICMP4 bcast packet */
        f->flags |= PICO_FRAME_FLAG_BCAST;
        pico_enqueue(pico_proto_icmp4.q_in, f);
        return 1;
    }

#endif
    return 0;
}

static int pico_ipv4_process_mcast_in(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (pico_ipv4_is_multicast(hdr->dst.addr)) {
#ifdef PICO_SUPPORT_IGMP
        /* Receiving UDP multicast datagram TODO set f->flags? */
        if (hdr->proto == PICO_PROTO_IGMP) {
            ip_mcast_dbg("MCAST: received IGMP message\n");
            pico_transport_receive(f, PICO_PROTO_IGMP);
            return 1;
        } else if ((pico_ipv4_mcast_filter(f->dev->stack, f) == 0) && (hdr->proto == PICO_PROTO_UDP)) {
            pico_enqueue(pico_proto_udp.q_in, f);
            return 1;
        }

#endif
        pico_frame_discard(f);
        return 1;
    }

    return 0;
}

static int pico_ipv4_process_local_unicast_in(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_ipv4_link test = {
        .address = {.addr = PICO_IP4_ANY}, .dev = NULL
    };
    if (pico_ipv4_link_find(S, &hdr->dst)) {
        if (pico_ipv4_nat_inbound(S, f, &hdr->dst) == 0)
            pico_enqueue(pico_proto_ipv4.q_in, f); /* dst changed, reprocess */
        else
            pico_transport_receive(f, hdr->proto);

        return 1;
    } else if (pico_tree_findKey(&S->Tree_dev_link, &test)) {
#ifdef PICO_SUPPORT_UDP
        /* address of this device is apparently 0.0.0.0; might be a DHCP packet */
        /* XXX KRO: is obsolete. Broadcast flag is set on outgoing DHCP messages.
         * incoming DHCP messages are to be broadcasted. Our current DHCP server
         * implementation does not take this flag into account yet though ... */
        pico_enqueue(pico_proto_udp.q_in, f);
        return 1;
#endif
    }

    return 0;
}

static void pico_ipv4_process_finally_try_forward(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if ((pico_ipv4_is_broadcast(S, hdr->dst.addr)) || ((f->flags & PICO_FRAME_FLAG_BCAST) != 0)) {
        /* don't forward broadcast frame, discard! */
        pico_frame_discard(f);
    } else if (pico_ipv4_forward(S, f) != 0) {
        pico_frame_discard(f);
        /* dbg("Forward failed.\n"); */
    }
}

#ifdef PICO_SUPPORT_RAWSOCKETS

struct pico_socket *pico_socket_ipv4_open(struct pico_stack *S, uint16_t proto)
{
    struct pico_socket_ipv4 *s;
    if ((proto & PICO_PROTO_RAWSOCKET) == 0) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    s = PICO_ZALLOC(sizeof(struct pico_socket_ipv4));
    if (!s) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    if ((proto & 0x00FF)== PICO_RAWSOCKET_RAW)
        s->hdr_included = 1;
    s->id = S->IP4Socket_id++;
    s->proto = (uint8_t)(proto & 0x00FF);
    s->sock.proto = &pico_proto_ipv4;
    s->sock.stack = S;

    pico_tree_insert(&S->IP4Sockets, s);
    return (struct pico_socket *)s;
}

int pico_socket_ipv4_recvfrom(struct pico_socket *s, void *buf, uint32_t len, void *orig,
                                  uint16_t *remote_port)
{
    struct pico_frame *f;
    uint8_t *data;
    uint16_t real_len;
    struct pico_socket_ipv4 *s4 = (struct pico_socket_ipv4 *)s;

    f = pico_dequeue(&s->q_in);
    if (!f)
        return 0;
    if (s4->hdr_included) {
        data = f->net_hdr;
        real_len = f->net_len;
    } else {
        data = f->transport_hdr;
        real_len = f->transport_len;
    }
    if (real_len < len) {
        len = real_len;
    }
    if (len == 0)
        return 0;
    memcpy(buf, data, (size_t)len);
    if (!s4->hdr_included && orig) {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
        memcpy(orig, &hdr->src, sizeof(struct pico_ip4));
        *remote_port = 0;
    }
    pico_frame_discard(f);
    return (int)len;
}

static int pico_socket_ipv4_process_out(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_ipv4 *s4 = (struct pico_socket_ipv4 *)s;
    int ret;
    uint32_t plen = f->len;
    if (s->dev && ((s->state & PICO_SOCKET_STATE_BOUND) != 0)) {
        f->dev = s->dev;
        ret = pico_datalink_send(f); /* implies discard */
        if (ret > 0)
            return (int)plen;
        else
            return -1;
    }

    if ((f->net_hdr[0] & 0xF0) == 0x40) {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
        struct pico_ipv4_route *rt;
        uint16_t iplen = (uint16_t)(
            (f->net_hdr[0] & 0x0F) * sizeof(uint32_t)); /* Read len of forged iphdr */

        if (iplen >= plen) {
            pico_err = PICO_ERR_EINVAL;
            pico_frame_discard(f);
            return -1;
        }
        f->net_len = iplen;
        f->transport_hdr = f->net_hdr + f->net_len;
        rt = route_find(s->stack, &hdr->dst);
        if (!rt) {
            pico_err = PICO_ERR_EHOSTUNREACH;
            pico_frame_discard(f);
            return -1;
        }
        if ((rt->gateway.addr != 0U) && (s4->dontroute)) {
            pico_err = PICO_ERR_EHOSTUNREACH;
            pico_frame_discard(f);
            return -1;
        }
        f->dev = rt->link->dev;
        ret = pico_datalink_send(f); /* implies discard */
        if (ret > 0)
            return (int)plen;
        else
            return -1;
    }
    pico_frame_discard(f);
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

int pico_socket_ipv4_sendto(struct pico_socket *s, const void *buf, uint32_t len, void *dst)
{
    struct pico_frame *f;
    struct pico_socket_ipv4 *s4 = (struct pico_socket_ipv4 *)s;
    (void)dst;
    if (!s4->hdr_included && (s4->proto == PICO_PROTO_IPV4)) {
       /* Raw socket: no send allowed withouth IP_HDRINCL, or if protocol is IPPROTO_IP */
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (len > pico_socket_get_mss(s)) {
        pico_err = PICO_ERR_EMSGSIZE;
        return -1;
    }

    if (!s4->hdr_included) {
        f = pico_proto_ipv4.alloc(s->stack, &pico_proto_ipv4, NULL, (uint16_t)(len));
        if (!f)
            return -1;
        memcpy(f->transport_hdr, (const uint8_t *)buf, len);
        f->transport_len = (uint16_t)len;
        f->sock = s;
        if (dst) {
            f->info = PICO_ZALLOC(sizeof(struct pico_remote_endpoint));
            if (f->info == NULL) {
                pico_frame_discard(f);
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }
            memcpy(f->info, dst, sizeof(struct pico_remote_endpoint));
        }
        if (pico_ipv4_frame_sock_push_ex(s->stack, &pico_proto_ipv4, f, s4->proto) > 0)
            return (int)len;
        else
            return -1;
    }

    /* Allocate packet and send */
    f = pico_proto_ethernet.alloc(s->stack, &pico_proto_ethernet, NULL, (uint16_t)(len));
    if (!f) {
        return -1;
    }
    memcpy(f->net_hdr, (const uint8_t *)buf, len);
    f->start = f->net_hdr;
    f->len = len;
    if (pico_socket_ipv4_process_out(s, f) > 0)
        return (int)len;
    else
        return -1;
}

int pico_socket_ipv4_close(struct pico_socket *arg)
{
    struct pico_socket_ipv4 *s = (struct pico_socket_ipv4 *)arg;
    if (s) {
        pico_tree_delete(&s->sock.stack->IP4Sockets, s);
        return 0;
    }
    pico_err = PICO_ERR_ENOENT;
    return -1;
}

int pico_setsockopt_ipv4(struct pico_socket *s, int option, void *value)
{
    struct pico_socket_ipv4 *s4 = (struct pico_socket_ipv4 *)s;
    switch(option) {
        case PICO_SOCKET_OPT_IP_HDRINCL:
            if (s4->proto == PICO_RAWSOCKET_RAW) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            s4->hdr_included = (*(int*)value)?1:0;
            return 0;
        case PICO_SOCKET_OPT_IP_DONTROUTE:
            s4->dontroute = (*(int*)value)?1:0;
            return 0;
        case PICO_SOCKET_OPT_IP_BINDTODEVICE:
            s->dev = (struct pico_device *)value;
            s->local_addr.ip4.addr = 0;
            return 0;
    }
    /* switch's default */
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

int pico_getsockopt_ipv4(struct pico_socket *s, int option, void *value)
{
    int *val = (int *)value;
    void ** pval = (void *)value;
    struct pico_socket_ipv4 *s4 = (struct pico_socket_ipv4 *)s;
    switch(option) {
        case PICO_SOCKET_OPT_IP_HDRINCL:
            *val = (int)s4->hdr_included;
            return 0;
        case PICO_SOCKET_OPT_IP_DONTROUTE:
            *val = (int)s4->dontroute;
            return 0;
        case PICO_SOCKET_OPT_IP_BINDTODEVICE:
            *pval = s->dev;
            return 0;
    }
    /* switch's default */
    pico_err = PICO_ERR_EINVAL;
    return -1;
}

static void pico_socket_ipv4_process_in(struct pico_frame *f)
{
    struct pico_tree_node *node;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
    pico_tree_foreach(node, &f->dev->stack->IP4Sockets) {
        struct pico_socket_ipv4 *s;
        struct pico_frame *cp;
        s = (struct pico_socket_ipv4 *) node->keyValue;
        if (!s->hdr_included && ((s->proto != PICO_PROTO_IPV4) && (s->proto != hdr->proto)))
            continue;
        if ((s->sock.state | PICO_SOCKET_STATE_BOUND) != 0) {
            if (s->sock.dev != f->dev)
                continue;
            if ((s->sock.local_addr.ip4.addr != 0) && (s->sock.local_addr.ip4.addr != hdr->dst.addr))
                continue;
        }
        cp = pico_frame_copy(f);
        if (cp) {
            pico_enqueue(&s->sock.q_in, cp);
            if (s->sock.wakeup) {
                s->sock.wakeup(PICO_SOCK_EV_RD, &s->sock);
            }
        }
    }
}
#endif

static int pico_ipv4_process_in(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    uint8_t option_len = 0;
    int ret = 0;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    uint16_t max_allowed = (uint16_t) ((int)f->buffer_len - (f->net_hdr - f->buffer) - (int)PICO_SIZE_IP4HDR);

    if (!hdr)
        return -1;

    (void)self;

    /* NAT needs transport header information */
    if (((hdr->vhl) & 0x0F) > 5) {
        option_len =  (uint8_t)(4 * (((hdr->vhl) & 0x0F) - 5));
    }

    f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR + option_len;
    f->transport_len = (uint16_t)(short_be(hdr->len) - PICO_SIZE_IP4HDR - option_len);
    f->net_len = (uint16_t)(PICO_SIZE_IP4HDR + option_len);

    if ((f->net_hdr + f->net_len) > (f->buffer + f->buffer_len)) {
        pico_frame_discard(f);
        return 0;
    }
#if defined(PICO_SUPPORT_IPV4FRAG) || defined(PICO_SUPPORT_IPV6FRAG)
    f->frag = short_be(hdr->frag);
#endif

    if (f->transport_len > max_allowed) {
        pico_frame_discard(f);
        return 0; /* Packet is discarded due to unfeasible length */
    }

#ifdef PICO_SUPPORT_IPFILTER
    if (ipfilter(f)) {
        /*pico_frame is discarded as result of the filtering*/
        return 0;
    }

#endif
    /* ret == 1 indicates to continue the function */
    ret = pico_ipv4_crc_check(f);
    if (ret < 1)
        return ret;

    /* Validate source IP address. Discard quietly if invalid */
    if (!pico_ipv4_is_valid_src(S, hdr->src.addr, f->dev)) {
        pico_frame_discard(f);
        return 0;
    }

#if defined(PICO_SUPPORT_IPV4FRAG) || defined(PICO_SUPPORT_IPV6FRAG)
    if (f->frag & PICO_IPV4_EVIL) {
        (void)pico_icmp4_param_problem(S, f, 0);
        pico_frame_discard(f); /* RFC 3514 */
        return 0;
    }
#endif

    if ((hdr->vhl & 0x0f) < 5) {
        /* RFC 791: IHL minimum value is 5 */
        (void)pico_icmp4_param_problem(S, f, 0);
        pico_frame_discard(f);
        return 0;
    }

#if defined(PICO_SUPPORT_IPV4FRAG) || defined(PICO_SUPPORT_IPV6FRAG)
    if (f->frag & (PICO_IPV4_MOREFRAG | PICO_IPV4_FRAG_MASK))
    {
#ifdef PICO_SUPPORT_IPV4FRAG
        pico_ipv4_process_frag(hdr, f, hdr->proto);
        /* Frame can be discarded, frag will handle its own copy */
#endif
        /* We do not support fragmentation, discard quietly */
        pico_frame_discard(f);
        return 0;
    }
#endif

#ifdef PICO_SUPPORT_RAWSOCKETS
    pico_socket_ipv4_process_in(f);
#endif

    if (pico_ipv4_process_bcast_in(S, f) > 0)
        return 0;

    if (pico_ipv4_process_mcast_in(f) > 0)
        return 0;

    if (pico_ipv4_process_local_unicast_in(S, f) > 0)
        return 0;

    pico_ipv4_process_finally_try_forward(S, f);

    return 0;
}



static int pico_ipv4_process_out(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(S);
    f->start = (uint8_t*) f->net_hdr;
#ifdef PICO_SUPPORT_IPFILTER
    if (ipfilter(f)) {
        /*pico_frame is discarded as result of the filtering*/
        return 0;
    }

#endif
    return pico_datalink_send(f);
}


struct pico_frame *pico_ipv4_alloc(struct pico_stack *S, struct pico_protocol *self, struct pico_device *dev, uint16_t size)
{
    struct pico_frame *f = NULL;
    IGNORE_PARAMETER(self);

    f = pico_proto_ethernet.alloc(S, &pico_proto_ethernet, dev, (uint16_t)(size + PICO_SIZE_IP4HDR));
    /* TODO: In 6LoWPAN topic branch update to make use of dev->ll_mode */

    if (!f)
        return NULL;

    f->net_len = PICO_SIZE_IP4HDR;
    f->transport_hdr = f->net_hdr + PICO_SIZE_IP4HDR;
    f->transport_len = (uint16_t)size;

    /* Datalink size is accounted for in pico_datalink_send (link layer) */
    f->len =  (uint32_t)(size + PICO_SIZE_IP4HDR);

    return f;
}


/* Interface: protocol definition */
struct pico_protocol pico_proto_ipv4 = {
    .name = "ipv4",
    .proto_number = PICO_PROTO_IPV4,
    .layer = PICO_LAYER_NETWORK,
    .alloc = pico_ipv4_alloc,
    .process_in = pico_ipv4_process_in,
    .process_out = pico_ipv4_process_out,
    .push = pico_ipv4_frame_sock_push,
};

int ipv4_route_compare(void *ka, void *kb)
{
    struct pico_ipv4_route *a = ka, *b = kb;
    uint32_t a_nm, b_nm;
    int cmp;

    a_nm = long_be(a->netmask.addr);
    b_nm = long_be(b->netmask.addr);

    /* S->Routes are sorted by (host side) netmask len, then by addr, then by metric. */
    if (a_nm < b_nm)
        return -1;

    if (b_nm < a_nm)
        return 1;

    cmp = pico_ipv4_compare(&a->dest, &b->dest);
    if (cmp)
        return cmp;

    if (a->metric < b->metric)
        return -1;

    if (a->metric > b->metric)
        return 1;

    return 0;
}

struct pico_ipv4_route initial_default_bcast_route = {
    .dest = {PICO_IP4_BCAST},
    .netmask = {PICO_IP4_BCAST},
    .gateway  = { 0 },
    .link = NULL,
    .metric = 1000
};

static struct pico_ipv4_route *route_find_default_bcast(struct pico_stack *S)
{
    return S->default_bcast_route;
}

static struct pico_ipv4_route *route_find(struct pico_stack *S, const struct pico_ip4 *addr)
{
    struct pico_ipv4_route *r;
    struct pico_tree_node *index;

    if (addr->addr == PICO_IP4_ANY) {
        return NULL;
    }

    if (addr->addr != PICO_IP4_BCAST) {
        pico_tree_foreach_reverse(index, &S->Routes) {
            r = index->keyValue;
            if ((addr->addr & (r->netmask.addr)) == (r->dest.addr)) {
                return r;
            }
        }
        return NULL;
    }

    return route_find_default_bcast(S);
}

struct pico_ip4 pico_ipv4_route_get_gateway(struct pico_stack *S, struct pico_ip4 *addr)
{
    struct pico_ip4 nullip;
    struct pico_ipv4_route *route;
    nullip.addr = 0U;

    if (!addr) {
        pico_err = PICO_ERR_EINVAL;
        return nullip;
    }

    route = route_find(S, addr);
    if (!route) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return nullip;
    }
    else
        return route->gateway;
}

struct pico_ip4 *pico_ipv4_source_find(struct pico_stack *S, const struct pico_ip4 *dst)
{
    struct pico_ip4 *myself = NULL;
    struct pico_ipv4_route *rt;
#ifdef PICO_SUPPORT_AODV
    union pico_address node_address;
    node_address.ip4.addr = dst->addr;
    if (dst->addr && pico_ipv4_is_unicast(dst->addr))
        pico_aodv_lookup(S, &node_address);

#endif

    if (!dst) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    rt = route_find(S, dst);
    if (rt && rt->link) {
        myself = &rt->link->address;
    } else {
        pico_err = PICO_ERR_EHOSTUNREACH;
    }

    return myself;
}

struct pico_device *pico_ipv4_source_dev_find(struct pico_stack *S, const struct pico_ip4 *dst)
{
    struct pico_device *dev = NULL;
    struct pico_ipv4_route *rt;

    if (!dst) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    rt = route_find(S, dst);
    if (rt && rt->link) {
        dev = rt->link->dev;
    } else {
        pico_err = PICO_ERR_EHOSTUNREACH;
    }

    return dev;
}


#ifdef PICO_SUPPORT_MCAST
/*                        link
 *                         |
 *                    MCASTGroups
 *                    |    |     |
 *         ------------    |     ------------
 *         |               |                |
 *   MCASTSources    MCASTSources     MCASTSources
 *   |  |  |  |      |  |  |  |       |  |  |  |
 *   S  S  S  S      S  S  S  S       S  S  S  S
 *
 *   MCASTGroups: RBTree(mcast_group)
 *   MCASTSources: RBTree(source)
 */
static int ipv4_mcast_groups_cmp(void *ka, void *kb)
{
    struct pico_mcast_group *a = ka, *b = kb;
    return pico_ipv4_compare(&a->mcast_addr.ip4, &b->mcast_addr.ip4);
}

static int ipv4_mcast_sources_cmp(void *ka, void *kb)
{
    struct pico_ip4 *a = ka, *b = kb;
    return pico_ipv4_compare(a, b);
}

static void pico_ipv4_mcast_print_groups(struct pico_ipv4_link *mcast_link)
{
    uint16_t i = 0;
    struct pico_mcast_group *g = NULL;
    struct pico_ip4 *source = NULL;
    struct pico_tree_node *index = NULL, *index2 = NULL;
    (void) source;

    ip_mcast_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    ip_mcast_dbg("+                           MULTICAST list interface %-16s             +\n", mcast_link->dev->name);
    ip_mcast_dbg("+---------------------------------------------------------------------------------+\n");
    ip_mcast_dbg("+  nr  |    interface     | host group | reference count | filter mode |  source  +\n");
    ip_mcast_dbg("+---------------------------------------------------------------------------------+\n");

    pico_tree_foreach(index, mcast_link->MCASTGroups) {
        g = index->keyValue;
        ip_mcast_dbg("+ %04d | %16s |  %08X  |      %05u      |      %u      | %8s +\n", i, mcast_link->dev->name, g->mcast_addr.ip4.addr, g->reference_count, g->filter_mode, "");
        pico_tree_foreach(index2, &g->MCASTSources) {
            source = index2->keyValue;
            ip_mcast_dbg("+ %4s | %16s |  %8s  |      %5s      |      %s      | %08X +\n", "", "", "", "", "", source->addr);
        }
        i++;
    }
    ip_mcast_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

static int mcast_group_update(struct pico_mcast_group *g, struct pico_tree *MCASTFilter, uint8_t filter_mode)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ip4 *source = NULL;
    /* cleanup filter */
    pico_tree_foreach_safe(index, &g->MCASTSources, _tmp) {
        source = index->keyValue;
        pico_tree_delete(&g->MCASTSources, source);
        PICO_FREE(source);
    }
    /* insert new filter */
    if (MCASTFilter) {
        pico_tree_foreach(index, MCASTFilter) {
            if (index->keyValue) {
                source = PICO_ZALLOC(sizeof(struct pico_ip4));
                if (!source) {
                    pico_err = PICO_ERR_ENOMEM;
                    return -1;
                }
                source->addr = ((struct pico_ip4 *)index->keyValue)->addr;
                if (pico_tree_insert(&g->MCASTSources, source)) {
                    dbg("IPv4: Failed to insert source in tree\n");
					PICO_FREE(source);
					return -1;
				}
            }
        }
    }

    g->filter_mode = filter_mode;
    return 0;
}

int pico_ipv4_mcast_join(struct pico_stack *S, struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv4_link *link = NULL;

    if (mcast_link)
        link = pico_ipv4_link_get(S, mcast_link);

    if (!link)
        link = S->ipv4_mcast_default_link;

    test.mcast_addr.ip4 = *mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (g) {
        if (reference_count)
            g->reference_count++;

#ifdef PICO_SUPPORT_IGMP
        pico_igmp_state_change(S, mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_UPDATE);
#endif
    } else {
        g = PICO_ZALLOC(sizeof(struct pico_mcast_group));
        if (!g) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        /* "non-existent" state of filter mode INCLUDE and empty source list */
        g->filter_mode = PICO_IP_MULTICAST_INCLUDE;
        g->reference_count = 1;
        g->mcast_addr.ip4 = *mcast_group;
        g->MCASTSources.root = &LEAF;
        g->MCASTSources.compare = ipv4_mcast_sources_cmp;
        if (pico_tree_insert(link->MCASTGroups, g)) {
            dbg("IPv4: Failed to insert group in tree\n");
            PICO_FREE(g);
			return -1;
		}

#ifdef PICO_SUPPORT_IGMP
        pico_igmp_state_change(S, mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_CREATE);
#endif
    }

    if (mcast_group_update(g, MCASTFilter, filter_mode) < 0) {
        dbg("Error in mcast_group update\n");
        return -1;
    }

    pico_ipv4_mcast_print_groups(link);
    return 0;
}

int pico_ipv4_mcast_leave(struct pico_stack *S, struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{

    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv4_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ip4 *source = NULL;

    if (mcast_link)
        link = pico_ipv4_link_get(S, mcast_link);

    if (!link)
        link = S->ipv4_mcast_default_link;

    if (!link)
        return -1;

    test.mcast_addr.ip4 = *mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (!g) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (reference_count && (--(g->reference_count) < 1)) {
#ifdef PICO_SUPPORT_IGMP
            pico_igmp_state_change(S, mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_DELETE);
#endif
            /* cleanup filter */
            pico_tree_foreach_safe(index, &g->MCASTSources, _tmp) {
                source = index->keyValue;
                pico_tree_delete(&g->MCASTSources, source);
                PICO_FREE(source);
            }
            pico_tree_delete(link->MCASTGroups, g);
            PICO_FREE(g);
        } else {
#ifdef PICO_SUPPORT_IGMP
            pico_igmp_state_change(S, mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_UPDATE);
#endif
            if (mcast_group_update(g, MCASTFilter, filter_mode) < 0)
                return -1;
        }
    }

    pico_ipv4_mcast_print_groups(link);
    return 0;
}

struct pico_ipv4_link *pico_ipv4_get_default_mcastlink(struct pico_stack *S)
{
    return S->ipv4_mcast_default_link;
}

static int pico_ipv4_mcast_filter(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv4_link *link = NULL;
    struct pico_tree_node *index = NULL, *index2 = NULL;
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

    test.mcast_addr.ip4 = hdr->dst;

    pico_tree_foreach(index, &S->Tree_dev_link) {
        link = index->keyValue;
        g = pico_tree_findKey(link->MCASTGroups, &test);
        if (g) {
            if (f->dev == link->dev) {
                ip_mcast_dbg("MCAST: IP %08X is group member of current link %s\n", hdr->dst.addr, f->dev->name);
                /* perform source filtering */
                switch (g->filter_mode) {
                case PICO_IP_MULTICAST_INCLUDE:
                    pico_tree_foreach(index2, &g->MCASTSources) {
                        if (hdr->src.addr == ((struct pico_ip4 *)index2->keyValue)->addr) {
                            ip_mcast_dbg("MCAST: IP %08X in included interface source list\n", hdr->src.addr);
                            return 0;
                        }
                    }
                    ip_mcast_dbg("MCAST: IP %08X NOT in included interface source list\n", hdr->src.addr);
                    return -1;

                case PICO_IP_MULTICAST_EXCLUDE:
                    pico_tree_foreach(index2, &g->MCASTSources) {
                        if (hdr->src.addr == ((struct pico_ip4 *)index2->keyValue)->addr) {
                            ip_mcast_dbg("MCAST: IP %08X in excluded interface source list\n", hdr->src.addr);
                            return -1;
                        }
                    }
                    ip_mcast_dbg("MCAST: IP %08X NOT in excluded interface source list\n", hdr->src.addr);
                    return 0;

                default:
                    return -1;
                }
            } else {
                ip_mcast_dbg("MCAST: IP %08X is group member of different link %s\n", hdr->dst.addr, link->dev->name);
            }
        } else {
            ip_mcast_dbg("MCAST: IP %08X is not a group member of link %s\n", hdr->dst.addr, f->dev->name);
        }
    }
    return -1;
}

#else

int pico_ipv4_mcast_join(struct pico_stack *S, struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{
    IGNORE_PARAMETER(S);
    IGNORE_PARAMETER(mcast_link);
    IGNORE_PARAMETER(mcast_group);
    IGNORE_PARAMETER(reference_count);
    IGNORE_PARAMETER(filter_mode);
    IGNORE_PARAMETER(MCASTFilter);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_ipv4_mcast_leave(struct pico_stack *S, struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{
    IGNORE_PARAMETER(S);
    IGNORE_PARAMETER(mcast_link);
    IGNORE_PARAMETER(mcast_group);
    IGNORE_PARAMETER(reference_count);
    IGNORE_PARAMETER(filter_mode);
    IGNORE_PARAMETER(MCASTFilter);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

struct pico_ipv4_link *pico_ipv4_get_default_mcastlink(struct pico_stack *S)
{
    IGNORE_PARAMETER(S);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return NULL;
}
#endif /* PICO_SUPPORT_MCAST */

/* #define DEBUG_ROUTE */
#ifdef DEBUG_ROUTE
void dbg_route(void)
{
    struct pico_ipv4_route *r;
    struct pico_tree_node *index;
    int count_hosts = 0;
    dbg("==== ROUTING TABLE =====\n");
    pico_tree_foreach(index, &S->Routes) {
        r = index->keyValue;
        dbg("Route to %08x/%08x, gw %08x, dev: %s, metric: %d\n", r->dest.addr, r->netmask.addr, r->gateway.addr, r->link->dev->name, r->metric);
        if (r->netmask.addr == 0xFFFFFFFF)
            count_hosts++;
    }
    dbg("================ total HOST nodes: %d ======\n\n\n", count_hosts);
}
#else
#define dbg_route() do { } while(0)
#endif

int pico_ipv4_frame_push(struct pico_stack *S, struct pico_frame *f, struct pico_ip4 *dst, uint8_t proto)
{

    struct pico_ipv4_route *route;
    struct pico_ipv4_link *link;
    struct pico_ipv4_hdr *hdr;
    uint8_t ttl = PICO_IPV4_DEFAULT_TTL;
    uint8_t vhl = 0x45; /* version 4, header length 20 */
#ifdef PICO_SUPPORT_MCAST
    struct pico_tree_node *index;
#endif

    if (!f || !dst) {
        pico_err = PICO_ERR_EINVAL;
        goto drop;
    }


    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (!hdr) {
        dbg("IP header error\n");
        pico_err = PICO_ERR_EINVAL;
        goto drop;
    }

    if (dst->addr == 0) {
        dbg("IP destination addr error\n");
        pico_err = PICO_ERR_EINVAL;
        goto drop;
    }

    route = route_find(S, dst);
    if (!route) {
        /* dbg("Route to %08x not found.\n", long_be(dst->addr)); */


        pico_err = PICO_ERR_EHOSTUNREACH;
        goto drop;
    } else {
        link = route->link;
#ifdef PICO_SUPPORT_MCAST
        if (pico_ipv4_is_multicast(dst->addr)) { /* if multicast */
            switch (proto) {
            case PICO_PROTO_UDP:
                if (pico_udp_get_mc_ttl(f->sock, &ttl) < 0)
                    ttl = PICO_IP_DEFAULT_MULTICAST_TTL;

                break;
#ifdef PICO_SUPPORT_IGMP
            case PICO_PROTO_IGMP:
                vhl = 0x46; /* header length 24 */
                ttl = 1;
                /* router alert (RFC 2113) */
                hdr->options[0] = 0x94;
                hdr->options[1] = 0x04;
                hdr->options[2] = 0x00;
                hdr->options[3] = 0x00;
                if (f->dev && link->dev != f->dev) { /* default link is not requested link */
                    pico_tree_foreach(index, &S->Tree_dev_link) {
                        link = index->keyValue;
                        if (link->dev == f->dev)
                            break;
                    }
                }

                break;
#endif
            default:
                ttl = PICO_IPV4_DEFAULT_TTL;
            }
        }

#endif
    }

    hdr->vhl = vhl;
    hdr->len = short_be((uint16_t)(f->transport_len + f->net_len));
    hdr->id = short_be(S->ipv4_progressive_id);

    if (
#ifdef PICO_SUPPORT_IPV4FRAG
        (0 == (f->frag & PICO_IPV4_MOREFRAG))  &&
#endif
        1 )
        S->ipv4_progressive_id++;

    if (f->send_ttl > 0) {
        ttl = f->send_ttl;
    }

    hdr->dst.addr = dst->addr;
    hdr->src.addr = link->address.addr;
    hdr->ttl = ttl;
    hdr->tos = f->send_tos;
    hdr->proto = proto;
    hdr->frag = short_be(PICO_IPV4_DONTFRAG);

#ifdef PICO_SUPPORT_IPV4FRAG
#  ifdef PICO_SUPPORT_UDP
    if (proto == PICO_PROTO_UDP) {
        /* first fragment, can not use transport_len to calculate IP length */
        if (f->transport_hdr != f->payload)
            hdr->len = short_be((uint16_t)(f->payload_len + sizeof(struct pico_udp_hdr) + f->net_len));

        /* set fragmentation flags and offset calculated in socket layer */
        hdr->frag = short_be(f->frag);
    }

    if (proto == PICO_PROTO_ICMP4)
    {
        hdr->frag = short_be(f->frag);
    }

#   endif
#endif /* PICO_SUPPORT_IPV4FRAG */
    pico_ipv4_checksum(f);

    if (f->sock && f->sock->dev) {
        /* if the socket has its device set, use that (currently used for DHCP) */
        f->dev = f->sock->dev;
    } else {
        f->dev = link->dev;
        if (f->sock)
            f->sock->dev = f->dev;
    }

#ifdef PICO_SUPPORT_MCAST
    if (pico_ipv4_is_multicast(hdr->dst.addr)) {
        struct pico_frame *cpy;
        int retval;
        /* Sending UDP multicast datagram, am I member? If so, loopback copy */
        if ((proto != PICO_PROTO_IGMP) && (pico_ipv4_mcast_filter(S,f) == 0)) {
            ip_mcast_dbg("MCAST: sender is member of group, loopback copy\n");
            cpy = pico_frame_copy(f);
            if (!cpy) {
                pico_err = PICO_ERR_ENOMEM;
                ip_mcast_dbg("MCAST: Failed to copy frame\n");
                goto drop;
            }

            retval = pico_enqueue(&S->q_ipv4.in, cpy);
            if (retval <= 0)
                pico_frame_discard(cpy);
        }
    }

#endif

/* #ifdef PICO_SUPPORT_AODV */
#if 0
    {
        union pico_address node_address;
        node_address.ip4.addr = hdr->dst.addr;
        if(hdr->dst.addr && pico_ipv4_is_unicast(hdr->dst.addr))
            pico_aodv_lookup(&node_address);
    }
#endif

    if (pico_ipv4_link_get(S, &hdr->dst)) {
        /* it's our own IP */
        return pico_enqueue(&S->q_ipv4.in, f);
    } else{
        /* TODO: Check if there are members subscribed here */
        return pico_enqueue(&S->q_ipv4.out, f);
    }

drop:
    pico_frame_discard(f);
    return -1;
}

static int pico_ipv4_frame_sock_push_ex(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f, uint8_t ip_proto_n)
{
    struct pico_ip4 *dst;
    struct pico_remote_endpoint *remote_endpoint = (struct pico_remote_endpoint *) f->info;
    IGNORE_PARAMETER(self);

    if (!f->sock) {
        pico_frame_discard(f);
        return -1;
    }

    if (remote_endpoint) {
        dst = &remote_endpoint->remote_addr.ip4;
    } else {
        dst = &f->sock->remote_addr.ip4;
    }

    return pico_ipv4_frame_push(S, f, dst, ip_proto_n);
}

static int pico_ipv4_frame_sock_push(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    return pico_ipv4_frame_sock_push_ex(S, self, f, (uint8_t)f->sock->proto->proto_number);
}


int MOCKABLE pico_ipv4_route_add(struct pico_stack *S, struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
    struct pico_ipv4_route test, *new;
    test.dest.addr = address.addr;
    test.netmask.addr = netmask.addr;
    test.metric = (uint32_t)metric;

    if (pico_tree_findKey(&S->Routes, &test)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    new = PICO_ZALLOC(sizeof(struct pico_ipv4_route));
    if (!new) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->dest.addr = address.addr;
    new->netmask.addr = netmask.addr;
    new->gateway.addr = gateway.addr;
    new->metric = (uint32_t)metric;
    if (gateway.addr == 0) {
        /* No gateway provided, use the link */
        new->link = link;
    } else {
        struct pico_ipv4_route *r = route_find(S, &gateway);
        if (!r ) { /* Specified Gateway is unreachable */
            pico_err = PICO_ERR_EHOSTUNREACH;
            PICO_FREE(new);
            return -1;
        }

        if (r->gateway.addr) { /* Specified Gateway is not a neighbor */
            pico_err = PICO_ERR_ENETUNREACH;
            PICO_FREE(new);
            return -1;
        }

        new->link = r->link;
    }

    if (!new->link) {
        pico_err = PICO_ERR_EINVAL;
        PICO_FREE(new);
        return -1;
    }

    if (pico_tree_insert(&S->Routes, new)) {
        dbg("IPv4: Failed to insert route in tree\n");
        PICO_FREE(new);
		return -1;
	}

    dbg_route();
    return 0;
}

int pico_ipv4_route_del(struct pico_stack *S, struct pico_ip4 address, struct pico_ip4 netmask, int metric)
{
    struct pico_ipv4_route test, *found;

    test.dest.addr = address.addr;
    test.netmask.addr = netmask.addr;
    test.metric = (uint32_t)metric;

    found = pico_tree_findKey(&S->Routes, &test);
    if (found) {

        pico_tree_delete(&S->Routes, found);
        PICO_FREE(found);

        dbg_route();
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}


int pico_ipv4_link_add(struct pico_stack *S, struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask)
{
    struct pico_ipv4_link test, *new;
    struct pico_ip4 network, gateway;
    char ipstr[30];

    if (!dev || !dev->stack) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    S = dev->stack;

    test.address.addr = address.addr;
    test.netmask.addr = netmask.addr;
    test.dev = dev;
    /** XXX: Valid netmask / unicast address test **/

    if (pico_tree_findKey(&S->Tree_dev_link, &test)) {
        pico_err = PICO_ERR_EADDRINUSE;
        return -1;
    }

    /** XXX: Check for network already in use (e.g. trying to assign 10.0.0.1/24 where 10.1.0.1/8 is in use) **/
    new = PICO_ZALLOC(sizeof(struct pico_ipv4_link));
    if (!new) {
        dbg("IPv4: Out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->address.addr = address.addr;
    new->netmask.addr = netmask.addr;
    new->dev = dev;
#ifdef PICO_SUPPORT_MCAST
    new->MCASTGroups = PICO_ZALLOC(sizeof(struct pico_tree));
    if (!new->MCASTGroups) {
        PICO_FREE(new);
        dbg("IPv4: Out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->MCASTGroups->root = &LEAF;
    new->MCASTGroups->compare = ipv4_mcast_groups_cmp;
#ifdef PICO_SUPPORT_IGMP
    new->mcast_compatibility = PICO_IGMPV3; /* default RFC 3376 $7.2.1 */
    new->mcast_last_query_interval = PICO_IGMP_QUERY_INTERVAL;
#endif
#endif

    if (pico_tree_insert(&S->Tree_dev_link, new)) {
        dbg("IPv4: Failed to insert link in tree\n");
#ifdef PICO_SUPPORT_MCAST
        PICO_FREE(new->MCASTGroups);
#endif
        PICO_FREE(new);
		return -1;
	}

#ifdef PICO_SUPPORT_MCAST
    do {
        struct pico_ip4 mcast_all_hosts, mcast_addr, mcast_nm, mcast_gw;
        if (!S->ipv4_mcast_default_link) {
            mcast_addr.addr = long_be(0xE0000000); /* 224.0.0.0 */
            mcast_nm.addr = long_be(0xF0000000); /* 15.0.0.0 */
            mcast_gw.addr = long_be(0x00000000);
            S->ipv4_mcast_default_link = new;
            pico_ipv4_route_add(S, mcast_addr, mcast_nm, mcast_gw, 1, new);
        }

        mcast_all_hosts.addr = PICO_MCAST_ALL_HOSTS;
        pico_ipv4_mcast_join(S, &address, &mcast_all_hosts, 1, PICO_IP_MULTICAST_EXCLUDE, NULL);
    } while(0);
#endif

    network.addr = address.addr & netmask.addr;
    gateway.addr = 0U;
    pico_ipv4_route_add(S, network, netmask, gateway, 1, new);
    pico_ipv4_to_string(ipstr, new->address.addr);
    dbg("Assigned ipv4 %s to device %s\n", ipstr, new->dev->name);
    if (S->default_bcast_route->link == NULL)
        S->default_bcast_route->link = new;

    return 0;
}

static int pico_ipv4_cleanup_routes(struct pico_stack *S, struct pico_ipv4_link *link)
{
    struct pico_tree_node *index = NULL, *tmp = NULL;
    struct pico_ipv4_route *route = NULL;

    pico_tree_foreach_safe(index, &S->Routes, tmp) {
        route = index->keyValue;
        if (link == route->link)
            pico_ipv4_route_del(S, route->dest, route->netmask, (int)route->metric);
    }
    return 0;
}

void MOCKABLE pico_ipv4_route_set_bcast_link(struct pico_stack *S, struct pico_ipv4_link *link)
{
    if (link)
        S->default_bcast_route->link = link;
}

int pico_ipv4_link_del(struct pico_stack *S, struct pico_device *dev, struct pico_ip4 address)
{
    struct pico_ipv4_link test, *found;

    if (!dev || !dev->stack) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }


    test.address.addr = address.addr;
    test.dev = dev;
    found = pico_tree_findKey(&S->Tree_dev_link, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return -1;
    }

#ifdef PICO_SUPPORT_MCAST
    do {
        struct pico_ip4 mcast_all_hosts, mcast_addr, mcast_nm;
        struct pico_mcast_group *g = NULL;
        struct pico_tree_node *index, *_tmp;
        if (found == S->ipv4_mcast_default_link) {
            mcast_addr.addr = long_be(0xE0000000); /* 224.0.0.0 */
            mcast_nm.addr = long_be(0xF0000000); /* 15.0.0.0 */
            S->ipv4_mcast_default_link = NULL;
            pico_ipv4_route_del(S, mcast_addr, mcast_nm, 1);
        }

        mcast_all_hosts.addr = PICO_MCAST_ALL_HOSTS;
        pico_ipv4_mcast_leave(S, &address, &mcast_all_hosts, 1, PICO_IP_MULTICAST_EXCLUDE, NULL);
        pico_tree_foreach_safe(index, found->MCASTGroups, _tmp) {
            g = index->keyValue;
            pico_tree_delete(found->MCASTGroups, g);
            PICO_FREE(g);
        }
    } while(0);
    PICO_FREE(found->MCASTGroups);
#endif

    pico_ipv4_cleanup_routes(S, found);
    pico_tree_delete(&S->Tree_dev_link, found);
    if (S->default_bcast_route->link == found)
        S->default_bcast_route->link = NULL;

    PICO_FREE(found);

    return 0;
}

struct pico_ipv4_link *pico_ipv4_link_get(struct pico_stack *S, struct pico_ip4 *address)
{
    struct pico_ipv4_link test = {
        0
    }, *found = NULL;
    test.address.addr = address->addr;

    found = pico_tree_findKey(&S->Tree_dev_link, &test);
    if (!found)
        return NULL;
    else
        return found;
}

struct pico_ipv4_link *MOCKABLE pico_ipv4_link_by_dev(struct pico_stack *S, struct pico_device *dev)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv4_link *link = NULL;

    pico_tree_foreach(index, &S->Tree_dev_link) {
        link = index->keyValue;
        if (link->dev == dev)
            return link;
    }
    return NULL;
}

struct pico_ipv4_link *pico_ipv4_link_by_dev_next(struct pico_stack *S, struct pico_device *dev, struct pico_ipv4_link *last)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv4_link *link = NULL;
    int valid = 0;

    if (last == NULL)
        valid = 1;

    pico_tree_foreach(index, &S->Tree_dev_link) {
        link = index->keyValue;
        if (link->dev == dev) {
            if (last == link)
                valid = 1;
            else if (valid > 0)
                return link;
        }
    }
    return NULL;
}

struct pico_device *MOCKABLE pico_ipv4_link_find(struct pico_stack *S, struct pico_ip4 *address)
{
    struct pico_ipv4_link test, *found;
    if (!address) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    test.dev = NULL;
    test.address.addr = address->addr;
    found = pico_tree_findKey(&S->Tree_dev_link, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return NULL;
    }

    return found->dev;
}


static int pico_ipv4_rebound_large(struct pico_stack *S, struct pico_frame *f)
{
#ifdef PICO_SUPPORT_IPV4FRAG
    uint16_t total_payload_written = 0;
    uint32_t len = f->transport_len;
    struct pico_frame *fr;
    struct pico_ip4 dst;
    struct pico_ipv4_hdr *hdr;
    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    dst.addr = hdr->src.addr;

    while(total_payload_written < len) {
        uint32_t space = (uint32_t)len - total_payload_written;
        if (space > PICO_IPV4_MAXPAYLOAD)
            space = PICO_IPV4_MAXPAYLOAD;

        fr = pico_ipv4_alloc(S, &pico_proto_ipv4, NULL, (uint16_t)space);
        if (!fr) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if (space + total_payload_written < len)
        {
            fr->frag |= PICO_IPV4_MOREFRAG;
        }
        else
        {
            fr->frag &= PICO_IPV4_FRAG_MASK;
        }

        fr->frag = (((total_payload_written) >> 3u) & 0xffffu) | fr->frag;

        memcpy(fr->transport_hdr, f->transport_hdr + total_payload_written, fr->transport_len);
        if (pico_ipv4_frame_push(S, fr, &dst, hdr->proto) > 0) {
            total_payload_written = (uint16_t)((uint16_t)fr->transport_len + total_payload_written);
        } else {
            /* No need to discard frame here, pico_ipv4_frame_push() already did that */
            break;
        }
    } /* while() */
    return (int)total_payload_written;
#else
    (void)f;
    return -1;
#endif
}

int pico_ipv4_rebound(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ip4 dst;
    struct pico_ipv4_hdr *hdr;
    if (!f) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (!hdr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    dst.addr = hdr->src.addr;
    if (f->transport_len > PICO_IPV4_MAXPAYLOAD) {
        return pico_ipv4_rebound_large(S, f);
    }

    return pico_ipv4_frame_push(S, f, &dst, hdr->proto);
}

static int pico_ipv4_pre_forward_checks(struct pico_stack *S, struct pico_frame *f)
{

    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;

    /* Decrease TTL, check if expired */
    hdr->ttl = (uint8_t)(hdr->ttl - 1);
    if (hdr->ttl < 1) {
        pico_notify_ttl_expired(S, f);
        dbg(" ------------------- TTL EXPIRED\n");
        return -1;
    }

    /* HACK: increase crc to compensate decreased TTL */
    hdr->crc++;

    /* If source is local, discard anyway (packets bouncing back and forth) */
    if (pico_ipv4_link_get(S, &hdr->src))
        return -1;

    /* If this was the last forwarded packet, silently discard to prevent duplications */
    if ((S->ipv4_pre_forward_last_src.addr == hdr->src.addr) && (S->ipv4_pre_forward_last_id == hdr->id)
        && (S->ipv4_pre_forward_last_dst.addr == hdr->dst.addr) && (S->ipv4_pre_forward_last_proto == hdr->proto)) {
        return -1;
    } else {
        S->ipv4_pre_forward_last_src.addr = hdr->src.addr;
        S->ipv4_pre_forward_last_dst.addr = hdr->dst.addr;
        S->ipv4_pre_forward_last_id = hdr->id;
        S->ipv4_pre_forward_last_proto = hdr->proto;
    }

    return 0;
}

static int pico_ipv4_forward_check_dev(struct pico_stack *S, struct pico_frame *f)
{
    if (f->dev->eth != NULL)
        f->len -= PICO_SIZE_ETHHDR;

    if (f->len > f->dev->mtu) {
        pico_notify_pkt_too_big(S, f);
        return -1;
    }

    return 0;
}

static int pico_ipv4_forward(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
    struct pico_ipv4_route *rt;
    if (!hdr) {
        return -1;
    }

    rt = route_find(S, &hdr->dst);
    if (!rt) {
        pico_notify_dest_unreachable(S, f);
        return -1;
    }

    f->dev = rt->link->dev;

    if (pico_ipv4_pre_forward_checks(S, f) < 0)
        return -1;

    pico_ipv4_nat_outbound(S, f, &rt->link->address);

    f->start = f->net_hdr;

    if (pico_ipv4_forward_check_dev(S, f) < 0)
        return -1;
#ifdef PICO_SUPPORT_IPFILTER
    if (ipfilter(f)) {
        /*pico_frame is discarded as result of the filtering*/
        return -1;
    }
#endif
    return pico_datalink_send(f);
}

int pico_ipv4_is_broadcast(struct pico_stack *S, uint32_t addr)
{
    struct pico_ipv4_link *link;
    struct pico_tree_node *index;
    if (addr == PICO_IP4_BCAST)
        return 1;

    pico_tree_foreach(index, &S->Tree_dev_link) {
        link = index->keyValue;
        if ((link->address.addr | (~link->netmask.addr)) == addr)
            return 1;
    }
    return 0;
}

void pico_ipv4_unreachable(struct pico_stack *S, struct pico_frame *f, int err)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
#if defined PICO_SUPPORT_TCP || defined PICO_SUPPORT_UDP
    f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR;
    pico_transport_error(S, f, hdr->proto, err);
#endif
}

int pico_ipv4_cleanup_links(struct pico_stack *S, struct pico_device *dev)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv4_link *link = NULL;

    if(!dev || !dev->stack)
        return PICO_ERR_EINVAL;

    pico_tree_foreach_safe(index, &S->Tree_dev_link, _tmp) {
        link = index->keyValue;
        if (dev == link->dev)
            pico_ipv4_link_del(S, dev, link->address);
    }
    return 0;
}

#endif
