/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Daniele Lacamera, Kristof Roelants
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
#include "pico_ipv6.h"
#include "pico_icmp6.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"
#include "pico_fragments.h"
#include "pico_ethernet.h"
#include "pico_6lowpan_ll.h"
#include "pico_mld.h"
#include "pico_mcast.h"
#ifdef PICO_SUPPORT_IPV6


#define PICO_IPV6_EXTHDR_OPT_PAD1 0
#define PICO_IPV6_EXTHDR_OPT_PADN 1
#define PICO_IPV6_EXTHDR_OPT_SRCADDR 201

#define PICO_IPV6_EXTHDR_OPT_ACTION_MASK 0xC0 /* highest-order two bits */
#define PICO_IPV6_EXTHDR_OPT_ACTION_SKIP 0x00 /* skip and continue processing */
#define PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD 0x40 /* discard packet */
#define PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SI 0x80 /* discard and send ICMP parameter problem */
#define PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SINM 0xC0 /* discard and send ICMP parameter problem if not multicast */

#define PICO_IPV6_MAX_RTR_SOLICITATION_DELAY 1000
#define PICO_IPV6_DEFAULT_DAD_RETRANS  1

#ifdef DEBUG_IPV6
#define ipv6_dbg      dbg
#else
#define ipv6_dbg(...) do { } while(0)
#endif

#ifdef PICO_SUPPORT_MCAST

#ifdef DEBUG_MCAST
#define ipv6_mcast_dbg dbg
#else
#define ipv6_mcast_dbg(...) do { } while(0)
#endif

#endif
/* queues */

const uint8_t PICO_IP6_ANY[PICO_SIZE_IP6] = {
    0
};
#ifdef PICO_SUPPORT_MCAST
static int pico_ipv6_mcast_filter(struct pico_stack *S, struct pico_frame *f);
#endif


int pico_ipv6_compare(const struct pico_ip6 *a, const struct pico_ip6 *b)
{
    uint32_t i;
    for (i = 0; i < sizeof(struct pico_ip6); i++) {
        if (a->addr[i] < b->addr[i])
            return -1;

        if (a->addr[i] > b->addr[i])
            return 1;
    }
    return 0;
}

int ipv6_link_compare(void *ka, void *kb)
{
    struct pico_ipv6_link *a = ka, *b = kb;
    struct pico_ip6 *a_addr, *b_addr;
    int ret;
    a_addr = &a->address;
    b_addr = &b->address;

    ret = pico_ipv6_compare(a_addr, b_addr);
    if (ret)
        return ret;

    /* zero can be assigned multiple times (e.g. for DHCP) */
    if (a->dev != NULL && b->dev != NULL && !memcmp(a->address.addr, PICO_IP6_ANY, PICO_SIZE_IP6) && !memcmp(b->address.addr, PICO_IP6_ANY, PICO_SIZE_IP6)) {
        /* XXX change PICO_IP6_ANY */
        if (a->dev < b->dev)
            return -1;

        if (a->dev > b->dev)
            return 1;
    }

    return 0;
}

static inline int ipv6_compare_metric(struct pico_ipv6_route *a, struct pico_ipv6_route *b)
{
    if (a->metric < b->metric)
        return -1;

    if (a->metric > b->metric)
        return 1;

    return 0;
}

int ipv6_route_compare(void *ka, void *kb)
{
    struct pico_ipv6_route *a = ka, *b = kb;
    int ret;

    /* Routes are sorted by (host side) netmask len, then by addr, then by metric. */
    ret = pico_ipv6_compare(&a->netmask, &b->netmask);
    if (ret)
        return ret;

    ret = pico_ipv6_compare(&a->dest, &b->dest);
    if (ret)
        return ret;

    return ipv6_compare_metric(a, b);

}


static char pico_ipv6_dec_to_char(uint8_t u)
{
    if (u < 10)
        return (char)('0' + u);
    else if (u < 16)
        return (char)('a' + (u - 10));
    else
        return '0';
}

static int pico_ipv6_hex_to_dec(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');

    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');

    return 0;
}

int pico_ipv6_to_string(char *ipbuf, const uint8_t ip[PICO_SIZE_IP6])
{
    uint8_t dec = 0, i = 0;

    if (!ipbuf || !ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* every nibble is one char */
    for (i = 0; i < ((uint8_t)PICO_SIZE_IP6) * 2u; ++i) {
        if (i % 4 == 0 && i != 0)
            *ipbuf++ = ':';

        if (i % 2 == 0) { /* upper nibble */
            dec = ip[i / 2] >> 4;
        } else { /* lower nibble */
            dec = ip[i / 2] & 0x0F;
        }

        *ipbuf++ = pico_ipv6_dec_to_char(dec);
    }
    *ipbuf = '\0';

    return 0;
}

int pico_string_to_ipv6(const char *ipstr, uint8_t *ip)
{
    uint8_t buf[PICO_SIZE_IP6] = {
        0
    };
    uint8_t doublecolon = 0, byte = 0;
    char p = 0;
    int i = 0, diff = 0, nibble = 0, hex = 0, colons = 0;
    int zeros = 0, shift = 0;

    pico_err = PICO_ERR_EINVAL;
    if (!ipstr || !ip)
        return -1;

    memset(ip, 0, PICO_SIZE_IP6);

    while((p = *ipstr++) != 0)
    {
        if (pico_is_hex(p) || (p == ':') || *ipstr == '\0') { /* valid signs */
            if (pico_is_hex(p)) {
                buf[byte] = (uint8_t)((buf[byte] << 4) + pico_ipv6_hex_to_dec(p));
                if (++nibble % 2 == 0)
                    ++byte;
            }

            if (p == ':' || *ipstr == '\0') { /* account for leftout leading zeros */
                ++hex;
                if (p == ':')
                    ++colons;

                diff = (hex * 4) - nibble;
                nibble += diff;
                switch (diff) {
                case 0:
                    /* 16-bit hex block ok f.e. 1db8 */
                    break;
                case 1:
                    /* one zero f.e. db8: byte = 1, buf[byte-1] = 0xdb, buf[byte] = 0x08 */
                    buf[byte] |= (uint8_t)(buf[byte - 1] << 4);
                    buf[byte - 1] >>= 4;
                    byte++;
                    break;
                case 2:
                    /* two zeros f.e. b8: byte = 1, buf[byte] = 0x00, buf[byte-1] = 0xb8 */
                    buf[byte] = buf[byte - 1];
                    buf[byte - 1] = 0x00;
                    byte++;
                    break;
                case 3:
                    /* three zeros f.e. 8: byte = 0, buf[byte] = 0x08, buf[byte+1] = 0x00 */
                    buf[byte + 1] = buf[byte];
                    buf[byte] = 0x00;
                    byte = (uint8_t)(byte + 2);
                    break;
                case 4:
                    /* case of :: */
                    if (doublecolon && colons != 2) /* catch case x::x::x but not ::x */
                        return -1;
                    else
                        doublecolon = byte;

                    break;
                default:
                    /* case of missing colons f.e. 20011db8 instead of 2001:1db8 */
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }
    if (colons < 2) /* valid IPv6 has atleast two colons */
        return -1;

    /* account for leftout :: zeros */
    zeros = PICO_SIZE_IP6 - byte;
    if (zeros) {
        shift = PICO_SIZE_IP6 - zeros - doublecolon;
        for (i = shift; i >= 0; --i) {
            /* (i-1) as arrays are indexed from 0 onwards */
            if ((doublecolon + (i - 1)) >= 0)
                buf[doublecolon + zeros + (i - 1)] = buf[doublecolon + (i - 1)];
        }
        memset(&buf[doublecolon], 0, (size_t)zeros);
    }

    memcpy(ip, buf, 16);
    pico_err = PICO_ERR_NOERR;
    return 0;
}

int pico_ipv6_is_linklocal(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: fe80::/10 */
    if ((addr[0] == 0xfe) && ((addr[1] >> 6) == 0x02))
        return 1;

    return 0;
}

int pico_ipv6_is_sitelocal(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: fec0::/10 */
    if ((addr[0] == 0xfe) && ((addr[1] >> 6) == 0x03))
        return 1;

    return 0;
}

int pico_ipv6_is_uniquelocal(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: fc00::/7 */
    if (((addr[0] >> 1) == 0x7e))
        return 1;

    return 0;
}

int pico_ipv6_is_global(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: 2000::/3 */
    if (((addr[0] >> 5) == 0x01))
        return 1;

    return 0;
}

int pico_ipv6_is_localhost(const uint8_t addr[PICO_SIZE_IP6])
{
    const uint8_t localhost[PICO_SIZE_IP6] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    if (memcmp(addr, localhost, PICO_SIZE_IP6) == 0)
        return 1;

    return 0;

}

int pico_ipv6_is_unicast(struct pico_stack *S, struct pico_ip6 *a)
{
    if (pico_ipv6_is_global(a->addr))
        return 1;
    else if (pico_ipv6_is_uniquelocal(a->addr))
        return 1;
    else if (pico_ipv6_is_sitelocal(a->addr))
        return 1;
    else if (pico_ipv6_is_linklocal(a->addr))
        return 1;
    else if (pico_ipv6_is_localhost(a->addr))
        return 1;
    else if(pico_ipv6_link_get(S, a))
        return 1;
    else
        return 0;

}

int pico_ipv6_is_multicast(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: ff00::/8 */
    if ((addr[0] == 0xff))
        return 1;

    return 0;
}

int pico_ipv6_is_allhosts_multicast(const uint8_t addr[PICO_SIZE_IP6])
{
    struct pico_ip6 allhosts = {{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }};
    return !memcmp(allhosts.addr, addr, PICO_SIZE_IP6);
}

int pico_ipv6_is_solicited(const uint8_t addr[PICO_SIZE_IP6])
{
    struct pico_ip6 solicited_node = {{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00 }};
    return !memcmp(solicited_node.addr, addr, 13);
}

int pico_ipv6_is_solnode_multicast(const uint8_t addr[PICO_SIZE_IP6], struct pico_device *dev)
{
    struct pico_ipv6_link *link;
    if (pico_ipv6_is_multicast(addr) == 0)
        return 0;

    link = pico_ipv6_link_by_dev(dev);
    while(link) {
        if (pico_ipv6_is_linklocal(link->address.addr)) {
            int i, match = 0;
            for(i = 13; i < 16; i++) {
                if (addr[i] == link->address.addr[i])
                    ++match;
            }
            /* Solicitation: last 3 bytes match a local address. */
            if (match == 3)
                return 1;
        }

        link = pico_ipv6_link_by_dev_next(dev, link);
    }
    return 0;
}

int pico_ipv6_is_unspecified(const uint8_t addr[PICO_SIZE_IP6])
{
    return !memcmp(PICO_IP6_ANY, addr, PICO_SIZE_IP6);
}

static struct pico_ipv6_route *pico_ipv6_route_find(struct pico_stack *S, const struct pico_ip6 *addr)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_route *r = NULL;
    int i = 0;
    if (!pico_ipv6_is_localhost(addr->addr) && (pico_ipv6_is_linklocal(addr->addr)  || pico_ipv6_is_sitelocal(addr->addr)))    {
        return NULL;
    }

    pico_tree_foreach_reverse(index, &S->IPV6Routes) {
        r = index->keyValue;
        for (i = 0; i < PICO_SIZE_IP6; ++i) {
            if ((addr->addr[i] & (r->netmask.addr[i])) != ((r->dest.addr[i]) & (r->netmask.addr[i]))) {
                break;
            }

            if (i + 1 == PICO_SIZE_IP6) {
                return r;
            }
        }
    }
    return NULL;
}

struct pico_ip6 *pico_ipv6_source_find(struct pico_stack *S, const struct pico_ip6 *dst)
{
    struct pico_ip6 *myself = NULL;
    struct pico_ipv6_route *rt;

    if(!dst) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    rt = pico_ipv6_route_find(S, dst);
    if (rt) {
        myself = &rt->link->address;
    } else
        pico_err = PICO_ERR_EHOSTUNREACH;

    return myself;
}

struct pico_device *pico_ipv6_source_dev_find(struct pico_stack *S, const struct pico_ip6 *dst)
{
    struct pico_device *dev = NULL;
    struct pico_ipv6_route *rt;

    if(!dst) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    rt = pico_ipv6_route_find(S, dst);
    if (rt && rt->link) {
        dev = rt->link->dev;
    } else
        pico_err = PICO_ERR_EHOSTUNREACH;

    return dev;
}

static int pico_ipv6_forward_check_dev(struct pico_stack *S, struct pico_frame *f)
{
    if(f->dev->mode == LL_MODE_ETHERNET && f->dev->eth != NULL)
        f->len -= PICO_SIZE_ETHHDR;

    if(f->len > f->dev->mtu) {
        pico_notify_pkt_too_big(S, f);
        return -1;
    }

    return 0;
}

static int pico_ipv6_pre_forward_checks(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;

    /* Decrease HOP count, check if expired */
    hdr->hop = (uint8_t)(hdr->hop - 1);
    if (hdr->hop < 1) {
        pico_notify_ttl_expired(S, f);
        dbg(" ------------------- HOP COUNT EXPIRED\n");
        return -1;
    }

    /* If source is local, discard anyway (packets bouncing back and forth) */
    if (pico_ipv6_link_get(S, &hdr->src))
        return -1;

    if (pico_ipv6_forward_check_dev(S, f) < 0)
        return -1;

    return 0;
}

static int pico_ipv6_forward(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    struct pico_ipv6_route *rt;
    if (!hdr) {
        pico_frame_discard(f);
        return -1;
    }

    rt = pico_ipv6_route_find(S, &hdr->dst);
    if (!rt) {
        pico_notify_dest_unreachable(S, f);
        pico_frame_discard(f);
        return -1;
    }

    f->dev = rt->link->dev;

    if (pico_ipv6_pre_forward_checks(S, f) < 0)
    {
        pico_frame_discard(f);
        return -1;
    }

    f->start = f->net_hdr;

    return pico_datalink_send(f);
}


static int pico_ipv6_process_hopbyhop(struct pico_ipv6_exthdr *hbh, struct pico_frame *f)
{
    uint8_t *option = NULL;
    uint8_t len = 0, optlen = 0;
    uint32_t ptr = sizeof(struct pico_ipv6_hdr);
    uint8_t *extensions_start = (uint8_t *)hbh;
    uint8_t must_align = 1;
    IGNORE_PARAMETER(f);

    option = ((uint8_t *)&hbh->ext.hopbyhop) + sizeof(struct hopbyhop_s);
    len = (uint8_t)HBH_LEN(hbh);
    ipv6_dbg("IPv6: hop by hop extension header length %u\n", len + 2);
    while (len) {
        switch (*option)
        {
        case PICO_IPV6_EXTHDR_OPT_PAD1:
            ++option;
            --len;
            break;

        case PICO_IPV6_EXTHDR_OPT_PADN:
            optlen = (uint8_t)((*(option + 1)) + 2); /* plus type and len byte */
            if (optlen == 0)
                return -1;
            option += optlen;
            len = (uint8_t)(len - optlen);
            break;
        case PICO_IPV6_EXTHDR_OPT_ROUTER_ALERT:
            optlen = (uint8_t)((*(option + 1)) + 2); /* plus type and len byte */
            /* MLD package */
            if(*(option + 1) == 2)
                must_align = 0;
            if (optlen == 0)
                return -1;
            option += optlen;
            len = (uint8_t)(len - optlen);
            break;
        default:
            /* unknown option */
            optlen = (uint8_t)(*(option + 1) + 2); /* plus type and len byte */
            switch ((*option) & PICO_IPV6_EXTHDR_OPT_ACTION_MASK) {
            case PICO_IPV6_EXTHDR_OPT_ACTION_SKIP:
                break;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD:
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SI:
                pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_IPV6OPT, ptr + (uint32_t)(option - extensions_start));
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SINM:
                if (!pico_ipv6_is_multicast(((struct pico_ipv6_hdr *)(f->net_hdr))->dst.addr))
                    pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_IPV6OPT, ptr + (uint32_t)(option - extensions_start));

                return -1;
            }
            ipv6_dbg("IPv6: option with type %u and length %u\n", *option, optlen);
            option += optlen;
            if (optlen == 0)
                return -1;
            len = (uint8_t)(len - optlen);
        }
    }
    return must_align;
}


static int pico_ipv6_process_routing(struct pico_ipv6_exthdr *routing, struct pico_frame *f, uint32_t ptr)
{
    IGNORE_PARAMETER(f);

    if (routing->ext.routing.segleft == 0)
        return 0;

    ipv6_dbg("IPv6: routing extension header with len %u\n", routing->ext.routing.len + 2);
    switch (routing->ext.routing.routtype) {
    case 0x00:
        /* deprecated */
        pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_HDRFIELD, ptr + 2);
        return -1;
    case 0x02:
        /* routing type for MIPv6: not supported yet */
        break;
    default:
        pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_HDRFIELD, ptr + 2);
        return -1;
    }
    return 0;
}

#define IP6FRAG_MORE(x) ((x & 0x0001))

static int pico_ipv6_process_destopt(struct pico_ipv6_exthdr *destopt, struct pico_frame *f, uint32_t opt_ptr)
{
    uint8_t *option = NULL;
    uint8_t len = 0, optlen = 0;
    opt_ptr += (uint32_t)(2u); /* Skip Dest_opts header */
    IGNORE_PARAMETER(f);
    option = ((uint8_t *)&destopt->ext.destopt) + sizeof(struct destopt_s);
    len = (uint8_t)(((destopt->ext.destopt.len + 1) << 3) - 2); /* len in bytes, minus nxthdr and len byte */
    ipv6_dbg("IPv6: destination option extension header length %u\n", len + 2);
    while (len) {
        optlen = (uint8_t)(*(option + 1) + 2);
        if ((optlen > len) || (optlen == 0))
            return -1;
        switch (*option)
        {
        case PICO_IPV6_EXTHDR_OPT_PAD1:
            break;

        case PICO_IPV6_EXTHDR_OPT_PADN:
            break;

        case PICO_IPV6_EXTHDR_OPT_SRCADDR:
            ipv6_dbg("IPv6: home address option with length %u\n", optlen);
            break;

        default:
            ipv6_dbg("IPv6: option with type %u and length %u\n", *option, optlen);
            switch (*option & PICO_IPV6_EXTHDR_OPT_ACTION_MASK) {
            case PICO_IPV6_EXTHDR_OPT_ACTION_SKIP:
                break;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD:
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SI:
                pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_IPV6OPT, opt_ptr);
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SINM:
                if (!pico_ipv6_is_multicast(((struct pico_ipv6_hdr *)(f->net_hdr))->dst.addr)) {
                    pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_IPV6OPT, opt_ptr);
                }

                return -1;
            }
            break;
        }
        opt_ptr += optlen;
        option += optlen;
        len = (uint8_t)(len - optlen);
    }
    return 0;
}

static int pico_ipv6_check_headers_sequence(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    int ptr = sizeof(struct pico_ipv6_hdr);
    int cur_nexthdr = 6; /* Starts with nexthdr field in ipv6 pkt */
    uint8_t nxthdr = hdr->nxthdr;
    for (;; ) {
        uint8_t optlen = *(f->net_hdr + ptr + 1);
        if (optlen == 0)
            return 0;
        switch (nxthdr) {
        case PICO_IPV6_EXTHDR_DESTOPT:
        case PICO_IPV6_EXTHDR_ROUTING:
        case PICO_IPV6_EXTHDR_HOPBYHOP:
        case PICO_IPV6_EXTHDR_ESP:
        case PICO_IPV6_EXTHDR_AUTH:
            optlen = (uint8_t)IPV6_OPTLEN(optlen);
            if (optlen == 0)
                return -1;
            break;
        case PICO_IPV6_EXTHDR_FRAG:
            optlen = 8;
            break;
        case PICO_IPV6_EXTHDR_NONE:
            return 0;

        case PICO_PROTO_TCP:
        case PICO_PROTO_UDP:
        case PICO_PROTO_ICMP6:
            return 0;
        default:
            /* Invalid next header */
            pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_NXTHDR, (uint32_t)cur_nexthdr);
            return -1;
        }
        cur_nexthdr = ptr;
        nxthdr = *(f->net_hdr + ptr);
        if (optlen == 0)
            return -1;
        ptr += optlen;
    }
}

static int pico_ipv6_check_aligned(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    if ((short_be(hdr->len) % 8) != 0) {
        pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_HDRFIELD, 4);
        return -1;
    }

    return 0;
}

static int pico_ipv6_extension_headers(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    uint8_t nxthdr = hdr->nxthdr;
    struct pico_ipv6_exthdr *exthdr = NULL, *frag_hdr = NULL;
    uint32_t ptr = sizeof(struct pico_ipv6_hdr);
    uint16_t cur_optlen;
    uint32_t cur_nexthdr = 6;
    int must_align = 0;

    f->net_len = sizeof(struct pico_ipv6_hdr);

    if (pico_ipv6_check_headers_sequence(f) < 0)
        return -1;

    for (;; ) {
        exthdr = (struct pico_ipv6_exthdr *)(f->net_hdr + f->net_len);
        cur_optlen = 0;

        switch (nxthdr) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            if (cur_nexthdr != 6) {
                /* The Hop-by-Hop Options header,
                 * when present, must immediately follow the IPv6 header.
                 */
                pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_NXTHDR, cur_nexthdr);
                return -1;
            }

            cur_optlen = IPV6_OPTLEN(exthdr->ext.hopbyhop.len);
            f->net_len = (uint16_t) (f->net_len + cur_optlen);
            must_align = pico_ipv6_process_hopbyhop(exthdr, f);
            if(must_align < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_ROUTING:
            cur_optlen = IPV6_OPTLEN(exthdr->ext.routing.len);
            f->net_len = (uint16_t) (f->net_len + cur_optlen);
            if (pico_ipv6_process_routing(exthdr, f, ptr) < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_FRAG:
            cur_optlen = 8u;
            f->net_len = (uint16_t) (f->net_len + cur_optlen);
            frag_hdr = exthdr;
            f->frag = (uint16_t)((frag_hdr->ext.frag.om[0] << 8) + frag_hdr->ext.frag.om[1]);
            /* If M-Flag is set, and packet is not 8B aligned, discard and alert */
            if (IP6FRAG_MORE(f->frag) && ((short_be(hdr->len) % 8) != 0)) {
                pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_HDRFIELD, 4);
                return -1;
            }

            break;
        case PICO_IPV6_EXTHDR_DESTOPT:
            cur_optlen = IPV6_OPTLEN(exthdr->ext.destopt.len);
            f->net_len = (uint16_t) (f->net_len + cur_optlen);
            must_align = 1;
            if (pico_ipv6_process_destopt(exthdr, f, ptr) < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_ESP:
            /* not supported, ignored. */
            return 0;
        case PICO_IPV6_EXTHDR_AUTH:
            /* not supported, ignored */
            return 0;
        case PICO_IPV6_EXTHDR_NONE:
            /* no next header */
            if (must_align && (pico_ipv6_check_aligned(f) < 0))
                return -1;

            return 0;

        case PICO_PROTO_TCP:
        case PICO_PROTO_UDP:
        case PICO_PROTO_ICMP6:
            if (must_align && (pico_ipv6_check_aligned(f) < 0))
                return -1;

            f->transport_hdr = f->net_hdr + f->net_len;
            f->transport_len = (uint16_t)(short_be(hdr->len) - (f->net_len - sizeof(struct pico_ipv6_hdr)));
            if ((f->transport_hdr + f->transport_len) > (f->buffer + f->buffer_len))
                return -1;
            if (frag_hdr) {
#ifdef PICO_SUPPORT_IPV6FRAG
                pico_ipv6_process_frag(frag_hdr, f, nxthdr);
#endif
                return -1;
            } else {
                return nxthdr;
            }

        default:
            /* Invalid next header */
            pico_icmp6_parameter_problem(f->dev->stack, f, PICO_ICMP6_PARAMPROB_NXTHDR, cur_nexthdr);
            return -1;
        }
        nxthdr = exthdr->nxthdr;
        cur_nexthdr = ptr;
        ptr += cur_optlen;
    }
}
static int pico_ipv6_process_mcast_in(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    struct pico_ipv6_exthdr *hbh = NULL;
    if (pico_ipv6_is_multicast(hdr->dst.addr)) {
#ifdef PICO_SUPPORT_MCAST
        /* Receiving UDP multicast datagram TODO set f->flags? */
        if(hdr->nxthdr == 0) {
            hbh = (struct pico_ipv6_exthdr *) (f->transport_hdr);
        }

        if (hdr->nxthdr == PICO_PROTO_ICMP6 || (hbh != NULL && hbh->nxthdr == PICO_PROTO_ICMP6)) {
            pico_transport_receive(f, PICO_PROTO_ICMP6);
            return 1;
        } else if ((pico_ipv6_mcast_filter(f->dev->stack, f) == 0) && (hdr->nxthdr == PICO_PROTO_UDP)) {
            pico_enqueue(pico_proto_udp.q_in, f);
            return 1;
        }

#else
        IGNORE_PARAMETER(hbh);
#endif
        pico_frame_discard(f);
        return 1;
    }

    return 0;
}
static int pico_ipv6_process_in(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    int proto = 0;
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    struct pico_ipv6_exthdr *hbh;
    IGNORE_PARAMETER(self);
    /* forward if not local, except if router alert is set */
    if (pico_ipv6_is_unicast(S, &hdr->dst) && !pico_ipv6_link_get(S, &hdr->dst)) {
        if(hdr->nxthdr == 0) {
            hbh = (struct pico_ipv6_exthdr *) f->transport_hdr;
            if(hbh->ext.routing.routtype == 0 &&
                hbh->ext.routing.segleft != 0)
                return pico_ipv6_forward(S, f);
        } else
            /* not local, try to forward. */
            return pico_ipv6_forward(S,f);
    }

    proto = pico_ipv6_extension_headers(f);
    if (proto <= 0) {
        pico_frame_discard(f);
        return 0;
    }

    f->proto = (uint8_t)proto;
    ipv6_dbg("IPv6: payload %u net_len %u nxthdr %u\n", short_be(hdr->len), f->net_len, proto);

    if (pico_ipv6_is_unicast(S, &hdr->dst)) {
        pico_transport_receive(f, f->proto);
    } else if (pico_ipv6_is_multicast(hdr->dst.addr)) {
        /* XXX perform multicast filtering: solicited-node multicast address MUST BE allowed! */
        if (pico_ipv6_process_mcast_in(f) > 0)
            return 0;

        pico_transport_receive(f, f->proto);
    }

    return 0;
}

static int pico_ipv6_process_out(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(S);

    f->start = (uint8_t*)f->net_hdr;

    return pico_datalink_send(f);
}

/* allocates an IPv6 packet without extension headers. If extension headers are needed,
 * include the len of the extension headers in the size parameter. Once a frame acquired
 * increment net_len and transport_hdr with the len of the extension headers, decrement
 * transport_len with this value.
 */
static struct pico_frame *pico_ipv6_alloc(struct pico_stack *S, struct pico_protocol *self, struct pico_device *dev, uint16_t size)
{
    struct pico_frame *f = NULL;

    IGNORE_PARAMETER(self);

    if (0) {}
#ifdef PICO_SUPPORT_6LOWPAN
    else if (PICO_DEV_IS_6LOWPAN(dev)) {
        f = pico_proto_6lowpan_ll.alloc(S, &pico_proto_6lowpan_ll, dev, (uint16_t)(size + PICO_SIZE_IP6HDR));
    }
#endif
    else {
#ifdef PICO_SUPPORT_ETH
        f = pico_proto_ethernet.alloc(S, &pico_proto_ethernet, dev, (uint16_t)(size + PICO_SIZE_IP6HDR));
#else
        f = pico_frame_alloc(size + PICO_SIZE_IP6HDR + PICO_SIZE_ETHHDR);
#endif
    }

    if (!f)
        return NULL;

    f->net_len = PICO_SIZE_IP6HDR;
    f->transport_hdr = f->net_hdr + PICO_SIZE_IP6HDR;
    f->transport_len = (uint16_t)size;

    /* Datalink size is accounted for in pico_datalink_send (link layer) */
    f->len =  (uint32_t)(size + PICO_SIZE_IP6HDR);

    return f;
}

static inline int ipv6_pushed_frame_valid(struct pico_frame *f, struct pico_ip6 *dst)
{
    struct pico_ipv6_hdr *hdr = NULL;
    if(!f || !dst)
        return -1;

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    if (!hdr) {
        dbg("IPv6: IP header error\n");
        return -1;
    }

    return 0;
}
int pico_ipv6_is_null_address(struct pico_ip6 *ip6)
{
    struct pico_ip6 null_addr = {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    return !memcmp(ip6, &null_addr, sizeof(struct pico_ip6));
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
static int ipv6_mcast_groups_cmp(void *ka, void *kb)
{
    struct pico_mcast_group *a = ka, *b = kb;
    return pico_ipv6_compare(&a->mcast_addr.ip6, &b->mcast_addr.ip6);
}
static int ipv6_mcast_sources_cmp(void *ka, void *kb)
{
    struct pico_ip6 *a = ka, *b = kb;
    return pico_ipv6_compare(a, b);
}

static void pico_ipv6_mcast_print_groups(struct pico_ipv6_link *mcast_link)
{
#ifdef PICO_DEBUG_MULTICAST
    uint16_t i = 0;
    struct pico_mcast_group *g = NULL;
    struct pico_ip6 *source = NULL;
    struct pico_tree_node *index = NULL, *index2 = NULL;
    char *ipv6_addr;
    (void) source;
    ipv6_mcast_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    ipv6_mcast_dbg("+                           MULTICAST list interface %-16s             +\n", mcast_link->dev->name);
    ipv6_mcast_dbg("+------------------------------------------------------------------------------------------+\n");
    ipv6_mcast_dbg("+  nr  |    interface     |                   host group | reference count | filter mode |  source  +\n");
    ipv6_mcast_dbg("+------------------------------------------------------------------------------------------+\n");
    ipv6_addr = PICO_ZALLOC(PICO_IPV6_STRING);
    pico_tree_foreach(index, mcast_link->MCASTGroups) {
        g = index->keyValue;
        pico_ipv6_to_string(ipv6_addr, &g->mcast_addr.addr[0]);
        ipv6_mcast_dbg("+ %04d | %16s |  %s  |      %05u      |      %u      | %8s +\n", i, mcast_link->dev->name, ipv6_addr, g->reference_count, g->filter_mode, "");
        pico_tree_foreach(index2, &g->MCASTSources) {
            source = index2->keyValue;
            pico_ipv6_to_string(ipv6_addr, source->addr);
            ipv6_mcast_dbg("+ %4s | %16s |  %8s  |      %5s      |      %s      | %s +\n", "", "", "", "", "", ipv6_addr);
        }
        i++;
    }
    PICO_FREE(ipv6_addr);
    ipv6_mcast_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
#else
    IGNORE_PARAMETER(mcast_link);
#endif

}

static int mcast_group_update_ipv6(struct pico_mcast_group *g, struct pico_tree *_MCASTFilter, uint8_t filter_mode)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ip6 *source = NULL;
    /* cleanup filter */
    pico_tree_foreach_safe(index, &g->MCASTSources, _tmp) {
        source = index->keyValue;
        pico_tree_delete(&g->MCASTSources, source);
        PICO_FREE(source);
    }
    /* insert new filter */
    if (_MCASTFilter) {
        pico_tree_foreach(index, _MCASTFilter) {
            if (index->keyValue) {
                source = PICO_ZALLOC(sizeof(struct pico_ip6));
                if (!source) {
                    pico_err = PICO_ERR_ENOMEM;
                    return -1;
                }
                *source = *((struct pico_ip6 *)index->keyValue);
                if (pico_tree_insert(&g->MCASTSources, source)) {
                    ipv6_mcast_dbg("IPv6 MCAST: Failed to insert source in tree\n");
                    PICO_FREE(source);
                    return -1;
                }
            }
        }
    }
    g->filter_mode = filter_mode;
    return 0;
}

int pico_ipv6_mcast_join(struct pico_stack *S, struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *_MCASTFilter)
{
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv6_link *link = NULL;
    int res = -1;
    if (mcast_link) {
        link = pico_ipv6_link_get(S, mcast_link);
    }

    if (!link) {
        link = S->ipv6_mcast_default_link;
    }

    test.mcast_addr.ip6 = *mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (g) {
        if (reference_count)
            g->reference_count++;

#ifdef PICO_SUPPORT_MLD
        res = pico_mld_state_change(S, mcast_link, mcast_group, filter_mode, _MCASTFilter, PICO_MLD_STATE_UPDATE);
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
        g->mcast_addr.ip6 = *mcast_group;
        g->MCASTSources.root = &LEAF;
        g->MCASTSources.compare = ipv6_mcast_sources_cmp;
        if (pico_tree_insert(link->MCASTGroups, g)) {
            ipv6_mcast_dbg("IPv6 MCAST: Failed to insert group in tree\n");
            PICO_FREE(g);
			return -1;
		}

#ifdef PICO_SUPPORT_MLD
        res = pico_mld_state_change(S, mcast_link, mcast_group, filter_mode, _MCASTFilter, PICO_MLD_STATE_CREATE);
#endif
    }

    if (mcast_group_update_ipv6(g, _MCASTFilter, filter_mode) < 0) {
        dbg("Error in mcast_group update\n");
        return -1;
    }

    pico_ipv6_mcast_print_groups(link);
    return res;
}

int pico_ipv6_mcast_leave(struct pico_stack *S, struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *_MCASTFilter)
{
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv6_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ip6 *source = NULL;
    int res = -1;
    if (mcast_link)
        link = pico_ipv6_link_get(S, mcast_link);

    if (!link)
        link = S->ipv6_mcast_default_link;

    test.mcast_addr.ip6 = *mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (!g) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (reference_count && (--(g->reference_count) < 1)) {
#ifdef PICO_SUPPORT_MLD
            res = pico_mld_state_change(S, mcast_link, mcast_group, filter_mode, _MCASTFilter, PICO_MLD_STATE_DELETE);
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
#ifdef PICO_SUPPORT_MLD
            res = pico_mld_state_change(S, mcast_link, mcast_group, filter_mode, _MCASTFilter, PICO_MLD_STATE_UPDATE);
#endif
            if (mcast_group_update_ipv6(g, _MCASTFilter, filter_mode) < 0)
                return -1;
        }
    }

    pico_ipv6_mcast_print_groups(link);
    return res;
}

struct pico_ipv6_link *pico_ipv6_get_default_mcastlink(struct pico_stack *S)
{
    return S->ipv6_mcast_default_link;
}

static int pico_ipv6_mcast_filter(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv6_link *link = NULL;
    struct pico_tree_node *index = NULL, *index2 = NULL;
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *) f->net_hdr;
#ifdef PICO_DEBUG_MULTICAST
    char ipv6_addr[PICO_IPV6_STRING];
#endif
    test.mcast_addr.ip6 = hdr->dst;

    pico_tree_foreach(index, &S->Tree_dev_ip6_link) {
        link = index->keyValue;
        g = pico_tree_findKey(link->MCASTGroups, &test);
        if (g) {
            if (f->dev == link->dev) {
#ifdef PICO_DEBUG_MULTICAST
                pico_ipv6_to_string( ipv6_addr, &hdr->dst.addr[0]);
                ipv6_mcast_dbg("MCAST: IP %s is group member of current link %s\n", ipv6_addr, f->dev->name);
#endif
                /* perform source filtering */
                switch (g->filter_mode) {
                case PICO_IP_MULTICAST_INCLUDE:
                    pico_tree_foreach(index2, &g->MCASTSources) {
                        if (hdr->src.addr == ((struct pico_ip6 *)index2->keyValue)->addr) {
#ifdef PICO_DEBUG_MULTICAST
                            pico_ipv6_to_string(ipv6_addr, &hdr->src.addr[0]);
                            ipv6_mcast_dbg("MCAST: IP %s in included interface source list\n", ipv6_addr);
#endif
                            return 0;
                        }
                    }
#ifdef PICO_DEBUG_MULTICAST
                    pico_ipv6_to_string(ipv6_addr, &hdr->src.addr[0]);
                    ipv6_mcast_dbg("MCAST: IP %s NOT in included interface source list\n", ipv6_addr);
#endif
                    return -1;

                case PICO_IP_MULTICAST_EXCLUDE:
                    pico_tree_foreach(index2, &g->MCASTSources) {
                        if (memcmp(hdr->src.addr, (((struct pico_ip6 *)index2->keyValue)->addr), sizeof(struct pico_ip6)) == 0) {
#ifdef PICO_DEBUG_MULTICAST
                            pico_ipv6_to_string(ipv6_addr, &hdr->src.addr[0]);
                            ipv6_mcast_dbg("MCAST: IP %s in excluded interface source list\n", ipv6_addr);
#endif
                            return -1;
                        }
                    }
#ifdef PICO_DEBUG_MULTICAST
                    pico_ipv6_to_string(ipv6_addr, &hdr->src.addr[0]);
                    ipv6_mcast_dbg("MCAST: IP %s NOT in excluded interface source list\n", ipv6_addr);
#endif
                    return 0;

                default:
                    return -1;
                }
            } else {
#ifdef PICO_DEBUG_MULTICAST
                pico_ipv6_to_string(ipv6_addr, &hdr->dst.addr[0]);
                ipv6_mcast_dbg("MCAST: IP %s is group member of different link %s\n", ipv6_addr, link->dev->name);
#endif
            }
        } else {
#ifdef PICO_DEBUG_MULTICAST
            pico_ipv6_to_string(ipv6_addr, &hdr->dst.addr[0]);
            ipv6_mcast_dbg("MCAST: IP %s is not a group member of link %s\n", ipv6_addr, f->dev->name);
#endif
        }
    }
    return -1;
}

#else

int pico_ipv6_mcast_join(struct pico_stack *S, struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *_MCASTFilter)
{
    IGNORE_PARAMETER(S);
    IGNORE_PARAMETER(mcast_link);
    IGNORE_PARAMETER(mcast_group);
    IGNORE_PARAMETER(reference_count);
    IGNORE_PARAMETER(filter_mode);
    IGNORE_PARAMETER(_MCASTFilter);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_ipv6_mcast_leave(struct pico_stack *S, struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *_MCASTFilter)
{
    IGNORE_PARAMETER(S);
    IGNORE_PARAMETER(mcast_link);
    IGNORE_PARAMETER(mcast_group);
    IGNORE_PARAMETER(reference_count);
    IGNORE_PARAMETER(filter_mode);
    IGNORE_PARAMETER(_MCASTFilter);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

struct pico_ipv6_link *pico_ipv6_get_default_mcastlink(struct pico_stack *S)
{
    IGNORE_PARAMETER(S);
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return NULL;
}
#endif /* PICO_SUPPORT_MCAST */
static inline struct pico_ipv6_route *ipv6_pushed_frame_checks(struct pico_stack *S, struct pico_frame *f, struct pico_ip6 *dst)
{
    struct pico_ipv6_route *route = NULL;

    if (ipv6_pushed_frame_valid(f, dst) < 0)
        return NULL;

    if (memcmp(dst->addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0) {
        dbg("IPv6: IP destination address error\n");
        return NULL;
    }

    route = pico_ipv6_route_find(S, dst);
    if (!route && !f->dev) {
        dbg("IPv6: route not found.\n");
        pico_err = PICO_ERR_EHOSTUNREACH;
        return NULL;
    }

    return route;
}

static inline void ipv6_push_hdr_adjust(struct pico_stack *S, struct pico_frame *f, struct pico_ipv6_link *link, struct pico_ip6 *src, struct pico_ip6 *dst,  uint8_t proto, int is_dad)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_hdr *hdr = NULL;
    struct pico_ipv6_exthdr *hbh = NULL;
    const uint8_t vtf = (uint8_t)long_be(0x60000000); /* version 6, traffic class 0, flow label 0 */

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    hdr->vtf = vtf;
    hdr->len = short_be((uint16_t)(f->transport_len + f->net_len - (uint16_t)sizeof(struct pico_ipv6_hdr)));
    hdr->nxthdr = proto;
    hdr->hop = f->dev->hostvars.hoplimit;
    hdr->dst = *dst;

    if (!src || !pico_ipv6_is_unicast(S, src))
        /* Address defaults to the link information: src address selection is done via link */
        hdr->src = link->address;
    else {
        /* Sender protocol is forcing an IPv6 address */
        hdr->src = *src;
    }
    if (f->send_ttl) {
        hdr->hop = f->send_ttl;
    }

    if (f->send_tos) {
        hdr->vtf |= ((uint32_t)f->send_tos << 20u);
    }

    /* make adjustments to defaults according to proto */
    switch (proto)
    {
#ifdef PICO_SUPPORT_MLD
    case 0:
    {
        hbh = (struct pico_ipv6_exthdr *) f->transport_hdr;
        switch(hbh->nxthdr) {
        case PICO_PROTO_ICMP6:
        {
            icmp6_hdr = (struct pico_icmp6_hdr *)(f->transport_hdr + sizeof(struct pico_ipv6_exthdr));
            if((icmp6_hdr->type >= PICO_MLD_QUERY && icmp6_hdr->type <= PICO_MLD_DONE) || icmp6_hdr->type == PICO_MLD_REPORTV2) {
                hdr->hop = 1;
            }

            icmp6_hdr->crc = 0;
            icmp6_hdr->crc = short_be(pico_mld_checksum(f));
            break;
        }
        }
        break;
    }
#else
        IGNORE_PARAMETER(hbh);
#endif
    case PICO_IPV6_EXTHDR_FRAG:
    {
        break;
    }
    case PICO_PROTO_ICMP6:
    {
        icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
        if (icmp6_hdr->type == PICO_ICMP6_NEIGH_SOL || icmp6_hdr->type == PICO_ICMP6_NEIGH_ADV || icmp6_hdr->type == PICO_ICMP6_ROUTER_SOL || icmp6_hdr->type == PICO_ICMP6_ROUTER_ADV)
            hdr->hop = 255;

        /* RFC6775 $5.5.1:
         *  ... An unspecified source address MUST NOT be used in NS messages.
         */
        if (f->dev->mode == LL_MODE_ETHERNET && (is_dad || link->istentative) && (icmp6_hdr->type == PICO_ICMP6_NEIGH_SOL || icmp6_hdr->type == PICO_ICMP6_ROUTER_SOL)) {
           memcpy(hdr->src.addr, PICO_IP6_ANY, PICO_SIZE_IP6);
        }


        icmp6_hdr->crc = 0;
        icmp6_hdr->crc = short_be(pico_icmp6_checksum(f));
        break;
    }
#ifdef PICO_SUPPORT_UDP
    case PICO_PROTO_UDP:
    {
        struct pico_udp_hdr *udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
        udp_hdr->crc = short_be(pico_udp_checksum_ipv6(f));
        break;
    }
#endif

    default:
        break;
    }

}

static int ipv6_frame_push_final(struct pico_stack *S, struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    if(pico_ipv6_link_get(S, &hdr->dst)) {
        return pico_enqueue(&S->q_ipv6.in, f);
    }
    else {
        return pico_enqueue(&S->q_ipv6.out, f);
    }
}

struct pico_ipv6_link *pico_ipv6_linklocal_get(struct pico_device *dev);

int pico_ipv6_frame_push(struct pico_stack *S, struct pico_frame *f, struct pico_ip6 *src, struct pico_ip6 *dst, uint8_t proto, int is_dad)
{
    struct pico_ipv6_route *route = NULL;
    struct pico_ipv6_link *link = NULL;

    if (dst && (pico_ipv6_is_linklocal(dst->addr) ||  pico_ipv6_is_multicast(dst->addr) || pico_ipv6_is_sitelocal(dst->addr))) {
        if (!f->dev) {
            pico_frame_discard(f);
            return -1;
        }

        if (pico_ipv6_is_sitelocal(dst->addr))
            link = pico_ipv6_sitelocal_get(f->dev);
        else
            link = pico_ipv6_linklocal_get(f->dev);

        if (link)
            goto push_final;
    }

    if (dst && pico_ipv6_is_localhost(dst->addr)) {
        f->dev = pico_get_device(S, "loop");
    }

    route = ipv6_pushed_frame_checks(S, f, dst);
    if (!route) {
        pico_frame_discard(f);
        return -1;
    }

    link = route->link;

    if (f->sock && f->sock->dev)
        f->dev = f->sock->dev;
    else {
        f->dev = link->dev;
        if (f->sock)
            f->sock->dev = f->dev;
    }


    #if 0
    if (pico_ipv6_is_multicast(hdr->dst.addr)) {
        /* XXX: reimplement loopback */
    }

    #endif

push_final:
    ipv6_push_hdr_adjust(S, f, link, src, dst, proto, is_dad);
    return ipv6_frame_push_final(S, f);
}

static int pico_ipv6_frame_sock_push(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_ip6 *dst = NULL;
    struct pico_remote_endpoint *remote_endpoint = NULL;

    IGNORE_PARAMETER(self);

    if (!f->sock) {
        pico_frame_discard(f);
        return -1;
    }

    remote_endpoint = (struct pico_remote_endpoint *)f->info;
    if (remote_endpoint) {
        dst = &remote_endpoint->remote_addr.ip6;
    } else {
        dst = &f->sock->remote_addr.ip6;
    }

    return pico_ipv6_frame_push(S, f, NULL, dst, (uint8_t)f->sock->proto->proto_number, 0);
}

/* interface: protocol definition */
struct pico_protocol pico_proto_ipv6 = {
    .name = "ipv6",
    .proto_number = PICO_PROTO_IPV6,
    .layer = PICO_LAYER_NETWORK,
    .alloc = pico_ipv6_alloc,
    .process_in = pico_ipv6_process_in,
    .process_out = pico_ipv6_process_out,
    .push = pico_ipv6_frame_sock_push,
};

#ifdef DEBUG_IPV6_ROUTE
static void pico_ipv6_dbg_route(void)
{
    struct pico_ipv6_route *r;
    struct pico_tree_node *index;
    char ipv6_addr[PICO_IPV6_STRING];
    char netmask_addr[PICO_IPV6_STRING];
    char gateway_addr[PICO_IPV6_STRING];

    pico_tree_foreach(index, &Routes){
        r = index->keyValue;
        pico_ipv6_to_string(ipv6_addr, r->dest.addr);
        pico_ipv6_to_string(netmask_addr, r->netmask.addr);
        pico_ipv6_to_string(gateway_addr, r->gateway.addr);
        dbg("Route to %s/%s, gw %s, dev: %s, metric: %d\n", ipv6_addr, netmask_addr, gateway_addr, r->link->dev->name, r->metric);
    }
}
#else
#define pico_ipv6_dbg_route() do { } while(0)
#endif

static inline struct pico_ipv6_route *ipv6_route_add_link(struct pico_stack *S, struct pico_ip6 gateway)
{
    struct pico_ip6 zerogateway = {{0}};
    struct pico_ipv6_route *r = pico_ipv6_route_find(S, &gateway);

    if (!r) { /* Specified Gateway is unreachable */
        pico_err = PICO_ERR_EHOSTUNREACH;
        return NULL;
    }

    if (memcmp(r->gateway.addr, zerogateway.addr, PICO_SIZE_IP6) != 0) { /* Specified Gateway is not a neighbor */
        pico_err = PICO_ERR_ENETUNREACH;
        return NULL;
    }

    return r;
}

struct pico_ipv6_route *pico_ipv6_gateway_by_dev(struct pico_stack *S, struct pico_device *dev)
{
    struct pico_ipv6_link *link = pico_ipv6_link_by_dev(dev);
    struct pico_ipv6_route *route = NULL;
    struct pico_tree_node *node = NULL;

    /* Iterate over the IPv6-routes */
    pico_tree_foreach(node, &S->IPV6Routes) {
        route = (struct pico_ipv6_route *)node->keyValue;
        /* If the route is a default router, specified by the gw being set */
        if (!pico_ipv6_is_unspecified(route->gateway.addr) && pico_ipv6_is_unspecified(route->netmask.addr)) {
            /* Iterate over device's links */
            while (link) {
                /* If link is equal to route's link, router list is not empty */
                if (0 == ipv6_link_compare(link, route->link))
                    return route;
                link = pico_ipv6_link_by_dev_next(dev, link);
            }
        }
    }

    return NULL;
}

struct pico_ipv6_route *pico_ipv6_gateway_by_dev_next(struct pico_stack *S, struct pico_device *dev, struct pico_ipv6_route *last)
{
    struct pico_ipv6_link *link = NULL;
    struct pico_ipv6_route *gw = NULL;
    struct pico_tree_node *i = NULL;
    int valid = 0;

    if (last == NULL)
        valid = 1;

    pico_tree_foreach(i, &S->IPV6Routes) {
        gw = (struct pico_ipv6_route *)i->keyValue;
        /* If the route is a default router, specified by the gw being set */
        if (!pico_ipv6_is_unspecified(gw->gateway.addr) && pico_ipv6_is_unspecified(gw->netmask.addr)) {
            /* Iterate over device's links */
            link = pico_ipv6_link_by_dev(dev);
            while (link) {
                /* If link is equal to route's link, routing list is not empty */
                if (0 == ipv6_link_compare(link, gw->link)) {
                    if (last == gw) {
                        valid = 1;
                    } else if (valid) {
                        return gw;
                    }
                    link = pico_ipv6_link_by_dev_next(dev, link);
                }
            }
        }
    }
    return NULL;
}

int pico_ipv6_route_add(struct pico_stack *S, struct pico_ip6 address, struct pico_ip6 netmask, struct pico_ip6 gateway, int metric, struct pico_ipv6_link *link)
{
    struct pico_ip6 zerogateway = {{0}};
    struct pico_ipv6_route test, *new = NULL;
    test.dest = address;
    test.netmask = netmask;
    test.metric = (uint32_t)metric;
    if (pico_tree_findKey(&S->IPV6Routes, &test)) {
        /* Route already exists */
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    new = PICO_ZALLOC(sizeof(struct pico_ipv6_route));
    if (!new) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ipv6_dbg("Adding IPV6 static route\n");
    new->dest = address;
    new->netmask = netmask;
    new->gateway = gateway;
    new->metric = (uint32_t)metric;
    if (memcmp(gateway.addr, zerogateway.addr, PICO_SIZE_IP6) == 0) {
        /* No gateway provided, use the link */
        new->link = link;
    } else {
        struct pico_ipv6_route *r = ipv6_route_add_link(S, gateway);
        if (!r) {
            if (link)
                new->link = link;
            else {
                PICO_FREE(new);
                return -1;
            }
        } else {
            new->link = r->link;
        }
    }

    if (new->link && (pico_ipv6_is_global(address.addr)) && (!pico_ipv6_is_global(new->link->address.addr))) {
        new->link = pico_ipv6_global_get(new->link->dev);
    }

    if (!new->link) {
        pico_err = PICO_ERR_EINVAL;
        PICO_FREE(new);
        return -1;
    }

    if (pico_tree_insert(&S->IPV6Routes, new)) {
        ipv6_dbg("IPv6: Failed to insert route in tree\n");
        PICO_FREE(new);
		return -1;
	}

    pico_ipv6_dbg_route();
    return 0;
}

int pico_ipv6_route_del(struct pico_stack *S, struct pico_ip6 address, struct pico_ip6 netmask, struct pico_ip6 gateway, int metric, struct pico_ipv6_link *link)
{
    struct pico_ipv6_route test, *found = NULL;

    IGNORE_PARAMETER(gateway);

    if (!link) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.dest = address;
    test.netmask = netmask;
    test.metric = (uint32_t)metric;

    found = pico_tree_findKey(&S->IPV6Routes, &test);
    if (found) {
        pico_tree_delete(&S->IPV6Routes, found);
        PICO_FREE(found);
        pico_ipv6_dbg_route();
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}

void pico_ipv6_router_down(struct pico_stack *S, const struct pico_ip6 *address)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv6_route *route = NULL;
    if (!address)
        return;

    pico_tree_foreach_safe(index, &S->IPV6Routes, _tmp)
    {
        route = index->keyValue;
        if (pico_ipv6_compare(address, &route->gateway) == 0) {
            if (pico_ipv6_route_del(S, route->dest, route->netmask, route->gateway, (int)route->metric, route->link) != 0) {
                dbg("Route del FAILED\n");
            }
        }
    }
}

#ifndef UNIT_TEST
static void pico_ipv6_nd_dad(pico_time now, void *arg)
{
    struct pico_ipv6_link *l, *info = (struct pico_ipv6_link *)arg;
    struct pico_ip6 old_address;
    if (!arg)
        return;

    IGNORE_PARAMETER(now);

    l = pico_ipv6_link_istentative(info->dev->stack, &info->address);
    if (!l)
        return;

    if (pico_device_link_state(l->dev) == 0) {
        l->dad_timer = pico_timer_add(l->dev->stack, 100, pico_ipv6_nd_dad, &l);
        if (!l->dad_timer) {
            dbg("IPv6: Failed to start nd_dad timer\n");
            /* TODO does this have disastrous consequences? */
        }
        return;
    }

    if (l->isduplicate) {
        dbg("IPv6: duplicate address.\n");
        old_address = info->address;
        if (pico_ipv6_is_linklocal(info->address.addr)) {
            info->address.addr[8] = (uint8_t)((uint8_t)(pico_rand() & 0xff) & (uint8_t)(~0x03));
            info->address.addr[9] = pico_rand() & 0xff;
            info->address.addr[10] = pico_rand() & 0xff;
            info->address.addr[11] = pico_rand() & 0xff;
            info->address.addr[12] = pico_rand() & 0xff;
            info->address.addr[13] = pico_rand() & 0xff;
            info->address.addr[14] = pico_rand() & 0xff;
            info->address.addr[15] = pico_rand() & 0xff;
            pico_ipv6_link_add(l->dev, info->address, l->netmask);
        }

        pico_ipv6_link_del(info->dev->stack, l->dev, old_address);
    }
    else {
        if (l->dup_detect_retrans-- == 0) {
            dbg("IPv6: DAD verified valid address.\n");

            l->istentative = 0;
        } else {
            /* Duplicate Address Detection */
            pico_icmp6_neighbor_solicitation(l->dev, &l->address, PICO_ICMP6_ND_DAD, NULL);
            l->dad_timer = pico_timer_add(l->dev->stack, PICO_ICMP6_MAX_RTR_SOL_DELAY, pico_ipv6_nd_dad, l);
            if (!l->dad_timer) {
                dbg("IPv6: Failed to start nd_dad timer\n");
                /* TODO does this have disastrous consequences? */
            }
        }
    }
}
#endif

static struct pico_ipv6_link *pico_ipv6_do_link_add(struct pico_device *dev, struct pico_ip6 address, struct pico_ip6 netmask)
{
    struct pico_ipv6_link test = {
        0
    }, *new = NULL;
    struct pico_ip6 network = {{0}}, gateway = {{0}};
    struct pico_ip6 mcast_addr = {{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    struct pico_ip6 mcast_nm = {{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    struct pico_ip6 mcast_gw = {{0}};
    struct pico_ip6 all_hosts = {{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }};
    int i = 0;
    if (!dev) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    test.address = address;
    test.dev = dev;
    /** XXX: Valid netmask / unicast address test **/

    if (pico_tree_findKey(&dev->stack->IPV6Links, &test)) {
        dbg("IPv6: trying to assign an invalid address (in use)\n");
        pico_err = PICO_ERR_EADDRINUSE;
        return NULL;
    }

    /** XXX: Check for network already in use (e.g. trying to assign 10.0.0.1/24 where 10.1.0.1/8 is in use) **/
    new = PICO_ZALLOC(sizeof(struct pico_ipv6_link));
    if (!new) {
        dbg("IPv6: out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    new->address = address;
    new->netmask = netmask;
    new->dev = dev;
    new->istentative = 1;
    new->isduplicate = 0;
    new->rs_retries = 0;
    new->rs_expire_time = PICO_TIME_MS() + pico_rand() % 1000;
#ifdef PICO_SUPPORT_MCAST
    new->MCASTGroups = PICO_ZALLOC(sizeof(struct pico_tree));
    if (!new->MCASTGroups) {
        PICO_FREE(new);
        dbg("IPv6: Out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    new->MCASTGroups->root = &LEAF;
    new->MCASTGroups->compare = ipv6_mcast_groups_cmp;
    new->mtu = 0;
#ifdef PICO_SUPPORT_MLD
    new->mcast_compatibility = PICO_MLDV2;
    new->mcast_last_query_interval = MLD_QUERY_INTERVAL;
#endif
#endif
    if (pico_tree_insert(&dev->stack->IPV6Links, new)) {
        ipv6_dbg("IPv6: Failed to insert link in tree\n");
#ifdef PICO_SUPPORT_MCAST
        PICO_FREE(new->MCASTGroups);
#endif
        PICO_FREE(new);
		return NULL;
	}
    for (i = 0; i < PICO_SIZE_IP6; ++i) {
        network.addr[i] = address.addr[i] & netmask.addr[i];
    }
#ifdef PICO_SUPPORT_MCAST
    do {
        if (!dev->stack->ipv6_mcast_default_link) {
            dev->stack->ipv6_mcast_default_link = new;
            pico_ipv6_route_add(dev->stack, mcast_addr, mcast_nm, mcast_gw, 1, new);
        }

        pico_ipv6_mcast_join(dev->stack, &address, &all_hosts, 1, PICO_IP_MULTICAST_EXCLUDE, NULL);
    } while(0);
#else
    IGNORE_PARAMETER(all_hosts);
#endif
    pico_ipv6_route_add(dev->stack, network, netmask, gateway, 1, new);
#ifdef PICO_SUPPORT_6LOWPAN
    if (!PICO_DEV_IS_6LOWPAN(dev))
#endif
        pico_ipv6_route_add(dev->stack, mcast_addr, mcast_nm, mcast_gw, 1, new);
    /* XXX MUST join the all-nodes multicast address on that interface, as well as
     *     the solicited-node multicast address corresponding to each of the IP
     *     addresses assigned to the interface. (RFC 4861 $7.2.1)
     * XXX RFC6775 (6LoWPAN): There is no need to join the solicited-node multicast address, since
     *     nobody multicasts NSs in this type of network. A host MUST join the all-nodes multicast
     *     address. */
#ifdef PICO_DEBUG_IPV6
    pico_ipv6_to_string(ipstr, new->address.addr);
    dbg("Assigned ipv6 %s to device %s\n", ipstr, new->dev->name);
#endif
    return new;
}

struct pico_ipv6_link *pico_ipv6_link_add_no_dad(struct pico_device *dev, struct pico_ip6 address, struct pico_ip6 netmask)
{
    struct pico_ipv6_link *new = pico_ipv6_do_link_add(dev, address, netmask);
    if (new) {
        new->istentative = 0;
    }
    return new;
}

struct pico_ipv6_link *pico_ipv6_link_add(struct pico_device *dev, struct pico_ip6 address, struct pico_ip6 netmask)
{
#ifdef DEBUG_IPV6
    char ipstr[40] = {
        0
    };
#endif
    /* Try to add the basic link */
    struct pico_ipv6_link *new;
    if (!dev)
        return NULL;
    
    new = pico_ipv6_do_link_add(dev, address, netmask);
    if (!new)
        return NULL;

    /* Apply DAD */
    new->dup_detect_retrans = PICO_IPV6_DEFAULT_DAD_RETRANS;
#ifndef UNIT_TEST
    /* Duplicate Address Detection */
    new->dad_timer = pico_timer_add(dev->stack, 100, pico_ipv6_nd_dad, new);
    if (!new->dad_timer) {
        dbg("IPv6: Failed to start nd_dad timer\n");
        pico_ipv6_link_del(dev->stack, dev, address);
        return NULL;
    }
#else
    new->istentative = 0;
#endif

#ifdef DEBUG_IPV6
    pico_ipv6_to_string(ipstr, new->address.addr);
    dbg("Assigned ipv6 %s to device %s\n", ipstr, new->dev->name);
#endif
    return new;
}

static int pico_ipv6_cleanup_routes(struct pico_stack *S, struct pico_ipv6_link *link)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv6_route *route = NULL;

    pico_tree_foreach_safe(index, &S->IPV6Routes, _tmp)
    {
        route = index->keyValue;
        if (link == route->link)
            pico_ipv6_route_del(S, route->dest, route->netmask, route->gateway, (int)route->metric, route->link);
    }
    return 0;
}

int pico_ipv6_cleanup_links(struct pico_stack *S, struct pico_device *dev)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv6_link *link = NULL;

    pico_tree_foreach_safe(index, &S->IPV6Links, _tmp)
    {
        link = index->keyValue;
        if (dev == link->dev)
            pico_ipv6_link_del(dev->stack, dev, link->address);
    }
    return 0;
}

int pico_ipv6_link_del(struct pico_stack *S, struct pico_device *dev, struct pico_ip6 address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
#ifdef PICO_SUPPORT_MCAST
    struct pico_ip6 all_hosts = {{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }};
    struct pico_mcast_group *g = NULL;
    struct pico_tree_node *index, *_tmp;
#endif

    if (!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.address = address;
    test.dev = dev;
    found = pico_tree_findKey(&S->IPV6Links, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return -1;
    }

    pico_ipv6_cleanup_routes(S, found);
    if (found->dad_timer)
        pico_timer_cancel(S, found->dad_timer);

#ifdef PICO_SUPPORT_MCAST
    /* TODO: Not sure how to properly delete MCAST groups, etc
     * this makes asan happy for now
     */

    if (found == S->ipv6_mcast_default_link) {
        pico_ipv6_mcast_leave(S, &found->address, &all_hosts, 1, PICO_IP_MULTICAST_EXCLUDE, NULL);
        S->ipv6_mcast_default_link = NULL;
    }

    pico_tree_foreach_safe(index, found->MCASTGroups, _tmp)
    {
        g = index->keyValue;
        pico_tree_delete(found->MCASTGroups, g);
        PICO_FREE(g);
    }

    PICO_FREE(found->MCASTGroups);
#endif

    pico_tree_delete(&S->IPV6Links, found);
    /* XXX MUST leave the solicited-node multicast address corresponding to the address (RFC 4861 $7.2.1) */
    PICO_FREE(found);
    return 0;
}

struct pico_ipv6_link *pico_ipv6_link_istentative(struct pico_stack *S, struct pico_ip6 *address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
    test.address = *address;

    found = pico_tree_findKey(&S->IPV6Links, &test);
    if (!found)
        return NULL;

    if (found->istentative)
        return found;

    return NULL;
}

struct pico_ipv6_link *pico_ipv6_link_get(struct pico_stack *S, struct pico_ip6 *address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
    test.address = *address;
    found = pico_tree_findKey(&S->IPV6Links, &test);
    if (!found) {
        return NULL;
    }

    if (found->istentative) {
        return NULL;
    }

    return found;
}

struct pico_device *pico_ipv6_link_find(struct pico_stack *S, struct pico_ip6 *address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
    if(!address) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    test.dev = NULL;
    test.address = *address;
    found = pico_tree_findKey(&S->IPV6Links, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return NULL;
    }

    if (found->istentative) {
        return NULL;
    }

    return found->dev;
}

struct pico_ip6 pico_ipv6_route_get_gateway(struct pico_stack *S, struct pico_ip6 *addr)
{
    struct pico_ip6 nullip = {{0}};
    struct pico_ipv6_route *route = NULL;

    if (!addr) {
        pico_err = PICO_ERR_EINVAL;
        return nullip;
    }

    route = pico_ipv6_route_find(S, addr);
    if (!route) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return nullip;
    }
    else
        return route->gateway;
}


struct pico_ipv6_link *pico_ipv6_link_by_dev(struct pico_device *dev)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_link *link = NULL;

    pico_tree_foreach(index, &dev->stack->IPV6Links)
    {
        link = index->keyValue;
        if (dev == link->dev)
            return link;
    }
    return NULL;
}

struct pico_ipv6_link *pico_ipv6_link_by_dev_next(struct pico_device *dev, struct pico_ipv6_link *last)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_link *link = NULL;
    int valid = 0;

    if (last == NULL)
        valid = 1;

    pico_tree_foreach(index, &dev->stack->IPV6Links)
    {
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

struct pico_ipv6_link *pico_ipv6_prefix_configured(struct pico_stack *S, struct pico_ip6 *prefix)
{
    unsigned int nm64_len = 8;
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_link *link = NULL;
    pico_tree_foreach(index, &S->IPV6Links) {
        link = index->keyValue;
        if (memcmp(link->address.addr, prefix->addr, nm64_len) == 0)
            return link;
    }
    return NULL;
}

struct pico_ipv6_link *pico_ipv6_linklocal_get(struct pico_device *dev)
{
    struct pico_ipv6_link *link = pico_ipv6_link_by_dev(dev);
    while (link && !pico_ipv6_is_linklocal(link->address.addr)) {
        link = pico_ipv6_link_by_dev_next(dev, link);
    }
    return link;
}

struct pico_ipv6_link *pico_ipv6_sitelocal_get(struct pico_device *dev)
{
    struct pico_ipv6_link *link = pico_ipv6_link_by_dev(dev);
    while (link && !pico_ipv6_is_sitelocal(link->address.addr)) {
        link = pico_ipv6_link_by_dev_next(dev, link);
    }
    return link;
}

struct pico_ipv6_link *pico_ipv6_global_get(struct pico_device *dev)
{
    struct pico_ipv6_link *link = pico_ipv6_link_by_dev(dev);
    while (link && !pico_ipv6_is_global(link->address.addr)) {
        dbg("[0x%02X] - is global: %d - %d\n", link->address.addr[0], pico_ipv6_is_global(link->address.addr), link->address.addr[0] >> 0x05);
        link = pico_ipv6_link_by_dev_next(dev, link);
    }
    return link;
}

#define TWO_HOURS   ((pico_time)(1000 * 60 * 60 * 2))

static uint32_t ipv6_lifetimer_check = 0u;

static void pico_ipv6_check_link_lifetime_expired(pico_time now, void *arg);
static void pico_ipv6_nd_enable_lifetime_check(struct pico_stack *S) 
{
    if (!ipv6_lifetimer_check)
        ipv6_lifetimer_check = pico_timer_add(S, 1000, pico_ipv6_check_link_lifetime_expired, S);
}

static void pico_ipv6_check_link_lifetime_expired(pico_time now, void *arg)
{
    struct pico_tree_node *index = NULL, *temp;
    struct pico_ipv6_link *link = NULL;
    int check_needed = 0;
#ifdef PICO_SUPPORT_6LOWPAN
    struct pico_ipv6_route *gw = NULL;
#endif
	struct pico_stack *S = (struct pico_stack *)arg;
    (void)arg;

    pico_tree_foreach_safe(index, &S->IPV6Links, temp) {
        link = index->keyValue;
        if ((link->expire_time > 0) && (link->expire_time < now)) {
            dbg("Warning: IPv6 address has expired.\n");
            pico_ipv6_link_del(S,link->dev, link->address);
        }
#ifdef PICO_SUPPORT_6LOWPAN
        else if (PICO_DEV_IS_6LOWPAN(link->dev) && !pico_ipv6_is_linklocal(link->address.addr) &&
                 (link->expire_time > 0) && (int)(link->expire_time - now) < (int)(TWO_HOURS >> 4)) {
            /* RFC6775: The host SHOULD unicast one or more RSs to the router well before the
             * shortest of the, Router Lifetime, PIO lifetimes and the lifetime of the 6COs. */
            while ((gw = pico_ipv6_gateway_by_dev_next(S, link->dev, gw))) {
                pico_6lp_nd_start_soliciting(link, gw);
            }
        }
#endif
    }
    if (!pico_timer_add(S, 1000, pico_ipv6_check_link_lifetime_expired, arg)) {
        dbg("IPv6: Failed to start check_link_lifetime timer\n");
        /* TODO No more link lifetime checking now */
    }
    ipv6_lifetimer_check = 0u;
    if (check_needed)
        pico_ipv6_nd_enable_lifetime_check(arg);
}

int pico_ipv6_lifetime_set(struct pico_ipv6_link *l, pico_time expire)
{
    pico_time now = PICO_TIME_MS();
    if (expire <= now) {
        return -1;
    }

    if (expire > 0xFFFFFFFE) {
        l->expire_time = 0u;
    }else if ((expire > (now + TWO_HOURS)) || (expire > l->expire_time)) {
        l->expire_time = expire;
    } else {
        l->expire_time = now + TWO_HOURS;
    }
    pico_ipv6_nd_enable_lifetime_check(l->dev->stack);
    return 0;
}

int pico_ipv6_dev_routing_enable(struct pico_device *dev)
{
    pico_time next_timer_expire;
    if (!dev->hostvars.routing)  {
        next_timer_expire = PICO_IPV6_ND_MIN_RADV_INTERVAL + (pico_rand() % (PICO_IPV6_ND_MAX_RADV_INTERVAL - PICO_IPV6_ND_MIN_RADV_INTERVAL));
        pico_timer_add(dev->stack, next_timer_expire, pico_ipv6_nd_ra_timer_callback, dev);
    }
    dev->hostvars.routing = 1;
    return 0;
}

int pico_ipv6_dev_routing_disable(struct pico_device *dev)
{
    dev->hostvars.routing = 0;
    return 0;
}

void pico_ipv6_unreachable(struct pico_stack *S, struct pico_frame *f, uint8_t code)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
#if defined PICO_SUPPORT_TCP || defined PICO_SUPPORT_UDP
    pico_transport_error(S, f, hdr->nxthdr, code);
#endif
}



#endif
