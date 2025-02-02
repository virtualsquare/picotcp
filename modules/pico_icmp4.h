/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
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
#ifndef INCLUDE_PICO_ICMP4
#define INCLUDE_PICO_ICMP4
#include "pico_defines.h"
#include "pico_addressing.h"
#include "pico_protocol.h"


extern struct pico_protocol pico_proto_icmp4;

PACKED_STRUCT_DEF pico_icmp4_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t crc;

    /* hun */
    PACKED_UNION_DEF hun_u {
        uint8_t ih_pptr;
        struct pico_ip4 ih_gwaddr;
        PEDANTIC_STRUCT_DEF ih_idseq_s {
            uint16_t idseq_id;
            uint16_t idseq_seq;
        } ih_idseq;
        uint32_t ih_void;
        PEDANTIC_STRUCT_DEF ih_pmtu_s {
            uint16_t ipm_void;
            uint16_t ipm_nmtu;
        } ih_pmtu;
        PEDANTIC_STRUCT_DEF ih_rta_s {
            uint8_t rta_numgw;
            uint8_t rta_wpa;
            uint16_t rta_lifetime;
        } ih_rta;
    } hun;

    /* dun */
    PACKED_UNION_DEF dun_u {
        PEDANTIC_STRUCT_DEF id_ts_s {
            uint32_t ts_otime;
            uint32_t ts_rtime;
            uint32_t ts_ttime;
        } id_ts;
        PEDANTIC_STRUCT_DEF id_ip_s {
            uint32_t ip_options;
            uint32_t ip_data_hi;
            uint32_t ip_data_lo;
        } id_ip;
        PEDANTIC_STRUCT_DEF id_ra_s {
            uint32_t ira_addr;
            uint32_t ira_pref;
        } id_ra;
        uint32_t id_mask;
        uint8_t id_data[1];
    } dun;
};

#define PICO_ICMPHDR_DRY_SIZE  4
#define PICO_ICMPHDR_UN_SIZE  8u

#define PICO_ICMP_ECHOREPLY    0
#define PICO_ICMP_DEST_UNREACH 3
#define PICO_ICMP_SOURCE_QUENCH  4
#define PICO_ICMP_REDIRECT   5
#define PICO_ICMP_ECHO   8
#define PICO_ICMP_TIME_EXCEEDED  11
#define PICO_ICMP_PARAMETERPROB  12
#define PICO_ICMP_TIMESTAMP    13
#define PICO_ICMP_TIMESTAMPREPLY 14
#define PICO_ICMP_INFO_REQUEST 15
#define PICO_ICMP_INFO_REPLY   16
#define PICO_ICMP_ADDRESS    17
#define PICO_ICMP_ADDRESSREPLY 18


#define  PICO_ICMP_UNREACH    3
#define  PICO_ICMP_SOURCEQUENCH  4
#define  PICO_ICMP_ROUTERADVERT  9
#define  PICO_ICMP_ROUTERSOLICIT  10
#define  PICO_ICMP_TIMXCEED    11
#define  PICO_ICMP_PARAMPROB    12
#define  PICO_ICMP_TSTAMP    13
#define  PICO_ICMP_TSTAMPREPLY  14
#define  PICO_ICMP_IREQ    15
#define  PICO_ICMP_IREQREPLY    16
#define  PICO_ICMP_MASKREQ    17
#define  PICO_ICMP_MASKREPLY    18

#define  PICO_ICMP_MAXTYPE    18
#define  PICO_ICMP_MAXCOOKIE    65528


#define  PICO_ICMP_UNREACH_NET          0
#define  PICO_ICMP_UNREACH_HOST          1
#define  PICO_ICMP_UNREACH_PROTOCOL          2
#define  PICO_ICMP_UNREACH_PORT          3
#define  PICO_ICMP_UNREACH_NEEDFRAG          4
#define  PICO_ICMP_UNREACH_SRCFAIL          5
#define  PICO_ICMP_UNREACH_NET_UNKNOWN        6
#define  PICO_ICMP_UNREACH_HOST_UNKNOWN       7
#define  PICO_ICMP_UNREACH_ISOLATED          8
#define  PICO_ICMP_UNREACH_NET_PROHIB          9
#define  PICO_ICMP_UNREACH_HOST_PROHIB        10
#define  PICO_ICMP_UNREACH_TOSNET          11
#define  PICO_ICMP_UNREACH_TOSHOST          12
#define  PICO_ICMP_UNREACH_FILTER_PROHIB      13
#define  PICO_ICMP_UNREACH_HOST_PRECEDENCE    14
#define  PICO_ICMP_UNREACH_PRECEDENCE_CUTOFF  15


#define  PICO_ICMP_REDIRECT_NET  0
#define  PICO_ICMP_REDIRECT_HOST  1
#define  PICO_ICMP_REDIRECT_TOSNET  2
#define  PICO_ICMP_REDIRECT_TOSHOST  3


#define  PICO_ICMP_TIMXCEED_INTRANS  0
#define  PICO_ICMP_TIMXCEED_REASS  1


#define  PICO_ICMP_PARAMPROB_OPTABSENT 1

#define PICO_SIZE_ICMP4HDR ((sizeof(struct pico_icmp4_hdr)))

struct pico_icmp4_stats
{
    struct pico_ip4 dst;
    unsigned long size;
    unsigned long seq;
    pico_time time;
    unsigned long ttl;
    int err;
};

int icmp4_socket_cmp(void *ka, void *kb);
int pico_icmp4_port_unreachable(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_proto_unreachable(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_dest_unreachable(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_mtu_exceeded(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_ttl_expired(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_frag_expired(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_ping(struct pico_stack *S, char *dst, int count, int interval, int timeout, int size, void (*cb)(struct pico_icmp4_stats *));
int pico_icmp4_ping_abort(struct pico_stack *S, int id);


struct pico_socket *pico_socket_icmp4_open(struct pico_stack *S);
int pico_socket_icmp4_close(struct pico_socket *arg);
int pico_socket_icmp4_sendto_check(struct pico_socket *s, void *buf, int len, void *dst, uint16_t remote_port);
int pico_socket_icmp4_recvfrom(struct pico_socket *s, void *buf, int len, void *orig, uint16_t *remote_port);
int pico_socket_icmp4_bind(struct pico_socket *s, void *addr, uint16_t port);

#ifdef PICO_SUPPORT_ICMP4
int pico_icmp4_packet_filtered(struct pico_stack *S, struct pico_frame *f);
int pico_icmp4_param_problem(struct pico_stack *S, struct pico_frame *f, uint8_t code);
int pico_icmp4_cookie_compare(void *ka, void *kb);
#else
# define pico_icmp4_packet_filtered(S, f) (-1)
# define pico_icmp4_param_problem(S, f, c) (-1)
#endif /* PICO_SUPPORT_ICMP4 */

#define PICO_PING_ERR_REPLIED 0
#define PICO_PING_ERR_TIMEOUT 1
#define PICO_PING_ERR_UNREACH 2
#define PICO_PING_ERR_ABORTED 3
#define PICO_PING_ERR_PENDING 0xFFFF

#endif
