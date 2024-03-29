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
#ifndef INCLUDE_PICO_TCP
#define INCLUDE_PICO_TCP
#include "pico_addressing.h"
#include "pico_protocol.h"
#include "pico_socket.h"

extern struct pico_protocol pico_proto_tcp;

PACKED_STRUCT_DEF pico_tcp_hdr {
    struct pico_trans trans;
    uint32_t seq;
    uint32_t ack;
    uint8_t len;
    uint8_t flags;
    uint16_t rwnd;
    uint16_t crc;
    uint16_t urgent;
};

PACKED_STRUCT_DEF tcp_pseudo_hdr_ipv4
{
    struct pico_ip4 src;
    struct pico_ip4 dst;
    uint16_t tcp_len;
    uint8_t res;
    uint8_t proto;
};

#define PICO_TCPHDR_SIZE 20
#define PICO_SIZE_TCPOPT_SYN 20
#define PICO_SIZE_TCPHDR (uint32_t)(sizeof(struct pico_tcp_hdr))
#define PICO_TCP_MIN_MSS (64 - PICO_SIZE_TCPHDR)

/* TCP options */
#define PICO_TCP_OPTION_END         0x00
#define PICO_TCPOPTLEN_END        1u
#define PICO_TCP_OPTION_NOOP        0x01
#define PICO_TCPOPTLEN_NOOP       1
#define PICO_TCP_OPTION_MSS         0x02
#define PICO_TCPOPTLEN_MSS        4
#define PICO_TCP_OPTION_WS          0x03
#define PICO_TCPOPTLEN_WS         3u
#define PICO_TCP_OPTION_SACK_OK        0x04
#define PICO_TCPOPTLEN_SACK_OK       2
#define PICO_TCP_OPTION_SACK        0x05
#define PICO_TCPOPTLEN_SACK       2 /* Plus the block */
#define PICO_TCP_OPTION_TIMESTAMP   0x08
#define PICO_TCPOPTLEN_TIMESTAMP  10u

/* TCP flags */
#define PICO_TCP_FIN 0x01u
#define PICO_TCP_SYN 0x02u
#define PICO_TCP_RST 0x04u
#define PICO_TCP_PSH 0x08u
#define PICO_TCP_ACK 0x10u
#define PICO_TCP_URG 0x20u
#define PICO_TCP_ECN 0x40u
#define PICO_TCP_CWR 0x80u

#define PICO_TCP_SYNACK    (PICO_TCP_SYN | PICO_TCP_ACK)
#define PICO_TCP_PSHACK    (PICO_TCP_PSH | PICO_TCP_ACK)
#define PICO_TCP_FINACK    (PICO_TCP_FIN | PICO_TCP_ACK)
#define PICO_TCP_FINPSHACK (PICO_TCP_FIN | PICO_TCP_PSH | PICO_TCP_ACK)
#define PICO_TCP_RSTACK    (PICO_TCP_RST | PICO_TCP_ACK)


PACKED_STRUCT_DEF pico_tcp_option
{
    uint8_t kind;
    uint8_t len;
};

struct pico_socket *pico_tcp_open(struct pico_stack *S, uint16_t family);
uint32_t pico_tcp_read(struct pico_socket *s, void *buf, uint32_t len);
int pico_tcp_initconn(struct pico_socket *s);
int pico_tcp_input(struct pico_socket *s, struct pico_frame *f);
uint16_t pico_tcp_checksum(struct pico_frame *f);
uint16_t pico_tcp_checksum_ipv4(struct pico_frame *f);
#ifdef PICO_SUPPORT_IPV6
uint16_t pico_tcp_checksum_ipv6(struct pico_frame *f);
#endif
uint16_t pico_tcp_overhead(struct pico_socket *s);
int pico_tcp_output(struct pico_socket *s, int loop_score);
int pico_tcp_queue_in_is_empty(struct pico_socket *s);
int pico_tcp_queue_in_size(struct pico_socket *s);
int pico_tcp_reply_rst(struct pico_stack *S, struct pico_frame *f);
void pico_tcp_cleanup_queues(struct pico_socket *sck);
void pico_tcp_notify_closing(struct pico_socket *sck);
void pico_tcp_flags_update(struct pico_frame *f, struct pico_socket *s);
int pico_tcp_set_bufsize_in(struct pico_socket *s, uint32_t value);
int pico_tcp_set_bufsize_out(struct pico_socket *s, uint32_t value);
int pico_tcp_get_bufsize_in(struct pico_socket *s, uint32_t *value);
int pico_tcp_get_bufsize_out(struct pico_socket *s, uint32_t *value);
int pico_tcp_set_keepalive_probes(struct pico_socket *s, uint32_t value);
int pico_tcp_set_keepalive_intvl(struct pico_socket *s, uint32_t value);
int pico_tcp_set_keepalive_time(struct pico_socket *s, uint32_t value);
int pico_tcp_set_linger(struct pico_socket *s, uint32_t value);
uint16_t pico_tcp_get_socket_mss(struct pico_socket *s);
int pico_tcp_check_listen_close(struct pico_socket *s);

#endif
