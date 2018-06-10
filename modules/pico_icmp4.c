/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_icmp4.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_eth.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_tree.h"
#include "pico_socket.h"

/* Queues */
static struct pico_queue icmp_in = {
    0
};
static struct pico_queue icmp_out = {
    0
};


/* Functions */

static int pico_icmp4_checksum(struct pico_frame *f)
{
    struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    if (!hdr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    hdr->crc = 0;
    hdr->crc = short_be(pico_checksum(hdr, f->transport_len));
    return 0;
}

#ifdef PICO_SUPPORT_PING
static void ping_recv_reply(struct pico_frame *f);
#endif


/******************************/
/* ICMP socket implementation */
/******************************/
static uint16_t I4Socket_id = 0;
struct pico_socket_icmp4 
{
    struct pico_socket sock;
    uint16_t id;
};


static int icmp4_socket_cmp(void *ka, void *kb)
{
    struct pico_socket_icmp4 *a = ka, *b = kb;
    if (a->id < b->id)
        return -1;
    if (a->id > b->id)
        return 1;
    return (0);
}


static PICO_TREE_DECLARE(I4Sockets, icmp4_socket_cmp);

struct pico_socket *pico_socket_icmp4_open(void)
{
    struct pico_socket_icmp4 *s;
    s = PICO_ZALLOC(sizeof(struct pico_socket_icmp4));
    if (!s) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    s->sock.proto = &pico_proto_icmp4;
    s->id = I4Socket_id++;
    pico_tree_insert(&I4Sockets, s);
    return (struct pico_socket *)s;
}

int pico_socket_icmp4_bind(struct pico_socket *s, void *addr, uint16_t port)
{
    struct pico_socket_icmp4 test;
    test.id = port;
    if (pico_tree_findKey(&I4Sockets, &test)) {
        pico_err = PICO_ERR_EADDRINUSE;
        return -1;
    }
    pico_tree_delete(&I4Sockets, s);
    s->id = port;
    pico_tree_insert(&I4Sockets, s);
    return 0;
}

int pico_socket_icmp4_recvfrom(struct pico_socket *s, void *buf, int len, void *orig,
                                  uint16_t *remote_port)
{
    struct pico_frame *f;
    f = pico_dequeue(&s->q_in);
    if (!f)
        return 0;
    if (f->transport_len < len) {
        len = f->transport_len;
    }
    memcpy(buf, f->transport_hdr, (size_t)len);
    if (orig) {
        struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
        memcpy(orig, &hdr->src, sizeof(struct pico_ip4));
    }
    *remote_port = 0;
    pico_frame_discard(f);
    return len;
}

int pico_socket_icmp4_sendto_check(struct pico_socket *s, const void *buf, int len, void *dst, uint16_t remote_port)
{
    struct pico_icmp4_hdr *hdr;
    struct pico_frame *echo;
    struct pico_socket_icmp4 *i4 = (struct pico_socket_icmp4 *)s;
    (void)remote_port;

    if (len < 8) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Check header sent */
    hdr = (struct pico_icmp4_hdr *) buf;
    if (hdr->type != PICO_ICMP_ECHO) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if(hdr->code != 0) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    hdr->hun.ih_idseq.idseq_id = i4->id;
    return len;
}


int pico_socket_icmp4_close(struct pico_socket *arg)
{
    struct pico_socket_icmp4 *s = (struct pico_socket_icmp4 *)arg;
    if (s) {
        pico_tree_delete(&I4Sockets, s);
        return 0;
    }
    pico_err = PICO_ERR_ENOENT;
    return -1;
}

static int pico_icmp4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    static int firstpkt = 1;
    static uint16_t last_id = 0;
    static uint16_t last_seq = 0;
    struct pico_socket_icmp4 *s = NULL;
    struct pico_socket_icmp4 test;
    IGNORE_PARAMETER(self);

    if (hdr->type == PICO_ICMP_ECHO) {
        hdr->type = PICO_ICMP_ECHOREPLY;
        /* outgoing frames require a f->len without the ethernet header len */
        if (f->dev && f->dev->eth)
            f->len -= PICO_SIZE_ETHHDR;

        if (!firstpkt && (hdr->hun.ih_idseq.idseq_id ==  last_id) && (last_seq == hdr->hun.ih_idseq.idseq_seq)) {
            /* The network duplicated the echo. Do not reply. */
            pico_frame_discard(f);
            return 0;
        }

        firstpkt = 0;
        last_id = hdr->hun.ih_idseq.idseq_id;
        last_seq = hdr->hun.ih_idseq.idseq_seq;
        pico_icmp4_checksum(f);
        pico_ipv4_rebound(f);
    } else if (hdr->type == PICO_ICMP_UNREACH) {
        f->net_hdr = f->transport_hdr + PICO_ICMPHDR_UN_SIZE;
        pico_ipv4_unreachable(f, hdr->code);
    } else if (hdr->type == PICO_ICMP_ECHOREPLY) {
#ifdef PICO_SUPPORT_PING
        ping_recv_reply(f);
#endif
        test.id = hdr->hun.ih_idseq.idseq_id;
        s = pico_tree_findKey(&I4Sockets, &test);
        if (s) {
            struct pico_frame *cp;
            cp = pico_frame_copy(f);
            if (cp) {
                pico_enqueue(&s->sock.q_in, cp);
                if (s->sock.wakeup) {
                    s->sock.wakeup(PICO_SOCK_EV_RD, &s->sock);
                }
            }
        }
        pico_frame_discard(f);
    } else {
        pico_frame_discard(f);
    }

    return 0;
}

static int pico_icmp4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    pico_icmp4_checksum(f);
    return (int)pico_network_send(f);
}

static int pico_icmp4_push(struct pico_protocol *self, struct pico_frame *f)
{
    if (pico_enqueue(self->q_out, f) > 0) {
        return f->payload_len;
    } else {
        return 0;
    }
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_icmp4 = {
    .name = "icmp4",
    .proto_number = PICO_PROTO_ICMP4,
    .layer = PICO_LAYER_TRANSPORT,
    .push = pico_icmp4_push,
    .process_in = pico_icmp4_process_in,
    .process_out = pico_icmp4_process_out,
    .q_in = &icmp_in,
    .q_out = &icmp_out,
};

static int pico_icmp4_notify(struct pico_frame *f, uint8_t type, uint8_t code)
{
    struct pico_frame *reply;
    struct pico_icmp4_hdr *hdr;
    struct pico_ipv4_hdr *info;
    uint16_t f_tot_len;

    if (f == NULL) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    f_tot_len = short_be(((struct pico_ipv4_hdr *)f->net_hdr)->len);

    if (f_tot_len < (sizeof(struct pico_ipv4_hdr)))
        return -1;

    /* Truncate tot len to be at most 8 bytes + iphdr */
    if (f_tot_len > (sizeof(struct pico_ipv4_hdr) + 8u)) {
        f_tot_len = (sizeof(struct pico_ipv4_hdr) + 8u);
    }

    reply = pico_proto_ipv4.alloc(&pico_proto_ipv4, f->dev, (uint16_t) (f_tot_len + PICO_ICMPHDR_UN_SIZE));
    info = (struct pico_ipv4_hdr*)(f->net_hdr);
    hdr = (struct pico_icmp4_hdr *) reply->transport_hdr;
    hdr->type = type;
    hdr->code = code;
    hdr->hun.ih_pmtu.ipm_nmtu = short_be(1500);
    hdr->hun.ih_pmtu.ipm_void = 0;
    reply->transport_len = (uint16_t)(f_tot_len +  PICO_ICMPHDR_UN_SIZE);
    reply->payload = reply->transport_hdr + PICO_ICMPHDR_UN_SIZE;
    memcpy(reply->payload, f->net_hdr, f_tot_len);
    pico_icmp4_checksum(reply);
    pico_ipv4_frame_push(reply, &info->src, PICO_PROTO_ICMP4);
    return 0;
}

int pico_icmp4_port_unreachable(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_PORT);
}

int pico_icmp4_proto_unreachable(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_PROTOCOL);
}

int pico_icmp4_dest_unreachable(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_HOST);
}

int pico_icmp4_ttl_expired(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_TIME_EXCEEDED, PICO_ICMP_TIMXCEED_INTRANS);
}

MOCKABLE int pico_icmp4_frag_expired(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_TIME_EXCEEDED, PICO_ICMP_TIMXCEED_REASS);
}

int pico_icmp4_mtu_exceeded(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_NEEDFRAG);
}

int pico_icmp4_packet_filtered(struct pico_frame *f)
{
    /*Parameter check executed in pico_icmp4_notify*/
    /*Packet Filtered: type 3, code 13 (Communication Administratively Prohibited)*/
    return pico_icmp4_notify(f, PICO_ICMP_UNREACH, PICO_ICMP_UNREACH_FILTER_PROHIB);
}

int pico_icmp4_param_problem(struct pico_frame *f, uint8_t code)
{
    return pico_icmp4_notify(f, PICO_ICMP_PARAMPROB, code);
}



/***********************/
/* Ping implementation */
/***********************/
/***********************/
/***********************/
/***********************/


#ifdef PICO_SUPPORT_PING


struct pico_icmp4_ping_cookie
{
    struct pico_ip4 dst;
    uint16_t err;
    uint16_t id;
    uint16_t seq;
    uint16_t size;
    int count;
    pico_time timestamp;
    int interval;
    int timeout;
    void (*cb)(struct pico_icmp4_stats*);
};

static int cookie_compare(void *ka, void *kb)
{
    struct pico_icmp4_ping_cookie *a = ka, *b = kb;
    if (a->id < b->id)
        return -1;

    if (a->id > b->id)
        return 1;

    return (a->seq - b->seq);
}

static PICO_TREE_DECLARE(Pings, cookie_compare);

static int8_t pico_icmp4_send_echo(struct pico_icmp4_ping_cookie *cookie)
{
    struct pico_frame *echo = NULL;
    struct pico_icmp4_hdr *hdr;
    struct pico_device *dev = pico_ipv4_source_dev_find(&cookie->dst);
    if (!dev)
        return -1;

    echo = pico_proto_ipv4.alloc(&pico_proto_ipv4, dev, (uint16_t)(PICO_ICMPHDR_UN_SIZE + cookie->size));
    if (!echo)
        return -1;

    hdr = (struct pico_icmp4_hdr *) echo->transport_hdr;

    hdr->type = PICO_ICMP_ECHO;
    hdr->code = 0;
    hdr->hun.ih_idseq.idseq_id = short_be(cookie->id);
    hdr->hun.ih_idseq.idseq_seq = short_be(cookie->seq);
    echo->transport_len = (uint16_t)(PICO_ICMPHDR_UN_SIZE + cookie->size);
    echo->payload = echo->transport_hdr + PICO_ICMPHDR_UN_SIZE;
    echo->payload_len = cookie->size;
    /* XXX: Fill payload */
    pico_icmp4_checksum(echo);
    pico_ipv4_frame_push(echo, &cookie->dst, PICO_PROTO_ICMP4);
    return 0;
}


static void ping_timeout(pico_time now, void *arg)
{
    struct pico_icmp4_ping_cookie *cookie = (struct pico_icmp4_ping_cookie *)arg;
    IGNORE_PARAMETER(now);

    if(pico_tree_findKey(&Pings, cookie)) {
        if (cookie->err == PICO_PING_ERR_PENDING) {
            struct pico_icmp4_stats stats;
            stats.dst = cookie->dst;
            stats.seq = cookie->seq;
            stats.time = 0;
            stats.size = cookie->size;
            stats.err = PICO_PING_ERR_TIMEOUT;
            dbg(" ---- Ping timeout!!!\n");
            cookie->cb(&stats);
        }

        pico_tree_delete(&Pings, cookie);
        PICO_FREE(cookie);
    }
}

static void next_ping(pico_time now, void *arg);
static int send_ping(struct pico_icmp4_ping_cookie *cookie)
{
    uint32_t timeout_timer = 0;
    struct pico_icmp4_stats stats;
    pico_icmp4_send_echo(cookie);
    cookie->timestamp = pico_tick;
    timeout_timer = pico_timer_add((uint32_t)cookie->timeout, ping_timeout, cookie);
    if (!timeout_timer) {
        goto fail;
    }
    if (cookie->seq < (uint16_t)cookie->count) {
        if (!pico_timer_add((uint32_t)cookie->interval, next_ping, cookie)) {
            pico_timer_cancel(timeout_timer);
            goto fail;
        }
    }
    return 0;

fail:
    dbg("ICMP4: Failed to start timer\n");
    cookie->err = PICO_PING_ERR_ABORTED;
    stats.err = cookie->err;
    cookie->cb(&stats);
    pico_tree_delete(&Pings, cookie);

    return -1;
}

static void next_ping(pico_time now, void *arg)
{
    struct pico_icmp4_ping_cookie *newcookie, *cookie = (struct pico_icmp4_ping_cookie *)arg;
    IGNORE_PARAMETER(now);

    if(pico_tree_findKey(&Pings, cookie)) {
        if (cookie->err == PICO_PING_ERR_ABORTED)
            return;

        if (cookie->seq < (uint16_t)cookie->count) {
            newcookie = PICO_ZALLOC(sizeof(struct pico_icmp4_ping_cookie));
            if (!newcookie)
                return;

            memcpy(newcookie, cookie, sizeof(struct pico_icmp4_ping_cookie));
            newcookie->seq++;

            if (pico_tree_insert(&Pings, newcookie)) {
                dbg("ICMP4: Failed to insert new cookie in tree \n");
                PICO_FREE(newcookie);
				return;
			}

            if (send_ping(newcookie)) {
                dbg("ICMP4: Failed to send ping\n");
                PICO_FREE(newcookie);
            }
        }
    }
}


static void ping_recv_reply(struct pico_frame *f)
{
    struct pico_icmp4_ping_cookie test, *cookie;
    struct pico_icmp4_hdr *hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    test.id  = short_be(hdr->hun.ih_idseq.idseq_id );
    test.seq = short_be(hdr->hun.ih_idseq.idseq_seq);

    cookie = pico_tree_findKey(&Pings, &test);
    if (cookie) {
        struct pico_icmp4_stats stats;
        if (cookie->err == PICO_PING_ERR_ABORTED)
            return;

        cookie->err = PICO_PING_ERR_REPLIED;
        stats.dst = ((struct pico_ipv4_hdr *)f->net_hdr)->src;
        stats.seq = cookie->seq;
        stats.size = cookie->size;
        stats.time = pico_tick - cookie->timestamp;
        stats.err = cookie->err;
        stats.ttl = ((struct pico_ipv4_hdr *)f->net_hdr)->ttl;
        if(cookie->cb != NULL)
            cookie->cb(&stats);
    } else {
        dbg("Reply for seq=%d, not found.\n", test.seq);
    }
}

int pico_icmp4_ping(char *dst, int count, int interval, int timeout, int size, void (*cb)(struct pico_icmp4_stats *))
{
    static uint16_t next_id = 0x91c0;
    struct pico_icmp4_ping_cookie *cookie;

    if((dst == NULL) || (interval == 0) || (timeout == 0) || (count == 0)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    cookie = PICO_ZALLOC(sizeof(struct pico_icmp4_ping_cookie));
    if (!cookie) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    if (pico_string_to_ipv4(dst, (uint32_t *)&cookie->dst.addr) < 0) {
        pico_err = PICO_ERR_EINVAL;
        PICO_FREE(cookie);
        return -1;
    }

    cookie->seq = 1;
    cookie->id = next_id++;
    cookie->err = PICO_PING_ERR_PENDING;
    cookie->size = (uint16_t)size;
    cookie->interval = interval;
    cookie->timeout = timeout;
    cookie->cb = cb;
    cookie->count = count;

    if (pico_tree_insert(&Pings, cookie)) {
        dbg("ICMP4: Failed to insert cookie in tree \n");
        PICO_FREE(cookie);
		return -1;
	}

    if (send_ping(cookie)) {
        PICO_FREE(cookie);
        return -1;
    }

    return cookie->id;

}

int pico_icmp4_ping_abort(int id)
{
    struct pico_tree_node *node;
    int found = 0;
    pico_tree_foreach(node, &Pings)
    {
        struct pico_icmp4_ping_cookie *ck =
            (struct pico_icmp4_ping_cookie *) node->keyValue;
        if (ck->id == (uint16_t)id) {
            ck->err = PICO_PING_ERR_ABORTED;
            found++;
        }
    }
    if (found > 0)
        return 0; /* OK if at least one pending ping has been canceled */

    pico_err = PICO_ERR_ENOENT;
    return -1;
}

#endif
