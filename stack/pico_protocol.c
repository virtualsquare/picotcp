/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   .

   Authors: Daniele Lacamera
 *********************************************************************/


#include "pico_protocol.h"
#include "pico_tree.h"
#include "pico_stack.h"

static int pico_proto_cmp(void *ka, void *kb)
{
    struct pico_protocol *a = ka, *b = kb;
    if (a->hash < b->hash)
        return -1;

    if (a->hash > b->hash)
        return 1;

    return 0;
}


static int proto_loop_in(struct pico_protocol *proto, int loop_score)
{
    struct pico_frame *f;
    while(loop_score > 0) {
        if (proto->q_in->frames == 0)
            break;

        f = pico_dequeue(proto->q_in);
        if ((f) && (proto->process_in(proto, f) > 0)) {
            loop_score--;
        }
    }
    return loop_score;
}

static int proto_loop_out(struct pico_protocol *proto, int loop_score)
{
    struct pico_frame *f;
    while(loop_score > 0) {
        if (proto->q_out->frames == 0)
            break;

        f = pico_dequeue(proto->q_out);
        if ((f) && (proto->process_out(proto, f) > 0)) {
            loop_score--;
        }
    }
    return loop_score;
}

#ifdef PICO_SUPPORT_TICKLESS
static void proto_full_loop_in(void *arg)
{
    struct pico_protocol *proto = (struct pico_protocol *)arg;
    struct pico_frame *f;
    while(1) {
        if (proto->q_in->frames <= 0)
            break;

        f = pico_dequeue(proto->q_in);
        proto->process_in(proto, f);
    }
}

static void proto_full_loop_out(void *arg)
{
    struct pico_protocol *proto = (struct pico_protocol *)arg;
    struct pico_frame *f;
    while(1) {
        if (proto->q_out->frames <= 0)
            break;

        f = pico_dequeue(proto->q_out);
        proto->process_out(proto, f);
    }
}
#endif



static int proto_loop(struct pico_protocol *proto, int loop_score, int direction)
{

    if (direction == PICO_LOOP_DIR_IN)
        loop_score = proto_loop_in(proto, loop_score);
    else if (direction == PICO_LOOP_DIR_OUT)
        loop_score = proto_loop_out(proto, loop_score);

    return loop_score;
}

static struct pico_tree_node *roundrobin_init(struct pico_proto_rr *rr, int direction)
{
    struct pico_tree_node *next_node = NULL;
    /* Initialization (takes place only once) */
    if (rr->node_in == NULL)
        rr->node_in = pico_tree_firstNode(rr->t->root);

    if (rr->node_out == NULL)
        rr->node_out = pico_tree_firstNode(rr->t->root);

    if (direction == PICO_LOOP_DIR_IN)
        next_node = rr->node_in;
    else
        next_node = rr->node_out;

    return next_node;
}

static void roundrobin_end(struct pico_proto_rr *rr, int direction, struct pico_tree_node *last)
{
    if (direction == PICO_LOOP_DIR_IN)
        rr->node_in = last;
    else
        rr->node_out = last;
}

static int pico_protocol_generic_loop(struct pico_proto_rr *rr, int loop_score, int direction)
{
    struct pico_protocol *start, *next;
    struct pico_tree_node *next_node = roundrobin_init(rr, direction);

    if (!next_node)
        return loop_score;

    next = next_node->keyValue;

    /* init start node */
    start = next;

    /* round-robin all layer protocols, break if traversed all protocols */
    while (loop_score > 1 && next != NULL) {
        loop_score = proto_loop(next, loop_score, direction);
        next_node = pico_tree_next(next_node);
        next = next_node->keyValue;
        if (next == NULL)
        {
            next_node = pico_tree_firstNode(rr->t->root);
            next = next_node->keyValue;
        }

        if (next == start)
            break;
    }
    roundrobin_end(rr, direction, next_node);
    return loop_score;
}

int pico_protocol_datalink_loop(struct pico_stack *S, int loop_score, int direction)
{
    return pico_protocol_generic_loop(&S->sched->rr_datalink, loop_score, direction);
}

int pico_protocol_network_loop(struct pico_stack *S, int loop_score, int direction)
{
    return pico_protocol_generic_loop(&S->sched->rr_network, loop_score, direction);
}

int pico_protocol_transport_loop(struct pico_stack *S, int loop_score, int direction)
{
    return pico_protocol_generic_loop(&S->sched->rr_transport, loop_score, direction);
}

int pico_protocol_socket_loop(struct pico_stack *S, int loop_score, int direction)
{
    return pico_protocol_generic_loop(&S->sched->rr_socket, loop_score, direction);
}

static void proto_layer_rr_reset(struct pico_proto_rr *rr)
{
    rr->node_in = NULL;
    rr->node_out = NULL;
}

int pico_protocol_scheduler_init(struct pico_stack *S)
{
    if (!S) {
        return PICO_ERR_EINVAL;
    }
    if (S->sched)
        return PICO_ERR_EEXIST;
    S->sched = PICO_ZALLOC(sizeof(struct pico_scheduler));
    if (!S->sched)
        return PICO_ERR_ENOMEM;

    /* Initialize empty trees */
    S->sched->Datalink_proto_tree.root = &LEAF;
    S->sched->Datalink_proto_tree.compare = pico_proto_cmp;
    S->sched->Network_proto_tree.root = &LEAF;
    S->sched->Network_proto_tree.compare = pico_proto_cmp;
    S->sched->Transport_proto_tree.root = &LEAF;
    S->sched->Transport_proto_tree.compare = pico_proto_cmp;
    S->sched->Socket_proto_tree.root = &LEAF;
    S->sched->Socket_proto_tree.compare = pico_proto_cmp;

    /* Link to round-robin structures */
    S->sched->rr_datalink.t = &S->sched->Datalink_proto_tree;
    S->sched->rr_network.t = &S->sched->Network_proto_tree;
    S->sched->rr_transport.t = &S->sched->Transport_proto_tree;
    S->sched->rr_socket.t = &S->sched->Socket_proto_tree;
    return PICO_ERR_NOERR;
}

void pico_protocol_init(struct pico_stack *S, struct pico_protocol *p)
{
    struct pico_tree *tree = NULL;
    struct pico_proto_rr *proto = NULL;
    if (!p)
        return;

    p->hash = pico_hash(p->name, (uint32_t)strlen(p->name));
    switch (p->layer) {
        case PICO_LAYER_DATALINK:
            tree = &S->sched->Datalink_proto_tree;
            proto = &S->sched->rr_datalink;
            break;
        case PICO_LAYER_NETWORK:
            tree = &S->sched->Network_proto_tree;
            proto = &S->sched->rr_network;
            break;
        case PICO_LAYER_TRANSPORT:
            tree = &S->sched->Transport_proto_tree;
            proto = &S->sched->rr_transport;
            break;
        case PICO_LAYER_SOCKET:
            tree = &S->sched->Socket_proto_tree;
            proto = &S->sched->rr_socket;
            break;
        default:
            dbg("Unknown protocol: %s (layer: %d)\n", p->name, p->layer);
            return;
    }
#ifdef PICO_SUPPORT_TICKLESS
    pico_queue_register_listener(p->q_in, proto_full_loop_in, p);
    pico_queue_register_listener(p->q_out, proto_full_loop_out, p);
#endif
    dbg("Protocol %s registered (layer: %d).\n", p->name, p->layer);

    if (pico_tree_insert(tree, p)) {
        dbg("Failed to insert protocol %s\n", p->name);
        return;
    }

    proto_layer_rr_reset(proto);
    dbg("Protocol %s registered (layer: %d).\n", p->name, p->layer);
}

