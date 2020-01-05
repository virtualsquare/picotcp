/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Roel Postelmans
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
#include "pico_stack.h"
#include "pico_ipv6.h"
#include "pico_mld.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#include "pico_mld.h"
#include "pico_igmp.h"
#include "pico_constants.h"
#include "pico_mcast.h"

#if (((defined(PICO_SUPPORT_MLD) && defined(PICO_SUPPORT_IPV6)) || defined(PICO_SUPPORT_IGMP)) && defined(PICO_SUPPORT_MCAST))

#ifdef DEBUG_MCAST
#define multicast_dbg dbg
#else
#define multicast_dbg(...) do {} while(0)
#endif

#define MCAST_EVENT_DELETE_GROUP           (0x0)
#define MCAST_EVENT_CREATE_GROUP           (0x1)
#define MCAST_EVENT_UPDATE_GROUP           (0x2)
#define MCAST_EVENT_QUERY_RECV             (0x3)
#define MCAST_EVENT_REPORT_RECV            (0x4)
#define MCAST_EVENT_TIMER_EXPIRED          (0x5)

#define MCAST_MODE_IS_INCLUDE              (1)
#define MCAST_MODE_IS_EXCLUDE              (2)
#define MCAST_CHANGE_TO_INCLUDE_MODE       (3)
#define MCAST_CHANGE_TO_EXCLUDE_MODE       (4)

#define MCAST_MODE_IS_INCLUDE              (1)
#define MCAST_MODE_IS_EXCLUDE              (2)
#define MCAST_CHANGE_TO_INCLUDE_MODE       (3)
#define MCAST_CHANGE_TO_EXCLUDE_MODE       (4)
#define MCAST_ALLOW_NEW_SOURCES            (5)
#define MCAST_BLOCK_OLD_SOURCES            (6)


static void pico_mcast_src_filtering_cleanup(struct mcast_filter_parameters *mcast )
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    /* cleanup filters */
    pico_tree_foreach_safe(index, mcast->allow, _tmp)
    {
        pico_tree_delete(mcast->allow, index->keyValue);
    }
    pico_tree_foreach_safe(index, mcast->block, _tmp)
    {
        pico_tree_delete(mcast->block, index->keyValue);
    }
}
static int pico_mcast_src_filtering_inc_inc(struct mcast_filter_parameters*mcast )
{
    struct pico_tree_node *index = NULL;
    union pico_address *source;
    /* all ADD_SOURCE_MEMBERSHIP had an equivalent DROP_SOURCE_MEMBERSHIP */
    if (mcast->p->event == MCAST_EVENT_DELETE_GROUP) {
        /* TO_IN (B) */
        mcast->record_type = MCAST_CHANGE_TO_INCLUDE_MODE;
        mcast->filter = mcast->allow;
        if (mcast->p->MCASTFilter) {
            pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
            {
                if (pico_tree_insert(mcast->allow, index->keyValue) == &LEAF) {
               	    multicast_dbg("MCAST: Failed to insert entry in tree\n");
                    return -1;
                }
                mcast->sources++;
            }
        } /* else { allow stays empty } */

        return 0;
    }

    /* ALLOW (B-A) */
    /* if event is CREATE A will be empty, thus only ALLOW (B-A) has sense */
    if (mcast->p->event == MCAST_EVENT_CREATE_GROUP) /* first ADD_SOURCE_MEMBERSHIP */
        mcast->record_type = MCAST_CHANGE_TO_INCLUDE_MODE;
    else
        mcast->record_type = MCAST_ALLOW_NEW_SOURCES;

    mcast->filter = mcast->allow;
    pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
    {
        if (pico_tree_insert(mcast->allow, index->keyValue) == &LEAF) {
            multicast_dbg("MCAST: Failed to insert entry in tree\n");
            return -1;
		}
        mcast->sources++;
    }
    pico_tree_foreach(index, &mcast->g->MCASTSources) /* A */
    {
        source = pico_tree_findKey(mcast->allow, index->keyValue);
        if (source) {
            pico_tree_delete(mcast->allow, source);
            mcast->sources--;
        }
    }
    if (!pico_tree_empty(mcast->allow)) /* record type is ALLOW */
        return 0;

    /* BLOCK (A-B) */
    mcast->record_type = MCAST_BLOCK_OLD_SOURCES;
    mcast->filter = mcast->block;
    pico_tree_foreach(index, &mcast->g->MCASTSources) /* A */
    {
        if (pico_tree_insert(mcast->block, index->keyValue) == &LEAF) {
            multicast_dbg("MCAST: Failed to insert entry in tree\n");
            return -1;
		}
        mcast->sources++;
    }
    pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
    {
        source = pico_tree_findKey(mcast->block, index->keyValue);
        if (source) {
            pico_tree_delete(mcast->block, source);
            mcast->sources--;
        }
    }
    if (!pico_tree_empty(mcast->block)) /* record type is BLOCK */
        return 0;

    /* ALLOW (B-A) and BLOCK (A-B) are empty: do not send report  */
    (mcast->p)->f = NULL;
    return MCAST_NO_REPORT;
}

static int pico_mcast_src_filtering_inc_excl(struct mcast_filter_parameters*mcast )
{
    struct pico_tree_node *index = NULL;
    mcast->record_type = MCAST_CHANGE_TO_EXCLUDE_MODE;
    mcast->filter = mcast->block;
    pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
    {
        if (pico_tree_insert(mcast->block, index->keyValue) == &LEAF) {
            multicast_dbg("MCAST: Failed to insert entry in tree\n");
            return -1;
		}
        mcast->sources++;
    }
    return 0;
}
static int pico_mcast_src_filtering_excl_inc(struct mcast_filter_parameters*mcast )
{
    struct pico_tree_node *index = NULL;
    mcast->record_type = MCAST_CHANGE_TO_INCLUDE_MODE;
    mcast->filter = mcast->allow;
    if (mcast->p->MCASTFilter) {
        pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
        {
            if (pico_tree_insert(mcast->allow, index->keyValue) == &LEAF) {
                multicast_dbg("MCAST: Failed to insert entry in tree\n");
                return -1;
			}
            mcast->sources++;
        }
    } /* else { allow stays empty } */

    return 0;
}
static int pico_mcast_src_filtering_excl_excl(struct mcast_filter_parameters*mcast )
{
    struct pico_tree_node *index = NULL;
    struct pico_ip6 *source = NULL;
    mcast->record_type = MCAST_BLOCK_OLD_SOURCES;
    mcast->filter = mcast->block;
    pico_tree_foreach(index, mcast->p->MCASTFilter)
    {
        if (pico_tree_insert(mcast->block, index->keyValue) == &LEAF) {
            multicast_dbg("MCAST: Failed to insert entry in tree\n");
            return -1;
		}

        mcast->sources++;
    }
    pico_tree_foreach(index, &mcast->g->MCASTSources) /* A */
    {
        source = pico_tree_findKey(mcast->block, index->keyValue); /* B */
        if (source) {
            pico_tree_delete(mcast->block, source);
            mcast->sources--;
        }
    }
    if (!pico_tree_empty(mcast->block)) /* record type is BLOCK */
        return 0;

    /* ALLOW (A-B) */
    mcast->record_type = MCAST_ALLOW_NEW_SOURCES;
    mcast->filter = mcast->allow;
    pico_tree_foreach(index, &mcast->g->MCASTSources)
    {
        if (pico_tree_insert(mcast->allow, index->keyValue) == &LEAF) {
            multicast_dbg("MCAST: Failed to insert entry in tree\n");
            return -1;
		}
        mcast->sources++;
    }
    pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
    {
        source = pico_tree_findKey(mcast->allow, index->keyValue); /* A */
        if (source) {
            pico_tree_delete(mcast->allow, source);
            mcast->sources--;
        }
    }
    if (!pico_tree_empty(mcast->allow)) /* record type is ALLOW */
        return 0;

    /* BLOCK (B-A) and ALLOW (A-B) are empty: do not send report  */
    mcast->p->f = NULL;
    return MCAST_NO_REPORT;
}

int8_t pico_mcast_generate_filter(struct pico_stack *S, struct mcast_filter_parameters *filter, struct mcast_parameters *p)
{
    p->stack = S;

    /* "non-existent" state of filter mode INCLUDE and empty source list */
    if (p->event == MCAST_EVENT_DELETE_GROUP) {
        p->filter_mode = PICO_IP_MULTICAST_INCLUDE;
        p->MCASTFilter = NULL;
    }

    if (p->event == MCAST_EVENT_QUERY_RECV)
        return 0;

    pico_mcast_src_filtering_cleanup(filter);

    switch (filter->g->filter_mode) {

    case PICO_IP_MULTICAST_INCLUDE:
        switch (p->filter_mode) {
        case PICO_IP_MULTICAST_INCLUDE:
            if(pico_mcast_src_filtering_inc_inc(filter) == MCAST_NO_REPORT)
                return MCAST_NO_REPORT;

            break;
        case PICO_IP_MULTICAST_EXCLUDE:
            /* TO_EX (B) */
            pico_mcast_src_filtering_inc_excl(filter);
            break;
        default:
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        break;
    case PICO_IP_MULTICAST_EXCLUDE:
        switch (p->filter_mode) {
        case PICO_IP_MULTICAST_INCLUDE:
            /* TO_IN (B) */
            pico_mcast_src_filtering_excl_inc(filter);
            break;
        case PICO_IP_MULTICAST_EXCLUDE:
            /* BLOCK (B-A) */
            if(pico_mcast_src_filtering_excl_excl(filter) == MCAST_NO_REPORT)
                return MCAST_NO_REPORT;

            break;
        default:
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    return 0;
}
#endif
