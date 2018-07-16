/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Daniele Lacamera
 *********************************************************************/
#ifndef PICO_OLSR_H
#define PICO_OLSR_H


/* Objects */
struct olsr_route_entry
{
    struct olsr_route_entry         *next;
    uint32_t time_left;
    struct pico_ip4 destination;
    struct olsr_route_entry         *gateway;
    struct pico_device              *iface;
    uint16_t metric;
    uint8_t link_type;
    struct olsr_route_entry         *children;
    uint16_t ansn;
    uint16_t seq;
    uint8_t lq, nlq;
    uint8_t                         advertised_tc;
};


void pico_olsr_init(void);
int pico_olsr_add(struct pico_device *dev);
struct olsr_route_entry *olsr_get_ethentry(struct pico_device *vif);
struct olsr_route_entry kill_neighbour(uint32_t loc_add, uint32_t rem_add);
uint8_t olsr_set_nlq(struct pico_ip4 addr, uint8_t nlq);
#endif
