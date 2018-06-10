/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

 *********************************************************************/
#ifndef INCLUDE_PICO_TAP
#define INCLUDE_PICO_TAP
#include "pico_config.h"
#include "pico_device.h"

void pico_tap_destroy(struct pico_device *tap);
struct pico_device *pico_tap_create(char *name);
int pico_tap_WFI(struct pico_device *dev, int timeout_ms);
void pico_tap_dsr(void *arg);

#endif

