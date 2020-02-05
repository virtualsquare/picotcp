#include "utils.h"
#include "pico_dns_common.h"
#include "pico_mdns.h"
#include "pico_ipv4.h"
#include "pico_addressing.h"
#include "pico_stack.h"

static struct pico_stack *stack = NULL;

/*** START MDNS ***/

#ifdef PICO_SUPPORT_MDNS

#define SECONDS 10

static int fully_initialized = 0;

void mdns_init_callback( pico_mdns_rtree *rtree,
                         char *str,
                         void *arg )
{
    printf("\nInitialised with hostname: %s\n\n", str);

    fully_initialized = 1;
}

void app_mdns(struct pico_stack *S, char *arg, struct pico_ip4 address)
{
    char *hostname, *peername;
    char *nxt = arg;
    uint64_t starttime = 0;
    int once = 0;
    stack = S;

    if (!nxt)
        exit(255);

    nxt = cpy_arg(&hostname, nxt);
    if(!hostname) {
        exit(255);
    }

    if(!nxt) {
        printf("Not enough args supplied!\n");
        exit(255);
    }

    nxt = cpy_arg(&peername, nxt);
    if(!peername) {
        exit(255);
    }

    printf("\nStarting mDNS module...\n");
    if (pico_mdns_init(stack, hostname, address, &mdns_init_callback, NULL)) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }

    printf("\nTry reinitialising mDNS\n");
    if (pico_mdns_init(stack, hostname, address, &mdns_init_callback, NULL)) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }

    printf("DONE - Re-initialising mDNS module.\n");

    starttime = PICO_TIME_MS();
    printf("Starting time: %d\n", starttime);

    while(1) {
        pico_stack_tick(S);
        usleep(2000);

        if (((PICO_TIME_MS() - starttime) > SECONDS * 1000) && fully_initialized && !once) {
            printf("\nTry reinitialising mDNS (a second time)\n");
            if (pico_mdns_init(stack, hostname, address, &mdns_init_callback, NULL)) {
                printf("Initialisation returned with Error!\n");
                exit(255);
            }
            once = 1;
            printf("DONE - Re-initialising mDNS module. (a second time)\n");
        }

    }
}
#endif
/*** END MDNS ***/
