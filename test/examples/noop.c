/* NOOP */
#include <pico_stack.h>
void app_noop(struct pico_stack *S)
{
    printf("-~-~-~-~-~-~-~-~-~ %s: launching PicoTCP NOOP loop -~-~-~-~-~-~-~-~-~\n", __FUNCTION__);
    while(1) {
        pico_stack_tick(S);
        usleep(2000);
    }
}

/* END NOOP */
