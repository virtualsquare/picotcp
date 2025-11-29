#include "pico_stack.h"

#if defined(PICO_SUPPORT_RTOS) || defined (PICO_SUPPORT_PTHREAD)
volatile uint32_t pico_ms_tick;
#endif

int main(void)
{
    struct pico_stack *S = NULL;
    pico_stack_init(&S);
    pico_stack_tick(S);
    return 0;
}
