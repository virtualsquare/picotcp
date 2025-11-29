#ifndef PICO_TEST_RAND_H
#define PICO_TEST_RAND_H

#include <time.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * WARNING: This is an UNSAFE random generator.
 * DO NOT USE for security, cryptography, or production.
 * Only for testing purposes.
 */
uint32_t pico_rand(void)
{
    static int seeded = 0;
    if (!seeded) {
        srand((uint32_t)time(NULL));
        seeded = 1;
    }
    return (uint32_t)rand() ^ ((uint32_t)rand() << 15) ^ ((uint32_t)rand() << 30);
}

#endif  /* PICO_TEST_RAND_H */
