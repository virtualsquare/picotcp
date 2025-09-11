/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
 *
 * This file also includes code from:
 * PicoTCP
 * Copyright (c) 2012-2017 Altran Intelligent Systems
 * Authors: Michele Di Pede
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
#include <ctype.h>
#include <stdlib.h>
#include "pico_strings.h"

char *get_string_terminator_position(char *const block, size_t len)
{
    size_t length = pico_strnlen(block, len);

    return (len != length) ? (block + length) : 0;
}

int pico_strncasecmp(const char *const str1, const char *const str2, size_t n)
{
    int ch1;
    int ch2;
    size_t i;

    for (i = 0; i < n; ++i) {
        ch1 = toupper(*(str1 + i));
        ch2 = toupper(*(str2 + i));
        if (ch1 < ch2)
            return -1;

        if (ch1 > ch2)
            return 1;

        if ((!ch1) && (!ch2))
            return 0;
    }
    return 0;
}

size_t pico_strnlen(const char *str, size_t n)
{
    size_t len = 0;

    if (!str)
        return 0;

    for (; len < n && *(str + len); ++len)
        ; /* TICS require this empty statement here */

    return len;
}

static inline int num2string_validate(int32_t num, char *buf, int len)
{
    if (num < 0)
        return -1;

    if (!buf)
        return -2;

    if (len < 2)
        return -3;

    return 0;
}

static inline int revert_and_shift(char *buf, int len, int pos)
{
    int i;

    len -= pos;
    for (i = 0; i < len; ++i)
        buf[i] = buf[i + pos];
    return len;
}

int num2string(int32_t num, char *buf, int len)
{
    ldiv_t res;
    int pos = 0;

    if (num2string_validate(num, buf, len))
        return -1;

    pos = len;
    buf[--pos] = '\0';

    res.quot = (long)num;

    do {
        if (!pos)
            return -3;

        res = ldiv(res.quot, 10);
        buf[--pos] = (char)((res.rem + '0') & 0xFF);
    } while (res.quot);

    return revert_and_shift(buf, len, pos);
}
