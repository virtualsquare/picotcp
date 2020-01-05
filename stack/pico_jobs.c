/*********************************************************************
 * PicoTCP-NG 
 * Copyright (c) 2020 Daniele Lacamera <root@danielinux.net>
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
#include "pico_defines.h"
#ifdef PICO_SUPPORT_TICKLESS
#include "pico_jobs.h"
struct pico_job
{
    void (*exe)(struct pico_stack *, void *);
    void *arg;
    struct pico_job *next;
    struct pico_stack *stack;
};


/* static int max_jobs; */

void pico_schedule_job(struct pico_stack *S, void (*exe)(struct pico_stack *, void*), void *arg)
{
    struct pico_job *job = PICO_ZALLOC(sizeof(struct pico_job));
    if  (!job)
        return;
    job->exe = exe;
    job->arg = arg;
    job->stack = S;
    if (!S->pico_jobs_backlog) {
       S->pico_jobs_backlog = job;
       S->pico_jobs_backlog_tail = job;
    } else {
        S->pico_jobs_backlog_tail->next = job;
        S->pico_jobs_backlog_tail = job;
    }
}

void pico_execute_pending_jobs(struct pico_stack *S)
{
    struct pico_job *job;
    /* int count = 0; */
    while(S->pico_jobs_backlog) {
        job = S->pico_jobs_backlog;
        if (job->exe) {
            job->exe(job->stack, job->arg);
        }
        S->pico_jobs_backlog = job->next;
        PICO_FREE(job);
        /* count++; */
        if (!S->pico_jobs_backlog)
            S->pico_jobs_backlog_tail = NULL;
    }
    /*
    if (count > max_jobs) {
        printf("Max jobs = %d\n", count);
        max_jobs = count;
    }
    */
}
#endif
