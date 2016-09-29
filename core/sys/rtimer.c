/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Implementation of the architecture-agnostic parts of the real-time timer module.
 * \author
 *         Adam Dunkels <adam@sics.se>
 *
 */

/**
 * \addtogroup rt
 * @{
 */

#include "sys/rtimer.h"
#include "contiki.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

static struct rtimer *next_rtimer;
static const rtimer_clock_t max_rtimer_value = -1;

/*---------------------------------------------------------------------------*/
void
rtimer_init(void)
{
  rtimer_arch_init();
}
/*---------------------------------------------------------------------------*/
int
rtimer_set(struct rtimer *rtimer, rtimer_clock_t time,
	   rtimer_clock_t duration,
	   rtimer_callback_t func, void *ptr)
{
  PRINTF("rtimer_set time %d\n", time);

  if(next_rtimer) {
    return RTIMER_ERR_ALREADY_SCHEDULED;
  }

  rtimer->func = func;
  rtimer->ptr = ptr;
  rtimer->time = time;
  next_rtimer = rtimer;
  rtimer_arch_schedule(time);

  return RTIMER_OK;
}
/*---------------------------------------------------------------------------*/
void
rtimer_run_next(void)
{
  struct rtimer *t;

  if(!(t = next_rtimer)) {
    return;
  }
  next_rtimer = NULL;
  t->func(t, t->ptr);
}
/*---------------------------------------------------------------------------*/
static void
subtract_and_compare(rtimer_clock_t a, rtimer_clock_t b,
    rtimer_clock_t *delta, int *smaller_or_equal)
{
  if(a == b) {
    *delta = 0;
    *smaller_or_equal = 1;
  } else if(a < b) {
    if((b - a) > (max_rtimer_value / 2)) {
      /* we assume that a wrapped around zero */
      *delta = a + 1 + (max_rtimer_value - b);
      *smaller_or_equal = 0;
    } else {
      *delta = b - a;
      *smaller_or_equal = 1;
    }
  } else {
    if((a - b) > (max_rtimer_value / 2)) {
      /* we assume that b wrapped around zero */
      *delta = b + 1 + (max_rtimer_value - a);
      *smaller_or_equal = 1;
    } else {
      *delta = a - b;
      *smaller_or_equal = 0;
    }
  }
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
rtimer_delta(rtimer_clock_t a, rtimer_clock_t b)
{
  rtimer_clock_t delta;
  int smaller_or_equal;

  subtract_and_compare(a, b, &delta, &smaller_or_equal);
  return delta;
}
/*---------------------------------------------------------------------------*/
int
rtimer_smaller_or_equal(rtimer_clock_t a, rtimer_clock_t b)
{
  rtimer_clock_t delta;
  int smaller_or_equal;

  subtract_and_compare(a, b, &delta, &smaller_or_equal);
  return smaller_or_equal;
}
/*---------------------------------------------------------------------------*/
int
rtimer_has_timed_out(rtimer_clock_t timeout)
{
  return rtimer_smaller_or_equal(timeout, RTIMER_NOW());
}
/*---------------------------------------------------------------------------*/
int
rtimer_is_schedulable(rtimer_clock_t start_time, rtimer_clock_t guard_time)
{
  return !rtimer_has_timed_out(start_time)
      && rtimer_delta(RTIMER_NOW(), start_time) >= guard_time;
}
/*---------------------------------------------------------------------------*/

/** @}*/
