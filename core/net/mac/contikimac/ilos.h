/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
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
 *         Intra-Layer Optimization for 802.15.4 Security (ILOS)
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef ILOS_H_
#define ILOS_H_

#include "contiki.h"
#include "sys/rtimer.h"
#include "net/llsec/wake-up-counter.h"

#ifdef ILOS_CONF_ENABLED
#define ILOS_ENABLED ILOS_CONF_ENABLED
#else /* ILOS_CONF_ENABLED */
#define ILOS_ENABLED 0
#endif /* ILOS_CONF_ENABLED */

#define ILOS_MIN_TIME_TO_STROBE US_TO_RTIMERTICKS(2000)
#if ILOS_ENABLED
#define ILOS_WAKE_UP_COUNTER_LEN (4)
#else /* ILOS_ENABLED */
#define ILOS_WAKE_UP_COUNTER_LEN (0)
#endif /* ILOS_ENABLED */

struct secrdc_phase {
  rtimer_clock_t t;
#if ILOS_ENABLED
  wake_up_counter_t his_wake_up_counter_at_t;
#endif /* ILOS_ENABLED */
};

#endif /* ILOS_H_ */
