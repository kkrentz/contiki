/*
 * Copyright (c) 2018, Hasso-Plattner-Institut.
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
 *         Coordinated Sampled Listening (CSL)
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef CSL_H_
#define CSL_H_

#include "net/mac/rdc.h"
#include "net/llsec/wake-up-counter.h"
#include "lib/leaky-bucket.h"
#include "dev/radio-async.h"
#include "sys/rtimer.h"

#ifdef CSL_CONF_ENABLED
#define CSL_ENABLED CSL_CONF_ENABLED
#else /* CSL_CONF_ENABLED */
#define CSL_ENABLED 0
#endif /* CSL_CONF_ENABLED */

#define CSL_MAX_RETRANSMISSION_DELAY (15) /* seconds */
#define CSL_ACKNOWLEDGEMENT_WINDOW_MIN \
    (RADIO_ASYNC_RECEIVE_CALIBRATION_TIME - 1 + RADIO_ASYNC_SHR_TIME - 1)
#define CSL_ACKNOWLEDGEMENT_WINDOW_MAX \
    (RADIO_ASYNC_RECEIVE_CALIBRATION_TIME + RADIO_ASYNC_SHR_TIME + 1)
#define CSL_ACKNOWLEDGEMENT_WINDOW (CSL_ACKNOWLEDGEMENT_WINDOW_MAX \
    - CSL_ACKNOWLEDGEMENT_WINDOW_MIN \
    + 1)
#define CSL_NEGATIVE_SYNC_GUARD_TIME (2 /* sender side */ \
    + 2 /* receiver side */ \
    + CSL_ACKNOWLEDGEMENT_WINDOW /* allow for pulse-delay attacks */)
#define CSL_POSITIVE_SYNC_GUARD_TIME (2 + 2)
#define CSL_CLOCK_TOLERANCE (15) /* ppm */
#define CSL_COMPENSATION_TOLERANCE (3) /* ppm */
#define CSL_MIN_TIME_BETWEEN_DRIFT_UPDATES (50) /* seconds */
#define CSL_MAX_OVERALL_UNCERTAINTY (US_TO_RTIMERTICKS(2000) \
    + CSL_NEGATIVE_SYNC_GUARD_TIME \
    + CSL_POSITIVE_SYNC_GUARD_TIME)
#define CSL_INITIAL_UPDATE_THRESHOLD ( \
    RTIMERTICKS_TO_S( \
    ((CSL_MAX_OVERALL_UNCERTAINTY - CSL_NEGATIVE_SYNC_GUARD_TIME - CSL_POSITIVE_SYNC_GUARD_TIME) \
    * (uint32_t)1000000) / (2 * CSL_CLOCK_TOLERANCE)) \
    - CSL_MAX_RETRANSMISSION_DELAY)
#define CSL_SUBSEQUENT_UPDATE_THRESHOLD MIN(300, \
    RTIMERTICKS_TO_S( \
    ((CSL_MAX_OVERALL_UNCERTAINTY - CSL_NEGATIVE_SYNC_GUARD_TIME - CSL_POSITIVE_SYNC_GUARD_TIME) \
    * (uint32_t)1000000) / CSL_COMPENSATION_TOLERANCE) \
    - CSL_MAX_RETRANSMISSION_DELAY)

struct csl_sync_data {
  rtimer_clock_t t;
  wake_up_counter_t his_wake_up_counter_at_t;
};

rtimer_clock_t csl_get_payload_frames_shr_end(void);
rtimer_clock_t csl_get_last_sfd_timestamp(void);
enum csl_framer_subtype csl_get_last_wake_up_frames_subtype(void);
rtimer_clock_t csl_get_phase(rtimer_clock_t t);
wake_up_counter_t csl_get_wake_up_counter(rtimer_clock_t t);
wake_up_counter_t csl_predict_wake_up_counter(void);
wake_up_counter_t csl_restore_wake_up_counter(void);
extern wake_up_counter_t csl_wake_up_counter;
extern const struct rdc_driver csl_driver;
extern struct leaky_bucket csl_hello_inc_bucket;
extern struct leaky_bucket csl_helloack_inc_bucket;

#endif /* CSL_H_ */
