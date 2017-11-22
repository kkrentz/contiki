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
 *         Framing-related functionality.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef CSL_FRAMER_H_
#define CSL_FRAMER_H_

#include "contiki.h"
#include "net/mac/framer.h"
#include "net/mac/csl/csl.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/linkaddr.h"
#include "dev/radio-async.h"

#ifdef CSL_FRAMER_CONF_OTP_LEN
#define CSL_FRAMER_OTP_LEN CSL_FRAMER_CONF_OTP_LEN
#else /* CSL_FRAMER_CONF_OTP_LEN */
#define CSL_FRAMER_OTP_LEN 2
#endif /* CSL_FRAMER_CONF_OTP_LEN */

#define CSL_FRAMER_PAN_ID_LEN (2)
#define CSL_FRAMER_PHASE_LEN (2)
#define CSL_FRAMER_AUTHENTICATED_ACKNOWLEDGEMENT_LEN (1 /* frame type */ + CSL_FRAMER_PHASE_LEN + ADAPTIVESEC_UNICAST_MIC_LEN)
#define CSL_FRAMER_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN (1 /* frame type */)
#define CSL_FRAMER_MAX_ACKNOWLEDGEMENT_LEN (MAX(CSL_FRAMER_AUTHENTICATED_ACKNOWLEDGEMENT_LEN, CSL_FRAMER_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN))
#define CSL_FRAMER_LONG_RENDEZVOUS_TIME_LEN (2)
#define CSL_FRAMER_SHORT_RENDEZVOUS_TIME_LEN (1)
#define CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN (1)
#define CSL_FRAMER_PAYLOAD_FRAMES_LEN_LEN (1)
#define CSL_FRAMER_SOURCE_INDEX_LEN (1)
#define CSL_FRAMER_HELLO_WAKE_UP_FRAME_LEN (RADIO_ASYNC_PHY_HEADER_LEN \
    + CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN \
    + CSL_FRAMER_PAN_ID_LEN \
    + CSL_FRAMER_LONG_RENDEZVOUS_TIME_LEN)
#define CSL_FRAMER_HELLOACK_WAKE_UP_FRAME_LEN (RADIO_ASYNC_PHY_HEADER_LEN \
    + CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN \
    + CSL_FRAMER_PAN_ID_LEN \
    + CSL_FRAMER_SHORT_RENDEZVOUS_TIME_LEN)
#define CSL_FRAMER_ACK_WAKE_UP_FRAME_LEN (RADIO_ASYNC_PHY_HEADER_LEN \
    + CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN \
    + CSL_FRAMER_SOURCE_INDEX_LEN \
    + CSL_FRAMER_PAYLOAD_FRAMES_LEN_LEN \
    + CSL_FRAMER_OTP_LEN \
    + CSL_FRAMER_SHORT_RENDEZVOUS_TIME_LEN)
#define CSL_FRAMER_NORMAL_WAKE_UP_FRAME_LEN (CSL_FRAMER_ACK_WAKE_UP_FRAME_LEN)
#define CSL_FRAMER_MAX_WAKE_UP_FRAME_LEN \
    MAX(CSL_FRAMER_HELLO_WAKE_UP_FRAME_LEN, \
    MAX(CSL_FRAMER_HELLOACK_WAKE_UP_FRAME_LEN, \
    MAX(CSL_FRAMER_ACK_WAKE_UP_FRAME_LEN, CSL_FRAMER_NORMAL_WAKE_UP_FRAME_LEN)))
#define CSL_FRAMER_MIN_WAKE_UP_FRAME_LEN \
    MIN(CSL_FRAMER_HELLO_WAKE_UP_FRAME_LEN, \
    MIN(CSL_FRAMER_HELLOACK_WAKE_UP_FRAME_LEN, \
    MIN(CSL_FRAMER_ACK_WAKE_UP_FRAME_LEN, CSL_FRAMER_NORMAL_WAKE_UP_FRAME_LEN)))
#define CSL_FRAMER_FRAME_TYPE (0x7 /* extended */ | (0x6 << 3) /* unused extended frame type 110 */)
#define CSL_FRAMER_MAX_XOR_LEN (CSL_FRAMER_MAX_WAKE_UP_FRAME_LEN \
    - RADIO_ASYNC_PHY_HEADER_LEN \
    - CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN)
#define CSL_FRAMER_MIN_NORMAL_PAYLOAD_FRAME_LEN (CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN \
    + 1 /* sequence number */ \
    + ADAPTIVESEC_UNICAST_MIC_LEN)
#define CSL_FRAMER_ACK_PAYLOAD_FRAME_LEN (CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN \
    + AKES_ACK_DATALEN)

#if CSL_ENABLED
#define CSL_FRAMER_HELLO_PIGGYBACK_LEN (WAKE_UP_COUNTER_LEN)
#define CSL_FRAMER_HELLOACK_PIGGYBACK_LEN (CSL_FRAMER_PHASE_LEN + WAKE_UP_COUNTER_LEN + AKES_NBR_CHALLENGE_LEN)
#define CSL_FRAMER_ACK_PIGGYBACK_LEN (CSL_FRAMER_PHASE_LEN + AKES_NBR_CHALLENGE_LEN)
#else /* CSL_ENABLED */
#define CSL_FRAMER_HELLO_PIGGYBACK_LEN (0)
#define CSL_FRAMER_HELLOACK_PIGGYBACK_LEN (0)
#define CSL_FRAMER_ACK_PIGGYBACK_LEN (0)
#endif /* CSL_ENABLED */

enum csl_framer_subtype {
  CSL_FRAMER_SUBTYPE_HELLO = 0,
  CSL_FRAMER_SUBTYPE_HELLOACK = 1,
  CSL_FRAMER_SUBTYPE_ACK = 2,
  CSL_FRAMER_SUBTYPE_NORMAL = 3,
};

uint8_t csl_framer_get_rendezvous_time_len(enum csl_framer_subtype subtype);
int csl_framer_has_destination_pan_id(enum csl_framer_subtype subtype);
int csl_framer_has_otp_etc(enum csl_framer_subtype subtype);
uint8_t csl_framer_length_of_wake_up_frame(enum csl_framer_subtype subtype);
void csl_framer_write_phase(uint8_t *dst, rtimer_clock_t phase);
rtimer_clock_t csl_framer_parse_phase(uint8_t *src);
int csl_framer_get_payload_frame_header_len(enum csl_framer_subtype subtype, int frame_pending);
void csl_framer_set_seqno(struct akes_nbr *receiver);
int csl_framer_received_duplicate(void);
extern const struct framer csl_framer;

#endif /* CSL_FRAMER_H_ */
