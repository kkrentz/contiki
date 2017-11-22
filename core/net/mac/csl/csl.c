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

#include "net/mac/csl/csl.h"
#include "net/mac/csl/csl-framer.h"
#include "net/mac/csl/csl-ccm-inputs.h"
#include "net/mac/csl/csl-strategy.h"
#include "net/mac/mac.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "lib/aes-128.h"
#include "net/nbr-table.h"
#include "lib/random.h"
#ifdef LPM_CONF_ENABLE
#include "lpm.h"
#endif /* LPM_CONF_ENABLE */

#ifdef CSL_CONF_MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS CSL_CONF_MAX_RETRANSMISSIONS
#else /* CSL_CONF_MAX_RETRANSMISSIONS */
#define MAX_RETRANSMISSIONS 5
#endif /* CSL_CONF_MAX_RETRANSMISSIONS */

#ifdef CSL_CONF_CHANNELS
#define CHANNELS CSL_CONF_CHANNELS
#else /* CSL_CONF_CHANNELS */
#define CHANNELS { 11 , 12 , 13 , 14 , 15 , 16 , 17 , 18 , 19 , 20 , 21 , 22 , 23 , 24 , 25 , 26 }
#endif /* CSL_CONF_CHANNELS */

#ifdef CSL_CONF_OUTPUT_POWER
#define OUTPUT_POWER CSL_CONF_OUTPUT_POWER
#else /* CSL_CONF_OUTPUT_POWER */
#define OUTPUT_POWER (0)
#endif /* CSL_CONF_OUTPUT_POWER */

#ifdef CSL_CONF_CCA_THRESHOLD
#define CCA_THRESHOLD CSL_CONF_CCA_THRESHOLD
#else /* CSL_CONF_CCA_THRESHOLD */
#define CCA_THRESHOLD (-81)
#endif /* CSL_CONF_CCA_THRESHOLD */

#ifdef CSL_CONF_MAX_BURST_INDEX
#define MAX_BURST_INDEX CSL_CONF_MAX_BURST_INDEX
#else /* CSL_CONF_MAX_BURST_INDEX */
#define MAX_BURST_INDEX (3)
#endif /* CSL_CONF_MAX_BURST_INDEX */

#ifdef CSL_CONF_MAX_CONSECUTIVE_INC_HELLOS
#define MAX_CONSECUTIVE_INC_HELLOS CSL_CONF_MAX_CONSECUTIVE_INC_HELLOS
#else /* CSL_CONF_MAX_CONSECUTIVE_INC_HELLOS */
#define MAX_CONSECUTIVE_INC_HELLOS (20)
#endif /* CSL_CONF_MAX_CONSECUTIVE_INC_HELLOS */

#ifdef CSL_CONF_MAX_INC_HELLO_RATE
#define MAX_INC_HELLO_RATE CSL_CONF_MAX_INC_HELLO_RATE
#else /* CSL_CONF_MAX_INC_HELLO_RATE */
#define MAX_INC_HELLO_RATE (15) /* 1 HELLO per 15s */
#endif /* CSL_CONF_MAX_INC_HELLO_RATE */

#ifdef CSL_CONF_MAX_CONSECUTIVE_INC_HELLOACKS
#define MAX_CONSECUTIVE_INC_HELLOACKS CSL_CONF_MAX_CONSECUTIVE_INC_HELLOACKS
#else /* CSL_CONF_MAX_CONSECUTIVE_INC_HELLOACKS */
#define MAX_CONSECUTIVE_INC_HELLOACKS (20)
#endif /* CSL_CONF_MAX_CONSECUTIVE_INC_HELLOACKS */

#ifdef CSL_CONF_MAX_INC_HELLOACK_RATE
#define MAX_INC_HELLOACK_RATE CSL_CONF_MAX_INC_HELLOACK_RATE
#else /* CSL_CONF_MAX_INC_HELLOACK_RATE */
#define MAX_INC_HELLOACK_RATE (8) /* 1 HELLOACK per 8s */
#endif /* CSL_CONF_MAX_INC_HELLOACK_RATE */

/* TODO handle these CC2538-specific adjustments in rtimer.c */
#define LPM_SWITCHING (2)
#define LPM_DEEP_SWITCHING (2)
#ifdef LPM_CONF_ENABLE
#if LPM_CONF_ENABLE
#if (LPM_CONF_MAX_PM == LPM_PM0)
#elif (LPM_CONF_MAX_PM == LPM_PM1)
#undef LPM_SWITCHING
#define LPM_SWITCHING (9)
#undef LPM_DEEP_SWITCHING
#define LPM_DEEP_SWITCHING (13)
#elif (LPM_CONF_MAX_PM == LPM_PM2)
#undef LPM_SWITCHING
#define LPM_SWITCHING (13)
#undef LPM_DEEP_SWITCHING
#define LPM_DEEP_SWITCHING (13)
#else
#warning unsupported power mode
#endif
#endif /* LPM_CONF_ENABLE */
#endif /* LPM_CONF_ENABLE */

#define MIN_BACK_OFF_EXPONENT 2
#define MAX_BACK_OFF_EXPONENT 5
#define WAKE_UP_FRAME_FIFOP_THRESHOLD (1 + 1)
#define SCAN_DURATION (RADIO_ASYNC_TIME_TO_TRANSMIT(RADIO_ASYNC_SYMBOLS_PER_BYTE \
    * (CSL_FRAMER_MAX_WAKE_UP_FRAME_LEN + RADIO_ASYNC_SHR_LEN)) + 2)
#define FRAME_CREATION_TIME (US_TO_RTIMERTICKS(1000))
#define COLLISION_AVOIDANCE_DURATION \
    (RADIO_ASYNC_RECEIVE_CALIBRATION_TIME + RADIO_ASYNC_CCA_TIME - 2)
#define WAKE_UP_SEQUENCE_GUARD_TIME (LPM_SWITCHING \
    + COLLISION_AVOIDANCE_DURATION \
    + RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME \
    - 1)
#define NEGATIVE_RENDEZVOUS_TIME_ACCURACY (2)
#define POSITIVE_RENDEZVOUS_TIME_ACCURACY (2)
#define RENDEZVOUS_GUARD_TIME (LPM_SWITCHING \
    + NEGATIVE_RENDEZVOUS_TIME_ACCURACY \
    + RADIO_ASYNC_RECEIVE_CALIBRATION_TIME)
#define LATE_WAKE_UP_GUARD_TIME (US_TO_RTIMERTICKS(10000))
#define LATE_RENDEZVOUS_TRESHOLD (US_TO_RTIMERTICKS(20000))
#define WAKE_UP_SEQUENCE_LENGTH(uncertainty, wake_up_frame_len) ((uint32_t) \
    (((((uint64_t)uncertainty) * 1000 * 1000 / RTIMER_ARCH_SECOND) \
    / (RADIO_ASYNC_BYTE_PERIOD * wake_up_frame_len)) \
    + 1 /* round up */ \
    + 1 /* once more */))
#define HELLO_WAKE_UP_SEQUENCE_LENGTH WAKE_UP_SEQUENCE_LENGTH( \
    WAKE_UP_COUNTER_INTERVAL * sizeof(channels), \
    CSL_FRAMER_HELLO_WAKE_UP_FRAME_LEN)
#define HELLO_WAKE_UP_SEQUENCE_TRANSMISSION_TIME RADIO_ASYNC_TIME_TO_TRANSMIT( \
    HELLO_WAKE_UP_SEQUENCE_LENGTH \
    * CSL_FRAMER_HELLO_WAKE_UP_FRAME_LEN \
    * RADIO_ASYNC_SYMBOLS_PER_BYTE)
#define MIN_PREPARE_LEAD_OVER_LOOP (10)
#define SFD (0xA7)

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

struct buffered_frame {
  struct buffered_frame *next;
  struct queuebuf *qb;
  mac_callback_t sent;
  int transmissions;
  rtimer_clock_t next_attempt;
  void *ptr;
};

struct late_rendezvous {
  struct late_rendezvous *next;
  rtimer_clock_t time;
  enum csl_framer_subtype subtype;
  uint8_t channel;
};

static void schedule_duty_cycle(rtimer_clock_t time);
static uint8_t get_channel(void);
static void set_channel(wake_up_counter_t wuc, const linkaddr_t *addr);
static void duty_cycle_wrapper(struct rtimer *t, void *ptr);
static char duty_cycle(void);
static void on_sfd(void);
static void on_wake_up_frame_fifop(void);
static int parse_wake_up_frame(void);
static void on_payload_frame_fifop(void);
static void prepare_acknowledgement(void);
static void on_final_payload_frame_fifop(void);
static void on_txdone(void);
static void delay_any_frames_to(const linkaddr_t *receiver, rtimer_clock_t next_attempt);
static struct buffered_frame *select_next_frame_to_transmit(void);
static struct buffered_frame *select_next_burst_frame(struct buffered_frame *bf);
static int create_wake_up_frame(uint8_t *dst);
static uint8_t prepare_next_wake_up_frames(uint8_t space);
static void schedule_transmission(rtimer_clock_t time);
static void transmit_wrapper(struct rtimer *rt, void *ptr);
static char transmit(void);
static int validate_acknowledgement(void);
static void on_transmitted(void);
static void send_list(mac_callback_t sent,
    void *ptr,
    struct rdc_buf_list *list);
static void try_skip_to_send(void);
static void queue_frame(mac_callback_t sent, void *ptr);
static rtimer_clock_t get_last_wake_up_time(void);

static union {
  struct {
    enum csl_framer_subtype subtype;
    uint16_t remaining_wake_up_frames;
    uint8_t next_frames_len;
    int got_wake_up_frames_shr;
    int waiting_for_wake_up_frames_shr;
    int left_radio_on;
    int waiting_for_unwanted_shr;
    int got_rendezvous_time;
    rtimer_clock_t rendezvous_time;
    int skip_to_rendezvous;
    int waiting_for_payload_frames_shr;
    int got_payload_frames_shr;
    int rejected_payload_frame;
    rtimer_clock_t wake_up_frame_timeout;
    linkaddr_t sender;
    int shall_send_acknowledgement;
    int received_frame;
    uint8_t last_burst_index;
    uint8_t acknowledgement[1 /* Frame Length */ + CSL_FRAMER_MAX_ACKNOWLEDGEMENT_LEN];
    struct packetbuf local_packetbuf[MAX_BURST_INDEX + 1];
    struct packetbuf *actual_packetbuf[MAX_BURST_INDEX + 1];
  } duty_cycle;

  struct {
    enum csl_framer_subtype subtype;
    uint8_t wake_up_frame_len;
    uint8_t rendezvous_time_len;
    struct buffered_frame *bf[MAX_BURST_INDEX + 1];
    int result[MAX_BURST_INDEX + 1];
    uint8_t last_burst_index;
    uint8_t burst_index;
    wake_up_counter_t receivers_wake_up_counter;
    rtimer_clock_t wake_up_sequence_start;
    uint16_t remaining_wake_up_frames;
    uint8_t wrote_payload_frames_phy_header;
    uint8_t remaining_payload_frame_bytes;
    uint8_t next_wake_up_frames[RADIO_ASYNC_LOOP_LEN];
    uint32_t wake_up_sequence_pos;
    rtimer_clock_t payload_frame_start;
    rtimer_clock_t next_rendezvous_time_update;
    uint8_t payload_frame[MAX_BURST_INDEX + 1][1 /* Frame Length */ + RADIO_ASYNC_MAX_FRAME_LEN];
    uint8_t acknowledgement_key[AES_128_KEY_LENGTH];
    uint8_t acknowledgement_nonce[CCM_STAR_NONCE_LENGTH];
    rtimer_clock_t acknowledgement_sfd_timestamp;
    rtimer_clock_t acknowledgement_phase;
    int waiting_for_acknowledgement_shr;
    int got_acknowledgement_shr;
    int is_waiting_for_txdone;
  } transmit;
} u;
const uint8_t shr[] = { 0x00 , 0x00 , 0x00 , 0x00 , SFD };
static const uint8_t channels[] = CHANNELS;
MEMB(buffered_frames_memb, struct buffered_frame, QUEUEBUF_NUM);
LIST(buffered_frames_list);
MEMB(late_rendezvous_memb, struct late_rendezvous, sizeof(channels));
LIST(late_rendezvous_list);
static struct rtimer timer;
static rtimer_clock_t duty_cycle_next;
static struct pt pt;
static int is_duty_cycling;
static int is_transmitting;
static int can_skip;
static int skipped;
PROCESS(post_processing, "post processing");
static volatile rtimer_clock_t sfd_timestamp;
static rtimer_clock_t wake_up_counter_last_increment;
wake_up_counter_t csl_wake_up_counter;
struct leaky_bucket csl_hello_inc_bucket;
struct leaky_bucket csl_helloack_inc_bucket;

/*---------------------------------------------------------------------------*/
static void
clear_missed_late_rendezvous(void)
{
  struct late_rendezvous *next;
  struct late_rendezvous *current;

  next = list_head(late_rendezvous_list);
  while(next) {
    current = next;
    next = list_item_next(current);
    if(!rtimer_is_schedulable(current->time
        - RENDEZVOUS_GUARD_TIME
        - (LPM_DEEP_SWITCHING - LPM_SWITCHING),
        RTIMER_GUARD_TIME + 2)) {
      list_remove(late_rendezvous_list, current);
      memb_free(&late_rendezvous_memb, current);
      PRINTF("csl: forgot late rendezvous\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
static struct late_rendezvous *
get_nearest_late_rendezvous(void)
{
  struct late_rendezvous *nearest;
  struct late_rendezvous *next;

  clear_missed_late_rendezvous();
  nearest = next = list_head(late_rendezvous_list);
  while(nearest && ((next = list_item_next(next)))) {
    if(rtimer_smaller_or_equal(next->time, nearest->time)) {
      nearest = next;
    }
  }
  return nearest;
}
/*---------------------------------------------------------------------------*/
static int
has_late_rendezvous_on_channel(uint8_t channel)
{
  struct late_rendezvous *lr;

  clear_missed_late_rendezvous();
  lr = list_head(late_rendezvous_list);
  while(lr) {
    if(lr->channel == channel) {
      return 1;
    }
    lr = list_item_next(lr);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
enable_local_packetbuf(uint8_t burst_index)
{
  u.duty_cycle.actual_packetbuf[burst_index] = packetbuf;
  packetbuf = &u.duty_cycle.local_packetbuf[burst_index];
}
/*---------------------------------------------------------------------------*/
static void
disable_local_packetbuf(uint8_t burst_index)
{
  packetbuf = u.duty_cycle.actual_packetbuf[burst_index];
}
/*---------------------------------------------------------------------------*/
static rtimer_clock_t
shift_to_future(rtimer_clock_t time)
{
  /* we assume that WAKE_UP_COUNTER_INTERVAL is a power of 2 */
  time = (RTIMER_NOW() & (~(WAKE_UP_COUNTER_INTERVAL - 1)))
      | (time & (WAKE_UP_COUNTER_INTERVAL - 1));
  while(!rtimer_is_schedulable(time, RTIMER_GUARD_TIME + 1)) {
    time += WAKE_UP_COUNTER_INTERVAL;
  }

  return time;
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  leaky_bucket_init(&csl_hello_inc_bucket,
      MAX_CONSECUTIVE_INC_HELLOS,
      MAX_INC_HELLO_RATE);
  leaky_bucket_init(&csl_helloack_inc_bucket,
      MAX_CONSECUTIVE_INC_HELLOACKS,
      MAX_INC_HELLOACK_RATE);
  memb_init(&buffered_frames_memb);
  list_init(buffered_frames_list);
  memb_init(&late_rendezvous_memb);
  list_init(late_rendezvous_list);
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_SFD_CALLBACK, on_sfd, 0);
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_TXDONE_CALLBACK, on_txdone, 0);
  NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_TXPOWER, OUTPUT_POWER);
  process_start(&post_processing, NULL);
  PT_INIT(&pt);
  duty_cycle_next = RTIMER_NOW() + WAKE_UP_COUNTER_INTERVAL;
  schedule_duty_cycle(duty_cycle_next - LPM_DEEP_SWITCHING);
}
/*---------------------------------------------------------------------------*/
static void
schedule_duty_cycle(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, duty_cycle_wrapper, NULL) != RTIMER_OK) {
    PRINTF("csl: rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
set_channel(wake_up_counter_t wuc, const linkaddr_t *addr)
{
  uint8_t i;
  uint8_t xored;

  xored = wuc.u8[0];
  for(i = 0; i < LINKADDR_SIZE; i++) {
    xored ^= addr->u8[i];
  }

  NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_CHANNEL,
      channels[xored & (sizeof(channels) - 1)]);
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_channel(void)
{
  radio_value_t rv;

  NETSTACK_RADIO_ASYNC.get_value(RADIO_PARAM_CHANNEL, &rv);
  return (uint8_t)rv;
}
/*---------------------------------------------------------------------------*/
static void
duty_cycle_wrapper(struct rtimer *rt, void *ptr)
{
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static char
duty_cycle(void)
{
  rtimer_clock_t last_wake_up_time;
  struct late_rendezvous *lr;

  PT_BEGIN(&pt);
#ifdef LPM_CONF_ENABLE
  lpm_set_max_pm(LPM_PM1);
#endif /* LPM_CONF_ENABLE */
  can_skip = 0;
  is_duty_cycling = 1;

  if(skipped) {
    skipped = 0;
  } else if(!u.duty_cycle.skip_to_rendezvous
      && has_late_rendezvous_on_channel(get_channel())) {
    /* skipping duty cycle */
  } else {
    if(!u.duty_cycle.skip_to_rendezvous) {
      last_wake_up_time = get_last_wake_up_time();
      csl_wake_up_counter = csl_get_wake_up_counter(last_wake_up_time);
      wake_up_counter_last_increment = last_wake_up_time;
      set_channel(csl_wake_up_counter, &linkaddr_node_addr);
      NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
          on_wake_up_frame_fifop,
          WAKE_UP_FRAME_FIFOP_THRESHOLD);

      /* if we come from PM0, we will be too early */
      while(!rtimer_has_timed_out(duty_cycle_next));

      NETSTACK_RADIO_ASYNC.on();
      u.duty_cycle.waiting_for_wake_up_frames_shr = 1;
      u.duty_cycle.wake_up_frame_timeout = RTIMER_NOW()
          + RADIO_ASYNC_RECEIVE_CALIBRATION_TIME
          + SCAN_DURATION;
      schedule_duty_cycle(u.duty_cycle.wake_up_frame_timeout);
      /* wait until timeout or on_wake_up_frame_fifop, whatever comes first */
      PT_YIELD(&pt);
      u.duty_cycle.waiting_for_wake_up_frames_shr = 0;
    }
    if(!u.duty_cycle.skip_to_rendezvous && !u.duty_cycle.got_wake_up_frames_shr) {
      NETSTACK_RADIO_ASYNC.off();
    } else {
      if(!u.duty_cycle.skip_to_rendezvous) {
        /* wait until timeout or on_wake_up_frame_fifop, whatever comes last */
        PT_YIELD(&pt);
      }
      if(u.duty_cycle.got_rendezvous_time) {
        if(!u.duty_cycle.left_radio_on
            && !u.duty_cycle.skip_to_rendezvous
            && !rtimer_smaller_or_equal(
                u.duty_cycle.rendezvous_time,
                RTIMER_NOW() + LATE_RENDEZVOUS_TRESHOLD)) {
          lr = memb_alloc(&late_rendezvous_memb);
          if(lr) {
            lr->time = u.duty_cycle.rendezvous_time;
            lr->subtype = u.duty_cycle.subtype;
            lr->channel = get_channel();
            list_add(late_rendezvous_list, lr);
          } else {
            PRINTF("csl: late_rendezvous_memb is full\n");
          }
        } else {
          NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
              on_payload_frame_fifop,
              1 + csl_framer_get_payload_frame_header_len(u.duty_cycle.subtype, 1));
          if(!u.duty_cycle.left_radio_on) {
            if(!u.duty_cycle.skip_to_rendezvous
                && rtimer_is_schedulable(
                    u.duty_cycle.rendezvous_time - RENDEZVOUS_GUARD_TIME, RTIMER_GUARD_TIME + 1)) {
              schedule_duty_cycle(u.duty_cycle.rendezvous_time - RENDEZVOUS_GUARD_TIME);
              PT_YIELD(&pt); /* wait until rendezvous */
            }
            /* if we come from PM0 we will be too early */
            while(!rtimer_has_timed_out(u.duty_cycle.rendezvous_time
                - NEGATIVE_RENDEZVOUS_TIME_ACCURACY
                - RADIO_ASYNC_RECEIVE_CALIBRATION_TIME));
            NETSTACK_RADIO_ASYNC.on();
          }
          u.duty_cycle.waiting_for_payload_frames_shr = 1;
          schedule_duty_cycle(u.duty_cycle.rendezvous_time
              + RADIO_ASYNC_SHR_TIME
              + POSITIVE_RENDEZVOUS_TIME_ACCURACY);
          while(1) {
            /* wait until timeout */
            PT_YIELD(&pt);
            u.duty_cycle.waiting_for_payload_frames_shr = 0;

            if(!u.duty_cycle.got_payload_frames_shr) {
              PRINTF("csl: missed %spayload frame %i\n",
                     u.duty_cycle.last_burst_index ? "bursted "
                  : (u.duty_cycle.skip_to_rendezvous ? "late "
                  : (u.duty_cycle.left_radio_on ? "early "
                  : "")), u.duty_cycle.remaining_wake_up_frames);
              NETSTACK_RADIO_ASYNC.off();
              u.duty_cycle.last_burst_index = u.duty_cycle.last_burst_index
                  ? u.duty_cycle.last_burst_index - 1
                  : 0;
              break;
            }

            PT_YIELD(&pt); /* wait until on_payload_frame_fifop */
            if(u.duty_cycle.rejected_payload_frame) {
              u.duty_cycle.last_burst_index = u.duty_cycle.last_burst_index
                  ? u.duty_cycle.last_burst_index - 1
                  : 0;
              break;
            }

            PT_YIELD(&pt); /* wait until on_final_payload_frame_fifop or on_txdone */
            if(!u.duty_cycle.next_frames_len
                || (u.duty_cycle.last_burst_index >= MAX_BURST_INDEX)) {
              break;
            }

            u.duty_cycle.last_burst_index++;
            NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
                on_payload_frame_fifop,
                1 + csl_framer_get_payload_frame_header_len(CSL_FRAMER_SUBTYPE_NORMAL, 1));
            u.duty_cycle.got_payload_frames_shr = 0;
            u.duty_cycle.waiting_for_payload_frames_shr = 1;
            u.duty_cycle.left_radio_on = 0;
            u.duty_cycle.remaining_wake_up_frames = 0;
            schedule_duty_cycle(RTIMER_NOW() + CSL_ACKNOWLEDGEMENT_WINDOW_MAX);
          }
        }
      }
    }
    NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 0);
    NETSTACK_RADIO_ASYNC.flushrx();
  }

  is_duty_cycling = 0;
  process_poll(&post_processing);

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static void
on_sfd(void)
{
  rtimer_clock_t now;
  uint8_t wake_up_frame_len;
  uint8_t wake_up_frame[CSL_FRAMER_MAX_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN];

  now = RTIMER_NOW();

  if(is_duty_cycling) {
    if(u.duty_cycle.waiting_for_unwanted_shr) {
      u.duty_cycle.waiting_for_unwanted_shr = 0;
    } else if(u.duty_cycle.waiting_for_wake_up_frames_shr) {
      u.duty_cycle.got_wake_up_frames_shr = 1;
      sfd_timestamp = now;
      if(rtimer_is_schedulable(u.duty_cycle.wake_up_frame_timeout, RTIMER_GUARD_TIME + 1)) {
        rtimer_arch_schedule(now);
      }
    } else if(u.duty_cycle.waiting_for_payload_frames_shr) {
      if(u.duty_cycle.left_radio_on && u.duty_cycle.remaining_wake_up_frames) {
        wake_up_frame_len = csl_framer_length_of_wake_up_frame(u.duty_cycle.subtype);
        if(NETSTACK_RADIO_ASYNC.read_phy_header() != wake_up_frame_len) {
          return;
        } else {
          NETSTACK_RADIO_ASYNC.read_raw(wake_up_frame, wake_up_frame_len);
        }
      }
      u.duty_cycle.got_payload_frames_shr = 1;
      sfd_timestamp = now;
#if DEBUG
      if(!u.duty_cycle.last_burst_index
          && (rtimer_delta(now, u.duty_cycle.rendezvous_time + RADIO_ASYNC_SHR_TIME) > 1)) {
        PRINTF("csl: rendezvous timing expected: %lu actual: %lu\n",
            u.duty_cycle.rendezvous_time + RADIO_ASYNC_SHR_TIME,
            now);
      }
#endif /* DEBUG */
    }
  } else if(is_transmitting) {
    if(u.transmit.waiting_for_acknowledgement_shr) {
      u.transmit.got_acknowledgement_shr = 1;
      if(!u.transmit.burst_index) {
        u.transmit.acknowledgement_sfd_timestamp = now;
      }
    } else {
      sfd_timestamp = now;
    }
  }
}
/*---------------------------------------------------------------------------*/
static int
is_anything_locked(void)
{
  return aes_128_locked || akes_nbr_locked || nbr_table_locked;
}
/*---------------------------------------------------------------------------*/
static void
on_wake_up_frame_fifop(void)
{
  if(!u.duty_cycle.got_wake_up_frames_shr) {
    return;
  }

  /* avoid that on_fifop is called twice */
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 0);
  enable_local_packetbuf(0);
  u.duty_cycle.got_rendezvous_time = parse_wake_up_frame();
  if(!u.duty_cycle.got_rendezvous_time
      || (u.duty_cycle.remaining_wake_up_frames >= 2)) {
    NETSTACK_RADIO_ASYNC.off();
    NETSTACK_RADIO_ASYNC.flushrx();
  } else {
    u.duty_cycle.left_radio_on = 1;
    if(u.duty_cycle.remaining_wake_up_frames == 1) {
      u.duty_cycle.waiting_for_unwanted_shr = 1;
    }
  }
  disable_local_packetbuf(0);

  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static int
parse_wake_up_frame(void)
{
  uint8_t datalen;
  uint8_t *dataptr;
  uint16_t dst_pid;
  struct akes_nbr_entry *entry;
  struct akes_nbr *nbr;
  uint32_t rendezvous_time_symbol_periods;
  rtimer_clock_t rendezvous_time_rtimer_ticks;
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  uint8_t otp[CSL_FRAMER_OTP_LEN];
  uint8_t rendezvous_time_len;

  datalen = NETSTACK_RADIO_ASYNC.read_phy_header_and_set_datalen();
  if((datalen > (CSL_FRAMER_MAX_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN))
      || (datalen < (CSL_FRAMER_MIN_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN))) {
    PRINTF("csl: invalid wake-up frame\n");
    return 0;
  }

  dataptr = packetbuf_dataptr();

  /* extended frame type and subtype */
  if(!NETSTACK_RADIO_ASYNC.read_payload(CSL_FRAMER_EXTENDED_FRAME_TYPE_LEN)) {
    PRINTF("csl: could not read at line %i\n", __LINE__);
    return 0;
  }
  if((dataptr[0] & 0x3F) != CSL_FRAMER_FRAME_TYPE) {
    PRINTF("csl: invalid frame type\n");
    return 0;
  }
  u.duty_cycle.subtype = (dataptr[0] >> 6) & 3;
  if(datalen != (csl_framer_length_of_wake_up_frame(u.duty_cycle.subtype))) {
    PRINTF("csl: invalid length\n");
    return 0;
  }
  dataptr++;

  /* destination PAN ID */
  if(csl_framer_has_destination_pan_id(u.duty_cycle.subtype)) {
    if(!NETSTACK_RADIO_ASYNC.read_payload(CSL_FRAMER_PAN_ID_LEN)) {
      PRINTF("csl: could not read at line %i\n", __LINE__);
      return 0;
    }
    dst_pid = (dataptr[0] ^ get_channel()) | (dataptr[1] << 8);
    if((dst_pid != IEEE802154_PANID)
        && (dst_pid != FRAME802154_BROADCASTPANDID)) {
      PRINTF("csl: for another PAN %04x\n", dst_pid);
      return 0;
    }
    dataptr += CSL_FRAMER_PAN_ID_LEN;
  }

  switch(u.duty_cycle.subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
    if(leaky_bucket_is_full(&csl_hello_inc_bucket)) {
      PRINTF("csl: HELLO bucket is full\n");
      return 0;
    }
    break;
  case CSL_FRAMER_SUBTYPE_HELLOACK:
    if(!akes_is_acceptable_helloack()) {
      PRINTF("csl: Unacceptable HELLOACK\n");
      return 0;
    }
    if(leaky_bucket_is_full(&csl_helloack_inc_bucket)) {
      PRINTF("csl: HELLOACK bucket is full\n");
      return 0;
    }
    break;
  default:
    break;
  }

  if(csl_framer_has_otp_etc(u.duty_cycle.subtype)) {
    /* source index */
    if(!NETSTACK_RADIO_ASYNC.read_payload(CSL_FRAMER_SOURCE_INDEX_LEN)) {
      PRINTF("csl: could not read at line %i\n", __LINE__);
      return 0;
    }
    nbr = akes_nbr_get_nbr(dataptr[0]);
    if(!nbr) {
      PRINTF("csl: invalid index\n");
      return 0;
    }
    entry = akes_nbr_get_entry_of(nbr);
    if(!entry) {
      PRINTF("csl: outdated index\n");
      return 0;
    }
    if((u.duty_cycle.subtype == CSL_FRAMER_SUBTYPE_ACK)
        && !akes_is_acceptable_ack(entry)) {
      PRINTF("csl: unacceptable ACK\n");
      return 0;
    }
    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, akes_nbr_get_addr(entry));
    CCM_STAR.set_key(nbr->pairwise_key);
    csl_ccm_inputs_generate_otp_nonce(nonce, 0);
    dataptr++;

    /* payload frame's length */
    if(!NETSTACK_RADIO_ASYNC.read_payload(CSL_FRAMER_PAYLOAD_FRAMES_LEN_LEN)) {
      PRINTF("csl: could not read at line %i\n", __LINE__);
      return 0;
    }
    u.duty_cycle.next_frames_len = dataptr[0];
    switch(u.duty_cycle.subtype) {
    case CSL_FRAMER_SUBTYPE_ACK:
      if(u.duty_cycle.next_frames_len != CSL_FRAMER_ACK_PAYLOAD_FRAME_LEN) {
        PRINTF("csl: ACK has invalid length\n");
        return 0;
      }
      break;
    case CSL_FRAMER_SUBTYPE_NORMAL:
      if(u.duty_cycle.next_frames_len <= CSL_FRAMER_MIN_NORMAL_PAYLOAD_FRAME_LEN) {
        PRINTF("csl: payload frame is too short\n");
        return 0;
      }
      break;
    default:
      break;
    }
    dataptr++;

    /* OTP */
    CCM_STAR.aead(nonce,
        NULL, 0,
        &u.duty_cycle.next_frames_len, 1,
        otp, CSL_FRAMER_OTP_LEN, 0);
    if(!NETSTACK_RADIO_ASYNC.read_payload(CSL_FRAMER_OTP_LEN)) {
      PRINTF("csl: could not read at line %i\n", __LINE__);
      return 0;
    }
    if(memcmp(otp, dataptr, CSL_FRAMER_OTP_LEN)) {
      PRINTF("csl: invalid OTP\n");
      return 0;
    }
    dataptr += CSL_FRAMER_OTP_LEN;
  }

  /* rendezvous time */
  rendezvous_time_len = csl_framer_get_rendezvous_time_len(u.duty_cycle.subtype);
  if(!NETSTACK_RADIO_ASYNC.read_payload(rendezvous_time_len)) {
    PRINTF("csl: could not read at line %i\n", __LINE__);
    return 0;
  }
  memcpy(&u.duty_cycle.remaining_wake_up_frames, dataptr, rendezvous_time_len);
  rendezvous_time_symbol_periods = (RADIO_ASYNC_SYMBOLS_PER_BYTE
          * ((uint32_t)u.duty_cycle.remaining_wake_up_frames
          * (datalen + RADIO_ASYNC_PHY_HEADER_LEN)))
      + (RADIO_ASYNC_SYMBOLS_PER_BYTE
          * (datalen + RADIO_ASYNC_PHY_HEADER_LEN - RADIO_ASYNC_SHR_LEN));
  rendezvous_time_rtimer_ticks = RADIO_ASYNC_TIME_TO_TRANSMIT(rendezvous_time_symbol_periods);
  switch(u.duty_cycle.subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
    if(u.duty_cycle.remaining_wake_up_frames >= HELLO_WAKE_UP_SEQUENCE_LENGTH) {
      PRINTF("csl: rendezvous time of HELLO is too late\n");
      return 0;
    }
    break;
  default:
    /* check upper bound maintained by SPLO-CSL */
    if(u.duty_cycle.remaining_wake_up_frames >= WAKE_UP_SEQUENCE_LENGTH(
        CSL_MAX_OVERALL_UNCERTAINTY,
        (datalen + RADIO_ASYNC_PHY_HEADER_LEN))) {
      PRINTF("csl: rendezvous time is too late\n");
      return 0;
    }
    break;
  }

  switch(u.duty_cycle.subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
    leaky_bucket_pour(&csl_hello_inc_bucket);
    break;
  case CSL_FRAMER_SUBTYPE_HELLOACK:
    leaky_bucket_pour(&csl_helloack_inc_bucket);
    break;
  default:
    break;
  }

  u.duty_cycle.rendezvous_time = csl_get_last_sfd_timestamp()
      + rendezvous_time_rtimer_ticks
      - 1;
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
on_payload_frame_fifop(void)
{
  uint8_t header_len;

  if(!u.duty_cycle.got_payload_frames_shr) {
    return;
  }

  /* avoid that on_payload_frame_fifop is called twice */
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
      NULL,
      RADIO_ASYNC_MAX_FRAME_LEN);
  enable_local_packetbuf(u.duty_cycle.last_burst_index);
  packetbuf_set_attr(PACKETBUF_ATTR_RSSI, NETSTACK_RADIO_ASYNC.get_rssi());

  if(u.duty_cycle.last_burst_index) {
    packetbuf_set_attr(PACKETBUF_ATTR_BURST_INDEX, u.duty_cycle.last_burst_index);
    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &u.duty_cycle.sender);
  }

  header_len = csl_framer_get_payload_frame_header_len(u.duty_cycle.subtype, 1);
  if(is_anything_locked()
      || (NETSTACK_RADIO_ASYNC.read_phy_header_and_set_datalen() < header_len)
      || !NETSTACK_RADIO_ASYNC.read_payload(header_len)
      || (csl_framer_has_otp_etc(u.duty_cycle.subtype)
          && (u.duty_cycle.next_frames_len != packetbuf_datalen()))
      || (NETSTACK_FRAMER.parse() == FRAMER_FAILED)) {
    NETSTACK_RADIO_ASYNC.off();
    NETSTACK_RADIO_ASYNC.flushrx();
    PRINTF("csl: rejected payload frame of length %i\n", packetbuf_datalen());
    u.duty_cycle.rejected_payload_frame = 1;
  } else {
    u.duty_cycle.next_frames_len = packetbuf_attr(PACKETBUF_ATTR_PENDING);
    linkaddr_copy(&u.duty_cycle.sender, packetbuf_addr(PACKETBUF_ADDR_SENDER));
    u.duty_cycle.shall_send_acknowledgement = !packetbuf_holds_broadcast();
    if(u.duty_cycle.shall_send_acknowledgement) {
      prepare_acknowledgement();
    }
    NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
        on_final_payload_frame_fifop,
        NETSTACK_RADIO_ASYNC.remaining_payload_bytes());
  }

  disable_local_packetbuf(u.duty_cycle.last_burst_index);

  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static void
prepare_acknowledgement(void)
{
  rtimer_clock_t acknowledgement_sfd_timestamp;
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  struct akes_nbr_entry *entry;
  uint8_t phase_len;

  u.duty_cycle.acknowledgement[1] = CSL_FRAMER_FRAME_TYPE;
  if(u.duty_cycle.subtype == CSL_FRAMER_SUBTYPE_HELLOACK) {
    u.duty_cycle.acknowledgement[0] = CSL_FRAMER_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN;
  } else {
    phase_len = u.duty_cycle.last_burst_index ? 0 : CSL_FRAMER_PHASE_LEN;
    u.duty_cycle.acknowledgement[0] = CSL_FRAMER_AUTHENTICATED_ACKNOWLEDGEMENT_LEN
        - CSL_FRAMER_PHASE_LEN
        + phase_len;
    if(phase_len) {
      acknowledgement_sfd_timestamp = sfd_timestamp
        + RADIO_ASYNC_TIME_TO_TRANSMIT(RADIO_ASYNC_SYMBOLS_PER_BYTE
            * (1 /* Frame Length */ + packetbuf_totlen() + RADIO_ASYNC_SHR_LEN))
        + RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME;
      csl_framer_write_phase(u.duty_cycle.acknowledgement + 2,
          csl_get_phase(acknowledgement_sfd_timestamp));
    }
    csl_ccm_inputs_generate_acknowledgement_nonce(nonce, 1);
    entry = akes_nbr_get_sender_entry();
    AES_128_GET_LOCK();
    CCM_STAR.set_key((u.duty_cycle.subtype == CSL_FRAMER_SUBTYPE_ACK)
        ? entry->tentative->pairwise_key
        : entry->permanent->pairwise_key);
    CCM_STAR.aead(nonce,
        NULL, 0,
        u.duty_cycle.acknowledgement + 1, 1 + phase_len,
        u.duty_cycle.acknowledgement + 1 + 1 + phase_len,
        ADAPTIVESEC_UNICAST_MIC_LEN, 1);
    AES_128_RELEASE_LOCK();
  }
  NETSTACK_RADIO_ASYNC.prepare(u.duty_cycle.acknowledgement);
}
/*---------------------------------------------------------------------------*/
static void
on_final_payload_frame_fifop(void)
{
  struct akes_nbr_entry *entry;
  int successful;

  /* avoid that on_final_payload_frame_fifop is called twice */
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 0);

  if(u.duty_cycle.shall_send_acknowledgement) {
    NETSTACK_RADIO_ASYNC.transmit();
  } else {
    NETSTACK_RADIO_ASYNC.off();
  }

  enable_local_packetbuf(u.duty_cycle.last_burst_index);

  successful =
      (NETSTACK_RADIO_ASYNC.read_payload(NETSTACK_RADIO_ASYNC.remaining_payload_bytes())
          && ((u.duty_cycle.subtype == CSL_FRAMER_SUBTYPE_HELLOACK)
              || !u.duty_cycle.shall_send_acknowledgement))
      || (!is_anything_locked()
          && ((entry = akes_nbr_get_sender_entry()))
          && (((u.duty_cycle.subtype != CSL_FRAMER_SUBTYPE_ACK)
              && entry->permanent
              && !ADAPTIVESEC_STRATEGY.verify(entry->permanent))
          || ((u.duty_cycle.subtype == CSL_FRAMER_SUBTYPE_ACK)
              && entry->tentative
              && !memcmp(((uint8_t *)packetbuf_dataptr()) + 1 + CSL_FRAMER_PHASE_LEN,
                         entry->tentative->meta->q,
                         AKES_NBR_CHALLENGE_LEN)
              && !ADAPTIVESEC_STRATEGY.verify(entry->tentative))));
  NETSTACK_RADIO_ASYNC.flushrx();

  disable_local_packetbuf(u.duty_cycle.last_burst_index);

  if(successful) {
    u.duty_cycle.received_frame = 1;
  }

  if(!u.duty_cycle.shall_send_acknowledgement) {
    duty_cycle();
  } else if(!successful) {
    /* abort acknowledgement transmission */
    NETSTACK_RADIO_ASYNC.off();
    u.duty_cycle.next_frames_len = 0;
    PRINTF("csl: flushing unicast frame\n");
    duty_cycle();
  }
}
/*---------------------------------------------------------------------------*/
static void
on_txdone(void)
{
  if(is_duty_cycling) {
    if(!u.duty_cycle.next_frames_len
        || (u.duty_cycle.last_burst_index >= MAX_BURST_INDEX)) {
      NETSTACK_RADIO_ASYNC.off();
    }
    duty_cycle();
  } else if(is_transmitting && u.transmit.is_waiting_for_txdone) {
    transmit();
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(post_processing, ev, data)
{
  rtimer_clock_t negative_uncertainty;
  rtimer_clock_t positive_uncertainty;
  struct buffered_frame *next;
  uint8_t burst_index;
  uint8_t i;
  int create_result;
  struct late_rendezvous *lr;
  uint8_t wake_up_frame[CSL_FRAMER_MAX_WAKE_UP_FRAME_LEN];
  int sent_once;
  struct csl_sync_data *sync_data;
  struct akes_nbr_entry *entry;
  int32_t drift;
  int32_t compensation;
  uint32_t seconds_since_last_sync;
  rtimer_clock_t end_of_transmission;
  uint8_t prepared_bytes;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);

    if(u.duty_cycle.received_frame) {
      for(burst_index = 0; burst_index <= u.duty_cycle.last_burst_index; burst_index++) {
        enable_local_packetbuf(burst_index);
        NETSTACK_MAC.input();
        disable_local_packetbuf(burst_index);
      }
    }

    PROCESS_PAUSE();

    /* send queued frames */
    sent_once = 0;
    while((next = select_next_frame_to_transmit())) {
      memset(&u.transmit, 0, sizeof(u.transmit));
      u.transmit.bf[0] = next;
      queuebuf_to_packetbuf(u.transmit.bf[0]->qb);

      /* schedule */
      drift = AKES_NBR_UNINITIALIZED_DRIFT;
      if(adaptivesec_is_hello()) {
        u.transmit.subtype = CSL_FRAMER_SUBTYPE_HELLO;
        /* the transmission of a HELLO's SHR has to coincide with a wake up */
        u.transmit.payload_frame_start = get_last_wake_up_time()
            - RADIO_ASYNC_SHR_TIME
            + (WAKE_UP_COUNTER_INTERVAL / 2);
        u.transmit.remaining_wake_up_frames = HELLO_WAKE_UP_SEQUENCE_LENGTH;
        do {
          u.transmit.payload_frame_start += WAKE_UP_COUNTER_INTERVAL;
          u.transmit.wake_up_sequence_start = u.transmit.payload_frame_start
              - HELLO_WAKE_UP_SEQUENCE_TRANSMISSION_TIME;
        } while(!rtimer_is_schedulable(u.transmit.wake_up_sequence_start,
            FRAME_CREATION_TIME + WAKE_UP_SEQUENCE_GUARD_TIME + RTIMER_GUARD_TIME + 2));
        sync_data = NULL;
      } else if(adaptivesec_is_helloack()) {
        u.transmit.subtype = CSL_FRAMER_SUBTYPE_HELLOACK;
        entry = akes_nbr_get_receiver_entry();
        if(!entry || !entry->tentative) {
          PRINTF("csl: HELLOACK receiver has gone\n");
          u.transmit.result[0] = MAC_TX_ERR_FATAL;
          on_transmitted();
          continue;
        }
        sync_data = &entry->tentative->sync_data;
      } else {
        u.transmit.subtype = adaptivesec_is_ack()
            ? CSL_FRAMER_SUBTYPE_ACK
            : CSL_FRAMER_SUBTYPE_NORMAL;
        entry = akes_nbr_get_receiver_entry();
        if(!entry || !entry->permanent) {
          PRINTF("csl: receiver has gone\n");
          u.transmit.result[0] = MAC_TX_ERR_FATAL;
          on_transmitted();
          continue;
        }
        sync_data = &entry->permanent->sync_data;
        drift = entry->permanent->drift;
      }
      u.transmit.wake_up_frame_len = csl_framer_length_of_wake_up_frame(u.transmit.subtype)
          + RADIO_ASYNC_PHY_HEADER_LEN;
      if(u.transmit.subtype != CSL_FRAMER_SUBTYPE_HELLO) {
        /* calculate uncertainty */
        seconds_since_last_sync = RTIMERTICKS_TO_S(rtimer_delta(sync_data->t, RTIMER_NOW()));
        negative_uncertainty = positive_uncertainty =
            ((seconds_since_last_sync
            * ((drift == AKES_NBR_UNINITIALIZED_DRIFT)
                ? CSL_CLOCK_TOLERANCE
                : CSL_COMPENSATION_TOLERANCE)
            * RTIMER_ARCH_SECOND) / (1000000)) + 1;
        negative_uncertainty += CSL_NEGATIVE_SYNC_GUARD_TIME;
        positive_uncertainty += CSL_POSITIVE_SYNC_GUARD_TIME;
        /* compensate for clock drift if known */
        if(drift == AKES_NBR_UNINITIALIZED_DRIFT) {
          compensation = 0;
        } else {
          compensation = ((int64_t)drift * (int64_t)seconds_since_last_sync / (int64_t)1000000);
        }
        /* scheduling */
        u.transmit.wake_up_sequence_start = shift_to_future(sync_data->t + compensation - negative_uncertainty);
        while(!rtimer_is_schedulable(u.transmit.wake_up_sequence_start,
              FRAME_CREATION_TIME + WAKE_UP_SEQUENCE_GUARD_TIME + RTIMER_GUARD_TIME + 2)) {
          u.transmit.wake_up_sequence_start += WAKE_UP_COUNTER_INTERVAL;
        }
        u.transmit.remaining_wake_up_frames = WAKE_UP_SEQUENCE_LENGTH(
            negative_uncertainty + positive_uncertainty,
            u.transmit.wake_up_frame_len);
        u.transmit.payload_frame_start = u.transmit.wake_up_sequence_start
            + RADIO_ASYNC_TIME_TO_TRANSMIT(
                (uint32_t)u.transmit.remaining_wake_up_frames
                * u.transmit.wake_up_frame_len
                * RADIO_ASYNC_SYMBOLS_PER_BYTE);
        /* predict wake-up counter */
        u.transmit.receivers_wake_up_counter.u32 = sync_data->his_wake_up_counter_at_t.u32
            + wake_up_counter_round_increments(
              rtimer_delta(sync_data->t, u.transmit.wake_up_sequence_start - compensation + negative_uncertainty));
      }

      /* TODO compute precisely */
      end_of_transmission = u.transmit.payload_frame_start + US_TO_RTIMERTICKS(6000);
      if(sent_once && !rtimer_smaller_or_equal(end_of_transmission,
          shift_to_future(duty_cycle_next))) {
        /* cancel second transmission to avoid to skip over the next wake up */
        break;
      }

      /* set channel */
      if(sync_data) {
        set_channel(csl_predict_wake_up_counter(), packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
      } else {
        set_channel(csl_get_wake_up_counter(csl_get_payload_frames_shr_end()), &linkaddr_node_addr);
      }
      lr = get_nearest_late_rendezvous();
      if(has_late_rendezvous_on_channel(get_channel())
          || (lr && (u.transmit.subtype == CSL_FRAMER_SUBTYPE_HELLO))
          || (lr && !rtimer_smaller_or_equal(end_of_transmission, lr->time))) {
        if(u.transmit.subtype == CSL_FRAMER_SUBTYPE_HELLO) {
          u.transmit.bf[0]->next_attempt = RTIMER_NOW()
              + HELLO_WAKE_UP_SEQUENCE_TRANSMISSION_TIME;
        } else {
          delay_any_frames_to(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
              RTIMER_NOW() + WAKE_UP_COUNTER_INTERVAL);
        }
        continue;
      }

      /* prepare acknowledgement nonce and key */
      switch(u.transmit.subtype) {
      case CSL_FRAMER_SUBTYPE_ACK:
      case CSL_FRAMER_SUBTYPE_NORMAL:
        memcpy(u.transmit.acknowledgement_key,
            akes_nbr_get_receiver_entry()->permanent->pairwise_key,
            AES_128_KEY_LENGTH);
        csl_ccm_inputs_generate_acknowledgement_nonce(u.transmit.acknowledgement_nonce, 0);
        u.transmit.receivers_wake_up_counter = csl_predict_wake_up_counter();
        break;
      default:
        break;
      }

      if(u.transmit.subtype == CSL_FRAMER_SUBTYPE_NORMAL) {
        /* check if we can burst more payload frames */
        while(u.transmit.last_burst_index < MAX_BURST_INDEX) {
          /* TODO compute precisely */
          end_of_transmission = u.transmit.payload_frame_start
              + ((u.transmit.last_burst_index + 1) * US_TO_RTIMERTICKS(6000));
          if(lr && !rtimer_smaller_or_equal(end_of_transmission, lr->time)) {
            /* we do not want to miss our late rendezvous */
            break;
          }
          if(sent_once && !rtimer_smaller_or_equal(end_of_transmission, shift_to_future(duty_cycle_next))) {
            /* we do not want to skip over our next wake up */
            break;
          }

          u.transmit.bf[u.transmit.last_burst_index + 1] =
              select_next_burst_frame(u.transmit.bf[u.transmit.last_burst_index]);
          if(!u.transmit.bf[u.transmit.last_burst_index + 1]) {
            break;
          }
          u.transmit.last_burst_index++;
        }
      }

      /* create payload frame(s) */
      i = u.transmit.last_burst_index;
      do {
        queuebuf_to_packetbuf(u.transmit.bf[i]->qb);
        packetbuf_set_attr(PACKETBUF_ATTR_BURST_INDEX, i);
        packetbuf_set_attr(PACKETBUF_ATTR_PENDING,
            ((i < MAX_BURST_INDEX) && u.transmit.bf[i + 1])
                ? u.transmit.payload_frame[i + 1][0]
                : 0);
        create_result = NETSTACK_FRAMER.create();
        if(create_result == FRAMER_FAILED) {
          break;
        }
        u.transmit.payload_frame[i][0] = packetbuf_totlen();
        memcpy(u.transmit.payload_frame[i] + 1,
            packetbuf_hdrptr(),
            packetbuf_totlen());
      } while(i--);
      if(create_result == FRAMER_FAILED) {
        PRINTF("csl: NETSTACK_FRAMER.create failed\n");
        u.transmit.result[0] = MAC_TX_ERR_FATAL;
        on_transmitted();
        continue;
      }
      u.transmit.remaining_payload_frame_bytes = u.transmit.payload_frame[0][0];

      /* prepare wake-up sequence */
      NETSTACK_RADIO_ASYNC.prepare_loop();
      if(!create_wake_up_frame(wake_up_frame)) {
        PRINTF("csl: wake-up frame creation failed\n");
        u.transmit.result[0] = MAC_TX_ERR_FATAL;
        on_transmitted();
        continue;
      }
      u.transmit.rendezvous_time_len = csl_framer_get_rendezvous_time_len(u.transmit.subtype);
      for(i = 0; i <= (RADIO_ASYNC_LOOP_LEN - u.transmit.wake_up_frame_len); i += u.transmit.wake_up_frame_len) {
        memcpy(u.transmit.next_wake_up_frames + i, wake_up_frame, u.transmit.wake_up_frame_len);
      }
      prepared_bytes = prepare_next_wake_up_frames(RADIO_ASYNC_LOOP_LEN);
      NETSTACK_RADIO_ASYNC.append_to_loop(u.transmit.next_wake_up_frames + RADIO_ASYNC_SHR_LEN,
          prepared_bytes - RADIO_ASYNC_SHR_LEN);

      /* schedule transmission */
      if(!rtimer_is_schedulable(u.transmit.wake_up_sequence_start
            - WAKE_UP_SEQUENCE_GUARD_TIME, RTIMER_GUARD_TIME + 1)) {
        PRINTF("csl: Transmission is not schedulable\n");
        u.transmit.result[0] = MAC_TX_ERR;
        on_transmitted();
        continue;
      }
      schedule_transmission(u.transmit.wake_up_sequence_start
          - WAKE_UP_SEQUENCE_GUARD_TIME);

      PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
      on_transmitted();
      PROCESS_PAUSE();
      sent_once = 1;
    }

    /* prepare next duty cycle */
#ifdef LPM_CONF_ENABLE
    lpm_set_max_pm(LPM_CONF_MAX_PM);
#endif /* LPM_CONF_ENABLE */
    memset(&u.duty_cycle, 0, sizeof(u.duty_cycle));
    duty_cycle_next = shift_to_future(duty_cycle_next);
    while(!rtimer_is_schedulable(duty_cycle_next - LPM_DEEP_SWITCHING, RTIMER_GUARD_TIME + 1)) {
      duty_cycle_next += WAKE_UP_COUNTER_INTERVAL;
    }
    lr = get_nearest_late_rendezvous();
    if(!lr
        || (rtimer_smaller_or_equal(
            duty_cycle_next + LATE_WAKE_UP_GUARD_TIME, lr->time))) {
      schedule_duty_cycle(duty_cycle_next - LPM_DEEP_SWITCHING);
    } else {
      u.duty_cycle.rendezvous_time = lr->time;
      u.duty_cycle.got_rendezvous_time = 1;
      u.duty_cycle.subtype = lr->subtype;
      u.duty_cycle.skip_to_rendezvous = 1;
      schedule_duty_cycle(lr->time
          - RENDEZVOUS_GUARD_TIME
          - (LPM_DEEP_SWITCHING - LPM_SWITCHING));
      NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_CHANNEL, lr->channel);
      list_remove(late_rendezvous_list, lr);
      memb_free(&late_rendezvous_memb, lr);
    }
    can_skip = lr ? 0 : 1;
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
delay_any_frames_to(const linkaddr_t *receiver, rtimer_clock_t next_attempt)
{
  struct buffered_frame *next;

  next = list_head(buffered_frames_list);
  while(next) {
    if(linkaddr_cmp(receiver, queuebuf_addr(next->qb, PACKETBUF_ADDR_RECEIVER))) {
      next->next_attempt = next_attempt;
    }
    next = list_item_next(next);
  }
}
/*---------------------------------------------------------------------------*/
static struct buffered_frame *
select_next_frame_to_transmit(void)
{
  rtimer_clock_t now;
  struct buffered_frame *next;

  now = RTIMER_NOW();
  next = list_head(buffered_frames_list);
  while(next) {
    if(rtimer_smaller_or_equal(next->next_attempt, now)) {
      if(next->transmissions) {
        PRINTF("csl: retransmission %i\n", next->transmissions);
      }
      return next;
    }
    next = list_item_next(next);
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
static struct buffered_frame *
select_next_burst_frame(struct buffered_frame *bf)
{
  rtimer_clock_t now;
  linkaddr_t *receiver;

  now = RTIMER_NOW();
  receiver = queuebuf_addr(bf->qb, PACKETBUF_ADDR_RECEIVER);
  while((bf = list_item_next(bf))) {
    if(linkaddr_cmp(receiver, queuebuf_addr(bf->qb, PACKETBUF_ADDR_RECEIVER))) {
      return rtimer_smaller_or_equal(bf->next_attempt, now) ? bf : NULL;
    }
  }

  return NULL;
}
/*---------------------------------------------------------------------------*/
static int
create_wake_up_frame(uint8_t *dst)
{
  struct akes_nbr_entry *entry;
  uint8_t payload_frames_length;
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];

  /* PHY header */
  memcpy(dst, shr, RADIO_ASYNC_SHR_LEN);
  dst += RADIO_ASYNC_SHR_LEN;
  dst[0] = csl_framer_length_of_wake_up_frame(u.transmit.subtype);
  dst++;

  /* extended frame type */
  dst[0] = CSL_FRAMER_FRAME_TYPE | (u.transmit.subtype << 6);
  dst++;

  /* destination PAN ID */
  if(csl_framer_has_destination_pan_id(u.transmit.subtype)) {
    dst[0] = (IEEE802154_PANID & 0xFF) ^ get_channel();
    dst[1] = (IEEE802154_PANID >> 8) & 0xFF;
    dst += CSL_FRAMER_PAN_ID_LEN;
  }

  /* OTP-related fields */
  if(csl_framer_has_otp_etc(u.transmit.subtype)) {
    entry = akes_nbr_get_receiver_entry();

    if(!entry || !entry->permanent) {
      return 0;
    }

    /* source index */
    dst[0] = entry->permanent->foreign_index;
    dst++;

    /* payload frame's length */
    payload_frames_length = packetbuf_totlen();
    dst[0] = payload_frames_length;
    dst++;

    /* OTP */
    csl_ccm_inputs_generate_otp_nonce(nonce, 1);
    AES_128_GET_LOCK();
    CCM_STAR.set_key(entry->permanent->pairwise_key);
    CCM_STAR.aead(nonce,
          NULL, 0,
          &payload_frames_length, 1,
          dst, CSL_FRAMER_OTP_LEN, 1);
    AES_128_RELEASE_LOCK();
    dst += CSL_FRAMER_OTP_LEN;
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
static uint8_t
prepare_next_wake_up_frames(uint8_t space)
{
  uint8_t prepared_bytes;
  uint8_t number_of_wake_up_frames;
  uint8_t i;
  uint8_t *p;
  uint8_t bytes;

  /* append the next wake-up frames */
  number_of_wake_up_frames = MIN(u.transmit.remaining_wake_up_frames,
      space / u.transmit.wake_up_frame_len);
  for(i = 0; i < number_of_wake_up_frames; i++) {
    u.transmit.remaining_wake_up_frames--;
    p = u.transmit.next_wake_up_frames
        + ((i + 1) * u.transmit.wake_up_frame_len)
        - u.transmit.rendezvous_time_len;
    memcpy(p, &u.transmit.remaining_wake_up_frames, u.transmit.rendezvous_time_len);
  }
  prepared_bytes = number_of_wake_up_frames * u.transmit.wake_up_frame_len;
  space -= prepared_bytes;
  u.transmit.wake_up_sequence_pos += prepared_bytes;

  /* append the first payload frame */
  if(!u.transmit.remaining_wake_up_frames
      && (space >= RADIO_ASYNC_PHY_HEADER_LEN)) {
    if(!u.transmit.wrote_payload_frames_phy_header) {
      memcpy(u.transmit.next_wake_up_frames + prepared_bytes, shr, RADIO_ASYNC_SHR_LEN);
      prepared_bytes += RADIO_ASYNC_SHR_LEN;
      u.transmit.next_wake_up_frames[prepared_bytes] = u.transmit.payload_frame[0][0];
      prepared_bytes += 1;
      space -= RADIO_ASYNC_PHY_HEADER_LEN;
      u.transmit.wake_up_sequence_pos += RADIO_ASYNC_PHY_HEADER_LEN;
      u.transmit.wrote_payload_frames_phy_header = 1;
    }

    bytes = MIN(space, u.transmit.remaining_payload_frame_bytes);
    memcpy(u.transmit.next_wake_up_frames + prepared_bytes,
        u.transmit.payload_frame[0]
        + 1 /* Frame Length */
        + u.transmit.payload_frame[0][0]
        - u.transmit.remaining_payload_frame_bytes,
        bytes);
    u.transmit.remaining_payload_frame_bytes -= bytes;
    prepared_bytes += bytes;
    u.transmit.wake_up_sequence_pos += bytes;
  }

  return prepared_bytes;
}
/*---------------------------------------------------------------------------*/
static void
schedule_transmission(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, transmit_wrapper, NULL) != RTIMER_OK) {
    PRINTF("csl: rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
transmit_wrapper(struct rtimer *rt, void *ptr)
{
  transmit();
}
/*---------------------------------------------------------------------------*/
static char
transmit(void)
{
  uint8_t prepared_bytes;

  PT_BEGIN(&pt);
  is_transmitting = 1;

  u.transmit.bf[0]->transmissions++;
  /* if we come from PM0 we will be too early */
  while(!rtimer_has_timed_out(u.transmit.wake_up_sequence_start
      - (WAKE_UP_SEQUENCE_GUARD_TIME - LPM_SWITCHING)));
  NETSTACK_RADIO_ASYNC.on();
  if(NETSTACK_RADIO_ASYNC.get_rssi() >= CCA_THRESHOLD) {
    NETSTACK_RADIO_ASYNC.off();
    PRINTF("csl: collision\n");
    u.transmit.result[0] = MAC_TX_COLLISION;
  } else {
    /* send the wake-up sequence, as well as the first payload frame */
    NETSTACK_RADIO_ASYNC.transmit();
    NETSTACK_RADIO_ASYNC.flushrx();
    sfd_timestamp = csl_get_payload_frames_shr_end();
    while(1) {
      u.transmit.next_rendezvous_time_update = u.transmit.wake_up_sequence_start
          + RADIO_ASYNC_TIME_TO_TRANSMIT(RADIO_ASYNC_SYMBOLS_PER_BYTE
              * (u.transmit.wake_up_sequence_pos - (MIN_PREPARE_LEAD_OVER_LOOP / 2)));
      if(!u.transmit.remaining_wake_up_frames && !u.transmit.remaining_payload_frame_bytes) {
        break;
      }
      schedule_transmission(u.transmit.next_rendezvous_time_update);
      PT_YIELD(&pt);
      prepared_bytes = prepare_next_wake_up_frames(RADIO_ASYNC_LOOP_LEN - MIN_PREPARE_LEAD_OVER_LOOP);
      NETSTACK_RADIO_ASYNC.append_to_loop(u.transmit.next_wake_up_frames, prepared_bytes);
    }
    if(rtimer_is_schedulable(u.transmit.next_rendezvous_time_update, RTIMER_GUARD_TIME + 1)) {
      schedule_transmission(u.transmit.next_rendezvous_time_update);
      PT_YIELD(&pt);
    }
    NETSTACK_RADIO_ASYNC.finish_loop();
    NETSTACK_RADIO_ASYNC.off();

    if(u.transmit.subtype == CSL_FRAMER_SUBTYPE_HELLO) {
      /* we do not expect acknowledgements to HELLOs */
      u.transmit.result[u.transmit.burst_index] = MAC_TX_OK;
    } else {
      NETSTACK_RADIO_ASYNC.on();

      while(1) {
        /* wait for acknowledgement */
        u.transmit.waiting_for_acknowledgement_shr = 1;
        u.transmit.got_acknowledgement_shr = 0;
        schedule_transmission(RTIMER_NOW() + CSL_ACKNOWLEDGEMENT_WINDOW_MAX);
        PT_YIELD(&pt);
        u.transmit.waiting_for_acknowledgement_shr = 0;
        if(!u.transmit.got_acknowledgement_shr) {
          PRINTF("csl: received no acknowledgement\n");
          u.transmit.result[u.transmit.burst_index] = MAC_TX_NOACK;
          break;
        }
        u.transmit.result[u.transmit.burst_index] = validate_acknowledgement();
        if(u.transmit.result[u.transmit.burst_index] != MAC_TX_OK) {
          break;
        }
        NETSTACK_RADIO_ASYNC.flushrx();

        /* check if we burst more payload frames */
        if(++u.transmit.burst_index > u.transmit.last_burst_index) {
          break;
        }

        /* transmit next payload frame */
        NETSTACK_RADIO_ASYNC.transmit();
        u.transmit.bf[u.transmit.burst_index]->transmissions++;

        /* move next payload frame to radio */
        NETSTACK_RADIO_ASYNC.prepare(u.transmit.payload_frame[u.transmit.burst_index]);

        /* wait for on_txdone */
        u.transmit.is_waiting_for_txdone = 1;
        PT_YIELD(&pt);
        u.transmit.is_waiting_for_txdone = 0;
      }

      NETSTACK_RADIO_ASYNC.off();
    }
  }

  NETSTACK_RADIO_ASYNC.flushrx();
  is_transmitting = 0;
  process_poll(&post_processing);
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static int
validate_acknowledgement(void)
{
  uint8_t len;
  uint8_t expected_len;
  uint8_t acknowledgement[CSL_FRAMER_MAX_ACKNOWLEDGEMENT_LEN];
  uint8_t phase_len;
  uint8_t expected_mic[ADAPTIVESEC_UNICAST_MIC_LEN];

  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
      NULL,
      RADIO_ASYNC_MAX_FRAME_LEN);

  phase_len = u.transmit.burst_index ? 0 : CSL_FRAMER_PHASE_LEN;
  expected_len = (u.transmit.subtype == CSL_FRAMER_SUBTYPE_HELLOACK)
      ? CSL_FRAMER_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN
      : (CSL_FRAMER_AUTHENTICATED_ACKNOWLEDGEMENT_LEN - CSL_FRAMER_PHASE_LEN + phase_len);

  /* frame length */
  len = NETSTACK_RADIO_ASYNC.read_phy_header();
  if(len != expected_len) {
    PRINTF("csl: acknowledgement frame has invalid length\n");
    return MAC_TX_COLLISION;
  }

  /* extended frame type */
  NETSTACK_RADIO_ASYNC.read_raw(acknowledgement, 1);
  if(acknowledgement[0] != CSL_FRAMER_FRAME_TYPE) {
    return MAC_TX_COLLISION;
  }
  if(u.transmit.subtype == CSL_FRAMER_SUBTYPE_HELLOACK) {
    return MAC_TX_OK;
  }

  if(aes_128_locked) {
    PRINTF("csl: could not validate acknowledgement frame\n");
    return MAC_TX_ERR;
  }

  /* CSL phase */
  if(phase_len) {
    NETSTACK_RADIO_ASYNC.read_raw(acknowledgement + 1, 2);
    u.transmit.acknowledgement_phase = csl_framer_parse_phase(acknowledgement + 1);
  }

  /* CCM* MIC */
  AES_128_GET_LOCK();
  CCM_STAR.set_key(u.transmit.acknowledgement_key);
  u.transmit.acknowledgement_nonce[LINKADDR_SIZE] &= ~(0x3F);
  u.transmit.acknowledgement_nonce[LINKADDR_SIZE] |= u.transmit.burst_index;
  CCM_STAR.aead(u.transmit.acknowledgement_nonce,
      NULL, 0,
      acknowledgement, 1 + phase_len,
      expected_mic, ADAPTIVESEC_UNICAST_MIC_LEN, 0);
  AES_128_RELEASE_LOCK();
  NETSTACK_RADIO_ASYNC.read_raw(acknowledgement + 1 + phase_len,
      ADAPTIVESEC_UNICAST_MIC_LEN);
  if(memcmp(expected_mic,
      acknowledgement + 1 + phase_len,
      ADAPTIVESEC_UNICAST_MIC_LEN)) {
    PRINTF("csl: inauthentic acknowledgement frame\n");
    return MAC_TX_COLLISION;
  } else {
    return MAC_TX_OK;
  }
}
/*---------------------------------------------------------------------------*/
static void
on_transmitted(void)
{
  linkaddr_t *receiver;
  struct akes_nbr_entry *entry;
  rtimer_clock_t next_attempt;
  uint8_t i;
  uint8_t back_off_exponent;
  uint8_t back_off_periods;
  uint32_t seconds_since_historical_sync;
  struct csl_sync_data new_sync_data;
  rtimer_clock_t expected_diff;
  rtimer_clock_t actual_diff;

  i = 0;
  do {
    switch(u.transmit.result[i]) {
    case MAC_TX_COLLISION:
    case MAC_TX_NOACK:
    case MAC_TX_ERR:
      if(u.transmit.bf[i]->transmissions
          >= queuebuf_attr(u.transmit.bf[i]->qb, PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS)) {
        /* intentionally no break; */
      } else {
        back_off_exponent = MIN(u.transmit.bf[i]->transmissions + MIN_BACK_OFF_EXPONENT,
            MAX_BACK_OFF_EXPONENT);
        back_off_periods = ((1 << back_off_exponent) - 1) & random_rand();
        next_attempt = RTIMER_NOW() + (WAKE_UP_COUNTER_INTERVAL * back_off_periods);
        receiver = queuebuf_addr(u.transmit.bf[i]->qb, PACKETBUF_ADDR_RECEIVER);
        delay_any_frames_to(receiver, next_attempt);
        break;
      }
    case MAC_TX_OK:
    case MAC_TX_ERR_FATAL:
      queuebuf_to_packetbuf(u.transmit.bf[i]->qb);
      queuebuf_free(u.transmit.bf[i]->qb);

      /* update stored wake-up time */
      if(!i && (u.transmit.result[0] == MAC_TX_OK)) {
        entry = akes_nbr_get_receiver_entry();
        switch(u.transmit.subtype) {
        case CSL_FRAMER_SUBTYPE_ACK:
        case CSL_FRAMER_SUBTYPE_NORMAL:
          if(!entry || !entry->permanent) {
            PRINTF("csl: receiver not found\n");
          } else {
            new_sync_data.his_wake_up_counter_at_t = u.transmit.receivers_wake_up_counter;
            new_sync_data.t = u.transmit.acknowledgement_sfd_timestamp
                - (WAKE_UP_COUNTER_INTERVAL - u.transmit.acknowledgement_phase);

            if(u.transmit.subtype == CSL_FRAMER_SUBTYPE_ACK) {
              entry->permanent->historical_sync_data = new_sync_data;
            } else {
              seconds_since_historical_sync = RTIMERTICKS_TO_S(
                  rtimer_delta(new_sync_data.t, entry->permanent->historical_sync_data.t));
              if(seconds_since_historical_sync >= CSL_MIN_TIME_BETWEEN_DRIFT_UPDATES) {
                expected_diff = WAKE_UP_COUNTER_INTERVAL
                    * (new_sync_data.his_wake_up_counter_at_t.u32
                    - entry->permanent->historical_sync_data.his_wake_up_counter_at_t.u32);
                actual_diff = new_sync_data.t - entry->permanent->historical_sync_data.t;
                entry->permanent->drift =
                  (((int64_t)actual_diff - (int64_t)expected_diff) * (int64_t)1000000)
                  / seconds_since_historical_sync;
                entry->permanent->historical_sync_data = entry->permanent->sync_data;
              }
            }

            entry->permanent->sync_data = new_sync_data;
          }
          break;
        default:
          break;
        }
      }

      mac_call_sent_callback(u.transmit.bf[i]->sent,
          u.transmit.bf[i]->ptr,
          u.transmit.result[i],
          u.transmit.bf[i]->transmissions);
      list_remove(buffered_frames_list, u.transmit.bf[i]);
      memb_free(&buffered_frames_memb, u.transmit.bf[i]);
      break;
    }
  } while((u.transmit.result[i] == MAC_TX_OK)
      && (++i <= u.transmit.last_burst_index));
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  queue_frame(sent, ptr);
  try_skip_to_send();
}
/*---------------------------------------------------------------------------*/
static void
send_list(mac_callback_t sent, void *ptr, struct rdc_buf_list *list)
{
  /* TODO implement if needed  */
  mac_call_sent_callback(sent, ptr, MAC_TX_ERR_FATAL, 0);
}
/*---------------------------------------------------------------------------*/
static void
try_skip_to_send(void)
{
  if(!skipped
      && can_skip
      && rtimer_is_schedulable(timer.time, RTIMER_GUARD_TIME + 1)) {
    skipped = 1;
    rtimer_arch_schedule(RTIMER_NOW());
  }
}
/*---------------------------------------------------------------------------*/
static void
queue_frame(mac_callback_t sent, void *ptr)
{
  struct buffered_frame *bf;
  struct buffered_frame *next;

  if(!packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS)) {
    packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS,
        MAX_RETRANSMISSIONS + 1);
  }

  bf = memb_alloc(&buffered_frames_memb);
  if(!bf) {
    PRINTF("csl: buffer is full\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }
  bf->qb = queuebuf_new_from_packetbuf();
  if(!bf->qb) {
    PRINTF("csl: queubuf is full\n");
    memb_free(&buffered_frames_memb, bf);
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }

  bf->ptr = ptr;
  bf->sent = sent;
  bf->transmissions = 0;
  bf->next_attempt = RTIMER_NOW();
  /* do not send earlier than other frames for that receiver */
  next = list_head(buffered_frames_list);
  while(next) {
    if(linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
        queuebuf_addr(next->qb, PACKETBUF_ADDR_RECEIVER))) {
      bf->next_attempt = next->next_attempt;
      break;
    }
    next = list_item_next(next);
  }
  list_add(buffered_frames_list, bf);
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  /* we operate in polling mode throughout */
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  /* TODO implement if needed */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
off(int keep_radio_on)
{
  /* TODO implement if needed  */
  return 1;
}
/*---------------------------------------------------------------------------*/
static unsigned short
channel_check_interval(void)
{
  return CLOCK_SECOND / NETSTACK_RDC_CHANNEL_CHECK_RATE;
}
/*---------------------------------------------------------------------------*/
static rtimer_clock_t
get_last_wake_up_time(void)
{
  return duty_cycle_next + RADIO_ASYNC_RECEIVE_CALIBRATION_TIME;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
csl_get_payload_frames_shr_end(void)
{
  return u.transmit.payload_frame_start + RADIO_ASYNC_SHR_TIME;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
csl_get_last_sfd_timestamp(void)
{
  return sfd_timestamp;
}
/*---------------------------------------------------------------------------*/
enum csl_framer_subtype
csl_get_last_wake_up_frames_subtype(void)
{
  return u.duty_cycle.subtype;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
csl_get_phase(rtimer_clock_t t)
{
  rtimer_clock_t result;

  result = rtimer_delta(get_last_wake_up_time(), t);
  while(result >= WAKE_UP_COUNTER_INTERVAL) {
    result -= WAKE_UP_COUNTER_INTERVAL;
  }
  return WAKE_UP_COUNTER_INTERVAL - result;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
csl_get_wake_up_counter(rtimer_clock_t t)
{
  rtimer_clock_t delta;
  wake_up_counter_t wuc;

  delta = rtimer_delta(wake_up_counter_last_increment, t);
  wuc = csl_wake_up_counter;
  wuc.u32 += wake_up_counter_increments(delta, NULL);

  return wuc;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
csl_predict_wake_up_counter(void)
{
  return u.transmit.receivers_wake_up_counter;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
csl_restore_wake_up_counter(void)
{
  struct akes_nbr_entry *entry;
  wake_up_counter_t wuc;
  rtimer_clock_t delta;
  int32_t drift;
  uint32_t seconds_since_last_sync;
  int32_t compensation;

  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    wuc.u32 = 0;
    PRINTF("csl: could not restore wake-up counter\n");
    return wuc;
  }

  drift = entry->permanent->drift;
  if(drift == AKES_NBR_UNINITIALIZED_DRIFT) {
    compensation = 0;
  } else {
    seconds_since_last_sync = RTIMERTICKS_TO_S(
        rtimer_delta(entry->permanent->sync_data.t, csl_get_last_sfd_timestamp()));
    compensation = ((int64_t)drift
        * (int64_t)seconds_since_last_sync / (int64_t)1000000);
  }

  delta = csl_get_last_sfd_timestamp()
      - entry->permanent->sync_data.t
      + compensation
      - (WAKE_UP_COUNTER_INTERVAL / 2);
  wuc.u32 = entry->permanent->sync_data.his_wake_up_counter_at_t.u32
      + wake_up_counter_round_increments(delta);
  return wuc;
}
/*---------------------------------------------------------------------------*/
const struct rdc_driver csl_driver = {
  "csl",
  init,
  send,
  send_list,
  input,
  on,
  off,
  channel_check_interval,
};
/*---------------------------------------------------------------------------*/
