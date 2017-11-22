/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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
 *         Adaptive Key Establishment Scheme (AKES).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/akes-delete.h"
#include "net/llsec/adaptivesec/akes-trickle.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/anti-replay.h"
#include "net/cmd-broker.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include "lib/csprng.h"
#include "lib/memb.h"
#include "lib/leaky-bucket.h"
#include "net/mac/csl/csl.h"
#include "net/mac/csl/csl-framer.h"
#include <string.h>

#ifdef AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS
#define MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS
#else /* AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS */
#define MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS (1)
#endif /* AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS */

#ifdef AKES_CONF_MAX_RETRANSMISSION_BACK_OFF
#define MAX_RETRANSMISSION_BACK_OFF AKES_CONF_MAX_RETRANSMISSION_BACK_OFF
#else /* AKES_CONF_MAX_RETRANSMISSION_BACK_OFF */
#define MAX_RETRANSMISSION_BACK_OFF (2) /* seconds */
#endif /* AKES_CONF_MAX_RETRANSMISSION_BACK_OFF */

#ifdef AKES_CONF_MAX_HELLO_RATE
#define MAX_HELLO_RATE AKES_CONF_MAX_HELLO_RATE
#else /* AKES_CONF_MAX_HELLO_RATE */
#define MAX_HELLO_RATE (5 * 60) /* 1 HELLO per 5min */
#endif /* AKES_CONF_MAX_HELLO_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOS
#define MAX_CONSECUTIVE_HELLOS AKES_CONF_MAX_CONSECUTIVE_HELLOS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */
#define MAX_CONSECUTIVE_HELLOS (10)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */

#ifdef AKES_CONF_MAX_HELLOACK_RATE
#define MAX_HELLOACK_RATE AKES_CONF_MAX_HELLOACK_RATE
#else /* AKES_CONF_MAX_HELLOACK_RATE */
#define MAX_HELLOACK_RATE (150) /* 1 HELLOACK per 150s */
#endif /* AKES_CONF_MAX_HELLOACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#define MAX_CONSECUTIVE_HELLOACKS AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */
#define MAX_CONSECUTIVE_HELLOACKS (20)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */

#ifdef AKES_CONF_MAX_ACK_RATE
#define MAX_ACK_RATE AKES_CONF_MAX_ACK_RATE
#else /* AKES_CONF_MAX_ACK_RATE */
#define MAX_ACK_RATE MAX_HELLOACK_RATE
#endif /* AKES_CONF_MAX_ACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_ACKS
#define MAX_CONSECUTIVE_ACKS AKES_CONF_MAX_CONSECUTIVE_ACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_ACKS */
#define MAX_CONSECUTIVE_ACKS MAX_CONSECUTIVE_HELLOACKS
#endif /* AKES_CONF_MAX_CONSECUTIVE_ACKS */

#define MAX_HELLOACK_DELAY ((AKES_MAX_WAITING_PERIOD * CLOCK_SECOND) \
    - (MAX_RETRANSMISSION_BACK_OFF * CLOCK_SECOND))
#if CSL_ENABLED
#define MIN_HELLOACK_DELAY (0)
#else /* CSL_ENABLED */
#define MIN_HELLOACK_DELAY (CLOCK_SECOND / NETSTACK_RDC_CHANNEL_CHECK_RATE)
#endif /* CSL_ENABLED */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

static void on_hello_sent(void *ptr, int status, int transmissions);
static void on_hello_done(void *ptr);
static void send_helloack(void *ptr);
static void send_ack(struct akes_nbr_entry *entry, int is_new);
#if !CSL_ENABLED
static void send_updateack(struct akes_nbr_entry *entry);
#endif /* !CSL_ENABLED */
static void on_ack_sent(void *ptr, int status, int transmissions);

/* A random challenge, which will be attached to HELLO commands */
static uint8_t hello_challenge[AKES_NBR_CHALLENGE_LEN];
static int is_awaiting_helloacks;
static struct ctimer hello_timer;
static struct cmd_broker_subscription subscription;
static struct leaky_bucket hello_bucket;
static struct leaky_bucket helloack_bucket;
static struct leaky_bucket ack_bucket;
#if CSL_ENABLED
static uint8_t q[AKES_NBR_CHALLENGE_LEN];
static rtimer_clock_t phi_2;
#endif /* CSL_ENABLED */

/*---------------------------------------------------------------------------*/
static void
prepare_update_command(uint8_t cmd_id,
    struct akes_nbr_entry *entry,
    enum akes_nbr_status status)
{
  uint8_t *payload;
  uint8_t payload_len;

  payload = adaptivesec_prepare_command(cmd_id, akes_nbr_get_addr(entry));
#if CSL_ENABLED
  if(cmd_id == AKES_UPDATE_IDENTIFIER) {
    csl_framer_set_seqno(entry->permanent);
  }
#else /* CSL_ENABLED */
  adaptivesec_add_security_header(entry->refs[status]);
  anti_replay_suppress_counter();
  if(status) {
    /* avoids that csma.c confuses frames for tentative and permanent neighbors */
    packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO,
        0xff00 + packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));
  }
#endif /* CSL_ENABLED */
#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, akes_nbr_index_of(entry->refs[status]));
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */

  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS,
        MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS + 1);
    break;
  default:
    break;
  }

  /* write payload */
  if(status) {
    akes_nbr_copy_challenge(payload, entry->tentative->challenge);
    payload += AKES_NBR_CHALLENGE_LEN;
    payload += CSL_FRAMER_HELLOACK_PIGGYBACK_LEN;
  }

#if CSL_ENABLED
  if(cmd_id == AKES_ACK_IDENTIFIER) {
    csl_framer_write_phase(payload, phi_2);
    payload += CSL_FRAMER_PHASE_LEN;
    akes_nbr_copy_challenge(payload, q);
    payload += AKES_NBR_CHALLENGE_LEN;
  }
#endif /* CSL_ENABLED */

#if AKES_NBR_WITH_INDICES
  payload[0] = akes_nbr_index_of(entry->refs[status]);
  payload++;
#endif /* AKES_NBR_WITH_INDICES */
#if ANTI_REPLAY_WITH_SUPPRESSION
  {
    frame802154_frame_counter_t reordered_counter;
    anti_replay_write_counter(payload);
    payload += 4;
    reordered_counter.u32 = LLSEC802154_HTONL(anti_replay_my_broadcast_counter);
    memcpy(payload, reordered_counter.u8, 4);
    payload += 4;
  }
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */

  payload_len = payload - ((uint8_t *)packetbuf_hdrptr());

#if AKES_NBR_WITH_GROUP_KEYS
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    akes_nbr_copy_key(payload, adaptivesec_group_key);
    packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES, payload_len);
    payload_len += AES_128_KEY_LENGTH;
    break;
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS */
  packetbuf_set_datalen(payload_len);
}
/*---------------------------------------------------------------------------*/
static void
process_update_command(struct akes_nbr *nbr, uint8_t *data, int cmd_id)
{
  switch(cmd_id) {
  case AKES_ACK_IDENTIFIER:
#if CSL_ENABLED
    nbr->sync_data.his_wake_up_counter_at_t = nbr->meta->predicted_wake_up_counter;
    nbr->sync_data.t = nbr->meta->helloack_sfd_timestamp
        - (WAKE_UP_COUNTER_INTERVAL - csl_framer_parse_phase(data));
    data += CSL_FRAMER_ACK_PIGGYBACK_LEN;
    nbr->drift = AKES_NBR_UNINITIALIZED_DRIFT;
    nbr->historical_sync_data = nbr->sync_data;
#endif /* CSL_ENABLED */
    akes_nbr_free_tentative_metadata(nbr);
    nbr->sent_authentic_hello = 1;
    break;
  case AKES_HELLOACK_IDENTIFIER:
#if CSL_ENABLED
    nbr->sync_data.t = csl_get_last_sfd_timestamp()
        - (WAKE_UP_COUNTER_INTERVAL - csl_framer_parse_phase(data));
    data += CSL_FRAMER_PHASE_LEN;
    nbr->sync_data.his_wake_up_counter_at_t = wake_up_counter_parse(data);
    data +=  WAKE_UP_COUNTER_LEN;
    akes_nbr_copy_challenge(q, data);
    data += AKES_NBR_CHALLENGE_LEN;
    phi_2 = csl_get_phase(csl_get_last_sfd_timestamp());
    nbr->drift = AKES_NBR_UNINITIALIZED_DRIFT;
#endif /* CSL_ENABLED */
    nbr->sent_authentic_hello = 0;
    break;
  }

#if !CSL_ENABLED
  anti_replay_was_replayed(&nbr->anti_replay_info);
#if ANTI_REPLAY_WITH_SUPPRESSION
  nbr->last_was_broadcast = 1;
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  akes_nbr_prolong(nbr);
#endif /* !CSL_ENABLED */

#if AKES_NBR_WITH_INDICES
  nbr->foreign_index = data[0];
  data++;
#endif /* AKES_NBR_WITH_INDICES */
#if ANTI_REPLAY_WITH_SUPPRESSION
  {
    frame802154_frame_counter_t disordered_counter;
    data += 4;
    memcpy(disordered_counter.u8, data, 4);
    nbr->anti_replay_info.his_broadcast_counter.u32 = LLSEC802154_HTONL(disordered_counter.u32);
    data += 4;
  }
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
#if AKES_NBR_WITH_GROUP_KEYS
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    akes_nbr_copy_key(nbr->group_key, data);
    break;
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS */
}
/*---------------------------------------------------------------------------*/
/*
 * We use AES-128 as a key derivation function (KDF). This is possible due to
 * simple circumstances. Speaking in terms of the extract-then-expand paradigm
 * [RFC 5869], we can skip over the extraction step since we already have a
 * uniformly-distributed key which we want to expand into session keys. For
 * implementing the expansion step, we may just use AES-128 [Paar and Pelzl,
 * Understanding Cryptography].
 */
static void
generate_pairwise_key(uint8_t *result, uint8_t *shared_secret)
{
  AES_128_GET_LOCK();
  AES_128.set_key(shared_secret);
  AES_128.encrypt(result);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
static void
change_hello_challenge(void)
{
  csprng_rand(hello_challenge, AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_broadcast_hello(void)
{
  uint8_t *payload;

  if(is_awaiting_helloacks) {
    PRINTF("akes: Still waiting for HELLOACKs\n");
    return;
  }

  if(leaky_bucket_is_full(&hello_bucket)) {
    PRINTF("akes: HELLO bucket is full\n");
    return;
  }
  leaky_bucket_pour(&hello_bucket);

  payload = adaptivesec_prepare_command(AKES_HELLO_IDENTIFIER, &linkaddr_null);
#if !CSL_ENABLED
  adaptivesec_add_security_header(NULL);
  anti_replay_suppress_counter();
#endif /* !CSL_ENABLED */

  /* write payload */
  akes_nbr_copy_challenge(payload, hello_challenge);
  payload += AKES_NBR_CHALLENGE_LEN;

  packetbuf_set_datalen(AKES_HELLO_DATALEN);

  PRINTF("akes: broadcasting HELLO\n");
  ADAPTIVESEC_STRATEGY.send(on_hello_sent, NULL);
}
/*---------------------------------------------------------------------------*/
void
akes_create_hello(void)
{
#if CSL_ENABLED
  uint8_t *dataptr;

  dataptr = packetbuf_dataptr();
  wake_up_counter_write(dataptr + 1 + AKES_NBR_CHALLENGE_LEN,
      csl_get_wake_up_counter(csl_get_payload_frames_shr_end()));
#endif /* CSL_ENABLED */
}
/*---------------------------------------------------------------------------*/
static void
on_hello_sent(void *ptr, int status, int transmissions)
{
  is_awaiting_helloacks = 1;
  ctimer_set(&hello_timer,
      AKES_MAX_WAITING_PERIOD * CLOCK_SECOND,
      on_hello_done,
      NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_hello_done(void *ptr)
{
  is_awaiting_helloacks = 0;
  change_hello_challenge();
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_hello(void)
{
  struct akes_nbr_entry *entry;

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_receiver_entry();

  return (entry && entry->permanent)
      || (!(entry && entry->tentative)
      && !leaky_bucket_is_full(&helloack_bucket)
      && (akes_nbr_count(AKES_NBR_TENTATIVE) < AKES_NBR_MAX_TENTATIVES)
      && akes_nbr_free_slots());
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_hello(uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  clock_time_t waiting_period;

  PRINTF("akes: Received HELLO\n");

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_sender_entry();

  if(entry && entry->permanent) {
#if ANTI_REPLAY_WITH_SUPPRESSION
    anti_replay_restore_counter(&entry->permanent->anti_replay_info);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
    switch(ADAPTIVESEC_STRATEGY.verify(entry->permanent)) {
    case ADAPTIVESEC_VERIFY_SUCCESS:
#if CSL_ENABLED
      leaky_bucket_effuse(&csl_hello_inc_bucket);
#else /* CSL_ENABLED */
      akes_nbr_prolong(entry->permanent);
#endif /* CSL_ENABLED */
      akes_trickle_on_fresh_authentic_hello(entry->permanent);
      return CMD_BROKER_CONSUMED;
    case ADAPTIVESEC_VERIFY_INAUTHENTIC:
      PRINTF("akes: Starting new session with permanent neighbor\n");
      break;
#if !CSL_ENABLED
    case ADAPTIVESEC_VERIFY_REPLAYED:
      PRINTF("akes: Replayed HELLO\n");
      return CMD_BROKER_ERROR;
#endif /* !CSL_ENABLED */
    }
  }

  if(leaky_bucket_is_full(&helloack_bucket)) {
    PRINTF("akes: Bucket is full\n");
    return CMD_BROKER_ERROR;
  }

  if(entry && entry->tentative) {
    PRINTF("akes: Received HELLO from tentative neighbor\n");
    return CMD_BROKER_ERROR;
  }

  /* Create tentative neighbor */
  entry = akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry) {
    PRINTF("akes: HELLO flood?\n");
    return CMD_BROKER_ERROR;
  }

  leaky_bucket_pour(&helloack_bucket);

  akes_nbr_copy_challenge(entry->tentative->challenge, payload);
  waiting_period = adaptivesec_random_clock_time(MIN_HELLOACK_DELAY, MAX_HELLOACK_DELAY);
#if CSL_ENABLED
  entry->tentative->sync_data.t = csl_get_last_sfd_timestamp()
      - (WAKE_UP_COUNTER_INTERVAL / 2);
  entry->tentative->sync_data.his_wake_up_counter_at_t =
      wake_up_counter_parse(payload + AKES_NBR_CHALLENGE_LEN);
#else /* CSL_ENABLED */
  entry->tentative->expiration_time = clock_seconds()
      + (waiting_period / CLOCK_SECOND)
      + AKES_ACK_DELAY;
#endif /* CSL_ENABLED */
  ctimer_set(&entry->tentative->meta->wait_timer,
      waiting_period,
      send_helloack,
      entry);
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  entry->tentative->meta->has_wait_timer = 1;
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
  PRINTF("akes: Will send HELLOACK in %lus\n", waiting_period / CLOCK_SECOND);
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static void
send_helloack(void *ptr)
{
  struct akes_nbr_entry *entry;
  uint8_t challenges[2 * AKES_NBR_CHALLENGE_LEN];
  uint8_t *secret;

  PRINTF("akes: Sending HELLOACK\n");

  entry = (struct akes_nbr_entry *)ptr;
  akes_nbr_copy_challenge(challenges, entry->tentative->challenge);
  csprng_rand(challenges + AKES_NBR_CHALLENGE_LEN, AKES_NBR_CHALLENGE_LEN);
  akes_nbr_copy_challenge(entry->tentative->challenge, challenges + AKES_NBR_CHALLENGE_LEN);

  /* write payload */
  prepare_update_command(entry->permanent ? AKES_HELLOACK_P_IDENTIFIER : AKES_HELLOACK_IDENTIFIER,
      entry,
      AKES_NBR_TENTATIVE);

  /* generate pairwise key */
  secret = AKES_SCHEME.get_secret_with_hello_sender(akes_nbr_get_addr(entry));
  if(!secret) {
    PRINTF("akes: No secret with HELLO sender\n");
    return;
  }
  generate_pairwise_key(challenges, secret);
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, challenges);

  adaptivesec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
int
akes_create_helloack(void)
{
#if CSL_ENABLED
  struct akes_nbr_entry *entry;
  struct akes_nbr *nbr;
  uint8_t *dataptr;

  entry = akes_nbr_get_receiver_entry();
  if(!entry || !((nbr = entry->tentative))) {
    return 0;
  }

  dataptr = packetbuf_dataptr();
  entry->tentative->meta->helloack_sfd_timestamp = csl_get_payload_frames_shr_end();
  csprng_rand(nbr->meta->q, AKES_NBR_CHALLENGE_LEN);
  nbr->meta->predicted_wake_up_counter = csl_predict_wake_up_counter();

  dataptr += 1 + AKES_NBR_CHALLENGE_LEN;
  csl_framer_write_phase(dataptr,
      csl_get_phase(entry->tentative->meta->helloack_sfd_timestamp));
  dataptr += CSL_FRAMER_PHASE_LEN;
  wake_up_counter_write(dataptr,
      csl_get_wake_up_counter(entry->tentative->meta->helloack_sfd_timestamp));
  dataptr += WAKE_UP_COUNTER_LEN;
  akes_nbr_copy_challenge(dataptr, nbr->meta->q);
#endif /* CSL_ENABLED */
  return 1;
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_helloack(void)
{
  if(!is_awaiting_helloacks
      || leaky_bucket_is_full(&ack_bucket)) {
    PRINTF("akes: Unacceptable ACK\n");
    return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_helloack(uint8_t *payload, int p_flag)
{
  struct akes_nbr_entry *entry;
  uint8_t *secret;
  uint8_t key[AKES_NBR_CHALLENGE_LEN * 2];
  int is_new;

  PRINTF("akes: Received HELLOACK\n");

  if(!akes_is_acceptable_helloack()) {
    return CMD_BROKER_ERROR;
  }

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_sender_entry();
  if(entry && entry->permanent && p_flag) {
    PRINTF("akes: No need to start a new session\n");
    return CMD_BROKER_ERROR;
  }

  secret = AKES_SCHEME.get_secret_with_helloack_sender(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  if(!secret) {
    PRINTF("akes: No secret with HELLOACK sender\n");
    return CMD_BROKER_ERROR;
  }

  /* copy challenges and generate key */
  akes_nbr_copy_challenge(key, hello_challenge);
  akes_nbr_copy_challenge(key + AKES_NBR_CHALLENGE_LEN, payload);
  generate_pairwise_key(key, secret);

#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, payload[AKES_NBR_CHALLENGE_LEN]);
  anti_replay_parse_counter(payload + AKES_NBR_CHALLENGE_LEN + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  if(adaptivesec_verify(key)) {
    PRINTF("akes: Invalid HELLOACK\n");
    return CMD_BROKER_ERROR;
  }

  is_new = 1;
  if(entry) {
    if(entry->permanent) {
      if(
#if AKES_NBR_WITH_PAIRWISE_KEYS
          !memcmp(key, entry->permanent->pairwise_key, AES_128_KEY_LENGTH)) {
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
          !memcmp(payload, entry->permanent->helloack_challenge, AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN)) {
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */

        PRINTF("akes: Replayed HELLOACK\n");
        return CMD_BROKER_ERROR;
      } else {
        akes_nbr_delete(entry, AKES_NBR_PERMANENT);
        is_new = 0;
      }
    }

    if(entry->tentative) {
#if !AKES_NBR_WITH_PAIRWISE_KEYS
      if(!entry->tentative->meta->has_wait_timer) {
        PRINTF("akes: Awaiting acknowledgement of ACK\n");
        return CMD_BROKER_ERROR;
      }
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */

      if(ctimer_expired(&entry->tentative->meta->wait_timer)) {
        PRINTF("akes: Awaiting ACK\n");
#if CSL_ENABLED
        leaky_bucket_effuse(&csl_helloack_inc_bucket);
#endif /* CSL_ENABLED */
        return CMD_BROKER_ERROR;
      } else {
        PRINTF("akes: Skipping HELLOACK\n");
        ctimer_stop(&entry->tentative->meta->wait_timer);
        akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
      }
    }
  }
#if CSL_ENABLED
  leaky_bucket_effuse(&csl_helloack_inc_bucket);
#endif /* CSL_ENABLED */

  entry = akes_nbr_new(AKES_NBR_PERMANENT);
  if(!entry) {
    return CMD_BROKER_ERROR;
  }

#if AKES_NBR_WITH_PAIRWISE_KEYS
  akes_nbr_copy_key(entry->permanent->pairwise_key, key);
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
  memcpy(entry->permanent->helloack_challenge,
      payload,
      AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN);
  akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry->tentative) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    return CMD_BROKER_ERROR;
  }
  entry->tentative->meta->has_wait_timer = 0;
  entry->tentative->expiration_time = clock_seconds()
      + AKES_MAX_WAITING_PERIOD
      + 1 /* leeway */;
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, key);
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
  process_update_command(entry->permanent,
      payload + AKES_NBR_CHALLENGE_LEN,
      AKES_HELLOACK_IDENTIFIER);
  send_ack(entry, is_new);
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct akes_nbr_entry *entry, int is_new)
{
  PRINTF("akes: Sending ACK\n");
  leaky_bucket_pour(&ack_bucket);
  prepare_update_command(AKES_ACK_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  NETSTACK_MAC.send(on_ack_sent, is_new ? entry : NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_ack_sent(void *is_new, int status, int transmissions)
{
  struct akes_nbr_entry *entry;

  if(status == MAC_TX_DEFERRED) {
    return;
  }

  entry = akes_nbr_get_receiver_entry();
  if(!entry
      || (!AKES_NBR_WITH_PAIRWISE_KEYS && !entry->tentative)
      || (!entry->permanent)) {
    PRINTF("akes: This should never happen\n");
    return;
  }
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
  if(status != MAC_TX_OK) {
    PRINTF("akes: ACK was not acknowledged\n");
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    return;
  }
  if(is_new) {
    akes_trickle_on_new_nbr();
  }
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_ack(struct akes_nbr_entry *entry)
{
  return entry
      && entry->tentative
      && ctimer_expired(&entry->tentative->meta->wait_timer);
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_ack(uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  int is_new;

  PRINTF("akes: Received ACK\n");

  entry = akes_nbr_get_sender_entry();
#if !CSL_ENABLED
#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, payload[0]);
  anti_replay_parse_counter(payload + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  if(!akes_is_acceptable_ack(entry)
      || adaptivesec_verify(entry->tentative->tentative_pairwise_key)) {
    PRINTF("akes: Invalid ACK\n");
    return CMD_BROKER_ERROR;
  }
#endif /* !CSL_ENABLED */

  if(entry->permanent) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    is_new = 0;
  } else {
    is_new = 1;
  }
  entry->permanent = entry->tentative;
  entry->tentative = NULL;
  process_update_command(entry->permanent, payload, AKES_ACK_IDENTIFIER);
  if(is_new) {
    akes_trickle_on_new_nbr();
  }

  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
void
akes_send_update(struct akes_nbr_entry *entry)
{
  prepare_update_command(AKES_UPDATE_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  NETSTACK_MAC.send(akes_delete_on_update_sent, NULL);
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_update(uint8_t cmd_id, uint8_t *payload)
{
#if !CSL_ENABLED
  struct akes_nbr_entry *entry;
#endif /* !CSL_ENABLED */

  PRINTF("akes: Received %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");

#if !CSL_ENABLED
  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    PRINTF("akes: Invalid %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");
    return CMD_BROKER_ERROR;
  }
#if ANTI_REPLAY_WITH_SUPPRESSION
  anti_replay_parse_counter(payload + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  if(ADAPTIVESEC_STRATEGY.verify(entry->permanent)
      != ADAPTIVESEC_VERIFY_SUCCESS) {
    PRINTF("akes: Invalid %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");
    return CMD_BROKER_ERROR;
  }
#endif /* !CSL_ENABLED */

#if CSL_ENABLED
  if(csl_framer_received_duplicate()) {
    PRINTF("akes: Duplicated UPDATE\n");
    return CMD_BROKER_ERROR;
  }
#else /* CSL_ENABLED */
  process_update_command(entry->permanent, payload, cmd_id);

  if(cmd_id == AKES_UPDATE_IDENTIFIER) {
    send_updateack(entry);
  }
#endif /* CSL_ENABLED */

  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
#if !CSL_ENABLED
static void
send_updateack(struct akes_nbr_entry *entry)
{
  prepare_update_command(AKES_UPDATEACK_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  adaptivesec_send_command_frame();
}
#endif /* !CSL_ENABLED */
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_command(uint8_t cmd_id, uint8_t *payload)
{
#if AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES,
        packetbuf_datalen() - AES_128_KEY_LENGTH - ADAPTIVESEC_UNICAST_MIC_LEN);
    break;
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES */

  switch(cmd_id) {
  case AKES_HELLO_IDENTIFIER:
    return on_hello(payload);
  case AKES_HELLOACK_IDENTIFIER:
    return on_helloack(payload, 0);
  case AKES_HELLOACK_P_IDENTIFIER:
    return on_helloack(payload, 1);
  case AKES_ACK_IDENTIFIER:
    return on_ack(payload);
  case AKES_UPDATE_IDENTIFIER:
#if !CSL_ENABLED
  case AKES_UPDATEACK_IDENTIFIER:
#endif /* !CSL_ENABLED */
    return on_update(cmd_id, payload);
  default:
    return CMD_BROKER_UNCONSUMED;
  }
}
/*---------------------------------------------------------------------------*/
enum akes_nbr_status
akes_get_receiver_status(void)
{
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) != FRAME802154_CMDFRAME) {
    return AKES_NBR_PERMANENT;
  }

  switch(adaptivesec_get_cmd_id()) {
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  case AKES_ACK_IDENTIFIER:
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    return AKES_NBR_TENTATIVE;
  default:
    return AKES_NBR_PERMANENT;
  }
}
/*---------------------------------------------------------------------------*/
void
akes_init(void)
{
  leaky_bucket_init(&hello_bucket, MAX_CONSECUTIVE_HELLOS, MAX_HELLO_RATE);
  leaky_bucket_init(&helloack_bucket, MAX_CONSECUTIVE_HELLOACKS, MAX_HELLOACK_RATE);
  leaky_bucket_init(&ack_bucket, MAX_CONSECUTIVE_ACKS, MAX_ACK_RATE);
  subscription.on_command = on_command;
  cmd_broker_subscribe(&subscription);
  akes_nbr_init();
  AKES_SCHEME.init();
  akes_delete_init();
  change_hello_challenge();
  akes_trickle_start();
}
/*---------------------------------------------------------------------------*/
