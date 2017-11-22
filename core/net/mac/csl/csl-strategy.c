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
 *         Uses pairwise session keys for securing frames.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/csl/csl-strategy.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "lib/memb.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#ifdef CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS
#else /* CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS */
#define MAX_RETRANSMISSIONS 3
#endif /* CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS */

struct ongoing_broadcast {
  uint32_t neighbor_bitmap;
  void *ptr;
  mac_callback_t sent;
  int transmissions;
};

static void send_broadcast(struct ongoing_broadcast *ob);
static void on_broadcast_sent(void *ptr, int status, int transmissions);
MEMB(ongoing_broadcasts_memb, struct ongoing_broadcast, QUEUEBUF_NUM);

/*---------------------------------------------------------------------------*/
int
csl_strategy_is_broadcast(void *ptr)
{
  return memb_inmemb(&ongoing_broadcasts_memb, ptr);
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  struct ongoing_broadcast *ob;

  if(adaptivesec_is_hello()) {
    NETSTACK_MAC.send(sent, ptr);
  } else if(packetbuf_holds_broadcast()) {
    ob = memb_alloc(&ongoing_broadcasts_memb);
    if(!ob) {
      PRINTF("csl-strategy: ongoing_broadcasts_memb is full\n");
      mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
      return;
    }
    ob->neighbor_bitmap = 0;
    ob->sent = sent;
    ob->ptr = ptr;
    ob->transmissions = 0;
    send_broadcast(ob);
  } else {
    NETSTACK_MAC.send(sent, ptr);
  }
}
/*---------------------------------------------------------------------------*/
static void
send_broadcast(struct ongoing_broadcast *ob)
{
  struct akes_nbr_entry *entry;

  /* find a permanent neighbor that has not received this frame, yet */
  entry = akes_nbr_head();
  while(entry) {
    if(entry->permanent
        && !((1 << akes_nbr_index_of(entry->permanent)) & ob->neighbor_bitmap))  {
      break;
    }
    entry = akes_nbr_next(entry);
  }

  if(!entry) {
    memb_free(&ongoing_broadcasts_memb, ob);
    mac_call_sent_callback(ob->sent, ob->ptr, MAC_TX_OK, ob->transmissions);
    return;
  }

  ob->neighbor_bitmap |= (1 << akes_nbr_index_of(entry->permanent));
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, akes_nbr_get_addr(entry));
  packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS, MAX_RETRANSMISSIONS);
  csl_framer_set_seqno(entry->permanent);
  NETSTACK_MAC.send(on_broadcast_sent, ob);
}
/*---------------------------------------------------------------------------*/
static void
on_broadcast_sent(void *ptr, int status, int transmissions)
{
  struct ongoing_broadcast *ob;

  switch(status) {
  case MAC_TX_DEFERRED:
    return;
  case MAC_TX_OK:
  case MAC_TX_COLLISION:
  case MAC_TX_NOACK:
  case MAC_TX_ERR:
  case MAC_TX_ERR_FATAL:
    ob = (struct ongoing_broadcast *)ptr;
    ob->transmissions += transmissions;
    send_broadcast(ob);
    return;
  }
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  uint8_t *dataptr;
  uint8_t datalen;
  enum akes_nbr_status status;
  struct akes_nbr_entry *entry;
  int8_t max_index;
  uint8_t local_index;

  dataptr = packetbuf_dataptr();
  datalen = packetbuf_datalen();
  if(adaptivesec_is_hello()) {
    entry = akes_nbr_head();
    max_index = -1;
    while(entry) {
      if(entry->permanent) {
        local_index = akes_nbr_index_of(entry->permanent);
        adaptivesec_aead(entry->permanent->pairwise_key,
            0,
            dataptr + datalen + (local_index * ADAPTIVESEC_BROADCAST_MIC_LEN),
            1);
        if(local_index > max_index) {
          max_index = local_index;
        }
      }
      entry = akes_nbr_next(entry);
    }
    if(max_index >= 0) {
      packetbuf_set_datalen(datalen + ((max_index + 1) * ADAPTIVESEC_BROADCAST_MIC_LEN));
    }
  } else {
    status = akes_get_receiver_status();
    entry = akes_nbr_get_receiver_entry();

    if(!entry || !entry->refs[status]) {
      return 0;
    }

    adaptivesec_aead(entry->refs[status]->pairwise_key,
        adaptivesec_get_sec_lvl() & (1 << 2),
        dataptr + datalen,
        1);
    packetbuf_set_datalen(datalen + ADAPTIVESEC_UNICAST_MIC_LEN);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static enum adaptivesec_verify
verify(struct akes_nbr *sender)
{
  uint8_t *dataptr;
  uint8_t *micptr;
  uint8_t mic[ADAPTIVESEC_BROADCAST_MIC_LEN];

  if(adaptivesec_is_hello()) {
    dataptr = packetbuf_dataptr();
    packetbuf_set_datalen(AKES_HELLO_DATALEN);
    micptr = dataptr
        + AKES_HELLO_DATALEN
        + (sender->foreign_index * ADAPTIVESEC_BROADCAST_MIC_LEN);
    adaptivesec_aead(sender->pairwise_key, 0, mic, 0);
    if(memcmp(micptr, mic, ADAPTIVESEC_BROADCAST_MIC_LEN)) {
      PRINTF("csl-strategy: inauthentic HELLO\n");
      return ADAPTIVESEC_VERIFY_INAUTHENTIC;
    }
  } else {
    if(adaptivesec_verify(sender->pairwise_key)) {
      PRINTF("csl-strategy: inauthentic unicast\n");
      return ADAPTIVESEC_VERIFY_INAUTHENTIC;
    }
  }

  return ADAPTIVESEC_VERIFY_SUCCESS;
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_overhead(void)
{
  return ADAPTIVESEC_UNICAST_MIC_LEN;
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  memb_init(&ongoing_broadcasts_memb);
}
/*---------------------------------------------------------------------------*/
const struct adaptivesec_strategy csl_strategy = {
  send,
  on_frame_created,
  verify,
  get_overhead,
  init
};
/*---------------------------------------------------------------------------*/
