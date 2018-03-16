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

#include "net/mac/csl/csl-framer.h"
#include "net/mac/csl/csl.h"
#include "net/packetbuf.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/mac/csl/csl-ccm-inputs.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*---------------------------------------------------------------------------*/
uint8_t
csl_framer_get_rendezvous_time_len(enum csl_framer_subtype subtype)
{
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
    return CSL_FRAMER_LONG_RENDEZVOUS_TIME_LEN;
  default:
    return CSL_FRAMER_SHORT_RENDEZVOUS_TIME_LEN;
  }
}
/*---------------------------------------------------------------------------*/
int
csl_framer_has_destination_pan_id(enum csl_framer_subtype subtype)
{
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
  case CSL_FRAMER_SUBTYPE_HELLOACK:
    return 1;
  default:
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
int
csl_framer_has_otp_etc(enum csl_framer_subtype subtype)
{
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_ACK:
  case CSL_FRAMER_SUBTYPE_NORMAL:
    return 1;
  default:
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
uint8_t
csl_framer_length_of_wake_up_frame(enum csl_framer_subtype subtype)
{
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
    return CSL_FRAMER_HELLO_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN;
  case CSL_FRAMER_SUBTYPE_HELLOACK:
    return CSL_FRAMER_HELLOACK_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN;
  case CSL_FRAMER_SUBTYPE_ACK:
    return CSL_FRAMER_ACK_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN;
  default:
    return CSL_FRAMER_NORMAL_WAKE_UP_FRAME_LEN - RADIO_ASYNC_PHY_HEADER_LEN;
  }
}
/*---------------------------------------------------------------------------*/
void
csl_framer_write_phase(uint8_t *dst, rtimer_clock_t phase)
{
  dst[0] = (phase >> 8) & 0xFF;
  dst[1] = phase & 0xFF;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
csl_framer_parse_phase(uint8_t *src)
{
  return (rtimer_clock_t) (src[0] << 8) | src[1];
}
/*---------------------------------------------------------------------------*/
static int
has_source_address(enum csl_framer_subtype subtype)
{
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
  case CSL_FRAMER_SUBTYPE_HELLOACK:
    return 1;
  default:
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
static int
has_seqno(enum csl_framer_subtype subtype)
{
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_NORMAL:
    return 1;
  default:
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
int
csl_framer_get_payload_frame_header_len(enum csl_framer_subtype subtype, int frame_pending)
{
  return 1 /* frame type and subtype */
    + (has_source_address(subtype) ? LINKADDR_SIZE : 0)
    + (has_seqno(subtype) ? 1 : 0)
    + (frame_pending ? 1 : 0);
}
/*---------------------------------------------------------------------------*/
static int
length(void)
{
  return csl_framer_get_payload_frame_header_len(CSL_FRAMER_SUBTYPE_NORMAL, 1);
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  enum csl_framer_subtype subtype;
  int is_command;
  uint8_t pending_frames_len;
  int len;
  uint8_t *p;

  is_command = 0;
  switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
  case FRAME802154_DATAFRAME:
    subtype = CSL_FRAMER_SUBTYPE_NORMAL;
    break;
  default:
    if(adaptivesec_is_hello()) {
      subtype = CSL_FRAMER_SUBTYPE_HELLO;
    } else if(adaptivesec_is_helloack()) {
      subtype = CSL_FRAMER_SUBTYPE_HELLOACK;
    } else if(adaptivesec_is_ack()) {
      subtype = CSL_FRAMER_SUBTYPE_ACK;
    } else {
      subtype = CSL_FRAMER_SUBTYPE_NORMAL;
      is_command = 1;
    }
    break;
  }
  pending_frames_len = packetbuf_attr(PACKETBUF_ATTR_PENDING);

  len = csl_framer_get_payload_frame_header_len(subtype, pending_frames_len);
  if(!packetbuf_hdralloc(len)) {
    PRINTF("csl-framer: packetbuf_hdralloc failed\n");
    return FRAMER_FAILED;
  }

  p = packetbuf_hdrptr();

  /* extended frame type and flags */
  p[0] = CSL_FRAMER_FRAME_TYPE
      | (is_command ? (1 << 6) : 0)
      | (pending_frames_len ? (1 << 7) : 0);
  p++;

  /* source address */
  if(has_source_address(subtype)) {
    memcpy(p, linkaddr_node_addr.u8, LINKADDR_SIZE);
    p += LINKADDR_SIZE;
  }

  /* sequence number */
  if(has_seqno(subtype)) {
    p[0] = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
    p++;
  }

  /* pending frame's length */
  if(pending_frames_len) {
    p[0] = pending_frames_len;
    p++;
  }

  return len;
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  enum csl_framer_subtype subtype;
  int len;
  int frame_pending;
  int is_command;
  uint8_t *p;
  linkaddr_t addr;

  p = packetbuf_hdrptr();

  /* extended frame type and flags */
  if((p[0] & 0x3F) != CSL_FRAMER_FRAME_TYPE) {
    PRINTF("csl-framer: unwanted frame type\n");
    return FRAMER_FAILED;
  }
  if(packetbuf_attr(PACKETBUF_ATTR_BURST_INDEX)) {
    subtype = CSL_FRAMER_SUBTYPE_NORMAL;
  } else {
    subtype = csl_get_last_wake_up_frames_subtype();
  }
  if(subtype == CSL_FRAMER_SUBTYPE_NORMAL) {
    frame_pending = (1 << 7) & p[0];
    is_command = (1 << 6) & p[0];
  } else {
    frame_pending = 0;
    is_command = 1;
  }
  if(is_command) {
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_CMDFRAME);
  } else {
#ifdef COLLISION_TRACING
    PRINTF("csl-framer: rejecting any data frames\n");
    return FRAMER_FAILED;
#endif /* COLLISION_TRACING */
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
  }
  len = csl_framer_get_payload_frame_header_len(subtype, frame_pending);
  switch(subtype) {
  case CSL_FRAMER_SUBTYPE_HELLO:
    if(packetbuf_totlen() < (len + AKES_HELLO_DATALEN)) {
      PRINTF("csl-framer: HELLO has invalid length\n");
      return FRAMER_FAILED;
    }
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_null);
    break;
  case CSL_FRAMER_SUBTYPE_HELLOACK:
    if(packetbuf_totlen() != (len + AKES_HELLOACK_DATALEN)) {
      PRINTF("csl-framer: HELLOACK has invalid length\n");
      return FRAMER_FAILED;
    }
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_node_addr);
    break;
  default:
    if(packetbuf_totlen() <= (len + ADAPTIVESEC_UNICAST_MIC_LEN)) {
      PRINTF("csl-framer: frame has invalid length\n");
      return FRAMER_FAILED;
    }
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_node_addr);
    break;
  }
  p++;

  /* source address */
  if(has_source_address(subtype)) {
    memcpy(addr.u8, p, LINKADDR_SIZE);
    if(linkaddr_cmp(&addr, &linkaddr_node_addr)) {
      PRINTF("csl-framer: frame from ourselves\n");
      return FRAMER_FAILED;
    }
    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &addr);
    p += LINKADDR_SIZE;
  }

  /* validation of HELLOs */
  if(subtype == CSL_FRAMER_SUBTYPE_HELLO) {
    if(!akes_is_acceptable_hello()) {
      PRINTF("csl-framer: unacceptable HELLO\n");
      return FRAMER_FAILED;
    }
  }

  /* sequence number */
  if(has_seqno(subtype)) {
    packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, p[0]);
    p++;
  }

  /* pending frame's length */
  if(frame_pending) {
    if(!p[0]) {
      PRINTF("csl-framer: pending frame has no length\n");
      return FRAMER_FAILED;
    }
    packetbuf_set_attr(PACKETBUF_ATTR_PENDING, p[0]);
    p++;
  }

  if(!packetbuf_hdrreduce(len)) {
    PRINTF("csl-framer: packetbuf_hdrreduce failed\n");
    return FRAMER_FAILED;
  }

  return len;
}
/*---------------------------------------------------------------------------*/
void
csl_framer_set_seqno(struct akes_nbr *receiver)
{
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, ++receiver->my_unicast_seqno);
}
/*---------------------------------------------------------------------------*/
int
csl_framer_received_duplicate(void)
{
  struct akes_nbr_entry *entry;
  uint8_t seqno;

  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    return 0;
  }

  seqno = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
  if(entry->permanent->his_unicast_seqno == seqno) {
    return 1;
  }
  entry->permanent->his_unicast_seqno = seqno;
  return 0;
}
/*---------------------------------------------------------------------------*/
const struct framer csl_framer = {
  length,
  create,
  parse
};
/*---------------------------------------------------------------------------*/
