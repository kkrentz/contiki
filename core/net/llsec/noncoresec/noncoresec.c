/**
 * \addtogroup noncoresec
 * @{
 */

/*
 * Copyright (c) 2014, Hasso-Plattner-Institut.
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
 *         802.15.4 security implementation, which uses a network-wide key
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/noncoresec/noncoresec.h"
#include "net/llsec/llsec802154.h"
#include "net/mac/frame802154.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include <string.h>

#ifdef NONCORESEC_CONF_KEY
#define NONCORESEC_KEY NONCORESEC_CONF_KEY
#else /* NONCORESEC_CONF_KEY */
#define NONCORESEC_KEY { 0x00 , 0x01 , 0x02 , 0x03 , \
                         0x04 , 0x05 , 0x06 , 0x07 , \
                         0x08 , 0x09 , 0x0A , 0x0B , \
                         0x0C , 0x0D , 0x0E , 0x0F }
#endif /* NONCORESEC_CONF_KEY */

/* network-wide CCM* key */
static uint8_t key[16] = NONCORESEC_KEY;
/* This node's current frame counter value */
static frame802154_frame_counter_t counter;

/*---------------------------------------------------------------------------*/
static void
bootstrap(llsec_on_bootstrapped_t on_bootstrapped)
{
  LLSEC802154_AES.set_key(key);
  on_bootstrapped();
}
/*---------------------------------------------------------------------------*/
static void
add_security_header(void)
{
  counter.u32++;
  
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1, counter.u16[0]);
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3, counter.u16[1]);
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, LLSEC802154_SECURITY_LEVEL);
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
  add_security_header();
  NETSTACK_MAC.send(sent, ptr);
}
/*---------------------------------------------------------------------------*/
static void
init_from_packetbuf(frame802154_frame_counter_t *counter)
{
  counter->u16[0] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1);
  counter->u16[1] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3);
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  static frame802154_frame_counter_t last;
  frame802154_frame_counter_t current;
  uint8_t *dataptr;
  uint8_t data_len;  
  
  /* check whether we have already secured the frame */
  init_from_packetbuf(&current);
  if(current.u32 > last.u32) {
    last = current;
    
    dataptr = packetbuf_dataptr();
    data_len = packetbuf_datalen();
    
    llsec802154_mic(linkaddr_node_addr.u8, dataptr + data_len, LLSEC802154_MIC_LENGTH);
#if LLSEC802154_USES_ENCRYPTION
    llsec802154_ctr(linkaddr_node_addr.u8);
#endif /* LLSEC802154_USES_ENCRYPTION */
    packetbuf_set_datalen(data_len + LLSEC802154_MIC_LENGTH);
  }
  
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  uint8_t generated_mic[LLSEC802154_MIC_LENGTH];
  uint8_t *received_mic;
  const uint8_t *sender_addr;
  
  if(packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL) == LLSEC802154_SECURITY_LEVEL) {
    sender_addr = packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8;
    packetbuf_set_datalen(packetbuf_datalen() - LLSEC802154_MIC_LENGTH);
    
#if LLSEC802154_USES_ENCRYPTION
    llsec802154_ctr(sender_addr);
#endif /* LLSEC802154_USES_ENCRYPTION */
    llsec802154_mic(sender_addr, generated_mic, LLSEC802154_MIC_LENGTH);
    
    received_mic = ((uint8_t *) packetbuf_hdrptr()) + packetbuf_datalen();
    if ((memcmp(generated_mic, received_mic, LLSEC802154_MIC_LENGTH) == 0)
        && packetbuf_hdrreduce(packetbuf_attr(PACKETBUF_ATTR_HDR_LEN))) {
      NETSTACK_NETWORK.input();
    }
  }
}
/*---------------------------------------------------------------------------*/
const struct llsec_driver noncoresec_driver = {
  bootstrap,
  send,
  on_frame_created,
  input
};
/*---------------------------------------------------------------------------*/

/** @} */
