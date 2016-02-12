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
 *         Generates CCM inputs as required by secrdc.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/secrdc-ccm-inputs.h"
#include "llsec/ccm-star-packetbuf.h"
#include "net/mac/contikimac/secrdc.h"
#include "net/packetbuf.h"
#include "net/llsec/llsec802154.h"
#include "net/mac/contikimac/potr.h"
#include "net/llsec/adaptivesec/adaptivesec.h"

/*---------------------------------------------------------------------------*/
void
secrdc_ccm_inputs_set_nonce(uint8_t *nonce, int forward)
{
  const linkaddr_t *source_addr;
#if SECRDC_WITH_SECURE_PHASE_LOCK
  uint8_t *hdrptr;
#if ILOS_ENABLED
  wake_up_counter_t wuc;
#endif /* ILOS_ENABLED */
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

  source_addr = forward ? &linkaddr_node_addr : packetbuf_addr(PACKETBUF_ADDR_SENDER);
  linkaddr_to_eui_64(nonce, source_addr);
#if ILOS_ENABLED
  hdrptr = packetbuf_hdrptr();
  nonce[8] = potr_has_strobe_index(hdrptr[0]) ? hdrptr[POTR_HEADER_LEN] : 0;
  if(adaptivesec_is_helloack() || adaptivesec_is_ack()) {
    wuc = wake_up_counter_parse(((uint8_t *)packetbuf_dataptr()) + 1);
  } else if(packetbuf_holds_broadcast()) {
    wuc = forward
        ? secrdc_get_wake_up_counter(secrdc_get_next_strobe_start() + WAKE_UP_COUNTER_INTERVAL)
        : secrdc_restore_wake_up_counter();
    wuc.u32 += 0xC0000000;
  } else {
    wuc = forward
        ? secrdc_predict_wake_up_counter()
        : secrdc_get_wake_up_counter(secrdc_get_last_wake_up_time());
    wuc.u32 += 0x40000000;
  }
  wake_up_counter_write(nonce + 9, wuc);
#elif LLSEC802154_USES_FRAME_COUNTER
#if SECRDC_WITH_SECURE_PHASE_LOCK
  hdrptr = packetbuf_hdrptr();
  nonce[8] = potr_has_strobe_index(hdrptr[0]) ? hdrptr[POTR_HEADER_LEN] : 0;
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  nonce[8] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3) >> 8;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  nonce[9] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3) & 0xff;
  nonce[10] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) >> 8;
  nonce[11] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xff;
#if LLSEC802154_USES_AUX_HEADER
  nonce[12] = packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL);
#else /* LLSEC802154_USES_AUX_HEADER */
  nonce[12] = packetbuf_holds_broadcast() ? 0xFF : packetbuf_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX);
#endif /* LLSEC802154_USES_AUX_HEADER */
#endif /* ILOS_ENABLED */
}
/*---------------------------------------------------------------------------*/
void
secrdc_ccm_inputs_to_acknowledgement_nonce(uint8_t *nonce)
{
#if ILOS_ENABLED
  nonce[12] |= (1 << 7);
  nonce[12] &= ~(1 << 6);
#else /* ILOS_ENABLED */
  nonce[12] = 0xFE;
#endif /* ILOS_ENABLED */
}
/*---------------------------------------------------------------------------*/
void
secrdc_ccm_inputs_derive_key(uint8_t *dst, uint8_t *key)
{
#if POTR_ENABLED
  AES_128_GET_LOCK();
  memset(dst, 0, AES_128_BLOCK_SIZE);
  AES_128.set_key(key);
  AES_128.encrypt(dst);
  AES_128_RELEASE_LOCK();
#else /* POTR_ENABLED */
  akes_nbr_copy_key(dst, key);
#endif /* POTR_ENABLED */
}
/*---------------------------------------------------------------------------*/
void
secrdc_ccm_inputs_set_derived_key(uint8_t *key)
{
#if POTR_ENABLED
  uint8_t block[AES_128_BLOCK_SIZE];

  secrdc_ccm_inputs_derive_key(block, key);
  CCM_STAR.set_key(block);
#else /* POTR_ENABLED */
  CCM_STAR.set_key(key);
#endif /* POTR_ENABLED */
}
/*---------------------------------------------------------------------------*/
