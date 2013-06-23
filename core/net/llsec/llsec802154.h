/**
 * \addtogroup llsec
 * @{
 */

/**
 * \defgroup llsec802154
 * 
 * Common functionality of 802.15.4-compliant llsec_drivers.
 * 
 * @{
 */

/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
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
 *         Common functionality of 802.15.4-compliant llsec_drivers.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef LLSEC802154_H_
#define LLSEC802154_H_

#include "net/mac/frame802154.h"
#include "contiki.h"

#ifdef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_SECURITY_LEVEL LLSEC802154_CONF_SECURITY_LEVEL
#else /* LLSEC802154_CONF_SECURITY_LEVEL */
#define LLSEC802154_SECURITY_LEVEL FRAME802154_SECURITY_LEVEL_NONE
#endif /* LLSEC802154_CONF_SECURITY_LEVEL */

#ifdef LLSEC802154_CONF_USES_EXPLICIT_KEYS
#define LLSEC802154_USES_EXPLICIT_KEYS LLSEC802154_CONF_USES_EXPLICIT_KEYS
#else /* LLSEC802154_CONF_USES_EXPLICIT_KEYS */
#define LLSEC802154_USES_EXPLICIT_KEYS 0
#endif /* LLSEC802154_CONF_USES_EXPLICIT_KEYS */

#if LLSEC802154_SECURITY_LEVEL == FRAME802154_SECURITY_LEVEL_NONE
#define LLSEC802154_MIC_LENGTH                 (0)
#define LLSEC802154_AUX_SECURITY_HEADER_LENGTH (0)
#define LLSEC802154_AUTH_FLAGS                 (0)
#elif (LLSEC802154_SECURITY_LEVEL & 3) == FRAME802154_SECURITY_LEVEL_MIC_32
#define LLSEC802154_MIC_LENGTH                 (4)
#define LLSEC802154_AUX_SECURITY_HEADER_LENGTH (5)
#define LLSEC802154_AUTH_FLAGS                 (0x49)
#elif (LLSEC802154_SECURITY_LEVEL & 3) == FRAME802154_SECURITY_LEVEL_MIC_64
#define LLSEC802154_MIC_LENGTH                 (8)
#define LLSEC802154_AUX_SECURITY_HEADER_LENGTH (5)
#define LLSEC802154_AUTH_FLAGS                 (0x59)
#elif (LLSEC802154_SECURITY_LEVEL & 3) == FRAME802154_SECURITY_LEVEL_MIC_128
#define LLSEC802154_MIC_LENGTH                 (16)
#define LLSEC802154_AUX_SECURITY_HEADER_LENGTH (5)
#define LLSEC802154_AUTH_FLAGS                 (0x79)
#else
#error "unsupported security level"
#endif
#define LLSEC802154_ENCRYPTION_FLAGS           (0x01)
#define LLSEC802154_USES_ENCRYPTION            (LLSEC802154_SECURITY_LEVEL & (1 << 2))

/* Defining surrogates in case 802.15.4 security is disabled */
#if !LLSEC802154_SECURITY_LEVEL
enum {
  PACKETBUF_ATTR_SECURITY_LEVEL,
  PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1,
  PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3
};
#endif /* LLSEC802154_SECURITY_LEVEL */

/* Defining surrogates in case of disabling explicit keys */
#if !LLSEC802154_USES_EXPLICIT_KEYS
enum {
  PACKETBUF_ATTR_KEY_ID_MODE,
  PACKETBUF_ATTR_KEY_INDEX,
  PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1
};
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */

#ifdef LLSEC802154_CONF_AES
#define LLSEC802154_AES LLSEC802154_CONF_AES
#else /* LLSEC802154_CONF_AES */
#define LLSEC802154_AES null_llsec802154_aes_driver
#endif /* LLSEC802154_CONF_AES */

/**
 * Structure of AES drivers.
 */
struct llsec802154_aes_driver {
  
  /**
   * \brief Sets the current 128-bit key.
   */
  void (* set_key)(uint8_t *key);
  
  /**
   * \brief AES-128 block cipher
   */
  void (* aes)(uint8_t *plaintext_and_result);
};

/**
 * \brief                Generates a MIC over the frame in the packetbuf.
 * \param result         The generated MIC will be put here
 * \param custom_mic_len <= 16; set to LLSEC802154_MIC_LENGTH to be compliant
 */
void llsec802154_mic(const uint8_t *extended_source_address,
    uint8_t *result,
    uint8_t custom_mic_len);

/**
 * \brief XORs the frame in the packetbuf with the key stream.
 */
void llsec802154_ctr(const uint8_t *extended_source_address);

extern const struct llsec802154_aes_driver LLSEC802154_AES;

#endif /* LLSEC802154_H_ */

/** @} */
/** @} */
