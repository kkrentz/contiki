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

#ifndef PROJECT_SIMPLE_UDP_CONF_H_
#define PROJECT_SIMPLE_UDP_CONF_H_

#if 0
/* enable the software implementation of AES-128 */
#undef AES_128_CONF
#define AES_128_CONF aes_128_driver
#endif

/* configure RDC layer */
#if 0
#undef CONTIKIMAC_CONF_COMPOWER
#define CONTIKIMAC_CONF_COMPOWER 0
#undef RDC_CONF_HARDWARE_CSMA
#define RDC_CONF_HARDWARE_CSMA 1
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC contikimac_driver
#else
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC nullrdc_driver
#endif

/* configure MAC layer */
#if 0
#undef CONTIKIMAC_CONF_WITH_PHASE_OPTIMIZATION
#define CONTIKIMAC_CONF_WITH_PHASE_OPTIMIZATION 1
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC csma_driver
#else
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC nullmac_driver
#endif

/* configure LLSEC layer */
#if 1
#undef ADAPTIVESEC_CONF_UNICAST_SEC_LVL
#define ADAPTIVESEC_CONF_UNICAST_SEC_LVL 2
#undef ADAPTIVESEC_CONF_BROADCAST_SEC_LVL
#define ADAPTIVESEC_CONF_BROADCAST_SEC_LVL 2
#undef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_CONF_USES_AUX_HEADER 0
#undef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS 14
#if 0
#include "net/llsec/adaptivesec/coresec-autoconf.h"
#else
#include "net/llsec/adaptivesec/noncoresec-autoconf.h"
#endif
#endif

/* configure ContikiMAC FRAMER */
#if 0
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER contikimac_framer
#undef CONTIKIMAC_FRAMER_CONF_ENABLED
#define CONTIKIMAC_FRAMER_CONF_ENABLED 1
#undef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER adaptivesec_framer
#undef ADAPTIVESEC_CONF_DECORATED_FRAMER
#define ADAPTIVESEC_CONF_DECORATED_FRAMER framer_802154
#endif

/* set a seeder */
#undef CSPRNG_CONF_SEEDER
#define CSPRNG_CONF_SEEDER iq_seeder

/* disable TCP */
#undef UIP_CONF_TCP
#define UIP_CONF_TCP 0

#endif /* PROJECT_SIMPLE_UDP_CONF_H_ */
