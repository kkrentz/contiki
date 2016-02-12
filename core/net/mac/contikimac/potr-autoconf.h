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

/**
 * \file
 *         Autoconfigures POTR
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#undef POTR_CONF_ENABLED
#define POTR_CONF_ENABLED 1
#undef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_CONF_WITH_GROUP_KEYS 1
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC secrdc_driver
#undef SECRDC_CONF_ENABLED
#define SECRDC_CONF_ENABLED 1
#undef AES_128_CONF_WITH_LOCKING
#define AES_128_CONF_WITH_LOCKING 1
#undef NBR_TABLE_CONF_WITH_LOCKING
#define NBR_TABLE_CONF_WITH_LOCKING 1
#undef AKES_NBR_CONF_WITH_LOCKING
#define AKES_NBR_CONF_WITH_LOCKING 1
#undef RADIO_ASYNC_CONF_WITH_CHECKSUM
#define RADIO_ASYNC_CONF_WITH_CHECKSUM 0
#undef SICSLOWPAN_CONF_MAC_MAX_PAYLOAD
#define SICSLOWPAN_CONF_MAC_MAX_PAYLOAD 127
