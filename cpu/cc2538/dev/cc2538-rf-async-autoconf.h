/*
 * Copyright (c) 2017, Hasso-Plattner-Institut.
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
 *         Autoconfigures the asynchronous RADIO driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#undef NETSTACK_CONF_RADIO
#define NETSTACK_CONF_RADIO nullradio_driver
#undef NETSTACK_CONF_RADIO_ASYNC
#define NETSTACK_CONF_RADIO_ASYNC cc2538_rf_async_driver
#undef STARTUP_GCC_CONF_RFCORE_RXTX_ISR
#define STARTUP_GCC_CONF_RFCORE_RXTX_ISR cc2538_rf_async_rxtx_isr
#undef STARTUP_GCC_CONF_RFCORE_ERROR_ISR
#define STARTUP_GCC_CONF_RFCORE_ERROR_ISR cc2538_rf_async_error_isr
#undef IQ_SEEDER_CONF_RADIO
#define IQ_SEEDER_CONF_RADIO cc2538_rf_async_driver
#undef RANDOM_CONF_RADIO
#define RANDOM_CONF_RADIO cc2538_rf_async_driver
