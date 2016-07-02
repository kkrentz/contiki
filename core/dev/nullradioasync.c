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
 *         Surrogate for NETSTACK_RADIO_ASYNC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "dev/nullradioasync.h"

/*---------------------------------------------------------------------------*/
static void
init(void)
{
}
/*---------------------------------------------------------------------------*/
static void
prepare(uint8_t *length_then_payload)
{
}
/*---------------------------------------------------------------------------*/
static void
transmit(void)
{
}
/*---------------------------------------------------------------------------*/
static void
on(void)
{
}
/*---------------------------------------------------------------------------*/
static void
off(void)
{
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_value(radio_param_t param, radio_value_t *value)
{
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_value(radio_param_t param, radio_value_t value)
{
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_object(radio_param_t param, void *dest, size_t size)
{
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_object(radio_param_t param, const void *src, size_t size)
{
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static void
flushrx(void)
{
}
/*---------------------------------------------------------------------------*/
static uint8_t
read_phy_header(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static uint8_t
read_phy_header_and_set_datalen(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
read_raw(uint8_t *buf, uint8_t bytes)
{
}
/*---------------------------------------------------------------------------*/
static int
read_payload(uint8_t bytes)
{
  return 1;
}
/*---------------------------------------------------------------------------*/
static uint8_t
remaining_payload_bytes(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
read_footer(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static int8_t
get_rssi(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
reprepare(uint8_t offset, uint8_t *src, uint8_t len)
{
}
/*---------------------------------------------------------------------------*/
static void
prepare_loop(void)
{
}
/*---------------------------------------------------------------------------*/
static void
append_to_loop(uint8_t *appendix, uint8_t appendix_len)
{
}
/*---------------------------------------------------------------------------*/
static void
finish_loop(void)
{
}
/*---------------------------------------------------------------------------*/
const struct radio_async_driver nullradioasync_driver = {
  init,
  prepare,
  transmit,
  on,
  off,
  get_value,
  set_value,
  get_object,
  set_object,
  flushrx,
  read_phy_header,
  read_phy_header_and_set_datalen,
  read_raw,
  remaining_payload_bytes,
  read_payload,
  read_footer,
  get_rssi,
  reprepare,
  prepare_loop,
  append_to_loop,
  finish_loop
};
/*---------------------------------------------------------------------------*/
