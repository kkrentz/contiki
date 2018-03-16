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

#include "contiki.h"
#include "net/netstack.h"
#include "net/packetbuf.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

PROCESS(sniffer_process, "sniffer_process");
AUTOSTART_PROCESSES(&sniffer_process);

/*---------------------------------------------------------------------------*/
static void
on_rxpktdone(void)
{
  uint8_t *dataptr;
  uint8_t i;

  packetbuf_clear();
  NETSTACK_RADIO_ASYNC.read_phy_header_and_set_datalen();
  NETSTACK_RADIO_ASYNC.read_payload(NETSTACK_RADIO_ASYNC.remaining_payload_bytes());

  dataptr = packetbuf_dataptr();
  for(i = 0; i < packetbuf_datalen(); i++) {
    PRINTF("%02x", dataptr[i]);
  }
  PRINTF("\n");
  NETSTACK_RADIO_ASYNC.flushrx();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sniffer_process, ev, data)
{
  PROCESS_BEGIN();

  NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_SHR_DEM_ZEROES, 3);
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, on_rxpktdone, 127);
  NETSTACK_RADIO_ASYNC.on();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
