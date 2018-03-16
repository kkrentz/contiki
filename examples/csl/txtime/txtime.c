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
#include "net/packetbuf.h"
#include "net/linkaddr.h"
#include "net/netstack.h"
#include "net/llsec/llsec.h"
#include "sys/etimer.h"
#include "lib/csprng.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "dev/radio-async.h"

#define MAX_DELAY (270 * CLOCK_SECOND)
#define NETWORK_SIZE (20)

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

PROCESS(txtime_process, "txtime_process");
AUTOSTART_PROCESSES(&txtime_process);

/*---------------------------------------------------------------------------*/
static int
count_neighbors(void)
{
  uint8_t count;
  struct akes_nbr_entry *next;

  count = 0;
  next = akes_nbr_head();
  while(next) {
    if(next->permanent
        && (next->permanent->drift != AKES_NBR_UNINITIALIZED_DRIFT)) {
      count++;
    }
    next = akes_nbr_next(next);
  }

  return count;
}
/*---------------------------------------------------------------------------*/
static void
on_sent(void *ptr, int status, int transmissions)
{
#ifdef ENERGY_TRACING
  switch(status) {
  case MAC_TX_OK:
    PRINTF("%i;uni;%lu;%lu;%lu;%i\n",
        linkaddr_node_addr.u16,
        packetbuf_get_rtimer_attr(PACKETBUF_ATTR_TXTIME),
        packetbuf_get_rtimer_attr(PACKETBUF_ATTR_RXTIME),
        packetbuf_get_rtimer_attr(PACKETBUF_ATTR_CPUTIME),
        transmissions);
    break;
  default:
    break;
  }
#endif /* ENERGY_TRACING */
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(txtime_process, ev, data)
{
  static struct etimer t;

  PROCESS_BEGIN();

  while(1) {
    etimer_set(&t, adaptivesec_random_clock_time(0, MAX_DELAY));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));

    if(count_neighbors() == (NETWORK_SIZE - 1)) {
      packetbuf_clear();
      memset(packetbuf_dataptr(), 0xFF, RADIO_ASYNC_MAX_FRAME_LEN - NETSTACK_FRAMER.length());
      packetbuf_set_datalen(RADIO_ASYNC_MAX_FRAME_LEN - NETSTACK_FRAMER.length());
      NETSTACK_LLSEC.send(on_sent, NULL);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
