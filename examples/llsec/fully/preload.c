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
 *         Preloads pairwise keys.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "net/llsec/adaptivesec/fully.h"
#include "dev/watchdog.h"
#include "dev/leds.h"
#include "sys/etimer.h"
#include "sys/node-id.h"
#include "sys/key-flash.h"
#include "lib/aes-128.h"
#include <stdio.h>
#include <string.h>

static struct etimer etimer;

/*---------------------------------------------------------------------------*/
static void
preload(void)
{
  uint16_t i;
  uint8_t master_key[AES_128_KEY_LENGTH]
      = { 0x11 , 0x11 , 0x11 , 0x11 ,
          0x22 , 0x22 , 0x22 , 0x22 ,
          0x33 , 0x33 , 0x33 , 0x33 ,
          0x44 , 0x44 , 0x44 , 0x44 };
  uint16_t key[FULLY_PAIRWISE_KEY_LEN / 2];

  key_flash_erase_keying_material();
  AES_128.set_key(master_key);
  for(i = 0; i < FULLY_MAX_NODES; i++) {
    memset(key, 0, FULLY_PAIRWISE_KEY_LEN);
    if(i <= node_id) {
      key[0] = i;
      key[1] = node_id;
    } else {
      key[0] = node_id;
      key[1] = i;
    }
    AES_128.encrypt((uint8_t *)key);
    key_flash_append_keying_material(key, FULLY_PAIRWISE_KEY_LEN);
  }
}
/*---------------------------------------------------------------------------*/
static void
restore(void)
{
  uint8_t i;
  uint16_t j;
  unsigned char key[AES_128_BLOCK_SIZE];

  for(j = 0; j < FULLY_MAX_NODES; j++) {
    key_flash_restore_keying_material(key, FULLY_PAIRWISE_KEY_LEN, j * FULLY_PAIRWISE_KEY_LEN);
    printf("%i: ", j);
    for(i = 0; i < FULLY_PAIRWISE_KEY_LEN; i++) {
      printf("%02X", key[i]);
    }
    printf("\n");
  }
}
/*---------------------------------------------------------------------------*/
PROCESS(preload_process, "Preload process");
AUTOSTART_PROCESSES(&preload_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(preload_process, ev, data)
{
  PROCESS_BEGIN();

  etimer_set(&etimer, 5 * CLOCK_SECOND);
  PROCESS_WAIT_UNTIL(etimer_expired(&etimer));

  watchdog_stop();
  leds_on(LEDS_RED);

  preload();

  leds_on(LEDS_BLUE);

  restore();

  leds_off(LEDS_RED + LEDS_BLUE);
  watchdog_start();
  while(1) {
    PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
