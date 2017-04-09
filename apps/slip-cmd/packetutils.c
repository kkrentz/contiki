/*
 * Copyright (c) 2011, Swedish Institute of Computer Science.
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
 */

#include "contiki.h"
#include "packetutils.h"
#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

/*---------------------------------------------------------------------------*/
int16_t
packetutils_serialize(uint8_t *dst)
{
  int16_t pos;
  uint16_t attribute_count;
  uint16_t attribute_count_pos;
  uint16_t i;
  uint16_t attr;
  const linkaddr_t *addr;

  /* serialize hdrlen, totlen, and data */
  packetbuf_compact();
  dst[0] = packetbuf_hdrlen();
  dst[1] = packetbuf_copyto(dst + 2);
  if(!dst[1]) {
    PRINTF("packetutils: packetbuf_copyto failed\n");
    return -1;
  }
  pos = 2 + dst[1];

  /* reserve space for attribute count */
  attribute_count_pos = pos++;

  /* serialize non-zero packetbuf attributes */
  attribute_count = 0;
  for(i = 0; i < PACKETBUF_NUM_ATTRS; i++) {
    attr = packetbuf_attr(i);
    if(attr != 0) {
      dst[pos++] = i;
      dst[pos++] = attr >> 8;
      dst[pos++] = attr & 255;
      attribute_count++;
    }
  }
  dst[attribute_count_pos] = attribute_count;

  /* serialize addresses */
  for(i = PACKETBUF_NUM_ATTRS; i < PACKETBUF_ATTR_MAX; i++) {
    addr = packetbuf_addr(i);
    memcpy(dst + pos, addr->u8, LINKADDR_SIZE);
    pos += LINKADDR_SIZE;
  }

  return pos;
}
/*---------------------------------------------------------------------------*/
int16_t
packetutils_deserialize(const uint8_t *src)
{
  int16_t pos;
  uint16_t attribute_count;
  uint16_t i;
  linkaddr_t addr;

  /* deserialize hdrlen, totlen, and data */
  packetbuf_copyfrom(src + 2, src[1]);
  packetbuf_hdrreduce(src[0]);
  pos = 2 + src[1];

  /* deserialize attribute count */
  attribute_count = src[pos++];

  for(i = 0; i < attribute_count; i++) {
    if(src[pos] >= PACKETBUF_NUM_ATTRS) {
      PRINTF("packetutils: illegal attribute %u\n", src[pos]);
      return -1;
    }
    packetbuf_set_attr(src[pos], (src[pos + 1] << 8) | src[pos + 2]);
    pos += 3;
  }

  /* deserialize addresses */
  for(i = PACKETBUF_NUM_ATTRS; i < PACKETBUF_ATTR_MAX; i++) {
    memcpy(addr.u8, src + pos, LINKADDR_SIZE);
    packetbuf_set_addr(i, &addr);
    pos += LINKADDR_SIZE;
  }

  return pos;
}
/*---------------------------------------------------------------------------*/
