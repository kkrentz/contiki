/*
 * Copyright (c) 2012, Texas Instruments Incorporated - http://www.ti.com/
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
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         Asynchronous RADIO driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "dev/radio-async.h"
#include "sys/clock.h"
#include "sys/rtimer.h"
#include "sys/energest.h"
#include "net/packetbuf.h"
#include "net/linkaddr.h"
#include "net/netstack.h"
#include "dev/cc2538-rf.h"
#include "dev/udma.h"
#include "dev/rfcore.h"
#include "dev/sys-ctrl.h"
#include "reg.h"
#include <string.h>

#define CRC_BIT_MASK 0x80
#define LQI_BIT_MASK 0x7F
#define RSSI_OFFSET 73
#define UDMA_TX_FLAGS (UDMA_CHCTL_ARBSIZE_128 \
    | UDMA_CHCTL_XFERMODE_AUTO \
    | UDMA_CHCTL_SRCSIZE_8 \
    | UDMA_CHCTL_DSTSIZE_8 \
    | UDMA_CHCTL_SRCINC_8 \
    | UDMA_CHCTL_DSTINC_NONE)
#define OUTPUT_CONFIG_COUNT (sizeof(output_power) / sizeof(output_config_t))
#define OUTPUT_POWER_MIN (output_power[OUTPUT_CONFIG_COUNT - 1].power)
#define OUTPUT_POWER_MAX (output_power[0].power)

#define DEBUG 0
#include <stdio.h>
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

typedef struct output_config {
  radio_value_t power;
  uint8_t txpower_val;
} output_config_t;

static void flushrx(void);

static const output_config_t output_power[] = {
  {  7, 0xFF },
  {  5, 0xED },
  {  3, 0xD5 },
  {  1, 0xC5 },
  {  0, 0xB6 },
  { -1, 0xB0 },
  { -3, 0xA1 },
  { -5, 0x91 },
  { -7, 0x88 },
  { -9, 0x72 },
  {-11, 0x62 },
  {-13, 0x58 },
  {-15, 0x42 },
  {-24, 0x00 },
};
static volatile uint8_t read_bytes;
#if DEBUG
static volatile int in_rx_mode;
static volatile int in_tx_mode;
#endif /* DEBUG */
static volatile radio_sfd_callback_t sfd_callback;
static volatile radio_fifop_callback_t fifop_callback;
static volatile radio_txdone_callback_t txdone_callback;
static volatile uint8_t current_channel;

/*---------------------------------------------------------------------------*/
static int
is_transmitting(void)
{
  return REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_TX_ACTIVE;
}
/*---------------------------------------------------------------------------*/
static void
prepare_raw(uint8_t *src, uint8_t len)
{
  udma_set_channel_src(CC2538_RF_CONF_TX_DMA_CHAN,
      (uint32_t)(src) + (len - 1));
  udma_set_channel_control_word(CC2538_RF_CONF_TX_DMA_CHAN,
      UDMA_TX_FLAGS | udma_xfer_size(len));
  udma_channel_enable(CC2538_RF_CONF_TX_DMA_CHAN);
  udma_channel_sw_request(CC2538_RF_CONF_TX_DMA_CHAN);
}
/*---------------------------------------------------------------------------*/
static void
set_shr_search(int enable)
{
  if(enable) {
    REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_RX_MODE;
  } else {
    REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_RX_MODE;
  }
}
/*---------------------------------------------------------------------------*/
static void
set_channel(uint8_t channel)
{
  REG(RFCORE_XREG_FREQCTRL) = CC2538_RF_CHANNEL_MIN
      + (channel - CC2538_RF_CHANNEL_MIN)
      * CC2538_RF_CHANNEL_SPACING;
  current_channel = channel;
}
/*---------------------------------------------------------------------------*/
static void
set_tx_power(radio_value_t power)
{
  uint8_t i;

  for(i = 1; i < OUTPUT_CONFIG_COUNT; i++) {
    if(power > output_power[i].power) {
      break;
    }
  }
  REG(RFCORE_XREG_TXPOWER) = output_power[i - 1].txpower_val;
}
/*---------------------------------------------------------------------------*/
static void
wait_for_rssi(void)
{
  while(!(REG(RFCORE_XREG_RSSISTAT) & RFCORE_XREG_RSSISTAT_RSSI_VALID));
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  /* Enable clock for the RF Core while Running, in Sleep and Deep Sleep */
  REG(SYS_CTRL_RCGCRFC) = 1;
  REG(SYS_CTRL_SCGCRFC) = 1;
  REG(SYS_CTRL_DCGCRFC) = 1;

  /* See Section "Register Settings Update" in the User's Guide */
  REG(RFCORE_XREG_AGCCTRL1) = 0x15;
  REG(RFCORE_XREG_TXFILTCFG) = 0x09;
  REG(ANA_REGS_IVCTRL) = 0x0B;
  REG(RFCORE_XREG_FSCAL1) = 0x01;

#if RADIO_ASYNC_WITH_CHECKSUM
  /* Note: the default value of FRMCTRL0 in the User's Guide is wrong */
  REG(RFCORE_XREG_FRMCTRL0) = RFCORE_XREG_FRMCTRL0_AUTOCRC;
#endif /* RADIO_ASYNC_WITH_CHECKSUM */

  /* Disable source address matching and AUTOPEND */
  REG(RFCORE_XREG_SRCMATCH) = 0;

  /* Disable disabling of SFD detection after frame reception */
  REG(RFCORE_XREG_FSMCTRL) |= RFCORE_XREG_FSMCTRL_RX2RX_TIME_OFF;

  /* Set TX Power */
  REG(RFCORE_XREG_TXPOWER) = CC2538_RF_TX_POWER;

  /* Set channel */
  set_channel(CC2538_RF_CHANNEL);

  /* Disable frame filtering */
  REG(RFCORE_XREG_FRMFILT0) &= ~RFCORE_XREG_FRMFILT0_FRAME_FILTER_EN;

  /* Configure DMA */
  udma_channel_mask_set(CC2538_RF_CONF_TX_DMA_CHAN);
  udma_set_channel_dst(CC2538_RF_CONF_TX_DMA_CHAN, RFCORE_SFR_RFDATA);

  /* Configure interrupts */
  REG(RFCORE_XREG_RFIRQM1) |= RFCORE_XREG_RFIRQM1_TXDONE;
  NVIC_EnableIRQ(RF_TX_RX_IRQn);
#if DEBUG
  REG(RFCORE_XREG_RFERRM) = RFCORE_XREG_RFERRM_RFERRM;
  NVIC_EnableIRQ(RF_ERR_IRQn);
#endif /* DEBUG */

  flushrx();
}
/*---------------------------------------------------------------------------*/
void
cc2538_rf_async_rxtx_isr(void)
{
  if(REG(RFCORE_SFR_RFIRQF0) & RFCORE_XREG_RFIRQM0_SFD) {
    REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_XREG_RFIRQM0_SFD;
    if(sfd_callback) {
      sfd_callback();
    }
  }
  if(REG(RFCORE_SFR_RFIRQF0) & RFCORE_XREG_RFIRQM0_FIFOP) {
    REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_XREG_RFIRQM0_FIFOP;
    if(fifop_callback) {
      fifop_callback();
    }
  }
  if(REG(RFCORE_SFR_RFIRQF1) & RFCORE_XREG_RFIRQM1_TXDONE) {
    REG(RFCORE_SFR_RFIRQF1) &= ~RFCORE_XREG_RFIRQM1_TXDONE;
#if DEBUG
    in_tx_mode = 0;
    in_rx_mode = 1;
#endif /* DEBUG */
    ENERGEST_SWITCH(ENERGEST_TYPE_TRANSMIT, ENERGEST_TYPE_LISTEN);
    if(txdone_callback) {
      txdone_callback();
    }
  }
}
/*---------------------------------------------------------------------------*/
void
cc2538_rf_async_error_isr(void)
{
  PRINTF("cc2538-rf-async: error 0x%08lx occurred\n", REG(RFCORE_SFR_RFERRF));
  REG(RFCORE_SFR_RFERRF) = 0;
}
/*---------------------------------------------------------------------------*/
static void
prepare(uint8_t *length_then_payload)
{
  CC2538_RF_CSP_ISFLUSHTX();
  REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_TX_MODE_LOOP;
  prepare_raw(length_then_payload, length_then_payload[0] + 1);
}
/*---------------------------------------------------------------------------*/
static void
transmit(void)
{
#if DEBUG
  if(in_tx_mode) {
    PRINTF("cc2538-rf-async: already transmitting\n");
    return;
  }
  in_rx_mode = 0;
  in_tx_mode = 1;
#endif /* DEBUG */

  CC2538_RF_CSP_ISTXON();
  ENERGEST_SWITCH(ENERGEST_TYPE_LISTEN, ENERGEST_TYPE_TRANSMIT);
}
/*---------------------------------------------------------------------------*/
static void
on(void)
{
#if DEBUG
  if(in_rx_mode) {
    PRINTF("cc2538-rf-async: already on\n");
    return;
  }
  in_rx_mode = 1;
#endif /* DEBUG */

  CC2538_RF_CSP_ISRXON();
  ENERGEST_ON(ENERGEST_TYPE_LISTEN);
}
/*---------------------------------------------------------------------------*/
static void
off(void)
{
#if DEBUG
  if(!in_rx_mode && !in_tx_mode) {
    PRINTF("cc2538-rf-async: already off\n");
    return;
  }
  in_rx_mode = 0;
  in_tx_mode = 0;
#endif /* DEBUG */

  CC2538_RF_CSP_ISRFOFF();
  ENERGEST_OFF(ENERGEST_TYPE_TRANSMIT);
  ENERGEST_OFF(ENERGEST_TYPE_LISTEN);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_value(radio_param_t param, radio_value_t *value)
{
  if(!value) {
    return RADIO_RESULT_INVALID_VALUE;
  }

  switch(param) {
  case RADIO_PARAM_CHANNEL:
    *value = (radio_value_t)current_channel;
    return RADIO_RESULT_OK;
  case RADIO_PARAM_IQ_LSBS:
    wait_for_rssi();
    *value = (radio_value_t)REG(RFCORE_XREG_RFRND);
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_value(radio_param_t param, radio_value_t value)
{
  switch(param) {
  case RADIO_PARAM_SHR_SEARCH:
    set_shr_search(value);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_SHR_DEM_ZEROES:
    if((value < 1) || (value > 3)) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    REG(RFCORE_XREG_MDMCTRL0) &= ~RFCORE_XREG_MDMCTRL0_DEM_NUM_ZEROS;
    REG(RFCORE_XREG_MDMCTRL0) |= value << 6;
    return RADIO_RESULT_OK;
  case RADIO_PARAM_SHR_MOD_ZEROES:
    if((value < 4) || (value > 34) || (value & 1)) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    REG(RFCORE_XREG_MDMCTRL0) &= ~RFCORE_XREG_MDMCTRL0_PREAMBLE_LENGTH;
    REG(RFCORE_XREG_MDMCTRL0) |= value - 4;
    return RADIO_RESULT_OK;
  case RADIO_PARAM_SHR_THRESHOLD:
    if(value & ~RFCORE_XREG_MDMCTRL1_CORR_THR) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    REG(RFCORE_XREG_MDMCTRL1) &=
        ~(RFCORE_XREG_MDMCTRL1_CORR_THR_SFD | RFCORE_XREG_MDMCTRL1_CORR_THR);
    if(value) {
      REG(RFCORE_XREG_MDMCTRL1) &= RFCORE_XREG_MDMCTRL1_CORR_THR_SFD | value;
    }
    return RADIO_RESULT_OK;
  case RADIO_PARAM_CHANNEL:
    if((value < CC2538_RF_CHANNEL_MIN)
        || (value > CC2538_RF_CHANNEL_MAX)) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    set_channel(value);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_TXPOWER:
    if(value < OUTPUT_POWER_MIN || value > OUTPUT_POWER_MAX) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    set_tx_power(value);
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
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
  switch(param) {
  case RADIO_PARAM_FIFOP_CALLBACK:
    fifop_callback = (radio_fifop_callback_t) src;
    if(!size) {
      REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_FIFOP;
      return RADIO_RESULT_OK;
    }
    REG(RFCORE_XREG_FIFOPCTRL) = size;
    REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_FIFOP;
    return RADIO_RESULT_OK;
  case RADIO_PARAM_SFD_CALLBACK:
    sfd_callback = (radio_sfd_callback_t) src;
    if(sfd_callback) {
      REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_SFD;
    } else {
      REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_SFD;
    }
    return RADIO_RESULT_OK;
  case RADIO_PARAM_TXDONE_CALLBACK:
    txdone_callback = (radio_txdone_callback_t) src;
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
}
/*---------------------------------------------------------------------------*/
static void
flushrx(void)
{
  CC2538_RF_CSP_ISFLUSHRX();
  read_bytes = 0;
}
/*---------------------------------------------------------------------------*/
static uint8_t
read_phy_header(void)
{
  uint8_t len;

  while(!REG(RFCORE_XREG_RXFIFOCNT));
  len = REG(RFCORE_SFR_RFDATA);

  /* ignore reserved bit */
  len &= ~(1 << 7);

#if RADIO_ASYNC_WITH_CHECKSUM
  if(len < RADIO_ASYNC_CHECKSUM_LEN) {
    PRINTF("cc2538-rf-async: frame too short\n");
    return 0;
  }
#endif /* RADIO_ASYNC_WITH_CHECKSUM */

  read_bytes = 0;

  return len - RADIO_ASYNC_CHECKSUM_LEN;
}
/*---------------------------------------------------------------------------*/
static uint8_t
read_phy_header_and_set_datalen(void)
{
  uint8_t len;

  len = read_phy_header();
  packetbuf_set_datalen(len);
  return len;
}
/*---------------------------------------------------------------------------*/
static void
read_raw(uint8_t *buf, uint8_t bytes)
{
  uint8_t i;

  while(REG(RFCORE_XREG_RXFIFOCNT) < bytes);
  for(i = 0; i < bytes; i++) {
    buf[i] = REG(RFCORE_SFR_RFDATA);
  }
}
/*---------------------------------------------------------------------------*/
static uint8_t
remaining_payload_bytes(void)
{
  return packetbuf_totlen() - read_bytes;
}
/*---------------------------------------------------------------------------*/
static int
read_payload(uint8_t bytes)
{
  if(remaining_payload_bytes() < bytes) {
    return 0;
  }
  read_raw(((uint8_t *)packetbuf_hdrptr()) + read_bytes, bytes);
  read_bytes += bytes;
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
read_footer(void)
{
#if RADIO_ASYNC_WITH_CHECKSUM
  uint8_t crc_corr;
  int8_t rssi;

  rssi = ((int8_t)REG(RFCORE_SFR_RFDATA)) - RSSI_OFFSET;
  crc_corr = REG(RFCORE_SFR_RFDATA);

  packetbuf_set_attr(PACKETBUF_ATTR_RSSI, rssi);
  packetbuf_set_attr(PACKETBUF_ATTR_LINK_QUALITY, crc_corr & LQI_BIT_MASK);

  if(!(crc_corr & CRC_BIT_MASK)) {
    PRINTF("cc2538-rf-async: invalid CRC\n");
    return 0;
  }
#endif /* RADIO_ASYNC_WITH_CHECKSUM */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int8_t
get_rssi(void)
{
  int8_t rssi;

  wait_for_rssi();
  rssi = REG(RFCORE_XREG_RSSI);
  rssi -= RSSI_OFFSET;

  return rssi;
}
/*---------------------------------------------------------------------------*/
static void
reprepare(uint8_t offset, uint8_t *patch, uint8_t patch_len)
{
  uint8_t i;

  for(i = 0; i < patch_len; i++) {
    REG(RFCORE_FFSM_TX_FIFO + 4 * (offset + 1 /* Frame Length */ + i)) = patch[i];
  }
}
/*---------------------------------------------------------------------------*/
static void
prepare_loop(void)
{
  CC2538_RF_CSP_ISFLUSHTX();
  REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_TX_MODE_LOOP;
}
/*---------------------------------------------------------------------------*/
static void
append_to_loop(uint8_t *appendix, uint8_t appendix_len)
{
  prepare_raw(appendix, appendix_len);
}
/*---------------------------------------------------------------------------*/
static void
finish_loop(void)
{
  uint8_t end_pos;

  if(!is_transmitting()) {
    PRINTF("cc2538-rf-async: am not looping\n");
    return;
  }

  end_pos = (uint8_t)REG(RFCORE_XREG_TXLAST_PTR);
  end_pos++;
  while((REG(RFCORE_XREG_TXFIRST_PTR)) != end_pos);
  while((REG(RFCORE_XREG_TXFIRST_PTR)) == end_pos);
}
/*---------------------------------------------------------------------------*/
const struct radio_async_driver cc2538_rf_async_driver = {
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

/** @} */
