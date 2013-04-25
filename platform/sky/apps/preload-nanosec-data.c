/**
 * \file
 *         Preloads a TMote Sky with the master key and a seed
 * \author
 *         Konrad Krentz <konrad.krentz@googlemail.com>
 */

#define NANOSEC_DATA
#include "dev/leds.h"
#include "dev/watchdog.h"
#include "sys/node-id.h"
#include "contiki.h"
#include "sys/etimer.h"
#include <stdio.h>
#include <string.h>

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)
#define MASTER_KEY_STR STR(MASTER_KEY)
#define SEED_STR STR(SEED)

static struct etimer etimer;

/*---------------------------------------------------------------------------*/
static void
preload_nanosec_data()
{
#ifdef NODEID
#ifdef MASTER_KEY
#ifdef SEED
  printf("Node id: %d\n", NODEID);
  if (strlen(MASTER_KEY_STR) != 16) {
    printf("Error: master key length %i != 16\n", strlen(MASTER_KEY_STR));
    return;
  } else {
    printf("Master key: %s\n", MASTER_KEY_STR);
  }
  if (strlen(SEED_STR) != 16) {
    printf("Error: seed length %i != 16\n", strlen(SEED_STR));
    return;
  } else {
    printf("Seed: %s\n", SEED_STR);  
  }
#else
#error "Missing variable: SEED=<16-byte seed as ASCII string>"
#endif /* SEED */
#else
#error "Missing variable: MASTER_KEY=<hexadecimal 16-byte master key as ASCII string>"
#endif /* MASTER_KEY */
#else
#error "Missing variable: NODEID=<the ID of the node>"
#endif /* NODEID */
}
/*---------------------------------------------------------------------------*/
PROCESS(preload_nanosec_data_process, "Preload nanosec data process");
AUTOSTART_PROCESSES(&preload_nanosec_data_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(preload_nanosec_data_process, ev, data)
{
  PROCESS_BEGIN();

  etimer_set(&etimer, 5*CLOCK_SECOND);
  PROCESS_WAIT_UNTIL(etimer_expired(&etimer));

  watchdog_stop();
  leds_on(LEDS_RED);
  
  preload_nanosec_data();
  
  leds_off(LEDS_RED + LEDS_BLUE);
  watchdog_start();
  while(1) {
    PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
