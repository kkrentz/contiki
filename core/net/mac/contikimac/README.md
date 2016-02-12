The `secrdc_driver` implements a denial-of-sleep-resilient version of ContikiMAC. While this driver was mainly tested using OpenMotes, it should also run on CC2538DKs and Re-Motes.

## Configuration

To enable the `secrdc_driver` add this to your `project-conf.h`:
```c
/* configure RADIO layer */
#include "cpu/cc2538/dev/cc2538-rf-async-autoconf.h"

/* configure RDC and MAC layer */
#include "net/mac/contikimac/secrdc-autoconf.h"

/* configure LLSEC layer (support for coresec is pending) */
#include "net/llsec/adaptivesec/noncoresec-autoconf.h"
/* for further details on configuring adaptivesec, see its README */
```

If you like to use Practical On-The-fly Rejection (POTR), also add this to your `project-conf.h`:
```c
#include "net/mac/contikimac/potr-autoconf.h"
```

If you like to use Intra-Layer Optimization for 802.15.4 Security (ILOS), add this line to your `project-conf.h`:
```c
#include "net/mac/contikimac/ilos-autoconf.h"
```


Finally, to autoconfigure FRAMERs add:
```c
/* configure FRAMERs */
#include "net/mac/contikimac/framer-autoconf.h"
```

## Troubleshooting

### Rev.E-OpenMotes

The 32kHz-clocks of our Rev.E-OpenMotes tick much too slow. However, our implementation also runs on Rev.E-OpenMotes with these settings:
```c
#undef SECRDC_CONF_PHASE_LOCK_FREQ_TOLERANCE
#define SECRDC_CONF_PHASE_LOCK_FREQ_TOLERANCE 6
```

When using Rev.G-OpenMotes and Rev.A1-OpenMotes, you can stick with the default settings.

## Reading

* [ARES2016](https://hpi.de/fileadmin/user_upload/fachgebiete/meinel/papers/Trust_and_Security_Engineering/2016_Krentz_ARES.pdf)
* [EWSN2017](https://hpi.de/fileadmin/user_upload/fachgebiete/meinel/papers/Trust_and_Security_Engineering/2017_Krentz_EWSN.pdf)
* [FPS2017](https://www.researchgate.net/publication/319820120_More_Lightweight_yet_Stronger_802154_Security_through_an_Intra-Layer_Optimization)
