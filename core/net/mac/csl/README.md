## Troubleshooting

### Packet Loss

The default size of the queuebuf is very low, which causes problems when, e.g., pinging at high rates. You can increase the size of the queuebuf like so:
```c
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM 20
```
