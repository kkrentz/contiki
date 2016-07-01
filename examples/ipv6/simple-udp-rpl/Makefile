all: broadcast-example unicast-sender unicast-receiver
APPS=servreg-hack
CONTIKI=../../..

MODULES += core/net/llsec/adaptivesec

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include
