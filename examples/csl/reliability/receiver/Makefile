CONTIKI_PROJECT = receiver
all: $(CONTIKI_PROJECT)

CONTIKI=../../../..

MODULES += core/net/llsec/adaptivesec
MODULES += core/net/mac/csl

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
SMALL=1

include $(CONTIKI)/Makefile.include
