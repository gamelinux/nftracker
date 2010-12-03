#Makefile
#CC=gcc
LDFLAGS=-lpcap -lpcre
CONFDIR=../etc
CFLAGS=-O3 -DCONFDIR='"${CONFDIR}/"'
DCFLAGS=-g
PCFLAGS=-g -pg
ifneq (${DEBUG},)
CFLAGS = -g -DDEBUG -Wall -Wno-pointer-sign -Wno-nonnull -DCONFDIR='"${CONFDIR}/"'
endif

DECODE_OBJ = decode-ethernet.o decode-ipv4.o decode-ipv6.o decode-others.o decode-tcp.o decode-udp.o decode-vlan.o
FILTER_OBJ = util-filter.o util-filter-network.o
SEARCH_OBJ = util-search.o util-search-pcre.o
LOG_OBJ = util-log.o util-log-cvs.o
SESSION_OBJ = util-session-queue.o util-session.o 
MISC_OBJ = bstrlib.o config.o util-system.o util-stats.o
SYSTEM_OBJ = util-system.o util-system-end.o
OBJECTS = ${MISC_OBJ} ${SESSION_OBJ} ${LOG_OBJ} ${DECODE_OBJ} ${FILTER_OBJ} ${SEARCH_OBJ} ${SYSTEM_OBJ} nftracker.o

all: nftracker

nftracker: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

debug:
	 ${MAKE} DEBUG=y

profile:
	${MAKE} CFLAGS+='${PCFLAGS}'

clean:
	-rm -v $(OBJECTS)
	-rm nftracker

indent:
	find -type f -name '*.[ch]' | xargs indent -kr -i4 -cdb -sc -sob -ss -ncs -ts8 -nut

# oldschool header file dependency checking.
deps:
	-rm -f deps.d
	for i in $(subst .o,.c,$(OBJECTS)); do gcc -MM $$i >> deps.d; done

ifneq ($(wildcard deps.d),)
include deps.d
endif

tags: *.h *.c
	ctags -R
