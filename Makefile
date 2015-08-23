# Makefile for monitoring utilies
#

CFLAGS			= 
CC			= gcc $(CFLAGS)

MODULES			= modsec_mon.o ipcache.o history.o util.o

all			: modsec_mon

modsec_mon		: $(MODULES)
	$(CC) -o modsec_mon $(MODULES)

.c.o			: 
	$(CC) -c $< -o $@

