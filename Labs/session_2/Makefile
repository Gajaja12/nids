# network traffic extraction tool -- session 1

CC      ?= cc
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O2 -g -Wall -Wextra  # libpcap needs u_char/u_int
LDLIBS  ?= -lpcap

nids: nids.c parse.c parse.h
	$(CC) $(CFLAGS) -o $@ nids.c parse.c $(LDLIBS)

.PHONY: check clean
check: nids
	@sh check.sh

clean:
	rm -f nids out.intro.txt
