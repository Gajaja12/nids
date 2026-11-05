# network traffic extraction tool -- session 2

CC      ?= cc
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O2 -g -Wall -Wextra  # libpcap needs u_char/u_int
LDLIBS  ?= -lpcap

nids: nids.c parse.c flow.c parse.h flow.h
	$(CC) $(CFLAGS) -o $@ nids.c parse.c flow.c $(LDLIBS)

.PHONY: check clean
check: nids
	@sh check.sh

clean:
	rm -rf nids nids.dSYM out.intro.txt flows.csv
