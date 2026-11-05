# network traffic extraction tool -- session 3

CC      ?= cc
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O2 -g -Wall -Wextra  # libpcap needs u_char/u_int
LDLIBS  ?= -lpcap -lm

SRC = nids.c parse.c flow.c window.c profile.c
HDR = parse.h flow.h window.h profile.h

nids: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

.PHONY: check clean
check: nids
	@sh check.sh

clean:
	rm -rf nids nids.dSYM out.intro.txt flows.csv features.csv windows.csv profile.csv
