# network traffic extraction tool -- session 4

CC      ?= cc
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O2 -g -Wall -Wextra  # libpcap needs u_char/u_int
LDLIBS  ?= -lpcap -lm

SRC = nids.c parse.c flow.c window.c profile.c detect.c
HDR = parse.h flow.h window.h profile.h detect.h

nids: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

.PHONY: check clean
check: nids
	@sh check.sh

clean:
	rm -rf nids out.intro.txt flows.csv features.csv windows.csv profile.csv alerts.csv
