#ifndef PARSE_H
#define PARSE_H

#include <sys/time.h>

/* called once per packet: data/caplen point at the raw frame, ts is the
   capture timestamp. Edit the implementation in parse.c. */
void handle_packet(const unsigned char *data, unsigned int caplen,
                   struct timeval ts);

#endif
