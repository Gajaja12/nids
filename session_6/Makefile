CC=	cc
CFLAGS=	-std=c99 -Wall -Wextra -O2

SRCS=	main.c common.c attack_synflood.c attack_udpflood.c \
	attack_icmpflood.c attack_dns.c attack_reflection.c \
	attack_beacon.c attack_httpflood.c
OBJS=	${SRCS:.c=.o}
HDRS=	common.h attacks.h

gen_traffic: ${OBJS}
	${CC} ${CFLAGS} -o gen_traffic ${OBJS}

${OBJS}: ${HDRS}

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

clean:
	rm -f gen_traffic ${OBJS}

.PHONY: clean
