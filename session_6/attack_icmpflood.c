#include "attacks.h"

u64
unit_icmpflood(FILE *f, u32 index)
{
	u8 src[4];
	u8 payload[56] = {0};

	bot_ip(index, src);
	send_icmp_echo(f, src, g_atk.target, ICMP_ECHO_REQUEST,
	    (u16)rng_range(1, 65535), (u16)index, payload, sizeof(payload));
	return (1000000u / (g_atk.rate ? g_atk.rate : 1));
}
