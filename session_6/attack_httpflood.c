#include "attacks.h"

u64
unit_httpflood(FILE *f, u32 index)
{
	u8 src[4];

	bot_ip(index, src);
	tcp_exchange(f, src, g_atk.target, (u16)rng_range(40000, 60000),
	    g_atk.target_port, (u16)rng_range(60, 200),
	    (u16)rng_range(40, 120));
	return (1000000u / (g_atk.rate ? g_atk.rate : 1));
}
