#include "attacks.h"

/* g_atk.rate is the period in seconds here, not a per-second rate. */
u64
unit_beacon(FILE *f, u32 index)
{
	u8 bot[4] = {10, 1, 0, 80};
	int jitter_steps;
	double jitter;

	(void)index;
	tcp_exchange(f, bot, g_atk.target, (u16)rng_range(40000, 60000),
	    g_atk.target_port, 20, 40);
	jitter_steps = (int)rng_range(0, 200) - 100;
	jitter = 1.0 + jitter_steps / 1000.0;
	return ((u64)(g_atk.rate * 1000000.0 * jitter));
}
