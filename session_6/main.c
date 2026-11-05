#include <stdlib.h>
#include <string.h>

#include "attacks.h"

static void
usage(const char *prog)
{

	fprintf(stderr,
"usage: %s --out FILE.pcap [options]\n"
"       %s --help\n"
"\n"
"Writes one pcap file of synthetic traffic: a background mix of\n"
"ordinary events, plus, if --pattern is given, one attack on top of\n"
"it. It opens no socket and touches no interface; the only output is\n"
"the file.\n"
"\n"
"  --out FILE            output pcap file (required)\n"
"  --seed N               PRNG seed; same seed, same file (default 1)\n"
"  --background SEC       length of the capture (default 120)\n"
"  --events N              number of background events: a mix of web,\n"
"                           DNS, ping and file-share traffic\n"
"                           (default 40)\n"
"  --pattern NAME           synflood | udpflood | icmpflood | dns |\n"
"                           reflection | beacon | httpflood (omit for a\n"
"                           clean background-only file)\n"
"  --target IP[:PORT]       attack target (or victim, for reflection)\n"
"  --start SEC              when the attack begins (default background/2)\n"
"  --duration SEC           how long the attack lasts (default 30)\n"
"  --rate N                 units per second (synflood/udpflood/\n"
"                           icmpflood/dns/reflection/httpflood); for\n"
"                           beacon, the interval in seconds instead\n"
"  --bots N                 number of distinct source hosts (default 1)\n"
"  --spoof                 synflood/udpflood: a fresh random source on\n"
"                           every packet, instead of a fixed pool\n"
"  --payload N              bytes per unit (udpflood/reflection);\n"
"                           default 60 for udpflood, 500 for reflection\n"
"\n"
"Examples:\n"
"  %s --out clean.pcap --background 120\n"
"      background traffic only, no attack; a baseline to check your\n"
"      detector raises nothing on quiet traffic\n"
"\n"
"  %s --out synflood.pcap --background 120 --pattern synflood \\\n"
"      --start 60 --duration 20 --rate 30\n"
"      a SYN flood from one source, starting at t=60s\n"
"\n"
"  %s --out synflood_dist.pcap --background 120 --pattern synflood \\\n"
"      --start 60 --duration 20 --rate 30 --bots 20 --spoof\n"
"      the same flood, spread over 20 spoofed sources instead of one\n"
"\n"
"  %s --out beacon.pcap --background 300 --pattern beacon \\\n"
"      --rate 20 --duration 300\n"
"      a beacon every ~20s; --duration must cover several periods\n",
	    prog, prog, prog, prog, prog, prog);
}

int
main(int argc, char **argv)
{
	const char *out, *pattern, *target_s, *rule;
	u32 seed, background_sec, events;
	u32 start_sec, duration_sec, rate, bots, bots_set;
	u32 spoof, payload_len;
	u16 default_port;
	attack_fn fn;
	u8 who[4];
	FILE *f;
	int i;

	out = NULL;
	pattern = NULL;
	target_s = NULL;
	rule = NULL;
	fn = NULL;
	seed = 1;
	background_sec = 120;
	events = 40;
	start_sec = UINT32_MAX;
	duration_sec = 30;
	rate = 10;
	bots = 1;
	bots_set = 0;
	spoof = 0;
	payload_len = 0;
	default_port = 443;
	memset(who, 0, sizeof(who));

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return (0);
		} else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
			out = argv[++i];
		} else if (!strcmp(argv[i], "--seed") && i + 1 < argc) {
			seed = (u32)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--background") && i + 1 < argc) {
			background_sec = (u32)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--events") && i + 1 < argc) {
			events = (u32)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--pattern") && i + 1 < argc) {
			pattern = argv[++i];
		} else if (!strcmp(argv[i], "--target") && i + 1 < argc) {
			target_s = argv[++i];
		} else if (!strcmp(argv[i], "--start") && i + 1 < argc) {
			start_sec = (u32)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--duration") && i + 1 < argc) {
			duration_sec = (u32)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--rate") && i + 1 < argc) {
			rate = (u32)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--bots") && i + 1 < argc) {
			bots = (u32)atoi(argv[++i]);
			bots_set = 1;
		} else if (!strcmp(argv[i], "--spoof")) {
			spoof = 1;
		} else if (!strcmp(argv[i], "--payload") && i + 1 < argc) {
			payload_len = (u32)atoi(argv[++i]);
		} else {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return (1);
		}
	}
	if (out == NULL) {
		usage(argv[0]);
		return (1);
	}
	if (start_sec == UINT32_MAX)
		start_sec = background_sec / 2;

	rng_seed(seed);
	g_atk.bots = bots;
	g_atk.spoof = spoof;
	g_atk.rate = rate;
	g_atk.duration = duration_sec;

	if (pattern != NULL) {
		if (!strcmp(pattern, "synflood")) {
			fn = unit_synflood;
			rule = bots > 1 ? "synflooddist" : "synflood";
			default_port = 443;
		} else if (!strcmp(pattern, "udpflood")) {
			fn = unit_udpflood;
			rule = "udpflood";
			default_port = 0;
			if (payload_len == 0)
				payload_len = 60;
		} else if (!strcmp(pattern, "icmpflood")) {
			fn = unit_icmpflood;
			rule = "icmpflood";
			default_port = 0;
		} else if (!strcmp(pattern, "dns")) {
			fn = unit_dns_randsub;
			rule = "dnsrandsub";
			default_port = 53;
		} else if (!strcmp(pattern, "reflection")) {
			fn = unit_reflection;
			rule = "reflection";
			default_port = 0;
			if (payload_len == 0)
				payload_len = 500;
			if (!bots_set)
				bots = 20;
			g_atk.bots = bots;
		} else if (!strcmp(pattern, "beacon")) {
			fn = unit_beacon;
			rule = "beacon";
			default_port = 443;
		} else if (!strcmp(pattern, "httpflood")) {
			fn = unit_httpflood;
			rule = "httpflood";
			default_port = 80;
			if (!bots_set)
				bots = 30;
			g_atk.bots = bots;
		} else {
			fprintf(stderr, "unknown --pattern: %s\n", pattern);
			return (1);
		}
	}
	g_atk.payload_len = (u16)payload_len;

	if (fn != NULL) {
		if (target_s != NULL)
			parse_ip_port(target_s, g_atk.target, &default_port);
		else
			parse_ip("10.1.0.5", g_atk.target);
		g_atk.target_port = default_port;
		memcpy(g_atk.victim, g_atk.target, 4);

		if ((!strcmp(pattern, "synflood") ||
		    !strcmp(pattern, "httpflood")) && bots <= 1 && !spoof) {
			who[0] = 203;
			who[1] = 0;
			who[2] = 113;
			who[3] = 50;
		} else if (!strcmp(pattern, "beacon")) {
			who[0] = 10;
			who[1] = 1;
			who[2] = 0;
			who[3] = 80;
		} else if (!strcmp(pattern, "dns") && bots <= 1) {
			who[0] = 10;
			who[1] = 1;
			who[2] = 0;
			who[3] = 70;
		} else {
			memcpy(who, g_atk.target, 4);
		}
	}

	f = fopen(out, "wb");
	if (f == NULL) {
		perror("fopen");
		return (1);
	}
	write_pcap_global_header(f);
	run_scenario(f, events, (u64)background_sec * 1000000u, fn,
	    (u64)start_sec * 1000000u, (u64)duration_sec * 1000000u);
	fclose(f);

	write_labels(out, rule, who, start_sec, start_sec + duration_sec);
	fprintf(stderr, "%s: %u background events, %u attack units\n",
	    out, events, g_atk.count_done);
	return (0);
}
