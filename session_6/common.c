#include <stdlib.h>
#include <string.h>

#include "common.h"

static u32 g_rng_state;
u64 g_clock_us;
struct attack_state g_atk;

void
rng_seed(u32 seed)
{

	g_rng_state = seed ? seed : 1;
}

u32
rng_u32(void)
{
	u32 x;

	x = g_rng_state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	g_rng_state = x;
	return (x);
}

u32
rng_range(u32 lo, u32 hi)
{

	if (hi <= lo)
		return (lo);
	return (lo + rng_u32() % (hi - lo + 1));
}

size_t
put_u8(u8 *b, size_t o, u8 v)
{

	b[o] = v;
	return (o + 1);
}

size_t
put_u16(u8 *b, size_t o, u16 v)
{

	b[o] = (u8)(v >> 8);
	b[o + 1] = (u8)v;
	return (o + 2);
}

size_t
put_u32(u8 *b, size_t o, u32 v)
{

	b[o] = (u8)(v >> 24);
	b[o + 1] = (u8)(v >> 16);
	b[o + 2] = (u8)(v >> 8);
	b[o + 3] = (u8)v;
	return (o + 4);
}

size_t
put_bytes(u8 *b, size_t o, const u8 *src, size_t n)
{

	memcpy(b + o, src, n);
	return (o + n);
}

static size_t
put_u16le(u8 *b, size_t o, u16 v)
{

	b[o] = (u8)v;
	b[o + 1] = (u8)(v >> 8);
	return (o + 2);
}

static size_t
put_u32le(u8 *b, size_t o, u32 v)
{

	b[o] = (u8)v;
	b[o + 1] = (u8)(v >> 8);
	b[o + 2] = (u8)(v >> 16);
	b[o + 3] = (u8)(v >> 24);
	return (o + 4);
}

u16
checksum16(const u8 *data, size_t len)
{
	u32 sum;
	size_t i;

	sum = 0;
	for (i = 0; i + 1 < len; i += 2)
		sum += ((u32)data[i] << 8) | data[i + 1];
	if (len & 1)
		sum += (u32)data[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffffu) + (sum >> 16);
	return ((u16)~sum);
}

void
parse_ip(const char *s, u8 out[4])
{
	unsigned a, b, c, d;

	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
	    a > 255 || b > 255 || c > 255 || d > 255) {
		fprintf(stderr, "bad IPv4 address: %s\n", s);
		exit(1);
	}
	out[0] = (u8)a;
	out[1] = (u8)b;
	out[2] = (u8)c;
	out[3] = (u8)d;
}

void
parse_ip_port(const char *s, u8 ip[4], u16 *port)
{
	char buf[64];
	char *colon;

	strncpy(buf, s, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	colon = strchr(buf, ':');
	if (colon != NULL) {
		*colon = '\0';
		*port = (u16)atoi(colon + 1);
	}
	parse_ip(buf, ip);
}

void
mac_for_ip(const u8 ip[4], u8 out[6])
{

	out[0] = 0x02;
	out[1] = 0x00;
	out[2] = ip[0];
	out[3] = ip[1];
	out[4] = ip[2];
	out[5] = ip[3];
}

void
write_pcap_global_header(FILE *f)
{
	u8 h[24];
	size_t o;

	o = 0;
	o = put_u32le(h, o, 0xa1b2c3d4u);
	o = put_u16le(h, o, 2);
	o = put_u16le(h, o, 4);
	o = put_u32le(h, o, 0);
	o = put_u32le(h, o, 0);
	o = put_u32le(h, o, 65535);
	o = put_u32le(h, o, 1);
	fwrite(h, 1, o, f);
}

void
write_packet(FILE *f, const u8 *pkt, size_t len)
{
	u8 h[16];
	size_t o;
	u32 sec, usec;

	sec = BASE_TS + (u32)(g_clock_us / 1000000u);
	usec = (u32)(g_clock_us % 1000000u);
	o = 0;
	o = put_u32le(h, o, sec);
	o = put_u32le(h, o, usec);
	o = put_u32le(h, o, (u32)len);
	o = put_u32le(h, o, (u32)len);
	fwrite(h, 1, o, f);
	fwrite(pkt, 1, len, f);
}

size_t
build_eth(u8 *b, const u8 src_ip[4], const u8 dst_ip[4])
{
	u8 smac[6], dmac[6];
	size_t o;

	mac_for_ip(src_ip, smac);
	mac_for_ip(dst_ip, dmac);
	o = 0;
	o = put_bytes(b, o, dmac, 6);
	o = put_bytes(b, o, smac, 6);
	o = put_u16(b, o, 0x0800);
	return (o);
}

size_t
build_ipv4(u8 *b, const u8 src[4], const u8 dst[4], u8 proto,
    u16 payload_len)
{
	size_t o;

	o = 0;
	o = put_u8(b, o, 0x45);
	o = put_u8(b, o, 0);
	o = put_u16(b, o, (u16)(20 + payload_len));
	o = put_u16(b, o, (u16)rng_range(0, 65535));
	o = put_u16(b, o, 0x4000);
	o = put_u8(b, o, 64);
	o = put_u8(b, o, proto);
	o = put_u16(b, o, 0);
	o = put_bytes(b, o, src, 4);
	o = put_bytes(b, o, dst, 4);
	put_u16(b, 10, checksum16(b, 20));
	return (o);
}

size_t
build_tcp(u8 *b, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, u16 win)
{
	size_t o;

	o = 0;
	o = put_u16(b, o, sport);
	o = put_u16(b, o, dport);
	o = put_u32(b, o, seq);
	o = put_u32(b, o, ack);
	o = put_u8(b, o, 5 << 4);
	o = put_u8(b, o, flags);
	o = put_u16(b, o, win);
	o = put_u16(b, o, 0);
	o = put_u16(b, o, 0);
	return (o);
}

size_t
build_udp(u8 *b, u16 sport, u16 dport, u16 payload_len)
{
	size_t o;

	o = 0;
	o = put_u16(b, o, sport);
	o = put_u16(b, o, dport);
	o = put_u16(b, o, (u16)(8 + payload_len));
	o = put_u16(b, o, 0);
	return (o);
}

size_t
build_icmp_echo(u8 *b, u8 type, u16 id, u16 seq, const u8 *payload,
    u16 paylen)
{
	size_t o;

	o = 0;
	o = put_u8(b, o, type);
	o = put_u8(b, o, 0);
	o = put_u16(b, o, 0);
	o = put_u16(b, o, id);
	o = put_u16(b, o, seq);
	o = put_bytes(b, o, payload, paylen);
	put_u16(b, 2, checksum16(b, o));
	return (o);
}

size_t
build_dns_query(u8 *b, u16 txid, const char *label)
{
	size_t o;
	const char *p;

	o = 0;
	o = put_u16(b, o, txid);
	o = put_u16(b, o, 0x0100);
	o = put_u16(b, o, 1);
	o = put_u16(b, o, 0);
	o = put_u16(b, o, 0);
	o = put_u16(b, o, 0);
	o = put_u8(b, o, (u8)strlen(label));
	for (p = label; *p != '\0'; p++)
		o = put_u8(b, o, (u8)*p);
	o = put_u8(b, o, 7);
	o = put_bytes(b, o, (const u8 *)"example", 7);
	o = put_u8(b, o, 0);
	o = put_u16(b, o, 1);
	o = put_u16(b, o, 1);
	return (o);
}

void
send_tcp(FILE *f, const u8 src[4], const u8 dst[4], u16 sport, u16 dport,
    u32 seq, u32 ack, u8 flags, const u8 *payload, u16 paylen)
{
	u8 pkt[MAXPKT];
	size_t o;

	o = build_eth(pkt, src, dst);
	o = build_ipv4(pkt + o, src, dst, 6, (u16)(20 + paylen)) + o;
	o = build_tcp(pkt + o, sport, dport, seq, ack, flags, 65535) + o;
	if (paylen > 0)
		o = put_bytes(pkt, o, payload, paylen);
	write_packet(f, pkt, o);
}

void
send_udp(FILE *f, const u8 src[4], const u8 dst[4], u16 sport, u16 dport,
    const u8 *payload, u16 paylen)
{
	u8 pkt[MAXPKT];
	size_t o;

	o = build_eth(pkt, src, dst);
	o = build_ipv4(pkt + o, src, dst, 17, (u16)(8 + paylen)) + o;
	o = build_udp(pkt + o, sport, dport, paylen) + o;
	if (paylen > 0)
		o = put_bytes(pkt, o, payload, paylen);
	write_packet(f, pkt, o);
}

void
send_icmp_echo(FILE *f, const u8 src[4], const u8 dst[4], u8 type, u16 id,
    u16 seq, const u8 *payload, u16 paylen)
{
	u8 pkt[MAXPKT];
	u8 icmp[64 + 1400];
	size_t io, o;

	io = build_icmp_echo(icmp, type, id, seq, payload, paylen);
	o = build_eth(pkt, src, dst);
	o = build_ipv4(pkt + o, src, dst, 1, (u16)io) + o;
	o = put_bytes(pkt, o, icmp, io);
	write_packet(f, pkt, o);
}

void
tcp_exchange(FILE *f, const u8 cip[4], const u8 sip[4], u16 cport,
    u16 sport, u16 reqlen, u16 resplen)
{
	u8 req[256], resp[1024];
	u32 cseq, sseq;
	u16 i;

	cseq = rng_range(1, 0xfffffff);
	sseq = rng_range(1, 0xfffffff);
	for (i = 0; i < reqlen; i++)
		req[i] = (u8)('A' + (i % 26));
	for (i = 0; i < resplen; i++)
		resp[i] = (u8)('a' + (i % 26));

	send_tcp(f, cip, sip, cport, sport, cseq, 0, TCP_SYN, NULL, 0);
	g_clock_us += rng_range(500, 3000);
	send_tcp(f, sip, cip, sport, cport, sseq, cseq + 1,
	    TCP_SYN | TCP_ACK, NULL, 0);
	g_clock_us += rng_range(500, 3000);
	send_tcp(f, cip, sip, cport, sport, cseq + 1, sseq + 1, TCP_ACK,
	    NULL, 0);
	g_clock_us += rng_range(500, 2000);
	send_tcp(f, cip, sip, cport, sport, cseq + 1, sseq + 1,
	    TCP_ACK | TCP_PSH, req, reqlen);
	g_clock_us += rng_range(2000, 15000);
	send_tcp(f, sip, cip, sport, cport, sseq + 1, cseq + 1 + reqlen,
	    TCP_ACK | TCP_PSH, resp, resplen);
	g_clock_us += rng_range(500, 3000);
	send_tcp(f, cip, sip, cport, sport, cseq + 1 + reqlen,
	    sseq + 1 + resplen, TCP_ACK | TCP_FIN, NULL, 0);
	g_clock_us += rng_range(300, 1500);
	send_tcp(f, sip, cip, sport, cport, sseq + 1 + resplen,
	    cseq + 2 + reqlen, TCP_ACK | TCP_FIN, NULL, 0);
	/* no trailing client ACK: avoids a spurious second flow */
}

void
bot_ip(u32 index, u8 out[4])
{

	if (g_atk.spoof) {
		out[0] = 203;
		out[1] = 0;
		out[2] = 113;
		out[3] = (u8)rng_range(1, 254);
	} else if (g_atk.bots <= 1) {
		out[0] = 203;
		out[1] = 0;
		out[2] = 113;
		out[3] = 50;
	} else {
		out[0] = 203;
		out[1] = 0;
		out[2] = 113;
		out[3] = (u8)(10 + (index % g_atk.bots));
	}
}

static void
background_event(FILE *f, const u8 client[4])
{
	static const u8 webserver[4] = {10, 1, 0, 5};
	static const u8 resolver[4] = {10, 1, 0, 1};
	static const u8 fileserver[4] = {10, 1, 0, 6};
	u32 roll;

	roll = rng_range(0, 99);
	if (roll < 55) {
		tcp_exchange(f, client, webserver,
		    (u16)rng_range(40000, 60000), 443,
		    (u16)rng_range(40, 200), (u16)rng_range(100, 900));
	} else if (roll < 80) {
		static const char hex[] = "0123456789abcdef";
		u8 payload[256];
		char label[9];
		size_t len;
		int i;

		for (i = 0; i < 8; i++)
			label[i] = hex[rng_range(0, 15)];
		label[8] = '\0';
		len = build_dns_query(payload, (u16)rng_range(0, 65535),
		    label);
		send_udp(f, client, resolver, (u16)rng_range(1024, 65535),
		    53, payload, (u16)len);
		g_clock_us += rng_range(5000, 40000);
	} else if (roll < 92) {
		u8 payload[56] = {0};
		u16 id;

		id = (u16)rng_range(1, 65535);
		send_icmp_echo(f, client, resolver, ICMP_ECHO_REQUEST, id,
		    1, payload, sizeof(payload));
		g_clock_us += rng_range(500, 3000);
		send_icmp_echo(f, resolver, client, ICMP_ECHO_REPLY, id, 1,
		    payload, sizeof(payload));
		g_clock_us += rng_range(1000, 10000);
	} else {
		tcp_exchange(f, client, fileserver,
		    (u16)rng_range(40000, 60000), 445,
		    (u16)rng_range(20, 80), (u16)rng_range(60, 300));
	}
}

void
run_scenario(FILE *f, u32 background_events, u64 background_us,
    attack_fn attack, u64 attack_start_us, u64 attack_duration_us)
{
	u64 cursor, bg_remaining, bg_gap_hint, bg_due, atk_due, atk_end;
	u32 atk_index;

	cursor = 0;
	bg_remaining = background_events;
	bg_gap_hint = background_events ?
	    background_us / (background_events + 1) : 0;
	bg_due = bg_remaining ?
	    rng_range(0, (u32)(2 * bg_gap_hint + 1)) : UINT64_MAX;
	atk_due = attack ? attack_start_us : UINT64_MAX;
	atk_end = attack_start_us + attack_duration_us;
	atk_index = 0;

	while (bg_remaining || (attack != NULL && atk_due < atk_end)) {
		if (bg_remaining && bg_due <= atk_due) {
			u8 client[4] = {10, 1, 0, (u8)rng_range(20, 59)};

			g_clock_us = bg_due > cursor ? bg_due : cursor;
			background_event(f, client);
			cursor = g_clock_us;
			bg_remaining--;
			bg_due = bg_remaining ?
			    cursor + rng_range(0, (u32)(2 * bg_gap_hint + 1)) :
			    UINT64_MAX;
		} else if (attack != NULL && atk_due < atk_end) {
			u64 scheduled, inc;

			g_clock_us = atk_due > cursor ? atk_due : cursor;
			scheduled = g_clock_us;
			inc = attack(f, atk_index++);
			cursor = g_clock_us;
			atk_due = scheduled + inc > cursor ?
			    scheduled + inc : cursor;
		} else {
			break;
		}
	}
	g_atk.count_done = atk_index;
}

void
write_labels(const char *out_path, const char *rule, const u8 who[4],
    u32 start_sec, u32 end_sec)
{
	char path[300];
	FILE *f;

	snprintf(path, sizeof(path), "%s.labels.csv", out_path);
	f = fopen(path, "w");
	if (f == NULL) {
		perror("fopen labels");
		exit(1);
	}
	fprintf(f, "rule,src,start,end\n");
	if (rule != NULL)
		fprintf(f, "%s,%u.%u.%u.%u,%u,%u\n", rule,
		    who[0], who[1], who[2], who[3],
		    BASE_TS + start_sec, BASE_TS + end_sec);
	fclose(f);
}
