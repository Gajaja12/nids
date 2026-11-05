#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAXPKT	1600

#define TCP_FIN	0x01
#define TCP_SYN	0x02
#define TCP_RST	0x04
#define TCP_PSH	0x08
#define TCP_ACK	0x10

#define BASE_TS	1700000000u

#define ICMP_ECHO_REQUEST	8
#define ICMP_ECHO_REPLY		0

extern u64 g_clock_us;

void	rng_seed(u32 seed);
u32	rng_u32(void);
u32	rng_range(u32 lo, u32 hi);

size_t	put_u8(u8 *b, size_t o, u8 v);
size_t	put_u16(u8 *b, size_t o, u16 v);
size_t	put_u32(u8 *b, size_t o, u32 v);
size_t	put_bytes(u8 *b, size_t o, const u8 *src, size_t n);
u16	checksum16(const u8 *data, size_t len);

void	parse_ip(const char *s, u8 out[4]);
void	parse_ip_port(const char *s, u8 ip[4], u16 *port);
void	mac_for_ip(const u8 ip[4], u8 out[6]);

void	write_pcap_global_header(FILE *f);
void	write_packet(FILE *f, const u8 *pkt, size_t len);

size_t	build_eth(u8 *b, const u8 src_ip[4], const u8 dst_ip[4]);
size_t	build_ipv4(u8 *b, const u8 src[4], const u8 dst[4], u8 proto,
	    u16 payload_len);
size_t	build_tcp(u8 *b, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags,
	    u16 win);
size_t	build_udp(u8 *b, u16 sport, u16 dport, u16 payload_len);
size_t	build_icmp_echo(u8 *b, u8 type, u16 id, u16 seq, const u8 *payload,
	    u16 paylen);
size_t	build_dns_query(u8 *b, u16 txid, const char *label);

void	send_tcp(FILE *f, const u8 src[4], const u8 dst[4], u16 sport,
	    u16 dport, u32 seq, u32 ack, u8 flags, const u8 *payload,
	    u16 paylen);
void	send_udp(FILE *f, const u8 src[4], const u8 dst[4], u16 sport,
	    u16 dport, const u8 *payload, u16 paylen);
void	send_icmp_echo(FILE *f, const u8 src[4], const u8 dst[4], u8 type,
	    u16 id, u16 seq, const u8 *payload, u16 paylen);
void	tcp_exchange(FILE *f, const u8 cip[4], const u8 sip[4], u16 cport,
	    u16 sport, u16 reqlen, u16 resplen);

void	write_labels(const char *out_path, const char *rule,
	    const u8 who[4], u32 start_sec, u32 end_sec);

struct attack_state {
	u8	target[4];
	u8	victim[4];
	u16	target_port;
	u32	bots;
	u32	spoof;
	u32	rate;
	u32	duration;
	u32	count_done;
	u16	payload_len;
};
extern struct attack_state g_atk;

void	bot_ip(u32 index, u8 out[4]);

typedef u64 (*attack_fn)(FILE *, u32);

void	run_scenario(FILE *f, u32 background_events, u64 background_us,
	    attack_fn attack, u64 attack_start_us, u64 attack_duration_us);

#endif /* !COMMON_H */
