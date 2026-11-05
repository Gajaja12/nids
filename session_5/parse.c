/*
 * parse.c -- sesion 5 (el parser no cambia; solo se anaden contadores).
 *
 * Cambio respecto a la sesion 1: el parser ya no imprime, rellena una
 * struct packet (parse_packet). handle_packet decide despues que hacer con
 * ella: en modo --flows la pasa a la tabla de flujos; sin --flows imprime la
 * misma linea que en la sesion 1 (asi `make check` sigue valiendo).
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "parse.h"
#include "flow.h"
#include "window.h"

/* Lee un campo de 16 bits en big-endian sin asumir alineacion (memcpy) */
static uint16_t rd16(const unsigned char *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return ntohs(v);
}

/* Lee 4 bytes y los deja como entero de host: a.b.c.d -> 0xAABBCCDD */
static uint32_t rd32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

enum parse_result parse_packet(const unsigned char *data, unsigned int caplen,
                               struct timeval ts, struct packet *p)
{
    /* 1. Ethernet: 14 bytes. Si no caben, ni siquiera sabemos el EtherType */
    if (caplen < 14)
        return PARSE_SHORT;
    if (rd16(data + 12) != 0x0800)
        return PARSE_NOT_IPV4;

    /* 2. IPv4: cabecera minima de 20 bytes */
    const unsigned int ip_off = 14;
    if (caplen < ip_off + 20)
        return PARSE_SHORT;
    const unsigned char *ip = data + ip_off;

    unsigned int ihl = (ip[0] & 0x0f) * 4;
    /* version != 4 o IHL < 20 es una cabecera corrupta: si siguieramos,
       leeriamos "el transporte" dentro de la propia cabecera IP */
    if ((ip[0] >> 4) != 4 || ihl < 20)
        return PARSE_SHORT;
    if (caplen < ip_off + ihl)
        return PARSE_SHORT;

    memset(p, 0, sizeof *p);
    p->ts_us = (int64_t)ts.tv_sec * 1000000 + ts.tv_usec;
    p->iplen = rd16(ip + 2);
    p->proto = ip[9];
    p->sip   = rd32(ip + 12);
    p->dip   = rd32(ip + 16);

    /* 3. Transporte */
    const unsigned char *t = data + ip_off + ihl;
    unsigned int avail = caplen - (ip_off + ihl);   /* ya validado: no desborda */

    if (p->proto == 6) {                /* TCP: hasta el byte 13 (flags) */
        if (avail < 14)
            return PARSE_SHORT;
        p->sport = rd16(t);
        p->dport = rd16(t + 2);
        p->flags = t[13];
    } else if (p->proto == 17) {        /* UDP: cabecera de 8 bytes */
        if (avail < 8)
            return PARSE_SHORT;
        p->sport = rd16(t);
        p->dport = rd16(t + 2);
    }
    return PARSE_OK;
}

static void ip_str(uint32_t ip, char *buf)
{
    snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}

static int analysis_on = 0;
static unsigned long long n_packets = 0, n_parsed = 0;   /* [S5] */

void parse_counters(unsigned long long *packets, unsigned long long *parsed)
{
    *packets = n_packets;
    *parsed  = n_parsed;
}
void parse_set_analysis(int on) { analysis_on = on; }

void handle_packet(const unsigned char *data, unsigned int caplen,
                   struct timeval ts)
{
    struct packet p;
    enum parse_result r = parse_packet(data, caplen, ts, &p);
    n_packets++;
    if (r == PARSE_OK)
        n_parsed++;     /* IPv4 valido (no truncado ni corrupto) */

    if (analysis_on) {
        /* Solo TCP/UDP validos alimentan ventanas y flujos; lo demas se descarta */
        if (r == PARSE_OK && (p.proto == 6 || p.proto == 17)) {
            window_process(&p);
            flow_process(&p);
        }
        return;
    }

    /* Modo sesion 1: una linea por paquete */
    unsigned long sec = (unsigned long)ts.tv_sec, usec = (unsigned long)ts.tv_usec;
    if (r == PARSE_NOT_IPV4)
        return;
    if (r == PARSE_SHORT) {
        printf("%lu.%06lu SHORT\n", sec, usec);
        return;
    }
    char s[16], d[16];
    ip_str(p.sip, s);
    ip_str(p.dip, d);
    if (p.proto == 6) {
        char f[5]; int n = 0;
        if (p.flags & TCP_SYN) f[n++] = 'S';
        if (p.flags & TCP_ACK) f[n++] = 'A';
        if (p.flags & TCP_FIN) f[n++] = 'F';
        if (p.flags & TCP_RST) f[n++] = 'R';
        if (n == 0) f[n++] = '-';
        f[n] = '\0';
        printf("%lu.%06lu TCP %s:%u > %s:%u len=%u flags=%s\n",
               sec, usec, s, p.sport, d, p.dport, p.iplen, f);
    } else if (p.proto == 17) {
        printf("%lu.%06lu UDP %s:%u > %s:%u len=%u\n",
               sec, usec, s, p.sport, d, p.dport, p.iplen);
    } else {
        printf("%lu.%06lu proto=%u %s > %s len=%u\n",
               sec, usec, p.proto, s, d, p.iplen);
    }
}
