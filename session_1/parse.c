/*
 * parse.c -- your work for session 1.
 *
 * handle_packet() is called once per packet. Make it print one line per
 * IPv4 packet:
 *
 *   TCP    <sec>.<usec> TCP <sip>:<sport> > <dip>:<dport> len=<iplen> flags=<F>
 *   UDP    <sec>.<usec> UDP <sip>:<sport> > <dip>:<dport> len=<iplen>
 *   other  <sec>.<usec> proto=<n> <sip> > <dip> len=<iplen>
 *   short  <sec>.<usec> SHORT
 *
 * <iplen> is the IPv4 total-length field. <F> is the set flags in order
 * S A F R, or "-". A non-IPv4 frame (ARP, IPv6, ...) prints nothing.
 *
 * Steps:
 *   1. Ethernet header (14 bytes): EtherType at bytes 12-13; 0x0800 = IPv4.
 *   2. IPv4 header: IHL = (ip[0] & 0x0f) * 4 is the header length.
 *      protocol = ip[9] (6 TCP, 17 UDP). total length = bytes 2-3.
 *      addresses = bytes 12-15 and 16-19.
 *   3. TCP/UDP: source/dest port = the first two 16-bit fields. TCP flags
 *      byte is byte 13 of the TCP header: SYN 0x02, ACK 0x10, FIN 0x01,
 *      RST 0x04.
 *   4. Bounds-check every read against caplen. Print SHORT and return
 *      instead of reading past it.
 *
 * Hints:
 *   unsigned short v; memcpy(&v, p, 2); v = ntohs(v);   // <arpa/inet.h>
 *   snprintf(buf, sizeof buf, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "parse.h"

void handle_packet(const unsigned char *data, unsigned int caplen,
                   struct timeval ts)
{
    unsigned long sec  = (unsigned long)ts.tv_sec;
    unsigned long usec = (unsigned long)ts.tv_usec;

    /* 1. Comprobación de la cabecera Ethernet (14 bytes) */
    if (caplen < 14) {
        printf("%lu.%06lu SHORT\n", sec, usec);
        return;
    }

    unsigned short ethertype;
    memcpy(&ethertype, data + 12, 2);
    
    if (ntohs(ethertype) != 0x0800) {
        return; /* Ignorar tramas que no sean IPv4 */
    }

    /* 2. Cabecera IPv4 (Mínimo 20 bytes) */
    unsigned int ip_offset = 14;
    if (caplen < ip_offset + 20) {
        printf("%lu.%06lu SHORT\n", sec, usec);
        return;
    }

    const unsigned char *ip = data + ip_offset;
    unsigned int ihl = (ip[0] & 0x0f) * 4;

    /* Validar que el paquete capturado contiene la cabecera IPv4 completa */
    if (caplen < ip_offset + ihl) {
        printf("%lu.%06lu SHORT\n", sec, usec);
        return;
    }

    unsigned short iplen;
    memcpy(&iplen, ip + 2, 2);
    iplen = ntohs(iplen);

    unsigned char proto = ip[9];

    char sip[16], dip[16];
    snprintf(sip, sizeof(sip), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
    snprintf(dip, sizeof(dip), "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);

    /* 3. Capa de Transporte (TCP/UDP) */
    unsigned int transport_offset = ip_offset + ihl;

    if (proto == 6) { /* TCP */
        /* Necesitamos al menos 14 bytes para llegar a los puertos y al byte de flags (byte 13) */
        if (caplen < transport_offset + 14) {
            printf("%lu.%06lu SHORT\n", sec, usec);
            return;
        }
        
        const unsigned char *tcp = data + transport_offset;
        unsigned short sport, dport;
        memcpy(&sport, tcp, 2);
        memcpy(&dport, tcp + 2, 2);

        unsigned char flags_byte = tcp[13];
        char flags_str[5] = {0};
        int f_idx = 0;
        
        if (flags_byte & 0x02) flags_str[f_idx++] = 'S';
        if (flags_byte & 0x10) flags_str[f_idx++] = 'A';
        if (flags_byte & 0x01) flags_str[f_idx++] = 'F';
        if (flags_byte & 0x04) flags_str[f_idx++] = 'R';
        
        if (f_idx == 0) {
            flags_str[0] = '-';
            flags_str[1] = '\0';
        }

        printf("%lu.%06lu TCP %s:%u > %s:%u len=%u flags=%s\n",
               sec, usec, sip, ntohs(sport), dip, ntohs(dport), iplen, flags_str);

    } else if (proto == 17) { /* UDP */
        /* La cabecera UDP siempre es de 8 bytes, validamos su lectura */
        if (caplen < transport_offset + 8) {
            printf("%lu.%06lu SHORT\n", sec, usec);
            return;
        }
        
        const unsigned char *udp = data + transport_offset;
        unsigned short sport, dport;
        memcpy(&sport, udp, 2);
        memcpy(&dport, udp + 2, 2);

        printf("%lu.%06lu UDP %s:%u > %s:%u len=%u\n",
               sec, usec, sip, ntohs(sport), dip, ntohs(dport), iplen);

    } else { /* Otros protocolos */
        printf("%lu.%06lu proto=%u %s > %s len=%u\n",
               sec, usec, proto, sip, dip, iplen);
    }
}
