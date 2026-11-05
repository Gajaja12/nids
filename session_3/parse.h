#ifndef PARSE_H
#define PARSE_H

#include <stdint.h>
#include <sys/time.h>

/* Flags TCP (byte 13 de la cabecera TCP) */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

/* Un paquete IPv4 ya "digerido": lo unico que necesita el resto del programa.
   Las direcciones y puertos van en orden de host (numericos) para poder
   compararlos y ordenarlos directamente. */
struct packet {
    int64_t  ts_us;   /* timestamp en microsegundos desde epoch */
    uint32_t sip, dip;
    uint16_t sport, dport;   /* 0 si no es TCP/UDP */
    uint16_t iplen;          /* campo "total length" de IPv4 */
    uint8_t  proto;          /* 6 TCP, 17 UDP, otro */
    uint8_t  flags;          /* flags TCP; 0 si no es TCP */
};

enum parse_result {
    PARSE_NOT_IPV4 = 0,  /* ARP, IPv6, ...: se ignora en silencio */
    PARSE_SHORT    = 1,  /* truncado o malformado */
    PARSE_OK       = 2   /* struct packet rellena */
};

/* Parsea una trama Ethernet; nunca lee mas alla de caplen. */
enum parse_result parse_packet(const unsigned char *data, unsigned int caplen,
                               struct timeval ts, struct packet *p);

/* Activa el modo analisis (--flows/--features/--profile): los paquetes
   TCP/UDP validos van a las ventanas por host y a la tabla de flujos. */
void parse_set_analysis(int on);

/* Llamada por nids.c una vez por paquete. */
void handle_packet(const unsigned char *data, unsigned int caplen,
                   struct timeval ts);

#endif
