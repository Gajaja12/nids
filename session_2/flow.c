/*
 * flow.c -- tabla de flujos (sesion 2).
 *
 * Tabla hash de tamano fijo con direccionamiento abierto y sondeo lineal.
 * Cada hueco tiene 3 estados: EMPTY (nunca usado), OPEN (flujo abierto) y
 * FREED (flujo cerrado). Se distingue FREED de EMPTY a proposito: ver lookup().
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "flow.h"

#ifndef TABLE_SIZE
#define TABLE_SIZE      (1u << 16)           /* potencia de 2: modulo = AND */
#endif
#define IDLE_TIMEOUT_US (60LL * 1000000LL)   /* 60 s */

enum { SLOT_EMPTY = 0, SLOT_OPEN, SLOT_FREED };

/* Clave canonica: los dos extremos (ip,puerto) ordenados numericamente */
struct key {
    uint32_t ip_lo, ip_hi;
    uint16_t port_lo, port_hi;
    uint8_t  proto;
};

struct flow {
    uint8_t  state;
    struct key key;
    /* lado "forward": quien envio el primer paquete */
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    int64_t  start_us, last_us, iat_sum_us;
    uint64_t fwd_pkts, fwd_bytes, bwd_pkts, bwd_bytes;
    uint32_t syn, ack, fin, rst;
};

static struct flow table[TABLE_SIZE];   /* estatica: arranca a cero = EMPTY */
static FILE *out = NULL;

int flows_enabled(void) { return out != NULL; }

int flows_open(const char *path)
{
    out = fopen(path, "w");
    if (!out)
        return -1;
    fputs("src_ip,src_port,dst_ip,dst_port,proto,duration,"
          "fwd_pkts,fwd_bytes,bwd_pkts,bwd_bytes,syn,ack,fin,rst,mean_iat\n", out);
    return 0;
}

/* ---- clave y hash ---------------------------------------------------- */

static struct key make_key(const struct packet *p)
{
    struct key k;
    memset(&k, 0, sizeof k);    /* padding a cero: la comparacion es limpia */
    k.proto = p->proto;
    /* "el menor primero": primero por IP, y a igualdad de IP por puerto */
    if (p->sip < p->dip || (p->sip == p->dip && p->sport <= p->dport)) {
        k.ip_lo = p->sip; k.port_lo = p->sport;
        k.ip_hi = p->dip; k.port_hi = p->dport;
    } else {
        k.ip_lo = p->dip; k.port_lo = p->dport;
        k.ip_hi = p->sip; k.port_hi = p->sport;
    }
    return k;
}

static int key_eq(const struct key *a, const struct key *b)
{
    return a->ip_lo == b->ip_lo && a->ip_hi == b->ip_hi &&
           a->port_lo == b->port_lo && a->port_hi == b->port_hi &&
           a->proto == b->proto;
}

/* FNV-1a sobre los campos de la clave (no sobre el struct, por el padding) */
static uint32_t hash_key(const struct key *k)
{
    uint32_t h = 2166136261u;
    uint32_t v[3] = { k->ip_lo, k->ip_hi,
                      ((uint32_t)k->port_lo << 16) | k->port_hi };
    for (int i = 0; i < 3; i++)
        for (int b = 0; b < 4; b++) {
            h ^= (v[i] >> (8 * b)) & 0xff;
            h *= 16777619u;
        }
    h ^= k->proto;
    h *= 16777619u;
    return h;
}

/* ---- salida ---------------------------------------------------------- */

static void ip_str(uint32_t ip, char *buf)
{
    snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}

/* Escribe la fila del flujo y libera el hueco (sin mover ningun otro) */
static void close_flow(struct flow *f)
{
    char s[16], d[16];
    ip_str(f->src_ip, s);
    ip_str(f->dst_ip, d);

    int64_t dur = f->last_us - f->start_us;
    uint64_t n = f->fwd_pkts + f->bwd_pkts;
    double mean = (n > 1) ? (double)f->iat_sum_us / (double)(n - 1) / 1e6 : 0.0;

    fprintf(out, "%s,%u,%s,%u,%s,%lld.%06lld,%llu,%llu,%llu,%llu,%u,%u,%u,%u,%.6f\n",
            s, f->src_port, d, f->dst_port,
            f->key.proto == 6 ? "TCP" : "UDP",
            (long long)(dur / 1000000), (long long)(dur % 1000000),
            (unsigned long long)f->fwd_pkts, (unsigned long long)f->fwd_bytes,
            (unsigned long long)f->bwd_pkts, (unsigned long long)f->bwd_bytes,
            f->syn, f->ack, f->fin, f->rst, mean);

    f->state = SLOT_FREED;
}

/* ---- tabla ----------------------------------------------------------- */

/*
 * Busca el flujo ABIERTO con clave k. Devuelve su indice, o -1 si no existe;
 * en ese caso *free_idx es donde insertar uno nuevo.
 *
 * Recorrido desde el hueco que marca el hash:
 *  - OPEN con la misma clave -> encontrado.
 *  - OPEN con otra clave     -> colision, seguir al siguiente.
 *  - FREED                   -> hueco reutilizable, pero SEGUIR: la clave que
 *                               buscamos puede estar mas adelante (insertada
 *                               cuando este hueco aun estaba ocupado).
 *  - EMPTY                   -> nunca se uso, asi que ninguna clave pudo
 *                               pasar de aqui: ahora si se puede parar.
 * Si FREED y EMPTY fueran lo mismo habria que recorrer toda la tabla en cada
 * fallo; asi cada busqueda cuesta lo que cuesta su cadena de colisiones.
 */
static int lookup(const struct key *k, uint32_t *free_idx)
{
    uint32_t h = hash_key(k) & (TABLE_SIZE - 1);
    int have_free = 0;

    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        uint32_t idx = (h + i) & (TABLE_SIZE - 1);
        struct flow *f = &table[idx];

        if (f->state == SLOT_OPEN) {
            if (key_eq(&f->key, k))
                return (int)idx;
            continue;
        }
        if (!have_free) {           /* primer hueco libre = donde insertar */
            *free_idx = idx;
            have_free = 1;
        }
        if (f->state == SLOT_EMPTY)
            break;
    }
    if (!have_free)                 /* tabla llena de flujos abiertos */
        *free_idx = h;              /* el llamador desaloja este */
    return -1;
}

static void start_flow(struct flow *f, const struct key *k, const struct packet *p)
{
    memset(f, 0, sizeof *f);
    f->state    = SLOT_OPEN;
    f->key      = *k;
    f->src_ip   = p->sip;  f->src_port = p->sport;   /* lado forward */
    f->dst_ip   = p->dip;  f->dst_port = p->dport;
    f->start_us = f->last_us = p->ts_us;
}

static void update_flow(struct flow *f, const struct packet *p)
{
    int64_t dt = p->ts_us - f->last_us;
    if (dt < 0)                     /* timestamps desordenados: no restar */
        dt = 0;
    f->iat_sum_us += dt;
    f->last_us    += dt;

    if (p->sip == f->src_ip && p->sport == f->src_port) {
        f->fwd_pkts++;  f->fwd_bytes += p->iplen;
    } else {
        f->bwd_pkts++;  f->bwd_bytes += p->iplen;
    }
    if (p->flags & TCP_SYN) f->syn++;
    if (p->flags & TCP_ACK) f->ack++;
    if (p->flags & TCP_FIN) f->fin++;
    if (p->flags & TCP_RST) f->rst++;
}

void flow_process(const struct packet *p)
{
    struct key k = make_key(p);
    uint32_t free_idx = 0;
    int idx = lookup(&k, &free_idx);
    struct flow *f;

    if (idx >= 0) {
        f = &table[idx];
        if (p->ts_us - f->last_us > IDLE_TIMEOUT_US) {
            /* Inactivo: cerrar el viejo y empezar uno nuevo para este paquete.
               Mismo hueco: la cadena de colisiones no cambia. */
            close_flow(f);
            start_flow(f, &k, p);
        }
    } else {
        f = &table[free_idx];
        if (f->state == SLOT_OPEN)   /* tabla llena: se escribe el desalojado */
            close_flow(f);
        start_flow(f, &k, p);
    }
    update_flow(f, p);

    /* TCP con FIN o RST: el paquete cuenta en el flujo y este se cierra ya */
    if (p->proto == 6 && (p->flags & (TCP_FIN | TCP_RST)))
        close_flow(f);
}

void flows_finish(void)
{
    if (!out)
        return;
    for (uint32_t i = 0; i < TABLE_SIZE; i++)
        if (table[i].state == SLOT_OPEN)
            close_flow(&table[i]);
    fclose(out);
    out = NULL;
}
