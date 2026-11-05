/*
 * flow.c -- tabla de flujos (sesion 3).
 *
 * Igual que en la sesion 2 (hash abierto, sondeo lineal, EMPTY/OPEN/FREED),
 * con estos cambios:
 *   - 4096 huecos y un barrido por segundo de captura que cierra los flujos
 *     inactivos (>60 s), para que DNS sueltos y SYN de un flood no llenen la tabla.
 *   - dos contadores nuevos por flujo (suma de huecos al cuadrado, paquetes
 *     SYN-sin-ACK) y el calculo de las 10 features al cerrar.
 *   - al cerrar, la fila va a flows.csv y/o features.csv y los valores al perfil.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "flow.h"
#include "profile.h"

#ifndef TABLE_SIZE
#define TABLE_SIZE      4096u                /* potencia de 2: modulo = AND */
#endif
#define IDLE_TIMEOUT_US (60LL * 1000000LL)   /* 60 s */

enum { SLOT_EMPTY = 0, SLOT_OPEN, SLOT_FREED };

struct key {
    uint32_t ip_lo, ip_hi;
    uint16_t port_lo, port_hi;
    uint8_t  proto;
};

struct flow {
    uint8_t  state;
    struct key key;
    uint32_t src_ip, dst_ip;                 /* lado forward = primer emisor */
    uint16_t src_port, dst_port;
    int64_t  start_us, last_us, iat_sum_us;
    double   iat_sum_s;                      /* [S3] suma de huecos, en s (double) */
    double   iat_sq_s2;                      /* [S3] suma de huecos^2, en s^2 */
    uint64_t fwd_pkts, fwd_bytes, bwd_pkts, bwd_bytes;
    uint32_t syn, ack, fin, rst;
    uint32_t syn_only;                       /* [S3] SYN puesto y ACK no */
};

static struct flow table[TABLE_SIZE];
static FILE *flows_out = NULL, *feat_out = NULL;
static int64_t last_sweep_sec = -1;

int flows_open(const char *path)
{
    flows_out = fopen(path, "w");
    if (!flows_out)
        return -1;
    fputs("src_ip,src_port,dst_ip,dst_port,proto,duration,"
          "fwd_pkts,fwd_bytes,bwd_pkts,bwd_bytes,syn,ack,fin,rst,mean_iat\n", flows_out);
    return 0;
}

int features_open(const char *path)
{
    feat_out = fopen(path, "w");
    if (!feat_out)
        return -1;
    fputs("src_ip,src_port,dst_ip,dst_port,proto,duration,pkts,bytes,"
          "bytes_per_s,pkts_per_s,fwd_byte_share,mean_pkt_size,"
          "mean_iat,std_iat,syn_only_frac\n", feat_out);
    return 0;
}

/* ---- clave y hash (sin cambios) -------------------------------------- */

static struct key make_key(const struct packet *p)
{
    struct key k;
    memset(&k, 0, sizeof k);
    k.proto = p->proto;
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

/* ---- cierre: features + salidas -------------------------------------- */

static void ip_str(uint32_t ip, char *buf)
{
    snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}

/*
 * Un hueco FREED seguido de un EMPTY puede pasar a EMPTY: ninguna cadena de
 * busqueda que lo cruce puede ir mas alla del EMPTY, asi que el resultado es
 * el mismo. Sin esto, tras miles de flujos cerrados todos los huecos serian
 * FREED y cada busqueda fallida recorreria la tabla entera. No mueve ninguna
 * entrada: solo cambia la etiqueta de huecos que ya estaban vacios.
 */
static void relax_freed(uint32_t i)
{
    while (table[i].state == SLOT_FREED &&
           table[(i + 1) & (TABLE_SIZE - 1)].state == SLOT_EMPTY) {
        table[i].state = SLOT_EMPTY;
        i = (i - 1) & (TABLE_SIZE - 1);
    }
}

static void close_flow(struct flow *f)
{
    char s[16], d[16];
    ip_str(f->src_ip, s);
    ip_str(f->dst_ip, d);
    const char *proto = f->key.proto == 6 ? "TCP" : "UDP";

    int64_t dur_us = f->last_us - f->start_us;
    uint64_t pkts  = f->fwd_pkts + f->bwd_pkts;
    uint64_t bytes = f->fwd_bytes + f->bwd_bytes;

    /* mean_iat de la sesion 2 (flows.csv) */
    double mean_iat = (pkts > 1) ? f->iat_sum_s / (double)(pkts - 1) : 0.0;

    if (flows_out)
        fprintf(flows_out,
                "%s,%u,%s,%u,%s,%lld.%06lld,%llu,%llu,%llu,%llu,%u,%u,%u,%u,%.6f\n",
                s, f->src_port, d, f->dst_port, proto,
                (long long)(dur_us / 1000000), (long long)(dur_us % 1000000),
                (unsigned long long)f->fwd_pkts, (unsigned long long)f->fwd_bytes,
                (unsigned long long)f->bwd_pkts, (unsigned long long)f->bwd_bytes,
                f->syn, f->ack, f->fin, f->rst, mean_iat);

    if (feat_out || profile_enabled()) {
        double dur   = (double)dur_us / 1e6;
        double bps   = dur > 0 ? (double)bytes / dur : 0.0;     /* 0 si duration = 0 */
        double pps   = dur > 0 ? (double)pkts  / dur : 0.0;
        double share = bytes > 0 ? (double)f->fwd_bytes / (double)bytes : 0.0;
        double mpkt  = pkts  > 0 ? (double)bytes / (double)pkts : 0.0;
        double sfrac = pkts  > 0 ? (double)f->syn_only / (double)pkts : 0.0;

        /* std = sqrt(E[x^2] - E[x]^2) sobre los (pkts-1) huecos. Por redondeo la
           resta puede salir -1e-18: se recorta a 0 antes de la raiz. */
        double std = 0.0;
        if (pkts > 1) {
            double gaps = (double)(pkts - 1);
            double var = f->iat_sq_s2 / gaps - mean_iat * mean_iat;
            std = var > 0 ? sqrt(var) : 0.0;
        }

        if (feat_out)
            fprintf(feat_out,
                    "%s,%u,%s,%u,%s,%.6f,%llu,%llu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                    s, f->src_port, d, f->dst_port, proto, dur,
                    (unsigned long long)pkts, (unsigned long long)bytes,
                    bps, pps, share, mpkt, mean_iat, std, sfrac);

        profile_add(PF_DURATION, dur);
        profile_add(PF_PKTS, (double)pkts);
        profile_add(PF_BYTES, (double)bytes);
        profile_add(PF_BYTES_PER_S, bps);
        profile_add(PF_PKTS_PER_S, pps);
        profile_add(PF_FWD_BYTE_SHARE, share);
        profile_add(PF_MEAN_PKT_SIZE, mpkt);
        profile_add(PF_MEAN_IAT, mean_iat);
        profile_add(PF_STD_IAT, std);
        profile_add(PF_SYN_ONLY_FRAC, sfrac);
    }

    f->state = SLOT_FREED;
    relax_freed((uint32_t)(f - table));
}

/* ---- tabla ----------------------------------------------------------- */

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
        if (!have_free) {
            *free_idx = idx;
            have_free = 1;
        }
        if (f->state == SLOT_EMPTY)
            break;
    }
    if (!have_free)
        *free_idx = h;
    return -1;
}

static void start_flow(struct flow *f, const struct key *k, const struct packet *p)
{
    memset(f, 0, sizeof *f);
    f->state    = SLOT_OPEN;
    f->key      = *k;
    f->src_ip   = p->sip;  f->src_port = p->sport;
    f->dst_ip   = p->dip;  f->dst_port = p->dport;
    f->start_us = f->last_us = p->ts_us;
}

static void update_flow(struct flow *f, const struct packet *p)
{
    int64_t dt = p->ts_us - f->last_us;
    if (dt < 0)
        dt = 0;
    f->iat_sum_us += dt;
    f->last_us    += dt;
    double g = (double)dt / 1e6;
    f->iat_sum_s  += g;                      /* [S3] suma en segundos, como el enunciado */
    f->iat_sq_s2  += g * g;                  /* [S3] para la desviacion tipica */

    if (p->sip == f->src_ip && p->sport == f->src_port) {
        f->fwd_pkts++;  f->fwd_bytes += p->iplen;
    } else {
        f->bwd_pkts++;  f->bwd_bytes += p->iplen;
    }
    if (p->flags & TCP_SYN) f->syn++;
    if (p->flags & TCP_ACK) f->ack++;
    if (p->flags & TCP_FIN) f->fin++;
    if (p->flags & TCP_RST) f->rst++;
    if ((p->flags & TCP_SYN) && !(p->flags & TCP_ACK))
        f->syn_only++;                       /* [S3] SYN puro (no SYN+ACK) */
}

/* Cierra todo flujo inactivo mas de 60 s respecto al reloj de la captura */
static void sweep(int64_t now_us)
{
    for (uint32_t i = 0; i < TABLE_SIZE; i++)
        if (table[i].state == SLOT_OPEN &&
            now_us - table[i].last_us > IDLE_TIMEOUT_US)
            close_flow(&table[i]);
}

void flow_process(const struct packet *p)
{
    /* Una vez por segundo de CAPTURA (no de reloj real): cuando el timestamp
       del paquete entra en un segundo nuevo. No cambia las filas: un flujo
       inactivo >60 s se habria partido igual al llegar su siguiente paquete;
       el barrido solo lo escribe antes y libera el hueco. */
    int64_t sec = p->ts_us / 1000000;
    if (sec > last_sweep_sec) {
        sweep(p->ts_us);
        last_sweep_sec = sec;
    }

    struct key k = make_key(p);
    uint32_t free_idx = 0;
    int idx = lookup(&k, &free_idx);
    struct flow *f;

    if (idx >= 0 && p->ts_us - table[idx].last_us > IDLE_TIMEOUT_US) {
        /* Inactivo: se cierra el viejo y este paquete empieza uno nuevo.
           Se vuelve a buscar hueco en vez de reutilizar el mismo: close_flow
           puede haber relajado FREED->EMPTY y reinsertar ahi rompería la
           cadena de busqueda de esta misma clave. */
        close_flow(&table[idx]);
        idx = lookup(&k, &free_idx);         /* ya no esta: da el hueco libre */
    }
    if (idx >= 0) {
        f = &table[idx];
    } else {
        f = &table[free_idx];
        if (f->state == SLOT_OPEN)           /* tabla llena: desalojar */
            close_flow(f);
        start_flow(f, &k, p);
    }
    update_flow(f, p);

    if (p->proto == 6 && (p->flags & (TCP_FIN | TCP_RST)))
        close_flow(f);
}

void flows_finish(void)
{
    for (uint32_t i = 0; i < TABLE_SIZE; i++)
        if (table[i].state == SLOT_OPEN)
            close_flow(&table[i]);
    if (flows_out) { fclose(flows_out); flows_out = NULL; }
    if (feat_out)  { fclose(feat_out);  feat_out = NULL; }
}