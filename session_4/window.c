/*
 * window.c -- contadores por host en ventanas de 30 s (sesion 3).
 *
 * Los hosts de la ventana actual viven en un array dinamico (en orden de
 * aparicion) con un indice hash para encontrarlos rapido. Al cambiar de
 * ventana se escribe una fila por host y todo se vacia ("empezar de cero").
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "window.h"
#include "profile.h"
#include "detect.h"

#define WINDOW_S 30

/* Conjunto de uint32 (IPs destino distintas): hash abierto que crece.
   El 0 marca "hueco", asi que la IP 0.0.0.0 se guarda con un flag aparte. */
struct u32set { uint32_t *a; size_t cap, n; int has_zero; };

static int set_add(struct u32set *s, uint32_t v)   /* 1 si es nueva */
{
    if (v == 0) {
        int fresh = !s->has_zero;
        s->has_zero = 1;
        return fresh;
    }
    if (2 * (s->n + 1) > s->cap) {                 /* factor de carga <= 1/2 */
        size_t ncap = s->cap ? s->cap * 2 : 16;
        uint32_t *na = calloc(ncap, sizeof *na);
        if (!na) { perror("calloc"); exit(1); }
        for (size_t i = 0; i < s->cap; i++)
            if (s->a[i]) {
                size_t j = (s->a[i] * 2654435761u) & (ncap - 1);
                while (na[j]) j = (j + 1) & (ncap - 1);
                na[j] = s->a[i];
            }
        free(s->a);
        s->a = na;
        s->cap = ncap;
    }
    size_t j = (v * 2654435761u) & (s->cap - 1);
    while (s->a[j]) {
        if (s->a[j] == v)
            return 0;
        j = (j + 1) & (s->cap - 1);
    }
    s->a[j] = v;
    s->n++;
    return 1;
}

struct host {
    uint32_t ip;
    uint32_t pkts_sent, syn_sent, synack_recv, n_ports;
    struct u32set dsts;      /* IPs destino distintas */
    uint8_t *ports;          /* bitmap de 65536 bits = 8192 bytes */
};

static struct host *hosts = NULL;   /* en orden de aparicion */
static size_t nhosts = 0, caphosts = 0;
static int32_t *index_tab = NULL;   /* ip -> posicion en hosts[], -1 = vacio */
static size_t index_cap = 0;

static FILE *out = NULL;
static int64_t cur_win = 0;
static int have_win = 0;

int windows_open(const char *path)
{
    out = fopen(path, "w");
    if (!out)
        return -1;
    fputs("window_start,host,pkts_sent,dst_hosts,dst_ports,"
          "syn_sent,synack_recv,unanswered_syn\n", out);
    return 0;
}

static size_t ip_slot(uint32_t ip) { return (ip * 2654435761u) & (index_cap - 1); }

static void index_rebuild(size_t ncap)
{
    free(index_tab);
    index_cap = ncap;
    index_tab = malloc(ncap * sizeof *index_tab);
    if (!index_tab) { perror("malloc"); exit(1); }
    memset(index_tab, 0xff, ncap * sizeof *index_tab);   /* todo -1 */
    for (size_t i = 0; i < nhosts; i++) {
        size_t j = ip_slot(hosts[i].ip);
        while (index_tab[j] >= 0) j = (j + 1) & (index_cap - 1);
        index_tab[j] = (int32_t)i;
    }
}

/* Devuelve el host (lo crea si hace falta). OJO: el puntero queda invalido
   si luego se crea otro host (realloc de hosts[]): no guardarlo. */
static struct host *host_get(uint32_t ip)
{
    if (index_cap == 0)
        index_rebuild(64);
    size_t j = ip_slot(ip);
    while (index_tab[j] >= 0) {
        if (hosts[index_tab[j]].ip == ip)
            return &hosts[index_tab[j]];
        j = (j + 1) & (index_cap - 1);
    }
    if (nhosts == caphosts) {
        caphosts = caphosts ? caphosts * 2 : 64;
        hosts = realloc(hosts, caphosts * sizeof *hosts);
        if (!hosts) { perror("realloc"); exit(1); }
    }
    struct host *h = &hosts[nhosts];
    memset(h, 0, sizeof *h);
    h->ip = ip;
    h->ports = calloc(8192, 1);
    if (!h->ports) { perror("calloc"); exit(1); }
    index_tab[j] = (int32_t)nhosts++;
    if (2 * nhosts > index_cap)            /* indice a <= 1/2 de carga */
        index_rebuild(index_cap * 2);
    return &hosts[nhosts - 1];
}

static void ip_str(uint32_t ip, char *buf)
{
    snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}

static void flush_window(void)
{
    for (size_t i = 0; i < nhosts; i++) {
        struct host *h = &hosts[i];
        size_t dst_hosts = h->dsts.n + (h->dsts.has_zero ? 1 : 0);
        /* SYN enviados menos SYN+ACK recibidos, minimo 0 (sin unsigned negativo) */
        uint32_t unanswered = h->syn_sent > h->synack_recv
                              ? h->syn_sent - h->synack_recv : 0;
        if (out) {
            char s[16];
            ip_str(h->ip, s);
            fprintf(out, "%lld,%s,%u,%zu,%u,%u,%u,%u\n", (long long)cur_win, s,
                    h->pkts_sent, dst_hosts, h->n_ports,
                    h->syn_sent, h->synack_recv, unanswered);
        }
        /* [S4] reglas de ventana sobre la misma fila que se acaba de producir */
        detect_window(cur_win, h->ip, dst_hosts, h->n_ports, h->syn_sent, unanswered);
        profile_add(PF_PKTS_SENT, h->pkts_sent);
        profile_add(PF_DST_HOSTS, (double)dst_hosts);
        profile_add(PF_DST_PORTS, h->n_ports);
        profile_add(PF_SYN_SENT, h->syn_sent);
        profile_add(PF_UNANSWERED_SYN, unanswered);
        free(h->dsts.a);
        free(h->ports);
    }
    nhosts = 0;                              /* "empezar de cero" */
    if (index_tab)
        memset(index_tab, 0xff, index_cap * sizeof *index_tab);
}

void window_process(const struct packet *p)
{
    /* La ventana empieza en un multiplo de 30 s: ts_sec / 30 * 30 (division entera) */
    int64_t w = (p->ts_us / 1000000) / WINDOW_S * WINDOW_S;
    if (!have_win) {
        cur_win = w;
        have_win = 1;
    } else if (w > cur_win) {                /* paquete de una ventana posterior */
        flush_window();
        cur_win = w;
    }                                        /* w < cur_win (desordenado): ventana actual */

    int syn_only = (p->flags & TCP_SYN) && !(p->flags & TCP_ACK);
    int synack   = (p->flags & TCP_SYN) &&  (p->flags & TCP_ACK);

    struct host *s = host_get(p->sip);       /* emisor */
    s->pkts_sent++;
    set_add(&s->dsts, p->dip);
    if (!(s->ports[p->dport >> 3] & (1u << (p->dport & 7)))) {
        s->ports[p->dport >> 3] |= (uint8_t)(1u << (p->dport & 7));
        s->n_ports++;
    }
    if (syn_only)
        s->syn_sent++;

    if (synack)                              /* aparece el receptor del SYN+ACK */
        host_get(p->dip)->synack_recv++;     /* (tras usar s: puede haber realloc) */
}

void windows_finish(void)
{
    if (have_win)
        flush_window();                      /* ultima ventana */
    free(hosts);   hosts = NULL;   nhosts = caphosts = 0;
    free(index_tab); index_tab = NULL; index_cap = 0;
    if (out) {
        fclose(out);
        out = NULL;
    }
}
