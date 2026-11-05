/*
 * profile.c -- perfil del trafico (sesion 3).
 * Guarda TODOS los valores de cada feature (un vector que crece con realloc)
 * y al final calcula n, media, p95 y p99 con percentil "nearest-rank".
 */
#include <stdio.h>
#include <stdlib.h>

#include "profile.h"

struct dvec { double *v; size_t n, cap; };

static struct dvec vec[PF_COUNT];
static FILE *out = NULL;

static const char *names[PF_COUNT] = {
    "duration", "pkts", "bytes", "bytes_per_s", "pkts_per_s",
    "fwd_byte_share", "mean_pkt_size", "mean_iat", "std_iat", "syn_only_frac",
    "pkts_sent", "dst_hosts", "dst_ports", "syn_sent", "unanswered_syn"
};

int profile_open(const char *path)
{
    out = fopen(path, "w");
    return out ? 0 : -1;
}

int profile_enabled(void) { return out != NULL; }

void profile_add(int feature, double value)
{
    if (!out)
        return;
    struct dvec *d = &vec[feature];
    if (d->n == d->cap) {                    /* crecer x2: coste amortizado O(1) */
        size_t ncap = d->cap ? d->cap * 2 : 1024;
        double *nv = realloc(d->v, ncap * sizeof *nv);
        if (!nv) {
            perror("realloc");
            exit(1);
        }
        d->v = nv;
        d->cap = ncap;
    }
    d->v[d->n++] = value;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);                /* evita restar: sin overflow ni NaN raros */
}

/* Nearest-rank: posicion ceil(p*n/100), contando desde 1.
   Con enteros: ceil(p*n/100) = (p*n + 99) / 100. Sin floats, sin errores de redondeo. */
static double percentile(const struct dvec *d, unsigned p)
{
    size_t k = ((size_t)p * d->n + 99) / 100;
    return d->v[k - 1];
}

void profile_finish(void)
{
    if (!out)
        return;
    fputs("feature,n,mean,p95,p99\n", out);
    for (int i = 0; i < PF_COUNT; i++) {
        struct dvec *d = &vec[i];
        if (d->n == 0) {
            fprintf(out, "%s,0,0.000000,0.000000,0.000000\n", names[i]);
            continue;
        }
        double sum = 0;
        for (size_t j = 0; j < d->n; j++)
            sum += d->v[j];
        qsort(d->v, d->n, sizeof *d->v, cmp_double);
        fprintf(out, "%s,%zu,%.6f,%.6f,%.6f\n", names[i], d->n,
                sum / (double)d->n, percentile(d, 95), percentile(d, 99));
        free(d->v);
        d->v = NULL;
    }
    fclose(out);
    out = NULL;
}
