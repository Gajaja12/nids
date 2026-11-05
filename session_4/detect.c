/*
 * detect.c -- reglas de deteccion (sesion 4).
 *
 *  - Los umbrales se leen de nids.conf, asi se cambian sin recompilar.
 *  - Reglas de ventana (portscan, sweep, synflood): se evaluan fila a fila.
 *  - Regla beacon: necesita ver TODA la captura (mira la periodicidad entre
 *    flujos), asi que solo guarda los inicios de flujo y decide al final.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect.h"

/* ---- configuracion ---------------------------------------------------- */

struct conf {
    double portscan_ports, portscan_syns;
    double synflood_unanswered, synflood_max_ports;
    double sweep_hosts, sweep_syns;
    double beacon_min_conns, beacon_min_period, beacon_max_cv;
};

/* Valores de serie = los del enunciado */
static struct conf C = { 50, 50, 100, 10, 20, 20, 8, 10, 0.10 };

static const struct { const char *name; double *dst; } keys[] = {
    { "portscan_ports",      &C.portscan_ports },
    { "portscan_syns",       &C.portscan_syns },
    { "synflood_unanswered", &C.synflood_unanswered },
    { "synflood_max_ports",  &C.synflood_max_ports },
    { "sweep_hosts",         &C.sweep_hosts },
    { "sweep_syns",          &C.sweep_syns },
    { "beacon_min_conns",    &C.beacon_min_conns },
    { "beacon_min_period",   &C.beacon_min_period },
    { "beacon_max_cv",       &C.beacon_max_cv },
};

static int load_conf(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s: ", path);
        perror("");
        return -1;
    }
    char line[256];
    for (int n = 1; fgets(line, sizeof line, f); n++) {
        if (!strchr(line, '\n') && !feof(f)) {
            fprintf(stderr, "%s:%d: line too long\n", path, n);
            fclose(f);
            return -1;
        }
        const char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;                       /* comentario o linea en blanco */

        char key[64];
        double value;
        /* %63[a-z_]: hasta 63 caracteres (deja sitio al '\0') del conjunto a-z y _ */
        if (sscanf(p, "%63[a-z_] = %lf", key, &value) != 2) {
            fprintf(stderr, "%s:%d: expected 'key = value'\n", path, n);
            fclose(f);
            return -1;
        }
        int found = 0;
        for (size_t i = 0; i < sizeof keys / sizeof *keys; i++)
            if (strcmp(key, keys[i].name) == 0) {
                *keys[i].dst = value;
                found = 1;
                break;
            }
        if (!found) {                       /* clave desconocida = error (suele ser una errata) */
            fprintf(stderr, "%s:%d: unknown key '%s'\n", path, n, key);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

/* ---- salida ----------------------------------------------------------- */

static FILE *out = NULL;

static void ip_str(uint32_t ip, char *buf)
{
    snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}

int detect_open(const char *alerts_path, const char *conf_path, int conf_explicit)
{
    if (load_conf(conf_path) != 0) {
        if (conf_explicit)
            return -1;
        fprintf(stderr, "warning: using built-in thresholds\n");
        /* load_conf pudo aplicar algunas claves antes de fallar: restaurar */
        struct conf def = { 50, 50, 100, 10, 20, 20, 8, 10, 0.10 };
        C = def;
    }
    out = fopen(alerts_path, "w");
    if (!out) {
        perror(alerts_path);
        return -1;
    }
    fputs("time,rule,src,dst,detail\n", out);
    return 0;
}

/* ---- reglas de ventana ------------------------------------------------ */

void detect_window(int64_t window_start, uint32_t host, size_t dst_hosts,
                   unsigned dst_ports, unsigned syn_sent, unsigned unanswered)
{
    if (!out)
        return;
    char h[16];
    ip_str(host, h);

    /* Las tres reglas son independientes: una fila puede disparar varias. */
    if (dst_ports >= C.portscan_ports && syn_sent >= C.portscan_syns)
        fprintf(out, "%lld,portscan,%s,-,dst_ports=%u syn_sent=%u\n",
                (long long)window_start, h, dst_ports, syn_sent);

    if ((double)dst_hosts >= C.sweep_hosts && syn_sent >= C.sweep_syns)
        fprintf(out, "%lld,sweep,%s,-,dst_hosts=%zu syn_sent=%u\n",
                (long long)window_start, h, dst_hosts, syn_sent);

    if (unanswered >= C.synflood_unanswered && dst_ports <= C.synflood_max_ports)
        fprintf(out, "%lld,synflood,%s,-,unanswered_syn=%u dst_ports=%u\n",
                (long long)window_start, h, unanswered, dst_ports);
}

/* ---- regla beacon ----------------------------------------------------- */

/* Un registro por flujo cerrado. En vez de un mapa clave -> lista, se guardan
   todos en un array y al final se ordena por (clave, inicio): los flujos de
   una misma clave quedan contiguos y YA ordenados por inicio (los flujos se
   cierran en distinto orden del que empezaron, asi que hay que ordenar). */
struct brec {
    int64_t  start_us;
    uint32_t src, dst;
    uint16_t dport;
    uint8_t  proto;
};

static struct brec *recs = NULL;
static size_t nrecs = 0, caprecs = 0;

void detect_flow(uint32_t src, uint32_t dst, uint16_t dport, uint8_t proto,
                 int64_t start_us)
{
    if (!out)
        return;
    if (nrecs == caprecs) {
        caprecs = caprecs ? caprecs * 2 : 4096;
        struct brec *n = realloc(recs, caprecs * sizeof *recs);
        if (!n) { perror("realloc"); exit(1); }
        recs = n;
    }
    recs[nrecs++] = (struct brec){ start_us, src, dst, dport, proto };
}

static int cmp_key(const struct brec *a, const struct brec *b)
{
    if (a->src != b->src)     return a->src < b->src ? -1 : 1;
    if (a->dst != b->dst)     return a->dst < b->dst ? -1 : 1;
    if (a->dport != b->dport) return a->dport < b->dport ? -1 : 1;
    if (a->proto != b->proto) return a->proto < b->proto ? -1 : 1;
    return 0;
}

static int cmp_rec(const void *x, const void *y)
{
    const struct brec *a = x, *b = y;
    int c = cmp_key(a, b);
    if (c)
        return c;
    return (a->start_us > b->start_us) - (a->start_us < b->start_us);
}

static void beacon_rule(void)
{
    qsort(recs, nrecs, sizeof *recs, cmp_rec);

    for (size_t i = 0; i < nrecs; ) {
        size_t j = i + 1;
        while (j < nrecs && cmp_key(&recs[i], &recs[j]) == 0)
            j++;
        size_t conns = j - i;               /* inicios de esta clave */

        if (conns >= C.beacon_min_conns && conns >= 2) {
            size_t ng = conns - 1;          /* huecos entre inicios consecutivos */
            double sum = 0;
            for (size_t k = i + 1; k < j; k++)
                sum += (double)(recs[k].start_us - recs[k - 1].start_us) / 1e6;
            double mean = sum / (double)ng;

            /* Desviacion tipica sobre n (como en la sesion 3), en dos pasadas:
               sum((g-media)^2)/n no sufre la cancelacion de E[x^2]-E[x]^2. */
            double ss = 0;
            for (size_t k = i + 1; k < j; k++) {
                double g = (double)(recs[k].start_us - recs[k - 1].start_us) / 1e6 - mean;
                ss += g * g;
            }
            double cv = mean > 0 ? sqrt(ss / (double)ng) / mean : 0.0;

            if (mean > 0 && mean >= C.beacon_min_period && cv <= C.beacon_max_cv) {
                char s[16], d[16];
                ip_str(recs[i].src, s);
                ip_str(recs[i].dst, d);
                fprintf(out, "%lld,beacon,%s,%s:%u,conns=%zu period=%.1f cv=%.3f\n",
                        (long long)(recs[i].start_us / 1000000), s, d,
                        recs[i].dport, conns, mean, cv);
            }
        }
        i = j;
    }
}

void detect_finish(void)
{
    if (!out)
        return;
    beacon_rule();
    fclose(out);
    out = NULL;
    free(recs);
    recs = NULL;
    nrecs = caprecs = 0;
}
