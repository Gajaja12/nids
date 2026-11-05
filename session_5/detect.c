/*
 * detect.c -- reglas de deteccion (sesion 4) + alertas en vivo e incidentes (sesion 5).
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
#include <time.h>

#include "detect.h"

/* ---- configuracion ---------------------------------------------------- */

struct conf {
    double portscan_ports, portscan_syns;
    double synflood_unanswered, synflood_max_ports;
    double sweep_hosts, sweep_syns;
    double beacon_min_conns, beacon_min_period, beacon_max_cv;
};

/* Valores de serie = los del enunciado */
#define DEFAULTS { 10, 10, 100, 10, 20, 20, 8, 10, 0.30 }
static struct conf C = DEFAULTS;

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
static const char *txt_file = NULL;

static void ip_str(uint32_t ip, char *buf)
{
    snprintf(buf, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}

int detect_open(const char *alerts_path, const char *txt_path,
                const char *conf_path, int conf_explicit)
{
    txt_file = txt_path;
    if (load_conf(conf_path) != 0) {
        if (conf_explicit)
            return -1;
        fprintf(stderr, "warning: using built-in thresholds\n");
        /* load_conf pudo aplicar algunas claves antes de fallar: restaurar */
        struct conf def = DEFAULTS;
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


/* ---- tuberia de alertas (sesion 5) ------------------------------------ */

#define INCIDENT_GAP_S 30       /* alertas a <= 30 s una de otra = mismo incidente */

struct alert {
    int64_t     time;           /* s epoch: inicio de ventana, o 1er inicio del beacon */
    const char *rule;
    char        src[16], dst[24], detail[96];
};

static struct alert *alerts = NULL;
static size_t nalerts = 0, capalerts = 0;
static unsigned long long n_incidents = 0;

unsigned long long detect_alert_count(void)    { return nalerts; }
unsigned long long detect_incident_count(void) { return n_incidents; }

static void fmt_time(int64_t sec, char *buf, size_t n)
{
    time_t t = (time_t)sec;
    struct tm tm;
    gmtime_r(&t, &tm);                       /* UTC, version reentrante */
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm);
}

/* Un unico sitio por el que sale CADA alerta: asi alerts.csv, la linea ALERT
   de la pantalla y los incidentes no pueden desincronizarse. */
static void raise_alert(int64_t t, const char *rule, const char *src,
                        const char *dst, const char *detail)
{
    fprintf(out, "%lld,%s,%s,%s,%s\n", (long long)t, rule, src, dst, detail);

    char ts[32];
    fmt_time(t, ts, sizeof ts);
    printf("ALERT %s %s %s > %s %s\n", ts, rule, src, dst, detail);
    fflush(stdout);                          /* en vivo se ve al instante */

    if (nalerts == capalerts) {
        capalerts = capalerts ? capalerts * 2 : 256;
        struct alert *na = realloc(alerts, capalerts * sizeof *alerts);
        if (!na) { perror("realloc"); exit(1); }
        alerts = na;
    }
    struct alert *a = &alerts[nalerts++];
    a->time = t;
    a->rule = rule;                          /* literales: viven todo el programa */
    snprintf(a->src, sizeof a->src, "%s", src);
    snprintf(a->dst, sizeof a->dst, "%s", dst);
    snprintf(a->detail, sizeof a->detail, "%s", detail);
}

/* ---- reglas de ventana ------------------------------------------------ */

void detect_window(int64_t window_start, uint32_t host, size_t dst_hosts,
                   unsigned dst_ports, unsigned syn_sent, unsigned unanswered)
{
    if (!out)
        return;
    char h[16], detail[96];
    ip_str(host, h);

    /* Las tres reglas son independientes: una fila puede disparar varias. */
    if (dst_ports >= C.portscan_ports && syn_sent >= C.portscan_syns) {
        snprintf(detail, sizeof detail, "dst_ports=%u syn_sent=%u", dst_ports, syn_sent);
        raise_alert(window_start, "portscan", h, "-", detail);
    }
    if ((double)dst_hosts >= C.sweep_hosts && syn_sent >= C.sweep_syns) {
        snprintf(detail, sizeof detail, "dst_hosts=%zu syn_sent=%u", dst_hosts, syn_sent);
        raise_alert(window_start, "sweep", h, "-", detail);
    }
    if (unanswered >= C.synflood_unanswered && dst_ports <= C.synflood_max_ports) {
        snprintf(detail, sizeof detail, "unanswered_syn=%u dst_ports=%u", unanswered, dst_ports);
        raise_alert(window_start, "synflood", h, "-", detail);
    }
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
                char s[16], dd[16], dst[24], detail[96];
                ip_str(recs[i].src, s);
                ip_str(recs[i].dst, dd);
                snprintf(dst, sizeof dst, "%s:%u", dd, recs[i].dport);
                snprintf(detail, sizeof detail, "conns=%zu period=%.1f cv=%.3f", conns, mean, cv);
                raise_alert(recs[i].start_us / 1000000, "beacon", s, dst, detail);
            }
        }
        i = j;
    }
}

/* ---- incidentes (sesion 5) ------------------------------------------- */

struct incident {
    int64_t     start, end;
    const char *rule;
    char        src[16], dst[24], detail[96];
    unsigned    n;
};

static int cmp_alert(const void *x, const void *y)    /* agrupa por regla/origen/destino, y por tiempo */
{
    const struct alert *a = x, *b = y;
    int c = strcmp(a->rule, b->rule);
    if (!c) c = strcmp(a->src, b->src);
    if (!c) c = strcmp(a->dst, b->dst);
    if (c) return c;
    return (a->time > b->time) - (a->time < b->time);
}

static int cmp_incident(const void *x, const void *y)  /* por inicio; el resto desempata */
{
    const struct incident *a = x, *b = y;
    if (a->start != b->start) return a->start < b->start ? -1 : 1;
    int c = strcmp(a->rule, b->rule);
    if (!c) c = strcmp(a->src, b->src);
    if (!c) c = strcmp(a->dst, b->dst);
    return c;
}

static void write_incidents(void)
{
    if (nalerts == 0) {
        FILE *f = fopen(txt_file, "w");          /* fichero vacio: "ningun incidente" */
        if (f) fclose(f); else perror(txt_file);
        return;
    }
    qsort(alerts, nalerts, sizeof *alerts, cmp_alert);

    struct incident *inc = malloc(nalerts * sizeof *inc);   /* a lo sumo uno por alerta */
    if (!inc) { perror("malloc"); exit(1); }
    size_t ni = 0;

    for (size_t i = 0; i < nalerts; ) {
        const struct alert *first = &alerts[i];
        size_t j = i + 1;
        int beacon = strcmp(first->rule, "beacon") == 0;
        /* Un beacon es SIEMPRE un incidente de una alerta (ya resume muchas conexiones) */
        while (!beacon && j < nalerts &&
               strcmp(alerts[j].rule, first->rule) == 0 &&
               strcmp(alerts[j].src, first->src) == 0 &&
               strcmp(alerts[j].dst, first->dst) == 0 &&
               alerts[j].time - alerts[j - 1].time <= INCIDENT_GAP_S)
            j++;

        struct incident *in = &inc[ni++];
        in->start = first->time;
        /* ventana: la ultima alerta cubre sus 30 s; beacon: fin = inicio */
        in->end   = beacon ? first->time : alerts[j - 1].time + 30;
        in->rule  = first->rule;
        in->n     = (unsigned)(j - i);
        snprintf(in->src, sizeof in->src, "%s", first->src);
        snprintf(in->dst, sizeof in->dst, "%s", first->dst);
        snprintf(in->detail, sizeof in->detail, "%s", first->detail);   /* detalle de la 1a alerta */
        i = j;
    }
    qsort(inc, ni, sizeof *inc, cmp_incident);
    n_incidents = ni;

    FILE *f = fopen(txt_file, "w");
    if (!f) {
        perror(txt_file);
        free(inc);
        return;
    }
    for (size_t i = 0; i < ni; i++) {
        char t1[32], t2[16];
        fmt_time(inc[i].start, t1, sizeof t1);
        time_t e = (time_t)inc[i].end;
        struct tm tm;
        gmtime_r(&e, &tm);
        strftime(t2, sizeof t2, "%H:%M:%S", &tm);   /* el fin solo lleva la hora */
        fprintf(f, "%s %s %s %s > %s alerts=%u %s\n", t1, t2, inc[i].rule,
                inc[i].src, inc[i].dst, inc[i].n, inc[i].detail);
    }
    fclose(f);
    free(inc);
}

void detect_finish(void)
{
    if (!out)
        return;
    beacon_rule();               /* puede producir mas alertas: antes de agrupar */
    write_incidents();
    fclose(out);
    out = NULL;
    free(recs);
    recs = NULL;
    nrecs = caprecs = 0;
    free(alerts);
    alerts = NULL;
    /* nalerts / n_incidents se conservan para el resumen */
}
