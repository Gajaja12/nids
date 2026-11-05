/*
 * labels.c -- columna "label" para features.csv y windows.csv (sesion 5).
 *
 * Una etiqueta (rule,src,start,end) encaja con una fila si el origen coincide
 * y los rangos de tiempo se solapan. Se compara en SEGUNDOS ENTEROS, ambos
 * extremos incluidos: las etiquetas vienen en segundos, y asi un flujo de
 * medio segundo despues de "end" no queda fuera por una fraccion.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "labels.h"

struct label {
    char     rule[32];
    uint32_t src;
    double   start, end;
};

static struct label *label_tab = NULL;
static size_t n_label_tab = 0, cap_label_tab = 0;
static int loaded = 0;

int labels_enabled(void) { return loaded; }

int labels_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open labels %s: ", path);
        perror("");
        return -1;
    }
    char line[256];
    for (int n = 1; fgets(line, sizeof line, f); n++) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
            continue;
        if (strncmp(line, "rule,", 5) == 0)        /* cabecera */
            continue;

        struct label l;
        char ip[16];
        /* %[^,] = todo hasta la siguiente coma; el ancho evita desbordar el buffer */
        if (sscanf(line, "%31[^,],%15[^,],%lf,%lf", l.rule, ip, &l.start, &l.end) != 4) {
            fprintf(stderr, "%s:%d: expected rule,src,start,end\n", path, n);
            fclose(f);
            return -1;
        }
        struct in_addr a;
        if (inet_pton(AF_INET, ip, &a) != 1) {
            fprintf(stderr, "%s:%d: bad address '%s'\n", path, n, ip);
            fclose(f);
            return -1;
        }
        l.src = ntohl(a.s_addr);                    /* a orden de host, como en struct packet */

        if (n_label_tab == cap_label_tab) {
            cap_label_tab = cap_label_tab ? cap_label_tab * 2 : 16;
            struct label *nl = realloc(label_tab, cap_label_tab * sizeof *label_tab);
            if (!nl) { perror("realloc"); exit(1); }
            label_tab = nl;
        }
        label_tab[n_label_tab++] = l;
    }
    fclose(f);
    loaded = 1;
    return 0;
}

/* Rango de la fila [lo, hi] en segundos enteros; devuelve la PRIMERA etiqueta
   (en orden del fichero) que encaja. */
static const char *match(uint32_t host, int64_t lo, int64_t hi)
{
    for (size_t i = 0; i < n_label_tab; i++)
        if (label_tab[i].src == host && (double)lo <= label_tab[i].end && label_tab[i].start <= (double)hi)
            return label_tab[i].rule;
    return "benign";
}

const char *label_flow(uint32_t src, int64_t first_us, int64_t last_us)
{
    return match(src, first_us / 1000000, last_us / 1000000);
}

const char *label_window(uint32_t host, int64_t window_start_sec)
{
    /* los 30 s de la ventana: w, w+1, ..., w+29 */
    return match(host, window_start_sec, window_start_sec + 29);
}
