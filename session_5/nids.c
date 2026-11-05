/*
 * nids.c -- sesion 5: el mini-NIDS completo.
 *
 *   ./nids --pcap FILE | --iface DEV   [--flows] [--features] [--profile]
 *          [--detect [--conf FILE]] [--labels FILE] [--filter EXPR]
 *
 * Un unico bucle (pcap_loop) sirve para fichero y para interfaz en vivo: lo
 * unico que cambia es como se abre el "handle". Todo lo demas es el mismo codigo.
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "flow.h"
#include "window.h"
#include "profile.h"
#include "detect.h"
#include "labels.h"

static pcap_t *g_handle = NULL;

/* Ctrl-C (o SIGTERM): NO se sale del programa desde el manejador (casi nada es
   seguro ahi); solo se pide a pcap_loop que termine. Despues del bucle, main
   hace el cierre ordenado: flujos, ventanas, beacons, incidentes, resumen. */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_handle)
        pcap_breakloop(g_handle);            /* documentado como seguro en un manejador */
}

static void on_packet(unsigned char *user,
                      const struct pcap_pkthdr *hdr,
                      const unsigned char *bytes)
{
    (void)user;
    handle_packet(bytes, hdr->caplen, hdr->ts);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s (--pcap FILE | --iface DEV) [options]\n"
        "  --pcap FILE     read packets from a pcap capture file\n"
        "  --iface DEV     capture live from network interface DEV\n"
        "  --features      write features.csv and windows.csv\n"
        "  --detect        run the detectors; write alerts.csv and alerts.txt\n"
        "  --conf FILE     thresholds (default nids.conf)\n"
        "  --labels FILE   add a label column to features.csv and windows.csv\n"
        "  --filter EXPR   BPF filter, as in tcpdump\n"
        "  --flows         write flows.csv\n"
        "  --profile       write profile.csv\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL, *iface = NULL;
    const char *conf_path = "nids.conf", *labels_path = NULL, *filter = NULL;
    int conf_explicit = 0;
    int want_flows = 0, want_features = 0, want_profile = 0, want_detect = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_path = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--flows") == 0) {
            want_flows = 1;
        } else if (strcmp(argv[i], "--features") == 0) {
            want_features = 1;
        } else if (strcmp(argv[i], "--profile") == 0) {
            want_profile = 1;
        } else if (strcmp(argv[i], "--detect") == 0) {
            want_detect = 1;
        } else if (strcmp(argv[i], "--conf") == 0 && i + 1 < argc) {
            conf_path = argv[++i];
            conf_explicit = 1;
        } else if (strcmp(argv[i], "--labels") == 0 && i + 1 < argc) {
            labels_path = argv[++i];
        } else if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            filter = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if ((pcap_path && iface) || (!pcap_path && !iface)) {   /* exactamente uno */
        usage(argv[0]);
        return 2;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    if (pcap_path)
        g_handle = pcap_open_offline(pcap_path, errbuf);
    else
        g_handle = pcap_open_live(iface, 262144, 1, 1000, errbuf);
    if (!g_handle) {
        fprintf(stderr, "cannot open packet source: %s\n", errbuf);
        return 1;
    }

    int dlt = pcap_datalink(g_handle);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "unsupported link-layer type %d (%s); need Ethernet\n",
                dlt, pcap_datalink_val_to_name(dlt) ? pcap_datalink_val_to_name(dlt) : "?");
        pcap_close(g_handle);
        return 1;
    }

    /* Filtro BPF: se compila e instala ANTES del primer paquete. Si no compila,
       se muestra el mensaje de libpcap y se para (antes de crear ningun fichero). */
    if (filter) {
        bpf_u_int32 net = 0, mask = PCAP_NETMASK_UNKNOWN;
        if (iface && pcap_lookupnet(iface, &net, &mask, errbuf) != 0)
            mask = PCAP_NETMASK_UNKNOWN;     /* sin mascara solo falla "ip broadcast" */
        struct bpf_program prog;
        if (pcap_compile(g_handle, &prog, filter, 1, mask) != 0) {
            fprintf(stderr, "filter error: %s\n", pcap_geterr(g_handle));
            pcap_close(g_handle);
            return 1;
        }
        if (pcap_setfilter(g_handle, &prog) != 0) {
            fprintf(stderr, "cannot install filter: %s\n", pcap_geterr(g_handle));
            pcap_freecode(&prog);
            pcap_close(g_handle);
            return 1;
        }
        pcap_freecode(&prog);                /* el programa ya esta instalado en el handle */
    }

    /* Las etiquetas se cargan ANTES de abrir las tablas: su cabecera depende de ellas. */
    if (labels_path && labels_load(labels_path) != 0) {
        pcap_close(g_handle);
        return 1;
    }

    /* Cada salida es opcional. Si falla abrir una, se aborta antes de procesar
       nada (mejor que perder el resultado al final). */
    if ((want_flows    && flows_open("flows.csv") != 0) ||
        (want_features && (features_open("features.csv") != 0 ||
                           windows_open("windows.csv") != 0)) ||
        (want_profile  && profile_open("profile.csv") != 0) ||
        (want_detect   && detect_open("alerts.csv", "alerts.txt", conf_path, conf_explicit) != 0)) {
        fprintf(stderr, "nids: cannot set up outputs/configuration "
                        "(see any message above; is this directory writable?)\n");
        pcap_close(g_handle);
        return 1;
    }
    parse_set_analysis(want_flows || want_features || want_profile || want_detect);

    /* sigaction SIN SA_RESTART: asi un read() bloqueado se interrumpe y el
       bucle puede terminar. (signal() en algunos sistemas reinicia la llamada.) */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int rc = pcap_loop(g_handle, 0, on_packet, NULL);

    /* Cierre ordenado: lo hace SIEMPRE el mismo codigo, acabe por fin de fichero,
       por Ctrl-C o por error de lectura. Primero flujos y ventanas (alimentan
       perfil y alertas), luego beacons + incidentes, y por ultimo el perfil. */
    flows_finish();
    windows_finish();
    detect_finish();
    profile_finish();

    /* Resumen en stderr (stdout queda para las alertas). */
    unsigned long long npk, nparsed;
    parse_counters(&npk, &nparsed);
    fprintf(stderr, "packets %llu, parsed %llu, flows %llu, windows %llu, alerts %llu, incidents %llu",
            npk, nparsed, flows_count(), windows_count(),
            detect_alert_count(), detect_incident_count());
    if (iface) {
        struct pcap_stat st;
        if (pcap_stats(g_handle, &st) == 0)
            fprintf(stderr, ", dropped by the kernel %u", st.ps_drop);
    }
    fputc('\n', stderr);

    pcap_close(g_handle);
    g_handle = NULL;

    /* Un error de lectura provocado por nuestra propia senal no es un fallo. */
    return (rc == -1 && !g_stop) ? 1 : 0;
}
