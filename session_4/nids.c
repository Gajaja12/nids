/*
 * nids.c -- sesion 4. Marcado con [S4] lo nuevo: --detect y --conf. Lo de la
 * sesion 3 ([S3]): --features, --profile y el cierre ordenado al terminar.
 *
 *   ./nids --pcap scenarios/office-quiet.pcap --features --profile
 *   ./nids --pcap scenarios/office-attacks.pcap --detect [--conf nids.conf]
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "flow.h"
#include "window.h"                                 /* [S3] */
#include "profile.h"                                /* [S3] */
#include "detect.h"                                 /* [S4] */

static pcap_t *g_handle = NULL;

static void on_sigint(int sig)
{
    (void)sig;
    if (g_handle)
        pcap_breakloop(g_handle);
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
        "usage: %s (--pcap FILE | --iface DEV) [--flows] [--features] [--profile] [--detect [--conf FILE]]\n"
        "  --pcap FILE   read packets from a pcap capture file\n"
        "  --iface DEV   capture live from network interface DEV\n"
        "  --flows       write flows.csv instead of one line per packet\n"
        "  --features    write features.csv and windows.csv\n"
        "  --profile     write profile.csv (distribution of every feature)\n"
        "  --detect      apply the rules in nids.conf and write alerts.csv\n"
        "  --conf FILE   use FILE instead of nids.conf (with --detect)\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *iface = NULL;
    int want_flows = 0, want_features = 0, want_profile = 0;   /* [S3] */
    int want_detect = 0;                                       /* [S4] */
    const char *conf_path = "nids.conf";                       /* [S4] */
    int conf_explicit = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_path = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--flows") == 0) {
            want_flows = 1;
        } else if (strcmp(argv[i], "--features") == 0) {   /* [S3] */
            want_features = 1;
        } else if (strcmp(argv[i], "--profile") == 0) {    /* [S3] */
            want_profile = 1;
        } else if (strcmp(argv[i], "--detect") == 0) {     /* [S4] */
            want_detect = 1;
        } else if (strcmp(argv[i], "--conf") == 0 && i + 1 < argc) {   /* [S4] */
            conf_path = argv[++i];
            conf_explicit = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if ((pcap_path && iface) || (!pcap_path && !iface)) {
        usage(argv[0]);
        return 2;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    if (pcap_path) {
        g_handle = pcap_open_offline(pcap_path, errbuf);
    } else {
        g_handle = pcap_open_live(iface, 262144, 1, 1000, errbuf);
    }
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

    /* [S3] Cada salida es opcional e independiente. Si falla abrir una, se
       aborta antes de procesar nada (mejor que perder el resultado al final). */
    if ((want_flows    && flows_open("flows.csv") != 0) ||
        (want_features && (features_open("features.csv") != 0 ||
                           windows_open("windows.csv") != 0)) ||
        (want_profile  && profile_open("profile.csv") != 0) ||
        (want_detect   && detect_open("alerts.csv", conf_path, conf_explicit) != 0)) {
        fprintf(stderr, "nids: cannot set up outputs/configuration "
                        "(see any message above; is this directory writable?)\n");
        pcap_close(g_handle);
        return 1;
    }
    /* Con cualquiera de las tres opciones se analiza; sin ninguna, salida de la sesion 1 */
    parse_set_analysis(want_flows || want_features || want_profile || want_detect);

    signal(SIGINT, on_sigint);

    int rc = pcap_loop(g_handle, 0, on_packet, NULL);

    /* [S3] Fin de fichero (o Ctrl+C). El orden importa poco, pero primero los
       flujos y las ventanas (alimentan el perfil) y por ultimo el perfil. */
    flows_finish();
    windows_finish();
    detect_finish();    /* [S4] regla beacon sobre toda la captura */
    profile_finish();

    pcap_close(g_handle);
    g_handle = NULL;

    return (rc == -1) ? 1 : 0;
}
