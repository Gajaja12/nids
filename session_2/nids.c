/*
 * nids.c -- sesion 2. Igual que en la sesion 1 salvo lo marcado con [S2]:
 * opcion --flows y volcado de los flujos abiertos al terminar.
 *
 *   ./nids --pcap scenarios/web.pcap --flows
 *   ./nids --iface eth0 --flows
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "flow.h"                                   /* [S2] */

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
        "usage: %s (--pcap FILE | --iface DEV) [--flows]\n"
        "  --pcap FILE   read packets from a pcap capture file\n"
        "  --iface DEV   capture live from network interface DEV\n"
        "  --flows       write flows.csv instead of one line per packet\n",
        argv0);
}

static int make_flows_path(const char *pcap, char *buf, size_t n){
    const char *base = strrchr(pcap, '/');
    base = base ? base + 1 : pcap;
    size_t len = strlen(base);
    if (len > 5 && strcmp(base + len - 5, ".pcap") == 0)
        len -= 5;
    int w = snprintf(buf, n, "%.*s.flows.csv", (int)len, base);
    return (w < 0 || (size_t)w >= n) ? -1 : 0;   /* -1 si no cabe */
    }

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *iface = NULL;
    int want_flows = 0;                             /* [S2] */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_path = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--flows") == 0) {   /* [S2] */
            want_flows = 1;
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

    char flows_path[512] = "flows.csv";   /* --iface: no hay nombre de pcap */
    if (want_flows && pcap_path &&
        make_flows_path(pcap_path, flows_path, sizeof flows_path) != 0) {
        fprintf(stderr, "flows path too long\n");
        pcap_close(g_handle);
        return 1;
    }
    if (want_flows && flows_open(flows_path) != 0) {
        perror(flows_path);
        pcap_close(g_handle);
        return 1;
    }

    signal(SIGINT, on_sigint);

    int rc = pcap_loop(g_handle, 0, on_packet, NULL);

    flows_finish();     /* [S2] fin de fichero (o Ctrl+C): cerrar lo abierto */

    pcap_close(g_handle);
    g_handle = NULL;

    return (rc == -1) ? 1 : 0;
}

