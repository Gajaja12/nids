/*
 * nids.c -- given, do not edit. Opens a packet source and calls
 * handle_packet() per packet (your work is in parse.c).
 *
 *   ./nids --pcap scenarios/intro.pcap
 *   ./nids --iface eth0
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"

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
        "usage: %s (--pcap FILE | --iface DEV)\n"
        "  --pcap FILE   read packets from a pcap capture file\n"
        "  --iface DEV   capture live from network interface DEV\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *iface = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_path = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
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

    signal(SIGINT, on_sigint);

    int rc = pcap_loop(g_handle, 0, on_packet, NULL);

    pcap_close(g_handle);
    g_handle = NULL;

    return (rc == -1) ? 1 : 0;
}
