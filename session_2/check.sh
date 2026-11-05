#!/bin/sh
# 1) sesion 1: la salida por paquete sobre intro.pcap sigue igual
# 2) sesion 2: flows.csv sobre web.pcap == web.flows.csv (ordenados)
fail=0

if [ -f scenarios/intro.pcap ]; then
    ./nids --pcap scenarios/intro.pcap > out.intro.txt
    if diff -u reference/intro.txt out.intro.txt >/dev/null; then
        echo "intro.pcap : PASS"
    else
        echo "intro.pcap : FAIL"; diff -u reference/intro.txt out.intro.txt; fail=1
    fi
fi

if [ -f scenarios/web.pcap ]; then
    ./nids --pcap scenarios/web.pcap --flows
    sort reference/web.flows.csv > /tmp/ref.sorted
    sort flows.csv > /tmp/out.sorted
    if diff -u /tmp/ref.sorted /tmp/out.sorted; then
        echo "web.pcap   : PASS"
    else
        echo "web.pcap   : FAIL"; fail=1
    fi
fi
exit $fail
