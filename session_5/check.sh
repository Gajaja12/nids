#!/bin/sh
# Comprobaciones de la sesion 5 (y regresion de sesiones anteriores).
# Todo se compara ORDENADO: el orden de filas no importa.
fail=0

cmp_sorted() {   # $1 = nuestra salida, $2 = referencia
    sort "$2" > /tmp/ref.sorted
    sort "$1" > /tmp/out.sorted
    if diff -q /tmp/ref.sorted /tmp/out.sorted >/dev/null; then
        echo "  $1 vs $2 : PASS"
    else
        echo "  $1 vs $2 : FAIL"; diff /tmp/ref.sorted /tmp/out.sorted | head -10; fail=1
    fi
}

if [ -f scenarios/office-day.pcap ]; then
    echo "office-day (umbrales de nids.conf):"
    ./nids --pcap scenarios/office-day.pcap --features --detect \
           --labels scenarios/office-day.labels.csv 2> /tmp/summary.txt > /dev/null
    echo "  resumen: $(cat /tmp/summary.txt)"
    for f in alerts.csv alerts.txt windows.csv features.csv; do
        [ -f reference/office-day.$f ] && cmp_sorted $f reference/office-day.$f
    done
    sh score.sh alerts.csv scenarios/office-day.labels.csv alerts.txt
fi

if [ -f scenarios/office-attacks.pcap ] && [ -f reference/office-attacks.alerts.csv ]; then
    echo "office-attacks (sesion 4, con nids.s4.conf; NO debe cambiar):"
    ./nids --pcap scenarios/office-attacks.pcap --detect --conf nids.s4.conf >/dev/null 2>&1
    cmp_sorted alerts.csv reference/office-attacks.alerts.csv
fi
exit $fail
