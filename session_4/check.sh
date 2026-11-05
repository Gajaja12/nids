#!/bin/sh
# Compara tu salida con reference/ para office-quiet y office-mixed (sesion 3)
# y las alertas de office-attacks (sesion 4).
# features/windows: se ordenan antes (el orden de filas no importa).
# profile: se compara tal cual (una diferencia en el ultimo decimal es aceptable).
fail=0

check_sorted() {   # $1 = salida nuestra, $2 = referencia
    sort "$2" > /tmp/ref.sorted
    sort "$1" > /tmp/out.sorted
    if diff -q /tmp/ref.sorted /tmp/out.sorted >/dev/null; then
        echo "  $1 vs $2 : PASS"
    else
        echo "  $1 vs $2 : FAIL"; diff /tmp/ref.sorted /tmp/out.sorted | head -10; fail=1
    fi
}

for cap in office-quiet office-mixed; do
    [ -f scenarios/$cap.pcap ] || { echo "falta scenarios/$cap.pcap"; continue; }
    echo "$cap:"
    if [ $cap = office-quiet ]; then
        ./nids --pcap scenarios/$cap.pcap --features --profile
    else
        ./nids --pcap scenarios/$cap.pcap --features
    fi
    check_sorted features.csv reference/$cap.features.csv
    check_sorted windows.csv  reference/$cap.windows.csv
    if [ $cap = office-quiet ]; then
        if diff -q profile.csv reference/$cap.profile.csv >/dev/null; then
            echo "  profile.csv : PASS"
        else
            echo "  profile.csv : difiere (revisa a mano los ultimos decimales)"
            diff profile.csv reference/$cap.profile.csv | head -10
        fi
    fi
done

if [ -f scenarios/office-attacks.pcap ]; then
    echo "office-attacks:"
    ./nids --pcap scenarios/office-attacks.pcap --detect
    check_sorted alerts.csv reference/office-attacks.alerts.csv
    [ -f scenarios/office-attacks.labels.csv ] && sh score.sh alerts.csv scenarios/office-attacks.labels.csv
fi
exit $fail
