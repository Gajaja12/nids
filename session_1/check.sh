#!/bin/sh
# Compare your output on intro.pcap against the shipped reference.
set -e

./nids --pcap scenarios/intro.pcap > out.intro.txt

if diff -u reference/intro.txt out.intro.txt; then
    echo "intro.pcap : PASS"
else
    echo
    echo "intro.pcap : FAIL -- your output (right) differs from the reference (left)."
    echo "Fix parse.c until the diff above is empty."
    exit 1
fi
