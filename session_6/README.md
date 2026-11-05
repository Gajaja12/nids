# gen_traffic

A synthetic traffic generator for the session 6 practical. It writes one
`.pcap` file and nothing else: no socket, no interface, no network
access of any kind. Run `./gen_traffic --help` for a short summary, or
`man ./gen_traffic.1` (`mandoc gen_traffic.1 | less`, if `man` resists a
path) for the full manual: every option, every attack pattern, the
label-file format, and worked examples.

C99, no dependencies beyond libc, one source file per attack pattern:

```
main.c              -- argument parsing and dispatch
common.c/common.h   -- PRNG, packet builders, pcap output, scheduler
attacks.h           -- one unit function per pattern
attack_*.c          -- one file per attack pattern
```

```
make
./gen_traffic --out synflood.pcap --background 120 --pattern synflood \
    --start 60 --duration 20 --rate 30
```

Background traffic (`--events`) is a mix, not one shape: mostly web
visits to `10.1.0.5:443`, plus DNS lookups, pings and internal
file-share connections (see the man page for the exact split). A
background-only file raises zero alerts against the session 5
reference detector.

Each run also writes `<out>.labels.csv`, in the same `rule,src,start,end`
format `--labels` already reads. Feed the pcap to your own
`./nids --pcap FILE --detect --labels FILE.labels.csv` from session 5.

Building a labeled dataset out of many runs (varying `--seed`,
`--pattern`, `--bots`, `--rate`, `--duration`, `--start`, and the
class balance between `--events` and attack volume) is covered in the
man page's CREATING A DATASET section, with worked sweep examples.

See the session 6 practical slides for the full task.
