# Session 1 -- packets in, one line out

You are building a network traffic extraction tool in C. Over sessions 1 to 5
it grows into a small intrusion detection system. This session it reads a
capture and prints one line per IPv4 packet.

See the repository root README for the team workflow (handle, project,
where to push). Copy this whole `session_1/` directory into your own
project and work there.

## Files

| file                   | what it is                                                               |
|------------------------|--------------------------------------------------------------------------|
| `nids.c`               | given. Opens the packet source and calls `handle_packet()`. Do not edit. |
| `parse.h`              | given. The `handle_packet()` prototype.                                  |
| `parse.c`              | **your work.** A stub that prints only the timestamp.                    |
| `Makefile`             | `make` builds `nids`; `make check` runs the check.                       |
| `scenarios/intro.pcap` | the capture to work on.                                                  |
| `reference/intro.txt`  | the exact output your program should produce for it.                     |

## Build and run

```
make
./nids --pcap scenarios/intro.pcap
```

Requires `libpcap` headers (`libpcap-dev` / `libpcap-devel`). In the lab
everything is already installed.

## What to do

Edit `parse.c` so that, for each Ethernet frame, it prints one line
describing the IPv4 packet inside. The full specification and hints are at
the top of `parse.c`. In short:

1. Parse the Ethernet header; skip frames that are not IPv4 (EtherType
   `0x0800`).
2. Parse the IPv4 header: source and destination address, protocol, total
   length.
3. For TCP and UDP, parse the source and destination ports. For TCP, also
   the SYN / ACK / FIN / RST flag bits.
4. Never read past `caplen`. A truncated packet prints `SHORT` and does not
   crash.
5. `make check` must pass: your output on `intro.pcap` has to match
   `reference/intro.txt` exactly.

`intro.pcap` includes a port scan and several malformed or truncated
records, so bounds-check every read, not just the clean packets.
