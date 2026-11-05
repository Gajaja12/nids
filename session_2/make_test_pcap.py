#!/usr/bin/env python3
"""Genera scenarios/test.pcap (NO es web.pcap): FIN, RST, UDP con timeout,
sesion abierta al final, ARP, IPv6 y un paquete truncado."""
import struct, socket

def ip(a): return socket.inet_aton(a)
def eth(payload, et=0x0800): return b"\x02"*6 + b"\x04"*6 + struct.pack("!H", et) + payload
def ipv4(src, dst, proto, l4):
    tot = 20 + len(l4)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 0, 0, 64, proto, 0, ip(src), ip(dst)) + l4
def tcp(sp, dp, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 8192, 0, 0) + data
def udp(sp, dp, data=b""): return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data
S, A, F, R = 2, 0x10, 1, 4
C, SV = "10.0.0.5", "93.184.216.34"
pk = []
def add(t, frame): pk.append((t, frame))
def T(t, s, sp, d, dp, fl, data=b""): add(t, eth(ipv4(s, d, 6, tcp(sp, dp, fl, data))))

t = 1700000000.0
# sesion cerrada por FIN
T(t+.00, C, 49152, SV, 80, S); T(t+.01, SV, 80, C, 49152, S|A); T(t+.02, C, 49152, SV, 80, A)
T(t+.03, C, 49152, SV, 80, A, b"x"*20); T(t+.04, SV, 80, C, 49152, A, b"y"*100)
T(t+.05, C, 49152, SV, 80, F|A)
# cerrada por RST (puerto cerrado)
T(t+1.0, C, 49300, SV, 81, S); T(t+1.001, SV, 81, C, 49300, R|A)
# UDP: dos consultas con 70 s de silencio
add(t+2.0, eth(ipv4(C, "8.8.8.8", 17, udp(40000, 53, b"q"*10))))
add(t+2.02, eth(ipv4("8.8.8.8", C, 17, udp(53, 40000, b"r"*30))))
add(t+72.02, eth(ipv4(C, "8.8.8.8", 17, udp(40000, 53, b"q"*10))))
add(t+72.05, eth(ipv4("8.8.8.8", C, 17, udp(53, 40000, b"r"*30))))
# ruido: ARP, IPv6, ICMP, truncado
add(t+3.0, eth(b"\0"*28, 0x0806)); add(t+3.1, eth(b"\0"*40, 0x86dd))
add(t+3.2, eth(ipv4(C, "1.1.1.1", 1, b"\x08\0\0\0\0\0\0\0")))
add(t+3.3, eth(ipv4(C, SV, 6, tcp(1234, 80, S)))[:30])
# sesion abierta hasta el final (nc)
T(t+4.0, C, 50000, "93.184.216.34", 80, S); T(t+4.01, SV, 80, C, 50000, S|A); T(t+4.02, C, 50000, SV, 80, A)

with open("scenarios/test.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, fr in pk:
        s = int(ts); us = int(round((ts - s) * 1e6))
        f.write(struct.pack("<IIII", s, us, len(fr), len(fr))); f.write(fr)
